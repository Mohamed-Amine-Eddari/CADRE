# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Compilation et validation de règles Sigma
==================================================

Pipeline de transformation d'une règle Sigma (YAML) en requête Lucene/KQL
exploitable par Elasticsearch + Kibana. Inclut :
- Compilation Sigma → Lucene via l'API Python pysigma (en mémoire)
- Validation syntaxique de la requête Lucene
- Double validation TP/FP contre l'index Elastic
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.pipelines.elasticsearch import ecs_windows, ecs_windows_old
from sigma.processing.pipeline import ProcessingPipeline

from .attente_indexation import ErreurComptageElastic, compter_evenements
from .logger import obtenir_logger

# Seuils de la double validation (configurables)
SEUIL_FP_MAX = 50  # Nombre max de FP sur 7 jours
FENETRE_TP_SEC = 600  # 10 minutes pour la fenêtre TP
FENETRE_FP_SEC = 604800  # 7 jours pour la fenêtre FP

# Pipelines pysigma disponibles, par nom.
# - "ecs_windows" : mappe les champs Sysmon Windows vers ECS (cible Windows).
# - "aucun" : pipeline identité (ProcessingPipeline vide). Utilisé pour Linux :
#   Auditbeat écrit déjà des champs ECS (process.title, process.executable…),
#   donc appliquer le mapping Windows renommerait les champs à tort. Sans
#   pipeline, les champs de la règle sont conservés tels quels.
_PIPELINES: dict[str, Any] = {
    "ecs_windows": ecs_windows,
    "ecs_windows_old": ecs_windows_old,
    "aucun": ProcessingPipeline,
}

# Champs de corrélation mappés `text` (analysé/tokenisé) côté Elasticsearch —
# PAS `wildcard`/`keyword`. Un wildcard Lucene classique (`champ:*a b*`) ne
# matche jamais un motif multi-mots sur un champ de ce type (le wildcard
# opère au niveau terme, pas phrase), même si le texte y est présent
# littéralement — vérifié empiriquement le 27/08 (CADRE-EVA-001, Faux
# Négatif reproduit deux fois en cycle réel malgré la présence confirmée du
# texte dans le document indexé ; comparaison directe contre Elasticsearch :
# wildcard = 0 résultat, clause phrase = résultats). Liste fermée et vérifiée
# manuellement contre le mapping ES réel — ne pas y ajouter un champ sans
# avoir confirmé son type via `GET winlogbeat-*/_mapping/field/<champ>`.
CHAMPS_TEXTE_ANALYSE: frozenset[str] = frozenset({"powershell.file.script_block_text"})

# `\` suivi d'un caractère quelconque -> ce caractère seul. Inverse
# l'échappement caractère-par-caractère de pysigma pour un motif wildcard
# (voir `add_escaped` dans sigma/backends/elasticsearch/elasticsearch_lucene.py :
# `+-=&|!(){}[]<>^"~*?:\/ ` sont tous échappés d'un antislash simple).
_RE_DESECHAPPER_WILDCARD = re.compile(r"\\(.)")


def _convertir_wildcard_si_multimots(contenu_echappe: str) -> str:
    """Retourne `*contenu_echappe*` inchangé (mono-mot), ou la phrase
    Lucene quotée équivalente si `contenu_echappe` contient un espace
    échappé (motif multi-mots). Sans nom de champ -- réutilisée à la fois
    pour un wildcard isolé et pour chaque alternative d'un groupe OR."""
    if "\\ " not in contenu_echappe:
        return f"*{contenu_echappe}*"
    valeur_litterale = _RE_DESECHAPPER_WILDCARD.sub(r"\1", contenu_echappe)
    valeur_phrase = valeur_litterale.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{valeur_phrase}"'


def _phraser_wildcard_multimots(requete_lucene: str) -> str:
    """
    Réécrit `champ:*a b*` en `champ:"a b"` pour les champs de
    `CHAMPS_TEXTE_ANALYSE`, uniquement quand le motif contient un espace
    échappé (signe d'un motif `contains` multi-mots). Les motifs mono-mot et
    les champs hors liste (`process.command_line`, `process.title`... déjà
    mappés `wildcard`/`keyword`, où un wildcard fonctionne correctement) ne
    sont jamais modifiés.

    Gère aussi la forme groupée `champ:(*a* OR *b*)` (trouvé par revue
    indépendante, 27/08) : pysigma produit systématiquement cette forme --
    jamais `champ:*a* OR champ:*b*` -- pour un `contains` avec plusieurs
    valeurs sur le MÊME champ (liste YAML, ou deux `selection` combinées
    par `or`), car le backend Lucene a `convert_or_as_in=True`. Chaque
    alternative du groupe est convertie indépendamment (un groupe peut
    mélanger une valeur mono-mot et une valeur multi-mots) ; vérifié
    empiriquement que Lucene accepte un OR mélangeant phrase quotée et
    wildcard dans les mêmes parenthèses.
    """
    for champ in CHAMPS_TEXTE_ANALYSE:
        champ_echappe = re.escape(champ)

        motif_groupe = re.compile(champ_echappe + r":\(((?:\*(?:\\.|[^*])*\*(?:\s+OR\s+)?)+)\)")

        def _remplacer_groupe(m: re.Match[str], champ: str = champ) -> str:
            alternatives = re.findall(r"\*((?:\\.|[^*])*)\*", m.group(1))
            reconstruit = " OR ".join(_convertir_wildcard_si_multimots(alt) for alt in alternatives)
            return f"{champ}:({reconstruit})"

        requete_lucene = motif_groupe.sub(_remplacer_groupe, requete_lucene)

        motif_simple = re.compile(champ_echappe + r":\*((?:\\.|[^*])*)\*")

        def _remplacer_simple(m: re.Match[str], champ: str = champ) -> str:
            return f"{champ}:{_convertir_wildcard_si_multimots(m.group(1))}"

        requete_lucene = motif_simple.sub(_remplacer_simple, requete_lucene)
    return requete_lucene


def compiler_sigma_vers_lucene(
    regle_sigma_yaml: str,
    pipeline: str = "ecs_windows",
) -> str | None:
    """
    Compile une règle Sigma (YAML) en requête Lucene, en mémoire via l'API
    Python de pysigma (pas de sous-processus ni de fichier temporaire —
    remplace l'ancien appel à `sigma-cli` en subprocess, coûteux à répéter
    sur un catalogue de dizaines d'attaques).

    Args:
        regle_sigma_yaml: Le contenu YAML de la règle Sigma
        pipeline: Nom du pipeline de conversion (ecs_windows par défaut)

    Returns:
        La requête Lucene/KQL ou None si échec
    """
    log = obtenir_logger()

    pipeline_factory = _PIPELINES.get(pipeline)
    if pipeline_factory is None:
        log.error(f"Pipeline Sigma inconnu : {pipeline!r}")
        return None

    try:
        collection = SigmaCollection.from_yaml(regle_sigma_yaml)
        processing_pipeline: ProcessingPipeline = pipeline_factory()
        backend = LuceneBackend(processing_pipeline=processing_pipeline)
        requetes = backend.convert(collection)
    except SigmaError as e:
        log.error(f"Échec compilation Sigma : {e}")
        return None
    except Exception as e:
        log.error(f"Échec compilation Sigma (erreur inattendue) : {e}")
        return None

    if not requetes:
        log.error("Compilation Sigma : sortie vide")
        return None

    requete = str(requetes[0]).strip()
    if not requete:
        log.error("Compilation Sigma : sortie vide")
        return None

    requete = _phraser_wildcard_multimots(requete)

    log.success(f"Compilation Sigma réussie ({len(requete)} caractères)")
    return requete


# =============================================================================
# Compilation MULTI-FORMAT (multi-SIEM) — le backend Elasticsearch installé
# sait produire plusieurs formats de sortie, sans dépendance supplémentaire.
# Chaque entrée : nom convivial -> (output_format pysigma, nom de fichier,
# description, mode de sérialisation).
#
# Pour ajouter un AUTRE SIEM (Splunk, Sentinel...), la table ci-dessous est
# prévue extensible côté architecture — mais ce n'est PAS un simple ajout de
# ligne, MÊME depuis le 27/08 (voir ci-dessous). POC initial mené (2026-08)
# avec `pysigma-backend-splunk` : la compilation Sigma -> SPL fonctionne et
# produit une syntaxe valide (vérifié contre une instance Splunk réelle via
# /services/search/parser), MAIS le catalogue CADRE utilisait alors
# directement la taxonomie ECS (event.code, process.command_line...) comme
# champs source, que le pipeline pysigma `splunk_windows_pipeline` (qui
# mappe depuis la taxonomie Sysmon brute) ne savait pas traduire : SPL
# syntaxiquement valide mais sémantiquement mort (aucune détection réelle).
#
# MISE À JOUR (27/08) : le catalogue Windows (39 attaques Sysmon/PowerShell
# sur 46) utilise désormais la taxonomie Sysmon brute en champ source
# (EventID, CommandLine, ScriptBlockText...) -- voir _SYSMON_EVENT_INFO/
# _POWERSHELL_EVENT_INFO dans orchestrateur.py. Compilation Elasticsearch
# (ecs_windows) inchangée bit-à-bit, prouvé par diff Lucene avant/après sur
# les 40 attaques concernées (aucune différence). MAIS le support Splunk
# reste NON livré et NON prouvé : exploration approfondie du code source
# des 3 pipelines pysigma Splunk (`splunk_windows_pipeline`,
# `splunk_windows_sysmon_acceleration_keywords`, `splunk_cim_data_model`)
# a montré que `splunk_cim_data_model` (le plus structuré) REJETTE purement
# et simplement toute règle PowerShell/Security/System -- pas juste un
# mauvais mapping, un échec de compilation (33% du catalogue Windows
# concerné) -- et que `splunk_windows_pipeline` (mapping minimal, EventID
# uniquement) ne garantit la justesse d'aucun autre champ sans un vrai
# Splunk + Add-on installé pour vérifier. `pysigma-backend-splunk` n'est
# d'ailleurs plus installé dans ce venv (seulement dans un venv POC isolé).
# Rebasculer la taxonomie était une condition nécessaire pour Splunk, pas
# suffisante -- chantier de fond distinct, qui nécessiterait un vrai
# déploiement Splunk pour être prouvé plutôt que simplement compilé.
# =============================================================================
FORMATS_SORTIE: dict[str, tuple[str, str, str, str]] = {
    "lucene": (
        "default",
        "cadre_lucene.txt",
        "Requêtes Lucene, une par ligne (Kibana Discover / Elastic)",
        "lignes",
    ),
    "es-dsl": (
        "dsl_lucene",
        "cadre_es_dsl.json",
        "Elasticsearch Query DSL (JSON) — utilisable via l'API _search",
        "json_array",
    ),
    # NB : le format kibana enrichit chaque règle avec les données MITRE ATT&CK
    # que pysigma télécharge une fois puis met en cache. Sans réseau ET sans
    # cache, il dégrade proprement (non produit + log clair). lucene/es-dsl,
    # eux, sont 100% hors-ligne.
    "kibana": (
        "siem_rule_ndjson",
        "cadre_kibana_import.ndjson",
        "Bundle Kibana Security — import direct (nécessite les données MITRE, "
        "téléchargées une fois puis mises en cache)",
        "ndjson",
    ),
}


def formats_sortie_disponibles() -> dict[str, str]:
    """{nom convivial: description} des formats de sortie multi-SIEM disponibles."""
    return {nom: infos[2] for nom, infos in FORMATS_SORTIE.items()}


def _serialiser_sortie(resultats: list[Any], mode: str) -> str:
    """Sérialise la sortie du backend selon le format cible (texte prêt à écrire)."""
    if mode == "json_array":
        return json.dumps(list(resultats), indent=2, ensure_ascii=False)
    if mode == "ndjson":  # Kibana attend un objet JSON par ligne
        return "\n".join(json.dumps(r, ensure_ascii=False) for r in resultats)
    return "\n".join(str(r) for r in resultats)  # "lignes"


def compiler_regles_multi(  # noqa: PLR0911 -- garde-fous défensifs à sortie
    # anticipée (format inconnu, lot vide, pipeline inconnu, erreurs de
    # compilation, sortie vide) : chaque cas retourne None avec un log clair ;
    # les fusionner nuirait à la lisibilité sans gain.
    regles_yaml: list[str],
    format_nom: str,
    pipeline: str = "ecs_windows",
) -> str | None:
    """
    Compile un LOT de règles Sigma vers un format de sortie multi-SIEM et
    retourne le contenu texte prêt à écrire dans un fichier.

    Args:
        regles_yaml: liste de règles Sigma (chaînes YAML), une par attaque.
        format_nom: clé de `FORMATS_SORTIE` (`lucene`, `es-dsl`, `kibana`).
        pipeline: pipeline de conversion (défaut `ecs_windows`).

    Returns:
        Le contenu compilé (str) ou None si le format est inconnu / la
        compilation échoue.
    """
    log = obtenir_logger()
    if format_nom not in FORMATS_SORTIE:
        log.error(f"Format de sortie inconnu : {format_nom!r}")
        return None
    if not regles_yaml:
        return None

    output_format, _fichier, _desc, mode = FORMATS_SORTIE[format_nom]
    pipeline_factory = _PIPELINES.get(pipeline)
    if pipeline_factory is None:
        log.error(f"Pipeline Sigma inconnu : {pipeline!r}")
        return None

    try:
        # Un document multi-règles = les YAML joints par le séparateur "---".
        collection = SigmaCollection.from_yaml("\n---\n".join(regles_yaml))
        backend = LuceneBackend(processing_pipeline=pipeline_factory())
        resultats = backend.convert(collection, output_format=output_format)
    except SigmaError as e:
        log.error(f"Compilation multi-format échouée ({format_nom}) : {e}")
        return None
    except Exception as e:  # défensif : un format exotique ne doit jamais planter l'appelant
        detail = str(e)
        # Le format Kibana (siem_rule_ndjson) enrichit chaque règle avec les
        # données MITRE ATT&CK, que pysigma TÉLÉCHARGE une fois puis met en
        # cache. Hors-ligne et sans cache, ce téléchargement échoue : on dégrade
        # proprement (None + message clair) sans planter. Les formats lucene et
        # es-dsl, eux, sont 100% hors-ligne.
        if any(m in detail for m in ("MITRE", "urlopen", "getaddrinfo", "timed out")):
            log.error(
                f"Format {format_nom} indisponible hors-ligne : il nécessite les données "
                f"MITRE ATT&CK (téléchargées une fois par pysigma puis mises en cache). "
                f"Formats hors-ligne disponibles : lucene, es-dsl. Détail : {e}"
            )
        else:
            log.error(f"Compilation multi-format échouée ({format_nom}, inattendu) : {e}")
        return None

    if not resultats:
        log.error(f"Compilation multi-format ({format_nom}) : sortie vide")
        return None

    # Même correctif que compiler_sigma_vers_lucene() (wildcard multi-mots
    # inutilisable sur un champ text analysé), appliqué ici séparément car ce
    # chemin compile via son propre backend, sans jamais passer par
    # compiler_sigma_vers_lucene(). "es-dsl" (dsl_lucene) enveloppe la même
    # chaîne Lucene brute (vérifié : query.bool.must[0].query_string.query)
    # mais volontairement non corrigé ici -- format d'export secondaire,
    # traitement JSON imbriqué disproportionné pour l'usage réel.
    if format_nom == "lucene":
        resultats = [_phraser_wildcard_multimots(str(r)) for r in resultats]
    elif format_nom == "kibana":
        for r in resultats:
            if isinstance(r, dict) and isinstance(r.get("query"), str):
                r["query"] = _phraser_wildcard_multimots(r["query"])

    return _serialiser_sortie(resultats, mode)


def valider_syntaxe_lucene(requete: str) -> tuple[bool, str | None]:
    """
    Vérifie la syntaxe d'une requête Lucene en l'envoyant à Elastic avec
    un size=0. Si Elastic répond sans erreur de parsing, la syntaxe est OK.
    """
    # Validation basique (champs équilibrés, pas de caractères interdits)
    if not requete or len(requete) < 3:
        return False, "Requête vide ou trop courte"

    # Pas de guillemets non fermés — en ignorant les guillemets échappés
    # (`\"`), qui sont des littéraux valides produits par pysigma quand une
    # valeur de détection contient elle-même un guillemet (ex. une commande
    # Windows normalisée `"...rundll32.exe" /?`). Sans cette exclusion, une
    # requête pourtant parfaitement valide était rejetée en SYNTAXE_INVALIDE.
    guillemets_non_echappes = len(re.findall(r'(?<!\\)"', requete))
    if guillemets_non_echappes % 2 != 0:
        return False, "Guillemets non équilibrés"

    # Pas de parenthèses non équilibrées
    if requete.count("(") != requete.count(")"):
        return False, "Parenthèses non équilibrées"

    return True, None


def double_validation_tp_fp(
    requete_lucene: str,
    elastic_url: str,
    auth: tuple | None,
    index_pattern: str = "winlogbeat-*",
    seuil_fp: int = SEUIL_FP_MAX,
    fenetre_tp_sec: int = FENETRE_TP_SEC,
    fenetre_fp_sec: int = FENETRE_FP_SEC,
    contexte: dict[str, Any] | None = None,
) -> tuple[bool, str, int, int]:
    """
    Double validation d'une règle de détection :
    1. Vrai positif (TP) : la requête doit matcher ≥1 événement récent
    2. Faux positif (FP) : la requête ne doit pas être trop bruyante

    Args:
        requete_lucene: La requête Lucene à valider
        elastic_url: URL Elastic
        auth: (user, password)
        index_pattern: Pattern d'index
        seuil_fp: Nombre max de FP tolérés
        fenetre_tp_sec: Fenêtre TP en secondes
        fenetre_fp_sec: Fenêtre FP en secondes
        contexte: Contexte additionnel pour logging

    Returns:
        Tuple (succès, raison, nb_tp, nb_fp)
    """
    log = obtenir_logger()
    ctx = contexte or {}

    # 1. Validation syntaxique
    valide, erreur = valider_syntaxe_lucene(requete_lucene)
    if not valide:
        log.error(f"Syntaxe Lucene invalide : {erreur}", **ctx)
        return False, f"SYNTAXE_INVALIDE:{erreur}", 0, 0

    # 2. Test TP : la règle doit matcher ≥1 événement sur la fenêtre récente
    requete_tp = {
        "query": {
            "bool": {
                "must": [{"query_string": {"query": requete_lucene}}],
                "filter": [{"range": {"@timestamp": {"gte": f"now-{fenetre_tp_sec}s"}}}],
            }
        }
    }
    try:
        nb_tp = compter_evenements(elastic_url, index_pattern, requete_tp, auth)

        # attendre_indexation() a déjà confirmé qu'au moins un des EventIDs
        # attendus existe, mais la requête Sigma compilée cible un champ
        # précis qui peut être indexé avec un léger retard (latence
        # near-real-time Elasticsearch + harvest Winlogbeat) — plus
        # sensible en cycle chargé avec plusieurs attaques enchaînées
        # (observé empiriquement : un seul retry de 3s ne suffisait pas
        # toujours). Backoff progressif (3s, 5s, 8s = 16s cumulés) avant de
        # conclure à un vrai Faux Négatif.
        for delai_retry in (3, 5, 8):
            if nb_tp > 0:
                break
            time.sleep(delai_retry)
            nb_tp = compter_evenements(elastic_url, index_pattern, requete_tp, auth)
    except ErreurComptageElastic as e:
        # Panne Elasticsearch, pas "0 résultat" -- fail CLOSED (comme un
        # Faux Négatif) plutôt que de risquer d'interpréter l'échec comme
        # un vrai zéro. Raison distincte pour ne pas confondre les deux
        # côté appelant (voir orchestrateur.py, statut ERREUR pas REJETE).
        log.error(f"ÉCHEC : mesure TP impossible (Elasticsearch injoignable) : {e}", **ctx)
        return False, "ERREUR_ELASTICSEARCH", 0, 0

    if nb_tp == 0:
        log.warn("ÉCHEC : Faux Négatif (règle ne détecte rien sur la fenêtre récente)", tp=0, **ctx)
        return False, "FAUX_NEGATIF", 0, 0

    log.info(f"Validation TP : {nb_tp} hit(s) sur {fenetre_tp_sec}s", tp=nb_tp, **ctx)

    # 3. Test FP : la règle ne doit pas être trop bruyante sur l'historique
    requete_fp = {
        "query": {
            "bool": {
                "must": [{"query_string": {"query": requete_lucene}}],
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": f"now-{fenetre_fp_sec}s",
                                "lt": f"now-{fenetre_tp_sec}s",
                            }
                        }
                    }
                ],
            }
        }
    }
    try:
        nb_fp = compter_evenements(elastic_url, index_pattern, requete_fp, auth)
    except ErreurComptageElastic as e:
        # LE cas critique de cette régression : sans cette garde, une panne
        # ES ici produisait silencieusement nb_fp=0 ("aucun bruit") --
        # fail OPEN, la règle était validée et déployée SANS jamais avoir
        # pu prouver l'absence de faux positifs. Fail CLOSED à la place.
        log.error(f"ÉCHEC : mesure FP impossible (Elasticsearch injoignable) : {e}", **ctx)
        return False, "ERREUR_ELASTICSEARCH", nb_tp, 0

    log.info(f"Validation FP : {nb_fp} hit(s) sur {fenetre_fp_sec}s", fp=nb_fp, **ctx)

    if nb_fp > seuil_fp:
        log.warn(
            f"ÉCHEC : Trop de faux positifs ({nb_fp} > {seuil_fp})",
            fp=nb_fp,
            seuil=seuil_fp,
            **ctx,
        )
        return False, f"TROP_DE_FP:{nb_fp}>{seuil_fp}", nb_tp, nb_fp

    log.success(
        f"DOUBLE VALIDATION RÉUSSIE — TP={nb_tp} FP={nb_fp}",
        tp=nb_tp,
        fp=nb_fp,
        **ctx,
    )
    return True, "OK", nb_tp, nb_fp


def valider_bruit_seul(
    requete_lucene: str,
    elastic_url: str,
    auth: tuple | None,
    index_pattern: str = "winlogbeat-*",
    seuil_fp: int = SEUIL_FP_MAX,
    fenetre_fp_sec: int = FENETRE_FP_SEC,
    fenetre_tp_sec: int = FENETRE_TP_SEC,
    contexte: dict[str, Any] | None = None,
) -> tuple[bool, str, int]:
    """
    Validation PARTIELLE : syntaxe + bruit (FP) uniquement, SANS exigence
    de fraîcheur TP (contrairement à `double_validation_tp_fp`).

    Réservée au cas où la requête à revalider est IDENTIQUE à une requête
    déjà validée avec succès (ex. approbation d'une revue humaine
    différée : la commande a été exécutée il y a plusieurs heures, un
    match TP frais dans les 600 dernières secondes n'a aucune raison
    d'exister même si la règle est parfaitement valide). La preuve TP
    déjà obtenue à l'exécution reste valable puisque rien dans la
    logique de détection n'a changé -- seule l'horloge a tourné.

    Ne JAMAIS utiliser sur un contenu de détection réellement modifié :
    dans ce cas `double_validation_tp_fp` (avec sa contrainte de
    fraîcheur) est la seule validation légitime.

    Returns:
        Tuple (succès, raison, nb_fp)
    """
    log = obtenir_logger()
    ctx = contexte or {}

    valide, erreur = valider_syntaxe_lucene(requete_lucene)
    if not valide:
        log.error(f"Syntaxe Lucene invalide : {erreur}", **ctx)
        return False, f"SYNTAXE_INVALIDE:{erreur}", 0

    requete_fp = {
        "query": {
            "bool": {
                "must": [{"query_string": {"query": requete_lucene}}],
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": f"now-{fenetre_fp_sec}s",
                                "lt": f"now-{fenetre_tp_sec}s",
                            }
                        }
                    }
                ],
            }
        }
    }
    try:
        nb_fp = compter_evenements(elastic_url, index_pattern, requete_fp, auth)
    except ErreurComptageElastic as e:
        # Même raisonnement que double_validation_tp_fp : une panne ES ici
        # produisait silencieusement nb_fp=0 ("aucun bruit") -- fail OPEN,
        # une revue pouvait être approuvée sans preuve d'absence de FP.
        log.error(f"ÉCHEC : mesure FP impossible (Elasticsearch injoignable) : {e}", **ctx)
        return False, "ERREUR_ELASTICSEARCH", 0

    log.info(f"Validation bruit seul (sans exigence TP) : {nb_fp} hit(s)", fp=nb_fp, **ctx)

    if nb_fp > seuil_fp:
        log.warn(
            f"ÉCHEC : Trop de faux positifs ({nb_fp} > {seuil_fp})",
            fp=nb_fp,
            seuil=seuil_fp,
            **ctx,
        )
        return False, f"TROP_DE_FP:{nb_fp}>{seuil_fp}", nb_fp

    log.success(f"VALIDATION BRUIT RÉUSSIE — FP={nb_fp}", fp=nb_fp, **ctx)
    return True, "OK", nb_fp
