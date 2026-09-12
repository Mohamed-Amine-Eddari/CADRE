# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Validation d'une règle Sigma EXISTANTE sur VOTRE télémétrie
===================================================================

Répond frontalement à l'objection « on peut installer toutes les règles
SigmaHQ existantes et voilà » : oui, mais lesquelles fonctionnent — et
lesquelles vous noient sous les faux positifs — sur VOTRE environnement ?

Ce module prend une règle Sigma quelconque (typiquement issue de SigmaHQ),
la compile vers Lucene avec le même pipeline que CADRE, puis mesure son
comportement réel contre les données déjà indexées dans Elasticsearch :

- ne compile pas          -> NON_COMPILABLE (champ non mappé / non supporté)
- 0 correspondance        -> SILENCIEUSE   (attaque absente OU champ non collecté)
- trop de correspondances -> BRUYANTE      (risque élevé de faux positifs chez vous)
- quelques correspondances-> ACTIVE        (matche votre télémétrie : à investiguer)
- mesure impossible       -> ERREUR        (Elasticsearch injoignable -- PAS un verdict
                                             sur la règle, ne jamais confondre avec
                                             SILENCIEUSE : "aucune preuve" ≠ "bon signe")

Aucune attaque n'est exécutée : on interroge la télémétrie EXISTANTE. Le
module ne dépend donc que d'Elasticsearch (pas de la VM cible).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .attente_indexation import ErreurComptageElastic, compter_evenements
from .compilation_sigma import compiler_sigma_vers_lucene
from .logger import obtenir_logger

# Au-delà de ce nombre de correspondances sur la fenêtre, on considère la
# règle « bruyante » sur l'environnement (trop de faux positifs probables).
SEUIL_BRUIT_DEFAUT = 100


def valider_regle_sigma(
    regle_yaml: str,
    elastic_url: str,
    auth: tuple | None,
    index_pattern: str = "winlogbeat-*",
    fenetre_jours: int = 7,
    seuil_bruit: int = SEUIL_BRUIT_DEFAUT,
) -> dict[str, Any]:
    """
    Valide une règle Sigma (contenu YAML) contre la télémétrie indexée.

    Returns:
        dict avec les clés : compilable (bool), requete_lucene (str|None),
        hits (int|None), verdict (str), detail (str), fenetre_jours,
        seuil_bruit.
    """
    log = obtenir_logger()
    resultat: dict[str, Any] = {
        "compilable": False,
        "requete_lucene": None,
        "hits": None,
        "verdict": "NON_COMPILABLE",
        "detail": "",
        "fenetre_jours": fenetre_jours,
        "seuil_bruit": seuil_bruit,
    }

    lucene = compiler_sigma_vers_lucene(regle_yaml)
    if not lucene:
        resultat["detail"] = (
            "La règle ne compile pas vers Lucene : un champ n'est pas mappé "
            "par le pipeline ecs_windows, ou la syntaxe n'est pas supportée. "
            "Sur votre SIEM Elastic, elle serait donc inopérante telle quelle."
        )
        log.warn("Validation règle Sigma : NON_COMPILABLE")
        return resultat

    resultat["compilable"] = True
    resultat["requete_lucene"] = lucene

    requete = {
        "query": {
            "bool": {
                "must": [{"query_string": {"query": lucene}}],
                "filter": [{"range": {"@timestamp": {"gte": f"now-{fenetre_jours}d"}}}],
            }
        }
    }
    try:
        hits = compter_evenements(elastic_url, index_pattern, requete, auth)
    except ErreurComptageElastic as e:
        # Régression sécurité (audit) : une panne ES ici affichait
        # auparavant le verdict SILENCIEUSE ("bon signe") -- une mesure
        # RATÉE n'est pas un vrai zéro, ne doit jamais se lire comme
        # rassurante. `hits` reste None (résultat par défaut) : aucune
        # mesure n'a réellement eu lieu.
        resultat["verdict"] = "ERREUR"
        resultat["detail"] = (
            f"Impossible d'interroger Elasticsearch ({e}). Aucune mesure "
            "n'a eu lieu -- ni un bon ni un mauvais signe, juste un échec "
            "technique. Réessayez une fois la connectivité rétablie."
        )
        log.error(f"Validation règle Sigma : ERREUR ({e})")
        return resultat

    resultat["hits"] = hits

    if hits == 0:
        resultat["verdict"] = "SILENCIEUSE"
        resultat["detail"] = (
            f"0 correspondance sur {fenetre_jours} j. Deux lectures possibles : "
            "soit l'attaque n'a jamais eu lieu chez vous (bon signe), soit le "
            "champ ciblé n'est pas collecté par votre télémétrie (angle mort "
            "à vérifier avant de faire confiance à cette règle)."
        )
    elif hits > seuil_bruit:
        resultat["verdict"] = "BRUYANTE"
        resultat["detail"] = (
            f"{hits} correspondances sur {fenetre_jours} j (> {seuil_bruit}). "
            "Risque élevé de faux positifs sur VOTRE environnement : déployée "
            "telle quelle, elle saturerait l'analyste. À affiner d'abord."
        )
    else:
        resultat["verdict"] = "ACTIVE"
        resultat["detail"] = (
            f"{hits} correspondance(s) sur {fenetre_jours} j : la règle matche "
            "votre télémétrie de façon modérée — à investiguer (détections "
            "réelles ou faux positifs à filtrer)."
        )

    log.info(f"Validation règle Sigma : {resultat['verdict']} ({hits} hits)")
    return resultat


def valider_fichier_regle(
    chemin: Path,
    elastic_url: str,
    auth: tuple | None,
    index_pattern: str = "winlogbeat-*",
    fenetre_jours: int = 7,
    seuil_bruit: int = SEUIL_BRUIT_DEFAUT,
) -> dict[str, Any]:
    """Charge une règle Sigma depuis un fichier `.yml` et la valide."""
    regle_yaml = Path(chemin).read_text(encoding="utf-8")
    resultat = valider_regle_sigma(
        regle_yaml,
        elastic_url=elastic_url,
        auth=auth,
        index_pattern=index_pattern,
        fenetre_jours=fenetre_jours,
        seuil_bruit=seuil_bruit,
    )
    resultat["fichier"] = str(chemin)
    return resultat
