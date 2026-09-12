# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Catalogue utilisateur (extensible par IA)
==================================================

Le catalogue natif (`catalogue_attaques.CATALOGUE`) reste
**immuable** : c'est le socle déterministe et testé du projet. Ce module
ajoute par-dessus un catalogue **personnel, persistant et extensible** —
alimenté typiquement par les brouillons de l'assistant LLM (`cadre suggest
--enregistrer`) que l'utilisateur valide.

Garantie centrale préservée : ces attaques suivent EXACTEMENT le même
pipeline que les natives (exécution WinRM → attente d'indexation → règle
Sigma déterministe → double validation TP/FP → déploiement). L'IA aide à
*proposer* une attaque ; elle ne décide jamais qu'une règle est déployée —
c'est toujours la double validation qui tranche.

Stockage : `~/.cadre/catalogue_perso.json` (liste d'objets JSON), à côté du
coffre-fort. Le chemin est un attribut de module surchargeable par les
tests (isolation).
"""

from __future__ import annotations

import json
import threading
from dataclasses import fields
from pathlib import Path
from typing import Any

from .catalogue_attaques import (
    AttaqueCatalogue,
    NiveauRisque,
    OrigineExecution,
    Plateforme,
)
from .logger import obtenir_logger

# Surchargé par les tests (isolation) — défaut : à côté du coffre-fort.
CHEMIN_CATALOGUE_PERSO = Path.home() / ".cadre" / "catalogue_perso.json"

# Même raisonnement que revue_regles._verrou_revues / raffinement._verrou_
# raffinements : protège le cycle lecture-modification-écriture de
# CHEMIN_CATALOGUE_PERSO contre les races intra-processus (régression, audit).
# Deux chemins réels écrivent ce même fichier en parallèle sous le dashboard :
# le thread d'arrière-plan d'une découverte IA (dashboard.demarrer_decouverte
# -> decouverte_ia.decouvrir_attaques -> enregistrer_attaque_utilisateur) et
# un thread HTTP traitant `/api/suggest/enregistrer` ou un import Atomic Red
# Team (dashboard.py, ThreadingHTTPServer -- un thread par requête). Sans
# verrou, le classique "dernier écrivain gagne" peut faire disparaître
# silencieusement l'une des deux attaques enregistrées. RLock (pas Lock) :
# enregistrer_attaque_utilisateur rappelle charger_attaques_utilisateur en
# tenant déjà le verrou -- un Lock simple ferait deadlocker le même thread
# sur sa propre ré-entrée.
_verrou_catalogue_perso = threading.RLock()

# Champs obligatoires pour qu'un brouillon devienne une attaque exécutable.
_CHAMPS_REQUIS = ("id", "nom", "technique_mitre", "tactique_mitre", "commande")


class ErreurCatalogueUtilisateur(Exception):
    """Brouillon d'attaque invalide ou conflit d'identifiant."""


def _noms_champs_valides() -> set[str]:
    return {f.name for f in fields(AttaqueCatalogue)}


def brouillon_vers_attaque(brouillon: dict[str, Any]) -> AttaqueCatalogue:
    """
    Convertit un brouillon (dict, typiquement produit par l'assistant LLM)
    en `AttaqueCatalogue` valide, en appliquant des valeurs par défaut sûres
    pour les champs absents. Lève `ErreurCatalogueUtilisateur` si un champ
    critique manque.

    Les clés inconnues du brouillon (ex. `brouillon_ia`, `modele` ajoutés
    par l'assistant) sont ignorées silencieusement — on ne garde que les
    champs réels du dataclass.
    """
    manquants = [c for c in _CHAMPS_REQUIS if not brouillon.get(c)]
    if manquants:
        raise ErreurCatalogueUtilisateur(
            f"Brouillon incomplet — champs requis manquants : {', '.join(manquants)}"
        )

    valides = _noms_champs_valides()
    donnees = {k: v for k, v in brouillon.items() if k in valides}

    # Valeurs par défaut sûres pour les champs structurants absents.
    donnees.setdefault("description", donnees.get("nom", ""))
    donnees.setdefault("sous_technique", None)
    donnees.setdefault("champ_principal", "process.command_line")
    donnees.setdefault("event_ids_attendus", ["1"])  # ProcessCreate par défaut

    # Normalisation des enums (le LLM renvoie des chaînes).
    donnees["niveau_risque"] = _normaliser_enum(
        donnees.get("niveau_risque"), NiveauRisque, NiveauRisque.FAIBLE
    )
    donnees["plateforme"] = _normaliser_enum(
        donnees.get("plateforme"), Plateforme, Plateforme.WINDOWS
    )
    # Régression (audit, reproduite en réel) : `origine_execution` n'était
    # jamais normalisé ici, contrairement à niveau_risque/plateforme
    # ci-dessus -- une valeur JSON restait une chaîne Python brute au lieu
    # d'un membre `OrigineExecution`. Sans effet au chargement lui-même,
    # mais `_cible_pour_attaque` (orchestrateur.py) appelle
    # `attaque.origine_execution.value`, qu'un `str` n'a pas :
    # AttributeError dès le premier cycle sur une attaque du catalogue
    # perso -- confirmé en conditions réelles sur les 3 attaques IA
    # existantes, toutes en erreur pour cette raison.
    donnees["origine_execution"] = _normaliser_enum(
        donnees.get("origine_execution"), OrigineExecution, OrigineExecution.CIBLE
    )

    # Une attaque Linux sans `valeur_detection` produirait une règle Sigma
    # `process.title|contains: ''` -- confirmé par compilation réelle, cela
    # donne la requête Lucene `process.title:*` (pysigma), qui matche
    # QUASIMENT TOUT événement de création de processus Linux (tout
    # process.title non vide). Contrairement à Windows, dont la corrélation
    # optionnelle retombe proprement sur `event.code` seul quand
    # `valeur_detection` est absent (voir `_calculer_signature_detection`,
    # orchestrateur.py), Linux N'A PAS d'équivalent catégoriel : le champ
    # `process.title|contains` EST l'unique sélection générée pour cette
    # plateforme -- l'omettre ne laisse aucun filtre de repli, seulement un
    # filtre vide qui matche tout. Refusé ici, au point d'entrée unique du
    # catalogue utilisateur (charge ET enregistrement passent tous deux par
    # cette fonction), plutôt que de laisser une telle attaque produire puis
    # potentiellement déployer une règle sans aucune spécificité.
    if donnees["plateforme"] == Plateforme.LINUX and not donnees.get("valeur_detection"):
        raise ErreurCatalogueUtilisateur(
            "Attaque Linux sans 'valeur_detection' refusée — la règle générée "
            "n'aurait aucune spécificité (process.title|contains vide compile "
            "en un filtre 'tout matcher' process.title:*)."
        )

    # event_ids_attendus doit être une liste de chaînes (setdefault ci-dessus
    # garantit une valeur non-None ici).
    eids = donnees["event_ids_attendus"]
    if isinstance(eids, (str, int)):
        donnees["event_ids_attendus"] = [str(eids)]
    else:
        donnees["event_ids_attendus"] = [str(e) for e in eids]

    try:
        return AttaqueCatalogue(**donnees)
    except TypeError as e:  # défense : champ inattendu / type incompatible
        raise ErreurCatalogueUtilisateur(f"Brouillon non convertible : {e}") from e


def _normaliser_enum(valeur: Any, enum_cls: Any, defaut: Any) -> Any:
    """Convertit une valeur (chaîne du LLM, membre déjà typé) en membre de
    `enum_cls`, avec repli sur `defaut`.

    La tolérance envers les chaînes est délibérée (le LLM et les JSON édités
    à la main en produisent), mais un repli SILENCIEUX est dangereux : une
    `plateforme` "ubuntu" non reconnue devenait `windows` sans le moindre
    signal, envoyant une commande Linux vers la VM Windows. On distingue
    donc le champ absent (cas normal, silencieux) de la valeur fournie mais
    non reconnue (faute de frappe ou hallucination du LLM, journalisée).
    """
    if isinstance(valeur, enum_cls):
        return valeur
    if isinstance(valeur, str):
        for membre in enum_cls:
            if valeur.lower() in (membre.value, membre.name.lower()):
                return membre
    if valeur not in (None, ""):
        obtenir_logger().warn(
            f"{enum_cls.__name__} : {valeur!r} non reconnu, repli sur {defaut.value!r}",
            valeurs_acceptees=[m.value for m in enum_cls],
        )
    return defaut


def charger_attaques_utilisateur(
    chemin: Path | None = None,
) -> list[AttaqueCatalogue]:
    """
    Charge les attaques personnelles depuis le fichier JSON. Retourne une
    liste vide si le fichier n'existe pas. Une entrée invalide est ignorée
    (avec un avertissement) plutôt que de faire échouer tout le chargement.

    Garde-fou anti-destruction réappliqué ICI, pas seulement à
    l'enregistrement (régression sécurité, audit) : `enregistrer_attaque_
    utilisateur()` filtre les commandes dangereuses à l'écriture, mais
    `catalogue_perso.json` reste un fichier texte modifiable directement par
    l'utilisateur (ou par tout futur code qui y écrirait sans passer par
    cette fonction) -- sans revérification au CHARGEMENT, une commande
    destructrice ajoutée hors du chemin normal deviendrait silencieusement
    exécutable par `cadre cycle` en mode réel, sans aucun garde-fou. Une
    entrée dont la commande est jugée dangereuse est ignorée (avec un
    avertissement), exactement comme une entrée structurellement invalide.
    """
    from .decouverte_ia import (  # noqa: PLC0415 (évite un cycle d'import)
        commande_dangereuse,
    )

    cible = chemin or CHEMIN_CATALOGUE_PERSO
    with _verrou_catalogue_perso:
        if not cible.is_file():
            return []

        try:
            brut = json.loads(cible.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            obtenir_logger().warn(f"Catalogue perso illisible ({cible}) : {e}")
            return []

    if not isinstance(brut, list):
        obtenir_logger().warn(f"Catalogue perso mal formé (attendu: liste) : {cible}")
        return []

    attaques: list[AttaqueCatalogue] = []
    for entree in brut:
        try:
            attaque = brouillon_vers_attaque(entree)
        except ErreurCatalogueUtilisateur as e:
            obtenir_logger().warn(f"Attaque perso ignorée (invalide) : {e}")
            continue
        motif = commande_dangereuse(attaque.commande)
        if motif:
            obtenir_logger().warn(
                f"Attaque perso ignorée (commande dangereuse, motif {motif!r}) : {attaque.id}"
            )
            continue
        # Même raisonnement que ci-dessus pour la commande : `enregistrer_
        # attaque_utilisateur()` refuse un id contenant un séparateur de
        # chemin à l'écriture (protection contre `repertoire_regles /
        # f"{id}.yml"` qui sort de son dossier), mais ce fichier reste
        # modifiable hors de cette fonction -- revérifié ici pour la même
        # raison que le filtre anti-commande juste au-dessus.
        if Path(attaque.id).name != attaque.id or attaque.id in (".", ".."):
            obtenir_logger().warn(f"Attaque perso ignorée (id invalide) : {attaque.id!r}")
            continue
        attaques.append(attaque)
    return attaques


def enregistrer_attaque_utilisateur(
    brouillon: dict[str, Any],
    chemin: Path | None = None,
) -> AttaqueCatalogue:
    """
    Valide un brouillon et l'ajoute au catalogue personnel (persisté JSON).

    Refuse un identifiant déjà présent — natif OU perso — pour ne jamais
    masquer une attaque native ni créer de doublon. Retourne l'attaque
    validée.
    """
    from .catalogue_attaques import (  # (évite un cycle d'import)  # noqa: PLC0415
        CATALOGUE,
    )
    from .decouverte_ia import (  # (évite un cycle d'import)  # noqa: PLC0415
        commande_dangereuse,
    )

    attaque = brouillon_vers_attaque(brouillon)

    # Garde-fou anti-destruction : `decouvrir_attaques()` et
    # `importer_atomics()` l'appliquent déjà avant d'atteindre ce point --
    # mais `cadre suggest --enregistrer` (et son équivalent dashboard,
    # `enregistrer_brouillon`) appellent CETTE fonction directement, sans
    # jamais passer par ce filtre. Sans ce contrôle, une commande destructrice
    # persisterait dans le catalogue perso et deviendrait éligible à `cadre
    # cycle` en mode réel, dont l'exécution WinRM précède la validation TP/FP
    # -- la validation ne protégerait que le déploiement de la RÈGLE, pas
    # l'exécution déjà jouée de la COMMANDE elle-même.
    motif = commande_dangereuse(attaque.commande)
    if motif:
        raise ErreurCatalogueUtilisateur(
            f"Commande refusée (motif : {motif!r}) — ce brouillon ne sera pas enregistré."
        )

    # Régression (audit sécurité) : `attaque.id` est utilisé tel quel dans
    # un nom de fichier de règle (`orchestrateur.py`, `repertoire_regles /
    # f"{attaque.id}.yml"`). Avec pathlib, joindre une chaîne "rootée" via
    # l'opérateur `/` REMPLACE le préfixe au lieu de le concaténer -- un id
    # commençant par `/` ou `\` contourne donc entièrement
    # `repertoire_regles`. Vecteur concret : un dépôt Atomic Red Team
    # importé (`atomic_vers_brouillon` dérive l'id du champ YAML
    # `attack_technique`, une source explicitement non fiable) pourrait
    # forger un id de ce type. `Path(attaque.id).name` isole le dernier
    # composant : différent de l'id d'origine si celui-ci contient un
    # séparateur de chemin. Cas à part : `attaque.id == ".."` a pour `.name`
    # ".." lui-même (pathlib ne le réduit pas), donc ce test seul ne le
    # rejette pas -- vérifié par échec réel du test avant cet ajout.
    if Path(attaque.id).name != attaque.id or attaque.id in (".", ".."):
        raise ErreurCatalogueUtilisateur(
            f"Identifiant {attaque.id!r} invalide — ne doit contenir aucun séparateur " "de chemin."
        )

    ids_natifs = {a.id for a in CATALOGUE}
    if attaque.id in ids_natifs:
        raise ErreurCatalogueUtilisateur(
            f"L'identifiant {attaque.id} existe déjà dans le catalogue natif — "
            "choisissez-en un autre."
        )

    cible = chemin or CHEMIN_CATALOGUE_PERSO
    with _verrou_catalogue_perso:
        existantes = charger_attaques_utilisateur(cible)
        if any(a.id == attaque.id for a in existantes):
            raise ErreurCatalogueUtilisateur(
                f"L'identifiant {attaque.id} est déjà dans votre catalogue personnel."
            )

        cible.parent.mkdir(parents=True, exist_ok=True)
        donnees = [_attaque_vers_dict(a) for a in [*existantes, attaque]]
        cible.write_text(json.dumps(donnees, indent=2, ensure_ascii=False), encoding="utf-8")
    obtenir_logger().success(
        f"Attaque perso enregistrée : {attaque.id} ({attaque.technique_mitre})"
    )
    return attaque


def _attaque_vers_dict(attaque: AttaqueCatalogue) -> dict[str, Any]:
    """Sérialise une attaque en dict JSON (enums → leur valeur str)."""
    from dataclasses import asdict  # noqa: PLC0415

    d = asdict(attaque)
    d["niveau_risque"] = attaque.niveau_risque.value
    d["plateforme"] = attaque.plateforme.value
    return d
