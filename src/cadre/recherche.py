# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Recherche par mot-clé dans le catalogue et Atomic Red Team
====================================================================

Le catalogue natif/perso et `cadre atomic` n'offraient jusqu'ici qu'une
recherche par ID/technique MITRE EXACTE (`obtenir_attaque`,
`obtenir_par_technique`, `--technique`). Ce module ajoute une recherche par
mot-clé en langage naturel (nom d'attaque, description), pour répondre à
« je décris une attaque ou donne son nom, CADRE la trouve tout seul ».

Volontairement simple (sous-chaîne insensible à la casse, pas de score de
pertinence sophistiqué) — cohérent avec la philosophie déterministe du
projet, pas de dépendance de fuzzy-matching externe.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .catalogue_attaques import AttaqueCatalogue, catalogue_actif


def rechercher_catalogue(
    mot_cle: str, catalogue: list[AttaqueCatalogue] | None = None
) -> list[AttaqueCatalogue]:
    """Sous-chaîne insensible à la casse sur nom, technique MITRE, puis
    description (ordre de priorité, tri stable). `catalogue_actif()`
    (natif + perso) par défaut."""
    source = catalogue if catalogue is not None else catalogue_actif()
    mc = mot_cle.lower()

    def priorite(a: AttaqueCatalogue) -> int:
        if mc in a.nom.lower():
            return 0
        if mc in a.technique_mitre.lower():
            return 1
        return 2

    resultats = [
        a
        for a in source
        if mc in a.nom.lower() or mc in a.technique_mitre.lower() or mc in a.description.lower()
    ]
    return sorted(resultats, key=priorite)


def rechercher_atomic(mot_cle: str, repertoire: Path | None = None) -> dict[str, Any]:
    """Recherche par mot-clé dans Atomic Red Team -- réutilise
    `importer_atomics()` (même filtre de sécurité, jamais de commande
    dangereuse en résultat) puis filtre son bilan par mot-clé sur
    nom/technique/description."""
    from .atomic_red_team import importer_atomics  # noqa: PLC0415

    rapport = importer_atomics(repertoire)
    mc = mot_cle.lower()

    retenus = [
        b
        for b in rapport["retenus"]
        if mc in str(b.get("nom", "")).lower()
        or mc in str(b.get("technique_mitre", "")).lower()
        or mc in str(b.get("description", "")).lower()
    ]
    refuses = [
        r
        for r in rapport["refuses"]
        if mc in str(r.get("nom", "")).lower() or mc in str(r.get("technique", "")).lower()
    ]
    return {"retenus": retenus, "refuses": refuses, "total_lus": rapport["total_lus"]}


def rechercher_attaques(
    mot_cle: str,
    inclure_atomic: bool = False,
    repertoire_atomic: Path | None = None,
) -> dict[str, Any]:
    """Combine catalogue et (optionnellement) Atomic Red Team.

    Returns:
        {"catalogue": [AttaqueCatalogue, ...],
         "atomic_red_team": [brouillon avec 'deja_importe': bool, ...],
         "atomic_refuses": [...], "trouve": bool}
    """
    catalogue_actuel = catalogue_actif()
    resultats_catalogue = rechercher_catalogue(mot_cle, catalogue_actuel)

    atomics_avec_statut: list[dict[str, Any]] = []
    atomic_refuses: list[dict[str, Any]] = []
    if inclure_atomic:
        ids_actifs = {a.id for a in catalogue_actuel}
        resultat_atomic = rechercher_atomic(mot_cle, repertoire_atomic)
        atomics_avec_statut = [
            {**b, "deja_importe": b.get("id") in ids_actifs} for b in resultat_atomic["retenus"]
        ]
        atomic_refuses = resultat_atomic["refuses"]

    return {
        "catalogue": resultats_catalogue,
        "atomic_red_team": atomics_avec_statut,
        "atomic_refuses": atomic_refuses,
        "trouve": bool(resultats_catalogue) or bool(atomics_avec_statut),
    }
