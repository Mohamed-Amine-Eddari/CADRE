# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Raffinement de règle en place
======================================

Permet d'ajuster les paramètres de détection d'une attaque EXISTANTE du
catalogue (native ou personnelle) sans créer une nouvelle entrée — la même
attaque, avec une valeur de corrélation ou un seuil de bruit affinés.
Combiné au déploiement idempotent (`rule_id_stable`, voir B7 dans
`PLAN/JALON5.md`), le prochain cycle sur cette attaque met à jour la MÊME
règle Kibana en place ; il ne la duplique jamais.

Volontairement restreint aux paramètres de DÉTECTION/BRUIT
(`valeur_detection`, `seuil_fp_max`, `faux_positifs_connus`) — un
raffinement affine une règle existante, il n'en invente pas une nouvelle :
l'identité de l'attaque (id, commande, technique MITRE...) n'est jamais
modifiable par ce mécanisme.

Stockage : `~/.cadre/raffinements.json` (dict `{attaque_id: {champ: valeur}}`),
à côté du catalogue personnel. Chemin surchargeable par les tests (isolation).
"""

from __future__ import annotations

import dataclasses
import json
import threading
from pathlib import Path
from typing import Any

from .catalogue_attaques import AttaqueCatalogue
from .logger import obtenir_logger

# Surchargé par les tests (isolation) — défaut : à côté du coffre-fort.
CHEMIN_RAFFINEMENTS = Path.home() / ".cadre" / "raffinements.json"

# Même raisonnement que revue_regles._verrou_revues : protège le cycle
# lecture-modification-écriture contre les races intra-processus (CLI et
# dashboard partagent le même fichier ; aujourd'hui atteint uniquement
# depuis le premier plan du dashboard, mais rien ne garantit qu'un futur
# chemin d'écriture en arrière-plan ne s'y ajoute pas). RLock : les
# fonctions d'écriture rappellent charger_raffinements en tenant déjà le
# verrou.
_verrou_raffinements = threading.RLock()

_CHAMPS_RAFFINABLES = frozenset({"valeur_detection", "seuil_fp_max", "faux_positifs_connus"})


class ErreurRaffinement(Exception):
    """Raffinement invalide (champ non autorisé, valeur incompatible)."""


def charger_raffinements(chemin: Path | None = None) -> dict[str, dict[str, Any]]:
    """Charge les raffinements enregistrés. Retourne un dict vide si le
    fichier n'existe pas ou est illisible/mal formé (jamais une exception)."""
    cible = chemin or CHEMIN_RAFFINEMENTS
    with _verrou_raffinements:
        if not cible.is_file():
            return {}
        try:
            brut = json.loads(cible.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            obtenir_logger().warn(f"Fichier de raffinements illisible ({cible}) : {e}")
            return {}
    if not isinstance(brut, dict):
        obtenir_logger().warn(f"Fichier de raffinements mal formé (attendu: objet) : {cible}")
        return {}
    return brut


def enregistrer_raffinement(
    attaque_id: str,
    champs: dict[str, Any],
    chemin: Path | None = None,
) -> None:
    """Valide et persiste un raffinement pour une attaque existante.

    Lève `ErreurRaffinement` si un champ non autorisé est demandé, ou si
    `seuil_fp_max` n'est pas un entier strictement positif. Ne vérifie PAS
    que `attaque_id` existe dans le catalogue — reste indépendant pour
    éviter tout cycle d'import ; l'appelant (CLI) vérifie en amont.
    """
    inconnus = set(champs) - _CHAMPS_RAFFINABLES
    if inconnus:
        raise ErreurRaffinement(
            f"Champ(s) non raffinable(s) : {', '.join(sorted(inconnus))} "
            f"(autorisés : {', '.join(sorted(_CHAMPS_RAFFINABLES))})"
        )
    if "seuil_fp_max" in champs and champs["seuil_fp_max"] is not None:
        seuil = champs["seuil_fp_max"]
        if not isinstance(seuil, int) or isinstance(seuil, bool) or seuil <= 0:
            raise ErreurRaffinement("seuil_fp_max doit être un entier strictement positif")

    cible = chemin or CHEMIN_RAFFINEMENTS
    with _verrou_raffinements:
        tous = charger_raffinements(cible)
        tous.setdefault(attaque_id, {}).update(champs)
        cible.parent.mkdir(parents=True, exist_ok=True)
        cible.write_text(json.dumps(tous, indent=2, ensure_ascii=False), encoding="utf-8")
    obtenir_logger().success(f"Raffinement enregistré pour {attaque_id} : {champs}")


def supprimer_raffinement(attaque_id: str, chemin: Path | None = None) -> bool:
    """Retire un raffinement (retour à la définition catalogue d'origine).
    Retourne True si quelque chose a effectivement été supprimé."""
    cible = chemin or CHEMIN_RAFFINEMENTS
    with _verrou_raffinements:
        tous = charger_raffinements(cible)
        if attaque_id not in tous:
            return False
        del tous[attaque_id]
        cible.write_text(json.dumps(tous, indent=2, ensure_ascii=False), encoding="utf-8")
    obtenir_logger().success(f"Raffinement retiré pour {attaque_id} (retour à l'original)")
    return True


def appliquer_raffinements(
    attaques: list[AttaqueCatalogue],
    chemin: Path | None = None,
) -> list[AttaqueCatalogue]:
    """Applique les raffinements enregistrés à une liste d'attaques :
    même `id`, mêmes commande/technique/EventIDs -- seuls les champs de
    détection/bruit changent (`dataclasses.replace`). Jamais de nouvelle
    entrée. Un champ inconnu dans le fichier (édité à la main, version
    antérieure) est ignoré avec un avertissement plutôt que de faire
    planter le chargement de tout le catalogue.
    """
    raffinements = charger_raffinements(chemin)
    if not raffinements:
        return attaques

    resultat = []
    for attaque in attaques:
        champs = raffinements.get(attaque.id)
        if not champs:
            resultat.append(attaque)
            continue
        champs_valides = {k: v for k, v in champs.items() if k in _CHAMPS_RAFFINABLES}
        ignores = set(champs) - _CHAMPS_RAFFINABLES
        if ignores:
            obtenir_logger().warn(
                f"Raffinement de {attaque.id} : champ(s) ignoré(s) (non raffinable) : "
                f"{', '.join(sorted(ignores))}"
            )
        resultat.append(
            dataclasses.replace(attaque, **champs_valides) if champs_valides else attaque
        )
    return resultat
