# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Revue humaine avant déploiement Kibana
================================================

File d'attente des règles générées (typiquement par l'IA, `cadre decouvrir
--revue`) qui ont passé la double validation TP/FP mais n'ont PAS encore
été déployées dans Kibana — le déploiement automatique et immédiat de
`executer_attaque_complete()` est volontairement interrompu juste avant
`deployer_kibana()` (voir `orchestrateur.executer_attaque_complete`,
paramètre `arreter_avant_deploiement`).

Chaque entrée référence le fichier Sigma déjà écrit sur disque
(`rules_generees/<ID>.yml`) que l'opérateur peut lire/éditer à la main
avant d'approuver (`cadre revue approuver`) ou de rejeter
(`cadre revue rejeter`) le déploiement.

Stockage : `~/.cadre/revues_en_attente.json` (dict `{rule_id_stable:
{...}}`), même famille que `raffinements.json`. Chemin surchargeable par
les tests (isolation). Une entrée est retirée du fichier dès qu'une
décision est prise -- l'audit de la décision elle-même vit dans le log
JSONL (`CADRELogger`), pas dans cet overlay.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from .logger import obtenir_logger

# Surchargé par les tests (isolation) — défaut : à côté du coffre-fort.
CHEMIN_REVUES = Path.home() / ".cadre" / "revues_en_attente.json"

# Protège le cycle lecture-modification-écriture de CHEMIN_REVUES contre les
# races intra-processus : le thread d'arrière-plan d'une découverte IA
# (dashboard.py, demarrer_decouverte) et le thread HTTP qui traite
# /api/revue/approuver ou /api/revue/rejeter peuvent tourner en parallèle et
# écrire ce même fichier -- sans verrou, le classique "dernier écrivain
# gagne" peut faire disparaître silencieusement soit la nouvelle entrée de
# revue, soit la décision d'approbation/rejet. Couvre aussi les lectures
# (charger_revues) : `write_text` n'est pas atomique, une lecture concurrente
# pourrait sinon tomber sur un fichier tronqué en cours d'écriture.
# RLock (pas Lock) : enregistrer_revue/supprimer_revue rappellent
# charger_revues en tenant déjà le verrou -- un Lock simple ferait
# deadlocker le même thread sur sa propre ré-entrée.
_verrou_revues = threading.RLock()

_CHAMPS_REQUIS = frozenset(
    {
        "rule_id_stable",
        "attaque_id",
        "nom_regle",
        "description",
        "technique_mitre",
        "severite",
        "index_pattern",
        "chemin_regle_sigma",
        "requete_lucene_derniere_validation",
        "nb_tp",
        "nb_fp",
    }
)


class ErreurRevue(Exception):
    """Entrée de revue invalide (champ requis manquant)."""


def charger_revues(chemin: Path | None = None) -> dict[str, dict[str, Any]]:
    """Charge les revues en attente. Retourne un dict vide si le fichier
    n'existe pas ou est illisible/mal formé (jamais une exception)."""
    cible = chemin or CHEMIN_REVUES
    with _verrou_revues:
        if not cible.is_file():
            return {}
        try:
            brut = json.loads(cible.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            obtenir_logger().warn(f"Fichier de revues illisible ({cible}) : {e}")
            return {}
    if not isinstance(brut, dict):
        obtenir_logger().warn(f"Fichier de revues mal formé (attendu: objet) : {cible}")
        return {}
    return brut


def obtenir_revue(rule_id_stable: str, chemin: Path | None = None) -> dict[str, Any] | None:
    """Une entrée en attente, ou None si absente."""
    return charger_revues(chemin).get(rule_id_stable)


def lister_revues(chemin: Path | None = None) -> list[dict[str, Any]]:
    """Toutes les entrées en attente, triées par date de création."""
    return sorted(charger_revues(chemin).values(), key=lambda e: e.get("cree_le", ""))


def enregistrer_revue(entree: dict[str, Any], chemin: Path | None = None) -> None:
    """Valide et persiste une entrée de revue.

    Lève `ErreurRevue` si un champ requis manque. `rule_id_stable` est la
    clé de stockage (identité déjà utilisée par `deployer_kibana()`). Si
    une entrée existe déjà pour ce `rule_id_stable` (ré-exécution après
    édition du YAML, par exemple), `cree_le` d'origine est conservé et
    seul `maj_le` avance -- l'entrée garde son ancienneté réelle.
    """
    manquants = _CHAMPS_REQUIS - set(entree)
    if manquants:
        raise ErreurRevue(f"Champ(s) requis manquant(s) : {', '.join(sorted(manquants))}")

    cible = chemin or CHEMIN_REVUES
    with _verrou_revues:
        tous = charger_revues(cible)
        rule_id_stable = entree["rule_id_stable"]
        maintenant = datetime.now().isoformat()

        nouvelle = dict(entree)
        nouvelle["statut"] = "EN_ATTENTE"
        existante = tous.get(rule_id_stable)
        nouvelle["cree_le"] = existante["cree_le"] if existante else maintenant
        nouvelle["maj_le"] = maintenant

        tous[rule_id_stable] = nouvelle
        cible.parent.mkdir(parents=True, exist_ok=True)
        cible.write_text(json.dumps(tous, indent=2, ensure_ascii=False), encoding="utf-8")
    obtenir_logger().success(f"Revue en attente enregistrée : {rule_id_stable}")


def supprimer_revue(rule_id_stable: str, chemin: Path | None = None) -> bool:
    """Retire une entrée (décision prise : approuvée ou rejetée).
    Retourne True si quelque chose a effectivement été supprimé."""
    cible = chemin or CHEMIN_REVUES
    with _verrou_revues:
        tous = charger_revues(cible)
        if rule_id_stable not in tous:
            return False
        del tous[rule_id_stable]
        cible.write_text(json.dumps(tous, indent=2, ensure_ascii=False), encoding="utf-8")
    return True
