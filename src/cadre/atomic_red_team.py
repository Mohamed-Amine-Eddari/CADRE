# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Ingestion Atomic Red Team (source d'attaques communautaire)
===================================================================

Atomic Red Team (Red Canary) est une **bibliothèque** d'environ 1600 tests
d'attaque (« atomics ») au format YAML, chacun mappé à une technique MITRE
ATT&CK. Ce module la branche comme **source d'attaques** de CADRE : il lit les
YAML, en extrait la commande, et les convertit au modèle CADRE
(`AttaqueCatalogue`) pour qu'ils passent EXACTEMENT le même pipeline que les
attaques natives (exécution → télémétrie → règle Sigma → double validation
TP/FP → déploiement).

Différence clé avec « juste lancer les atomics » — les 3 garde-fous de CADRE,
réutilisés tels quels :

1. **Filtre de sécurité** (`commande_dangereuse`, partagé avec l'agent IA) :
   Atomic Red Team contient des tests DESTRUCTEURS (chiffrement, effacement,
   arrêt machine…). Tout atomic dont la commande correspond à la denylist est
   REFUSÉ avant toute exécution. Cohérent avec la contrainte labo non-destructif.
2. **Plateforme** : seuls les atomics `windows`/`linux` automatisables (executor
   non-`manual`) sont retenus ; le reste est ignoré, jamais deviné.
3. **Barrière de validation** : un atomic importé ne « compte » que s'il passe
   la double validation TP/FP du pipeline — la source ne décide jamais seule.

C'est ce qui distingue l'intégration « à la manière CADRE » d'un simple
lanceur d'atomics : CADRE ne fait pas confiance à la source, il l'homologue.

Usage :
    from cadre.atomic_red_team import importer_atomics, repertoire_exemple
    rapport = importer_atomics(repertoire_exemple())
    for b in rapport["retenus"]:
        ...  # brouillon prêt pour brouillon_vers_attaque()
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .catalogue_attaques import CATALOGUE, Plateforme
from .decouverte_ia import commande_dangereuse
from .logger import obtenir_logger

# Répertoire d'exemples embarqué : un petit jeu d'atomics au vrai format ART,
# pour que la fonctionnalité marche sans cloner le dépôt complet. Pointer
# `--repo` vers un checkout d'Atomic Red Team (dossier `atomics/`) donne accès
# aux ~1600 tests.
_REPERTOIRE_EXEMPLE = Path(__file__).parent / "data" / "atomics_exemple"

# Plateformes ART -> plateforme CADRE. macos/office-365/azure-ad/... = ignorés
# (CADRE cible Windows via WinRM et Linux via SSH uniquement).
_PLATEFORME_ART: dict[str, Plateforme] = {
    "windows": Plateforme.WINDOWS,
    "linux": Plateforme.LINUX,
}

# Executors automatisables. `manual` = pas de commande exécutable -> ignoré.
_EXECUTORS_AUTO = frozenset({"command_prompt", "powershell", "sh", "bash"})

# Mots trop génériques pour servir de valeur de détection distinctive.
_MOTS_BANALS = frozenset(
    {
        "powershell",
        "cmd",
        "exe",
        "the",
        "and",
        "for",
        "get",
        "set",
        "new",
        "true",
        "false",
        "null",
        "echo",
        "bash",
        "sh",
        "sudo",
        "http",
        "https",
        "com",
        "org",
        "net",
        "www",
        "test",
        "temp",
        "path",
        "file",
        "name",
    }
)

# Technique MITRE -> tactique, dérivé du catalogue natif (source de vérité) et
# complété pour quelques techniques fréquentes d'Atomic Red Team absentes du
# catalogue. Un atomic dont la technique est inconnue reçoit "Execution" par
# défaut (le cas le plus courant) — jamais bloquant.
_TECHNIQUE_TACTIQUE: dict[str, str] = {a.technique_mitre: a.tactique_mitre for a in CATALOGUE}
_TECHNIQUE_TACTIQUE.update(
    {
        "T1059": "Execution",
        "T1059.001": "Execution",
        "T1059.003": "Execution",
        "T1059.004": "Execution",
        "T1105": "Command and Control",
        "T1547.001": "Persistence",
        "T1053.005": "Persistence",
        "T1112": "Defense Evasion",
        "T1486": "Impact",
    }
)
_TACTIQUE_DEFAUT = "Execution"


@dataclass(frozen=True)
class TestAtomic:
    """Un atomic parsé et normalisé (une entrée de `atomic_tests`)."""

    technique_mitre: str
    nom: str
    description: str
    plateforme: Plateforme
    executor: str
    commande: str
    elevation_requise: bool = False
    cleanup: str = ""
    guid: str = ""


def repertoire_exemple() -> Path:
    """Répertoire d'atomics d'exemple embarqué (défaut de `--repo`)."""
    return _REPERTOIRE_EXEMPLE


def tactique_pour_technique(technique: str) -> str:
    """Tactique MITRE d'une technique (catalogue natif + carte ART), avec défaut."""
    return _TECHNIQUE_TACTIQUE.get(
        technique, _TECHNIQUE_TACTIQUE.get(technique.split(".", 1)[0], _TACTIQUE_DEFAUT)
    )


def interpoler_arguments(commande: str, input_arguments: dict[str, Any]) -> str:
    """Remplace les `#{arg}` d'une commande atomic par la valeur `default` de
    l'argument (mécanique d'Atomic Red Team). Un `#{arg}` sans défaut connu est
    laissé tel quel — inoffensif pour la détection sur le texte de commande."""
    if not input_arguments:
        return commande

    def _remplacer(m: re.Match[str]) -> str:
        nom = m.group(1)
        arg = input_arguments.get(nom)
        if isinstance(arg, dict) and arg.get("default") is not None:
            return str(arg["default"])
        return m.group(0)

    return re.sub(r"#\{([^}]+)\}", _remplacer, commande)


def deriver_valeur_detection(commande: str) -> str | None:
    """Extrait un jeton distinctif de la commande pour la corrélation de détection.

    Heuristique : le plus long jeton « mot » (lettres/chiffres/._-) d'au moins
    5 caractères qui n'est pas un mot banal. Analogue à la façon dont le
    catalogue natif corrèle sur une valeur réelle déjà présente dans la
    commande. None si rien de distinctif — la règle retombe alors sur
    `event.code` seul.
    """
    jetons = re.findall(r"[A-Za-z0-9][A-Za-z0-9._\-]{4,}", commande)
    candidats = [j for j in jetons if j.lower() not in _MOTS_BANALS]
    if not candidats:
        return None
    return max(candidats, key=len)


def parser_fichier_atomic(chemin: Path) -> list[TestAtomic]:
    """Parse un fichier YAML Atomic Red Team en une liste de `TestAtomic`.

    Tolérant : un test mal formé, sans executor automatisable, ou multi-
    plateforme non supportée est ignoré silencieusement (pas d'exception) —
    l'objectif est d'ingérer un dépôt réel et hétérogène sans planter.
    """
    try:
        donnees = yaml.safe_load(chemin.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as e:
        obtenir_logger().warn(f"Atomic illisible ({chemin.name}) : {e}")
        return []
    if not isinstance(donnees, dict):
        return []

    technique = str(donnees.get("attack_technique", "")).strip()
    tests_bruts = donnees.get("atomic_tests")
    if not technique or not isinstance(tests_bruts, list):
        return []

    tests: list[TestAtomic] = []
    for brut in tests_bruts:
        if not isinstance(brut, dict):
            continue
        executor = brut.get("executor")
        if not isinstance(executor, dict):
            continue
        nom_exec = str(executor.get("name", "")).strip().lower()
        commande = executor.get("command")
        if nom_exec not in _EXECUTORS_AUTO or not commande:
            continue  # manual / sans commande -> non automatisable

        plateformes = brut.get("supported_platforms") or []
        plateforme = next(
            (
                _PLATEFORME_ART[str(p).lower()]
                for p in plateformes
                if str(p).lower() in _PLATEFORME_ART
            ),
            None,
        )
        if plateforme is None:
            continue  # macos / cloud / etc. -> hors cible CADRE

        commande_finale = interpoler_arguments(
            str(commande).strip(), brut.get("input_arguments") or {}
        )
        tests.append(
            TestAtomic(
                technique_mitre=technique,
                nom=str(brut.get("name", "")).strip() or technique,
                description=str(brut.get("description", "")).strip(),
                plateforme=plateforme,
                executor=nom_exec,
                commande=commande_finale,
                elevation_requise=bool(executor.get("elevation_required", False)),
                cleanup=str(executor.get("cleanup_command", "") or "").strip(),
                guid=str(brut.get("auto_generated_guid", "")).strip(),
            )
        )
    return tests


def charger_atomics(
    repertoire: Path,
    plateformes: set[Plateforme] | None = None,
    techniques: set[str] | None = None,
) -> list[TestAtomic]:
    """Parcourt un dépôt Atomic Red Team (arborescence de `T*/T*.yaml`) et
    retourne tous les atomics automatisables, filtrés par plateforme et/ou
    technique le cas échéant."""
    if not repertoire.is_dir():
        obtenir_logger().warn(f"Répertoire d'atomics introuvable : {repertoire}")
        return []

    tests: list[TestAtomic] = []
    for chemin in sorted(repertoire.rglob("*.yaml")):
        for test in parser_fichier_atomic(chemin):
            if plateformes and test.plateforme not in plateformes:
                continue
            if techniques and test.technique_mitre not in techniques:
                continue
            tests.append(test)
    return tests


def _id_atomic(technique: str, index: int) -> str:
    """Identifiant CADRE stable et lisible pour un atomic importé."""
    technique_plat = technique.replace(".", "")
    return f"CADRE-ART-{technique_plat}-{index}"


def atomic_vers_brouillon(test: TestAtomic, index: int) -> dict[str, Any]:
    """Convertit un `TestAtomic` en brouillon d'attaque CADRE (dict), prêt pour
    `brouillon_vers_attaque()` / `enregistrer_attaque_utilisateur()`.

    Le champ de détection dépend de la cible : `process.command_line` sur
    Windows, `process.title` sur Linux (cohérent avec le reste du catalogue)."""
    linux = test.plateforme == Plateforme.LINUX
    return {
        "id": _id_atomic(test.technique_mitre, index),
        "nom": f"[ART] {test.nom}",
        "description": test.description or test.nom,
        "technique_mitre": test.technique_mitre,
        "tactique_mitre": tactique_pour_technique(test.technique_mitre),
        "sous_technique": None,
        "commande": test.commande,
        "champ_principal": "process.title" if linux else "process.command_line",
        "valeur_detection": deriver_valeur_detection(test.commande),
        "plateforme": test.plateforme.value,
        "references": [
            f"https://attack.mitre.org/techniques/{test.technique_mitre.replace('.', '/')}/",
            "https://github.com/redcanaryco/atomic-red-team",
        ],
    }


def importer_atomics(
    repertoire: Path | None = None,
    plateformes: set[Plateforme] | None = None,
    techniques: set[str] | None = None,
) -> dict[str, Any]:
    """Ingestion complète : charge les atomics, applique le filtre de sécurité,
    convertit les atomics sûrs en brouillons CADRE.

    Returns:
        {
          "retenus":  [brouillon, ...],      # sûrs, convertis
          "refuses":  [{nom, technique, motif}, ...],  # bloqués par la denylist
          "total_lus": int,
        }
    Ne persiste rien et n'exécute rien : c'est une étape pure (l'appelant décide
    d'enregistrer au catalogue ou de lancer le pipeline).
    """
    log = obtenir_logger()
    source = repertoire or repertoire_exemple()
    tests = charger_atomics(source, plateformes=plateformes, techniques=techniques)

    retenus: list[dict[str, Any]] = []
    refuses: list[dict[str, Any]] = []
    compteur_par_technique: dict[str, int] = {}

    for test in tests:
        motif = commande_dangereuse(test.commande)
        if motif:
            log.warn(
                f"Atomic REFUSÉ (commande dangereuse : {motif!r}) : {test.nom}",
                technique=test.technique_mitre,
            )
            refuses.append({"nom": test.nom, "technique": test.technique_mitre, "motif": motif})
            continue
        compteur_par_technique[test.technique_mitre] = (
            compteur_par_technique.get(test.technique_mitre, 0) + 1
        )
        retenus.append(atomic_vers_brouillon(test, compteur_par_technique[test.technique_mitre]))

    log.info(
        f"Atomic Red Team : {len(retenus)} retenu(s), {len(refuses)} refusé(s) "
        f"sur {len(tests)} atomic(s) automatisable(s)",
        source=str(source),
    )
    return {"retenus": retenus, "refuses": refuses, "total_lus": len(tests)}
