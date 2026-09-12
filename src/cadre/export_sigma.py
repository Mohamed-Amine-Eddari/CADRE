# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Export des règles au format SigmaHQ (partage / contribution)
====================================================================

Génère, pour chaque attaque du catalogue, sa règle Sigma déterministe et
l'écrit dans un répertoire d'export propre, accompagné d'un index Markdown.
Le résultat est un jeu de règles Sigma standard, directement partageable
(contribution open-source, import dans un autre outil, revue par un pair).

Aucune dépendance au réseau : l'export ne fait que générer et écrire des
fichiers YAML — il fonctionne hors ligne, sans VM ni SIEM.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from .catalogue_attaques import CATALOGUE
from .logger import obtenir_logger


def exporter_regles_sigma(repertoire_sortie: Path) -> dict[str, Any]:
    """
    Exporte toutes les règles du catalogue natif au format Sigma (un fichier
    `.yml` par attaque) plus un `index.md` récapitulatif.

    Args:
        repertoire_sortie: dossier de destination (créé si absent).

    Returns:
        {"nb": int, "repertoire": str, "regles": [{"id","technique","tactique","fichier"}]}
    """
    # Import différé : évite un cycle d'import (orchestrateur importe rapport,
    # qui n'a pas à dépendre d'export au chargement) et n'instancie le moteur
    # que lorsqu'on exporte réellement.
    from .compilation_sigma import (  # noqa: PLC0415
        FORMATS_SORTIE,
        compiler_regles_multi,
    )
    from .orchestrateur import OrchestrateurCADRE  # noqa: PLC0415

    log = obtenir_logger()
    repertoire_sortie.mkdir(parents=True, exist_ok=True)
    orchestrateur = OrchestrateurCADRE()

    exportees: list[dict[str, str]] = []
    regles_yaml: list[str] = []
    for attaque in CATALOGUE:
        # La génération déterministe est prouvée : les 68 règles compilent.
        regle_yaml = orchestrateur.generer_regle_sigma_depuis_attaque(attaque, {})
        regles_yaml.append(regle_yaml)
        chemin = repertoire_sortie / f"{attaque.id}.yml"
        chemin.write_text(regle_yaml, encoding="utf-8")
        exportees.append(
            {
                "id": attaque.id,
                "technique": attaque.technique_mitre,
                "tactique": attaque.tactique_mitre,
                "fichier": chemin.name,
            }
        )

    # Compilation MULTI-FORMAT (multi-SIEM) : en plus des YAML Sigma, on produit
    # les requêtes prêtes à l'emploi — dont le bundle Kibana importable en un clic.
    formats_produits: list[dict[str, str]] = []
    for nom, (_of, fichier, description, _mode) in FORMATS_SORTIE.items():
        contenu = compiler_regles_multi(regles_yaml, nom)
        if contenu:
            (repertoire_sortie / fichier).write_text(contenu, encoding="utf-8")
            formats_produits.append({"format": nom, "fichier": fichier, "description": description})

    index = [
        "# Règles Sigma générées par CADRE",
        "",
        f"*Export du {datetime.now().strftime('%d/%m/%Y %H:%M')} — "
        f"{len(exportees)} règles, générées de façon déterministe depuis le "
        "catalogue MITRE ATT&CK de CADRE.*",
        "",
        "Chaque règle est au format [Sigma](https://github.com/SigmaHQ/sigma) "
        "standard et peut être compilée vers Elasticsearch, Splunk, "
        "Microsoft Sentinel, etc. via `pysigma`.",
        "",
    ]
    if formats_produits:
        index += [
            "## Formats prêts à l'emploi (multi-SIEM)",
            "",
            "En plus des règles Sigma sources, l'export contient les requêtes " "compilées :",
            "",
            "| Format | Fichier | Usage |",
            "|--------|---------|-------|",
        ]
        for f in formats_produits:
            index.append(f"| {f['format']} | `{f['fichier']}` | {f['description']} |")
        index += [
            "",
            "> **Kibana** : importez `cadre_kibana_import.ndjson` via "
            "*Security → Rules → Import* pour déployer toutes les détections d'un coup.",
            "",
        ]
    index += [
        "## Règles sources (Sigma)",
        "",
        "| ID | Technique | Tactique | Fichier |",
        "|----|-----------|----------|---------|",
    ]
    for e in sorted(exportees, key=lambda x: x["id"]):
        index.append(f"| {e['id']} | {e['technique']} | {e['tactique']} | `{e['fichier']}` |")
    index.append("")
    (repertoire_sortie / "index.md").write_text("\n".join(index), encoding="utf-8")

    log.success(
        f"{len(exportees)} règles Sigma + {len(formats_produits)} format(s) "
        f"multi-SIEM exportés dans {repertoire_sortie}"
    )
    return {
        "nb": len(exportees),
        "repertoire": str(repertoire_sortie),
        "regles": exportees,
        "formats": formats_produits,
    }
