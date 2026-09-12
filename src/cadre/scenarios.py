# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Scénarios d'adversaire (kill chains)
============================================

Un *scénario* enchaîne plusieurs attaques du catalogue dans l'ordre d'une
vraie campagne d'attaque (une « kill chain » MITRE ATT&CK), au lieu de
tester des techniques isolées. C'est ce qui rapproche CADRE d'un outil
d'émulation d'adversaire — mais **de façon déterministe** : chaque scénario
est une liste ordonnée et figée d'attaques déjà présentes dans le catalogue,
donc reproductible à l'identique, contrairement à un planificateur autonome.

Différence clé avec un émulateur classique (type Caldera) : après avoir joué
la chaîne, CADRE **génère, valide (TP/FP) et déploie** la détection de chaque
étape, puis mesure la **couverture de la kill chain** — combien de phases sont
effectivement détectées, et où sont les angles morts. C'est la valeur que
l'émulation seule n'apporte pas.

Usage :
    from cadre.scenarios import SCENARIOS, obtenir_scenario, attaques_ordonnees
    scenario = obtenir_scenario("RANSOMWARE")
    for attaque in attaques_ordonnees(scenario):
        ...
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .catalogue_attaques import AttaqueCatalogue, obtenir_attaque

# Statuts d'un résultat qui comptent comme « étape détectée » dans la kill
# chain : une règle a été générée ET validée (TP/FP) — ou, en simulation, sa
# syntaxe est valide. EN_ATTENTE_REVUE (cadre cycle --revue) est le même cas
# que VALIDE_NON_DEPLOYE : la règle est prouvée (TP/FP passés), seul le
# déploiement Kibana est différé -- ici volontairement (revue humaine) plutôt
# que par échec technique. Tout le reste (angle mort, rejet, erreur, non
# applicable) est une phase NON couverte.
STATUTS_DETECTES = frozenset({"VALIDE", "VALIDE_NON_DEPLOYE", "SIMULE", "EN_ATTENTE_REVUE"})

# Statuts comptant comme « phase de kill chain RÉELLEMENT détectée » pour
# `analyser_kill_chain`/le rapport kill chain dédié (régression, audit) --
# volontairement PLUS STRICT que STATUTS_DETECTES : ce rapport affirme
# explicitement « chaque phase déclenche une détection VALIDÉE »
# (rapport.py::generer_rapport_kill_chain), une affirmation qui ne tient que
# si la détection a réellement été prouvée contre de la télémétrie (TP/FP
# mesurés) -- jamais sur la seule foi d'une syntaxe Sigma qui compile
# (SIMULE, `cadre scenario --simulate`, aucune attaque exécutée, aucune
# mesure). Sans cette distinction, un scénario entièrement simulé affichait
# « 100% de couverture, kill chain entièrement couverte » -- couverture
# surestimée, aucune preuve réelle derrière le chiffre.
STATUTS_DETECTES_KILL_CHAIN = STATUTS_DETECTES - {"SIMULE"}


@dataclass(frozen=True)
class ScenarioAdversaire:
    """Une chaîne d'attaque ordonnée émulant un profil d'adversaire réel."""

    id: str
    nom: str
    adversaire: str  # profil émulé, ex. « Opérateur de ransomware »
    description: str
    plateforme: str  # "windows" | "linux" — homogénéité de la cible
    attaque_ids: list[str]  # IDs catalogue, DANS L'ORDRE de la kill chain
    reference: str = ""  # lien MITRE / plan d'émulation de référence
    tags: list[str] = field(default_factory=list)


# =============================================================================
# SCÉNARIOS — chaque étape est une attaque EXISTANTE du catalogue (déterministe)
# =============================================================================

SCENARIOS: list[ScenarioAdversaire] = [
    ScenarioAdversaire(
        id="RANSOMWARE",
        nom="Opération ransomware (chaîne complète)",
        adversaire="Opérateur de ransomware (type Conti / LockBit)",
        description=(
            "Kill chain complète d'un ransomware : exécution initiale, "
            "reconnaissance de l'hôte, vol d'identifiants, collecte des "
            "données, effacement des traces, puis impact destructeur. "
            "Le scénario emblématique pour démontrer la couverture de "
            "détection de bout en bout."
        ),
        plateforme="windows",
        attaque_ids=[
            "CADRE-EXE-002",  # Execution — script initial
            "CADRE-DIS-001",  # Discovery — reconnaissance système
            "CADRE-DIS-003",  # Discovery — processus en cours
            "CADRE-CRE-002",  # Credential Access — dump LSASS
            "CADRE-COL-001",  # Collection — données locales
            "CADRE-IMP-001",  # Defense Evasion — effacement des traces
            "CADRE-IMP-002",  # Impact — destruction de données
        ],
        reference="https://attack.mitre.org/software/",
        tags=["ransomware", "impact", "kill-chain-complete"],
    ),
    ScenarioAdversaire(
        id="VOL_IDENTIFIANTS",
        nom="Campagne de vol d'identifiants",
        adversaire="Acteur d'espionnage (type APT29)",
        description=(
            "Un attaquant furtif qui exécute du code, cartographie le "
            "réseau et les comptes, moissonne des identifiants (mémoire "
            "LSASS + fichiers), puis exfiltre discrètement. Démontre la "
            "détection d'une intrusion orientée credential harvesting."
        ),
        plateforme="windows",
        attaque_ids=[
            "CADRE-EXE-002",  # Execution
            "CADRE-DIS-002",  # Discovery — configuration réseau
            "CADRE-DIS-004",  # Discovery — comptes du domaine
            "CADRE-CRE-002",  # Credential Access — LSASS
            "CADRE-CRE-003",  # Credential Access — identifiants en fichiers
            "CADRE-EXF-001",  # Exfiltration — canal alternatif
        ],
        reference="https://attack.mitre.org/groups/G0016/",
        tags=["apt", "credential-access", "exfiltration"],
    ),
    ScenarioAdversaire(
        id="RECONNAISSANCE",
        nom="Reconnaissance approfondie de l'hôte",
        adversaire="Attaquant en phase de découverte post-compromission",
        description=(
            "La phase de reconnaissance qui suit un accès initial : "
            "l'attaquant cartographie méthodiquement l'hôte (système, "
            "réseau, processus, connexions, comptes, utilisateur courant) "
            "avant de choisir sa prochaine action. Chaîne 100 % Discovery, "
            "idéale pour valider la couverture de cette tactique souvent "
            "sous-détectée."
        ),
        plateforme="windows",
        attaque_ids=[
            "CADRE-DIS-001",  # System information
            "CADRE-DIS-002",  # Network configuration
            "CADRE-DIS-003",  # Process discovery
            "CADRE-DIS-005",  # Network connections
            "CADRE-DIS-009",  # System owner/user
            "CADRE-DIS-004",  # Account discovery
        ],
        reference="https://attack.mitre.org/tactics/TA0007/",
        tags=["discovery", "reconnaissance"],
    ),
    ScenarioAdversaire(
        id="INTRUSION_LINUX",
        nom="Intrusion Linux (reconnaissance + credential access)",
        adversaire="Attaquant sur serveur Linux compromis",
        description=(
            "Kill chain multi-OS côté Linux : exécution shell, "
            "reconnaissance (système, processus, comptes), accès aux "
            "identifiants (/etc/shadow), puis impact. Démontre que la "
            "détection CADRE couvre aussi les cibles Linux via Auditbeat."
        ),
        plateforme="linux",
        attaque_ids=[
            "CADRE-LIN-001",  # Execution — shell
            "CADRE-LIN-005",  # Discovery — système
            "CADRE-LIN-007",  # Discovery — processus
            "CADRE-LIN-011",  # Discovery — comptes
            "CADRE-LIN-017",  # Credential Access — /etc/shadow
            "CADRE-LIN-019",  # Impact — destruction de données
        ],
        reference="https://attack.mitre.org/matrices/enterprise/linux/",
        tags=["linux", "multi-os", "kill-chain"],
    ),
]


def obtenir_scenario(identifiant: str) -> ScenarioAdversaire | None:
    """Récupère un scénario par son identifiant (insensible à la casse)."""
    cible = identifiant.strip().upper()
    return next((s for s in SCENARIOS if s.id == cible), None)


def attaques_ordonnees(scenario: ScenarioAdversaire) -> list[AttaqueCatalogue]:
    """Résout les IDs du scénario en objets attaque, DANS L'ORDRE de la chaîne.

    Ignore silencieusement un ID absent du catalogue — `valider_scenarios()`
    est le garde-fou qui garantit qu'il n'y en a pas ; ici on reste tolérant
    pour ne jamais faire planter un run à cause d'un ID mal orthographié.
    """
    attaques = []
    for attaque_id in scenario.attaque_ids:
        attaque = obtenir_attaque(attaque_id)
        if attaque is not None:
            attaques.append(attaque)
    return attaques


def valider_scenarios() -> list[str]:
    """Vérifie que chaque ID référencé existe dans le catalogue.

    Retourne la liste des références cassées (`SCENARIO/ID`) — vide si tout
    est cohérent. Utilisé par les tests pour éviter un scénario qui pointe
    vers une attaque supprimée ou mal nommée.
    """
    casses = []
    for scenario in SCENARIOS:
        for attaque_id in scenario.attaque_ids:
            if obtenir_attaque(attaque_id) is None:
                casses.append(f"{scenario.id}/{attaque_id}")
    return casses


def analyser_kill_chain(
    scenario: ScenarioAdversaire,
    resultats: list[dict[str, Any]],
    mode_simulation: bool = False,
) -> dict[str, Any]:
    """Analyse la couverture de détection d'une kill chain exécutée.

    Reconstitue l'ordre du scénario à partir des résultats (indexés par ID
    d'attaque), calcule pour chaque étape si elle est détectée, et agrège la
    couverture globale. C'est le cœur du livrable « meilleur que l'émulation
    seule » : on ne dit pas juste « la chaîne a été jouée », on dit « X/N
    phases détectées, voici les angles morts ».

    `mode_simulation` (transmis tel quel dans le résultat, sous
    `"mode_simulation"`) n'affecte AUCUN calcul ici -- `detectee` utilise
    déjà `STATUTS_DETECTES_KILL_CHAIN`, qui exclut SIMULE. Il sert
    uniquement à ce que le rapport kill chain (`rapport.py`) puisse afficher
    clairement qu'un run simulé n'a mesuré AUCUNE détection réelle, pour ne
    jamais laisser un 0% de couverture simulé se lire comme un vrai échec.
    """
    par_id = {r.get("id"): r for r in resultats}
    etapes: list[dict[str, Any]] = []
    for position, attaque in enumerate(attaques_ordonnees(scenario), 1):
        resultat = par_id.get(attaque.id, {})
        statut = str(resultat.get("statut") or "NON_EXECUTE")
        etapes.append(
            {
                "position": position,
                "id": attaque.id,
                "nom": attaque.nom,
                "technique_mitre": attaque.technique_mitre,
                "tactique": attaque.tactique_mitre,
                "statut": statut,
                "detectee": statut in STATUTS_DETECTES_KILL_CHAIN,
                "raison": resultat.get("raison", ""),
            }
        )

    total = len(etapes)
    detectees = sum(1 for e in etapes if e["detectee"])
    return {
        "scenario_id": scenario.id,
        "scenario_nom": scenario.nom,
        "adversaire": scenario.adversaire,
        "plateforme": scenario.plateforme,
        "total_etapes": total,
        "etapes_detectees": detectees,
        "etapes_angle_mort": total - detectees,
        "couverture_pct": round(100 * detectees / total, 1) if total else 0.0,
        "etapes": etapes,
        "mode_simulation": mode_simulation,
    }
