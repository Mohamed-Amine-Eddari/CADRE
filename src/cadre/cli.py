# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Interface CLI professionnelle
=====================================

Commandes disponibles :
    cadre init           Initialise la configuration et stocke les secrets
                         dans le coffre-fort (--set, --list)
    cadre cycle          Exécute un cycle d'audit complet
    cadre scenario       Émule une kill chain d'adversaire (couverture par phase)
    cadre atomic         Ingère Atomic Red Team comme source d'attaques (filtrée)
    cadre status         Affiche l'état de la stack
    cadre rapport        Génère les rapports
    cadre list           Liste les attaques du catalogue
    cadre loop           Boucle automatisée avec rotation
    cadre daemon         Mode daemon (PID file)
    cadre metrics        Serveur métriques Prometheus
    cadre dashboard      Dashboard web local (lecture des rapports + démo simulée)
    cadre suggest        Brouillon d'attaque assisté par IA (Ollama)
    cadre decouvrir      Décrit une attaque en langage naturel (ou son nom) et
                         exécute toute la chaîne (--revue pour ne pas déployer
                         directement dans Kibana)
    cadre rechercher     Recherche par mot-clé (catalogue + Atomic Red Team,
                         --decouvrir pour relayer vers l'IA si rien trouvé)
    cadre revue          Règles en attente de revue avant déploiement Kibana
                         (lister, approuver, rejeter)
    cadre regle          Édite une règle DÉJÀ déployée dans Kibana
                         (lire, editer, pousser [--forcer])
    cadre export-sigma   Exporte les règles au format Sigma partageable
    cadre valider-regle  Valide une règle Sigma existante sur VOTRE télémétrie
    cadre secrets-sync-beats
                         Repousse CADRE_ELASTIC_PASS vers winlogbeat/auditbeat
                         après une rotation (sinon la télémétrie s'arrête)
"""

from __future__ import annotations

import contextlib
import csv
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any, NoReturn

# Force UTF-8 stdout on Windows
if sys.platform == "win32":
    try:
        # sys.stdout n'est pas garanti TextIOWrapper (donc pas de .reconfigure()
        # dans les stubs) ; c'est justement ce que le except AttributeError couvre.
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, OSError):
        pass

import click
from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from . import __version__
from .catalogue_attaques import CATALOGUE, catalogue_actif, statistiques_catalogue
from .coffre_fort import ErreurSecurite, obtenir_coffre
from .orchestrateur import (
    OrchestrateurCADRE,
    VerrouCycleActifError,
    _acquerir_verrou_cycle,
    _liberer_verrou_cycle,
    detecter_regles_similaires,
)
from .rapport import _defuse_formule_csv, generer_rapport_soutenance
from .scenarios import SCENARIOS, attaques_ordonnees, obtenir_scenario

# Console partagée par toute la CLI. rich résout sys.stdout paresseusement
# (à chaque .print(), pas à la construction) : sûr à instancier une seule
# fois au niveau module, y compris sous CliRunner qui redirige stdout par
# test. La couleur est désactivée automatiquement hors terminal (tests, CI,
# redirection vers un fichier) — aucun code ANSI ne pollue une sortie captée.
console = Console(highlight=False)
# Console dédiée à stderr pour la sortie DÉCORATIVE (bannière) : garde stdout
# propre pour les sorties de données machine-lisibles (`stats --json`, exports
# redirigés…). Un terminal interactif voit toujours la bannière (stderr est
# affiché) ; un pipe vers jq/fichier ne récupère que les données.
console_err = Console(stderr=True, highlight=False)

# Palette CADRE : cyan/bleu = identité, vert/jaune/rouge = sémantique
# (succès/attention/danger), magenta = contenu généré par l'assistant IA —
# jamais la même couleur qu'un résultat déterministe, pour qu'on ne les
# confonde jamais visuellement, cohérent avec la règle "toujours étiqueter
# l'IA" appliquée dans les rapports (rapport.py, GUIDE_PROJET.md section 9).
COULEUR_RISQUE = {"low": "green", "medium": "yellow3", "high": "bold red"}


# Lettres du logo ASCII, 5 colonnes x 7 lignes chacune — ASCII pur (#/espace
# uniquement), jamais de bloc Unicode (▀▄█ etc.) : un ancien incident sur ce
# projet (bandit qui plantait sur un emoji dans les logs, cf. W7/FIX/SYNTHESE.md)
# a déjà montré qu'un caractère non-ASCII peut casser silencieusement sur
# certains codepages Windows. Construit programmatiquement pour garantir
# l'alignement plutôt que de la concaténation de chaînes à la main.
_LETTRES_LOGO: dict[str, tuple[str, str, str, str, str, str, str]] = {
    "C": (" ### ", "#   #", "#    ", "#    ", "#    ", "#   #", " ### "),
    "A": (" ### ", "#   #", "#   #", "#####", "#   #", "#   #", "#   #"),
    "D": ("#### ", "#   #", "#   #", "#   #", "#   #", "#   #", "#### "),
    "R": ("#### ", "#   #", "#   #", "#### ", "#  # ", "#   #", "#   #"),
    "E": ("#####", "#    ", "#    ", "#### ", "#    ", "#    ", "#####"),
}


def _logo_ascii(mot: str = "CADRE") -> str:
    """Rendu ASCII du logo, lettre par lettre, une ligne à la fois."""
    return "\n".join(" ".join(_LETTRES_LOGO[lettre][i] for lettre in mot) for i in range(7))


def _banniere() -> Panel:
    """Bannière CADRE — panneau centré, bordure d'accent, logo ASCII pur,
    sans dépendance à l'unicode exotique."""
    contenu = Text()
    contenu.append(_logo_ascii() + "\n", style="bold #00c2a8")
    contenu.append(f"v{__version__}\n\n", style="dim")
    contenu.append("Continuous Adversary-Driven Rule Engineering\n", style="white")
    contenu.append("Audit SOC automatisé · MITRE ATT&CK · Sigma", style="dim italic")
    return Panel(
        Align.center(contenu),
        border_style="#00c2a8",
        padding=(1, 4),
    )


@click.group()
@click.version_option(version=__version__, prog_name="cadre")
@click.option("--verbose", "-v", is_flag=True, help="Affiche aussi les logs DEBUG dans le terminal")
@click.option(
    "--quiet", "-q", is_flag=True, help="N'affiche que les avertissements/erreurs dans le terminal"
)
def cli(verbose, quiet):
    """CADRE — Continuous Adversary-Driven Rule Engineering"""
    # Positionné AVANT toute création du logger singleton (obtenir_logger()
    # le lit à l'instanciation) — la trace fichier JSON reste toujours
    # complète, seule la verbosité console change.
    if verbose and quiet:
        console.print("[yellow3]--verbose et --quiet sont mutuellement exclusifs[/yellow3]")
    elif verbose:
        os.environ["CADRE_LOG_LEVEL"] = "DEBUG"
    elif quiet:
        os.environ["CADRE_LOG_LEVEL"] = "WARN"
    console_err.print(_banniere())


@cli.command()
@click.option("--set", "set_secret", multiple=True, help="Définir un secret (format: CLE=VALEUR)")
@click.option("--list", "lister", is_flag=True, help="Lister les secrets configurés")
def init(set_secret, lister):
    """Initialise CADRE : configure les secrets et le coffre-fort."""
    coffre = obtenir_coffre()

    if lister:
        cles = coffre.lister_cles()
        if not cles:
            console.print(
                "[dim]Aucun secret configuré.[/dim] Utilisez : cadre init --set CLE=VALEUR"
            )
        else:
            console.print("[bold]Secrets configurés :[/bold]")
            for cle in cles:
                console.print(f"  [cyan]•[/cyan] {cle}")
        return

    if not set_secret:
        console.print("[bold]Mode interactif :[/bold]")
        console.print("  Les credentials seront stockés dans le coffre-fort système.")
        console.print("  [dim](Aucun mot de passe ne sera affiché ni stocké en clair.)[/dim]\n")

        secrets_requis = [
            ("CADRE_VM_IP", "Adresse IP de la VM Windows cible"),
            ("CADRE_VM_USER", "Nom d'utilisateur Windows (ex: CadreUser)"),
            ("CADRE_VM_PASS", "Mot de passe Windows"),
            ("CADRE_ELASTIC_URL", "URL Elasticsearch (défaut: http://127.0.0.1:9200)"),
            ("CADRE_ELASTIC_USER", "Utilisateur Elastic (défaut: elastic)"),
            ("CADRE_ELASTIC_PASS", "Mot de passe Elastic"),
            ("CADRE_KIBANA_URL", "URL Kibana (défaut: http://127.0.0.1:5601)"),
        ]

        for cle, description in secrets_requis:
            console.print(f"\n{description}")
            if "PASS" in cle:
                valeur = getpass.getpass(f"  {cle} : ")
            else:
                valeur = click.prompt(f"  {cle}", default="")
            if valeur:
                coffre.stocker(cle, valeur)
                console.print("  [green]Stocké[/green]")

        console.print("\n[bold green]Initialisation terminée.[/bold green]")
        console.print("Testez avec : [cyan]cadre status[/cyan]")
        return

    for item in set_secret:
        if "=" not in item:
            console.print(f"[yellow3]Format invalide : {item}[/yellow3] (attendu: CLE=VALEUR)")
            continue
        cle, valeur = item.split("=", 1)
        try:
            coffre.stocker(cle, valeur)
        except ErreurSecurite as e:
            # Ex. valeur vide (`--set CLE=`) ou nom de clé invalide -- un
            # traceback brut pour une simple faute de frappe était trop
            # sévère, surtout au milieu d'une liste de plusieurs --set.
            console.print(f"[bold red]Échec pour {cle} :[/bold red] {e}")
            continue
        console.print(f"[green][/green] {cle} stocké")


@cli.command("secrets-sync-beats")
def secrets_sync_beats():
    """Repousse CADRE_ELASTIC_PASS (coffre-fort) vers winlogbeat.yml et
    auditbeat.yml, puis redémarre les deux agents.

    À exécuter après toute rotation de CADRE_ELASTIC_PASS (`cadre init --set`
    ou reset direct côté Elasticsearch) : Winlogbeat et Auditbeat lisent leur
    propre fichier de configuration, jamais le coffre-fort CADRE -- sans
    cette resynchronisation, ils continuent d'utiliser l'ancien mot de passe
    et la télémétrie s'arrête silencieusement.
    """
    from .synchronise_secrets import synchroniser_secrets_beats

    console.print("[bold]Resynchronisation des agents de télémétrie...[/bold]\n")
    orchestrateur = OrchestrateurCADRE()

    if not orchestrateur.config.get("elastic_pass"):
        console.print("[bold red]CADRE_ELASTIC_PASS introuvable dans le coffre-fort.[/bold red]")
        console.print("[dim]Définissez-le d'abord : cadre init --set CADRE_ELASTIC_PASS=...[/dim]")
        sys.exit(1)

    resultats = synchroniser_secrets_beats(orchestrateur)
    for r in resultats:
        if r.ok:
            console.print(f"[bold green]OK[/bold green]  {r.cible} — {r.detail}")
        else:
            console.print(f"[bold red]ÉCHEC[/bold red]  {r.cible} — {r.detail}")

    if not all(r.ok for r in resultats):
        console.print(
            "\n[yellow3]Au moins une cible n'a pas pu être resynchronisée.[/yellow3] "
            "Vérifiez la connectivité (VM allumée, WinRM/SSH actifs) puis relancez."
        )
        sys.exit(1)
    console.print(
        "\n[bold green]Les deux agents utilisent maintenant le nouveau mot de passe.[/bold green]"
    )


def _selectionner_attaques_cycle(
    technique: tuple[str, ...], attaque_ids: tuple[str, ...]
) -> tuple[list, list[str]]:
    """Résout la sélection d'attaques d'un cycle (--technique/--id/tout le
    catalogue), partagé entre l'exécution réelle et --dry-run."""
    catalogue = catalogue_actif()  # natif + attaques perso
    if attaque_ids:
        selection = []
        inconnues = []
        for attaque_id in attaque_ids:
            attaque = next((a for a in catalogue if a.id == attaque_id), None)
            if attaque:
                selection.append(attaque)
            else:
                inconnues.append(attaque_id)
        return selection, inconnues
    if technique:
        return [a for a in catalogue if a.technique_mitre in technique], []
    return list(catalogue), []


def _afficher_dry_run(technique: tuple[str, ...], attaque_ids: tuple[str, ...]) -> None:
    """Affiche la liste des attaques qui seraient exécutées par `cadre
    cycle --dry-run`, sans rien exécuter (aucun appel WinRM/ES/Kibana)."""
    selection, inconnues = _selectionner_attaques_cycle(technique, attaque_ids)
    if inconnues:
        console.print(f"[bold red]Attaques introuvables :[/bold red] {', '.join(inconnues)}")
    table = Table(
        title=f"Dry-run — {len(selection)} attaque(s) seraient exécutées",
        title_style="bold cyan",
        header_style="bold white",
        border_style="grey50",
        box=box.SIMPLE_HEAVY,
    )
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Technique", style="bold", no_wrap=True)
    table.add_column("Plateforme", no_wrap=True)
    table.add_column("Commande")
    for a in selection:
        table.add_row(a.id, a.technique_mitre, a.plateforme.value, a.commande[:80])
    console.print(table)
    console.print(
        "\n[dim]Aucune commande n'a été exécutée — retirez --dry-run pour lancer "
        "réellement.[/dim]"
    )


def _signaler_verrou_actif_et_quitter(e: VerrouCycleActifError) -> NoReturn:
    """Message clair (pas une traceback Python brute) quand un cycle réel
    est déjà en cours ailleurs -- régression (audit) : `cycle`, `decouvrir`
    et `rechercher --auto-decouvrir` appellent tous, directement ou via
    `decouvrir_attaques()`, une fonction qui acquiert le verrou
    inter-processus (F-009) sans jamais rattraper VerrouCycleActifError,
    plantant la commande avec une traceback incompréhensible pour
    l'utilisateur au lieu d'un message actionnable. `sys.exit(1)` (jamais
    une simple `return`) : un échec de commande CLI doit rester un échec
    (code de sortie non nul), pas un succès silencieux. Type `NoReturn` :
    mypy sait alors qu'aucun code après l'appel n'est jamais atteint, sans
    `return`/`continue` explicite à chaque site d'appel."""
    console.print(f"[bold red]Cycle déjà en cours[/bold red] — {e}")
    console.print(
        "[dim]Un autre `cadre cycle`/`cadre loop`/le dashboard tourne déjà contre "
        "cette cible. Réessayez une fois ce cycle terminé.[/dim]"
    )
    sys.exit(1)


# Sous-ensemble « démo » : 5 techniques Windows fiables (3 tactiques), rapides,
# pour une démonstration courte sans jouer les 62 attaques. Toutes Windows
# (cible joignable), sans dépendance Internet.
# Sous-ensemble de DÉMONSTRATION fiable (voir DEMO/1-scenario.md).
# Uniquement des techniques prouvées VALIDE au dernier cycle réel, toutes
# Windows/EventID 1 (rapides, indexation immédiate), couvrant 3 tactiques.
# 4 sur 5 se détectent sur un INDICATEUR RÉEL (pas le marqueur de test) ;
# la 5e (marqueur) est incluse à dessein pour présenter honnêtement la
# distinction « validation de cycle » vs « détection de production ».
# On a retiré CADRE-PER-002 (angle mort au dernier cycle) et CADRE-CRE-002
# (faux négatif) : trop risqués pour une démo qui ne doit pas échouer.
IDS_DEMO = (
    "CADRE-DIS-001",  # T1082 systeminfo.exe        — Discovery       (vraie TTP)
    "CADRE-DIS-009",  # T1033 whoami /all           — Discovery       (vraie TTP)
    "CADRE-EVA-003",  # T1140 certutil -decode      — Defense Evasion (vraie TTP)
    "CADRE-EXE-005",  # T1218.011 rundll32          — Defense Evasion (vraie TTP)
    "CADRE-EXE-002",  # T1059.003 cmd baseline      — Execution       (marqueur assumé)
)


@cli.command()
@click.option("--technique", "-t", multiple=True, help="Limiter à certaines techniques MITRE")
@click.option(
    "--id",
    "attaque_ids",
    multiple=True,
    help="Exécuter uniquement ces attaques (par ID catalogue, répétable)",
)
@click.option(
    "--demo",
    is_flag=True,
    help="Sous-ensemble de démo : 5 techniques Windows fiables et rapides. "
    "Idéal pour une soutenance ; « tout le catalogue » reste par défaut.",
)
@click.option("--output", "-o", default="./rapports", help="Répertoire de sortie")
@click.option("--simulate", "-s", is_flag=True, help="Mode simulation (sans VM)")
@click.option(
    "--dry-run",
    "dry_run",
    is_flag=True,
    help="Affiche les attaques qui seraient exécutées, sans rien lancer "
    "(aucun appel WinRM/Elasticsearch/Kibana)",
)
@click.option(
    "--llm",
    is_flag=True,
    help="Enrichit le rapport d'une synthèse IA (Ollama local, optionnel)",
)
@click.option(
    "--ia-draft-regles",
    "ia_draft_regles",
    is_flag=True,
    help="Demande en plus à l'IA un brouillon de règle Sigma comparatif par attaque "
    "(jamais compilé/validé/déployé — coûteux, ~1-2 min/attaque)",
)
@click.option(
    "--timeout-indexation",
    "timeout_indexation",
    type=int,
    default=None,
    help="Secondes d'attente d'un événement avant de déclarer un angle mort "
    "(défaut: 180). C'est le poste de coût dominant d'un cycle : chaque angle "
    "mort attend ce délai en entier. Baisser accélère beaucoup une démo, mais "
    "risque de faire passer une indexation lente pour un angle mort.",
)
@click.option(
    "--generation",
    type=click.Choice(["deterministe", "llm"]),
    default="deterministe",
    help="Générateur de la règle candidate : 'deterministe' (défaut, "
    "reproductible) ou 'llm' (le LLM rédige la règle). Dans les DEUX cas la "
    "règle passe la MÊME validation TP/FP avant déploiement ; le mode llm "
    "retombe sur le déterministe s'il échoue.",
)
@click.option(
    "--parallel",
    "parallele",
    is_flag=True,
    help="G2 : parallélisme prudent, borné à 2 attaques WinRM/validation "
    "simultanées. Ignoré (avec avertissement) avec --demo/--id, qui restent "
    "structurellement séquentiels. Voir docs/ARCHITECTURE.md.",
)
@click.option(
    "--revue",
    is_flag=True,
    help="Avec --id UNIQUEMENT : s'arrête avant déploiement Kibana pour "
    "revue humaine (voir 'cadre revue'). Refusé si un des --id appartient "
    "au catalogue natif -- réservé aux attaques perso/IA jamais éprouvées.",
)
def cycle(  # noqa: PLR0912, PLR0915 -- commande CLI : un aiguillage sur ses
    # options (dry-run / simulate / --id / --technique / mode génération /
    # revue), chaque branche courte et explicite ; la logique métier est
    # déjà extraite en helpers (_selectionner_attaques_cycle,
    # _afficher_synthese_cycle...).
    technique,
    attaque_ids,
    demo,
    output,
    simulate,
    dry_run,
    llm,
    ia_draft_regles,
    timeout_indexation,
    generation,
    parallele,
    revue,
):
    """Exécute un cycle d'audit complet (ou ciblé)."""
    # Régression (audit) : `--technique ""` (chaîne vide, ex. variable shell
    # mal substituée) passait le typage click (une str vide reste une str)
    # puis filtrait TOUJOURS sur `a.technique_mitre in [""]` -- aucune
    # attaque du catalogue n'a une technique_mitre vide, donc le cycle
    # tournait silencieusement sur 0 attaque, sans jamais avertir
    # l'utilisateur que son filtre ne correspond à rien.
    if any(not t.strip() for t in technique):
        console.print(
            "[bold red]--technique vide refusé[/bold red] — une technique MITRE ne "
            "peut pas être une chaîne vide (retirez --technique pour tout exécuter)."
        )
        sys.exit(1)

    # Régression (audit) : `--timeout-indexation` n'était jamais validé -- un
    # timeout <= 0 (ex. faute de frappe, variable shell mal substituée)
    # passait le typage entier de click puis se propageait tel quel jusqu'à
    # `attendre_indexation()` (attente_indexation.py), dont la toute première
    # comparaison (`elapsed > timeout_max_sec`) est déjà vraie avant le
    # moindre appel réseau : CHAQUE attaque du cycle serait silencieusement
    # déclarée ANGLE_MORT sans qu'Elasticsearch soit jamais interrogé --
    # aucune trace Python, mais un cycle entier faussé sans le moindre
    # avertissement.
    if timeout_indexation is not None and timeout_indexation <= 0:
        console.print(
            f"[bold red]--timeout-indexation invalide[/bold red] : "
            f"{timeout_indexation} (doit être strictement positif, en secondes)."
        )
        sys.exit(1)

    # --demo = raccourci vers un sous-ensemble Windows fiable (sauf si --id fourni).
    if demo and not attaque_ids:
        attaque_ids = IDS_DEMO
        console.print(f"[cyan]Mode DÉMO[/cyan] — {len(IDS_DEMO)} techniques Windows fiables\n")
    if dry_run:
        _afficher_dry_run(technique, attaque_ids)
        return

    if revue:
        if not attaque_ids:
            console.print(
                "[bold red]--revue nécessite --id[/bold red] "
                "(une ou plusieurs attaques précises)."
            )
            sys.exit(1)
        natives = {a.id for a in CATALOGUE} & set(attaque_ids)
        if natives:
            console.print(
                f"[bold red]--revue refusé[/bold red] pour une attaque native déjà "
                f"éprouvée : {', '.join(natives)} (réservé aux attaques perso/IA)"
            )
            sys.exit(1)

    if parallele and attaque_ids:
        raison = "--demo" if demo else "--id"
        console.print(f"[yellow]--parallel ignoré avec {raison}[/yellow] — reste séquentiel.\n")
        parallele = False
    elif parallele:
        console.print(
            "[cyan]Mode parallèle[/cyan] — jusqu'à 2 attaques WinRM/validation simultanées\n"
        )

    if simulate:
        console.print("[bold cyan]Mode SIMULATION[/bold cyan] — pas d'exécution réelle\n")
    else:
        console.print(f"[bold]Démarrage du cycle d'audit CADRE v{__version__}[/bold]\n")
    if generation == "llm":
        console.print(
            "[magenta]Génération des règles par LLM[/magenta] — validées TP/FP "
            "avant déploiement, comme le déterministe.\n"
        )

    config = {
        "repertoire_rapports": Path(output),
        "ia_brouillon_regle": ia_draft_regles,
        "mode_generation_regle": generation,
    }
    if timeout_indexation is not None:
        config["timeout_indexation_sec"] = timeout_indexation
    orchestrateur = OrchestrateurCADRE(config=config)

    if attaque_ids:
        # Plusieurs IDs possibles (multiple=True)
        catalogue = catalogue_actif()  # natif + attaques perso
        resultats = []
        inconnues = []
        # F-009 : cette branche appelle executer_attaque_complete() directement
        # (sélection d'IDs précis), sans jamais passer par
        # executer_cycle_complet() -- donc sans jamais acquérir le verrou
        # inter-processus qui évite qu'un `cadre cycle --id ...` réel et un
        # autre cycle/le dashboard ne tournent en même temps contre la même
        # cible. Même granularité que executer_cycle_complet : acquis une
        # seule fois pour tout le groupe d'IDs, jamais en simulation.
        if not simulate:
            try:
                _acquerir_verrou_cycle()
            except VerrouCycleActifError as e:
                _signaler_verrou_actif_et_quitter(e)
        try:
            for attaque_id in attaque_ids:
                attaque = next((a for a in catalogue if a.id == attaque_id), None)
                if not attaque:
                    inconnues.append(attaque_id)
                    continue
                if simulate:
                    resultat = orchestrateur._executer_attaque_simulation(attaque)
                else:
                    resultat = orchestrateur.executer_attaque_complete(
                        attaque, arreter_avant_deploiement=revue, source_revue="cycle"
                    )
                resultats.append(resultat)
        finally:
            if not simulate:
                _liberer_verrou_cycle()
        if inconnues:
            console.print(f"[bold red]Attaques introuvables :[/bold red] {', '.join(inconnues)}")
            console.print("Utilisez : [cyan]cadre list[/cyan]")
        if not resultats:
            sys.exit(1)
        for r in resultats:
            if r.get("statut") == "EN_ATTENTE_REVUE":
                console.print(
                    f"  [yellow3]{r['id']}[/yellow3] en attente de revue "
                    f"[dim](cadre revue approuver {r['rule_id_stable']})[/dim]"
                )
        orchestrateur.resultats = resultats
        orchestrateur._generer_rapports_fin_cycle(avec_llm=llm)
    else:
        try:
            orchestrateur.executer_cycle_complet(
                list(technique) if technique else None,
                mode_simulation=simulate,
                avec_llm=llm,
                parallele=parallele,
            )
        except VerrouCycleActifError as e:
            _signaler_verrou_actif_et_quitter(e)

    _afficher_synthese_cycle(orchestrateur.resultats, output)


def _afficher_synthese_cycle(resultats: list, output: str) -> None:
    """Panneau de synthèse d'un cycle (compteurs par statut).

    Régression (audit) : « pipeline figé en revue » -- VALIDE_NON_DEPLOYE,
    EN_ATTENTE_REVUE et REJETE étaient absents des statuts comptés. Un
    `cadre cycle --id ... --revue` (où CHAQUE attaque finit forcément en
    EN_ATTENTE_REVUE) affichait un panneau entièrement à zéro -- Validées:
    0, Angles morts: 0, Simulées: 0, Erreurs: 0 -- qui se lisait comme "rien
    ne s'est passé"/pipeline figé, alors que les attaques avaient bien été
    validées TP/FP et attendaient une revue humaine (déjà listées juste
    au-dessus, ligne par ligne, mais absentes du résumé chiffré final)."""
    compteur = {
        statut: sum(1 for r in resultats if r.get("statut") == statut)
        for statut in (
            "VALIDE",
            "VALIDE_NON_DEPLOYE",
            "EN_ATTENTE_REVUE",
            "REJETE",
            "ANGLE_MORT",
            "SIMULE",
            "ERREUR",
            "NON_APPLICABLE",
        )
    }
    synthese = Text()
    synthese.append("Validées : ", style="bold")
    synthese.append(f"{compteur['VALIDE']}\n", style="bold green")
    if compteur["VALIDE_NON_DEPLOYE"]:
        synthese.append("Validées (non déployées) : ", style="bold")
        synthese.append(f"{compteur['VALIDE_NON_DEPLOYE']}\n", style="bold green")
    if compteur["EN_ATTENTE_REVUE"]:
        synthese.append("En attente de revue : ", style="bold")
        synthese.append(f"{compteur['EN_ATTENTE_REVUE']}\n", style="bold yellow3")
    if compteur["REJETE"]:
        synthese.append("Rejetées : ", style="bold")
        synthese.append(f"{compteur['REJETE']}\n", style="bold yellow")
    synthese.append(" Angles morts : ", style="bold")
    synthese.append(f"{compteur['ANGLE_MORT']}\n", style="bold magenta")
    synthese.append("Simulées : ", style="bold")
    synthese.append(f"{compteur['SIMULE']}\n", style="bold cyan")
    synthese.append("Erreurs : ", style="bold")
    synthese.append(f"{compteur['ERREUR']}\n", style="bold red")
    if compteur["NON_APPLICABLE"]:
        synthese.append("Non applicables : ", style="bold")
        synthese.append(f"{compteur['NON_APPLICABLE']}\n", style="dim")
    synthese.append("Rapports dans : ", style="bold")
    synthese.append(output, style="dim")
    console.print(Panel(synthese, title="Synthèse", border_style="grey50"))


def _afficher_liste_scenarios() -> None:
    """Tableau des scénarios d'adversaire disponibles."""
    table = Table(
        title="Scénarios d'adversaire (kill chains)",
        title_style="bold cyan",
        header_style="bold white",
        border_style="grey50",
        box=box.SIMPLE_HEAVY,
    )
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Adversaire émulé", style="bold")
    table.add_column("Cible", no_wrap=True)
    table.add_column("Phases", justify="right", no_wrap=True)
    for s in SCENARIOS:
        table.add_row(s.id, s.adversaire, s.plateforme, str(len(s.attaque_ids)))
    console.print(table)
    console.print(
        "\n[dim]Lancer une kill chain :[/dim] "
        "[cyan]cadre scenario --id RANSOMWARE[/cyan] "
        "[dim](ajouter --simulate pour une démo sans VM)[/dim]"
    )


def _afficher_kill_chain(analyse: dict, output: str) -> None:
    """Affiche le déroulé de la kill chain + la couverture dans le terminal."""
    console.print()
    for e in analyse["etapes"]:
        detectee = e["detectee"]
        marque = "[bold green][/bold green]" if detectee else "[bold red][/bold red]"
        couleur = "green" if detectee else "red"
        console.print(
            f"  {marque} [dim]{e['position']}.[/dim] "
            f"[bold]{e['tactique']}[/bold] — {e['nom']} "
            f"[{couleur}]({e['statut']})[/{couleur}]"
        )
    detectees = analyse["etapes_detectees"]
    total = analyse["total_etapes"]
    pct = analyse["couverture_pct"]
    couleur_pct = "bold green" if pct >= 80 else "yellow3" if pct >= 50 else "bold red"
    synthese = Text()
    synthese.append("Adversaire : ", style="bold")
    synthese.append(f"{analyse['adversaire']}\n", style="cyan")
    synthese.append(" Couverture de la chaîne : ", style="bold")
    synthese.append(f"{detectees}/{total} phases ({pct:.0f}%)\n", style=couleur_pct)
    synthese.append("Rapport kill chain dans : ", style="bold")
    synthese.append(output, style="dim")
    console.print(Panel(synthese, title="Synthèse kill chain", border_style="grey50"))


@cli.command()
@click.option("--id", "scenario_id", default=None, help="ID du scénario à exécuter")
@click.option("--list", "lister", is_flag=True, help="Liste les scénarios disponibles")
@click.option("--output", "-o", default="./rapports", help="Répertoire de sortie")
@click.option("--simulate", "-s", is_flag=True, help="Mode simulation (sans VM)")
@click.option(
    "--llm",
    is_flag=True,
    help="Enrichit le rapport d'une synthèse IA (Ollama local, optionnel)",
)
def scenario(scenario_id, lister, output, simulate, llm):
    """Émule une kill chain d'adversaire complète et mesure sa couverture."""
    if lister or not scenario_id:
        _afficher_liste_scenarios()
        if not scenario_id and not lister:
            console.print(
                "\n[yellow]Précisez un scénario :[/yellow] [cyan]cadre scenario --id <ID>[/cyan]"
            )
        return

    scenario_obj = obtenir_scenario(scenario_id)
    if scenario_obj is None:
        console.print(f"[bold red]Scénario introuvable :[/bold red] {scenario_id}")
        console.print("Utilisez : [cyan]cadre scenario --list[/cyan]")
        sys.exit(1)

    nb = len(attaques_ordonnees(scenario_obj))
    if simulate:
        console.print("[bold cyan]Mode SIMULATION[/bold cyan] — pas d'exécution réelle")
    console.print(
        f"[bold]Émulation : {scenario_obj.nom}[/bold] "
        f"[dim]({nb} phases, cible {scenario_obj.plateforme})[/dim]\n"
    )

    orchestrateur = OrchestrateurCADRE(config={"repertoire_rapports": Path(output)})
    analyse = orchestrateur.executer_scenario(scenario_obj, mode_simulation=simulate, avec_llm=llm)
    _afficher_kill_chain(analyse, output)


def _afficher_import_atomic(rapport: dict) -> None:
    """Tableaux des atomics retenus / refusés par l'ingestion Atomic Red Team."""
    retenus = rapport["retenus"]
    refuses = rapport["refuses"]

    table = Table(
        title=f" Atomic Red Team — {len(retenus)} test(s) sûr(s) retenu(s)",
        title_style="bold cyan",
        header_style="bold white",
        border_style="grey50",
        box=box.SIMPLE_HEAVY,
    )
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Technique", no_wrap=True)
    table.add_column("Cible", no_wrap=True)
    table.add_column("Détection", style="dim")
    table.add_column("Nom")
    for b in retenus:
        table.add_row(
            b["id"],
            b["technique_mitre"],
            b["plateforme"],
            str(b["valeur_detection"] or "event.code seul"),
            b["nom"],
        )
    console.print(table)

    if refuses:
        console.print(
            f"\n[bold red]{len(refuses)} atomic(s) DESTRUCTEUR(s) refusé(s) "
            "par le filtre de sécurité[/bold red] [dim](jamais exécutés)[/dim] :"
        )
        for r in refuses:
            console.print(
                f"  [red]•[/red] {r['technique']} — {r['nom']} "
                f"[dim](motif : {r['motif']})[/dim]"
            )


@cli.command()
@click.option(
    "--repo",
    default=None,
    help="Répertoire d'un dépôt Atomic Red Team (dossier `atomics/`). "
    "Défaut : le petit jeu d'exemples embarqué.",
)
@click.option(
    "--platform",
    "plateforme",
    type=click.Choice(["windows", "linux"]),
    default=None,
    help="Ne retenir que les atomics de cette plateforme",
)
@click.option("--technique", "-t", multiple=True, help="Filtrer par technique MITRE (répétable)")
@click.option(
    "--import",
    "importer",
    is_flag=True,
    help="Enregistrer les atomics sûrs dans le catalogue personnel "
    "(ils rejoignent alors `cadre list`, `cadre cycle`, `cadre scenario`)",
)
def atomic(repo, plateforme, technique, importer):
    """Ingère Atomic Red Team comme source d'attaques (filtrée + validée)."""
    from .atomic_red_team import importer_atomics, repertoire_exemple
    from .catalogue_attaques import Plateforme
    from .catalogue_utilisateur import (
        ErreurCatalogueUtilisateur,
        enregistrer_attaque_utilisateur,
    )

    source = Path(repo) if repo else repertoire_exemple()
    if repo and not source.is_dir():
        console.print(f"[bold red]Répertoire introuvable :[/bold red] {source}")
        sys.exit(1)
    if not repo:
        console.print(
            "[dim]Source : jeu d'exemples embarqué. Passez [cyan]--repo <chemin>[/cyan] "
            "vers un checkout d'Atomic Red Team pour les ~1600 tests.[/dim]\n"
        )

    plateformes = {Plateforme(plateforme)} if plateforme else None
    rapport = importer_atomics(source, plateformes=plateformes, techniques=set(technique) or None)
    _afficher_import_atomic(rapport)

    if not importer:
        console.print(
            "\n[dim]Aperçu uniquement. Ajoutez [cyan]--import[/cyan] pour les "
            "enregistrer au catalogue.[/dim]"
        )
        return

    ajoutes, deja = 0, 0
    for brouillon in rapport["retenus"]:
        try:
            enregistrer_attaque_utilisateur({**brouillon})
            ajoutes += 1
        except ErreurCatalogueUtilisateur:
            deja += 1  # id déjà présent (import déjà effectué)
    synthese = Text()
    synthese.append("Ajoutés au catalogue : ", style="bold")
    synthese.append(f"{ajoutes}\n", style="bold green")
    if deja:
        synthese.append("↺ Déjà présents : ", style="bold")
        synthese.append(f"{deja}\n", style="dim")
    synthese.append("Vérifiez avec : ", style="bold")
    synthese.append("cadre list", style="cyan")
    console.print(Panel(synthese, title="Import Atomic Red Team", border_style="grey50"))


@cli.command()
def status():
    """Affiche l'état de la stack (Elastic, Kibana, VM)."""
    console.print("[bold]Vérification de la stack...[/bold]\n")
    import requests
    import urllib3

    from .reseau import verifier_tls

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    config = OrchestrateurCADRE()

    services = [
        ("Elasticsearch", config.config["elastic_url"]),
        ("Kibana", config.config["kibana_url"]),
    ]

    table = Table(box=box.SIMPLE, show_header=False)
    table.add_column("État", no_wrap=True)
    table.add_column("Service", style="bold", no_wrap=True)
    table.add_column("URL", style="dim")

    for nom, url in services:
        try:
            r = requests.get(url, timeout=5, verify=verifier_tls(), auth=config.auth_elastic)
            if r.status_code == 200:
                table.add_row("[bold green]OK[/bold green]", nom, url)
            else:
                table.add_row(f"[yellow3] HTTP {r.status_code}[/yellow3]", nom, url)
        except Exception as e:
            table.add_row(f"[bold red]{e}[/bold red]", nom, url)

    console.print(table)

    vm_ok, vm_detail = config.verifier_winrm_reel()
    etat_vm = "[bold green]OK[/bold green]" if vm_ok else f"[bold red]{vm_detail}[/bold red]"
    console.print(
        f"\n   [bold]VM cible[/bold] : [cyan]{config.config['vm_ip']}[/cyan] " f"({etat_vm})"
    )


@cli.command()
@click.option("--soutenance", is_flag=True, help="Génère le rapport de soutenance PFA")
def rapport(soutenance):
    """Génère les rapports Markdown et CSV."""
    if soutenance:
        generer_rapport_soutenance({}, Path("./RAPPORT_PFA_CADRE.md"))
        console.print(
            "[bold green]Rapport de soutenance généré :[/bold green] ./RAPPORT_PFA_CADRE.md"
        )
    else:
        # Régression (audit) « rapport mort » -- cette branche affichait
        # "Génération des rapports en cours..." (message trompeur, laisse
        # croire qu'un travail a lieu) puis ne faisait RIEN : jamais
        # implémentée (voir l'ancien commentaire "Logique pour générer
        # depuis le dernier cycle", resté un TODO). Les rapports Markdown/
        # CSV/HTML sont DÉJÀ générés automatiquement à la fin de chaque
        # `cadre cycle` (_generer_rapports_fin_cycle) -- ce message oriente
        # honnêtement vers la vraie source plutôt que de simuler un travail
        # inexistant.
        console.print(
            "[yellow3]Rien à générer ici.[/yellow3] Les rapports (Markdown/CSV/HTML) "
            "sont générés automatiquement à la fin de chaque [cyan]cadre cycle[/cyan]. "
            "Pour le rapport de soutenance : [cyan]cadre rapport --soutenance[/cyan]."
        )


@cli.command()
@click.option("--output", "-o", default="./rapports", help="Répertoire des cycles")
@click.option(
    "--cumul",
    is_flag=True,
    help="Valeur cumulée sur tous les cycles de `cadre loop` (rapports/cadre_cumulatif.json), "
    "pas seulement le dernier cycle.",
)
def metriques(output, cumul):
    """Affiche la valeur métier du dernier cycle (temps gagné, couverture)."""
    from .metriques import calculer_tendance_cumulative, metriques_dernier_cycle

    repertoire = Path(output)

    if cumul:
        import json as json_lib

        chemin_cumulatif = repertoire / "cadre_cumulatif.json"
        if not chemin_cumulatif.is_file():
            console.print(
                "[yellow3]Aucun cumulatif trouvé.[/yellow3] `--cumul` nécessite au moins un "
                "cycle exécuté via [cyan]cadre loop[/cyan] (pas `cadre cycle`, qui ne "
                "l'alimente pas)."
            )
            return
        c = calculer_tendance_cumulative(
            json_lib.loads(chemin_cumulatif.read_text(encoding="utf-8"))
        )
        if not c:
            console.print("[yellow3]Cumulatif présent mais vide ou mal formé.[/yellow3]")
            return
        corps = Text()
        corps.append(" Cycles exécutés (cadre loop) : ", style="bold")
        corps.append(f"{c['total_cycles']}\n", style="bold green")
        corps.append(" Règles validées cumulées : ", style="bold")
        corps.append(
            f"{c['regles_validees_cumul']}  ({c['taux_reussite_cumul_pct']}% sur "
            f"{c['total_attaques']} attaques testées)\n",
            style="dim",
        )
        corps.append("⏱ Temps d'ingénierie économisé (cumulé) : ", style="bold")
        corps.append(
            f"~{c['temps_gagne_heures_cumul']} h "
            f"(~{c['temps_gagne_jours_ouvres_cumul']} j-homme)\n",
            style="bold cyan",
        )
        console.print(Panel(corps, title="Valeur métier cumulée — cadre loop", border_style="cyan"))
        return

    m = metriques_dernier_cycle(repertoire)
    if not m:
        console.print(
            "[yellow3]Aucun cycle trouvé.[/yellow3] Lancez d'abord : [cyan]cadre cycle[/cyan]"
        )
        return

    dernier = sorted(repertoire.glob("cycle_*.csv"), reverse=True)[0]
    corps = Text()
    corps.append(" Règles de détection produites : ", style="bold")
    corps.append(f"{m['regles_produites']}", style="bold green")
    corps.append(f"  ({m['taux_reussite_pct']}% sur {m['applicables']} applicables)\n", style="dim")
    corps.append("⏱ Temps d'ingénierie économisé : ", style="bold")
    corps.append(
        f"~{m['temps_gagne_heures']} h (~{m['temps_gagne_jours_ouvres']} j-homme)\n",
        style="bold cyan",
    )
    corps.append(" Couverture MITRE ATT&CK : ", style="bold")
    corps.append(
        f"{m['tactiques_couvertes']}/{m['total_tactiques_catalogue']} tactiques "
        f"({m['couverture_tactiques_pct']}%)\n",
        style="bold magenta",
    )
    corps.append("Bruit résiduel médian : ", style="bold")
    corps.append(f"{m['faux_positifs_median']} FP/règle\n", style="yellow3")
    corps.append(
        f"\n[hypothèse : {m['hypothese_heures_par_regle']} h par règle écrite à la main]",
        style="dim italic",
    )
    console.print(Panel(corps, title=f"Valeur métier — {dernier.stem}", border_style="cyan"))


@cli.command()
@click.argument("attaque_id")
@click.option("--output", "-o", default="./rapports", help="Répertoire des cycles")
def derive(attaque_id, output):
    """Détecte si une règle déjà validée se dégrade dans le temps (perte de
    détection ou dérive de bruit), en comparant sa mesure la plus récente à
    la première mesure connue sur les cycles archivés."""
    from .metriques import detecter_derive_regle

    d = detecter_derive_regle(attaque_id, Path(output))

    if d["statut"] == "INSUFFISANT":
        console.print(
            f"[yellow3]Pas assez d'historique pour {attaque_id}[/yellow3] "
            f"({d['nb_mesures']} mesure(s), 2 minimum). Relancez plusieurs cycles réels "
            f"réutilisant cette attaque pour accumuler de l'historique."
        )
        return

    couleurs = {"STABLE": "green", "DERIVE_BRUIT": "yellow3", "PERTE_DETECTION": "red"}
    libelles = {
        "STABLE": "Stable",
        "DERIVE_BRUIT": " Dérive de bruit (plus de faux positifs qu'à l'origine)",
        "PERTE_DETECTION": " Perte de détection (ne détecte plus rien)",
    }
    couleur = couleurs[d["statut"]]
    corps = Text()
    corps.append(f"{libelles[d['statut']]}\n\n", style=f"bold {couleur}")
    corps.append(f"Mesures comparées : {d['nb_mesures']}\n", style="dim")
    corps.append(
        f"Première : {d['premiere']['timestamp']} — TP={d['premiere']['nb_tp']} "
        f"FP={d['premiere']['nb_fp']}\n"
    )
    corps.append(
        f"Dernière : {d['derniere']['timestamp']} — TP={d['derniere']['nb_tp']} "
        f"FP={d['derniere']['nb_fp']}"
    )
    console.print(Panel(corps, title=f"Dérive — {attaque_id}", border_style=couleur))


@cli.command(name="nettoyer-kibana")
@click.option(
    "--appliquer",
    is_flag=True,
    help="Supprimer réellement les règles orphelines (sinon inventaire seul)",
)
def nettoyer_kibana(appliquer):
    """Nettoie les règles CADRE ORPHELINES dans Kibana : des doublons laissés
    par d'anciens déploiements (rule_id UUID) d'avant le mécanisme
    d'idempotence, jamais remis à jour depuis. Ne supprime une orpheline que
    si une règle à jour couvre déjà la même technique — jamais une détection
    unique. Sans --appliquer : inventaire seul, aucune suppression."""
    orchestrateur = OrchestrateurCADRE()

    if appliquer and not click.confirm(
        "Supprimer définitivement les règles orphelines de Kibana ?", default=False
    ):
        console.print("[yellow3]Annulé — aucune règle supprimée.[/yellow3]")
        return

    resultat = orchestrateur.nettoyer_regles_orphelines_kibana(appliquer=appliquer)

    if resultat.get("erreur"):
        console.print(f"[bold red]{resultat['erreur']}[/bold red]")
        sys.exit(1)

    sures = resultat["orphelines_sures"]
    corps = Text()
    corps.append(f"Règles CADRE dans Kibana : {resultat['total_cadre']}\n", style="dim")
    corps.append(f"  à jour (rule_id stable) : {resultat['stables']}\n")
    corps.append(f"  orphelines supprimables : {len(sures)}\n", style="yellow3")
    if resultat["orphelines_preservees"]:
        corps.append(
            f"  orphelines PRÉSERVÉES (sans équivalent à jour) : "
            f"{len(resultat['orphelines_preservees'])}\n",
            style="cyan",
        )
    if appliquer:
        corps.append(f"\n✓ {resultat['supprimees']} règle(s) supprimée(s).", style="bold green")
    elif sures:
        corps.append(
            f"\nInventaire seul. Relancez avec [bold]--appliquer[/bold] pour supprimer "
            f"les {len(sures)} orpheline(s).",
            style="dim",
        )
    else:
        corps.append("\nRien à nettoyer — Kibana est propre.", style="green")
    console.print(Panel(corps, title="Nettoyage Kibana", border_style="yellow3"))


@cli.command()
@click.argument("attaque_id")
@click.option(
    "--valeur-detection",
    "valeur_detection",
    default=None,
    help="Nouvelle valeur de corrélation (texte déjà présent dans la commande réelle)",
)
@click.option(
    "--seuil-fp",
    "seuil_fp_max",
    type=int,
    default=None,
    help="Nouveau seuil de faux positifs max pour cette attaque",
)
@click.option(
    "--reinitialiser",
    is_flag=True,
    help="Retire le raffinement, revient à la définition catalogue d'origine",
)
def raffiner(attaque_id, valeur_detection, seuil_fp_max, reinitialiser):
    """Affine les paramètres de détection d'une attaque EXISTANTE du
    catalogue -- jamais une nouvelle entrée. Combiné au déploiement
    idempotent (rule_id stable), le prochain cycle sur cette attaque met à
    jour la MÊME règle Kibana en place, ne la duplique jamais."""
    from .catalogue_attaques import obtenir_attaque
    from .raffinement import (
        ErreurRaffinement,
        enregistrer_raffinement,
        supprimer_raffinement,
    )

    attaque = obtenir_attaque(attaque_id)
    if attaque is None:
        console.print(f"[bold red]Attaque introuvable :[/bold red] {attaque_id}")
        raise SystemExit(1)

    if reinitialiser:
        retire = supprimer_raffinement(attaque_id)
        if retire:
            console.print(
                f"[green]Raffinement retiré pour {attaque_id}[/green] — revient à la "
                "définition catalogue d'origine."
            )
        else:
            console.print(f"[yellow3]Aucun raffinement actif pour {attaque_id}.[/yellow3]")
        return

    champs = {}
    if valeur_detection is not None:
        champs["valeur_detection"] = valeur_detection
    if seuil_fp_max is not None:
        champs["seuil_fp_max"] = seuil_fp_max
    if not champs:
        console.print(
            "[yellow3]Rien à raffiner[/yellow3] — précisez --valeur-detection et/ou "
            "--seuil-fp, ou --reinitialiser."
        )
        return

    try:
        enregistrer_raffinement(attaque_id, champs)
    except ErreurRaffinement as e:
        console.print(f"[bold red]Raffinement refusé :[/bold red] {e}")
        raise SystemExit(1) from e

    console.print(
        f"[green]Raffinement enregistré pour {attaque_id}.[/green] Relancez "
        f"[cyan]cadre cycle --id {attaque_id}[/cyan] pour re-valider et mettre à jour "
        "la même règle Kibana en place."
    )


# =============================================================================
# COMMANDE EXPORT-SIGMA : exporte les règles au format Sigma partageable
# =============================================================================
@cli.command(name="export-sigma")
@click.option("--output", "-o", default="./regles_sigma_export", help="Répertoire d'export")
def export_sigma(output):
    """Exporte les règles du catalogue au format Sigma partageable (contribution)."""
    from .export_sigma import exporter_regles_sigma

    res = exporter_regles_sigma(Path(output))
    corps = Text()
    corps.append(f"{res['nb']}", style="bold green")
    corps.append(" règles Sigma exportées\n")
    corps.append("Répertoire : ", style="dim")
    corps.append(f"{res['repertoire']}\n", style="cyan")
    if res.get("formats"):
        corps.append("\nFormats prêts à l'emploi (multi-SIEM) :\n", style="bold")
        for f in res["formats"]:
            marque = "  * " if f["format"] == "kibana" else "  • "
            corps.append(
                f"{marque}{f['fichier']}", style="green" if f["format"] == "kibana" else "white"
            )
            corps.append(f"  — {f['description']}\n", style="dim")
        corps.append(
            "\nAstuce Kibana : importez le .ndjson via Security → Rules → Import.",
            style="italic cyan",
        )
    console.print(
        Panel(corps, title="Export Sigma (partageable / multi-SIEM)", border_style="green")
    )


# =============================================================================
# COMMANDE VALIDER-REGLE : valide une règle Sigma existante sur VOTRE télémétrie
# =============================================================================
@cli.command(name="valider-regle")
@click.argument("fichier", type=click.Path(exists=True, dir_okay=False))
@click.option("--jours", "-j", default=7, help="Fenêtre d'analyse (jours d'historique)")
@click.option("--seuil", "-s", default=100, help="Seuil de bruit (max avant 'BRUYANTE')")
def valider_regle(fichier, jours, seuil):
    """Valide une règle Sigma EXISTANTE (ex. SigmaHQ) sur VOTRE télémétrie Elastic."""
    from .validation_regle import valider_fichier_regle

    orchestrateur = OrchestrateurCADRE()
    res = valider_fichier_regle(
        Path(fichier),
        elastic_url=orchestrateur.config["elastic_url"],
        auth=orchestrateur.auth_elastic,
        index_pattern=orchestrateur.config["index_pattern"],
        fenetre_jours=jours,
        seuil_bruit=seuil,
    )
    couleurs = {
        "NON_COMPILABLE": "bold red",
        "SILENCIEUSE": "yellow3",
        "BRUYANTE": "red",
        "ACTIVE": "bold green",
        # Neutre, distinct des couleurs de jugement ci-dessus : ERREUR n'est
        # PAS un verdict sur la règle (panne réseau), ne doit jamais se lire
        # comme "silencieuse/bon signe" (confusion visuelle avec le jaune).
        "ERREUR": "grey50",
    }
    verdict = res["verdict"]
    corps = Text()
    corps.append("Fichier  : ", style="bold")
    corps.append(f"{res['fichier']}\n", style="dim")
    corps.append("Verdict  : ", style="bold")
    corps.append(f"{verdict}\n", style=couleurs.get(verdict, "white"))
    if res["hits"] is not None:
        corps.append("Correspondances : ", style="bold")
        corps.append(f"{res['hits']} sur {res['fenetre_jours']} j\n", style="cyan")
    if res["requete_lucene"]:
        corps.append("Lucene   : ", style="bold")
        corps.append(f"{res['requete_lucene']}\n", style="dim")
    corps.append(f"\n{res['detail']}", style="italic")
    console.print(
        Panel(
            corps,
            title="Validation d'une règle Sigma sur votre télémétrie",
            border_style=couleurs.get(verdict, "cyan").replace("bold ", ""),
        )
    )


# =============================================================================
# COMMANDE SUGGEST : brouillon d'attaque assisté par IA (Ollama)
# =============================================================================
@cli.command()
@click.option(
    "--description",
    "-d",
    required=True,
    help="Description en langage naturel de l'attaque à modéliser",
)
@click.option("--technique", "-t", default=None, help="Technique MITRE ATT&CK imposée (optionnel)")
@click.option("--output", "-o", default=None, help="Fichier où écrire le brouillon JSON")
@click.option(
    "--enregistrer",
    is_flag=True,
    help="Valide le brouillon et l'ajoute au catalogue personnel "
    "(~/.cadre/catalogue_perso.json) — il sera exécuté aux prochains cycles, "
    "avec la MÊME validation TP/FP que les attaques natives.",
)
@click.option(
    "--id",
    "attaque_id",
    default=None,
    help="Identifiant à donner à l'attaque enregistrée (ex: CADRE-PERSO-001). "
    "Requis avec --enregistrer si le brouillon n'en fournit pas.",
)
def suggest(description, technique, output, enregistrer, attaque_id):
    """
    Propose un brouillon d'attaque via l'assistant LLM local (Ollama).

    Sans --enregistrer : affiche seulement le brouillon (rien n'est ajouté).
    Avec --enregistrer : après validation de structure, l'attaque rejoint
    votre catalogue personnel et sera exécutée aux prochains cycles — mais
    déployée UNIQUEMENT si elle passe la double validation TP/FP, comme
    toute attaque native. L'IA propose, la validation dispose.
    """
    from .assistant_llm import obtenir_assistant_llm

    assistant = obtenir_assistant_llm()
    console.print(
        f"[magenta]Génération d'un brouillon via {assistant.modele} "
        f"({assistant.url})...[/magenta]\n"
    )

    brouillon = assistant.suggerer_attaque(description, technique_mitre=technique)
    if not brouillon:
        console.print(
            "[bold red]Échec de la génération[/bold red] "
            "(Ollama injoignable ou réponse invalide)."
        )
        console.print("   Vérifiez : [cyan]docker compose up -d ollama[/cyan]")
        sys.exit(1)

    if attaque_id:
        brouillon["id"] = attaque_id

    texte = json.dumps(brouillon, indent=2, ensure_ascii=False)
    console.print(
        Panel(
            Syntax(texte, "json", theme="ansi_dark", background_color="default"),
            title="BROUILLON IA — à valider avant tout ajout au catalogue",
            title_align="left",
            border_style="magenta",
        )
    )

    if output:
        Path(output).write_text(texte, encoding="utf-8")
        console.print(f"\nBrouillon écrit dans : [cyan]{output}[/cyan]")

    if enregistrer:
        from .catalogue_utilisateur import (
            ErreurCatalogueUtilisateur,
            enregistrer_attaque_utilisateur,
        )

        try:
            attaque = enregistrer_attaque_utilisateur(brouillon)
        except ErreurCatalogueUtilisateur as e:
            console.print(f"\n[bold red]Non enregistré :[/bold red] {e}")
            if "id" in str(e).lower() or not brouillon.get("id"):
                console.print(
                    "   Donnez un identifiant unique : "
                    "[cyan]cadre suggest -d '...' --enregistrer --id CADRE-PERSO-001[/cyan]"
                )
            sys.exit(1)
        console.print(
            f"\n[bold green]Attaque ajoutée à votre catalogue :[/bold green] "
            f"{attaque.id} ({attaque.technique_mitre})"
        )
        console.print(
            "   Elle sera exécutée aux prochains cycles. "
            "Vérifiez d'abord : [cyan]cadre cycle --id "
            f"{attaque.id} --dry-run[/cyan]"
        )


# Intentions de découverte sûres (lecture/énumération) proposées par défaut à
# l'agent IA — le filtre anti-destruction reste la garde dure quoi qu'il arrive.
_INTENTIONS_DECOUVERTE_DEFAUT: list[tuple[str, str | None]] = [
    ("Énumérer les tâches planifiées du système", "T1053.005"),
    ("Lister les partages réseau accessibles", "T1135"),
    ("Afficher la table de routage réseau", "T1016"),
    ("Lister les pilotes installés sur le système", "T1652"),
    ("Énumérer les variables d'environnement", "T1082"),
]


@cli.command()
@click.option(
    "--description",
    "-d",
    "descriptions",
    multiple=True,
    help="Intention d'attaque à faire générer par l'IA (répétable). "
    "Sans option, un jeu d'intentions de découverte sûres est utilisé.",
)
@click.option("--technique", "-t", default=None, help="Technique MITRE imposée (avec un seul -d)")
@click.option("--output", "-o", default="./rapports", help="Répertoire de sortie")
@click.option(
    "--revue",
    is_flag=True,
    help="S'arrête juste après la validation TP/FP, AVANT tout déploiement "
    "Kibana -- écrit un fichier de règle éditable + une entrée dans "
    "'cadre revue lister'. Approuver/rejeter séparément avec "
    "'cadre revue approuver|rejeter'. Jamais de prompt interactif.",
)
def decouvrir(descriptions, technique, output, revue):
    """
    Agent IA autonome : l'IA génère de NOUVELLES attaques, CADRE les
    exécute dans le labo isolé et n'ajoute que celles VALIDÉES (TP/FP).

    Quatre garde-fous : filtre anti-destruction (aucune commande destructrice
    exécutée) · labo host-only · validation avant conservation · avec
    --revue, aucun déploiement Kibana sans revue humaine. L'IA propose, les
    garde-fous disposent.
    """
    from .decouverte_ia import decouvrir_attaques

    if descriptions:
        intentions = list(descriptions)
        techniques = [technique] if technique and len(intentions) == 1 else None
    else:
        intentions = [d for d, _ in _INTENTIONS_DECOUVERTE_DEFAUT]
        techniques = [t for _, t in _INTENTIONS_DECOUVERTE_DEFAUT]

    console.print(
        Panel(
            Text(
                "L'IA va générer des attaques, CADRE les exécute dans le labo "
                "isolé et ne garde que les validées.\nGarde-fous : filtre "
                "anti-destruction · host-only · validation TP/FP"
                + (" · revue humaine avant déploiement" if revue else "")
                + ".",
                style="white",
            ),
            title="Découverte autonome par IA",
            border_style="magenta",
        )
    )

    orchestrateur = OrchestrateurCADRE(config={"repertoire_rapports": Path(output)})
    try:
        resultat = decouvrir_attaques(orchestrateur, intentions, techniques, revue=revue)
    except VerrouCycleActifError as e:
        _signaler_verrou_actif_et_quitter(e)

    synth = Text()
    synth.append("Découvertes et ajoutées : ", style="bold")
    synth.append(f"{len(resultat['decouvertes'])}\n", style="bold green")
    synth.append("Refusées (commande dangereuse) : ", style="bold")
    synth.append(f"{len(resultat['refusees'])}\n", style="bold red")
    synth.append("• Non validées / échecs : ", style="bold")
    synth.append(f"{len(resultat['echecs'])}", style="yellow3")
    console.print(Panel(synth, title="Bilan découverte", border_style="grey50"))

    for d in resultat["decouvertes"]:
        if d["statut"] == "EN_ATTENTE_REVUE":
            console.print(
                f"  [yellow3]{d['id']}[/yellow3] {d['technique_mitre']} — {d['nom']} "
                f"[dim](cadre revue approuver {d['rule_id_stable']})[/dim]"
            )
        else:
            console.print(f"  [green]{d['id']}[/green] {d['technique_mitre']} — {d['nom']}")
    for r in resultat["refusees"]:
        console.print(f"  [red]refusée[/red] (motif: {r['motif_refus']}) — {r['description']}")


# =============================================================================
# GROUPE REVUE : file d'attente de règles en attente de déploiement Kibana
# =============================================================================
@cli.group()
def revue():
    """Règles IA en attente de revue humaine avant déploiement Kibana."""


@revue.command(name="lister")
def revue_lister():
    """Liste les règles validées TP/FP mais pas encore déployées."""
    from .revue_regles import lister_revues

    entrees = lister_revues()
    if not entrees:
        console.print("[dim]Aucune règle en attente de revue.[/dim]")
        return

    table = Table(
        title="Règles en attente de revue",
        title_style="bold cyan",
        header_style="bold white",
        border_style="grey50",
        box=box.SIMPLE_HEAVY,
    )
    table.add_column("rule_id", style="cyan", no_wrap=True)
    table.add_column("Technique", no_wrap=True)
    table.add_column("Nom")
    table.add_column("TP", justify="right")
    table.add_column("FP", justify="right")
    table.add_column("Fichier", style="dim")
    for e in entrees:
        table.add_row(
            e["rule_id_stable"],
            e["technique_mitre"],
            e["nom_regle"],
            str(e["nb_tp"]),
            str(e["nb_fp"]),
            e["chemin_regle_sigma"],
        )
    console.print(table)
    console.print(
        "\n[dim]Approuver :[/dim] [cyan]cadre revue approuver <rule_id>[/cyan]  "
        "[dim]Rejeter :[/dim] [cyan]cadre revue rejeter <rule_id>[/cyan]"
    )


@revue.command(name="approuver")
@click.argument("rule_id")
@click.option(
    "--forcer",
    is_flag=True,
    help="Déployer même si la re-validation échoue après édition du YAML "
    "(échec tracé en log WARN, jamais silencieux).",
)
def revue_approuver(rule_id, forcer):
    """Revalide et déploie une règle en attente (potentiellement éditée)."""
    from .revue_regles import obtenir_revue, supprimer_revue

    entree = obtenir_revue(rule_id)
    if entree is None:
        console.print(f"[bold red]Aucune revue en attente pour :[/bold red] {rule_id}")
        console.print("Utilisez : [cyan]cadre revue lister[/cyan]")
        sys.exit(1)

    orchestrateur = OrchestrateurCADRE()
    resultat = orchestrateur.approuver_revue(entree, forcer=forcer)

    if resultat["deploye"]:
        style = "bold yellow3" if resultat["force"] else "bold green"
        titre = (
            "Déployée (forcée malgré échec de revalidation)" if resultat["force"] else "Déployée"
        )
        console.print(
            Panel(
                f"[{style}]{titre}[/{style}] — {rule_id}\n"
                f"TP={resultat['nb_tp']} FP={resultat['nb_fp']} — {resultat['raison']}",
                border_style="yellow3" if resultat["force"] else "green",
            )
        )
        supprimer_revue(rule_id)
    else:
        console.print(
            Panel(
                f"[bold red]Non déployée[/bold red] — {rule_id}\n"
                f"{resultat['statut']} : {resultat['raison']}\n"
                f"[dim]L'entrée reste en attente — corrigez le YAML et relancez, "
                f"ou utilisez --forcer.[/dim]",
                border_style="red",
            )
        )
        sys.exit(1)


@revue.command(name="rejeter")
@click.argument("rule_id")
def revue_rejeter(rule_id):
    """Rejette une règle en attente — rien n'est déployé, l'entrée est retirée."""
    from .revue_regles import supprimer_revue

    if supprimer_revue(rule_id):
        console.print(f"[green]Rejetée :[/green] {rule_id} — rien n'a été déployé.")
    else:
        console.print(f"[bold red]Aucune revue en attente pour :[/bold red] {rule_id}")
        sys.exit(1)


# =============================================================================
# GROUPE REGLE : édition encadrée d'une règle DÉJÀ déployée dans Kibana
# =============================================================================
@cli.group(name="regle")
def regle():
    """Gère une règle DÉJÀ déployée dans Kibana (lecture, édition encadrée)."""


@regle.command(name="lire")
@click.argument("rule_id")
def regle_lire(rule_id):
    """Affiche l'état actuel d'une règle déployée dans Kibana."""
    orchestrateur = OrchestrateurCADRE()
    donnees = orchestrateur.lire_regle_kibana(rule_id)
    if donnees is None:
        console.print(f"[bold red]Introuvable dans Kibana :[/bold red] {rule_id}")
        sys.exit(1)

    resume = Text()
    resume.append("Nom : ", style="bold")
    resume.append(f"{donnees.get('name', '?')}\n")
    resume.append("Type : ", style="bold")
    resume.append(f"{donnees.get('type', '?')}\n")
    resume.append("Activée : ", style="bold")
    resume.append(f"{donnees.get('enabled')}\n")
    resume.append("Index : ", style="bold")
    resume.append(f"{', '.join(donnees.get('index', []))}\n")
    resume.append("Tags : ", style="bold")
    resume.append(f"{', '.join(donnees.get('tags', []))}\n")
    resume.append("Requête : ", style="bold")
    resume.append(f"{donnees.get('query', '?')}", style="dim")
    console.print(Panel(resume, title=f"Règle Kibana — {rule_id}", border_style="grey50"))


def _chemin_regle_pour_edition(rule_id: str, fichier: str | None) -> Path:
    if fichier:
        return Path(fichier)
    return Path("rules_generees") / f"{rule_id.upper()}.yml"


@regle.command(name="editer")
@click.argument("rule_id")
@click.option(
    "--fichier",
    default=None,
    help="Fichier Sigma YAML à éditer (défaut : rules_generees/<RULE_ID>.yml).",
)
def regle_editer(rule_id, fichier):
    """Prépare un fichier Sigma éditable pour une règle déjà déployée."""
    from .catalogue_attaques import obtenir_attaque

    orchestrateur = OrchestrateurCADRE()
    donnees = orchestrateur.lire_regle_kibana(rule_id)
    if donnees is None:
        console.print(f"[bold red]Introuvable dans Kibana :[/bold red] {rule_id}")
        sys.exit(1)

    chemin_regle = _chemin_regle_pour_edition(rule_id, fichier)
    if not chemin_regle.is_file():
        attaque = obtenir_attaque(rule_id.upper())
        if attaque is None:
            console.print(
                f"[bold red]Aucun fichier local pour {rule_id}[/bold red] et aucune "
                f"attaque catalogue correspondante -- précisez [cyan]--fichier[/cyan] "
                f"vers un YAML Sigma existant."
            )
            sys.exit(1)
        chemin_regle.parent.mkdir(parents=True, exist_ok=True)
        chemin_regle.write_text(
            orchestrateur.generer_regle_sigma_depuis_attaque(attaque, {}), encoding="utf-8"
        )

    console.print(
        Panel(
            f"Règle actuellement dans Kibana : [bold]{donnees.get('name', rule_id)}[/bold]\n"
            f"Fichier à éditer : [cyan]{chemin_regle}[/cyan]\n\n"
            f"Éditez ce fichier YAML puis lancez :\n"
            f"[cyan]cadre regle pousser {rule_id}[/cyan]",
            title="Édition de règle",
            border_style="grey50",
        )
    )


@regle.command(name="pousser")
@click.argument("rule_id")
@click.option(
    "--fichier", default=None, help="Fichier Sigma YAML édité (même défaut que 'editer')."
)
@click.option(
    "--pipeline",
    type=click.Choice(["ecs_windows", "aucun"]),
    default="ecs_windows",
    help="Pipeline pySigma de compilation (Windows: ecs_windows, Linux: aucun).",
)
@click.option(
    "--forcer",
    is_flag=True,
    help="Déployer même si la re-validation échoue (échec tracé en log WARN, jamais silencieux).",
)
def regle_pousser(rule_id, fichier, pipeline, forcer):
    """Revalide et repousse une règle Kibana éditée."""
    chemin_regle = _chemin_regle_pour_edition(rule_id, fichier)
    if not chemin_regle.is_file():
        console.print(f"[bold red]Fichier introuvable :[/bold red] {chemin_regle}")
        console.print(f"Utilisez d'abord : [cyan]cadre regle editer {rule_id}[/cyan]")
        sys.exit(1)

    regle_sigma_yaml = chemin_regle.read_text(encoding="utf-8")
    orchestrateur = OrchestrateurCADRE()
    resultat = orchestrateur.redeployer_regle_editee(
        rule_id, regle_sigma_yaml, pipeline=pipeline, forcer=forcer
    )

    if resultat["deploye"]:
        style = "bold yellow3" if resultat["force"] else "bold green"
        titre = (
            "Déployée (forcée malgré échec de revalidation)" if resultat["force"] else "Déployée"
        )
        console.print(
            Panel(
                f"[{style}]{titre}[/{style}] — {rule_id}\n"
                f"TP={resultat['nb_tp']} FP={resultat['nb_fp']} — {resultat['raison']}",
                border_style="yellow3" if resultat["force"] else "green",
            )
        )
    else:
        console.print(
            Panel(
                f"[bold red]Non déployée[/bold red] — {rule_id}\n"
                f"{resultat['statut']} : {resultat['raison']}\n"
                f"[dim]La règle Kibana reste inchangée -- corrigez le YAML et "
                f"relancez, ou utilisez --forcer.[/dim]",
                border_style="red",
            )
        )
        sys.exit(1)


# =============================================================================
# COMMANDE RECHERCHER : recherche par mot-clé (catalogue + Atomic Red Team)
# =============================================================================
@cli.command(name="rechercher")
@click.argument("mot_cle")
@click.option(
    "--sans-atomic",
    is_flag=True,
    help="Ne cherche que dans le catalogue (natif + perso), pas dans Atomic Red Team.",
)
@click.option(
    "--repo",
    default=None,
    help="Dépôt Atomic Red Team local (défaut : jeu d'exemples embarqué).",
)
@click.option(
    "--decouvrir",
    "auto_decouvrir",
    is_flag=True,
    help="Si rien n'est trouvé, génère immédiatement l'attaque via l'IA "
    "(comme 'cadre decouvrir'), TOUJOURS avec revue avant déploiement -- "
    "contenu jamais éprouvé, jamais déployé sans revue humaine.",
)
@click.option("--output", "-o", default="./rapports", help="Répertoire de sortie")
def rechercher(mot_cle, sans_atomic, repo, auto_decouvrir, output):
    """Cherche une attaque par mot-clé dans le catalogue et Atomic Red Team."""
    from .recherche import rechercher_attaques

    resultat = rechercher_attaques(
        mot_cle,
        inclure_atomic=not sans_atomic,
        repertoire_atomic=Path(repo) if repo else None,
    )

    if resultat["catalogue"]:
        table = Table(
            title=f"Catalogue — résultats pour « {mot_cle} »",
            title_style="bold cyan",
            header_style="bold white",
            border_style="grey50",
            box=box.SIMPLE_HEAVY,
        )
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Technique", no_wrap=True)
        table.add_column("Nom")
        for a in resultat["catalogue"]:
            table.add_row(a.id, a.technique_mitre, a.nom)
        console.print(table)

    if resultat["atomic_red_team"]:
        table2 = Table(
            title="Atomic Red Team — résultats",
            title_style="bold cyan",
            header_style="bold white",
            border_style="grey50",
            box=box.SIMPLE_HEAVY,
        )
        table2.add_column("ID si importé", style="cyan", no_wrap=True)
        table2.add_column("Technique", no_wrap=True)
        table2.add_column("Nom")
        table2.add_column("Déjà importé", justify="center")
        for b in resultat["atomic_red_team"]:
            table2.add_row(
                b["id"],
                b["technique_mitre"],
                b["nom"],
                "[green]oui[/green]" if b["deja_importe"] else "[dim]non[/dim]",
            )
        console.print(table2)
        premiere_technique = resultat["atomic_red_team"][0]["technique_mitre"]
        console.print(
            "\n[dim]Importer :[/dim] "
            f"[cyan]cadre atomic --import --technique {premiere_technique}[/cyan]"
        )

    if resultat["trouve"]:
        return

    console.print(f"[yellow]Rien trouvé pour « {mot_cle} ».[/yellow]")
    if not auto_decouvrir:
        console.print(f'Utilisez : [cyan]cadre decouvrir -d "{mot_cle}" --revue[/cyan]')
        return

    console.print(
        "\n[magenta]Génération via l'IA[/magenta] — revue avant déploiement "
        "obligatoire (contenu jamais éprouvé).\n"
    )
    from .decouverte_ia import decouvrir_attaques

    orchestrateur = OrchestrateurCADRE(config={"repertoire_rapports": Path(output)})
    try:
        resultat_decouverte = decouvrir_attaques(orchestrateur, [mot_cle], revue=True)
    except VerrouCycleActifError as verrou:
        _signaler_verrou_actif_et_quitter(verrou)
    for d in resultat_decouverte["decouvertes"]:
        console.print(
            f"  [yellow3]{d['id']}[/yellow3] {d['technique_mitre']} — {d['nom']} "
            f"[dim](cadre revue approuver {d['rule_id_stable']})[/dim]"
        )
    for e in resultat_decouverte["echecs"]:
        console.print(f"  [red]échec[/red] — {e.get('raison', '')}")
    for r in resultat_decouverte["refusees"]:
        console.print(f"  [red]refusée[/red] (motif: {r['motif_refus']})")


# =============================================================================
# COMMANDE LOOP : boucle automatisée avec rotation
# =============================================================================
@cli.command()
@click.option(
    "--intervalle",
    "-i",
    default=3600,
    help="Intervalle entre cycles en secondes (défaut: 3600 = 1h)",
)
@click.option(
    "--max-cycles", "-n", default=None, type=int, help="Nombre max de cycles (défaut: infini)"
)
@click.option(
    "--techniques-par-cycle", "-t", default=4, help="Nombre d'attaques par cycle (défaut: 4)"
)
@click.option("--webhook", "-w", multiple=True, help="URL webhook Slack/Discord (répétable)")
@click.option("--email", help="Adresse email de destination")
@click.option("--smtp-host", help="Serveur SMTP")
@click.option("--smtp-port", default=587, help="Port SMTP (défaut: 587)")
@click.option("--smtp-user", help="Utilisateur SMTP")
@click.option(
    "--smtp-password",
    envvar="CADRE_SMTP_PASSWORD",
    help="Mot de passe SMTP (préférer la variable d'environnement CADRE_SMTP_PASSWORD "
    "pour éviter de l'exposer dans l'historique shell)",
)
@click.option("--smtp-from", default="cadre@example.com", help="Expéditeur")
@click.option("--no-rotation", is_flag=True, help="Désactiver la rotation des techniques")
def loop(
    intervalle,
    max_cycles,
    techniques_par_cycle,
    webhook,
    email,
    smtp_host,
    smtp_port,
    smtp_user,
    smtp_password,
    smtp_from,
    no_rotation,
):
    """
    Boucle automatisée : exécute des cycles d'audit en continu.

    Exemples:
      cadre loop --intervalle 1800                    # 1 cycle toutes les 30 min
      cadre loop --intervalle 3600 --max-cycles 24     # 1 cycle/h pendant 24h
      cadre loop --webhook https://hooks.slack.com/... # avec notif Slack
    """
    from .boucle import BoucleAutomatisee

    email_smtp = None
    if smtp_host:
        email_smtp = {
            "host": smtp_host,
            "port": smtp_port,
            "user": smtp_user,
            "password": smtp_password,
            "from": smtp_from,
        }

    infos = Text()
    infos.append("⏱ Intervalle : ", style="bold")
    infos.append(f"{intervalle}s\n", style="cyan")
    infos.append("Max cycles : ", style="bold")
    # `max_cycles or 'infini'` traiterait 0 (limite valide et distincte de
    # "illimité") comme "infini" -- 0 est falsy en Python.
    infos.append(f"{'infini' if max_cycles is None else max_cycles}\n", style="cyan")
    infos.append("Attaques/cycle : ", style="bold")
    infos.append(f"{techniques_par_cycle}\n", style="cyan")
    if webhook:
        infos.append("Webhooks : ", style="bold")
        infos.append(f"{len(webhook)} configuré(s)\n", style="cyan")
    if email:
        infos.append("Email : ", style="bold")
        infos.append(f"{email}\n", style="cyan")
    console.print(Panel(infos, title="Boucle automatisée CADRE", border_style="cyan"))
    console.print("[dim]Ctrl+C pour arrêter proprement après le cycle en cours.[/dim]\n")

    boucle = BoucleAutomatisee(
        intervalle_sec=intervalle,
        webhooks=list(webhook) if webhook else None,
        email_dest=email,
        email_smtp=email_smtp,
        rotation_techniques=not no_rotation,
        techniques_par_cycle=techniques_par_cycle,
    )
    stats_finales = boucle.demarrer(max_cycles=max_cycles)

    console.print("\n[bold]Statistiques cumulatives finales :[/bold]")
    click.echo(json.dumps(stats_finales, indent=2, ensure_ascii=False))


# =============================================================================
# COMMANDE DAEMON : mode service (avec fichier PID)
# =============================================================================
@cli.command()
@click.option("--intervalle", "-i", default=3600, help="Intervalle entre cycles en secondes")
@click.option("--pidfile", "-p", default="./cadre.pid", help="Fichier PID")
def daemon(intervalle, pidfile):
    """
    Mode daemon : lance CADRE en arrière-plan avec fichier PID.

    Équivalent de `cadre loop` mais détaché du terminal.
    """
    pidfile_path = Path(pidfile)
    if pidfile_path.exists():
        try:
            existing_pid = int(pidfile_path.read_text().strip())
        except ValueError:
            # Régression (audit) : un fichier PID au contenu non numérique
            # (vide, tronqué par un crash précédent, édité à la main) faisait
            # planter `int(...)` avec une ValueError brute non rattrapée --
            # traceback Python incompréhensible au lieu du message actionnable
            # déjà prévu juste en dessous pour le cas "PID mort". Un fichier
            # illisible est traité comme un fichier obsolète : nettoyé, puis
            # la commande continue normalement.
            console.print(f"[yellow3] Fichier PID illisible ({pidfile_path}) — nettoyage[/yellow3]")
            pidfile_path.unlink()
        else:
            try:
                os.kill(existing_pid, 0)  # Vérifie que le process existe
                console.print(f"[bold red]CADRE tourne déjà[/bold red] (PID {existing_pid})")
                sys.exit(1)
            except OSError:
                console.print(f"[yellow3] PID {existing_pid} mort — nettoyage[/yellow3]")
                pidfile_path.unlink()

    # Fork (mypy reconnaît sys.platform, pas os.name, comme garde de plateforme
    # pour exposer os.fork() dans les stubs — os.name == "posix" est équivalent
    # à l'exécution mais invisible pour l'analyse statique).
    if sys.platform != "win32":
        pid = os.fork()
        if pid > 0:
            # Parent
            pidfile_path.write_text(str(pid))
            console.print(f"[bold green]CADRE daemon démarré[/bold green] (PID {pid})")
            console.print(f"   PID file : [cyan]{pidfile_path.absolute()}[/cyan]")
            console.print(f"   Arrêter avec : kill {pid}")
            return
    else:
        # Régression (audit) : ce message affirmait le mode daemon
        # "non supporté" sur Windows, mais l'exécution continuait ensuite
        # tout droit vers "lance la boucle" (aucun `sys.exit`/`return` ici) --
        # `cadre daemon` sur Windows démarrait donc quand même la VRAIE
        # boucle continue (attaques réelles répétées contre la cible
        # configurée, jamais du simulé), au premier plan, en contradiction
        # totale avec le message qui vient d'être affiché. `sys.exit(1)`
        # arrête réellement la commande ici.
        console.print(
            "[yellow3] Mode daemon (fork + PID file) non supporté sur Windows[/yellow3] "
            "— utilisez 'cadre loop' dans un service/Task Scheduler."
        )
        sys.exit(1)

    # Enfant : lance la boucle -- mypy tourne sous Windows dans cet environnement
    # et traite donc `sys.platform == "win32"` comme statiquement vrai (option
    # --platform non fixée = plateforme d'exécution de mypy) : il ne voit que
    # la branche `else` ci-dessus (qui se termine par sys.exit) et croit ce
    # code jamais atteint. Réellement atteignable sur un vrai POSIX, où
    # `sys.platform != "win32"` sans le `return` du parent (fork==0, enfant).
    from .boucle import BoucleAutomatisee  # type: ignore[unreachable]

    boucle = BoucleAutomatisee(intervalle_sec=intervalle)
    try:
        boucle.demarrer()
    finally:
        if pidfile_path.exists():
            pidfile_path.unlink()


# =============================================================================
# COMMANDE METRICS : export Prometheus/Grafana
# =============================================================================
def _texte_metriques_prometheus(cumulatif_path: Path) -> str:
    """Construit le corps texte du endpoint `/metrics` à partir du fichier
    cumulatif le plus RÉCENT sur disque -- lu à chaque appel, jamais mis en
    cache.

    Régression (audit) : avant ce correctif, `stats` était lu UNE SEULE FOIS
    à l'appel de `cadre metrics` (avant l'instanciation de `MetricsHandler`),
    puis capturé par fermeture (closure) et réutilisé tel quel pour CHAQUE
    requête HTTP servie ensuite -- pendant toute la durée de vie du process,
    potentiellement des jours si lancé à côté de `cadre loop`/`cadre daemon`
    en service. Or ces deux commandes réécrivent `cadre_cumulatif.json`
    après CHAQUE cycle -- exactement la donnée que cet endpoint est censé
    exposer en continu à Prometheus. Résultat : tous les compteurs exportés
    (`cadre_cycles_total`, `cadre_validees_total`, ...) restaient figés à
    l'instantané pris au démarrage du serveur de métriques, quel que soit le
    nombre de cycles réels exécutés depuis -- un `rate()` PromQL dessus
    resterait à 0 pour toujours, une alerte Grafana sur la progression du
    cumul ne se déclencherait jamais. Isolé dans sa propre fonction (plutôt
    que relu inline dans `do_GET`) pour rester testable sans ouvrir un vrai
    port HTTP.
    """
    from .metriques import calculer_tendance_cumulative

    stats: dict[str, Any] = {}
    if cumulatif_path.exists():
        with contextlib.suppress(Exception):
            stats = json.loads(cumulatif_path.read_text(encoding="utf-8"))

    metrics_text = "# HELP cadre_cycles_total Total CADRE cycles executed\n"
    metrics_text += "# TYPE cadre_cycles_total counter\n"
    metrics_text += f"cadre_cycles_total {stats.get('total_cycles', 0)}\n"
    metrics_text += "# HELP cadre_validees_total Total validated rules\n"
    metrics_text += "# TYPE cadre_validees_total counter\n"
    metrics_text += f"cadre_validees_total {stats.get('validees', 0)}\n"
    metrics_text += "# HELP cadre_rejetees_total Total rejected rules (too many FP)\n"
    metrics_text += "# TYPE cadre_rejetees_total counter\n"
    metrics_text += f"cadre_rejetees_total {stats.get('rejetees', 0)}\n"
    metrics_text += "# HELP cadre_angles_morts_total Total blind spots\n"
    metrics_text += "# TYPE cadre_angles_morts_total counter\n"
    metrics_text += f"cadre_angles_morts_total {stats.get('angles_morts', 0)}\n"
    metrics_text += "# HELP cadre_erreurs_total Total errors\n"
    metrics_text += "# TYPE cadre_erreurs_total counter\n"
    metrics_text += f"cadre_erreurs_total {stats.get('erreurs', 0)}\n"
    cumul = calculer_tendance_cumulative(stats)
    if cumul:
        metrics_text += (
            "# HELP cadre_temps_gagne_heures_cumul Cumulative engineering "
            "hours saved across all cadre loop cycles\n"
        )
        metrics_text += "# TYPE cadre_temps_gagne_heures_cumul gauge\n"
        metrics_text += f"cadre_temps_gagne_heures_cumul {cumul['temps_gagne_heures_cumul']}\n"
    return metrics_text


@cli.command()
@click.option("--port", "-p", default=9090, help="Port HTTP (défaut: 9090)")
@click.option("--bind", default="127.0.0.1", help="Adresse de bind (défaut: 127.0.0.1)")
def metrics(port, bind):
    """
    Expose les métriques CADRE au format Prometheus (port HTTP).

    À scraper par Prometheus : http://localhost:9090/metrics
    """
    # Régression (audit) : `--port` n'était jamais validé -- un port hors
    # plage (ex. 99999, 0) passait le typage entier de click (valide comme
    # int) puis plantait dans ThreadingHTTPServer() avec un traceback
    # OverflowError/OSError incompréhensible au lieu d'un message clair.
    if not (1 <= port <= 65535):
        console.print(f"[bold red]Port invalide[/bold red] : {port} (attendu 1-65535)")
        sys.exit(1)

    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    cumulatif_path = Path("./rapports/cadre_cumulatif.json")

    class MetricsHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/metrics":
                # Relu à CHAQUE requête (voir _texte_metriques_prometheus) --
                # jamais l'instantané pris au démarrage du serveur.
                metrics_text = _texte_metriques_prometheus(cumulatif_path)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.end_headers()
                self.wfile.write(metrics_text.encode("utf-8"))
            elif self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "ok"}')
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            # Silencieux
            pass

    # ThreadingHTTPServer par cohérence avec le dashboard (dashboard.py) --
    # même si ce handler est en lecture seule (aucun état mutable partagé),
    # un scrape Prometheus lent ne doit pas bloquer le /health check.
    server = ThreadingHTTPServer((bind, port), MetricsHandler)
    console.print(
        f"[bold]Métriques Prometheus exposées sur[/bold] [cyan]http://{bind}:{port}/metrics[/cyan]"
    )
    console.print(f"   Health check : [cyan]http://{bind}:{port}/health[/cyan]")
    console.print("   [dim]Ctrl+C pour arrêter[/dim]")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\nArrêt du serveur de métriques")
        server.shutdown()


# =============================================================================
# COMMANDE DASHBOARD : interface web locale (pilotage complet + catalogue)
# =============================================================================
@cli.command()
@click.option("--port", "-p", default=8765, help="Port HTTP (défaut: 8765)")
@click.option("--bind", default="127.0.0.1", help="Adresse de bind (défaut: 127.0.0.1)")
@click.option("--output", "-o", default="./rapports", help="Répertoire des rapports à afficher")
def dashboard(port, bind, output):
    """
    Dashboard web local : parcourt les cycles déjà exécutés, affiche le
    détail par statut, sert les rapports (HTML/CSV/MD/Navigator), explore le
    catalogue d'attaques (description, payload) et permet de lancer un
    cycle complet ou une attaque individuelle, en mode SIMULATION ou RÉEL.
    Un lancement réel touche la vraie VM/SIEM configurés : la route HTTP
    exige une confirmation explicite, sinon elle refuse (400). Un seul
    cycle/une seule attaque à la fois. Aucune authentification en local
    (bind 127.0.0.1 par défaut). Pour un usage en équipe (--bind non-
    loopback), un mot de passe devient obligatoire : cadre init
    --set CADRE_DASHBOARD_PASSWORD=<mot de passe> -- sinon le
    serveur refuse de démarrer.
    """
    # Régression (audit) : même défaut que `cadre metrics --port` avant
    # correction -- un port hors plage (ex. 99999, -1) passe le typage
    # entier de click (valide comme int) puis plante dans
    # ThreadingHTTPServer() avec un OverflowError/OSError brut
    # ("bind(): port must be 0-65535") au lieu d'un message clair. Les deux
    # commandes ouvrent un ThreadingHTTPServer sur un port utilisateur --
    # elles doivent se comporter pareil face à une entrée invalide.
    if not (1 <= port <= 65535):
        console.print(f"[bold red]Port invalide[/bold red] : {port} (attendu 1-65535)")
        sys.exit(1)

    from .dashboard import lancer_dashboard

    console.print(f"[bold]Dashboard CADRE[/bold] sur [cyan]http://{bind}:{port}/[/cyan]")
    console.print(f"   Rapports lus depuis : [dim]{output}[/dim]")
    console.print("   [dim]Ctrl+C pour arrêter[/dim]")
    lancer_dashboard(port=port, bind=bind, repertoire_rapports=Path(output))


def _exporter_catalogue_csv(fichier: Path) -> None:
    """Exporte le catalogue en CSV pour Excel/LibreOffice (audit, présentation)."""
    fichier.parent.mkdir(parents=True, exist_ok=True)
    champs = [
        "id",
        "nom",
        "technique_mitre",
        "tactique_mitre",
        "plateforme",
        "niveau_risque",
        "event_ids_attendus",
        "commande",
    ]
    with fichier.open("w", encoding="utf-8-sig", newline="") as f:  # BOM -> accents OK dans Excel
        writer = csv.DictWriter(f, fieldnames=champs, extrasaction="ignore")
        writer.writeheader()
        for a in catalogue_actif():
            writer.writerow(
                {
                    k: _defuse_formule_csv(v)
                    for k, v in {
                        "id": a.id,
                        "nom": a.nom,
                        "technique_mitre": a.technique_mitre,
                        "tactique_mitre": a.tactique_mitre,
                        "plateforme": a.plateforme.value,
                        "niveau_risque": a.niveau_risque.value,
                        "event_ids_attendus": ",".join(a.event_ids_attendus),
                        "commande": a.commande,
                    }.items()
                }
            )


@cli.command(name="list")
@click.option(
    "--csv",
    "fichier_csv",
    default=None,
    help="Exporte le catalogue vers ce fichier CSV au lieu de l'afficher (Excel/LibreOffice)",
)
def list_attaques(fichier_csv):
    # NB: la fonction n'est PAS nommée "list" — ce nom masquerait le
    # list() builtin Python dans tout ce module (bug réel découvert :
    # "cadre cycle --technique ..." et "cadre loop --webhook ..." plantaient
    # silencieusement à cause de list(technique)/list(webhook) qui
    # résolvaient vers cette commande Click au lieu du constructeur natif).
    # @cli.command(name="list") garde "cadre list" identique pour l'utilisateur.
    """Liste les attaques du catalogue."""
    if fichier_csv:
        _exporter_catalogue_csv(Path(fichier_csv))
        console.print(f"[bold green]Catalogue exporté :[/bold green] {fichier_csv}")
        return

    catalogue = catalogue_actif()
    nb_perso = len(catalogue) - len(CATALOGUE)
    titre = f"Catalogue CADRE — {len(catalogue)} attaques"
    if nb_perso:
        titre += f" (dont {nb_perso} perso)"
    table = Table(
        title=titre,
        title_style="bold cyan",
        header_style="bold white",
        border_style="grey50",
        box=box.SIMPLE_HEAVY,
    )
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Technique", style="bold", no_wrap=True)
    table.add_column("Tactique", no_wrap=True)
    table.add_column("Risque", no_wrap=True)
    table.add_column("Nom")
    ids_natifs = {a.id for a in CATALOGUE}
    for a in catalogue:
        couleur = COULEUR_RISQUE.get(a.niveau_risque.value, "white")
        marque = "" if a.id in ids_natifs else " [magenta][/magenta]"
        table.add_row(
            a.id,
            a.technique_mitre,
            a.tactique_mitre,
            f"[{couleur}]{a.niveau_risque.value}[/{couleur}]",
            a.nom + marque,
        )
    console.print(table)


@cli.command()
@click.option("--json", "sortie_json", is_flag=True, help="Sortie JSON brute (scriptable)")
def stats(sortie_json):
    """Affiche les statistiques du catalogue d'attaques."""
    s = statistiques_catalogue()
    doublons = detecter_regles_similaires()
    if sortie_json:
        click.echo(json.dumps({**s, "regles_similaires": doublons}, indent=2, ensure_ascii=False))
        return

    resume = Text()
    resume.append(str(s["total"]), style="bold cyan")
    resume.append(" attaques   ")
    resume.append(str(s["tactiques_uniques"]), style="bold cyan")
    resume.append(" tactiques   ")
    resume.append(str(s["techniques_uniques"]), style="bold cyan")
    resume.append(" techniques uniques")
    console.print(Panel(resume, title="Statistiques du catalogue", border_style="cyan"))

    table_tactiques = Table(title="Par tactique MITRE", header_style="bold white", box=box.SIMPLE)
    table_tactiques.add_column("Tactique")
    table_tactiques.add_column("Attaques", justify="right")
    for tactique, n in sorted(s["par_tactique"].items(), key=lambda kv: -kv[1]):
        table_tactiques.add_row(tactique, str(n))

    table_risque = Table(title="Par niveau de risque", header_style="bold white", box=box.SIMPLE)
    table_risque.add_column("Niveau")
    table_risque.add_column("Attaques", justify="right")
    for niveau, n in s["par_niveau_risque"].items():
        couleur = COULEUR_RISQUE.get(niveau, "white")
        table_risque.add_row(f"[{couleur}]{niveau}[/{couleur}]", str(n))

    console.print(Columns([table_tactiques, table_risque]))

    if doublons:
        table_doublons = Table(
            title=" Règles à logique de détection identique (au-delà du nom)",
            header_style="bold yellow",
            box=box.SIMPLE,
        )
        table_doublons.add_column("Attaques concernées")
        for groupe in doublons:
            table_doublons.add_row(", ".join(groupe))
        console.print(table_doublons)


def main():
    cli()


if __name__ == "__main__":
    main()
