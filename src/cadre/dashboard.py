# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Dashboard web local
============================

Serveur HTTP local (bibliothèque standard uniquement — même approche que
`cadre metrics`, pas de nouvelle dépendance) qui donne un accès complet
au pilotage de CADRE depuis un navigateur :

- Liste les cycles déjà exécutés et affiche le détail par statut.
- Sert en lecture seule les rapports déjà générés (HTML, CSV, Markdown,
  layer ATT&CK Navigator) avec garde anti path-traversal.
- Vérifie l'état de la stack (Elasticsearch, Kibana, VM cible) — même
  logique que `cadre status`.
- Liste le catalogue d'attaques (lecture seule).
- Liste les secrets configurés (jamais leurs valeurs) et permet d'en
  définir de nouveaux, via le coffre-fort habituel (journalisé comme
  tout accès au coffre-fort — voir `coffre_fort.py`).
- Découverte IA (`cadre decouvrir`) : décrit une attaque en langage naturel,
  l'agent la génère, l'exécute réellement et la valide TP/FP. `/api/suggest`
  et `/api/suggest/enregistrer` (équivalent HTTP de `cadre suggest
  --enregistrer`) existent aussi -- plus légers, sans exécution ni
  validation TP/FP, seulement le garde-fou anti-destruction -- mais
  DÉLIBÉRÉMENT sans bouton dans l'interface : Découverte IA couvre le même
  besoin opérateur avec `revue: true`, en filtrant en plus par une preuve
  réelle de détection avant tout ajout au catalogue. Ces deux routes restent
  disponibles (testées) pour un usage API direct, pas pour l'ergonomie du
  dashboard.
- Lance un cycle complet, en mode SIMULATION ou RÉEL. Un cycle réel
  touche la vraie VM/SIEM configurés : la route HTTP exige un champ
  `confirmer: true` explicite dans le corps de la requête, sans quoi
  elle refuse (400) — aucun bouton de l'interface ne peut le contourner
  silencieusement. Un seul cycle à la fois, quel que soit le mode.

Bind 127.0.0.1 par défaut : outil de pilotage local, pas un service
exposé, aucune authentification requise dans ce mode. Le même principe
de confiance que la CLI elle-même (qui exécute déjà des cycles réels
sans confirmation) — la confirmation ajoutée ici est une garde
supplémentaire contre un clic accidentel, pas un modèle de sécurité
multi-utilisateurs.

Usage en équipe (`--bind` non-loopback) : une authentification HTTP
Basic devient OBLIGATOIRE (secret `CADRE_DASHBOARD_PASSWORD`, comparaison
en temps constant, verrouillage anti-brute-force par IP source) — le
serveur refuse de démarrer sans ce secret configuré. Limite assumée :
Basic Auth encode, ne chiffre pas — un reverse-proxy TLS (nginx/Caddy)
en amont est requis pour un vrai déploiement réseau, CADRE ne le fournit
pas lui-même.
"""

from __future__ import annotations

import base64
import csv
import hmac
import json
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

import requests
import urllib3

from .logger import obtenir_logger
from .rapport import _COULEUR_PAR_STATUT, _TITRES_STATUTS
from .reseau import verifier_tls

if TYPE_CHECKING:
    from .catalogue_attaques import AttaqueCatalogue

# Racine du frontend statique (dashboard/ à la racine du projet). Résolu depuis
# ce fichier (src/cadre/dashboard.py -> parents[2] = racine projet) pour être
# indépendant du répertoire courant ; repli sur ./dashboard si la disposition
# diffère.
_REP_DASHBOARD = Path(__file__).resolve().parents[2] / "dashboard"
if not _REP_DASHBOARD.is_dir():
    _REP_DASHBOARD = Path("dashboard").resolve()

# Content-Security-Policy stricte : tout en 'self', aucune ressource distante,
# aucun script/style inline (pas d'unsafe-inline). Cohérent avec la posture
# "hors-ligne, zéro dépendance externe". frame-ancestors 'none' = anti-clickjacking.
_CSP_DASHBOARD = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'none'; object-src 'none'"
)

# Types MIME servis par le frontend statique (liste blanche stricte).
_TYPES_CONTENU: dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".png": "image/png",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".md": "text/markdown; charset=utf-8",
}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_PREFIXE_CYCLE = "cycle_"


def lister_cycles(repertoire_rapports: Path) -> list[dict[str, Any]]:
    """
    Liste les cycles déjà exécutés, du plus récent au plus ancien, à
    partir des fichiers `cycle_<horodatage>.csv` déjà générés par
    `rapport.generer_csv()`.
    """
    if not repertoire_rapports.is_dir():
        return []

    fichiers_csv = sorted(repertoire_rapports.glob(f"{_PREFIXE_CYCLE}*.csv"), reverse=True)

    # Un seul glob pour TOUS les rapports de scénario, avant la boucle --
    # un `glob()` par cycle À L'INTÉRIEUR de la boucle ci-dessous était
    # O(n²) (mesuré : ~9s pour 500 cycles, ~35s pour 1000, largement dans
    # la trajectoire du projet à son rythme de croisement actuel). Indexé
    # par horodatage : le format est TOUJOURS %Y%m%d_%H%M%S (15 caractères
    # fixes, voir orchestrateur.py/_horodatage_lisible), donc les 15
    # derniers caractères du nom de fichier (avant ".html") isolent
    # l'horodatage sans ambiguïté, même si l'ID de scénario contient
    # lui-même des "_" (ex. scenario_CADRE-SCENARIO-001_20260814_153045).
    scenario_par_horodatage = {
        f.stem[-15:]: f.name for f in repertoire_rapports.glob("scenario_*.html")
    }

    cycles = []
    for fichier_csv in fichiers_csv:
        horodatage = fichier_csv.stem[len(_PREFIXE_CYCLE) :]
        lignes = _lire_csv(fichier_csv)
        compteurs: dict[str, int] = {}
        for ligne in lignes:
            statut = ligne.get("statut", "?")
            compteurs[statut] = compteurs.get(statut, 0) + 1
        cycles.append(
            {
                "horodatage": horodatage,
                "total": len(lignes),
                "compteurs": compteurs,
                "html_disponible": (repertoire_rapports / f"cycle_{horodatage}.html").exists(),
                "navigator_disponible": (
                    repertoire_rapports / f"cycle_{horodatage}_navigator.json"
                ).exists(),
                "markdown_disponible": (repertoire_rapports / f"cycle_{horodatage}.md").exists(),
                "pdf_disponible": (repertoire_rapports / f"cycle_{horodatage}.pdf").exists(),
                "scenario_html": scenario_par_horodatage.get(horodatage),
            }
        )
    return cycles


def dernier_cycle(repertoire_rapports: Path) -> dict[str, Any] | None:
    """
    Résumé du cycle le plus RÉCENT uniquement -- même forme qu'un élément de
    `lister_cycles()`, mais sans lire tous les CSV historiques (un seul,
    celui du dernier cycle). `vue-ensemble.js`/`detections.js`/`erreurs.js`
    n'ont jamais besoin que de `cycles[0]` -- passer par `lister_cycles()`
    pour ça leur imposait le coût O(n) de l'historique complet à chaque
    sondage, pour ne garder qu'un seul élément.
    """
    if not repertoire_rapports.is_dir():
        return None
    fichiers_csv = sorted(repertoire_rapports.glob(f"{_PREFIXE_CYCLE}*.csv"), reverse=True)
    if not fichiers_csv:
        return None
    fichier_csv = fichiers_csv[0]
    horodatage = fichier_csv.stem[len(_PREFIXE_CYCLE) :]
    lignes = _lire_csv(fichier_csv)
    compteurs: dict[str, int] = {}
    for ligne in lignes:
        statut = ligne.get("statut", "?")
        compteurs[statut] = compteurs.get(statut, 0) + 1
    scenario_html = next(
        (f.name for f in repertoire_rapports.glob(f"scenario_*_{horodatage}.html")),
        None,
    )
    return {
        "horodatage": horodatage,
        "total": len(lignes),
        "compteurs": compteurs,
        "html_disponible": (repertoire_rapports / f"cycle_{horodatage}.html").exists(),
        "navigator_disponible": (
            repertoire_rapports / f"cycle_{horodatage}_navigator.json"
        ).exists(),
        "markdown_disponible": (repertoire_rapports / f"cycle_{horodatage}.md").exists(),
        "pdf_disponible": (repertoire_rapports / f"cycle_{horodatage}.pdf").exists(),
        "scenario_html": scenario_html,
    }


def detail_cycle(repertoire_rapports: Path, horodatage: str) -> dict[str, Any] | None:
    """Détail complet (toutes les lignes) d'un cycle donné, groupé par statut."""
    # Régression sécurité (traversée de chemin) : `horodatage` vient tel
    # quel de l'URL cliente (route GET /api/cycles/<horodatage>, sans garde
    # CSRF puisque GET) -- une simple concaténation laissait un segment
    # `../` s'échapper de `repertoire_rapports` et lire n'importe quel
    # fichier `*.csv` lisible par le processus, n'importe où sur le disque.
    fichier_csv = chemin_securise(repertoire_rapports, f"cycle_{horodatage}.csv")
    if fichier_csv is None:
        return None

    lignes = _lire_csv(fichier_csv)
    groupes: dict[str, list[dict[str, Any]]] = {}
    for ligne in lignes:
        groupes.setdefault(ligne.get("statut", "?"), []).append(ligne)

    return {
        "horodatage": horodatage,
        "total": len(lignes),
        "groupes": groupes,
        "titres_statuts": _TITRES_STATUTS,
        "couleurs_statuts": _COULEUR_PAR_STATUT,
    }


def _lire_csv(fichier_csv: Path) -> list[dict[str, Any]]:
    # "utf-8-sig" retire le BOM éventuel écrit par generer_csv (compat. Excel)
    # sans casser la lecture d'un CSV sans BOM. Un fichier disparu entre le
    # listing et la lecture (TOCTOU) renvoie [] plutôt que de faire crasher la
    # requête dashboard.
    try:
        with fichier_csv.open(encoding="utf-8-sig", newline="") as f:
            return list(csv.DictReader(f))
    except FileNotFoundError:
        return []


def metriques_dernier_cycle(repertoire_rapports: Path) -> dict[str, Any]:
    """Indicateurs de valeur métier du cycle le plus récent (délègue à `metriques`)."""
    from .metriques import metriques_dernier_cycle as _calcul  # noqa: PLC0415

    return _calcul(repertoire_rapports)


def derive_toutes_regles(repertoire_rapports: Path) -> dict[str, Any]:
    """Historique de dérive de tout le catalogue (délègue à `metriques`) --
    vue d'ensemble dashboard, une passe sur les cycles archivés."""
    from .metriques import detecter_derive_toutes_regles as _calcul  # noqa: PLC0415

    return {"derives": _calcul(repertoire_rapports)}


def _horodatage_lisible(ts: str) -> str:
    """cycle_20260804_201919 -> 2026-08-04 20:19:19 (sinon renvoie tel quel)."""
    corps = ts[len(_PREFIXE_CYCLE) :] if ts.startswith(_PREFIXE_CYCLE) else ts
    if len(corps) == 15 and corps[8] == "_" and corps.replace("_", "").isdigit():
        d, h = corps[:8], corps[9:]
        return f"{d[:4]}-{d[4:6]}-{d[6:8]} {h[:2]}:{h[2:4]}:{h[4:6]}"
    return ts


def page_index_rapports(repertoire_rapports: Path) -> str:
    """
    Page HTML autonome listant TOUS les rapports de cycle (du plus récent au
    plus ancien), avec pour chacun ses liens HTML / Markdown / CSV / Navigator.
    Servie sur /rapports/ ; c'est la destination du lien « Tous les rapports ».
    """
    cycles = lister_cycles(repertoire_rapports)
    familles = [
        ("VALIDE", "validées", "#5fae7d"),
        ("VALIDE_NON_DEPLOYE", "validées (non déployées)", "#9bc47f"),
        ("EN_ATTENTE_REVUE", "en attente de revue", "#00c2a8"),
        ("REJETE", "rejetées", "#d9a44e"),
        ("ANGLE_MORT", "angles morts", "#d9705f"),
        ("ERREUR", "erreurs", "#8a9490"),
        ("NON_APPLICABLE", "non applicables", "#6d7773"),
    ]

    def _lien_rapport(horodatage: str, ext: str, lab: str, ok: bool, telecharger: bool) -> str:
        if not ok:
            return f'<span class="off">{lab}</span>'
        attribut = "download" if telecharger else 'target="_blank"'
        return f'<a href="/rapports/cycle_{horodatage}{ext}" {attribut}>{lab}</a>'

    lignes = []
    for c in cycles:
        ts = c["horodatage"]
        compteurs = c["compteurs"]
        pills = "".join(
            f'<span class="pill"><i style="background:{coul}"></i>{compteurs[cle]} {lab}</span>'
            for cle, lab, coul in familles
            if compteurs.get(cle)
        )
        versions = [
            (".html", "HTML", True, False),
            (".md", "Markdown", c["markdown_disponible"], False),
            (".csv", "CSV", True, False),
            # `download` : téléchargement direct du binaire, sans passer par
            # un onglet HTML intermédiaire -- c'est tout l'intérêt du PDF ici
            # (les autres formats s'ouvrent pour consultation, celui-ci se
            # télécharge en un clic).
            (".pdf", "PDF", c["pdf_disponible"], True),
            ("_navigator.json", "Navigator", c["navigator_disponible"], False),
        ]
        liens = "".join(
            _lien_rapport(ts, ext, lab, ok, telecharger) for ext, lab, ok, telecharger in versions
        )
        if c.get("scenario_html"):
            liens += (
                f'<a href="/rapports/{c["scenario_html"]}" target="_blank" '
                f'class="kc">Kill chain</a>'
            )
        lignes.append(
            f'<div class="carte"><div class="tete"><span class="ts">{_horodatage_lisible(ts)}</span>'
            f'<span class="tot">{c["total"]} attaque(s)</span></div>'
            f'<div class="pills">{pills}</div><div class="liens">{liens}</div></div>'
        )
    corps = "".join(lignes) or '<p class="vide">Aucun rapport pour l\'instant.</p>'
    return f"""<!doctype html>
<html lang="fr" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CADRE — Tous les rapports ({len(cycles)})</title>
<style>
:root {{ --bg:#10161a; --surface:#171f24; --surface2:#1c252b; --border:#29343a; --border2:#3d4a45;
  --ink:#e9ebe6; --ink2:#a3aca8; --ink3:#6d7773; --accent:#d9a44e; --accent2:#f0c274; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; padding:2rem 1.5rem 4rem; background:var(--bg); color:var(--ink);
  font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
.wrap {{ max-width:900px; margin:0 auto; }}
header {{ border-bottom:2px solid var(--accent); padding-bottom:0.8rem; margin-bottom:1.5rem; }}
.marque {{ font-weight:700; letter-spacing:0.12em; color:var(--accent); font-size:0.8rem; }}
h1 {{ margin:0.2rem 0 0; font-size:1.4rem; }}
.sous {{ color:var(--ink3); font-size:0.85rem; margin-top:0.3rem; }}
a.retour {{ color:var(--accent2); text-decoration:none; font-size:0.82rem; }}
.carte {{ background:var(--surface); border:1px solid var(--border); border-radius:8px;
  padding:0.9rem 1.1rem; margin-bottom:0.7rem; }}
.tete {{ display:flex; justify-content:space-between; align-items:baseline; gap:10px; }}
.ts {{ font-family:ui-monospace,Consolas,monospace; font-weight:600; }}
.tot {{ color:var(--ink3); font-size:0.75rem; }}
.pills {{ display:flex; flex-wrap:wrap; gap:6px; margin:0.5rem 0; }}
.pill {{ display:inline-flex; align-items:center; gap:6px; font-size:0.7rem; color:var(--ink2);
  border:1px solid var(--border2); border-radius:999px; padding:2px 9px; }}
.pill i {{ width:8px; height:8px; border-radius:50%; }}
.liens {{ display:flex; flex-wrap:wrap; gap:8px; padding-top:0.5rem; border-top:1px dashed var(--border); }}
.liens a {{ font-size:0.76rem; text-decoration:none; color:var(--ink2); background:var(--bg);
  border:1px solid var(--border2); border-radius:5px; padding:4px 10px; }}
.liens a:hover {{ color:var(--accent2); border-color:var(--accent); }}
.liens a.kc {{ color:var(--accent2); border-color:var(--accent); font-weight:600; }}
.liens .off {{ font-size:0.76rem; color:var(--ink3); opacity:0.4; padding:4px 10px;
  text-decoration:line-through; }}
.vide {{ color:var(--ink3); font-style:italic; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="marque">CADRE</div>
    <h1>Tous les rapports</h1>
    <div class="sous">{len(cycles)} cycle(s) au total · du plus récent au plus ancien ·
      <a class="retour" href="/">← retour au dashboard</a></div>
  </header>
  {corps}
</div>
</body>
</html>
"""


def chemin_securise(repertoire: Path, nom_fichier: str) -> Path | None:
    """
    Résout `nom_fichier` à l'intérieur de `repertoire` et refuse toute
    tentative de sortie (`../`, chemin absolu) — retourne None si le
    fichier demandé n'est pas réellement sous `repertoire`.
    """
    base = repertoire.resolve()
    cible = (base / nom_fichier).resolve()
    if not cible.is_relative_to(base) or not cible.is_file():
        return None
    return cible


def _chemin_ecriture_securise(repertoire: Path, nom_fichier: str) -> Path | None:
    """Comme `chemin_securise()`, mais pour un fichier PAS ENCORE CRÉÉ
    (écriture) -- ne vérifie donc pas `is_file()`, seulement que la cible
    calculée reste bien sous `repertoire` (refuse `../`, chemin absolu hors
    de `repertoire`)."""
    base = repertoire.resolve()
    cible = (base / nom_fichier).resolve()
    if not cible.is_relative_to(base):
        return None
    return cible


def tail_logs(fichier_log: Path, n: int = 50) -> list[dict[str, Any]]:
    """Retourne les `n` derniers événements de niveau visible du logger JSON
    (le plus récent en dernier).

    Exclut les entrées DEBUG (régression, audit navigateur réel) : le
    fichier sur disque reste une trace d'audit complète et volontairement
    non filtrée (voir `Logger.evenement`), mais `SECRET_READ` — journalisé
    en DEBUG précisément pour ne pas inonder la CONSOLE, car le dashboard
    relit ce secret à chaque sondage HTTP (auth vérifiée sur chaque
    requête, toutes les 2 à 9 s selon le sondeur) — inondait quand même
    cette vue-ci : après une minute d'ouverture du dashboard, les 60
    dernières lignes affichées étaient à 100 % `SECRET_READ`, masquant
    toute erreur ou avertissement réel. Cette vue est, comme la console,
    une surface de suivi en direct — pas la trace d'audit elle-même — donc
    la même politique de filtrage s'y applique.

    `n <= 0` renvoie explicitement [] ("les n derniers événements" pour
    n=0, c'est aucun -- l'attente intuitive) et `n` est plafonné à 1000 :
    sans ces deux gardes, `lignes[-n:]` exploite le comportement de slicing
    Python `lignes[-0:]` == `lignes[0:]` (n=0 renvoyait TOUT le fichier de
    journal au lieu de rien) et `lignes[-(-5):]` == `lignes[5:]` (un n
    négatif produisait un résultat tout aussi surprenant, quasiment tout le
    fichier aussi).
    """
    if not fichier_log.is_file() or n <= 0:
        return []
    n = min(n, 1000)
    lignes = fichier_log.read_text(encoding="utf-8").strip().split("\n")
    evenements: list[dict[str, Any]] = []
    for ligne in reversed(lignes):
        if len(evenements) >= n:
            break
        if not ligne:
            continue
        try:
            evenement = json.loads(ligne)
        except json.JSONDecodeError:
            continue
        if evenement.get("niveau") == "DEBUG":
            continue
        evenements.append(evenement)
    evenements.reverse()
    return evenements


def _verifier_service_http(url: str, auth: tuple | None) -> dict[str, Any]:
    """Un service HTTP (ES/Kibana) — factorisé pour tourner en thread (voir
    `verifier_statut_stack`)."""
    try:
        r = requests.get(url, timeout=5, verify=verifier_tls(), auth=auth)
        return {"ok": r.status_code == 200, "detail": f"HTTP {r.status_code}", "url": url}
    except requests.exceptions.RequestException:
        # Détail court et lisible pour l'UI (la stack trace complète part
        # dans les logs si besoin, jamais dans un panneau utilisateur).
        return {
            "ok": False,
            "detail": "injoignable — démarrez la stack (docker compose up -d)",
            "url": url,
        }


def verifier_statut_stack(config: dict[str, Any], orchestrateur: Any = None) -> dict[str, Any]:
    """
    Vérifie Elasticsearch, Kibana (HTTP) et la VM cible (port WinRM) —
    même logique que `cadre status`, réutilisable depuis le web.

    U3/G1 : les 3 vérifications sont indépendantes (aucun état partagé,
    aucune dépendance d'ordre) — exécutées en parallèle plutôt qu'en
    séquence. Sur le chemin heureux, gain négligeable (déjà rapide) ; sur le
    chemin d'échec, borne le pire cas au timeout le plus long (5s) au lieu
    d'un cumul séquentiel (jusqu'à ~13s avant ce correctif — voir
    REVUE/U1-e2e.md §1).

    `orchestrateur` (optionnel) : réutilise une instance déjà construite au
    lieu d'en fabriquer une nouvelle. Régression (audit, mesurée en réel) :
    la barre d'état du dashboard sonde `/api/statut` toutes les 5s -- sans
    ce paramètre, chaque sondage reconstruisait un `OrchestrateurCADRE`
    complet, qui recharge et rejournalise (`SECRET_READ`) une dizaine de
    secrets à chaque fois (dont plusieurs sans rapport avec cette
    vérification -- mots de passe VM Linux, comptes de test brute force...),
    alors qu'aucun ne change entre deux sondages. Mesuré : 979/1000
    dernières entrées de journal réduites à du bruit en quelques minutes,
    évinçant la trace réelle d'un cycle (WinRM, indexation, déploiements).
    `creer_gestionnaire()` construit désormais un orchestrateur unique,
    réutilisé pour toute la durée de vie du serveur dashboard, et le passe
    ici. Paramètre optionnel : `verification_globale()` (bouton manuel, pas
    de sondage répété) continue de construire une instance fraîche, sans
    changement de comportement.
    """
    if orchestrateur is None:
        from .orchestrateur import OrchestrateurCADRE  # noqa: PLC0415

        orchestrateur = OrchestrateurCADRE(config=config)
    vm_ip = orchestrateur.config.get("vm_ip", "")

    with ThreadPoolExecutor(max_workers=3) as executeur:
        futur_es = executeur.submit(
            _verifier_service_http,
            orchestrateur.config["elastic_url"],
            orchestrateur.auth_elastic,
        )
        futur_kibana = executeur.submit(
            _verifier_service_http,
            orchestrateur.config["kibana_url"],
            orchestrateur.auth_elastic,
        )
        futur_vm = executeur.submit(orchestrateur._verifier_connectivite_vm)

        resultat: dict[str, Any] = {
            "elasticsearch": futur_es.result(),
            "kibana": futur_kibana.result(),
            "vm": {"ok": futur_vm.result(), "detail": vm_ip or "non configurée", "url": vm_ip},
        }
    return resultat


def lister_catalogue() -> list[dict[str, Any]]:
    """Catalogue actif en lecture seule (natif + attaques perso de l'utilisateur)."""
    from .catalogue_attaques import CATALOGUE, catalogue_actif  # noqa: PLC0415

    ids_natifs = {a.id for a in CATALOGUE}
    return [
        {
            "id": a.id,
            "nom": a.nom,
            "technique_mitre": a.technique_mitre,
            "tactique_mitre": a.tactique_mitre,
            "plateforme": a.plateforme.value,
            "niveau_risque": a.niveau_risque.value,
            "event_ids_attendus": a.event_ids_attendus,
            "perso": a.id not in ids_natifs,
        }
        for a in catalogue_actif()
    ]


def detail_attaque(identifiant: str) -> dict[str, Any] | None:
    """Détail complet d'une attaque (description + payload) pour la fiche
    dashboard — None si l'ID est inconnu. Contrairement à `lister_catalogue()`
    (liste légère, jamais `commande` -- voir test dédié), c'est une
    divulgation volontaire et scoping par ID exact : l'utilisateur a
    explicitement demandé CETTE attaque."""
    from .catalogue_attaques import CATALOGUE, obtenir_attaque  # noqa: PLC0415

    a = obtenir_attaque(identifiant)
    if a is None:
        return None
    ids_natifs = {x.id for x in CATALOGUE}
    return {
        "id": a.id,
        "nom": a.nom,
        "description": a.description,
        "commande": a.commande,
        "technique_mitre": a.technique_mitre,
        "tactique_mitre": a.tactique_mitre,
        "sous_technique": a.sous_technique,
        "plateforme": a.plateforme.value,
        "niveau_risque": a.niveau_risque.value,
        "event_ids_attendus": a.event_ids_attendus,
        "champ_principal": a.champ_principal,
        "valeur_detection": a.valeur_detection,
        "faux_positifs_connus": a.faux_positifs_connus,
        "references": a.references,
        "prerequisites": a.prerequisites,
        "duree_estimee_sec": a.duree_estimee_sec,
        "requires_internet": a.requires_internet,
        "origine_execution": a.origine_execution.value,
        "perso": a.id not in ids_natifs,
    }


def obtenir_stats_catalogue() -> dict[str, Any]:
    """Statistiques du catalogue + détection de règles à logique dupliquée
    -- même paire d'appels que `cadre stats --json`, jamais exposée côté
    dashboard jusqu'ici (seul `lister_catalogue()`, liste brute sans total
    ni avertissement de doublon, alimentait l'onglet Catalogue)."""
    from .catalogue_attaques import statistiques_catalogue  # noqa: PLC0415
    from .orchestrateur import detecter_regles_similaires  # noqa: PLC0415

    return {**statistiques_catalogue(), "regles_similaires": detecter_regles_similaires()}


# Les 14 tactiques MITRE ATT&CK Enterprise, dans l'ordre canonique de la
# kill-chain (colonnes de la matrice). `hors_scope=True` = tactique
# entièrement côté attaquant, en amont de tout contact avec la cible
# (OSINT, scan externe, achat d'infrastructure, développement de malware) :
# aucune commande, même exécutée depuis Kali, ne peut y générer de
# télémétrie observable sur la cible. On les affiche quand même, grisées,
# pour montrer honnêtement le périmètre.
#
# Initial Access (TA0001) a longtemps été hors périmètre pour une raison
# différente et désormais caduque ("aucune commande ne s'exécute avant
# d'avoir un accès à la cible") -- CADRE-INI-001 (origine Kali, T1133)
# couvre maintenant cette tactique.
_TACTIQUES_MITRE: tuple[tuple[str, str, bool], ...] = (
    ("Reconnaissance", "TA0043", True),
    ("Resource Development", "TA0042", True),
    ("Initial Access", "TA0001", False),
    ("Execution", "TA0002", False),
    ("Persistence", "TA0003", False),
    ("Privilege Escalation", "TA0004", False),
    ("Defense Evasion", "TA0005", False),
    ("Credential Access", "TA0006", False),
    ("Discovery", "TA0007", False),
    ("Lateral Movement", "TA0008", False),
    ("Collection", "TA0009", False),
    ("Command and Control", "TA0011", False),
    ("Exfiltration", "TA0010", False),
    ("Impact", "TA0040", False),
)


def _techniques_par_statut(repertoire_rapports: Path) -> tuple[set[str], set[str]]:
    """
    Parcourt tous les rapports de cycle déjà générés et retourne
    (techniques_validees, techniques_testees) — l'ensemble des `technique_mitre`
    qui ont, dans au moins un cycle, atteint un statut de succès (VALIDE /
    VALIDE_NON_DEPLOYE / EN_ATTENTE_REVUE) et l'ensemble de celles réellement
    tentées. EN_ATTENTE_REVUE (cadre cycle --revue) est un succès au même
    titre que VALIDE_NON_DEPLOYE : la règle est prouvée (TP/FP passés), seul
    le déploiement est différé, volontairement, en attendant une revue
    humaine.
    """
    validees: set[str] = set()
    testees: set[str] = set()
    if not repertoire_rapports.is_dir():
        return validees, testees
    for fichier_csv in repertoire_rapports.glob(f"{_PREFIXE_CYCLE}*.csv"):
        for ligne in _lire_csv(fichier_csv):
            technique = ligne.get("technique_mitre")
            statut = ligne.get("statut")
            if not technique or statut == "NON_APPLICABLE":
                continue
            testees.add(technique)
            if statut in ("VALIDE", "VALIDE_NON_DEPLOYE", "EN_ATTENTE_REVUE"):
                validees.add(technique)
    return validees, testees


def construire_matrice(repertoire_rapports: Path) -> dict[str, Any]:
    """
    Matrice de couverture MITRE ATT&CK : les 14 tactiques en colonnes, chaque
    technique du catalogue en cellule, colorée selon son statut réel —
    validée (passée en cycle), couverte (au catalogue, jamais encore validée)
    ou hors-scope (tactique amont non émulable). C'est la vue « ATT&CK
    Navigator » de CADRE : elle montre d'un coup d'œil la couverture ET les
    angles morts assumés.
    """
    from .catalogue_attaques import catalogue_actif  # noqa: PLC0415

    validees, testees = _techniques_par_statut(repertoire_rapports)

    # Regroupe les attaques par tactique puis par technique (une technique peut
    # porter plusieurs attaques — ex. deux variantes OS de T1552.001).
    par_tactique: dict[str, dict[str, dict[str, Any]]] = {}
    for a in catalogue_actif():
        techs = par_tactique.setdefault(a.tactique_mitre, {})
        cell = techs.setdefault(
            a.technique_mitre,
            {"technique": a.technique_mitre, "nom": a.nom, "attaques": []},
        )
        cell["attaques"].append(a.id)

    colonnes: list[dict[str, Any]] = []
    total_couvertes = total_validees = 0
    for nom, id_mitre, hors_scope in _TACTIQUES_MITRE:
        techs = par_tactique.get(nom, {})
        cellules = []
        for tech in sorted(techs.values(), key=lambda c: c["technique"]):
            code = tech["technique"]
            validee = code in validees
            testee = code in testees
            etat = "validee" if validee else ("testee" if testee else "couverte")
            cellules.append(
                {
                    "technique": code,
                    "nom": tech["nom"],
                    "nb_attaques": len(tech["attaques"]),
                    "attaques": tech["attaques"],
                    "etat": etat,
                }
            )
            total_couvertes += 1
            if validee:
                total_validees += 1
        colonnes.append(
            {
                "nom": nom,
                "id_mitre": id_mitre,
                "hors_scope": hors_scope,
                "techniques": cellules,
                "nb": len(cellules),
            }
        )

    tactiques_couvertes = sum(1 for c in colonnes if c["nb"] > 0)
    tactiques_dans_scope = sum(1 for _, _, hs in _TACTIQUES_MITRE if not hs)
    return {
        "colonnes": colonnes,
        "resume": {
            "techniques_couvertes": total_couvertes,
            "techniques_validees": total_validees,
            "tactiques_couvertes": tactiques_couvertes,
            "tactiques_dans_scope": tactiques_dans_scope,
            "total_tactiques": len(_TACTIQUES_MITRE),
        },
    }


def lister_secrets() -> list[str]:
    """Noms des secrets configurés — jamais leurs valeurs."""
    from .coffre_fort import obtenir_coffre  # noqa: PLC0415

    return obtenir_coffre().lister_cles()


# Identifiants standards que CADRE peut utiliser. Les mots de passe sont les
# seuls réellement critiques ; l'IP/user/URL ont des valeurs par défaut.
_SECRETS_ATTENDUS = (
    ("CADRE_VM_IP", "IP de la VM Windows cible", False),
    ("CADRE_VM_USER", "Utilisateur Windows de la VM", False),
    ("CADRE_VM_PASS", "Mot de passe de la VM Windows", True),
    ("CADRE_ELASTIC_PASS", "Mot de passe Elasticsearch", True),
    ("CADRE_LINUX_VM_IP", "IP de la VM Kali (Linux)", False),
    ("CADRE_LINUX_VM_USER", "Utilisateur SSH de la VM Kali", False),
    ("CADRE_LINUX_VM_PASS", "Mot de passe SSH de la VM Kali", True),
    ("CADRE_DASHBOARD_PASSWORD", "Mot de passe du dashboard (requis hors 127.0.0.1)", True),
)


def statut_secrets() -> list[dict[str, Any]]:
    """
    État de chaque identifiant attendu : configuré ou non — sans jamais
    exposer la valeur. Contrairement à `lister_cles()` (qui n'énumère que
    l'environnement et le .env), ceci teste la résolution réelle via le
    coffre-fort, TROUSSEAU SYSTÈME INCLUS. C'est ce qui évite le message
    trompeur « aucun secret configuré » alors que les secrets sont dans le
    trousseau Windows.
    """
    from .coffre_fort import secret_or_none  # noqa: PLC0415

    return [
        {
            "cle": cle,
            "libelle": libelle,
            "critique": critique,
            "configure": secret_or_none(cle) is not None,
        }
        for cle, libelle, critique in _SECRETS_ATTENDUS
    ]


def definir_secret(cle: str, valeur: str) -> None:
    """Délègue au coffre-fort habituel — accès journalisé, jamais la valeur en clair dans les logs."""
    from .coffre_fort import obtenir_coffre  # noqa: PLC0415

    obtenir_coffre().stocker(cle, valeur)


def verification_globale(config: dict[str, Any]) -> dict[str, Any]:
    """
    Bilan de santé complet et lisible, pensé pour un seul clic depuis le
    dashboard : chaque brique est un point /avec un détail. Regroupe
    l'état de la stack (Elasticsearch, Kibana, VM), les identifiants requis,
    l'assistant IA (optionnel), et le catalogue chargé.

    Retourne {"points": [...], "tout_ok": bool}. `tout_ok` ignore les points
    marqués `optionnel` (Ollama) : leur absence n'empêche pas d'auditer.
    """
    points: list[dict[str, Any]] = []

    def ajouter(nom: str, ok: bool, detail: str, *, optionnel: bool = False) -> None:
        points.append({"nom": nom, "ok": ok, "detail": detail, "optionnel": optionnel})

    # 1. Stack (réutilise la logique de cadre status)
    libelles = {"elasticsearch": "Elasticsearch", "kibana": "Kibana", "vm": "VM cible (WinRM)"}
    for cle, info in verifier_statut_stack(config).items():
        ajouter(libelles.get(cle, cle), info["ok"], info["detail"])

    # 2. Identifiants critiques (mots de passe)
    for s in statut_secrets():
        if s["critique"]:
            ajouter(
                f"Secret {s['cle']}",
                s["configure"],
                "configuré" if s["configure"] else "à définir",
            )

    # 3. Assistant IA (optionnel — n'empêche jamais un audit)
    from .assistant_llm import obtenir_assistant_llm  # noqa: PLC0415

    assistant = obtenir_assistant_llm()
    ollama_ok = assistant.disponible()
    ajouter(
        "Assistant IA (Ollama)",
        ollama_ok,
        f"modèle {assistant.modele}" if ollama_ok else "injoignable (optionnel)",
        optionnel=True,
    )

    # 4. Catalogue chargé
    from .catalogue_attaques import CATALOGUE, catalogue_actif  # noqa: PLC0415

    actif = catalogue_actif()
    nb_perso = len(actif) - len(CATALOGUE)
    ajouter(
        "Catalogue d'attaques",
        len(actif) > 0,
        f"{len(actif)} attaques" + (f" (dont {nb_perso} perso)" if nb_perso else ""),
    )

    tout_ok = all(p["ok"] for p in points if not p["optionnel"])
    return {"points": points, "tout_ok": tout_ok}


def generer_brouillon_ia(description: str, technique: str | None) -> dict[str, Any] | None:
    """Brouillon d'attaque via l'assistant LLM — jamais ajouté au catalogue automatiquement."""
    from .assistant_llm import obtenir_assistant_llm  # noqa: PLC0415

    return obtenir_assistant_llm().suggerer_attaque(description, technique_mitre=technique)


def enregistrer_brouillon(brouillon: dict[str, Any]) -> dict[str, Any]:
    """
    Valide un brouillon et l'ajoute au catalogue personnel (même chemin que
    `cadre suggest --enregistrer`). Retourne {ok, id, technique} ou
    {ok: False, erreur}. Ne lève jamais — la route HTTP renvoie le message.
    """
    from .catalogue_utilisateur import (  # noqa: PLC0415
        ErreurCatalogueUtilisateur,
        enregistrer_attaque_utilisateur,
    )

    try:
        attaque = enregistrer_attaque_utilisateur(brouillon)
    except ErreurCatalogueUtilisateur as e:
        return {"ok": False, "erreur": str(e)}
    return {"ok": True, "id": attaque.id, "technique": attaque.technique_mitre}


class EtatDecouverte:
    """État thread-safe de l'agent de découverte IA + son dernier résultat."""

    def __init__(self) -> None:
        self._verrou = threading.Lock()
        self.en_cours = False
        self.demarre_a: str | None = None
        self.termine_a: str | None = None
        self.resultat: dict[str, Any] | None = None
        self.erreur: str | None = None

    def demarrer(self) -> bool:
        with self._verrou:
            if self.en_cours:
                return False
            self.en_cours = True
            self.demarre_a = datetime.now(UTC).isoformat()
            self.termine_a = None
            self.resultat = None
            self.erreur = None
            return True

    def terminer(self, resultat: dict[str, Any] | None = None, erreur: str | None = None) -> None:
        with self._verrou:
            self.en_cours = False
            self.termine_a = datetime.now(UTC).isoformat()
            self.resultat = resultat
            self.erreur = erreur

    def snapshot(self) -> dict[str, Any]:
        with self._verrou:
            return {
                "en_cours": self.en_cours,
                "demarre_a": self.demarre_a,
                "termine_a": self.termine_a,
                "resultat": self.resultat,
                "erreur": self.erreur,
            }


def demarrer_decouverte(
    config: dict[str, Any],
    etat: EtatDecouverte,
    description: str,
    technique: str | None = None,
    revue: bool = False,
) -> bool:
    """
    Lance l'agent de découverte IA dans un thread démon pour UNE intention
    fournie par l'utilisateur. Exécute de VRAIES attaques (générées par
    l'IA, filtrées, validées) sur la VM configurée — la route HTTP
    appelante exige donc une confirmation explicite, comme un cycle réel.
    Retourne False si une découverte est déjà en cours.
    """
    if not etat.demarrer():
        return False

    def _executer() -> None:
        from .decouverte_ia import decouvrir_attaques  # noqa: PLC0415
        from .orchestrateur import (  # noqa: PLC0415
            OrchestrateurCADRE,
            VerrouCycleActifError,
        )

        try:
            orchestrateur = OrchestrateurCADRE(config=config)
            techniques = [technique] if technique else None
            resultat = decouvrir_attaques(orchestrateur, [description], techniques, revue=revue)
            etat.terminer(resultat=resultat)
        except VerrouCycleActifError as e:
            # F-009 : collision de verrou inter-processus (appelé par
            # decouvrir_attaques via _acquerir_verrou_cycle) : message
            # opérationnel sûr à afficher tel quel, pas une exception
            # arbitraire soumise à la discipline log-only ci-dessous.
            etat.terminer(erreur=str(e))
        except Exception as e:  # défense en profondeur : jamais de crash silencieux
            # Détail complet dans les journaux, jamais dans l'état exposé via
            # GET /api/decouverte/statut (même discipline que /api/secrets,
            # /api/revue/approuver, /api/export-sigma) -- une exception
            # inattendue ici pourrait exposer un détail interne (config VM,
            # chemin serveur, jeton...).
            obtenir_logger().error(f"Échec découverte IA : {e}")
            etat.terminer(erreur="échec de la découverte IA (voir journaux serveur)")

    threading.Thread(target=_executer, daemon=True).start()
    return True


class EtatCycle:
    """État partagé (thread-safe) du cycle en cours — simulation ou réel."""

    def __init__(self) -> None:
        self._verrou = threading.Lock()
        self.en_cours = False
        self.mode: str | None = None
        self.demarre_a: str | None = None
        self.termine_a: str | None = None
        self.erreur: str | None = None
        # Progression fine (alimentée par l'orchestrateur via maj_progression) :
        # {faites, total, attaque_id, technique, etape (1-9), etape_nom}. Permet
        # au diagramme des 9 étapes du dashboard de s'illuminer réellement.
        self.progression: dict[str, Any] = {}

    def demarrer(self, mode: str) -> bool:
        """Passe à l'état 'en cours' si aucun cycle n'est déjà actif. False si déjà en cours."""
        with self._verrou:
            if self.en_cours:
                return False
            self.en_cours = True
            self.mode = mode
            self.demarre_a = datetime.now(UTC).isoformat()
            self.termine_a = None
            self.erreur = None
            self.progression = {}
            return True

    def maj_progression(self, info: dict[str, Any]) -> None:
        """Callback de progression appelé par l'orchestrateur à chaque étape."""
        with self._verrou:
            self.progression = dict(info)

    def terminer(self, erreur: str | None = None) -> None:
        with self._verrou:
            self.en_cours = False
            self.termine_a = datetime.now(UTC).isoformat()
            self.erreur = erreur

    def snapshot(self) -> dict[str, Any]:
        with self._verrou:
            return {
                "en_cours": self.en_cours,
                "mode": self.mode,
                "demarre_a": self.demarre_a,
                "termine_a": self.termine_a,
                "erreur": self.erreur,
                "progression": dict(self.progression),
            }


def demarrer_cycle(
    config: dict[str, Any],
    etat: EtatCycle,
    mode: str = "simulation",
    techniques: list[str] | None = None,
    parallele: bool = False,
) -> bool:
    """
    Lance un cycle complet dans un thread démon.

    `mode="simulation"` (défaut) : `_executer_attaque_simulation`, ne
    touche jamais WinRM/Elasticsearch/Kibana.
    `mode="reel"` : exécution réelle contre la VM/SIEM configurés. La
    route HTTP appelante est responsable d'exiger une confirmation
    explicite avant d'appeler cette fonction avec `mode="reel"` — cette
    fonction elle-même ne re-vérifie rien, elle fait confiance à
    l'appelant (frontière déjà posée côté route).

    `parallele` : mêmes garde-fous que `cadre cycle --parallel` (isolation
    par lot de règles à signature non-conflictuelle, voir orchestrateur.py) —
    jusqu'ici jamais exposé côté dashboard, un cycle catalogue complet y
    restait toujours séquentiel.

    Retourne False sans rien faire si un cycle est déjà en cours.
    """
    if mode not in ("simulation", "reel"):
        raise ValueError(f"mode inconnu : {mode!r}")
    if not etat.demarrer(mode):
        return False

    def _executer() -> None:
        # Import différé : évite un cycle d'import au chargement du module
        # et garde le coût d'import hors du chemin de démarrage du serveur.
        from .orchestrateur import (  # noqa: PLC0415
            OrchestrateurCADRE,
            VerrouCycleActifError,
        )

        try:
            orchestrateur = OrchestrateurCADRE(config=config)
            orchestrateur.executer_cycle_complet(
                techniques_a_executer=techniques,
                mode_simulation=(mode == "simulation"),
                rapporteur=etat.maj_progression,  # progression fine → /api/cycle/statut
                parallele=parallele,
            )
            etat.terminer()
        except VerrouCycleActifError as e:
            # F-009 : collision de verrou inter-processus (voir
            # _acquerir_verrou_cycle dans orchestrateur.py) : message
            # opérationnel sûr à afficher tel quel, pas une exception
            # arbitraire d'une lib tierce soumise à la discipline ci-dessous.
            etat.terminer(erreur=str(e))
        except Exception as e:  # défense en profondeur : jamais de crash silencieux du thread
            # Détail complet dans les journaux, jamais dans l'état exposé via
            # GET /api/cycle/statut (même discipline que /api/secrets,
            # /api/revue/approuver, /api/export-sigma).
            obtenir_logger().error(f"Échec cycle ({mode}) : {e}")
            etat.terminer(erreur=f"échec du cycle {mode} (voir journaux serveur)")

    threading.Thread(target=_executer, daemon=True).start()
    return True


def demarrer_attaque_unique(
    config: dict[str, Any],
    etat: EtatCycle,
    attaque: AttaqueCatalogue,
    mode: str = "simulation",
) -> bool:
    """
    Lance UNE SEULE attaque (par ID exact) dans un thread démon — réutilise
    le même verrou anti-concurrence `etat` que `demarrer_cycle` : un cycle
    complet et une attaque unique s'excluent mutuellement DANS ce processus.
    En mode réel, `_acquerir_verrou_cycle()`/`_liberer_verrou_cycle()` (F-009)
    sont en plus acquis autour de l'exécution, pour l'exclusion INTER-
    processus (contre un `cadre cycle`/`cadre decouvrir` réel lancé en
    parallèle).

    Réplique `cadre cycle --id` (cli.py) : appelle directement
    `executer_attaque_complete()`/`_executer_attaque_simulation()` sur cette
    attaque -- jamais `executer_cycle_complet(techniques_a_executer=[...])`,
    qui exécuterait TOUTES les attaques partageant la même technique MITRE.

    `_rapporter_etape()` (progression envoyée au front) lit
    `self._rapporteur`/`self._tls.ctx_progression`, deux attributs posés
    normalement par `_boucle_attaques` (cycle multi-attaques) -- jamais par
    `executer_attaque_complete()` seule. On les pose ici à la main pour que
    `/api/cycle/statut` expose une progression complète (attaque_id/
    technique/nom/faites=0/total=1), pas juste `{etape, etape_nom}`.

    Génère aussi les rapports de fin de cycle (comme `cadre cycle --id`) :
    l'attaque apparaît donc dans l'historique et la matrice de couverture,
    exactement comme un cycle normal.

    Retourne False sans rien faire si un cycle/une attaque est déjà en cours.
    """
    if mode not in ("simulation", "reel"):
        raise ValueError(f"mode inconnu : {mode!r}")
    if not etat.demarrer(mode):
        return False

    def _executer() -> None:
        from .orchestrateur import (  # noqa: PLC0415
            OrchestrateurCADRE,
            VerrouCycleActifError,
            _acquerir_verrou_cycle,
            _liberer_verrou_cycle,
        )

        # F-009 : le docstring de cette fonction affirme depuis le début être
        # cohérent avec le verrou inter-processus, mais `etat` (EtatCycle)
        # n'exclut que dans CE processus (le dashboard) -- jamais contre un
        # `cadre cycle`/`cadre decouvrir` réel lancé en parallèle dans un
        # autre processus, exactement le scénario que F-009 doit empêcher.
        verrou_acquis = False
        try:
            if mode == "reel":
                _acquerir_verrou_cycle()
                verrou_acquis = True
            orchestrateur = OrchestrateurCADRE(config=config)
            orchestrateur._rapporteur = etat.maj_progression
            orchestrateur._tls.ctx_progression = {
                "faites": 0,
                "total": 1,
                "attaque_id": attaque.id,
                "technique": attaque.technique_mitre,
                "nom": attaque.nom,
            }
            orchestrateur._rapporter_etape(0, "Démarrage")  # même patron que _boucle_attaques
            if mode == "simulation":
                resultat = orchestrateur._executer_attaque_simulation(attaque)
            else:
                resultat = orchestrateur.executer_attaque_complete(attaque)
            orchestrateur.resultats = [resultat]
            orchestrateur._generer_rapports_fin_cycle()
            etat.terminer()
        except VerrouCycleActifError as e:
            # F-009 : collision de verrou inter-processus (même raisonnement
            # que demarrer_cycle ci-dessus) -- message sûr à afficher tel quel.
            etat.terminer(erreur=str(e))
        except Exception as e:  # défense en profondeur : jamais de crash silencieux du thread
            # Détail complet dans les journaux, jamais dans l'état exposé via
            # GET /api/cycle/statut (même discipline que /api/secrets,
            # /api/revue/approuver, /api/export-sigma).
            obtenir_logger().error(f"Échec attaque unique '{attaque.id}' : {e}")
            etat.terminer(erreur="échec de l'exécution de l'attaque (voir journaux serveur)")
        finally:
            if verrou_acquis:
                _liberer_verrou_cycle()

    threading.Thread(target=_executer, daemon=True).start()
    return True


def lister_revues_dashboard() -> list[dict[str, Any]]:
    """Règles IA validées TP/FP mais en attente de revue humaine avant
    déploiement Kibana -- le dashboard peut déjà EN CRÉER (Découverte IA,
    case "Envoyer en revue avant déploiement") mais n'offrait jusqu'ici
    aucun moyen de les lister/traiter sans repasser par `cadre revue`."""
    from .revue_regles import lister_revues  # noqa: PLC0415

    return lister_revues()


def approuver_revue_dashboard(
    config: dict[str, Any], rule_id: str, forcer: bool = False
) -> dict[str, Any]:
    """Revalide et déploie une règle en attente -- même chemin que
    `cadre revue approuver` (`orchestrateur.approuver_revue`), réel : appel
    Elastic/Kibana véritable, pas simulé. `{"trouve": False}` si `rule_id`
    n'a pas d'entrée en attente."""
    from .orchestrateur import OrchestrateurCADRE  # noqa: PLC0415
    from .revue_regles import obtenir_revue, supprimer_revue  # noqa: PLC0415

    entree = obtenir_revue(rule_id)
    if entree is None:
        return {"trouve": False}

    orchestrateur = OrchestrateurCADRE(config=config)
    resultat = orchestrateur.approuver_revue(entree, forcer=forcer)
    if resultat["deploye"]:
        supprimer_revue(rule_id)
    return {"trouve": True, **resultat}


def rejeter_revue_dashboard(rule_id: str) -> bool:
    """Rejette une règle en attente -- rien n'est déployé, l'entrée est
    simplement retirée de la file. Retourne False si `rule_id` est inconnu."""
    from .revue_regles import supprimer_revue  # noqa: PLC0415

    return supprimer_revue(rule_id)


def raffiner_attaque_dashboard(
    attaque_id: str,
    valeur_detection: str | None = None,
    seuil_fp_max: int | None = None,
    reinitialiser: bool = False,
) -> dict[str, Any]:
    """Ajuste le seuil de faux positifs ou la valeur de détection d'une
    attaque EXISTANTE -- même chemin que `cadre raffiner` (déploiement
    idempotent, `rule_id` stable : le prochain cycle met à jour la MÊME
    règle Kibana, ne la duplique jamais)."""
    from .catalogue_attaques import obtenir_attaque  # noqa: PLC0415
    from .raffinement import (  # noqa: PLC0415
        ErreurRaffinement,
        enregistrer_raffinement,
        supprimer_raffinement,
    )

    if obtenir_attaque(attaque_id) is None:
        return {"erreur": f"attaque introuvable : {attaque_id}"}

    if reinitialiser:
        return {"retire": supprimer_raffinement(attaque_id)}

    champs: dict[str, Any] = {}
    if valeur_detection is not None:
        champs["valeur_detection"] = valeur_detection
    if seuil_fp_max is not None:
        champs["seuil_fp_max"] = seuil_fp_max
    if not champs:
        return {"erreur": "rien à raffiner -- valeur_detection et/ou seuil_fp_max requis"}

    try:
        enregistrer_raffinement(attaque_id, champs)
    except ErreurRaffinement as e:
        return {"erreur": str(e)}
    return {"enregistre": True}


def exporter_sigma_dashboard(output: str = "./regles_sigma_export") -> dict[str, Any]:
    """Exporte les règles validées du catalogue au format Sigma partageable
    -- même chemin que `cadre export-sigma`, écrit réellement sur disque
    côté serveur (le dashboard reste un outil de pilotage local, pas un
    service de transfert de fichiers)."""
    from .export_sigma import exporter_regles_sigma  # noqa: PLC0415

    return exporter_regles_sigma(Path(output))


_MOTIF_RULE_ID = re.compile(r"[A-Za-z0-9._-]+")


def _chemin_regle_edition(
    rule_id: str, fichier: str | None, repertoire_regles: Path
) -> Path | None:
    """Même défaut que `cadre regle editer/pousser` (`cli.py`,
    `_chemin_regle_pour_edition`) -- dupliqué ici plutôt qu'importé : c'est
    un simple calcul de chemin (3 lignes), et `cli.py` importe déjà
    `dashboard.py` pour `cadre dashboard` -- éviter le sens inverse.

    Contrairement à la CLI (opérateur local de confiance, qui peut pointer
    `--fichier` n'importe où sur SA propre machine), ce chemin est piloté
    par une requête HTTP : `fichier` est donc contraint à rester sous
    `repertoire_regles` (le frontend ne l'envoie d'ailleurs jamais lui-même
    -- il ne fait qu'écho du chemin déjà calculé côté serveur, voir
    outils.js) et `rule_id` est validé (sinon `../../..` construit un
    chemin hors de `repertoire_regles`). Retourne None si la requête doit
    être rejetée."""
    if fichier:
        return _chemin_ecriture_securise(repertoire_regles, fichier)
    if not _MOTIF_RULE_ID.fullmatch(rule_id):
        return None
    return repertoire_regles / f"{rule_id.upper()}.yml"


def lire_regle_dashboard(config: dict[str, Any], rule_id: str) -> dict[str, Any]:
    """État actuel d'une règle DÉJÀ déployée dans Kibana -- même chemin que
    `cadre regle lire` (appel Kibana réel, jamais simulé)."""
    from .orchestrateur import OrchestrateurCADRE  # noqa: PLC0415

    orchestrateur = OrchestrateurCADRE(config=config)
    donnees = orchestrateur.lire_regle_kibana(rule_id)
    if donnees is None:
        return {"erreur": f"introuvable dans Kibana : {rule_id}"}
    return {"trouve": True, "regle": donnees}


def preparer_edition_regle_dashboard(
    config: dict[str, Any], rule_id: str, fichier: str | None = None
) -> dict[str, Any]:
    """Prépare le YAML Sigma éditable d'une règle déjà déployée -- même
    chemin que `cadre regle editer` : vérifie d'abord que Kibana connaît
    `rule_id`, puis lit le fichier local existant ou, à défaut, régénère la
    règle depuis le catalogue et l'écrit sur disque (identique à la CLI,
    pour que `cadre regle pousser` retrouve le même fichier ensuite)."""
    from .catalogue_attaques import obtenir_attaque  # noqa: PLC0415
    from .orchestrateur import OrchestrateurCADRE  # noqa: PLC0415

    orchestrateur = OrchestrateurCADRE(config=config)
    donnees = orchestrateur.lire_regle_kibana(rule_id)
    if donnees is None:
        return {"erreur": f"introuvable dans Kibana : {rule_id}"}

    repertoire_regles = Path(config.get("repertoire_regles") or "rules_generees")
    chemin_regle = _chemin_regle_edition(rule_id, fichier, repertoire_regles)
    if chemin_regle is None:
        return {"erreur": "rule_id ou fichier invalide"}
    try:
        if not chemin_regle.is_file():
            attaque = obtenir_attaque(rule_id.upper())
            if attaque is None:
                return {
                    "erreur": (
                        f"aucun fichier local pour {rule_id} et aucune attaque catalogue "
                        "correspondante -- fournissez 'fichier'"
                    )
                }
            chemin_regle.parent.mkdir(parents=True, exist_ok=True)
            chemin_regle.write_text(
                orchestrateur.generer_regle_sigma_depuis_attaque(attaque, {}), encoding="utf-8"
            )
        contenu = chemin_regle.read_text(encoding="utf-8")
    except OSError as e:
        # Une erreur d'E/S (permission refusée, disque plein...) ne doit
        # jamais planter la requête -- détail complet dans les logs, jamais
        # dans la réponse HTTP (str(OSError) inclut le chemin absolu
        # serveur, même discipline que _verifier_service_http/definir_secret).
        obtenir_logger().error(f"Lecture règle '{rule_id}' impossible : {e}")
        return {"erreur": "chemin de règle illisible (voir logs serveur)"}

    return {
        "trouve": True,
        "nom_kibana": donnees.get("name", rule_id),
        "chemin": str(chemin_regle),
        "contenu": contenu,
    }


def pousser_regle_dashboard(
    config: dict[str, Any],
    rule_id: str,
    contenu_yaml: str,
    fichier: str | None = None,
    pipeline: str = "ecs_windows",
    forcer: bool = False,
) -> dict[str, Any]:
    """Revalide et repousse le YAML édité vers Kibana -- même chemin que
    `cadre regle pousser` (`orchestrateur.redeployer_regle_editee`, jamais
    simulé). Le contenu édité (venu du textarea du dashboard) est d'abord
    réécrit sur le fichier local, pour que la CLI retrouve la même version
    si l'utilisateur bascule entre les deux."""
    from .orchestrateur import OrchestrateurCADRE  # noqa: PLC0415

    repertoire_regles = Path(config.get("repertoire_regles") or "rules_generees")
    chemin_regle = _chemin_regle_edition(rule_id, fichier, repertoire_regles)
    if chemin_regle is None:
        return {
            "deploye": False,
            "statut": "ERREUR",
            "raison": "rule_id ou fichier invalide",
            "nb_tp": 0,
            "nb_fp": 0,
            "force": False,
        }
    try:
        chemin_regle.parent.mkdir(parents=True, exist_ok=True)
        chemin_regle.write_text(contenu_yaml, encoding="utf-8")
    except OSError as e:
        # Une erreur d'E/S (permission refusée, disque plein...) ne doit
        # jamais planter la requête -- forme de retour compatible avec le
        # contrat de redeployer_regle_editee (la route lit resultat["deploye"]).
        # Détail complet dans les logs, jamais dans la réponse HTTP
        # (str(OSError) inclut le chemin absolu serveur).
        obtenir_logger().error(f"Écriture règle '{rule_id}' impossible : {e}")
        return {
            "deploye": False,
            "statut": "ERREUR",
            "raison": "chemin de règle illisible (voir logs serveur)",
            "nb_tp": 0,
            "nb_fp": 0,
            "force": False,
        }

    orchestrateur = OrchestrateurCADRE(config=config)
    return orchestrateur.redeployer_regle_editee(
        rule_id, contenu_yaml, pipeline=pipeline, forcer=forcer
    )


def _resoudre_source_atomic_et_plateformes(
    repo: str | None, platform: str | None
) -> tuple[Any, Any] | dict[str, Any]:
    """Résolution commune apercu/import : répertoire source (embarqué par
    défaut) + filtre de plateforme. Retourne un dict `{"erreur": ...}` en cas
    de répertoire ou plateforme invalide -- jamais d'exception laissée
    remonter jusqu'à la route HTTP."""
    from .atomic_red_team import repertoire_exemple  # noqa: PLC0415
    from .catalogue_attaques import Plateforme  # noqa: PLC0415

    source = Path(repo) if repo else repertoire_exemple()
    if repo and not source.is_dir():
        return {"erreur": f"répertoire introuvable : {source}"}
    if platform:
        try:
            plateformes = {Plateforme(platform)}
        except ValueError:
            return {"erreur": f"plateforme inconnue : {platform}"}
    else:
        plateformes = None
    return source, plateformes


def apercu_atomic_dashboard(
    repo: str | None = None, platform: str | None = None, techniques: list[str] | None = None
) -> dict[str, Any]:
    """Charge et filtre les tests Atomic Red Team SANS rien persister --
    même chemin que `cadre atomic` (sans `--import`) : aperçu pur, aucune
    écriture au catalogue."""
    from .atomic_red_team import importer_atomics  # noqa: PLC0415

    resolu = _resoudre_source_atomic_et_plateformes(repo, platform)
    if isinstance(resolu, dict):
        return resolu
    source, plateformes = resolu
    return importer_atomics(
        source, plateformes=plateformes, techniques=set(techniques) if techniques else None
    )


def importer_atomic_dashboard(
    repo: str | None = None, platform: str | None = None, techniques: list[str] | None = None
) -> dict[str, Any]:
    """Filtre puis enregistre les tests Atomic Red Team retenus au catalogue
    personnel -- même chemin que `cadre atomic --import`."""
    from .atomic_red_team import importer_atomics  # noqa: PLC0415
    from .catalogue_utilisateur import (  # noqa: PLC0415
        ErreurCatalogueUtilisateur,
        enregistrer_attaque_utilisateur,
    )

    resolu = _resoudre_source_atomic_et_plateformes(repo, platform)
    if isinstance(resolu, dict):
        return resolu
    source, plateformes = resolu
    rapport = importer_atomics(
        source, plateformes=plateformes, techniques=set(techniques) if techniques else None
    )

    ajoutes, deja = 0, 0
    for brouillon in rapport["retenus"]:
        try:
            enregistrer_attaque_utilisateur({**brouillon})
            ajoutes += 1
        except ErreurCatalogueUtilisateur:
            deja += 1  # id déjà présent (import déjà effectué)
    return {**rapport, "ajoutes": ajoutes, "deja_presents": deja}


def valider_regle_dashboard(
    config: dict[str, Any], contenu_yaml: str, jours: int = 7, seuil: int = 100
) -> dict[str, Any]:
    """Valide une règle Sigma EXTERNE (collée par l'utilisateur, ex. SigmaHQ)
    sur la télémétrie réelle -- même chemin que `cadre valider-regle`, sur le
    contenu YAML directement (pas de fichier serveur requis, contrairement à
    la CLI : le dashboard reçoit le texte déjà en mémoire depuis le
    navigateur)."""
    from .orchestrateur import OrchestrateurCADRE  # noqa: PLC0415
    from .validation_regle import valider_regle_sigma  # noqa: PLC0415

    orchestrateur = OrchestrateurCADRE(config=config)
    return valider_regle_sigma(
        contenu_yaml,
        elastic_url=orchestrateur.config["elastic_url"],
        auth=orchestrateur.auth_elastic,
        index_pattern=orchestrateur.config["index_pattern"],
        fenetre_jours=jours,
        seuil_bruit=seuil,
    )


def _entetes_securite(handler: BaseHTTPRequestHandler, *, csp: bool = False) -> None:
    """En-têtes de sécurité communs. `csp=True` ajoute la CSP stricte (réservée
    aux réponses du dashboard lui-même ; PAS aux rapports générés qui ont leurs
    propres styles/scripts inline et seraient cassés par une CSP stricte)."""
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header("Cache-Control", "no-store")
    if csp:
        handler.send_header("Content-Security-Policy", _CSP_DASHBOARD)
        handler.send_header("X-Frame-Options", "DENY")


def _reponse_json(handler: BaseHTTPRequestHandler, data: Any, statut: int = 200) -> None:
    corps = json.dumps(data, ensure_ascii=False).encode("utf-8")
    handler.send_response(statut)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    _entetes_securite(handler)
    handler.send_header("Content-Length", str(len(corps)))
    handler.end_headers()
    handler.wfile.write(corps)


def _reponse_401_auth_requise(handler: BaseHTTPRequestHandler) -> None:
    """401 + `WWW-Authenticate` -- déclenche la boîte de dialogue Basic Auth
    du navigateur. Utilisé uniquement quand un mot de passe dashboard est
    configuré (`CADRE_DASHBOARD_PASSWORD`) ; sans secret, aucune requête
    n'atteint jamais ce code (voir `_auth_ok`)."""
    corps = json.dumps({"erreur": "authentification requise"}, ensure_ascii=False).encode("utf-8")
    handler.send_response(401)
    handler.send_header("WWW-Authenticate", 'Basic realm="CADRE Dashboard"')
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    _entetes_securite(handler)
    handler.send_header("Content-Length", str(len(corps)))
    handler.end_headers()
    handler.wfile.write(corps)


def _servir_statique(handler: BaseHTTPRequestHandler, chemin_rel: str) -> bool:
    """Sert un fichier du frontend statique (dashboard/), avec CSP stricte.

    Protégé contre la traversée de chemin (resolve + is_relative_to) et limité
    aux extensions de la liste blanche. Retourne False si non trouvé/refusé
    (l'appelant renvoie alors 404). Le path '' ou '/' sert index.html.
    """
    base = _REP_DASHBOARD.resolve()
    rel = chemin_rel.lstrip("/") or "index.html"
    cible = (base / rel).resolve()
    if not cible.is_relative_to(base) or not cible.is_file():
        return False
    type_contenu = _TYPES_CONTENU.get(cible.suffix.lower())
    if type_contenu is None:
        return False  # extension hors liste blanche -> pas servie
    corps = cible.read_bytes()
    handler.send_response(200)
    handler.send_header("Content-Type", type_contenu)
    # CSP stricte uniquement sur le document HTML et ses ressources.
    _entetes_securite(handler, csp=True)
    handler.send_header("Content-Length", str(len(corps)))
    handler.end_headers()
    handler.wfile.write(corps)
    return True


# Plafond du corps JSON accepté (1 Mio) : les charges utiles légitimes du
# dashboard sont minuscules (mode, clé/valeur, description). Refuser au-delà
# évite qu'un Content-Length géant fasse allouer toute la mémoire (DoS local).
_TAILLE_MAX_CORPS = 1024 * 1024


def _lire_corps_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    """Lit et parse le corps JSON d'une requête POST. `{}` si absent/invalide."""
    try:
        longueur = int(handler.headers.get("Content-Length", 0) or 0)
    except ValueError:
        return {}  # Content-Length non numérique -- un client HTTP brut peut l'envoyer
    if longueur <= 0 or longueur > _TAILLE_MAX_CORPS:
        return {}
    brut = handler.rfile.read(longueur)
    try:
        data = json.loads(brut)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


# Hôtes loopback -- deux usages : (1) `_origine_locale_ok` compare le `Host`
# visé par une requête POST (garde CSRF), (2) `lancer_dashboard` compare le
# `bind` de démarrage pour décider si l'authentification est obligatoire.
# Une seule liste, pas deux, pour ne jamais les laisser diverger.
_HOTES_LOCAUX = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})

# Anti-brute-force sur l'authentification dashboard (module-level : partagé
# entre toutes les instances de handler, une par requête HTTP). Verrouille
# PAR IP SOURCE après plusieurs échecs, indépendamment de la justesse du mot
# de passe fourni ensuite -- empêche un essai illimité même si l'attaquant
# finit par deviner juste après le seuil.
_verrou_echecs_auth = threading.Lock()
_echecs_auth: dict[str, tuple[int, float]] = {}
_MAX_ECHECS_AUTH = 5
_FENETRE_VERROUILLAGE_AUTH_SEC = 300.0  # 5 min

# Sessions de connexion (page de connexion CADRE, cf. connexion.html) --
# alternative à l'en-tête `Authorization: Basic` brut pour l'usage navigateur :
# la popup native (grise, sans marque) est remplacée par une page HTML sous
# contrôle CADRE, qui pose ensuite un cookie de session. Basic Auth reste
# entièrement fonctionnel en parallèle (scripts/API directe) -- ceci n'est
# qu'une seconde voie d'authentification, jamais un remplacement.
# En mémoire, par processus : cohérent avec `_echecs_auth` ci-dessus (un
# dashboard local, un seul process, jamais de session à faire survivre à un
# redémarrage).
_verrou_sessions = threading.Lock()
_sessions: dict[str, float] = {}  # jeton -> expiration (epoch seconds)
_DUREE_SESSION_SEC = 8 * 3600  # 8 h -- une session de travail, pas un token permanent
_NOM_COOKIE_SESSION = "cadre_session"

# Ressources statiques nécessaires au RENDU de la page de connexion elle-même
# (CSS partagé + page/JS dédiés + logo officiel) -- seules exceptions à
# l'authentification obligatoire : aucune ne révèle d'état ni de donnée du
# projet, uniquement de la mise en forme. Tout le reste (app.js, composants.css,
# /api/* hors /api/login) reste strictement derrière l'authentification.
_CHEMINS_PUBLICS_SANS_AUTH = frozenset(
    {
        "/connexion.html",
        "/css/tokens.css",
        "/css/base.css",
        "/css/composants.css",
        "/css/connexion.css",
        "/js/connexion.js",
    }
)


def _creer_session() -> str:
    jeton = secrets.token_urlsafe(32)
    with _verrou_sessions:
        _sessions[jeton] = time.time() + _DUREE_SESSION_SEC
    return jeton


def _session_valide(jeton: str | None) -> bool:
    if not jeton:
        return False
    with _verrou_sessions:
        expiration = _sessions.get(jeton)
        if expiration is None:
            return False
        if time.time() > expiration:
            del _sessions[jeton]
            return False
        return True


def _revoquer_session(jeton: str | None) -> None:
    if not jeton:
        return
    with _verrou_sessions:
        _sessions.pop(jeton, None)


def _lire_cookie(handler: BaseHTTPRequestHandler, nom: str) -> str | None:
    """Parse minimal de l'en-tête `Cookie` -- un seul cookie nous intéresse,
    inutile d'importer `http.cookies` pour ça."""
    entete = handler.headers.get("Cookie", "")
    for morceau in entete.split(";"):
        cle, sep, valeur = morceau.strip().partition("=")
        if sep and cle == nom:
            return valeur
    return None


def creer_gestionnaire(
    repertoire_rapports: Path,
    fichier_log: Path,
    config_orchestrateur: dict[str, Any],
    etat_cycle: EtatCycle,
    etat_decouverte: EtatDecouverte,
) -> type[BaseHTTPRequestHandler]:
    """Fabrique la classe de handler HTTP, liée aux chemins/config de cette instance."""

    # Un seul orchestrateur, construit à la demande puis réutilisé pour toute
    # la durée de vie du serveur -- voir le docstring de verifier_statut_stack()
    # pour le bug (flood du journal SECRET_READ) que ceci corrige. Verrou
    # nécessaire : ThreadingHTTPServer traite les requêtes concurremment,
    # deux sondages quasi simultanés ne doivent pas construire deux instances.
    _verrou_orchestrateur_statut = threading.Lock()
    _orchestrateur_statut_cache: list[Any] = []

    def _orchestrateur_statut() -> Any:
        if not _orchestrateur_statut_cache:
            from .orchestrateur import OrchestrateurCADRE  # noqa: PLC0415

            with _verrou_orchestrateur_statut:
                if not _orchestrateur_statut_cache:
                    _orchestrateur_statut_cache.append(
                        OrchestrateurCADRE(config=config_orchestrateur)
                    )
        return _orchestrateur_statut_cache[0]

    class GestionnaireDashboard(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass  # silencieux — CADRE a déjà son propre logger structuré

        def _origine_locale_ok(self) -> bool:
            """Garde-fou CSRF/DNS-rebinding pour toute route à effet de bord --
            en pratique tous les POST, plus l'unique route GET qui lit/écrit
            un fichier serveur (`/api/regle/<id>/editer`, voir do_GET).

            Défense en profondeur, trois couches :
            1. En-tête custom `X-CADRE-Local: 1` OBLIGATOIRE. Une page tierce ne
               peut pas le poser sur une « simple request » ; l'ajouter force un
               pré-vol CORS que ce serveur n'autorise pas. Bloque le CSRF même
               sans en-tête Origin.
            2. `Host` visé loopback (bloque le DNS rebinding).
            3. `Origin` (si présent) loopback (bloque le CSRF navigateur classique).
            """
            if self.headers.get("X-CADRE-Local") != "1":
                return False
            hote_host = (self.headers.get("Host", "").rsplit(":", 1)[0]) or ""
            if hote_host not in _HOTES_LOCAUX:
                return False
            origin = self.headers.get("Origin")
            return origin is None or urlparse(origin).hostname in _HOTES_LOCAUX

        def _verrouille(self, ip: str) -> bool:
            with _verrou_echecs_auth:
                nb, dernier = _echecs_auth.get(ip, (0, 0.0))
                return (
                    nb >= _MAX_ECHECS_AUTH
                    and (time.time() - dernier) < _FENETRE_VERROUILLAGE_AUTH_SEC
                )

        def _enregistrer_echec_auth(self, ip: str) -> None:
            with _verrou_echecs_auth:
                nb, _ = _echecs_auth.get(ip, (0, 0.0))
                _echecs_auth[ip] = (nb + 1, time.time())

        def _reinitialiser_echecs_auth(self, ip: str) -> None:
            with _verrou_echecs_auth:
                _echecs_auth.pop(ip, None)

        def _auth_ok(self) -> bool:  # noqa: PLR0911 -- suite de gardes séquentielles
            # (session, verrou, en-tête absent/malformé, comparaison) ; les
            # regrouper nuirait à la lisibilité sans réduire la logique réelle.
            """Vérifie l'en-tête `Authorization: Basic` contre le mot de passe
            du coffre-fort (`CADRE_DASHBOARD_PASSWORD`), en temps constant
            (`hmac.compare_digest`). Un seul secret partagé -- le nom
            d'utilisateur n'est pas vérifié, ce n'est pas un modèle
            multi-compte. Sans secret configuré, retourne toujours True :
            l'authentification est un opt-in, jamais une surprise pour un
            usage solo en 127.0.0.1 (voir `lancer_dashboard` pour le cas où
            elle devient obligatoire)."""
            from .coffre_fort import secret_or_none  # noqa: PLC0415

            mot_de_passe_attendu = secret_or_none("CADRE_DASHBOARD_PASSWORD")
            if mot_de_passe_attendu is None:
                return True

            # Session posée par la page de connexion (voir _gerer_login) --
            # vérifiée AVANT le verrouillage anti-brute-force : présenter un
            # cookie de session ne consomme jamais le compteur d'échecs (ce
            # n'est pas une tentative de mot de passe), et un jeton invalide/
            # expiré retombe simplement sur le chemin Basic Auth ci-dessous.
            if _session_valide(_lire_cookie(self, _NOM_COOKIE_SESSION)):
                return True

            ip = self.client_address[0]
            if self._verrouille(ip):
                return False

            entete = self.headers.get("Authorization", "")
            if not entete:
                # Aucun en-tête DU TOUT : simple chargement de page sans
                # identifiants encore fournis (ex. première visite de la page
                # de connexion, ou tout GET de ressource statique) -- ce
                # n'est pas une tentative ratée, personne n'a rien essayé.
                # Ne JAMAIS compter ce cas : avant ce correctif, chaque
                # rechargement de /connexion.html avant la première saisie
                # consommait le compteur anti-brute-force, au point de
                # verrouiller un utilisateur légitime avant même sa première
                # tentative de mot de passe (constaté en test navigateur réel).
                return False
            if not entete.startswith("Basic "):
                self._enregistrer_echec_auth(ip)
                return False
            try:
                decode = base64.b64decode(entete[len("Basic ") :]).decode("utf-8")
                _, _, mot_de_passe_fourni = decode.partition(":")
            except (ValueError, UnicodeDecodeError):
                self._enregistrer_echec_auth(ip)
                return False

            # Comparé en bytes (UTF-8), pas en str : hmac.compare_digest()
            # lève TypeError sur des str contenant un caractère non-ASCII
            # (ex. un mot de passe avec un accent) -- non rattrapé ici, ça
            # plantait CHAQUE requête authentifiée, rendant le dashboard
            # réseau totalement inutilisable pour quiconque configure un
            # CADRE_DASHBOARD_PASSWORD avec un accent. Les bytes n'ont pas
            # cette restriction.
            if hmac.compare_digest(
                mot_de_passe_fourni.encode("utf-8"), mot_de_passe_attendu.encode("utf-8")
            ):
                self._reinitialiser_echecs_auth(ip)
                return True
            self._enregistrer_echec_auth(ip)
            return False

        def _exiger_auth(self) -> bool:
            """Envoie 401 si l'authentification échoue. Retourne True si la
            requête doit continuer normalement, False si la réponse a déjà
            été envoyée (l'appelant doit alors arrêter le traitement).

            Sur échec, deux comportements selon la nature de la requête :
            - `/api/*` (appelé en `fetch` par le frontend, jamais par une
              navigation directe) : 401 JSON classique, inchangé.
            - Toute autre requête GET (chargement de page dans un onglet) :
              sert la page de connexion CADRE (200, sans `WWW-Authenticate`)
              plutôt que de déclencher la popup Basic Auth générique du
              navigateur, qui n'affiche ni logo ni contexte."""
            if self._auth_ok():
                return True
            chemin = urlparse(self.path).path
            if chemin in _CHEMINS_PUBLICS_SANS_AUTH:
                return True
            if self.command == "GET" and not chemin.startswith("/api/"):
                if not _servir_statique(self, "connexion.html"):
                    _reponse_401_auth_requise(self)
                return False
            _reponse_401_auth_requise(self)
            return False

        def _gerer_login(self) -> None:
            """`POST /api/login` -- unique route POST accessible sans session
            préalable (c'est son rôle). Même protection CSRF que les autres
            POST (`_origine_locale_ok`) et même verrouillage anti-brute-force
            que Basic Auth (`_verrouille`/`_enregistrer_echec_auth`, IP
            partagée entre les deux voies -- un attaquant ne peut pas
            contourner le verrou en alternant Basic Auth et formulaire)."""
            if not self._origine_locale_ok():
                _reponse_json(
                    self,
                    {"erreur": "origine non autorisée (protection CSRF — accès local uniquement)"},
                    statut=403,
                )
                return

            from .coffre_fort import secret_or_none  # noqa: PLC0415

            mot_de_passe_attendu = secret_or_none("CADRE_DASHBOARD_PASSWORD")
            if mot_de_passe_attendu is None:
                # Aucun mot de passe configuré : rien à vérifier, mais pas de
                # session à créer non plus -- _auth_ok() renvoie déjà True
                # inconditionnellement dans ce cas.
                _reponse_json(self, {"ok": True})
                return

            ip = self.client_address[0]
            if self._verrouille(ip):
                _reponse_json(
                    self,
                    {"erreur": "trop de tentatives — réessayez dans quelques minutes"},
                    statut=429,
                )
                return

            corps = _lire_corps_json(self)
            mot_de_passe_fourni = corps.get("mot_de_passe", "")
            if not isinstance(mot_de_passe_fourni, str):
                mot_de_passe_fourni = ""

            if hmac.compare_digest(
                mot_de_passe_fourni.encode("utf-8"), mot_de_passe_attendu.encode("utf-8")
            ):
                self._reinitialiser_echecs_auth(ip)
                jeton = _creer_session()
                # `_reponse_json` n'expose pas d'en-tête `Set-Cookie` (aucun
                # autre appelant n'en a besoin) -- réponse construite ici
                # pour pouvoir l'ajouter avant `end_headers()`.
                corps_reponse = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header(
                    "Set-Cookie",
                    f"{_NOM_COOKIE_SESSION}={jeton}; Path=/; Max-Age={_DUREE_SESSION_SEC}; "
                    "HttpOnly; SameSite=Strict",
                )
                _entetes_securite(self)
                self.send_header("Content-Length", str(len(corps_reponse)))
                self.end_headers()
                self.wfile.write(corps_reponse)
                return
            self._enregistrer_echec_auth(ip)
            _reponse_json(self, {"erreur": "mot de passe incorrect"}, statut=401)

        def _gerer_logout(self) -> None:
            """`POST /api/logout` -- révoque la session côté serveur et
            demande au navigateur d'oublier le cookie. CSRF : même garde que
            toute autre route POST à effet de bord."""
            if not self._origine_locale_ok():
                _reponse_json(
                    self,
                    {"erreur": "origine non autorisée (protection CSRF — accès local uniquement)"},
                    statut=403,
                )
                return
            _revoquer_session(_lire_cookie(self, _NOM_COOKIE_SESSION))
            corps = json.dumps({"ok": True}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header(
                "Set-Cookie",
                f"{_NOM_COOKIE_SESSION}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict",
            )
            _entetes_securite(self)
            self.send_header("Content-Length", str(len(corps)))
            self.end_headers()
            self.wfile.write(corps)

        def do_GET(self) -> None:  # noqa: PLR0912, PLR0915 -- table de routage plate,
            # une branche par endpoint ; découper en sous-méthodes séparerait
            # des cas qui partagent le même dispatch simple sans gain réel.
            if not self._exiger_auth():
                return
            url = urlparse(self.path)
            chemin = url.path

            if chemin in ("/", "/connexion.html") or chemin.startswith(
                ("/css/", "/js/", "/assets/")
            ):
                # Frontend statique (dashboard/) servi avec CSP stricte.
                if not _servir_statique(self, chemin):
                    self.send_response(404)
                    _entetes_securite(self)
                    self.end_headers()
            elif chemin == "/api/cycles":
                _reponse_json(self, {"cycles": lister_cycles(repertoire_rapports)})
            elif chemin == "/api/cycle/dernier":
                # Dédié (voir dernier_cycle()) : évite de payer le coût de
                # l'historique complet quand un seul élément est utile.
                _reponse_json(self, {"cycle": dernier_cycle(repertoire_rapports)})
            elif chemin.startswith("/api/cycles/"):
                horodatage = chemin[len("/api/cycles/") :]
                detail = detail_cycle(repertoire_rapports, horodatage)
                if detail is None:
                    _reponse_json(self, {"erreur": "cycle introuvable"}, statut=404)
                else:
                    _reponse_json(self, detail)
            elif chemin == "/api/logs":
                try:
                    n = int(parse_qs(url.query).get("n", ["50"])[0])
                except ValueError:
                    n = 50
                _reponse_json(self, {"evenements": tail_logs(fichier_log, n)})
            elif chemin == "/api/cycle/statut":
                _reponse_json(self, etat_cycle.snapshot())
            elif chemin == "/api/decouverte/statut":
                _reponse_json(self, etat_decouverte.snapshot())
            elif chemin == "/api/statut":
                _reponse_json(
                    self,
                    verifier_statut_stack(
                        config_orchestrateur, orchestrateur=_orchestrateur_statut()
                    ),
                )
            elif chemin == "/api/verifier":
                _reponse_json(self, verification_globale(config_orchestrateur))
            elif chemin == "/api/catalogue":
                _reponse_json(self, {"attaques": lister_catalogue()})
            elif chemin == "/api/stats":
                _reponse_json(self, obtenir_stats_catalogue())
            elif chemin.startswith("/api/catalogue/"):
                identifiant = chemin[len("/api/catalogue/") :]
                detail = detail_attaque(identifiant)
                if detail is None:
                    _reponse_json(self, {"erreur": "attaque introuvable"}, statut=404)
                else:
                    _reponse_json(self, detail)
            elif chemin == "/api/matrice":
                _reponse_json(self, construire_matrice(repertoire_rapports))
            elif chemin == "/api/metriques":
                _reponse_json(self, metriques_dernier_cycle(repertoire_rapports))
            elif chemin == "/api/derive":
                _reponse_json(self, derive_toutes_regles(repertoire_rapports))
            elif chemin == "/api/secrets":
                _reponse_json(self, {"secrets": statut_secrets()})
            elif chemin == "/api/revue":
                _reponse_json(self, {"revues": lister_revues_dashboard()})
            elif chemin.startswith("/api/regle/") and chemin.endswith("/editer"):
                # Garde-fou CSRF (normalement réservé aux POST, voir do_POST) :
                # cette route GET a un effet de bord réel -- elle peut LIRE et
                # ÉCRIRE un fichier serveur à un chemin fourni par le client
                # (`fichier=`), jamais validé par chemin_securise() (choix
                # architectural assumé pour un outil local mono-utilisateur).
                # Sans ce garde, une simple balise <img> sur une page tierce
                # suffirait à déclencher une lecture/écriture arbitraire, sans
                # authentification, en mode par défaut (bind loopback).
                if not self._origine_locale_ok():
                    _reponse_json(
                        self,
                        {
                            "erreur": "origine non autorisée (protection CSRF — accès local uniquement)"
                        },
                        statut=403,
                    )
                    return
                rule_id = chemin[len("/api/regle/") : -len("/editer")]
                fichier = parse_qs(url.query).get("fichier", [None])[0]
                resultat = preparer_edition_regle_dashboard(
                    config_orchestrateur, rule_id, fichier=fichier
                )
                _reponse_json(self, resultat, statut=404 if "erreur" in resultat else 200)
            elif chemin.startswith("/api/regle/"):
                rule_id = chemin[len("/api/regle/") :]
                resultat = lire_regle_dashboard(config_orchestrateur, rule_id)
                _reponse_json(self, resultat, statut=404 if "erreur" in resultat else 200)
            elif chemin == "/api/atomic/apercu":
                # `repo` est un chemin local ARBITRAIRE, par design (même
                # sémantique que `cadre atomic --repo` : l'opérateur pointe
                # vers SON propre clone d'Atomic Red Team, où qu'il soit sur
                # le disque -- pas de répertoire de base à sandboxer ici,
                # contrairement à /api/regle/pousser). Même garde CSRF que
                # /api/regle/<id>/editer (l'autre route GET à effet de
                # bord) : sans elle, une simple balise <img> sur une page
                # tierce déclencherait un parcours récursif d'un répertoire
                # arbitraire, sans authentification, en mode par défaut
                # (bind loopback).
                if not self._origine_locale_ok():
                    _reponse_json(
                        self,
                        {
                            "erreur": "origine non autorisée (protection CSRF — accès local uniquement)"
                        },
                        statut=403,
                    )
                    return
                qs = parse_qs(url.query)
                # `technique` accepte une valeur unique OU une liste séparée
                # par des virgules (le frontend n'a besoin d'envoyer qu'un
                # seul paramètre de requête, pas un par technique).
                techniques = [
                    t.strip()
                    for brut in qs.get("technique", [])
                    for t in brut.split(",")
                    if t.strip()
                ]
                resultat = apercu_atomic_dashboard(
                    repo=qs.get("repo", [None])[0],
                    platform=qs.get("platform", [None])[0],
                    techniques=techniques,
                )
                _reponse_json(self, resultat, statut=400 if "erreur" in resultat else 200)
            elif chemin in ("/rapports", "/rapports/"):
                corps = page_index_rapports(repertoire_rapports).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(corps)))
                self.end_headers()
                self.wfile.write(corps)
            elif chemin.startswith("/rapports/"):
                nom_fichier = chemin[len("/rapports/") :]
                cible = chemin_securise(repertoire_rapports, nom_fichier)
                if cible is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                type_contenu = {
                    ".html": "text/html; charset=utf-8",
                    ".json": "application/json; charset=utf-8",
                    ".csv": "text/csv; charset=utf-8",
                    ".md": "text/markdown; charset=utf-8",
                    ".pdf": "application/pdf",
                }.get(cible.suffix, "application/octet-stream")
                corps = cible.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", type_contenu)
                if cible.suffix == ".pdf":
                    # Suggestion de nom de fichier au téléchargement -- le lien
                    # porte déjà l'attribut `download`, ceci est la confirmation
                    # cote serveur (fait autorité si le lien est ouvert autrement,
                    # ex. copie d'URL dans un nouvel onglet).
                    self.send_header("Content-Disposition", f'attachment; filename="{cible.name}"')
                self.send_header("Content-Length", str(len(corps)))
                self.end_headers()
                self.wfile.write(corps)
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self) -> None:  # noqa: PLR0912, PLR0915, PLR0911 -- table de routage plate,
            # une branche par endpoint ; même justification que do_GET.
            # /api/login échappe nécessairement à la porte _exiger_auth() ci-
            # dessous (on ne peut pas exiger d'être déjà authentifié pour
            # s'authentifier) ; /api/logout suit la même exception par
            # cohérence. Toutes deux appliquent leur propre garde CSRF en
            # interne -- voir _gerer_login/_gerer_logout.
            if self.path == "/api/login":
                self._gerer_login()
                return
            if self.path == "/api/logout":
                self._gerer_logout()
                return
            if not self._exiger_auth():
                return
            # Garde-fou CSRF : toutes les routes POST modifient l'état (lancer
            # une attaque réelle, exécuter l'agent IA, écrire un secret) — on
            # refuse toute requête qui n'émane pas de la boucle locale.
            if not self._origine_locale_ok():
                _reponse_json(
                    self,
                    {"erreur": "origine non autorisée (protection CSRF — accès local uniquement)"},
                    statut=403,
                )
                return
            if self.path == "/api/cycle/lancer":
                corps = _lire_corps_json(self)
                mode = corps.get("mode", "simulation")
                if mode not in ("simulation", "reel"):
                    _reponse_json(self, {"erreur": "mode invalide (simulation|reel)"}, statut=400)
                    return
                if mode == "reel" and corps.get("confirmer") is not True:
                    _reponse_json(
                        self,
                        {"erreur": "confirmation explicite requise pour un cycle réel"},
                        statut=400,
                    )
                    return
                techniques = corps.get("techniques") or None
                # Validation liste blanche : ne jamais faire confiance au client.
                # Toute technique inconnue du catalogue chargé -> rejet, pas
                # d'exécution (l'orchestrateur ne reçoit que des ids validés).
                if techniques is not None:
                    if not isinstance(techniques, list):
                        _reponse_json(
                            self, {"erreur": "techniques doit être une liste"}, statut=400
                        )
                        return
                    connues = {a.get("technique_mitre") for a in lister_catalogue()}
                    inconnues = [str(t) for t in techniques if t not in connues]
                    if inconnues:
                        _reponse_json(
                            self,
                            {"erreur": "technique(s) inconnue(s) : " + ", ".join(inconnues)},
                            statut=400,
                        )
                        return
                parallele = bool(corps.get("parallele"))
                lance = demarrer_cycle(
                    config_orchestrateur,
                    etat_cycle,
                    mode=mode,
                    techniques=techniques,
                    parallele=parallele,
                )
                if lance:
                    _reponse_json(self, {"lance": True, "mode": mode})
                else:
                    _reponse_json(
                        self, {"lance": False, "raison": "un cycle est déjà en cours"}, statut=409
                    )
            elif self.path == "/api/attaque/lancer":
                corps = _lire_corps_json(self)
                identifiant = corps.get("id")
                if not identifiant or not isinstance(identifiant, str):
                    _reponse_json(self, {"erreur": "id requis"}, statut=400)
                    return
                mode = corps.get("mode", "simulation")
                if mode not in ("simulation", "reel"):
                    _reponse_json(self, {"erreur": "mode invalide (simulation|reel)"}, statut=400)
                    return
                if mode == "reel" and corps.get("confirmer") is not True:
                    _reponse_json(
                        self,
                        {"erreur": "confirmation explicite requise pour une attaque réelle"},
                        statut=400,
                    )
                    return
                from .catalogue_attaques import obtenir_attaque  # noqa: PLC0415

                attaque = obtenir_attaque(identifiant)
                if attaque is None:
                    _reponse_json(self, {"erreur": "attaque introuvable"}, statut=404)
                    return
                lance = demarrer_attaque_unique(
                    config_orchestrateur, etat_cycle, attaque, mode=mode
                )
                if lance:
                    _reponse_json(self, {"lance": True, "mode": mode, "id": attaque.id})
                else:
                    _reponse_json(
                        self,
                        {"lance": False, "raison": "un cycle ou une attaque est déjà en cours"},
                        statut=409,
                    )
            elif self.path == "/api/decouverte/lancer":
                # L'agent IA exécute de VRAIES attaques → confirmation exigée,
                # comme un cycle réel (garde-fou côté route).
                corps = _lire_corps_json(self)
                description = corps.get("description")
                if not description or not isinstance(description, str) or not description.strip():
                    _reponse_json(self, {"erreur": "description requise"}, statut=400)
                    return
                if corps.get("confirmer") is not True:
                    _reponse_json(
                        self,
                        {"erreur": "confirmation explicite requise (attaques réelles)"},
                        statut=400,
                    )
                    return
                technique = corps.get("technique")
                technique = str(technique).strip() or None if technique else None
                revue = bool(corps.get("revue"))
                lance = demarrer_decouverte(
                    config_orchestrateur, etat_decouverte, description.strip(), technique, revue
                )
                if lance:
                    _reponse_json(self, {"lance": True})
                else:
                    _reponse_json(
                        self,
                        {"lance": False, "raison": "une découverte est déjà en cours"},
                        statut=409,
                    )
            elif self.path == "/api/secrets":
                corps = _lire_corps_json(self)
                cle, valeur = corps.get("cle"), corps.get("valeur")
                if not cle or not valeur:
                    _reponse_json(self, {"erreur": "cle et valeur requises"}, statut=400)
                    return
                try:
                    definir_secret(cle, valeur)
                    _reponse_json(self, {"defini": True})
                except Exception as e:
                    # Détail complet dans les logs, jamais dans la réponse
                    # HTTP (même discipline que _verifier_service_http) --
                    # une exception inattendue ici pourrait exposer un
                    # détail interne (chemin, driver du coffre-fort...).
                    obtenir_logger().error(f"Échec définition secret '{cle}' : {e}")
                    _reponse_json(
                        self, {"erreur": "échec de l'enregistrement du secret"}, statut=400
                    )
            elif self.path == "/api/revue/approuver":
                corps = _lire_corps_json(self)
                rule_id = corps.get("rule_id")
                if not rule_id or not isinstance(rule_id, str):
                    _reponse_json(self, {"erreur": "rule_id requis"}, statut=400)
                    return
                try:
                    resultat = approuver_revue_dashboard(
                        config_orchestrateur, rule_id, forcer=bool(corps.get("forcer"))
                    )
                except Exception as e:  # défense en profondeur : jamais de crash silencieux
                    # Détail complet dans les logs, jamais dans la réponse
                    # HTTP (même discipline que _verifier_service_http).
                    obtenir_logger().error(f"Échec approbation revue '{rule_id}' : {e}")
                    _reponse_json(self, {"erreur": "échec de l'approbation"}, statut=400)
                    return
                if not resultat["trouve"]:
                    _reponse_json(
                        self, {"erreur": "aucune revue en attente pour " + rule_id}, statut=404
                    )
                    return
                _reponse_json(self, resultat)
            elif self.path == "/api/revue/rejeter":
                corps = _lire_corps_json(self)
                rule_id = corps.get("rule_id")
                if not rule_id or not isinstance(rule_id, str):
                    _reponse_json(self, {"erreur": "rule_id requis"}, statut=400)
                    return
                if rejeter_revue_dashboard(rule_id):
                    _reponse_json(self, {"rejete": True})
                else:
                    _reponse_json(
                        self, {"erreur": "aucune revue en attente pour " + rule_id}, statut=404
                    )
            elif self.path == "/api/raffiner":
                corps = _lire_corps_json(self)
                attaque_id = corps.get("attaque_id")
                if not attaque_id or not isinstance(attaque_id, str):
                    _reponse_json(self, {"erreur": "attaque_id requis"}, statut=400)
                    return
                resultat = raffiner_attaque_dashboard(
                    attaque_id,
                    valeur_detection=corps.get("valeur_detection") or None,
                    seuil_fp_max=corps.get("seuil_fp_max") or None,
                    reinitialiser=bool(corps.get("reinitialiser")),
                )
                _reponse_json(self, resultat, statut=400 if "erreur" in resultat else 200)
            elif self.path == "/api/export-sigma":
                corps = _lire_corps_json(self)
                try:
                    resultat = exporter_sigma_dashboard(
                        corps.get("output") or "./regles_sigma_export"
                    )
                    _reponse_json(self, resultat)
                except Exception as e:  # défense en profondeur : jamais de crash silencieux
                    # Détail complet dans les logs, jamais dans la réponse
                    # HTTP (même discipline que _verifier_service_http) --
                    # pourrait exposer un chemin serveur.
                    obtenir_logger().error(f"Échec export Sigma : {e}")
                    _reponse_json(self, {"erreur": "échec de l'export"}, statut=400)
            elif self.path == "/api/regle/pousser":
                corps = _lire_corps_json(self)
                rule_id = corps.get("rule_id")
                contenu_yaml = corps.get("contenu")
                if not rule_id or not isinstance(rule_id, str):
                    _reponse_json(self, {"erreur": "rule_id requis"}, statut=400)
                    return
                if not contenu_yaml or not isinstance(contenu_yaml, str):
                    _reponse_json(self, {"erreur": "contenu requis"}, statut=400)
                    return
                resultat = pousser_regle_dashboard(
                    config_orchestrateur,
                    rule_id,
                    contenu_yaml,
                    fichier=corps.get("fichier") or None,
                    pipeline=corps.get("pipeline") or "ecs_windows",
                    forcer=bool(corps.get("forcer")),
                )
                _reponse_json(self, resultat, statut=200 if resultat["deploye"] else 400)
            elif self.path == "/api/atomic/importer":
                corps = _lire_corps_json(self)
                techniques = corps.get("techniques") or []
                # `techniques` doit être une liste : sans ce contrôle, une
                # chaîne (ex. "T1110") est itérable caractère par caractère
                # en Python -- silencieusement transformée en une liste de
                # lettres au lieu d'être rejetée proprement (comportement
                # incorrect sans plantage, jamais détecté par un test avant).
                if not isinstance(techniques, list):
                    _reponse_json(self, {"erreur": "techniques doit être une liste"}, statut=400)
                    return
                # Chaque élément doit être une chaîne non vide -- un filtrage
                # silencieux des éléments invalides (ex. [1, 2, 3]) réduisait
                # une liste malformée à une liste VIDE, traitée plus bas comme
                # « aucun filtre » (set(techniques) if techniques else None) :
                # la requête importait alors TOUT le référentiel Atomic Red
                # Team au lieu d'être rejetée. Liste réellement vide (aucune
                # technique cochée) : comportement inchangé, "aucun filtre".
                if not all(isinstance(t, str) and t for t in techniques):
                    _reponse_json(
                        self,
                        {"erreur": "techniques doit être une liste de chaînes non vides"},
                        statut=400,
                    )
                    return
                resultat = importer_atomic_dashboard(
                    repo=corps.get("repo") or None,
                    platform=corps.get("platform") or None,
                    techniques=techniques,
                )
                _reponse_json(self, resultat, statut=400 if "erreur" in resultat else 200)
            elif self.path == "/api/valider-regle":
                corps = _lire_corps_json(self)
                contenu_yaml = corps.get("contenu")
                if not contenu_yaml or not isinstance(contenu_yaml, str):
                    _reponse_json(self, {"erreur": "contenu requis"}, statut=400)
                    return
                try:
                    jours = int(corps.get("jours") or 7)
                    seuil = int(corps.get("seuil") or 100)
                except (ValueError, TypeError):
                    _reponse_json(
                        self, {"erreur": "jours et seuil doivent être des entiers"}, statut=400
                    )
                    return
                resultat = valider_regle_dashboard(
                    config_orchestrateur, contenu_yaml, jours=jours, seuil=seuil
                )
                _reponse_json(self, resultat)
            elif self.path == "/api/suggest":
                corps = _lire_corps_json(self)
                description = corps.get("description")
                if not description:
                    _reponse_json(self, {"erreur": "description requise"}, statut=400)
                    return
                brouillon = generer_brouillon_ia(description, corps.get("technique"))
                if brouillon is None:
                    _reponse_json(
                        self, {"erreur": "Ollama injoignable ou réponse invalide"}, statut=502
                    )
                else:
                    _reponse_json(self, brouillon)
            elif self.path == "/api/suggest/enregistrer":
                corps = _lire_corps_json(self)
                brouillon = corps.get("brouillon")
                # `brouillon` doit être un dict : un `{"brouillon": "texte"}`
                # ou `{"brouillon": [1, 2]}` est truthy (donc passait le seul
                # `if not brouillon` d'avant) mais fait planter le `{**brouillon}`
                # ou `brouillon.get(...)` en aval avec un TypeError/AttributeError
                # non rattrapé, jamais une réponse 400 propre.
                if not isinstance(brouillon, dict):
                    _reponse_json(self, {"ok": False, "erreur": "brouillon requis"}, statut=400)
                    return
                if corps.get("id"):
                    brouillon = {**brouillon, "id": corps["id"]}
                if not brouillon:
                    _reponse_json(self, {"ok": False, "erreur": "brouillon requis"}, statut=400)
                    return
                resultat = enregistrer_brouillon(brouillon)
                _reponse_json(self, resultat, statut=200 if resultat.get("ok") else 400)
            else:
                self.send_response(404)
                self.end_headers()

    return GestionnaireDashboard


def lancer_dashboard(
    port: int = 8765,
    bind: str = "127.0.0.1",
    repertoire_rapports: Path = Path("./rapports"),
    repertoire_regles: Path = Path("./rules_generees"),
    fichier_log: Path = Path("./logs/cadre.log.json"),
) -> None:
    """Démarre le serveur HTTP du dashboard (bloquant — `serve_forever()`).

    Refuse de démarrer si `bind` n'est pas loopback et qu'aucun mot de passe
    (`CADRE_DASHBOARD_PASSWORD`) n'est configuré -- sécurisé par défaut :
    exposer le dashboard sur le réseau sans authentification ne peut pas
    arriver par oubli (voir module docstring, `GestionnaireDashboard._auth_ok`).

    `ThreadingHTTPServer` (pas `HTTPServer`) : un `HTTPServer` classique est
    mono-thread -- une requête lente (ex. un `GET /api/services` qui attend
    plusieurs secondes le timeout d'un service VM/SIEM injoignable) bloque
    TOUTES les autres requêtes, y compris le sondage 2s de la progression
    d'un cycle en cours. L'état partagé (`EtatCycle`/`EtatDecouverte`,
    `_echecs_auth`, le logger fichier) est déjà protégé par verrou pour
    exactement ce scénario multi-thread.
    """
    if bind not in _HOTES_LOCAUX:
        from .coffre_fort import ErreurSecurite, secret_or_none  # noqa: PLC0415

        if secret_or_none("CADRE_DASHBOARD_PASSWORD") is None:
            raise ErreurSecurite(
                f"--bind {bind} n'est pas loopback : le dashboard exposerait un "
                "pilotage complet (attaques réelles, secrets) sans authentification. "
                "Configurez d'abord un mot de passe : "
                "cadre init --set CADRE_DASHBOARD_PASSWORD=<mot de passe>"
            )
    config_orchestrateur = {
        "repertoire_rapports": repertoire_rapports,
        "repertoire_regles": repertoire_regles,
    }
    etat_cycle = EtatCycle()
    etat_decouverte = EtatDecouverte()
    gestionnaire = creer_gestionnaire(
        repertoire_rapports, fichier_log, config_orchestrateur, etat_cycle, etat_decouverte
    )
    serveur = ThreadingHTTPServer((bind, port), gestionnaire)
    try:
        serveur.serve_forever()
    except KeyboardInterrupt:
        serveur.shutdown()
