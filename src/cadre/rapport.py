# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Génération de rapports
==============================

Génère automatiquement :
- Un rapport Markdown détaillé par cycle d'audit
- Un rapport de soutenance (PFA) complet et structuré
- Un rapport client (posture de sécurité)
- Une exportation CSV pour analyse dans Excel/LibreOffice
- Un rapport HTML autonome (sans dépendance externe)
- Un layer MITRE ATT&CK Navigator (JSON) pour la heatmap de couverture
"""

from __future__ import annotations

import csv
import json
import math
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

from .logger import obtenir_logger
from .scenarios import STATUTS_DETECTES

_ORDRE_STATUTS = [
    "VALIDE",
    "VALIDE_NON_DEPLOYE",
    "EN_ATTENTE_REVUE",
    "SIMULE",
    "REJETE",
    "ANGLE_MORT",
    "ERREUR",
    "NON_APPLICABLE",
]
_TITRES_STATUTS = {
    "VALIDE": "Règles validées et déployées",
    "VALIDE_NON_DEPLOYE": "Règles validées, non déployées",
    "EN_ATTENTE_REVUE": "Règles validées, en attente de revue humaine",
    "SIMULE": "Attaques simulées (syntaxe validée, non exécutées en réel)",
    "REJETE": "Règles rejetées",
    "ANGLE_MORT": "Angles morts",
    "ERREUR": "Erreurs d'exécution",
    "NON_APPLICABLE": "Non applicables (plateforme incompatible)",
}


def _grouper_par_statut(
    resultats_cycle: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    groupes: dict[str, list[dict[str, Any]]] = {s: [] for s in _ORDRE_STATUTS}
    for r in resultats_cycle:
        groupes.setdefault(r.get("statut", "?"), []).append(r)
    return groupes


def _format_duree(sec: float) -> str:
    """Durée lisible : '45 s' ou '1 min 27 s'."""
    total = round(sec)
    if total < 60:
        return f"{total} s"
    return f"{total // 60} min {total % 60:02d} s"


def _section_resume_executif(
    groupes: dict[str, list[dict[str, Any]]], total: int, duree_sec: float | None = None
) -> list[str]:
    # Même définition du « succès » que scenarios.STATUTS_DETECTES (VALIDE,
    # VALIDE_NON_DEPLOYE, SIMULE) -- un cycle --simulate entièrement réussi
    # ne doit pas afficher 0% (SIMULE était absent de ce calcul avant, ce qui
    # produisait un taux faux sur tout rapport de simulation).
    succes = sum(len(groupes[s]) for s in STATUTS_DETECTES)
    # Le taux de réussite se calcule sur les attaques APPLICABLES à la
    # cible configurée — une attaque Linux non exécutée contre une cible
    # Windows n'est pas un échec, ça ne doit pas pénaliser le taux.
    applicables = total - len(groupes["NON_APPLICABLE"])
    taux = (succes / applicables * 100) if applicables else 0.0
    lignes = [
        "# Rapport de cycle d'audit CADRE",
        "",
        f"**Date** : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
        "",
        "## Résumé exécutif",
        "",
        f"- **Attaques testées** : {total}",
        f"- **Règles validées et déployées** : {len(groupes['VALIDE'])}",
        f"- **Règles validées, déploiement Kibana échoué** : {len(groupes['VALIDE_NON_DEPLOYE'])}",
        f"- **Règles rejetées** (faux négatif ou trop de faux positifs) : {len(groupes['REJETE'])}",
        f"- **Angles morts** (aucune télémétrie collectée) : {len(groupes['ANGLE_MORT'])}",
        f"- **Erreurs d'exécution** : {len(groupes['ERREUR'])}",
    ]
    if groupes["EN_ATTENTE_REVUE"]:
        lignes.append(
            f"- **Règles validées, en attente de revue humaine** (mode `--revue`) : "
            f"{len(groupes['EN_ATTENTE_REVUE'])}"
        )
    if groupes["SIMULE"]:
        lignes.append(
            f"- **Attaques simulées** (mode `--simulate`, non exécutées en réel) : {len(groupes['SIMULE'])}"
        )
    if groupes["NON_APPLICABLE"]:
        lignes.append(
            f"- **Non applicables** (plateforme incompatible avec la cible) : "
            f"{len(groupes['NON_APPLICABLE'])}"
        )
    lignes.append(f"- **Taux de réussite** : **{taux:.1f}%** ({succes}/{applicables})")
    if duree_sec is not None:
        lignes.append(f"- **Durée du cycle** : {_format_duree(duree_sec)}")
    lignes.append("")
    return lignes


def _section_synthese_ia(
    resume_llm: str | None,
    analyse_llm: str | None,
    explication_rejets: str | None = None,
) -> list[str]:
    if not (resume_llm or analyse_llm or explication_rejets):
        return []
    lignes = [
        "## Synthèse IA (assistance, non déterministe)",
        "",
        "*Généré par l'assistant LLM local (Ollama) à titre indicatif — "
        "n'affecte ni la génération ni la validation des règles ci-dessous.*",
        "",
    ]
    if resume_llm:
        lignes.extend([resume_llm, ""])
    if analyse_llm:
        lignes.extend(["### Pistes d'investigation — angles morts", "", analyse_llm, ""])
    if explication_rejets:
        lignes.extend(
            [
                "### Pistes de réduction de faux positifs — règles rejetées",
                "",
                explication_rejets,
                "",
            ]
        )
    return lignes


def _ligne_tableau_resultat(r: dict[str, Any]) -> str:
    nom = r.get("description", r.get("nom", ""))
    return (
        f"| {r.get('technique_mitre', '?')} — {nom} | "
        f"{r.get('tactique', '?')} | {r.get('nb_tp', '-')} | {r.get('nb_fp', '-')} | "
        f"{r.get('raison', '-')} |"
    )


def _section_resultats_par_statut(groupes: dict[str, list[dict[str, Any]]]) -> list[str]:
    lignes = ["## Résultats par statut", ""]
    for statut in _ORDRE_STATUTS:
        groupe = groupes[statut]
        if not groupe:
            continue
        lignes.append(f"### {_TITRES_STATUTS[statut]} ({len(groupe)})")
        lignes.append("")
        lignes.append("| Technique | Tactique | TP | FP | Raison |")
        lignes.append("|-----------|----------|----|----|--------|")
        lignes.extend(_ligne_tableau_resultat(r) for r in groupe)
        lignes.append("")
    return lignes


def _section_regles_sigma(resultats_cycle: list[dict[str, Any]]) -> list[str]:
    regles = [r for r in resultats_cycle if r.get("regle_sigma_yaml")]
    if not regles:
        return []
    lignes = ["## Détail des règles Sigma générées", ""]
    for r in regles:
        lignes.append(f"### {r.get('technique_mitre')} — {r.get('description', '')}")
        lignes.append("")
        generateur = r.get("generateur_regle", "deterministe")
        lignes.append(
            f"**Règle générée par : `{generateur}`** — validée TP/FP puis "
            "utilisée pour le déploiement (même barrière quel que soit le générateur)."
        )
        lignes.append("")
        lignes.append("```yaml")
        lignes.append(r["regle_sigma_yaml"])
        lignes.append("```")
        lignes.append("")
        if r.get("regle_sigma_ia_brouillon"):
            lignes.append("**Brouillon IA comparatif — non validé, non déployé**")
            lignes.append("")
            lignes.append("```yaml")
            lignes.append(r["regle_sigma_ia_brouillon"])
            lignes.append("```")
            lignes.append("")
    return lignes


def _section_recommandations_angles_morts(aveugles: list[dict[str, Any]]) -> list[str]:
    if not aveugles:
        return []
    lignes = [
        "## Recommandations — angles morts à investiguer",
        "",
        "Les techniques ci-dessous n'ont généré AUCUN événement dans le SIEM.",
        "Cela indique un problème de collecte (Sysmon mal configuré, agent absent, "
        "règle de filtrage trop agressive). À corriger avant la production :",
        "",
    ]
    for r in aveugles:
        lignes.append(f"- **{r.get('technique_mitre')}** : {r.get('description', '')}")
        lignes.append(f"  - EventIDs attendus : `{r.get('event_ids_attendus', [])}`")
        lignes.append("  - Action : vérifier la configuration Sysmon et Winlogbeat")
    lignes.append("")
    return lignes


def _section_valeur_metier(resultats_cycle: list[dict[str, Any]]) -> list[str]:
    """Section 'Valeur métier' : quantifie l'apport du cycle (temps gagné,
    couverture MITRE, qualité). Import différé pour éviter tout couplage dur
    au module métriques depuis le chemin de rapport."""
    from .metriques import calculer_metriques_valeur  # noqa: PLC0415

    m = calculer_metriques_valeur(resultats_cycle)
    if m["applicables"] == 0:
        return []
    return [
        "## Valeur métier",
        "",
        f"- **Règles de détection produites** : {m['regles_produites']} "
        f"(taux de réussite {m['taux_reussite_pct']}% sur {m['applicables']} attaques applicables)",
        f"- **Temps d'ingénierie estimé économisé** : ~{m['temps_gagne_heures']} h "
        f"(~{m['temps_gagne_jours_ouvres']} jours-homme) — *hypothèse : "
        f"{m['hypothese_heures_par_regle']} h par règle écrite manuellement*",
        f"- **Couverture MITRE ATT&CK obtenue** : {m['tactiques_couvertes']}/"
        f"{m['total_tactiques_catalogue']} tactiques ({m['couverture_tactiques_pct']}%), "
        f"{m['techniques_couvertes']} technique(s) distincte(s) couverte(s)",
        f"- **Bruit résiduel médian** : {m['faux_positifs_median']} faux positifs "
        f"par règle validée (médiane sur 7 jours d'historique — robuste aux "
        f"règles baseline volontairement bruyantes)",
        "",
    ]


def generer_rapport_cycle(
    resultats_cycle: list[dict[str, Any]],
    fichier_sortie: Path,
    resume_llm: str | None = None,
    analyse_llm: str | None = None,
    explication_rejets: str | None = None,
    duree_sec: float | None = None,
) -> Path:
    """
    Génère un rapport Markdown pour un cycle d'audit, structuré par statut
    (validées / rejetées / angles morts / erreurs) plutôt qu'en tableau plat.

    Args:
        resultats_cycle: Liste de dicts avec les clés :
            - technique_mitre, tactique, statut, nb_tp, nb_fp, etc.
        fichier_sortie: Chemin du fichier .md à créer
        resume_llm: Synthèse exécutive générée par l'assistant IA (optionnel)
        analyse_llm: Pistes d'investigation des angles morts, IA (optionnel)
        explication_rejets: Pistes de réduction de FP pour les règles
            rejetées, IA (optionnel) — symétrique à `analyse_llm`
    """
    log = obtenir_logger()
    fichier_sortie.parent.mkdir(parents=True, exist_ok=True)

    groupes = _grouper_par_statut(resultats_cycle)
    total = len(resultats_cycle)
    succes = sum(len(groupes[s]) for s in STATUTS_DETECTES)
    applicables = total - len(groupes["NON_APPLICABLE"])
    taux = (succes / applicables * 100) if applicables else 0.0

    contenu = [
        *_section_resume_executif(groupes, total, duree_sec),
        *_section_valeur_metier(resultats_cycle),
        *_section_synthese_ia(resume_llm, analyse_llm, explication_rejets),
        *_section_resultats_par_statut(groupes),
        *_section_regles_sigma(resultats_cycle),
        *_section_recommandations_angles_morts(groupes["ANGLE_MORT"]),
        "## Conclusion",
        "",
        f"Taux de réussite : **{succes}/{applicables} = {taux:.1f}%** "
        f"(sur {applicables} attaques applicables à la cible configurée, {total} au total)",
        "",
    ]

    fichier_sortie.write_text("\n".join(contenu), encoding="utf-8")
    log.success(f"Rapport de cycle généré : {fichier_sortie}")
    return fichier_sortie


# Caractères de tête qu'Excel/LibreOffice interprètent comme un début de
# formule à l'ouverture d'un CSV (CWE-1236 -- injection de formule).
_PREFIXES_FORMULE_CSV = ("=", "+", "-", "@", "\t", "\r")


def _defuse_formule_csv(valeur: Any) -> Any:
    """Neutralise une valeur susceptible d'être lue comme une formule par
    Excel/LibreOffice à l'ouverture du CSV (régression sécurité, audit) --
    une cellule commençant par =/+/-/@ (ou tabulation/retour chariot)
    déclenche du contenu actif dès l'ouverture (ex. HYPERLINK exfiltrant des
    données vers un serveur externe, DDE sur d'anciennes versions d'Excel).
    `description`/`raison`/`nom` peuvent provenir d'un brouillon généré par
    le LLM ou d'une attaque personnelle (catalogue_utilisateur.py) -- jamais
    un contenu de confiance à l'export. Préfixée d'une apostrophe
    (convention standard Excel) pour forcer une lecture en texte brut, sans
    altérer la valeur affichée ni son contenu réel."""
    if isinstance(valeur, str) and valeur.startswith(_PREFIXES_FORMULE_CSV):
        return "'" + valeur
    return valeur


def generer_csv(resultats_cycle: list[dict[str, Any]], fichier_sortie: Path) -> Path:
    """
    Exporte les résultats au format CSV pour analyse Excel.
    """
    fichier_sortie.parent.mkdir(parents=True, exist_ok=True)
    champs = [
        "timestamp",
        "id",
        "technique_mitre",
        "tactique",
        "description",
        "statut",
        "nb_tp",
        "nb_fp",
        "score_confiance",
        "raison",
        "event_ids_attendus",
    ]
    # encoding "utf-8-sig" = UTF-8 avec BOM (Byte Order Mark). Sans ce BOM,
    # Excel/LibreOffice sous Windows ouvrent le CSV en Windows-1252 par défaut
    # et affichent les accents en mojibake ("RÃ¨gle" au lieu de "Règle"). Le BOM
    # signale explicitement l'UTF-8 aux tableurs, qui affichent alors les accents
    # correctement. Les lecteurs internes utilisent "utf-8-sig" pour retirer ce BOM.
    with fichier_sortie.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=champs, extrasaction="ignore")
        writer.writeheader()
        for r in resultats_cycle:
            row = dict(r)
            if isinstance(row.get("event_ids_attendus"), list):
                row["event_ids_attendus"] = ",".join(row["event_ids_attendus"])
            if not row.get("timestamp"):
                row["timestamp"] = datetime.now().isoformat()
            writer.writerow({k: _defuse_formule_csv(v) for k, v in row.items()})
    obtenir_logger().success(f"Export CSV généré : {fichier_sortie}")
    return fichier_sortie


# Couleur par statut, réutilisée par le rapport HTML et le layer Navigator.
# EN_ATTENTE_REVUE reprend l'accent "encours" du dashboard (--st-encours,
# dashboard/css/tokens.css) : même statut, même couleur sémantique partout.
_COULEUR_PAR_STATUT = {
    "VALIDE": "#4caf50",
    "VALIDE_NON_DEPLOYE": "#8bc34a",
    "EN_ATTENTE_REVUE": "#00c2a8",
    "SIMULE": "#5f9bd9",
    "REJETE": "#ff9800",
    "ANGLE_MORT": "#f44336",
    "ERREUR": "#9e9e9e",
}


# Palette de statut de l'interface (cohérente avec le dashboard : paper+brass).
_STATUT_COULEUR_UI = {
    "VALIDE": "#5fae7d",
    "VALIDE_NON_DEPLOYE": "#9bc47f",
    "EN_ATTENTE_REVUE": "#00c2a8",
    "SIMULE": "#5f9bd9",
    "REJETE": "#d9a44e",
    "ANGLE_MORT": "#d9705f",
    "ERREUR": "#8a9490",
    "NON_APPLICABLE": "#6d7773",
}
_STATUT_LABEL_COURT = {
    "VALIDE": "Validée & déployée",
    "VALIDE_NON_DEPLOYE": "Validée (non déployée)",
    "EN_ATTENTE_REVUE": "En attente de revue",
    "SIMULE": "Simulée",
    "REJETE": "Rejetée",
    "ANGLE_MORT": "Angle mort",
    "ERREUR": "Erreur",
    "NON_APPLICABLE": "Non applicable",
}


def _ligne_tableau_pdf(r: dict[str, Any], style_normal: Any) -> list[Any]:
    """
    Une ligne du tableau détail PDF d'un statut. Échappement OBLIGATOIRE
    (comme pour le rapport HTML, `_ligne_html` ci-dessous) : `Paragraph()`
    de reportlab interprète son texte comme un balisage XML/HTML restreint
    (<b>, <font>, <a href>, <img src>...), jamais comme du texte brut.
    `nom`/`raison` proviennent de la découverte IA (description générée par
    le LLM, jamais filtrée par le garde-fou anti-destruction qui ne porte
    que sur `commande`) ou d'un import Atomic Red Team tiers -- non fiables
    par nature.
    """
    from reportlab.platypus import Paragraph  # noqa: PLC0415

    technique = escape(str(r.get("technique_mitre", "?")))
    nom = escape(str(r.get("description", r.get("nom", ""))))
    raison = escape(str(r.get("raison", "-")))
    return [
        Paragraph(f"{technique} — {nom}", style_normal),
        str(r.get("tactique", "?")),
        str(r.get("nb_tp", "-")),
        str(r.get("nb_fp", "-")),
        Paragraph(raison, style_normal),
    ]


def generer_rapport_pdf(
    resultats_cycle: list[dict[str, Any]],
    fichier_sortie: Path,
    duree_sec: float | None = None,
) -> Path:
    """
    Génère un rapport PDF autonome pour un cycle d'audit (reportlab, natif --
    aucun moteur de rendu HTML externe, cohérent avec la contrainte « zéro
    dépendance lourde » déjà appliquée au rapport HTML). Répond au besoin
    d'un téléchargement direct depuis le tableau de bord, sans passer par
    l'ouverture manuelle du rapport HTML puis un « imprimer en PDF ».

    Reprend la même palette de statut que le rapport HTML/Navigator
    (`_COULEUR_PAR_STATUT`) pour une lecture cohérente entre les formats.
    """
    # Import différé (PLC0415) : reportlab est une dépendance relativement
    # lourde, chargée uniquement quand un PDF est effectivement demandé --
    # jamais payée par un import de rapport.py qui n'en a pas besoin (ex. CLI
    # sans génération de rapport).
    from reportlab.lib import colors  # noqa: PLC0415
    from reportlab.lib.pagesizes import A4  # noqa: PLC0415
    from reportlab.lib.styles import (  # noqa: PLC0415
        ParagraphStyle,
        getSampleStyleSheet,
    )
    from reportlab.lib.units import cm  # noqa: PLC0415
    from reportlab.platypus import (  # noqa: PLC0415
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    fichier_sortie.parent.mkdir(parents=True, exist_ok=True)

    groupes = _grouper_par_statut(resultats_cycle)
    total = len(resultats_cycle)
    succes = sum(len(groupes[s]) for s in STATUTS_DETECTES)
    applicables = total - len(groupes["NON_APPLICABLE"])
    taux = (succes / applicables * 100) if applicables else 0.0

    accent = colors.HexColor("#00c2a8")
    noir = colors.HexColor("#1a1a1a")
    gris = colors.HexColor("#5a5a5a")
    styles = getSampleStyleSheet()
    style_titre = ParagraphStyle(
        "CadreTitre", parent=styles["Title"], textColor=accent, fontSize=26, spaceAfter=2
    )
    style_soustitre = ParagraphStyle(
        "CadreSousTitre", parent=styles["Normal"], textColor=gris, fontSize=11, spaceAfter=14
    )
    style_h2 = ParagraphStyle(
        "CadreH2",
        parent=styles["Heading2"],
        textColor=noir,
        fontSize=13,
        spaceBefore=14,
        spaceAfter=6,
    )

    elements: list[Any] = [
        Paragraph("CADRE", style_titre),
        Paragraph(
            f"Rapport de cycle d'audit — {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            style_soustitre,
        ),
        Paragraph("Résumé exécutif", style_h2),
    ]

    lignes_resume = [
        ("Attaques testées", str(total)),
        ("Règles validées et déployées", str(len(groupes["VALIDE"]))),
        ("Règles validées, déploiement Kibana échoué", str(len(groupes["VALIDE_NON_DEPLOYE"]))),
        ("Règles rejetées", str(len(groupes["REJETE"]))),
        ("Angles morts", str(len(groupes["ANGLE_MORT"]))),
        ("Erreurs d'exécution", str(len(groupes["ERREUR"]))),
    ]
    if groupes["EN_ATTENTE_REVUE"]:
        lignes_resume.append(("En attente de revue humaine", str(len(groupes["EN_ATTENTE_REVUE"]))))
    if groupes["SIMULE"]:
        lignes_resume.append(("Attaques simulées", str(len(groupes["SIMULE"]))))
    if groupes["NON_APPLICABLE"]:
        lignes_resume.append(("Non applicables", str(len(groupes["NON_APPLICABLE"]))))
    lignes_resume.append(("Taux de réussite", f"{taux:.1f} % ({succes}/{applicables})"))
    if duree_sec is not None:
        lignes_resume.append(("Durée du cycle", _format_duree(duree_sec)))

    table_resume = Table(lignes_resume, colWidths=[9 * cm, 7 * cm])
    table_resume.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 9.5),
                ("TEXTCOLOR", (0, 0), (-1, -1), noir),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#fbeee0")]),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
                ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(table_resume)

    for statut in _ORDRE_STATUTS:
        groupe = groupes[statut]
        if not groupe:
            continue
        elements.append(Paragraph(f"{_TITRES_STATUTS[statut]} ({len(groupe)})", style_h2))
        entetes = ["Technique", "Tactique", "TP", "FP", "Raison"]
        lignes_tableau = [entetes]
        for r in groupe:
            lignes_tableau.append(_ligne_tableau_pdf(r, styles["Normal"]))
        table = Table(lignes_tableau, colWidths=[5.5 * cm, 2.8 * cm, 1.2 * cm, 1.2 * cm, 5.3 * cm])
        couleur_statut = colors.HexColor(_COULEUR_PAR_STATUT.get(statut, "#9e9e9e"))
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), couleur_statut),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f5f5f5")],
                    ),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        elements.append(table)
        elements.append(Spacer(1, 6))

    doc = SimpleDocTemplate(
        str(fichier_sortie),
        pagesize=A4,
        topMargin=1.8 * cm,
        bottomMargin=1.8 * cm,
        leftMargin=1.6 * cm,
        rightMargin=1.6 * cm,
        title="CADRE — Rapport de cycle d'audit",
    )
    doc.build(elements)
    obtenir_logger().success(f"Rapport PDF généré : {fichier_sortie}")
    return fichier_sortie


def _donut_svg(groupes: dict[str, list[dict[str, Any]]]) -> str:
    """Anneau SVG autonome (aucune lib) de répartition des statuts."""
    segments = [(s, len(groupes[s])) for s in _ORDRE_STATUTS if groupes[s]]
    # `segments` ne contient que des groupes non vides (garde `if groupes[s]`
    # ci-dessus) : `total` ne peut valoir 0 que si `segments` est lui-même
    # vide, auquel cas la boucle de tracé des arcs ci-dessous ne s'exécute
    # jamais (aucune division par `total`) -- un `or 1` ici n'évite donc
    # aucune division par zéro, il ne fait qu'afficher "1 attaque" au lieu
    # de "0" sur un cycle sans aucun résultat.
    total = sum(v for _, v in segments)
    r, cx, cy, largeur = 62.0, 90.0, 90.0, 26.0
    circ = 2 * math.pi * r
    arcs, offset = [], 0.0
    for statut, v in segments:
        dash = v / total * circ
        couleur = _STATUT_COULEUR_UI.get(statut, "#8a9490")
        arcs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{couleur}" '
            f'stroke-width="{largeur}" stroke-dasharray="{dash:.2f} {circ - dash:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})">'
            f"<title>{escape(_STATUT_LABEL_COURT.get(statut, statut))} : {v}</title></circle>"
        )
        offset += dash
    return (
        '<svg viewBox="0 0 180 180" class="donut" role="img" '
        'aria-label="Répartition des statuts">'
        f'{"".join(arcs)}'
        f'<text x="{cx}" y="{cy - 2}" text-anchor="middle" class="donut-num">{total}</text>'
        f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" class="donut-lab">attaques</text>'
        "</svg>"
    )


def _legende_statuts(groupes: dict[str, list[dict[str, Any]]]) -> str:
    items = []
    for statut in _ORDRE_STATUTS:
        n = len(groupes[statut])
        if not n:
            continue
        couleur = _STATUT_COULEUR_UI.get(statut, "#8a9490")
        items.append(
            f'<li><span class="pastille" style="background:{couleur}"></span>'
            f"{escape(_STATUT_LABEL_COURT.get(statut, statut))}"
            f"<b>{n}</b></li>"
        )
    return f'<ul class="legende-donut">{"".join(items)}</ul>'


def _bars_tactiques(resultats_cycle: list[dict[str, Any]]) -> str:
    """Barres horizontales empilées par tactique (validées / autres / angles morts)."""
    par_tactique: dict[str, dict[str, int]] = {}
    for r in resultats_cycle:
        tac = str(r.get("tactique") or "?")
        statut = str(r.get("statut") or "?")
        d = par_tactique.setdefault(tac, {})
        d[statut] = d.get(statut, 0) + 1
    if not par_tactique:
        return '<p class="vide">Aucune donnée.</p>'
    maxi = max(sum(d.values()) for d in par_tactique.values()) or 1
    lignes = []
    for tac, d in sorted(par_tactique.items(), key=lambda kv: -sum(kv[1].values())):
        total = sum(d.values())
        segs = []
        for statut in _ORDRE_STATUTS:
            n = d.get(statut, 0)
            if not n:
                continue
            pct = n / maxi * 100
            couleur = _STATUT_COULEUR_UI.get(statut, "#8a9490")
            segs.append(
                f'<span class="seg" style="width:{pct:.1f}%;background:{couleur}" '
                f'title="{escape(_STATUT_LABEL_COURT.get(statut, statut))} : {n}"></span>'
            )
        lignes.append(
            '<div class="bar-row">'
            f'<span class="bar-lab">{escape(tac)}</span>'
            f'<span class="bar-track">{"".join(segs)}</span>'
            f'<span class="bar-val">{total}</span></div>'
        )
    return f'<div class="bars">{"".join(lignes)}</div>'


def _ligne_html_resultat(r: dict[str, Any]) -> str:
    nom = escape(str(r.get("description", r.get("nom", ""))))
    technique = escape(str(r.get("technique_mitre", "?")))
    tactique = escape(str(r.get("tactique", "?")))
    raison = escape(str(r.get("raison", "-")))
    statut = str(r.get("statut", "?"))
    couleur = _STATUT_COULEUR_UI.get(statut, "#8a9490")
    label = escape(_STATUT_LABEL_COURT.get(statut, statut))
    tp = r.get("nb_tp", "-")
    fp = r.get("nb_fp", "-")
    recherche = escape(f"{technique} {nom} {tactique} {statut} {raison}".lower(), quote=True)
    return (
        f'<tr data-statut="{escape(statut, quote=True)}" data-recherche="{recherche}" '
        f'data-tp="{escape(str(tp), quote=True)}" data-fp="{escape(str(fp), quote=True)}">'
        f'<td class="mono">{technique}</td><td>{nom}</td><td>{tactique}</td>'
        f'<td><span class="chip" style="--c:{couleur}">{label}</span></td>'
        f'<td class="num">{escape(str(tp))}</td><td class="num">{escape(str(fp))}</td>'
        f'<td class="raison">{raison}</td></tr>'
    )


def _regles_html(resultats_cycle: list[dict[str, Any]]) -> str:
    regles = [r for r in resultats_cycle if r.get("regle_sigma_yaml")]
    if not regles:
        return ""
    blocs = []
    for r in regles:
        technique = escape(str(r.get("technique_mitre", "?")))
        nom = escape(str(r.get("description", "")))
        gen = escape(str(r.get("generateur_regle", "deterministe")))
        yaml_regle = escape(str(r["regle_sigma_yaml"]))
        blocs.append(
            f"<details><summary><span class='mono'>{technique}</span> — {nom} "
            f"<span class='tag-gen'>{gen}</span></summary>"
            f"<pre class='yaml'>{yaml_regle}</pre></details>"
        )
    return (
        '<section class="carte"><h2>Règles Sigma générées &amp; validées</h2>'
        '<p class="aide">Chaque règle est passée par la même double validation TP/FP, '
        "quel que soit son générateur. Cliquez pour déplier le YAML.</p>"
        f'{"".join(blocs)}</section>'
    )


def _recommandations_html(aveugles: list[dict[str, Any]]) -> str:
    if not aveugles:
        return ""
    items = []
    for r in aveugles:
        technique = escape(str(r.get("technique_mitre", "?")))
        nom = escape(str(r.get("description", "")))
        eids = escape(str(r.get("event_ids_attendus", [])))
        items.append(
            f"<li><b>{technique}</b> — {nom}<br>"
            f"<span class='aide'>EventIDs attendus : <code>{eids}</code> · "
            "Action : vérifier Sysmon &amp; Winlogbeat sur la cible.</span></li>"
        )
    return (
        '<section class="carte alerte"><h2>Angles morts à investiguer</h2>'
        '<p class="aide">Ces techniques n\'ont produit AUCUNE télémétrie : problème de '
        "collecte (Sysmon, agent, filtrage), pas de règle. À corriger avant la production.</p>"
        f'<ul class="reco">{"".join(items)}</ul></section>'
    )


def _kpi(valeur: str, libelle: str, note: str = "", primaire: bool = False) -> str:
    cls = "kpi primaire" if primaire else "kpi"
    note_html = f'<div class="kpi-note">{escape(note)}</div>' if note else ""
    return (
        f'<div class="{cls}"><div class="kpi-val">{escape(valeur)}</div>'
        f'<div class="kpi-lab">{escape(libelle)}</div>{note_html}</div>'
    )


def generer_rapport_html(resultats_cycle: list[dict[str, Any]], fichier_sortie: Path) -> Path:
    """
    Génère un rapport HTML **interactif et autonome** (CSS + JS inline, aucune
    dépendance ni accès réseau) pour un cycle d'audit : bandeau d'indicateurs,
    anneau de répartition et barres par tactique en SVG, table filtrable et
    triable, règles Sigma dépliables, recommandations d'angles morts. Thème
    clair/sombre. Conçu pour être ouvert directement dans un navigateur ou
    servi par le dashboard.
    """
    log = obtenir_logger()
    fichier_sortie.parent.mkdir(parents=True, exist_ok=True)

    from .metriques import calculer_metriques_valeur  # noqa: PLC0415

    groupes = _grouper_par_statut(resultats_cycle)
    total = len(resultats_cycle)
    succes = sum(len(groupes[s]) for s in STATUTS_DETECTES)
    applicables = total - len(groupes["NON_APPLICABLE"])
    taux = (succes / applicables * 100) if applicables else 0.0
    m = calculer_metriques_valeur(resultats_cycle)
    horodatage = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    lignes_table = "\n".join(
        _ligne_html_resultat(r) for statut in _ORDRE_STATUTS for r in groupes[statut]
    )
    chips_filtre = "".join(
        f'<button class="chip-filtre" data-statut="{escape(s, quote=True)}" '
        f'style="--c:{_STATUT_COULEUR_UI.get(s, "#8a9490")}" onclick="basculerChip(this)">'
        f"{escape(_STATUT_LABEL_COURT.get(s, s))} ({len(groupes[s])})</button>"
        for s in _ORDRE_STATUTS
        if groupes[s]
    )

    kpis = "".join(
        [
            _kpi(f"{taux:.0f}%", "Taux de réussite", f"{succes}/{applicables} applicables", True),
            _kpi(str(len(groupes["VALIDE"])), "Règles déployées", "dans Kibana"),
            _kpi(str(len(groupes["ANGLE_MORT"])), "Angles morts", "aucune télémétrie"),
            _kpi(
                f"~{m['temps_gagne_heures']} h",
                "Temps économisé",
                f"~{m['temps_gagne_jours_ouvres']} j-homme",
            ),
            _kpi(str(m["faux_positifs_median"]), "FP médian / règle", "bruit résiduel (7 j)"),
            _kpi(
                f"{m['tactiques_couvertes']}/{m['total_tactiques_catalogue']}",
                "Tactiques MITRE",
                f"{m['couverture_tactiques_pct']}% du catalogue",
            ),
        ]
    )

    html = f"""<!doctype html>
<html lang="fr" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport de cycle CADRE — {horodatage}</title>
<style>
:root {{
  --bg:#10161a; --surface:#171f24; --surface2:#1c252b; --border:#29343a; --border2:#3d4a45;
  --ink:#e9ebe6; --ink2:#a3aca8; --ink3:#6d7773; --accent:#d9a44e; --accent2:#f0c274;
}}
:root[data-theme="light"] {{
  --bg:#f5f1e8; --surface:#fffdf8; --surface2:#f0ebe0; --border:#ddd5c5; --border2:#c9bfa8;
  --ink:#2b2621; --ink2:#5c554a; --ink3:#8a8072; --accent:#b5822f; --accent2:#946719;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; padding:2rem 1.5rem 4rem; background:var(--bg); color:var(--ink);
  font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; line-height:1.5; }}
.wrap {{ max-width:1100px; margin:0 auto; }}
.entete {{ display:flex; justify-content:space-between; align-items:flex-start; gap:1rem;
  flex-wrap:wrap; border-bottom:2px solid var(--accent); padding-bottom:1rem; margin-bottom:1.5rem; }}
.marque {{ font-weight:700; letter-spacing:0.12em; color:var(--accent); font-size:0.8rem; }}
h1 {{ margin:0.2rem 0 0.1rem; font-size:1.5rem; }}
.date {{ color:var(--ink3); font-size:0.85rem; }}
.btn-theme {{ background:var(--surface); color:var(--ink2); border:1px solid var(--border2);
  border-radius:6px; padding:6px 12px; cursor:pointer; font-size:0.8rem; }}
.btn-theme:hover {{ border-color:var(--accent); color:var(--accent2); }}
.entete-actions {{ display:flex; gap:8px; flex-wrap:wrap; }}
/* Impression / export PDF : mise en page propre, tout déplié, fond clair */
@media print {{
  :root {{ --bg:#fff; --surface:#fff; --surface2:#f4f4f4; --border:#ccc; --border2:#bbb;
    --ink:#111; --ink2:#333; --ink3:#666; --accent:#8a5a10; --accent2:#8a5a10; }}
  .entete-actions, .barre-outils, .btn-theme {{ display:none !important; }}
  body {{ padding:0; }}
  details {{ }} details > summary {{ list-style:none; }}
  .carte, .kpi, details {{ break-inside:avoid; box-shadow:none; }}
  table {{ font-size:0.72rem; }}
  a[href]:after {{ content:""; }}
}}
.kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:0.8rem; margin-bottom:1.5rem; }}
.kpi {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:1rem 1.1rem; }}
.kpi.primaire {{ border-color:var(--accent); box-shadow:inset 0 0 0 1px var(--accent); }}
.kpi-val {{ font-size:1.8rem; font-weight:700; color:var(--accent2); line-height:1; }}
.kpi-lab {{ font-size:0.82rem; color:var(--ink); margin-top:0.35rem; }}
.kpi-note {{ font-size:0.72rem; color:var(--ink3); margin-top:0.15rem; }}
.grille2 {{ display:grid; grid-template-columns:minmax(0,320px) 1fr; gap:1rem; margin-bottom:1.5rem; }}
@media (max-width:760px) {{ .grille2 {{ grid-template-columns:1fr; }} }}
.carte {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:1.1rem 1.25rem; margin-bottom:1.5rem; }}
.carte h2 {{ margin:0 0 0.4rem; font-size:1.05rem; }}
.aide {{ color:var(--ink3); font-size:0.8rem; margin:0.2rem 0 0.8rem; }}
.donut-bloc {{ display:flex; align-items:center; gap:1rem; flex-wrap:wrap; }}
.donut {{ width:150px; height:150px; flex-shrink:0; }}
.donut-num {{ fill:var(--ink); font-size:34px; font-weight:700; }}
.donut-lab {{ fill:var(--ink3); font-size:13px; }}
.legende-donut {{ list-style:none; margin:0; padding:0; font-size:0.82rem; min-width:150px; }}
.legende-donut li {{ display:flex; align-items:center; gap:8px; padding:2px 0; }}
.legende-donut b {{ margin-left:auto; font-variant-numeric:tabular-nums; }}
.pastille {{ width:11px; height:11px; border-radius:3px; flex-shrink:0; }}
.bars {{ display:flex; flex-direction:column; gap:8px; }}
.bar-row {{ display:grid; grid-template-columns:130px 1fr 2em; align-items:center; gap:10px; font-size:0.8rem; }}
.bar-lab {{ color:var(--ink2); text-align:right; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
.bar-track {{ display:flex; height:16px; background:var(--bg); border:1px solid var(--border); border-radius:4px; overflow:hidden; }}
.bar-track .seg {{ height:100%; }}
.bar-track .seg + .seg {{ box-shadow:inset 1px 0 0 var(--surface); }}
.bar-val {{ font-variant-numeric:tabular-nums; color:var(--ink); text-align:right; }}
.barre-outils {{ display:flex; gap:0.6rem; flex-wrap:wrap; align-items:center; margin-bottom:0.8rem; }}
#rech {{ flex:1; min-width:180px; background:var(--bg); border:1px solid var(--border2); border-radius:6px;
  padding:8px 11px; color:var(--ink); font-size:0.85rem; }}
.chip-filtre {{ background:var(--bg); border:1px solid var(--border2); border-radius:999px; padding:4px 11px;
  cursor:pointer; font-size:0.74rem; color:var(--ink2); }}
.chip-filtre::before {{ content:""; display:inline-block; width:8px; height:8px; border-radius:50%;
  background:var(--c); margin-right:6px; vertical-align:middle; }}
.chip-filtre.on {{ border-color:var(--c); color:var(--ink); background:var(--surface2); }}
table {{ width:100%; border-collapse:collapse; font-size:0.82rem; }}
th, td {{ text-align:left; padding:0.55rem 0.6rem; border-bottom:1px solid var(--border); vertical-align:top; }}
th {{ color:var(--ink3); font-size:0.72rem; text-transform:uppercase; letter-spacing:0.04em;
  cursor:pointer; user-select:none; white-space:nowrap; }}
th.triable:hover {{ color:var(--accent2); }}
.mono {{ font-family:ui-monospace,"Cascadia Code",Consolas,monospace; }}
.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
.raison {{ color:var(--ink2); max-width:340px; }}
.chip {{ display:inline-block; padding:2px 9px; border-radius:999px; font-size:0.7rem; font-weight:600;
  color:var(--c); border:1px solid var(--c); white-space:nowrap; }}
details {{ border:1px solid var(--border); border-radius:6px; margin-bottom:6px; background:var(--bg); }}
summary {{ cursor:pointer; padding:8px 11px; font-size:0.84rem; }}
.tag-gen {{ font-size:0.68rem; color:var(--ink3); border:1px solid var(--border2); border-radius:4px; padding:1px 6px; margin-left:6px; }}
pre.yaml {{ margin:0; padding:0.9rem 1rem; background:var(--surface2); border-top:1px solid var(--border);
  overflow-x:auto; font-family:ui-monospace,Consolas,monospace; font-size:0.78rem; color:var(--ink); }}
.carte.alerte {{ border-color:var(--border2); }}
.reco {{ margin:0; padding-left:1.1rem; font-size:0.85rem; }}
.reco li {{ margin-bottom:0.6rem; }}
code {{ font-family:ui-monospace,Consolas,monospace; font-size:0.8rem; color:var(--accent2); }}
.vide {{ color:var(--ink3); font-style:italic; }}
.pied {{ color:var(--ink3); font-size:0.75rem; text-align:center; margin-top:2rem; }}
</style>
</head>
<body>
<div class="wrap">
  <header class="entete">
    <div>
      <div class="marque">CADRE</div>
      <h1>Rapport de cycle d'audit</h1>
      <div class="date">{horodatage} · {total} attaque(s) exécutée(s)</div>
    </div>
    <div class="entete-actions">
      <button class="btn-theme" onclick="window.print()" title="Ouvre la boîte d'impression : choisissez « Enregistrer au format PDF »">Imprimer / PDF</button>
      <button class="btn-theme" onclick="basculerTheme()">◐ Thème</button>
    </div>
  </header>

  <div class="kpis">{kpis}</div>

  <div class="grille2">
    <section class="carte">
      <h2>Répartition des statuts</h2>
      <div class="donut-bloc">{_donut_svg(groupes)}{_legende_statuts(groupes)}</div>
    </section>
    <section class="carte">
      <h2>Couverture par tactique MITRE</h2>
      <p class="aide">Attaques par tactique, empilées par statut (survolez un segment).</p>
      {_bars_tactiques(resultats_cycle)}
    </section>
  </div>

  <section class="carte">
    <h2>Détail des attaques</h2>
    <div class="barre-outils">
      <input id="rech" placeholder="Filtrer (technique, nom, tactique, raison...)" oninput="filtrer()">
      {chips_filtre}
    </div>
    <div style="overflow-x:auto">
      <table id="tab">
        <thead><tr>
          <th class="triable" onclick="trier(0,false)">Technique</th>
          <th class="triable" onclick="trier(1,false)">Nom</th>
          <th class="triable" onclick="trier(2,false)">Tactique</th>
          <th class="triable" onclick="trier(3,false)">Statut</th>
          <th class="triable num" onclick="trier(4,true)">TP</th>
          <th class="triable num" onclick="trier(5,true)">FP</th>
          <th>Raison</th>
        </tr></thead>
        <tbody id="corps">{lignes_table}</tbody>
      </table>
    </div>
  </section>

  {_regles_html(resultats_cycle)}
  {_recommandations_html(groupes["ANGLE_MORT"])}

  <p class="pied">Rapport autonome généré par CADRE · aucune donnée ne quitte votre poste.</p>
</div>
<script>
// Avant impression / export PDF : déplie toutes les règles Sigma pour qu'elles
// apparaissent dans le PDF (une section repliée ne s'imprime pas).
window.addEventListener("beforeprint", function() {{
  document.querySelectorAll("details").forEach(function(d) {{ d.open = true; }});
}});
function basculerTheme() {{
  const r = document.documentElement;
  r.setAttribute("data-theme", r.getAttribute("data-theme") === "light" ? "dark" : "light");
}}
const corps = document.getElementById("corps");
function chipsActifs() {{
  return [...document.querySelectorAll(".chip-filtre.on")].map(c => c.dataset.statut);
}}
function filtrer() {{
  const q = document.getElementById("rech").value.toLowerCase();
  const actifs = chipsActifs();
  corps.querySelectorAll("tr").forEach(tr => {{
    const okTexte = !q || (tr.dataset.recherche || "").includes(q);
    const okStatut = actifs.length === 0 || actifs.includes(tr.dataset.statut);
    tr.style.display = (okTexte && okStatut) ? "" : "none";
  }});
}}
function basculerChip(btn) {{ btn.classList.toggle("on"); filtrer(); }}
let sensTri = {{}};
function trier(col, numerique) {{
  const rows = [...corps.querySelectorAll("tr")];
  const sens = sensTri[col] = -(sensTri[col] || 1);
  rows.sort((a, b) => {{
    let x = a.children[col].textContent.trim(), y = b.children[col].textContent.trim();
    if (numerique) {{ x = parseFloat(x) || 0; y = parseFloat(y) || 0; return (x - y) * sens; }}
    return x.localeCompare(y, "fr") * sens;
  }});
  rows.forEach(r => corps.appendChild(r));
}}
</script>
</body>
</html>
"""
    fichier_sortie.write_text(html, encoding="utf-8")
    log.success(f"Rapport HTML généré : {fichier_sortie}")
    return fichier_sortie


def _etape_kill_chain_html(etape: dict[str, Any], derniere: bool) -> str:
    """Une phase de la kill chain : puce colorée + connecteur vers la suivante.

    La puce ne porte plus d'icône (juste la couleur) -- le statut reste
    pleinement lisible sans elle : `title` (infobulle) et le `label` visible
    plus bas dans `.kc-meta` portent déjà le texte complet, jamais couleur
    seule.
    """
    couleur = _STATUT_COULEUR_UI.get(str(etape.get("statut")), "#8a9490")
    label = escape(_STATUT_LABEL_COURT.get(str(etape.get("statut")), str(etape.get("statut"))))
    connecteur = "" if derniere else '<div class="kc-lien" aria-hidden="true"></div>'
    return (
        '<li class="kc-etape">'
        f'<div class="kc-puce" style="--c:{couleur}" title="{label}"></div>'
        f"{connecteur}"
        '<div class="kc-corps">'
        f'<div class="kc-tactique">{escape(str(etape.get("tactique")))}</div>'
        f'<div class="kc-nom">{escape(str(etape.get("nom")))}</div>'
        f'<div class="kc-meta"><code>{escape(str(etape.get("id")))}</code> · '
        f'{escape(str(etape.get("technique_mitre")))} · '
        f'<span style="color:{couleur}">{label}</span></div>'
        "</div>"
        "</li>"
    )


def generer_rapport_kill_chain(
    scenario: Any, analyse: dict[str, Any], fichier_sortie: Path
) -> Path:
    """
    Génère un rapport HTML **autonome** visualisant la couverture de détection
    d'une kill chain d'adversaire (scénario) : le nombre de phases détectées
    sur le total, la chaîne d'attaque phase par phase (chaque étape marquée
    détectée ou angle mort ), et la liste des angles morts à combler.

    C'est le livrable qui distingue CADRE d'un simple émulateur : on ne montre
    pas seulement que la chaîne a été jouée, mais **quelle proportion de la
    campagne serait effectivement détectée** par le SOC.
    """
    log = obtenir_logger()
    fichier_sortie.parent.mkdir(parents=True, exist_ok=True)

    horodatage = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    etapes = analyse.get("etapes", [])
    total = int(analyse.get("total_etapes", 0))
    detectees = int(analyse.get("etapes_detectees", 0))
    couverture = float(analyse.get("couverture_pct", 0.0))
    angles_morts = [e for e in etapes if not e.get("detectee")]

    # Régression (audit) : "détectee" exclut désormais SIMULE (voir
    # scenarios.STATUTS_DETECTES_KILL_CHAIN) -- un run --simulate affiche
    # donc 0% par construction (aucune mesure réelle n'a eu lieu). Sans ce
    # bandeau, ce 0% se lirait comme un échec de détection au lieu d'une
    # simple absence de preuve dans ce mode.
    bandeau_simulation = (
        (
            '<div class="carte alerte"><h2>Rapport de simulation (--simulate)</h2>'
            '<p class="aide">Aucune attaque n\'a été exécutée sur la cible : '
            "syntaxe Sigma validée uniquement, aucune mesure TP/FP réelle. "
            "La couverture ci-dessous est nulle par construction — ce n'est "
            "PAS un échec de détection, relancez sans <code>--simulate</code> "
            "pour une mesure réelle.</p></div>"
        )
        if analyse.get("mode_simulation")
        else ""
    )

    etapes_html = "\n".join(
        _etape_kill_chain_html(e, derniere=(i == len(etapes) - 1)) for i, e in enumerate(etapes)
    )
    if angles_morts:
        am_items = "".join(
            f"<li><code>{escape(str(e.get('id')))}</code> — "
            f"{escape(str(e.get('nom')))} "
            f"<span class=\"am-tac\">({escape(str(e.get('tactique')))})</span></li>"
            for e in angles_morts
        )
        angles_html = (
            '<div class="carte alerte"><h2>Angles morts à combler '
            f"({len(angles_morts)})</h2>"
            '<p class="aide">Ces phases de la campagne ne seraient PAS détectées '
            "en l'état — ce sont les règles prioritaires à créer.</p>"
            f'<ul class="am-liste">{am_items}</ul></div>'
        )
    else:
        angles_html = (
            '<div class="carte succes"><h2>Kill chain entièrement couverte</h2>'
            '<p class="aide">Chaque phase de cette campagne déclenche une détection '
            "validée. Aucun angle mort.</p></div>"
        )

    kpis = "".join(
        [
            _kpi(f"{couverture:.0f}%", "Couverture de la chaîne", "phases détectées", True),
            _kpi(f"{detectees}/{total}", "Phases détectées", "règles validées"),
            _kpi(str(len(angles_morts)), "Angles morts", "phases non détectées"),
            _kpi(str(total), "Phases MITRE", "longueur de la chaîne"),
        ]
    )

    html = f"""<!doctype html>
<html lang="fr" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kill chain — {escape(str(analyse.get("scenario_nom", scenario.id)))}</title>
<style>
:root {{ --bg:#10161a; --surface:#171f24; --surface2:#1c252b; --border:#29343a; --border2:#3d4a45;
  --ink:#e9ebe6; --ink2:#a3aca8; --ink3:#6d7773; --accent:#d9a44e; --accent2:#f0c274;
  --ok:#5fae7d; --ko:#d9705f; }}
:root[data-theme="light"] {{ --bg:#f5f1e8; --surface:#fffdf8; --surface2:#f0ebe0; --border:#ddd5c5;
  --border2:#c9bfa8; --ink:#2b2621; --ink2:#5c554a; --ink3:#8a8072; --accent:#b5822f; --accent2:#946719; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; padding:2rem 1.5rem 4rem; background:var(--bg); color:var(--ink);
  font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; line-height:1.5; }}
.wrap {{ max-width:920px; margin:0 auto; }}
.entete {{ display:flex; justify-content:space-between; align-items:flex-start; gap:1rem;
  flex-wrap:wrap; border-bottom:2px solid var(--accent); padding-bottom:1rem; margin-bottom:1.5rem; }}
.marque {{ font-weight:700; letter-spacing:0.12em; color:var(--accent); font-size:0.8rem; }}
h1 {{ margin:0.2rem 0 0.1rem; font-size:1.5rem; }}
.adversaire {{ color:var(--ink2); font-size:0.95rem; }}
.date {{ color:var(--ink3); font-size:0.85rem; }}
.btn-theme {{ background:var(--surface); color:var(--ink2); border:1px solid var(--border2);
  border-radius:6px; padding:6px 12px; cursor:pointer; font-size:0.8rem; }}
.btn-theme:hover {{ border-color:var(--accent); color:var(--accent2); }}
.kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:0.8rem; margin-bottom:1.5rem; }}
.kpi {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:1rem 1.1rem; }}
.kpi.primaire {{ border-color:var(--accent); box-shadow:inset 0 0 0 1px var(--accent); }}
.kpi-val {{ font-size:1.8rem; font-weight:700; color:var(--accent2); line-height:1; }}
.kpi-lab {{ font-size:0.82rem; color:var(--ink); margin-top:0.35rem; }}
.kpi-note {{ font-size:0.72rem; color:var(--ink3); margin-top:0.15rem; }}
.carte {{ background:var(--surface); border:1px solid var(--border); border-radius:8px;
  padding:1.1rem 1.25rem; margin-bottom:1.5rem; }}
.carte h2 {{ margin:0 0 0.4rem; font-size:1.05rem; }}
.carte.alerte {{ border-left:4px solid var(--ko); }}
.carte.succes {{ border-left:4px solid var(--ok); }}
.aide {{ color:var(--ink3); font-size:0.85rem; margin:0.2rem 0 0.8rem; }}
.desc {{ color:var(--ink2); font-size:0.9rem; margin:0 0 1.2rem; }}
/* --- Kill chain verticale --- */
.kc {{ list-style:none; margin:0; padding:0; }}
.kc-etape {{ position:relative; display:flex; gap:1rem; padding-bottom:1.4rem; }}
.kc-puce {{ position:relative; z-index:2; flex-shrink:0; width:34px; height:34px; border-radius:50%;
  background:var(--surface); border:2px solid var(--c); color:var(--c); display:flex;
  align-items:center; justify-content:center; font-weight:700; font-size:1rem; }}
.kc-lien {{ position:absolute; left:16px; top:34px; bottom:0; width:2px; background:var(--border2); }}
.kc-corps {{ padding-top:0.15rem; }}
.kc-tactique {{ font-size:0.72rem; letter-spacing:0.08em; text-transform:uppercase; color:var(--accent); }}
.kc-nom {{ font-weight:600; font-size:0.98rem; }}
.kc-meta {{ font-size:0.8rem; color:var(--ink3); margin-top:0.1rem; }}
.kc-meta code {{ background:var(--surface2); padding:1px 5px; border-radius:4px; }}
.am-liste {{ margin:0.4rem 0 0; padding-left:1.2rem; font-size:0.9rem; }}
.am-liste li {{ padding:2px 0; }}
.am-liste code {{ background:var(--surface2); padding:1px 5px; border-radius:4px; }}
.am-tac {{ color:var(--ink3); }}
.pied {{ color:var(--ink3); font-size:0.78rem; text-align:center; margin-top:2rem; }}
@media print {{ .btn-theme {{ display:none; }} body {{ padding:0; }} }}
</style>
</head>
<body>
<div class="wrap">
  <div class="entete">
    <div>
      <div class="marque">CADRE · ÉMULATION D'ADVERSAIRE</div>
      <h1>{escape(str(analyse.get("scenario_nom", scenario.id)))}</h1>
      <div class="adversaire">Adversaire émulé : {escape(str(analyse.get("adversaire", "")))}</div>
      <div class="date">{escape(horodatage)} · cible {escape(str(analyse.get("plateforme", "")))}</div>
    </div>
    <button class="btn-theme" onclick="basculerTheme()">Thème</button>
  </div>

  <p class="desc">{escape(str(getattr(scenario, "description", "")))}</p>

  {bandeau_simulation}

  <div class="kpis">{kpis}</div>

  <div class="carte">
    <h2>Déroulé de la kill chain</h2>
    <p class="aide">Chaque phase a été jouée dans l'ordre, puis CADRE a tenté de
    générer et valider sa détection. La couleur et le libellé de chaque puce
    indiquent son statut (règle validée ou angle mort).</p>
    <ul class="kc">
{etapes_html}
    </ul>
  </div>

  {angles_html}

  <div class="pied">Généré par CADRE — Continuous Adversary-Driven Rule Engineering ·
  scénario déterministe et reproductible</div>
</div>
<script>
function basculerTheme() {{
  const r = document.documentElement;
  r.dataset.theme = r.dataset.theme === "light" ? "dark" : "light";
}}
</script>
</body>
</html>
"""
    fichier_sortie.write_text(html, encoding="utf-8")
    log.success(f"Rapport kill chain généré : {fichier_sortie}")
    return fichier_sortie


def generer_layer_navigator(
    resultats_cycle: list[dict[str, Any]],
    fichier_sortie: Path,
    nom: str = "CADRE — Couverture de détection",
) -> Path:
    """
    Génère un layer MITRE ATT&CK Navigator (format JSON v4.5) à partir des
    résultats d'un cycle — pour visualiser la couverture réelle sous forme
    de heatmap sur https://mitre-attack.github.io/attack-navigator/.

    Une technique testée par plusieurs attaques prend le meilleur statut
    obtenu (VALIDE prime sur REJETE, qui prime sur ANGLE_MORT, etc.),
    l'ordre étant celui de `_ORDRE_STATUTS`. Les attaques NON_APPLICABLE
    (plateforme incompatible) ne sont pas incluses : elles n'ont jamais
    été testées sur cette cible.
    """
    log = obtenir_logger()
    fichier_sortie.parent.mkdir(parents=True, exist_ok=True)

    par_technique: dict[str, dict[str, Any]] = {}
    for r in resultats_cycle:
        statut = r.get("statut")
        technique = r.get("technique_mitre")
        if not technique or statut not in _COULEUR_PAR_STATUT:
            continue
        existant = par_technique.get(technique)
        if existant is None or _ORDRE_STATUTS.index(statut) < _ORDRE_STATUTS.index(
            existant["statut"]
        ):
            par_technique[technique] = {"statut": statut, "description": r.get("description", "")}

    techniques = [
        {
            "techniqueID": technique_id,
            "color": _COULEUR_PAR_STATUT[info["statut"]],
            "comment": f"{_TITRES_STATUTS[info['statut']]} — {info['description']}",
            "enabled": True,
        }
        for technique_id, info in sorted(par_technique.items())
    ]

    layer = {
        "name": nom,
        "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Généré par CADRE le {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
        "techniques": techniques,
        "gradient": {"colors": ["#f44336", "#ff9800", "#4caf50"], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": _TITRES_STATUTS[statut], "color": couleur}
            for statut, couleur in _COULEUR_PAR_STATUT.items()
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    fichier_sortie.write_text(json.dumps(layer, indent=2, ensure_ascii=False), encoding="utf-8")
    log.success(f"Layer ATT&CK Navigator généré : {fichier_sortie}")
    return fichier_sortie


def generer_rapport_soutenance(
    resultats_complets: dict[str, Any],
    fichier_sortie: Path,
    nom_etudiant: str = "Mohamed Amine EDDARI",
    nom_encadrant: str = "Encadrant SOC",
    etablissement: str = "École Supérieure d'Ingénierie",
) -> Path:
    """
    Génère le rapport PFA complet pour la soutenance.
    """
    fichier_sortie.parent.mkdir(parents=True, exist_ok=True)
    log = obtenir_logger()

    contenu = f"""# Projet de Fin d'Année — CADRE
## Continuous Adversary-Driven Rule Engineering

---

**Auteur** : {nom_etudiant}
**Encadrant** : {nom_encadrant}
**Établissement** : {etablissement}
**Date de soutenance** : {datetime.now().strftime('%d/%m/%Y')}
**Version** : 1.0.0

---

## Résumé exécutif

CADRE est un système d'**audit continu de SOC** basé sur l'émulation d'adversaire
et l'ingénierie de détection assistée par IA. Le projet démontre qu'il est possible
d'automatiser la création, la validation et le déploiement de règles de détection
de qualité entreprise, à partir de l'exécution contrôlée de techniques MITRE ATT&CK
contre une infrastructure Elastic/Kibana.

## 1. Problématique

Les organisations font face à deux défis majeurs dans la gestion de leur SOC :

1. **L'angle mort permanent** : les règles de détection couvrent un sous-ensemble fini
   de techniques MITRE ATT&CK. L'attaquant n'a qu'à utiliser une technique non couverte.

2. **La dérive temporelle** : les règles deviennent obsolètes à mesure que les
   attaquants font évoluer leurs TTPs (Tactiques, Techniques, Procédures).

3. **Le coût humain** : un ingénieur détection écrit en moyenne 5 règles/jour.
   Pour un SOC de taille moyenne, c'est plusieurs mois de travail par an.

## 2. Solution proposée

CADRE propose un **pipeline CI/CD de détection** qui :

1. **Émule** une technique MITRE ATT&CK sur une VM cible
2. **Collecte** la télémétrie via Sysmon + Winlogbeat → Elasticsearch
3. **Recherche** l'EventID attendu (déterminisme)
4. **Anonymise** le log (RGPD)
5. **Génère** une règle Sigma de façon déterministe à partir du catalogue
   (aucun LLM dans cette étape — reproductibilité et auditabilité garanties)
6. **Compile** Sigma → Lucene
7. **Valide** en double : TP (détecte l'attaque) + FP (pas trop bruyant)
8. **Déploie** automatiquement dans Kibana via API

En complément du pipeline, un **assistant LLM local (Ollama)** aide à la
rédaction de nouvelles entrées de catalogue à partir d'une description en
langage naturel et à la synthèse des rapports d'audit — toujours en dehors
du chemin de génération/validation/déploiement des règles.

## 3. Architecture technique

```
┌──────────────────────────────────────────────────────────────┐
│ Hôte Windows (Zone 1 — Orchestrateur + SIEM)                 │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ Docker Compose (CADRE_SIEM)                             │ │
│ │ • Elasticsearch (indexation)                           │ │
│ │ • Kibana (visualisation + alertes)                     │ │
│ │ └────────────────────────────────────────────────────────┘ │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ Orchestrateur CADRE (Python, hors conteneur)            │ │
│ │ • Catalogue déterministe d'attaques (34 entrées)        │ │
│ │ • Génération Sigma + pysigma (compilation en mémoire)   │ │
│ │ • Coffre-fort (Fernet)                                  │ │
│ │ • Ollama (LLM local, assistance hors chemin critique)   │ │
│ │ └────────────────────────────────────────────────────────┘ │
│              │ WinRM (5985)                                 │
│              ▼                                              │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ VM Windows 10 (Zone 2 — Cible)                        │ │
│ │ • Sysmon (télémétrie enrichie)                        │ │
│ │ • Winlogbeat (collecte → Elasticsearch)                │ │
│ │ • Firewall + Defender désactivés (par design)         │ │
│ └────────────────────────────────────────────────────────┘ │
│              (réseau Host-Only VirtualBox)                  │
└──────────────────────────────────────────────────────────────┘
```

## 4. Choix techniques

### 4.1. Pourquoi Elastic + Kibana (et pas Wazuh/Splunk) ?

- **Open source** vs Wazuh (limité en scalabilité)
- **Maturité** vs Splunk Enterprise (coût prohibitif)
- **Kibana SIEM** intégré nativement, API REST pour déploiement de règles
- **Performances** d'Elasticsearch sur la recherche full-text (LogLash natif)

### 4.2. Pourquoi Sigma (et pas des règles Kibana natives) ?

- **Portabilité** : une règle Sigma peut être convertie en Lucene, Splunk SPL, KQL
- **Communauté** : > 3000 règles publiques, modèle de Threat Intel partagé
- **Validation** : syntaxe vérifiable hors-ligne avant déploiement

### 4.3. Pourquoi Ollama local pour l'assistant IA (et pas Gemini API) ?

CADRE utilise un LLM local en **couche d'assistance** (brouillons de
catalogue, synthèses de rapport) — jamais pour générer ou valider une règle
réellement déployée, ce qui reste 100% déterministe.

- **Confidentialité** : les logs contiennent des données sensibles
- **Coût** : un LLM local est gratuit après l'investissement initial
- **Disponibilité** : pas de rate-limiting, pas de 503, pas de dépendance externe
- **Reproductibilité du cœur du pipeline** : l'assistant peut évoluer sans
  jamais casser le déterminisme des règles déployées

## 5. Raffinements intégrés

| Raffinement | Description | Statut |
|-------------|-------------|--------|
| Déterminisme | Catalogue prédéfini au lieu de génération libre | |
| Anonymisation PII | RGPD-by-design, hashing déterministe | |
| Coffre-fort credentials | Aucun secret en clair dans le code | |
| Attente d'indexation | Polling adaptatif pour éviter les angles morts | |
| Double validation TP/FP | Test sur fenêtre 5 min + bruit 7 jours | |
| Logger structuré JSON | Traçabilité complète pour forensic | |
| Rapports automatiques | Markdown + CSV pour exploitation | |
| Catalogue de 40 attaques | Couvre 11 tactiques MITRE | |
| Filtrage FP par atténuation | Whitelist des process connus | |
| Assistant LLM (Ollama) | Brouillons de catalogue + synthèses, hors chemin critique | |

## 6. Résultats de l'audit

*(Cette section sera mise à jour après exécution du pipeline.)*

```
Nombre de cycles exécutés : {resultats_complets.get('nb_cycles', 'N/A')}
Techniques couvertes       : {resultats_complets.get('nb_techniques', 'N/A')}
Règles générées            : {resultats_complets.get('nb_regles', 'N/A')}
Règles déployées           : {resultats_complets.get('nb_deployees', 'N/A')}
Angles morts détectés      : {resultats_complets.get('nb_aveugles', 'N/A')}
```

## 7. Limites et perspectives

### 7.1. Limites actuelles

- **Mono-SIEM** : ne fonctionne qu'avec Elastic + Kibana
- **Mono-OS** : attaques Windows uniquement (Linux = 0% du catalogue)
- **Mono-environnement** : nécessite un hôte Docker + VM VirtualBox
- **Modèle Ollama limité** : qualité des règles dépendante du LLM choisi

### 7.2. Perspectives

- Support multi-SIEM (Wazuh, Splunk, Chronicle)
- Ajout d'attaques Linux (audit cron, systemd, etc.)
- Interface web (React/Streamlit) pour pilotage
- API REST pour intégration dans un pipeline DevSecOps
- Publication d'un catalogue de règles publiques

## 8. Conclusion

CADRE démontre la **faisabilité d'un Purple Team automatisé** dans un contexte
de stage PFA, avec un niveau de qualité industriellement utilisable. Le projet
aborde les vrais défis de l'ingénierie de détection : déterminisme, faux positifs,
anonymisation, déploiement continu.

Les compétences acquises couvrent : sécurité offensive (MITRE ATT&CK), sécurité
défensive (SIEM, Sigma), DevOps (CI/CD, conteneurisation), IA appliquée (LLM local),
et ingénierie logicielle (architecture propre, tests, documentation).

---

*Document généré automatiquement par CADRE. Pour plus de détails, consulter
le dépôt Git et la documentation technique dans `docs/`.*
"""
    fichier_sortie.write_text(contenu, encoding="utf-8")
    log.success(f"Rapport de soutenance généré : {fichier_sortie}")
    return fichier_sortie
