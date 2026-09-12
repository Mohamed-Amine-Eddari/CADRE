# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Métriques de valeur
===========================

Transforme les résultats bruts d'un cycle (VALIDE / REJETE / ANGLE_MORT…)
en indicateurs de **valeur métier** : temps d'ingénierie économisé,
couverture MITRE ATT&CK réellement obtenue, qualité des règles produites.

Principe d'honnêteté : le "temps gagné" est une **estimation** dérivée d'une
hypothèse explicite et configurable (temps moyen d'écriture manuelle d'une
règle de détection), jamais un chiffre inventé présenté comme mesuré. La
valeur par défaut (1,6 h/règle) vient de la référence sectorielle citée dans
la documentation du projet : un ingénieur détection écrit ~5 règles par jour
ouvré, soit ~1,6 h par règle. Toute sortie de ce module la rappelle comme
hypothèse.
"""

from __future__ import annotations

import csv
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

# Hypothèse de référence, explicite et défendable (voir docstring du module).
HEURES_PAR_REGLE_MANUELLE = 1.6

# Statuts comptant comme "une règle de détection produite avec succès".
# EN_ATTENTE_REVUE (cadre cycle --revue) : la règle a bien été validée
# (TP/FP passés) -- seul le déploiement Kibana est différé, volontairement,
# en attendant une revue humaine. Compte comme un succès au même titre que
# VALIDE_NON_DEPLOYE (déploiement différé pour une autre raison, technique).
_STATUTS_SUCCES = ("VALIDE", "VALIDE_NON_DEPLOYE", "EN_ATTENTE_REVUE")


def _total_tactiques_catalogue() -> int:
    """Nombre de tactiques MITRE distinctes couvertes par le catalogue."""
    from .catalogue_attaques import CATALOGUE  # noqa: PLC0415

    return len({a.tactique_mitre for a in CATALOGUE})


def calculer_metriques_valeur(
    resultats: list[dict[str, Any]],
    heures_par_regle_manuelle: float = HEURES_PAR_REGLE_MANUELLE,
) -> dict[str, Any]:
    """
    Calcule les indicateurs de valeur d'un cycle.

    Args:
        resultats: liste de dicts de résultats (clés statut, technique_mitre,
            tactique, nb_fp…).
        heures_par_regle_manuelle: hypothèse de temps d'écriture manuelle
            d'une règle, pour l'estimation du temps gagné.

    Returns:
        dict d'indicateurs, prêt à afficher ou sérialiser.
    """
    total = len(resultats)
    non_applicables = sum(1 for r in resultats if r.get("statut") == "NON_APPLICABLE")
    applicables = total - non_applicables

    succes = [r for r in resultats if r.get("statut") in _STATUTS_SUCCES]
    nb_regles = len(succes)

    # Couverture : tactiques et techniques distinctes réellement couvertes
    # par au moins une règle validée.
    tactiques_couvertes = {r.get("tactique") for r in succes if r.get("tactique")}
    techniques_couvertes = {r.get("technique_mitre") for r in succes if r.get("technique_mitre")}
    techniques_testees = {
        r.get("technique_mitre")
        for r in resultats
        if r.get("statut") != "NON_APPLICABLE" and r.get("technique_mitre")
    }
    total_tactiques = _total_tactiques_catalogue()

    # Qualité : faux positifs MÉDIANS des règles validées (bruit résiduel
    # typique). La médiane plutôt que la moyenne : une ou deux règles
    # baseline volontairement bruyantes (ex. CADRE-EXE-001, seuil FP élevé
    # assumé) suffisent à faire exploser une moyenne, ce qui donnerait une
    # image faussement mauvaise de la qualité usuelle des règles.
    fp_valides = [
        r["nb_fp"]
        for r in succes
        if isinstance(r.get("nb_fp"), (int, float)) and r.get("nb_fp") is not None
    ]
    fp_median = round(statistics.median(fp_valides), 1) if fp_valides else 0.0

    heures_gagnees = round(nb_regles * heures_par_regle_manuelle, 1)

    return {
        "total_attaques": total,
        "applicables": applicables,
        "non_applicables": non_applicables,
        "regles_produites": nb_regles,
        "taux_reussite_pct": round(nb_regles / applicables * 100, 1) if applicables else 0.0,
        "temps_gagne_heures": heures_gagnees,
        "temps_gagne_jours_ouvres": round(heures_gagnees / 8, 2),
        "hypothese_heures_par_regle": heures_par_regle_manuelle,
        "tactiques_couvertes": len(tactiques_couvertes),
        "total_tactiques_catalogue": total_tactiques,
        "couverture_tactiques_pct": (
            round(len(tactiques_couvertes) / total_tactiques * 100, 1) if total_tactiques else 0.0
        ),
        "techniques_couvertes": len(techniques_couvertes),
        "techniques_testees": len(techniques_testees),
        "faux_positifs_median": fp_median,
    }


def calculer_tendance_cumulative(cumulatif: dict[str, Any]) -> dict[str, Any]:
    """
    Dérive des indicateurs de valeur agrégés depuis le fichier cumulatif
    (`rapports/cadre_cumulatif.json`, alimenté par le mode `cadre loop`).

    Retourne un dict vide si le cumulatif ne contient pas les clés attendues.
    """
    if not cumulatif or "validees" not in cumulatif:
        return {}

    validees = cumulatif.get("validees", 0)
    total_attaques = cumulatif.get("total_attaques", 0)
    heures = round(validees * HEURES_PAR_REGLE_MANUELLE, 1)
    return {
        "total_cycles": cumulatif.get("total_cycles", 0),
        "total_attaques": total_attaques,
        "regles_validees_cumul": validees,
        "temps_gagne_heures_cumul": heures,
        "temps_gagne_jours_ouvres_cumul": round(heures / 8, 2),
        "taux_reussite_cumul_pct": (
            round(validees / total_attaques * 100, 1) if total_attaques else 0.0
        ),
    }


def _entier_depuis_csv(brut: Any) -> int | None:
    """Convertit une colonne numérique de CSV (str) en int, ou None si absente/non numérique."""
    return int(brut) if brut not in (None, "", "-") and str(brut).isdigit() else None


def metriques_dernier_cycle(repertoire_rapports: Path) -> dict[str, Any]:
    """
    Charge le cycle le plus récent (`cycle_*.csv`) et calcule ses indicateurs
    de valeur. Retourne un dict vide si aucun cycle. Point d'entrée unique
    partagé par `cadre metriques` (CLI) et le dashboard (`/api/metriques`).
    """
    if not repertoire_rapports.is_dir():
        return {}
    cycles = sorted(repertoire_rapports.glob("cycle_*.csv"), reverse=True)
    if not cycles:
        return {}
    with cycles[0].open(encoding="utf-8-sig", newline="") as f:  # retire le BOM (compat Excel)
        lignes = list(csv.DictReader(f))
    for r in lignes:  # nb_fp arrive en str depuis le CSV
        r["nb_fp"] = _entier_depuis_csv(r.get("nb_fp"))
    return calculer_metriques_valeur(lignes)


def detecter_derive_regle(attaque_id: str, repertoire_rapports: Path) -> dict[str, Any]:
    """
    Compare la validation la PLUS RÉCENTE d'une attaque à sa première mesure
    historique connue, en parcourant tous les cycles archivés
    (`cycle_*.csv`, triés chronologiquement par nom de fichier horodaté) --
    détecte qu'une règle « pourrit » (environnement qui change, indicateur
    devenu obsolète) sans attendre qu'elle finisse par échouer en silence.

    Rien de nouveau à mesurer : relit des mesures TP/FP déjà produites par
    `double_validation_tp_fp` à chaque cycle passé, via le champ `id`
    (ajouté à l'export CSV pour rendre ce suivi possible -- absent des
    cycles archivés avant ce changement, naturellement ignorés).

    Retourne `{"statut": "INSUFFISANT", ...}` si moins de 2 mesures
    exploitables existent pour cette attaque.
    """
    mesures: list[dict[str, Any]] = []
    if repertoire_rapports.is_dir():
        for fichier in sorted(repertoire_rapports.glob("cycle_*.csv")):
            with fichier.open(encoding="utf-8-sig", newline="") as f:
                for ligne in csv.DictReader(f):
                    if ligne.get("id") != attaque_id:
                        continue
                    tp = _entier_depuis_csv(ligne.get("nb_tp"))
                    fp = _entier_depuis_csv(ligne.get("nb_fp"))
                    if tp is None or fp is None:
                        continue
                    mesures.append({"timestamp": ligne.get("timestamp"), "nb_tp": tp, "nb_fp": fp})

    if len(mesures) < 2:
        return {"statut": "INSUFFISANT", "nb_mesures": len(mesures)}
    return _statut_depuis_mesures(mesures)


def _statut_depuis_mesures(mesures: list[dict[str, Any]]) -> dict[str, Any]:
    """Cœur de la logique de dérive, partagé par `detecter_derive_regle`
    (une attaque) et `detecter_derive_toutes_regles` (vue d'ensemble) --
    `mesures` doit déjà contenir au moins 2 entrées triées chronologiquement."""
    premiere, derniere = mesures[0], mesures[-1]

    if premiere["nb_tp"] > 0 and derniere["nb_tp"] == 0:
        statut = "PERTE_DETECTION"
    elif premiere["nb_fp"] > 0 and derniere["nb_fp"] > premiere["nb_fp"] * 1.5:
        statut = "DERIVE_BRUIT"
    else:
        statut = "STABLE"

    return {
        "statut": statut,
        "nb_mesures": len(mesures),
        "premiere": premiere,
        "derniere": derniere,
    }


def detecter_derive_toutes_regles(repertoire_rapports: Path) -> dict[str, dict[str, Any]]:
    """
    Version multi-attaques de `detecter_derive_regle` : une seule passe sur
    les cycles archivés (au lieu d'une par attaque) -- pour la vue
    d'ensemble du dashboard, où on veut le statut de dérive de tout le
    catalogue d'un coup, pas une attaque à la fois.

    Retourne `{attaque_id: résultat}` uniquement pour les attaques ayant au
    moins 2 mesures exploitables (les autres n'ont simplement pas encore
    assez d'historique -- pas une erreur, juste absentes du résultat).
    """
    mesures_par_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if repertoire_rapports.is_dir():
        for fichier in sorted(repertoire_rapports.glob("cycle_*.csv")):
            with fichier.open(encoding="utf-8-sig", newline="") as f:
                for ligne in csv.DictReader(f):
                    aid = ligne.get("id")
                    if not aid:
                        continue
                    tp = _entier_depuis_csv(ligne.get("nb_tp"))
                    fp = _entier_depuis_csv(ligne.get("nb_fp"))
                    if tp is None or fp is None:
                        continue
                    mesures_par_id[aid].append(
                        {"timestamp": ligne.get("timestamp"), "nb_tp": tp, "nb_fp": fp}
                    )

    return {
        aid: _statut_depuis_mesures(mesures)
        for aid, mesures in mesures_par_id.items()
        if len(mesures) >= 2
    }
