"""
Tests pour les scénarios d'adversaire (src/cadre/scenarios.py) et la commande
`cadre scenario`. Vérifie la cohérence du catalogue (aucune référence cassée),
la logique d'analyse de kill chain, le rapport HTML autonome, et la CLI.
"""

from __future__ import annotations

from click.testing import CliRunner

from cadre.cli import cli
from cadre.scenarios import (
    SCENARIOS,
    STATUTS_DETECTES,
    STATUTS_DETECTES_KILL_CHAIN,
    ScenarioAdversaire,
    analyser_kill_chain,
    attaques_ordonnees,
    obtenir_scenario,
    valider_scenarios,
)


# ---------------------------------------------------------------------------
# Cohérence du catalogue de scénarios
# ---------------------------------------------------------------------------
def test_aucune_reference_cassee():
    """Chaque ID d'attaque référencé doit exister dans le catalogue."""
    assert valider_scenarios() == []


def test_ids_scenarios_uniques():
    ids = [s.id for s in SCENARIOS]
    assert len(ids) == len(set(ids))


def test_scenarios_non_vides():
    for s in SCENARIOS:
        assert len(s.attaque_ids) >= 2, f"{s.id} doit enchaîner au moins 2 phases"


def test_attaques_ordonnees_preserve_ordre():
    scenario = obtenir_scenario("RANSOMWARE")
    assert scenario is not None
    attaques = attaques_ordonnees(scenario)
    assert [a.id for a in attaques] == scenario.attaque_ids


def test_obtenir_scenario_insensible_casse():
    assert obtenir_scenario("ransomware") is not None
    assert obtenir_scenario("RANSOMWARE") is not None
    assert obtenir_scenario("  ransomware  ") is not None


def test_obtenir_scenario_inconnu():
    assert obtenir_scenario("NEXISTE_PAS") is None


# ---------------------------------------------------------------------------
# Analyse de kill chain
# ---------------------------------------------------------------------------
def _scenario_factice() -> ScenarioAdversaire:
    scenario = obtenir_scenario("RECONNAISSANCE")
    assert scenario is not None
    return scenario


def test_analyser_kill_chain_couverture_totale():
    scenario = _scenario_factice()
    resultats = [{"id": aid, "statut": "VALIDE"} for aid in scenario.attaque_ids]
    analyse = analyser_kill_chain(scenario, resultats)
    assert analyse["total_etapes"] == len(scenario.attaque_ids)
    assert analyse["etapes_detectees"] == len(scenario.attaque_ids)
    assert analyse["etapes_angle_mort"] == 0
    assert analyse["couverture_pct"] == 100.0
    assert all(e["detectee"] for e in analyse["etapes"])


def test_analyser_kill_chain_angle_mort():
    scenario = _scenario_factice()
    resultats = [{"id": scenario.attaque_ids[0], "statut": "VALIDE"}]
    resultats += [{"id": aid, "statut": "ANGLE_MORT"} for aid in scenario.attaque_ids[1:]]
    analyse = analyser_kill_chain(scenario, resultats)
    assert analyse["etapes_detectees"] == 1
    assert analyse["etapes_angle_mort"] == len(scenario.attaque_ids) - 1
    assert 0 < analyse["couverture_pct"] < 100


def test_analyser_kill_chain_preserve_ordre_des_phases():
    scenario = _scenario_factice()
    analyse = analyser_kill_chain(scenario, [])
    positions = [e["position"] for e in analyse["etapes"]]
    ids = [e["id"] for e in analyse["etapes"]]
    assert positions == list(range(1, len(scenario.attaque_ids) + 1))
    assert ids == scenario.attaque_ids


def test_statut_simule_compte_comme_detecte():
    assert "SIMULE" in STATUTS_DETECTES
    assert "VALIDE" in STATUTS_DETECTES
    assert "ANGLE_MORT" not in STATUTS_DETECTES


def test_analyser_kill_chain_simule_ne_compte_jamais_comme_detecte():
    """Régression sécurité (audit) : couverture kill chain surestimée --
    `analyser_kill_chain` utilisait STATUTS_DETECTES (qui inclut SIMULE),
    donc un scénario entièrement joué en `--simulate` (aucune attaque
    exécutée, aucune mesure TP/FP réelle -- seule la syntaxe Sigma a été
    validée) affichait 100% de couverture et « chaque phase déclenche une
    détection VALIDÉE ». STATUTS_DETECTES_KILL_CHAIN exclut SIMULE
    spécifiquement pour ce rapport, qui affirme une preuve réelle."""
    assert "SIMULE" not in STATUTS_DETECTES_KILL_CHAIN
    assert "VALIDE" in STATUTS_DETECTES_KILL_CHAIN
    assert "EN_ATTENTE_REVUE" in STATUTS_DETECTES_KILL_CHAIN

    scenario = _scenario_factice()
    resultats = [{"id": aid, "statut": "SIMULE"} for aid in scenario.attaque_ids]
    analyse = analyser_kill_chain(scenario, resultats, mode_simulation=True)
    assert analyse["etapes_detectees"] == 0
    assert analyse["couverture_pct"] == 0.0
    assert not any(e["detectee"] for e in analyse["etapes"])


def test_analyser_kill_chain_transmet_mode_simulation():
    scenario = _scenario_factice()
    analyse = analyser_kill_chain(scenario, [], mode_simulation=True)
    assert analyse["mode_simulation"] is True
    analyse_reelle = analyser_kill_chain(scenario, [])
    assert analyse_reelle["mode_simulation"] is False


def test_statut_en_attente_revue_compte_comme_detecte():
    """Régression (audit) : une étape validée TP/FP mais dont le déploiement
    est différé pour revue humaine (`cadre cycle --revue`) est une détection
    prouvée -- elle ne doit pas se lire comme une phase non couverte de la
    kill chain."""
    assert "EN_ATTENTE_REVUE" in STATUTS_DETECTES


# ---------------------------------------------------------------------------
# Rapport HTML kill chain
# ---------------------------------------------------------------------------
def test_rapport_kill_chain_autonome(tmp_path):
    from cadre.rapport import generer_rapport_kill_chain

    scenario = _scenario_factice()
    resultats = [{"id": aid, "statut": "VALIDE"} for aid in scenario.attaque_ids]
    analyse = analyser_kill_chain(scenario, resultats)
    fichier = tmp_path / "kc.html"
    generer_rapport_kill_chain(scenario, analyse, fichier)

    html = fichier.read_text(encoding="utf-8")
    assert "<!doctype html>" in html
    # Autonome : aucune ressource réseau externe.
    assert "http://" not in html.replace("http://www.w3", "")  # (namespaces SVG tolérés)
    assert 'src="http' not in html
    assert "<link" not in html
    # Contient bien chaque phase de la chaîne.
    for aid in scenario.attaque_ids:
        assert aid in html


def test_rapport_kill_chain_signale_le_mode_simulation(tmp_path):
    """Régression (audit) : sans indication claire, un run --simulate (0%
    de couverture par construction, voir test_analyser_kill_chain_simule_
    ne_compte_jamais_comme_detecte) se lirait comme un échec de détection
    réel plutôt qu'une simple absence de mesure dans ce mode."""
    from cadre.rapport import generer_rapport_kill_chain

    scenario = _scenario_factice()
    resultats = [{"id": aid, "statut": "SIMULE"} for aid in scenario.attaque_ids]
    analyse = analyser_kill_chain(scenario, resultats, mode_simulation=True)
    fichier = tmp_path / "kc.html"
    generer_rapport_kill_chain(scenario, analyse, fichier)

    html = fichier.read_text(encoding="utf-8")
    assert "--simulate" in html
    assert "aucune mesure" in html.lower() or "aucune attaque" in html.lower()


def test_rapport_kill_chain_reel_sans_bandeau_simulation(tmp_path):
    from cadre.rapport import generer_rapport_kill_chain

    scenario = _scenario_factice()
    resultats = [{"id": aid, "statut": "VALIDE"} for aid in scenario.attaque_ids]
    analyse = analyser_kill_chain(scenario, resultats)
    fichier = tmp_path / "kc.html"
    generer_rapport_kill_chain(scenario, analyse, fichier)

    html = fichier.read_text(encoding="utf-8")
    assert "Rapport de simulation" not in html


# ---------------------------------------------------------------------------
# CLI : cadre scenario
# ---------------------------------------------------------------------------
def test_cli_scenario_list():
    runner = CliRunner()
    resultat = runner.invoke(cli, ["scenario", "--list"])
    assert resultat.exit_code == 0
    assert "RANSOMWARE" in resultat.output


def test_cli_scenario_sans_argument_liste():
    runner = CliRunner()
    resultat = runner.invoke(cli, ["scenario"])
    assert resultat.exit_code == 0
    assert "RANSOMWARE" in resultat.output


def test_cli_scenario_inconnu():
    runner = CliRunner()
    resultat = runner.invoke(cli, ["scenario", "--id", "NEXISTE_PAS"])
    assert resultat.exit_code == 1


def test_cli_scenario_simulation(tmp_path):
    """`--output` ne redirige QUE `repertoire_rapports` (voir `cli.py::scenario`,
    `OrchestrateurCADRE(config={"repertoire_rapports": ...})`, sans
    `repertoire_regles`) -- `isolated_filesystem()` est donc nécessaire pour
    que `Path("./rules_generees")` (défaut relatif au CWD) ne pointe pas vers
    le vrai dossier du dépôt. Sans ça, une simulation "test" écrit pour de
    vrai dans rules_generees/ à chaque run (trouvé par bissection, même
    cause que le correctif apporté à test_atomic_red_team.py)."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        resultat = runner.invoke(
            cli,
            ["scenario", "--id", "RECONNAISSANCE", "--simulate", "--output", str(tmp_path)],
        )
    assert resultat.exit_code == 0, resultat.output
    assert "Couverture de la chaîne" in resultat.output
    # Le rapport kill chain dédié doit avoir été écrit.
    assert list(tmp_path.glob("scenario_RECONNAISSANCE_*.html"))
