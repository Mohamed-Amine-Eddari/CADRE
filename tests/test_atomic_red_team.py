"""
Tests pour l'ingestion Atomic Red Team (src/cadre/atomic_red_team.py) et la
commande `cadre atomic`. Vérifie le parsing du vrai schéma ART, le filtre de
sécurité (refus des atomics destructeurs), le routage de plateforme, et la
conversion vers le modèle CADRE.
"""

from __future__ import annotations

from click.testing import CliRunner

from cadre.atomic_red_team import (
    atomic_vers_brouillon,
    charger_atomics,
    deriver_valeur_detection,
    importer_atomics,
    interpoler_arguments,
    parser_fichier_atomic,
    repertoire_exemple,
    tactique_pour_technique,
)
from cadre.catalogue_attaques import Plateforme
from cadre.catalogue_utilisateur import brouillon_vers_attaque
from cadre.cli import cli


# ---------------------------------------------------------------------------
# Parsing du schéma Atomic Red Team
# ---------------------------------------------------------------------------
def test_charger_atomics_exemple_ignore_manual_et_macos():
    """5 atomics automatisables : le test `manual` et la variante macos sont exclus."""
    tests = charger_atomics(repertoire_exemple())
    noms = {t.nom for t in tests}
    assert len(tests) == 5
    assert "Manual PowerShell step (non-automatable)" not in noms
    assert "macOS system_profiler (hors cible CADRE)" not in noms


def test_interpoler_arguments():
    cmd = "echo #{marker}; run"
    args = {"marker": {"default": "CADRE_ART_X"}}
    assert interpoler_arguments(cmd, args) == "echo CADRE_ART_X; run"


def test_interpoler_arguments_sans_defaut_laisse_intact():
    assert interpoler_arguments("echo #{inconnu}", {}) == "echo #{inconnu}"


def test_deriver_valeur_detection_jeton_distinctif():
    assert deriver_valeur_detection("echo CADRE_ART_PROC_LINUX; ps -ef") == "CADRE_ART_PROC_LINUX"


def test_deriver_valeur_detection_rien_de_distinctif():
    # Que des mots banals / trop courts -> None (règle sur event.code seul).
    assert deriver_valeur_detection("ps -ef") is None


def test_tactique_derivee_du_catalogue():
    # T1082 est dans le catalogue natif comme Discovery.
    assert tactique_pour_technique("T1082") == "Discovery"
    # Technique totalement inconnue -> défaut Execution (jamais bloquant).
    assert tactique_pour_technique("T9999") == "Execution"


# ---------------------------------------------------------------------------
# Filtre de sécurité (garde-fou n°1, partagé avec l'agent IA)
# ---------------------------------------------------------------------------
def test_filtre_refuse_atomics_destructeurs():
    rapport = importer_atomics()
    refuses_tech = {r["technique"] for r in rapport["refuses"]}
    retenus_tech = {b["technique_mitre"] for b in rapport["retenus"]}
    # cipher /w (T1485) et wevtutil cl (T1070.001) doivent être REFUSÉS.
    assert "T1485" in refuses_tech
    assert "T1070.001" in refuses_tech
    # Les tests bénins doivent être retenus.
    assert "T1082" in retenus_tech
    assert len(rapport["retenus"]) == 3
    assert len(rapport["refuses"]) == 2


# ---------------------------------------------------------------------------
# Conversion vers le modèle CADRE
# ---------------------------------------------------------------------------
def test_brouillons_convertibles_en_attaque():
    rapport = importer_atomics()
    for brouillon in rapport["retenus"]:
        attaque = brouillon_vers_attaque(brouillon)  # ne doit pas lever
        assert attaque.id.startswith("CADRE-ART-")
        assert attaque.nom.startswith("[ART]")


def test_routage_plateforme_champ_detection():
    rapport = importer_atomics()
    par_id = {b["id"]: b for b in rapport["retenus"]}
    # Linux -> process.title ; Windows -> process.command_line.
    assert par_id["CADRE-ART-T1057-1"]["champ_principal"] == "process.title"
    assert par_id["CADRE-ART-T1082-1"]["champ_principal"] == "process.command_line"


def test_filtre_par_plateforme():
    rapport = importer_atomics(plateformes={Plateforme.LINUX})
    assert all(b["plateforme"] == "linux" for b in rapport["retenus"])
    assert len(rapport["retenus"]) == 1


def test_filtre_par_technique():
    rapport = importer_atomics(techniques={"T1082"})
    assert {b["technique_mitre"] for b in rapport["retenus"]} == {"T1082"}


def test_parser_fichier_inexistant_ne_leve_pas():
    assert parser_fichier_atomic(repertoire_exemple() / "nexiste_pas.yaml") == []


def test_atomic_vers_brouillon_id_stable():
    tests = charger_atomics(repertoire_exemple(), techniques={"T1082"})
    brouillon = atomic_vers_brouillon(tests[0], 1)
    assert brouillon["id"] == "CADRE-ART-T1082-1"


def test_regle_sigma_dun_atomic_compile(tmp_path):
    """Régression : un nom d'atomic (préfixe [ART], ':' possible) doit produire
    un `title:` YAML valide qui compile en Lucene — sinon la règle est
    structurellement cassée pour toute source arbitraire."""
    from cadre.compilation_sigma import compiler_sigma_vers_lucene
    from cadre.orchestrateur import OrchestrateurCADRE, _titre_sigma_yaml

    # Un nom hostile est double-quoté ; un nom natif reste en scalaire simple.
    assert _titre_sigma_yaml("[ART] X: y") == '"[ART] X: y"'
    assert _titre_sigma_yaml("PowerShell - Discovery (Get-Process)") == (
        "PowerShell - Discovery (Get-Process)"
    )

    rapport = importer_atomics(techniques={"T1082"})
    attaque = brouillon_vers_attaque(rapport["retenus"][0])
    # `_executer_attaque_simulation` écrit la règle sur disque (comportement
    # normal, pas un mock à ajouter) -- `repertoire_regles` DOIT pointer vers
    # tmp_path, sinon ce test écrit pour de vrai dans rules_generees/ à
    # chaque run (trouvé par bissection : cause du churn id/date récurrent
    # sur CADRE-ART-T1082-1.yml).
    orch = OrchestrateurCADRE(
        config={
            "vm_pass": "x",
            "elastic_pass": "x",
            "repertoire_regles": tmp_path / "regles",
        }
    )
    regle = orch._executer_attaque_simulation(attaque)["regle_sigma_yaml"]
    assert compiler_sigma_vers_lucene(regle), "la règle d'un atomic doit compiler"


# ---------------------------------------------------------------------------
# CLI : cadre atomic
# ---------------------------------------------------------------------------
def test_cli_atomic_apercu():
    runner = CliRunner()
    resultat = runner.invoke(cli, ["atomic"])
    assert resultat.exit_code == 0
    assert "CADRE-ART-" in resultat.output
    assert "refusé" in resultat.output  # les destructeurs sont signalés


def test_cli_atomic_repo_introuvable():
    runner = CliRunner()
    resultat = runner.invoke(cli, ["atomic", "--repo", "/chemin/inexistant/xyz"])
    assert resultat.exit_code == 1


def test_cli_atomic_import(tmp_path, monkeypatch):
    # isolation_environnement redirige déjà CHEMIN_CATALOGUE_PERSO vers tmp_path.
    runner = CliRunner()
    resultat = runner.invoke(cli, ["atomic", "--import"])
    assert resultat.exit_code == 0, resultat.output
    assert "Ajoutés au catalogue" in resultat.output
    # Les atomics importés apparaissent dans le catalogue actif.
    from cadre.catalogue_attaques import catalogue_actif

    ids = {a.id for a in catalogue_actif()}
    assert any(i.startswith("CADRE-ART-") for i in ids)
