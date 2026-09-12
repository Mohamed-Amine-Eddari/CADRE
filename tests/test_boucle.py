"""
Tests pour la boucle automatisée et le mode simulation.
"""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cadre.boucle import BoucleAutomatisee
from cadre.catalogue_attaques import obtenir_attaque, statistiques_catalogue
from cadre.orchestrateur import OrchestrateurCADRE, VerrouCycleActifError


class TestStatistiquesCatalogue:
    """Tests que le catalogue étendu fonctionne."""

    def test_catalogue_a_au_moins_25_attaques(self):
        """Le catalogue étendu doit contenir ≥25 attaques (12 v1.0 + 11 v1.1 + 3 Linux)."""
        stats = statistiques_catalogue()
        assert stats["total"] >= 25, f"Seulement {stats['total']} attaques"

    def test_couverture_tactiques(self):
        """Le catalogue doit couvrir ≥8 tactiques."""
        stats = statistiques_catalogue()
        assert stats["tactiques_uniques"] >= 8

    def test_attaques_linux_presentes(self):
        """Les 3 attaques Linux doivent être dans le catalogue."""
        linux_ids = ["CADRE-LIN-001", "CADRE-LIN-002", "CADRE-LIN-003"]
        for id_attaque in linux_ids:
            a = obtenir_attaque(id_attaque)
            assert a is not None, f"Attaque {id_attaque} manquante"
            assert a.plateforme.value == "linux"


class TestModeSimulation:
    """Tests du mode simulation."""

    def test_simulation_genere_regle(self, tmp_path, monkeypatch):
        """Le mode simulation doit générer une règle Sigma sans toucher la VM."""
        from cadre.catalogue_attaques import obtenir_attaque
        from cadre.orchestrateur import OrchestrateurCADRE

        monkeypatch.chdir(tmp_path)
        config = {
            "repertoire_rapports": tmp_path / "rapports",
            "repertoire_regles": tmp_path / "regles",
        }
        orch = OrchestrateurCADRE(config=config)

        a = obtenir_attaque("CADRE-DIS-001")
        resultat = orch._executer_attaque_simulation(a)

        assert resultat["statut"] == "SIMULE"
        assert "regle_sigma_yaml" in resultat
        assert "requete_lucene" in resultat

        # La règle doit être sauvegardée
        regle_path = tmp_path / "regles" / f"{a.id}.yml"
        assert regle_path.exists()


class TestBoucleAutomatisee:
    """Tests de la boucle automatisée."""

    def test_initialisation(self, tmp_path):
        boucle = BoucleAutomatisee(
            intervalle_sec=60,
            rapport_cumulatif=tmp_path / "stats.json",
        )
        assert boucle.intervalle_sec == 60
        assert boucle._cycles_executes == 0
        assert boucle._arret_demande is False

    def test_selection_rotation(self, tmp_path):
        """La rotation doit sélectionner un sous-ensemble d'attaques."""
        boucle = BoucleAutomatisee(
            intervalle_sec=60,
            rapport_cumulatif=tmp_path / "stats.json",
            techniques_par_cycle=4,
        )
        boucle._cycles_executes = 0
        sel1 = boucle._selectionner_techniques_rotation()
        assert len(sel1) == 4

        boucle._cycles_executes = 1
        sel2 = boucle._selectionner_techniques_rotation()
        assert len(sel2) == 4
        # Les sélections doivent être différentes (rotation)
        assert [a.id for a in sel1] != [a.id for a in sel2]

    def test_stats_cumulatives_sauvegardees(self, tmp_path):
        """Les stats cumulatives doivent être persistées sur disque."""
        cumulatif = tmp_path / "stats.json"
        boucle = BoucleAutomatisee(
            intervalle_sec=60,
            rapport_cumulatif=cumulatif,
        )
        resultats = [
            {"technique_mitre": "T1059.001", "statut": "VALIDE"},
            {"technique_mitre": "T1059.001", "statut": "VALIDE"},
            {"technique_mitre": "T1136.001", "statut": "REJETE"},
        ]
        # Stats calculées via la vraie méthode (pas un dict à la main) : le
        # contrat exact des clés attendues par _mettre_a_jour_cumulatif vit
        # dans _calculer_stats_cycle, pas dans ce test -- éviter qu'un futur
        # champ ajouté à l'une nécessite aussi une mise à jour manuelle ici.
        boucle._mettre_a_jour_cumulatif(resultats, boucle._calculer_stats_cycle(resultats))

        assert cumulatif.exists()
        data = json.loads(cumulatif.read_text(encoding="utf-8"))
        assert data["total_cycles"] == 1
        assert data["validees"] == 2
        assert data["rejetees"] == 1
        assert "T1059.001" in data["par_technique"]
        assert data["par_technique"]["T1059.001"]["validees"] == 2

    def test_stats_cumulatives_comptent_tous_les_statuts_reels(self, tmp_path):
        """Régression : NON_APPLICABLE (cible non configurée) et
        VALIDE_NON_DEPLOYE (validation TP/FP réussie, échec du déploiement
        Kibana) sont des statuts RÉELS renvoyés par executer_attaque_complete,
        omis avant ce correctif -- total_attaques ne se réconciliait plus
        avec la somme des catégories comptées."""
        cumulatif = tmp_path / "stats.json"
        boucle = BoucleAutomatisee(intervalle_sec=60, rapport_cumulatif=cumulatif)
        resultats = [
            {"technique_mitre": "T1059.001", "statut": "VALIDE"},
            {"technique_mitre": "T1059.001", "statut": "VALIDE_NON_DEPLOYE"},
            {"technique_mitre": "T1136.001", "statut": "NON_APPLICABLE"},
            {"technique_mitre": "T1136.001", "statut": "REJETE"},
            {"technique_mitre": "T1136.001", "statut": "ANGLE_MORT"},
            {"technique_mitre": "T1136.001", "statut": "ERREUR"},
        ]
        stats = boucle._calculer_stats_cycle(resultats)
        boucle._mettre_a_jour_cumulatif(resultats, stats)

        data = json.loads(cumulatif.read_text(encoding="utf-8"))
        somme_categories = (
            data["validees"]
            + data["validees_non_deployees"]
            + data["rejetees"]
            + data["angles_morts"]
            + data["non_applicables"]
            + data["erreurs"]
        )
        assert somme_categories == data["total_attaques"] == len(resultats)
        assert data["validees_non_deployees"] == 1
        assert data["non_applicables"] == 1

    def test_ecriture_cumulatif_echouee_ne_leve_pas(self, tmp_path, monkeypatch):
        """Régression sécurité (audit) : « daemon meurt sur erreur
        d'écriture » -- une erreur disque (disque plein, antivirus qui
        verrouille le fichier, lecteur réseau déconnecté...) en écrivant le
        cumulatif ne doit jamais remonter non rattrapée : les VRAIS rapports
        du cycle sont déjà écrits à ce stade, seul ce fichier de stats
        secondaire serait perdu -- pas une raison de tuer le daemon entier
        (potentiellement des jours de cycles programmés)."""
        boucle = BoucleAutomatisee(intervalle_sec=60, rapport_cumulatif=tmp_path / "stats.json")
        resultats = [{"technique_mitre": "T1059.001", "statut": "VALIDE"}]

        def write_text_qui_echoue(*a, **k):
            raise OSError("disque plein")

        monkeypatch.setattr(Path, "write_text", write_text_qui_echoue)
        erreurs = []
        monkeypatch.setattr(boucle.log, "error", lambda msg, **k: erreurs.append(msg))

        # Ne doit PAS lever -- c'est exactement ce que ce test prouve.
        boucle._mettre_a_jour_cumulatif(resultats, boucle._calculer_stats_cycle(resultats))

        assert erreurs  # échec journalisé, pas silencieux
        assert "disque plein" in erreurs[0]

    def test_arret_propre(self, tmp_path):
        """L'arrêt doit se faire après le cycle en cours."""
        boucle = BoucleAutomatisee(
            intervalle_sec=1,
            rapport_cumulatif=tmp_path / "stats.json",
        )

        # Demander arrêt
        boucle.demander_arret()
        # L'indicateur d'arrêt doit être activé
        assert boucle._arret_demande is True


class TestHandlerSignal:
    def test_handler_sigint_demande_arret(self, tmp_path):
        boucle = BoucleAutomatisee(intervalle_sec=60, rapport_cumulatif=tmp_path / "stats.json")
        assert boucle._arret_demande is False
        boucle._handler_sigint(None, None)
        assert boucle._arret_demande is True


class TestRotationDesactivee:
    def test_rotation_desactivee_retourne_tout_le_catalogue(self, tmp_path):
        from cadre.catalogue_attaques import CATALOGUE

        boucle = BoucleAutomatisee(
            intervalle_sec=60,
            rapport_cumulatif=tmp_path / "stats.json",
            rotation_techniques=False,
        )
        selection = boucle._selectionner_techniques_rotation()
        assert len(selection) == len(CATALOGUE)

    def test_rotation_inclut_les_attaques_perso(self, tmp_path):
        """Régression (audit) : `_selectionner_techniques_rotation()`
        utilisait le CATALOGUE natif figé, jamais `catalogue_actif()` --
        `cadre cycle` teste bien les attaques perso (executer_cycle_complet
        utilise déjà catalogue_actif()), mais le daemon (`cadre daemon`/
        `cadre loop`) ne les rotait jamais, silencieusement."""
        from cadre.catalogue_attaques import CATALOGUE
        from cadre.catalogue_utilisateur import enregistrer_attaque_utilisateur

        enregistrer_attaque_utilisateur(
            {
                "id": "CADRE-PERSO-ROTATION",
                "nom": "Test perso rotation",
                "technique_mitre": "T1059.001",
                "tactique_mitre": "Execution",
                "commande": "whoami",
            }
        )
        boucle = BoucleAutomatisee(
            intervalle_sec=60,
            rapport_cumulatif=tmp_path / "stats.json",
            rotation_techniques=False,
        )
        selection = boucle._selectionner_techniques_rotation()
        assert len(selection) == len(CATALOGUE) + 1
        assert any(a.id == "CADRE-PERSO-ROTATION" for a in selection)


class TestNotificationWebhook:
    def test_sans_webhook_configure(self, tmp_path):
        boucle = BoucleAutomatisee(intervalle_sec=60, rapport_cumulatif=tmp_path / "stats.json")
        assert boucle._notifier_webhook("msg", {"erreurs": 0}) is False

    def test_webhook_succes(self, tmp_path, monkeypatch):
        boucle = BoucleAutomatisee(
            intervalle_sec=60,
            rapport_cumulatif=tmp_path / "stats.json",
            webhooks=["https://hooks.example.com/x"],
        )

        class ReponseFactice:
            status_code = 200

        monkeypatch.setattr("requests.post", lambda *a, **k: ReponseFactice())
        stats = {"validees": 1, "rejetees": 0, "angles_morts": 0, "erreurs": 0}
        assert boucle._notifier_webhook("msg", stats) is True

    def test_webhook_http_echec(self, tmp_path, monkeypatch):
        boucle = BoucleAutomatisee(
            intervalle_sec=60,
            rapport_cumulatif=tmp_path / "stats.json",
            webhooks=["https://hooks.example.com/x"],
        )

        class ReponseFactice:
            status_code = 500

        monkeypatch.setattr("requests.post", lambda *a, **k: ReponseFactice())
        stats = {"validees": 0, "rejetees": 0, "angles_morts": 0, "erreurs": 1}
        assert boucle._notifier_webhook("msg", stats) is False

    def test_webhook_exception_reseau(self, tmp_path, monkeypatch):
        boucle = BoucleAutomatisee(
            intervalle_sec=60,
            rapport_cumulatif=tmp_path / "stats.json",
            webhooks=["https://hooks.example.com/x"],
        )

        def post_qui_echoue(*a, **k):
            raise ConnectionError("timeout")

        monkeypatch.setattr("requests.post", post_qui_echoue)
        stats = {"validees": 0, "rejetees": 0, "angles_morts": 0, "erreurs": 1}
        assert boucle._notifier_webhook("msg", stats) is False


class TestNotificationEmail:
    def test_sans_destinataire(self, tmp_path):
        boucle = BoucleAutomatisee(intervalle_sec=60, rapport_cumulatif=tmp_path / "stats.json")
        assert boucle._notifier_email("sujet", "msg") is False

    def test_email_succes(self, tmp_path, monkeypatch):
        boucle = BoucleAutomatisee(
            intervalle_sec=60,
            rapport_cumulatif=tmp_path / "stats.json",
            email_dest="soc@example.com",
            email_smtp={"host": "smtp.example.com", "port": 587},
        )

        class ServeurFactice:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def starttls(self):
                pass

            def send_message(self, msg):
                pass

        monkeypatch.setattr("smtplib.SMTP", lambda host, port: ServeurFactice())
        assert boucle._notifier_email("sujet", "msg") is True

    def test_email_avec_authentification(self, tmp_path, monkeypatch):
        appels = {}
        boucle = BoucleAutomatisee(
            intervalle_sec=60,
            rapport_cumulatif=tmp_path / "stats.json",
            email_dest="soc@example.com",
            email_smtp={
                "host": "smtp.example.com",
                "port": 587,
                "user": "bot",
                "password": "secret",  # pragma: allowlist secret
            },
        )

        class ServeurFactice:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def starttls(self):
                pass

            def login(self, user, password):
                appels["login"] = (user, password)

            def send_message(self, msg):
                pass

        monkeypatch.setattr("smtplib.SMTP", lambda host, port: ServeurFactice())
        assert boucle._notifier_email("sujet", "msg") is True
        assert appels["login"] == ("bot", "secret")

    def test_email_exception(self, tmp_path, monkeypatch):
        boucle = BoucleAutomatisee(
            intervalle_sec=60,
            rapport_cumulatif=tmp_path / "stats.json",
            email_dest="soc@example.com",
            email_smtp={"host": "smtp.example.com"},
        )
        monkeypatch.setattr(
            "smtplib.SMTP", lambda *a, **k: (_ for _ in ()).throw(OSError("refused"))
        )
        assert boucle._notifier_email("sujet", "msg") is False


class TestExecuterUnCycle:
    def test_cycle_complet_avec_notifications(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        boucle = BoucleAutomatisee(
            intervalle_sec=60,
            rapport_cumulatif=tmp_path / "stats.json",
            techniques_par_cycle=2,
            webhooks=["https://hooks.example.com/x"],
        )
        monkeypatch.setattr("cadre.boucle.time.sleep", lambda *_: None)

        resultat_attaque = {
            "id": "CADRE-TEST-001",
            "technique_mitre": "T1059.001",
            "statut": "VALIDE",
        }
        monkeypatch.setattr(
            boucle.orchestrateur, "executer_attaque_complete", lambda a: resultat_attaque
        )
        monkeypatch.setattr(boucle.orchestrateur, "_generer_rapports_fin_cycle", lambda: None)

        class ReponseFactice:
            status_code = 200

        monkeypatch.setattr("requests.post", lambda *a, **k: ReponseFactice())

        resultats = boucle.executer_un_cycle()
        assert len(resultats) == 2
        assert all(r["statut"] == "VALIDE" for r in resultats)
        assert tmp_path.joinpath("stats.json").exists()

    def test_techniques_par_cycle_zero_ne_reutilise_pas_le_cycle_precedent(
        self, tmp_path, monkeypatch
    ):
        """Régression : self.orchestrateur.resultats n'était réassigné qu'à
        L'INTÉRIEUR de la boucle sur les attaques -- avec 0 attaque
        sélectionnée, la boucle ne s'exécute jamais et l'attribut gardait
        silencieusement les résultats du cycle PRÉCÉDENT, que
        _generer_rapports_fin_cycle() dupliquait alors sous un nouvel
        horodatage pour un cycle qui n'a rien exécuté."""
        monkeypatch.chdir(tmp_path)
        boucle = BoucleAutomatisee(
            intervalle_sec=60,
            rapport_cumulatif=tmp_path / "stats.json",
            techniques_par_cycle=1,
        )
        monkeypatch.setattr("cadre.boucle.time.sleep", lambda *_: None)
        monkeypatch.setattr(
            boucle.orchestrateur,
            "executer_attaque_complete",
            lambda a: {"id": a.id, "technique_mitre": a.technique_mitre, "statut": "VALIDE"},
        )
        monkeypatch.setattr(boucle.orchestrateur, "_generer_rapports_fin_cycle", lambda: None)

        # 1er cycle : une vraie attaque, résultats non vides.
        boucle.executer_un_cycle()
        assert boucle.orchestrateur.resultats != []

        # 2e cycle : 0 attaque sélectionnée -- resultats doit être
        # réinitialisé à [], pas garder ceux du 1er cycle.
        boucle.techniques_par_cycle = 0
        resultats = boucle.executer_un_cycle()
        assert resultats == []
        assert boucle.orchestrateur.resultats == []

    def test_exception_sur_une_attaque_est_capturee(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        boucle = BoucleAutomatisee(
            intervalle_sec=60,
            rapport_cumulatif=tmp_path / "stats.json",
            techniques_par_cycle=1,
        )
        monkeypatch.setattr("cadre.boucle.time.sleep", lambda *_: None)

        def executer_qui_explose(attaque):
            raise RuntimeError("panne VM")

        monkeypatch.setattr(boucle.orchestrateur, "executer_attaque_complete", executer_qui_explose)
        monkeypatch.setattr(boucle.orchestrateur, "_generer_rapports_fin_cycle", lambda: None)

        resultats = boucle.executer_un_cycle()
        assert resultats[0]["statut"] == "ERREUR"
        assert "panne VM" in resultats[0]["raison"]

    def test_arret_demande_interrompt_la_boucle_d_attaques(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        boucle = BoucleAutomatisee(
            intervalle_sec=60,
            rapport_cumulatif=tmp_path / "stats.json",
            techniques_par_cycle=4,
        )
        monkeypatch.setattr("cadre.boucle.time.sleep", lambda *_: None)
        monkeypatch.setattr(boucle.orchestrateur, "_generer_rapports_fin_cycle", lambda: None)

        appels = []

        def executer(attaque):
            appels.append(attaque.id)
            boucle._arret_demande = True
            return {
                "id": attaque.id,
                "technique_mitre": attaque.technique_mitre,
                "statut": "VALIDE",
            }

        monkeypatch.setattr(boucle.orchestrateur, "executer_attaque_complete", executer)
        resultats = boucle.executer_un_cycle()
        # Une seule attaque exécutée avant que l'arrêt ne coupe la boucle.
        assert len(appels) == 1
        assert len(resultats) == 1


class TestVerrouCycleInterProcessus:
    """F-009 : `executer_un_cycle()` (utilisée par `cadre loop`/`cadre
    daemon`) exécute toujours des attaques RÉELLES mais appelait
    `executer_attaque_complete()` directement, sans jamais passer par
    `executer_cycle_complet()` -- le verrou inter-processus qui évite qu'un
    `cadre cycle`/le dashboard ne tourne en même temps contre la même cible
    n'était donc jamais acquis par ces deux commandes.

    `_verrou_isole` : fixture globale autouse (conftest.py) -- plus besoin
    de la redéclarer ici."""

    def _boucle_factice(self, tmp_path, monkeypatch, statut="VALIDE"):
        monkeypatch.chdir(tmp_path)
        boucle = BoucleAutomatisee(
            intervalle_sec=60,
            rapport_cumulatif=tmp_path / "stats.json",
            techniques_par_cycle=1,
        )
        monkeypatch.setattr("cadre.boucle.time.sleep", lambda *_: None)
        monkeypatch.setattr(
            boucle.orchestrateur,
            "executer_attaque_complete",
            lambda a: {"id": a.id, "technique_mitre": a.technique_mitre, "statut": statut},
        )
        monkeypatch.setattr(boucle.orchestrateur, "_generer_rapports_fin_cycle", lambda: None)
        return boucle

    def test_cycle_acquiert_puis_libere_le_verrou(self, tmp_path, monkeypatch, _verrou_isole):
        boucle = self._boucle_factice(tmp_path, monkeypatch)
        boucle.executer_un_cycle()
        assert not _verrou_isole.exists()  # libéré à la fin, jamais laissé traîner

    def test_cycle_refuse_si_deja_verrouille_par_un_autre_processus(
        self, tmp_path, monkeypatch, _verrou_isole
    ):
        boucle = self._boucle_factice(tmp_path, monkeypatch)
        _verrou_isole.write_text(str(os.getpid()), encoding="utf-8")  # notre PID = vivant, garanti

        with pytest.raises(RuntimeError, match="déjà en cours"):
            boucle.executer_un_cycle()
        # Le verrou pré-existant (pas le nôtre) reste en place.
        assert _verrou_isole.exists()

    def test_verrou_libere_meme_si_une_attaque_leve(self, tmp_path, monkeypatch, _verrou_isole):
        boucle = self._boucle_factice(tmp_path, monkeypatch)

        def executer_qui_explose(attaque):
            raise RuntimeError("panne VM")

        monkeypatch.setattr(boucle.orchestrateur, "executer_attaque_complete", executer_qui_explose)
        boucle.executer_un_cycle()  # l'exception d'une attaque est capturée, pas propagée
        assert not _verrou_isole.exists()


class TestDemarrer:
    def test_s_arrete_a_max_cycles(self, tmp_path, monkeypatch):
        boucle = BoucleAutomatisee(
            intervalle_sec=0,
            rapport_cumulatif=tmp_path / "stats.json",
        )
        appels = []
        monkeypatch.setattr(boucle, "executer_un_cycle", lambda: appels.append(1) or [])

        stats = boucle.demarrer(max_cycles=3)
        assert len(appels) == 3
        assert stats is boucle._statistiques_cumulatives

    def test_arret_demande_avant_le_prochain_cycle(self, tmp_path, monkeypatch):
        boucle = BoucleAutomatisee(
            intervalle_sec=0,
            rapport_cumulatif=tmp_path / "stats.json",
        )

        def cycle_qui_demande_arret():
            boucle._arret_demande = True
            return []

        monkeypatch.setattr(boucle, "executer_un_cycle", cycle_qui_demande_arret)
        stats = boucle.demarrer(max_cycles=None)
        assert boucle._cycles_executes == 1
        assert stats is boucle._statistiques_cumulatives

    def test_max_cycles_zero_narrete_aucun_cycle(self, tmp_path, monkeypatch):
        """Régression : `if max_cycles` traitait 0 comme "illimité" (falsy
        en Python) -- `--max-cycles 0` tournait donc indéfiniment au lieu
        de ne lancer aucun cycle."""
        boucle = BoucleAutomatisee(intervalle_sec=0, rapport_cumulatif=tmp_path / "stats.json")
        appels = []
        monkeypatch.setattr(boucle, "executer_un_cycle", lambda: appels.append(1) or [])

        boucle.demarrer(max_cycles=0)
        assert appels == []
        assert boucle._cycles_executes == 0

    def test_premier_cycle_reel_numerote_1_pas_2(self, tmp_path, monkeypatch):
        """Régression : `_cycles_executes` était incrémenté AVANT
        executer_un_cycle() dans demarrer(), qui calcule lui-même son
        numéro affiché en ajoutant +1 -- le tout premier cycle réel
        s'affichait "Cycle 2"."""
        boucle = BoucleAutomatisee(intervalle_sec=0, rapport_cumulatif=tmp_path / "stats.json")
        monkeypatch.setattr("cadre.boucle.time.sleep", lambda *_: None)
        monkeypatch.setattr(boucle.orchestrateur, "_generer_rapports_fin_cycle", lambda: None)
        monkeypatch.setattr(
            boucle.orchestrateur,
            "executer_attaque_complete",
            lambda a: {"id": a.id, "technique_mitre": a.technique_mitre, "statut": "VALIDE"},
        )

        messages = []
        monkeypatch.setattr(boucle.log, "info", lambda msg, **k: messages.append(msg))
        boucle.demarrer(max_cycles=1)
        assert any("[Cycle 1]" in m for m in messages)
        assert not any("[Cycle 2]" in m for m in messages)

    def test_rotation_demarre_a_decalage_zero_au_premier_cycle(self, tmp_path, monkeypatch):
        """Régression liée : le décalage de rotation utilisait aussi
        `_cycles_executes` déjà incrémenté -- le 1er cycle réel sautait
        directement le 1er lot d'attaques du catalogue."""
        boucle = BoucleAutomatisee(
            intervalle_sec=0,
            rapport_cumulatif=tmp_path / "stats.json",
            techniques_par_cycle=4,
        )
        monkeypatch.setattr("cadre.boucle.time.sleep", lambda *_: None)
        monkeypatch.setattr(boucle.orchestrateur, "_generer_rapports_fin_cycle", lambda: None)
        monkeypatch.setattr(
            boucle.orchestrateur,
            "executer_attaque_complete",
            lambda a: {"id": a.id, "technique_mitre": a.technique_mitre, "statut": "VALIDE"},
        )

        selection_attendue = [a.id for a in boucle._selectionner_techniques_rotation()]
        appels = []
        original = boucle.orchestrateur.executer_attaque_complete
        monkeypatch.setattr(
            boucle.orchestrateur,
            "executer_attaque_complete",
            lambda a: appels.append(a.id) or original(a),
        )
        boucle.demarrer(max_cycles=1)
        assert appels == selection_attendue


class TestDemarrerResilienceVerrou:
    """Régression F-009 : une collision de verrou inter-processus (voir
    TestVerrouCycleInterProcessus plus haut) lève VerrouCycleActifError
    DEPUIS executer_un_cycle(). Avant ce correctif, demarrer() n'avait
    aucun try/except autour de cet appel : une seule collision transitoire
    tuait définitivement le daemon/la boucle au lieu de simplement reporter
    ce cycle au prochain intervalle."""

    def test_collision_de_verrou_ne_tue_pas_la_boucle(self, tmp_path, monkeypatch):
        boucle = BoucleAutomatisee(intervalle_sec=0, rapport_cumulatif=tmp_path / "stats.json")
        appels = []

        def cycle_qui_collisionne_une_fois():
            appels.append(1)
            if len(appels) == 1:
                raise VerrouCycleActifError("cycle déjà en cours (verrou tenu par PID 4242)")
            return []

        monkeypatch.setattr(boucle, "executer_un_cycle", cycle_qui_collisionne_une_fois)
        stats = boucle.demarrer(max_cycles=2)
        assert len(appels) == 3  # 1 collision absorbée + 2 cycles réels
        assert boucle._cycles_executes == 2  # le cycle en collision NE compte PAS
        assert stats is boucle._statistiques_cumulatives

    def test_collision_de_verrou_journalisee_en_avertissement(self, tmp_path, monkeypatch):
        boucle = BoucleAutomatisee(intervalle_sec=0, rapport_cumulatif=tmp_path / "stats.json")

        def cycle_qui_collisionne():
            boucle._arret_demande = True  # un seul essai suffit pour ce test
            raise VerrouCycleActifError("cycle déjà en cours")

        monkeypatch.setattr(boucle, "executer_un_cycle", cycle_qui_collisionne)
        avertissements = []
        monkeypatch.setattr(boucle.log, "warn", lambda msg, **k: avertissements.append(msg))
        boucle.demarrer(max_cycles=None)
        assert avertissements  # avertissement journalisé, pas un crash silencieux
        assert "verrou" in avertissements[0].lower()

    def test_autre_exception_nest_pas_avalee(self, tmp_path, monkeypatch):
        """Seules les collisions de verrou (VerrouCycleActifError) sont
        absorbées -- toute autre erreur inattendue doit continuer à
        interrompre la boucle (pas de except Exception large qui
        masquerait un vrai bug)."""
        boucle = BoucleAutomatisee(intervalle_sec=0, rapport_cumulatif=tmp_path / "stats.json")

        def cycle_qui_explose():
            raise ValueError("bug réel, pas une collision de verrou")

        monkeypatch.setattr(boucle, "executer_un_cycle", cycle_qui_explose)
        with pytest.raises(ValueError, match="bug réel"):
            boucle.demarrer(max_cycles=1)

    def test_runtime_error_generique_nest_pas_avale(self, tmp_path, monkeypatch):
        """Régression de précision : le catch cible VerrouCycleActifError
        (sous-classe dédiée), PAS RuntimeError au sens large -- un
        RuntimeError générique venant d'ailleurs (bug réel, pas F-009) ne
        doit jamais être confondu avec une collision de verrou ni absorbé
        silencieusement."""
        boucle = BoucleAutomatisee(intervalle_sec=0, rapport_cumulatif=tmp_path / "stats.json")

        def cycle_qui_explose():
            raise RuntimeError("bug interne sans rapport avec le verrou F-009")

        monkeypatch.setattr(boucle, "executer_un_cycle", cycle_qui_explose)
        with pytest.raises(RuntimeError, match="bug interne"):
            boucle.demarrer(max_cycles=1)


class TestConnectivite:
    """Tests de la vérification de connectivité réseau."""

    def test_connectivite_echec_si_ip_vide(self):
        orch = OrchestrateurCADRE(config={"vm_ip": ""})
        assert orch._verifier_connectivite_vm() is False

    @patch("socket.socket")
    def test_connectivite_echec_si_timeout(self, mock_socket):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1  # Erreur
        mock_sock.__enter__.return_value = mock_sock  # voir test_connectivite_ok
        mock_socket.return_value = mock_sock
        orch = OrchestrateurCADRE(config={"vm_ip": "192.168.1.1"})
        assert orch._verifier_connectivite_vm() is False

    @patch("socket.socket")
    def test_connectivite_ok(self, mock_socket):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0  # OK
        # `with socket.socket(...) as sock:` (U3/V1) : __enter__ doit
        # renvoyer le MÊME mock, sinon `sock` référence un enfant auto-généré
        # dont connect_ex() n'est pas configuré.
        mock_sock.__enter__.return_value = mock_sock
        mock_socket.return_value = mock_sock
        orch = OrchestrateurCADRE(config={"vm_ip": "192.168.1.1"})
        assert orch._verifier_connectivite_vm() is True
