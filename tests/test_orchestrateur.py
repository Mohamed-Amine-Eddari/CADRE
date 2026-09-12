"""
Tests pour l'orchestrateur (src/cadre/orchestrateur.py) — le cœur du pipeline
CADRE. WinRM, Elasticsearch et Kibana sont mockés : ce module ne doit jamais
toucher un vrai réseau ou une vraie VM pendant les tests.
"""

from __future__ import annotations

import dataclasses
import os
import threading
import time
from pathlib import Path

import pytest
import yaml

from cadre.coffre_fort import ErreurSecurite
from cadre.orchestrateur import (
    OrchestrateurCADRE,
    construire_sequence_eql,
    detecter_regles_similaires,
)
from cadre.scenarios import ScenarioAdversaire


class CoffreFactice:
    """Coffre-fort qui ne trouve jamais de secret (sauf valeur par défaut)."""

    def obtenir(self, cle, defaut=None):
        if defaut is not None:
            return defaut
        raise ErreurSecurite(f"{cle} manquant")


@pytest.fixture(autouse=True)
def coffre_factice(monkeypatch):
    monkeypatch.setattr("cadre.orchestrateur.obtenir_coffre", CoffreFactice)


@pytest.fixture(autouse=True)
def pas_de_vraie_attente(monkeypatch):
    """Empêche les backoff/sleep réels de ralentir les tests."""
    monkeypatch.setattr("cadre.orchestrateur.time.sleep", lambda *_: None)


@pytest.fixture
def orchestrateur(tmp_path):
    config = {
        "repertoire_rapports": tmp_path / "rapports",
        "repertoire_regles": tmp_path / "regles",
        "vm_ip": "127.0.0.1",
        "vm_user": "CadreUser",
        "vm_pass": "motdepasse",
        "elastic_url": "http://localhost:9200",
        "elastic_user": "elastic",
        "elastic_pass": "elasticpass",
        "kibana_url": "http://localhost:5601",
    }
    return OrchestrateurCADRE(config=config)


class TestInitialisation:
    def test_cree_les_repertoires(self, orchestrateur):
        assert orchestrateur.config["repertoire_rapports"].is_dir()
        assert orchestrateur.config["repertoire_regles"].is_dir()

    def test_secret_manquant_est_tolere(self, tmp_path, monkeypatch):
        """Un secret absent ne doit jamais faire planter l'orchestrateur."""

        class CoffreVide:
            def obtenir(self, cle, defaut=None):
                raise ErreurSecurite("introuvable")

        monkeypatch.setattr("cadre.orchestrateur.obtenir_coffre", CoffreVide)
        orch = OrchestrateurCADRE(
            config={
                "repertoire_rapports": tmp_path / "r",
                "repertoire_regles": tmp_path / "g",
            }
        )
        assert orch.config["vm_pass"] is None


class TestDurcissementWinRM:
    """WinRM configurable : défaut labo strictement inchangé, durcissement
    production (HTTPS/5986/Kerberos/validate) via variables d'environnement."""

    _CLES = (
        "CADRE_WINRM_SCHEME",
        "CADRE_WINRM_PORT",
        "CADRE_WINRM_TRANSPORT",
        "CADRE_WINRM_CERT_VALIDATION",
        "CADRE_VM_IP",
        "CADRE_ELASTIC_URL",
    )

    @pytest.fixture(autouse=True)
    def _env_propre(self, monkeypatch):
        # Aucune variable CADRE_* héritée de l'environnement ne doit fausser
        # les tests de défaut.
        for c in self._CLES:
            monkeypatch.delenv(c, raising=False)

    def _orch(self, tmp_path, **extra):
        return OrchestrateurCADRE(
            config={
                "repertoire_rapports": tmp_path / "r",
                "repertoire_regles": tmp_path / "g",
                **extra,
            }
        )

    def test_defaut_labo_inchange(self, tmp_path):
        o = self._orch(tmp_path)
        assert o.config["vm_winrm_scheme"] == "http"
        assert o.config["vm_winrm_port"] == 5985
        assert o.config["vm_winrm_transport"] == "ntlm"
        assert o.config["vm_winrm_cert_validation"] == "ignore"

    def test_surcharge_production_via_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CADRE_WINRM_SCHEME", "https")
        monkeypatch.setenv("CADRE_WINRM_PORT", "5986")
        monkeypatch.setenv("CADRE_WINRM_TRANSPORT", "kerberos")
        monkeypatch.setenv("CADRE_WINRM_CERT_VALIDATION", "validate")
        monkeypatch.setenv("CADRE_ELASTIC_URL", "https://siem.prod:9200")
        o = self._orch(tmp_path)
        assert o.config["vm_winrm_scheme"] == "https"
        assert o.config["vm_winrm_port"] == 5986
        assert isinstance(o.config["vm_winrm_port"], int)
        assert o.config["vm_winrm_transport"] == "kerberos"
        assert o.config["vm_winrm_cert_validation"] == "validate"
        # La lacune est corrigée : l'URL Elastic est bien lue depuis l'env.
        assert o.config["elastic_url"] == "https://siem.prod:9200"

    def test_config_passee_gagne_sur_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CADRE_WINRM_PORT", "5986")
        o = self._orch(tmp_path, vm_winrm_port=7000)
        assert o.config["vm_winrm_port"] == 7000

    def test_port_invalide_garde_le_defaut(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CADRE_WINRM_PORT", "pas_un_nombre")
        o = self._orch(tmp_path)
        assert o.config["vm_winrm_port"] == 5985  # défaut conservé, pas de crash

    def _capturer_session(self, orch, monkeypatch):
        captured: dict = {}

        class FakeResult:
            status_code = 0
            std_err = b""

        class FakeSession:
            def __init__(self, endpoint, **kw):
                captured["endpoint"] = endpoint
                captured.update(kw)

            def run_ps(self, _cmd):
                return FakeResult()

        monkeypatch.setattr("cadre.orchestrateur.winrm.Session", FakeSession)
        monkeypatch.setattr(orch, "_verifier_connectivite_vm", lambda: True)
        assert orch.executer_commande_winrm("echo test") is True
        return captured

    def test_endpoint_labo(self, tmp_path, monkeypatch):
        o = self._orch(tmp_path, vm_ip="127.0.0.1", vm_user="u", vm_pass="x")
        c = self._capturer_session(o, monkeypatch)
        assert c["endpoint"] == "http://127.0.0.1:5985/wsman"
        assert c["transport"] == "ntlm"
        assert c["server_cert_validation"] == "ignore"

    def test_endpoint_production(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CADRE_WINRM_SCHEME", "https")
        monkeypatch.setenv("CADRE_WINRM_PORT", "5986")
        monkeypatch.setenv("CADRE_WINRM_TRANSPORT", "kerberos")
        monkeypatch.setenv("CADRE_WINRM_CERT_VALIDATION", "validate")
        o = self._orch(tmp_path, vm_ip="10.0.0.50", vm_user="u", vm_pass="x")
        c = self._capturer_session(o, monkeypatch)
        assert c["endpoint"] == "https://10.0.0.50:5986/wsman"
        assert c["transport"] == "kerberos"
        assert c["server_cert_validation"] == "validate"


class TestAuthElastic:
    def test_auth_presente(self, orchestrateur):
        assert orchestrateur.auth_elastic == ("elastic", "elasticpass")

    def test_auth_absente_sans_mot_de_passe(self, orchestrateur):
        orchestrateur.config["elastic_pass"] = None
        assert orchestrateur.auth_elastic is None


class TestConnectiviteVM:
    def test_pas_d_ip_configuree(self, orchestrateur):
        orchestrateur.config["vm_ip"] = ""
        assert orchestrateur._verifier_connectivite_vm() is False

    def test_port_ferme(self, orchestrateur, monkeypatch):
        class SocketFactice:
            def settimeout(self, t):
                pass

            def connect_ex(self, addr):
                return 111  # connexion refusée

            def close(self):
                pass

            def __enter__(self):  # U3/V1 : `with socket.socket(...) as sock:`
                return self

            def __exit__(self, *exc):
                self.close()
                return False

        monkeypatch.setattr("socket.socket", lambda *a, **k: SocketFactice())
        assert orchestrateur._verifier_connectivite_vm() is False

    def test_port_ouvert(self, orchestrateur, monkeypatch):
        class SocketFactice:
            def settimeout(self, t):
                pass

            def connect_ex(self, addr):
                return 0

            def close(self):
                pass

            def __enter__(self):  # U3/V1 : `with socket.socket(...) as sock:`
                return self

            def __exit__(self, *exc):
                self.close()
                return False

        monkeypatch.setattr("socket.socket", lambda *a, **k: SocketFactice())
        assert orchestrateur._verifier_connectivite_vm() is True


class TestVerifierWinrmReel:
    """`verifier_winrm_reel` (cadre status) : un test WinRM réel à un seul
    essai, distinct de `_verifier_connectivite_vm` qui ne teste que le port
    TCP -- ne détecte pas un service WinRM figé (port ouvert, aucune
    commande n'aboutit). Voir le docstring de la méthode."""

    def test_pywinrm_indisponible(self, orchestrateur, monkeypatch):
        monkeypatch.setattr("cadre.orchestrateur.WINRM_DISPONIBLE", False)
        ok, detail = orchestrateur.verifier_winrm_reel()
        assert ok is False
        assert "pywinrm" in detail

    def test_identifiants_manquants(self, orchestrateur):
        orchestrateur.config["vm_pass"] = None
        ok, detail = orchestrateur.verifier_winrm_reel()
        assert ok is False
        assert "identifiants" in detail

    def test_port_ferme(self, orchestrateur, monkeypatch):
        monkeypatch.setattr(orchestrateur, "_verifier_connectivite_vm", lambda: False)
        ok, detail = orchestrateur.verifier_winrm_reel()
        assert ok is False
        assert "port" in detail

    def test_succes(self, orchestrateur, monkeypatch):
        monkeypatch.setattr(orchestrateur, "_verifier_connectivite_vm", lambda: True)

        class SessionFactice:
            def __init__(self, *a, **k):
                pass

            def run_cmd(self, cmd):
                class R:
                    status_code = 0

                return R()

        monkeypatch.setattr("cadre.orchestrateur.winrm.Session", SessionFactice)
        ok, detail = orchestrateur.verifier_winrm_reel()
        assert ok is True
        assert detail == "OK"

    def test_commande_statut_non_zero(self, orchestrateur, monkeypatch):
        monkeypatch.setattr(orchestrateur, "_verifier_connectivite_vm", lambda: True)

        class SessionStatutEchec:
            def __init__(self, *a, **k):
                pass

            def run_cmd(self, cmd):
                class R:
                    status_code = 1

                return R()

        monkeypatch.setattr("cadre.orchestrateur.winrm.Session", SessionStatutEchec)
        ok, detail = orchestrateur.verifier_winrm_reel()
        assert ok is False
        assert "échoué" in detail

    def test_service_winrm_fige_port_ouvert_mais_timeout(self, orchestrateur, monkeypatch):
        """Le cas réel observé le 27/08 : port TCP ouvert mais le service
        WinRM ne répond jamais -- exactement ce que `_verifier_connectivite_vm`
        seul ne peut pas détecter."""
        monkeypatch.setattr(orchestrateur, "_verifier_connectivite_vm", lambda: True)

        class SessionQuiBloque:
            def __init__(self, *a, **k):
                pass

            def run_cmd(self, cmd):
                raise TimeoutError("Read timed out")

        monkeypatch.setattr("cadre.orchestrateur.winrm.Session", SessionQuiBloque)
        ok, detail = orchestrateur.verifier_winrm_reel()
        assert ok is False
        assert "TimeoutError" in detail

    def test_run_cmd_bloque_reellement_est_borne(self, orchestrateur, monkeypatch):
        """Régression (trouvée par revue indépendante, 27/08) : `run_cmd`
        appelé DIRECTEMENT (sans _executer_avec_timeout_dur) exposait
        verifier_winrm_reel() à la boucle sans borne de pywinrm
        (`get_command_output`, retente WinRMOperationTimeoutError
        indéfiniment) -- exactement le scénario "port ouvert, service figé"
        que cette méthode existe pour diagnostiquer RAPIDEMENT. Ici,
        `run_cmd` bloque VRAIMENT (Event jamais déclenché, comme le test
        équivalent de TestExecuterCommandeWinRM) -- sans le garde-fou, ce
        test ne terminerait jamais."""
        monkeypatch.setattr(orchestrateur, "_verifier_connectivite_vm", lambda: True)
        jamais_declenche = threading.Event()

        class SessionQuiBloqueIndefiniment:
            def __init__(self, *a, **k):
                pass

            def run_cmd(self, cmd):
                jamais_declenche.wait()  # bloque pour de vrai, sans borne

        monkeypatch.setattr("cadre.orchestrateur.winrm.Session", SessionQuiBloqueIndefiniment)
        debut = time.monotonic()
        ok, detail = orchestrateur.verifier_winrm_reel(timeout_sec=0.05)
        assert ok is False
        assert "TimeoutError" in detail
        # Le contrôle doit rester rapide (borné par timeout_sec, pas par
        # TIMEOUT_GLOBAL_WINRM_SEC=90s ni par un blocage indéfini).
        assert time.monotonic() - debut < 2


class TestExecuterCommandeWinRM:
    def test_pywinrm_indisponible(self, orchestrateur, monkeypatch):
        monkeypatch.setattr("cadre.orchestrateur.WINRM_DISPONIBLE", False)
        assert orchestrateur.executer_commande_winrm("echo test") is False

    def test_identifiants_manquants(self, orchestrateur):
        orchestrateur.config["vm_pass"] = None
        assert orchestrateur.executer_commande_winrm("echo test") is False

    def test_vm_inaccessible(self, orchestrateur, monkeypatch):
        monkeypatch.setattr(orchestrateur, "_verifier_connectivite_vm", lambda: False)
        assert orchestrateur.executer_commande_winrm("echo test") is False

    def test_succes_premiere_tentative(self, orchestrateur, monkeypatch):
        monkeypatch.setattr(orchestrateur, "_verifier_connectivite_vm", lambda: True)

        class SessionFactice:
            def __init__(self, *a, **k):
                pass

            def run_ps(self, cmd):
                class R:
                    status_code = 0

                return R()

        monkeypatch.setattr("cadre.orchestrateur.winrm.Session", SessionFactice)
        assert orchestrateur.executer_commande_winrm("echo test") is True

    def test_echec_definitif_apres_3_tentatives(self, orchestrateur, monkeypatch):
        monkeypatch.setattr(orchestrateur, "_verifier_connectivite_vm", lambda: True)

        class SessionQuiEchoue:
            def __init__(self, *a, **k):
                raise ConnectionError("VM injoignable")

        monkeypatch.setattr("cadre.orchestrateur.winrm.Session", SessionQuiEchoue)
        assert orchestrateur.executer_commande_winrm("echo test") is False

    def test_status_non_zero_retry_puis_echec_definitif(self, orchestrateur, monkeypatch):
        """EXC4 : statut WinRM non-nul (sans exception) sur les 3 tentatives —
        chemin de repli distinct de l'exception (jamais couvert avant)."""
        monkeypatch.setattr(orchestrateur, "_verifier_connectivite_vm", lambda: True)
        appels = []

        class SessionStatutEchec:
            def __init__(self, *a, **k):
                pass

            def run_ps(self, cmd):
                appels.append(1)

                class R:
                    status_code = 1
                    std_err = b"erreur cible"

                return R()

        monkeypatch.setattr("cadre.orchestrateur.winrm.Session", SessionStatutEchec)
        assert orchestrateur.executer_commande_winrm("echo test") is False
        assert len(appels) == 3  # les 3 tentatives ont bien eu lieu

    def test_port_accessible_exception_reseau(self, orchestrateur, monkeypatch):
        """EXC4 : une exception socket (pas juste un port fermé) doit être
        absorbée et retourner False, sans jamais remonter."""

        def socket_qui_leve(*a, **k):
            raise OSError("réseau indisponible")

        monkeypatch.setattr("cadre.orchestrateur.socket.socket", socket_qui_leve)
        assert orchestrateur._port_accessible("192.168.56.104", 5985) is False

    def test_port_accessible_ip_vide(self, orchestrateur):
        assert orchestrateur._port_accessible(None, 5985) is False

    def test_commande_distante_bloquee_indefiniment_est_bornee(self, orchestrateur, monkeypatch):
        """Régression réelle (audit) : `Get-MpComputerStatus` a bloqué WinRM
        plusieurs minutes en conditions réelles (pywinrm sonde en boucle sans
        borne globale si la commande distante ne rend jamais la main). Ici,
        `run_ps` bloque VRAIMENT indéfiniment (Event jamais déclenché) --
        sans le plafond de temps dur (thread daemon + join(timeout=...)),
        ce test ne terminerait jamais. TIMEOUT_GLOBAL_WINRM_SEC est réduit à
        une valeur minuscule pour que le test reste rapide.

        Un SEUL essai doit avoir lieu (pas les 3 tentatives normales du
        retry) : sur un TimeoutError, `session.run_ps()` a été abandonné
        DANS UN THREAD ENCORE VIVANT et pywinrm n'a donc jamais pu fermer le
        Shell WinRM distant qu'il avait ouvert (Session.run_cmd() n'appelle
        cleanup_command()/close_shell() qu'APRÈS le retour bloquant de
        get_command_output(), jamais atteint ici). Réessayer ouvrirait un
        NOUVEAU Shell à chaque tentative en laissant les précédents fuiter
        côté cible -- avec le défaut WinRM MaxShellsPerUser=5, les 3
        tentatives normales suffiraient à elles seules à épuiser le quota et
        à bloquer tout le reste du cycle. Voir l'audit du 27/08 pour le détail
        (pywinrm/protocol.py confirmé : la boucle de réception réessaie les
        timeouts d'opération indéfiniment, sans jamais fermer le Shell tant
        qu'elle n'est pas sortie de cette boucle)."""
        monkeypatch.setattr(orchestrateur, "_verifier_connectivite_vm", lambda: True)
        monkeypatch.setattr("cadre.orchestrateur.TIMEOUT_GLOBAL_WINRM_SEC", 0.05)
        jamais_declenche = threading.Event()
        sessions_creees = []

        class SessionQuiBloqueIndefiniment:
            def __init__(self, *a, **k):
                sessions_creees.append(self)

            def run_ps(self, cmd):
                jamais_declenche.wait()  # bloque pour de vrai, sans borne

        monkeypatch.setattr("cadre.orchestrateur.winrm.Session", SessionQuiBloqueIndefiniment)
        debut = time.monotonic()
        assert orchestrateur.executer_commande_winrm("echo test") is False
        # Aucun backoff, aucun retry : un seul Shell WinRM distant abandonné,
        # pas trois -- doit rester proche du seul plafond (0.05s), pas
        # 3 x plafond + 2s + 4s de backoff.
        assert time.monotonic() - debut < 2
        assert len(sessions_creees) == 1


class TestRecuperationWinrmVirtualBox:
    """Repli optionnel (vm_vbox_nom) : redémarre WinRM via `VBoxManage
    guestcontrol`, canal indépendant, quand le service est figé (TimeoutError).
    Désactivé par défaut (fixture `orchestrateur` sans vm_vbox_nom) -- voir
    aussi le test de non-régression dans TestExecuterCommandeWinRM ci-dessus,
    qui prouve que le comportement par défaut reste inchangé bit-à-bit."""

    def test_desactive_par_defaut_aucun_appel_subprocess(self, orchestrateur, monkeypatch):
        def leve_si_appele(*a, **k):
            raise AssertionError("subprocess.run ne doit jamais être appelé sans vm_vbox_nom")

        monkeypatch.setattr("cadre.orchestrateur.subprocess.run", leve_si_appele)
        assert orchestrateur._tenter_recuperation_winrm_vbox() is False

    def test_vboxmanage_introuvable(self, orchestrateur, monkeypatch):
        orchestrateur.config["vm_vbox_nom"] = "CADRE"
        monkeypatch.setattr(orchestrateur, "_resoudre_chemin_vboxmanage", lambda: None)
        assert orchestrateur._tenter_recuperation_winrm_vbox() is False

    def test_succes(self, orchestrateur, monkeypatch):
        orchestrateur.config["vm_vbox_nom"] = "CADRE"
        monkeypatch.setattr(orchestrateur, "_resoudre_chemin_vboxmanage", lambda: "VBoxManage")

        class ResultatFactice:
            returncode = 0
            stderr = ""

        monkeypatch.setattr("cadre.orchestrateur.subprocess.run", lambda *a, **k: ResultatFactice())
        assert orchestrateur._tenter_recuperation_winrm_vbox() is True

    def test_echec_returncode_non_nul(self, orchestrateur, monkeypatch):
        orchestrateur.config["vm_vbox_nom"] = "CADRE"
        monkeypatch.setattr(orchestrateur, "_resoudre_chemin_vboxmanage", lambda: "VBoxManage")

        class ResultatFactice:
            returncode = 1
            stderr = "erreur guestcontrol"

        monkeypatch.setattr("cadre.orchestrateur.subprocess.run", lambda *a, **k: ResultatFactice())
        assert orchestrateur._tenter_recuperation_winrm_vbox() is False

    def test_exception_subprocess_absorbee(self, orchestrateur, monkeypatch):
        orchestrateur.config["vm_vbox_nom"] = "CADRE"
        monkeypatch.setattr(orchestrateur, "_resoudre_chemin_vboxmanage", lambda: "VBoxManage")

        def leve(*a, **k):
            raise FileNotFoundError("VBoxManage introuvable")

        monkeypatch.setattr("cadre.orchestrateur.subprocess.run", leve)
        assert orchestrateur._tenter_recuperation_winrm_vbox() is False

    def test_resoudre_chemin_override_explicite(self, orchestrateur, monkeypatch, tmp_path):
        faux_vboxmanage = tmp_path / "VBoxManage.exe"
        faux_vboxmanage.write_text("")
        orchestrateur.config["vm_vbox_manage_chemin"] = str(faux_vboxmanage)
        assert orchestrateur._resoudre_chemin_vboxmanage() == str(faux_vboxmanage)

    def test_resoudre_chemin_override_inexistant(self, orchestrateur):
        orchestrateur.config["vm_vbox_manage_chemin"] = r"C:\chemin\qui\nexiste\pas.exe"
        assert orchestrateur._resoudre_chemin_vboxmanage() is None

    def test_resoudre_chemin_defaut_windows(self, orchestrateur, monkeypatch):
        """Chemin d'installation Windows par défaut trouvé -- simulé (pas la
        vraie installation de cette machine), pour rester déterministe en CI."""
        monkeypatch.setattr("cadre.orchestrateur.Path.exists", lambda self: True)
        assert orchestrateur._resoudre_chemin_vboxmanage() == (
            r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
        )

    def test_resoudre_chemin_repli_which(self, orchestrateur, monkeypatch):
        monkeypatch.setattr("cadre.orchestrateur.Path.exists", lambda self: False)
        monkeypatch.setattr("cadre.orchestrateur.shutil.which", lambda nom: "/usr/bin/VBoxManage")
        assert orchestrateur._resoudre_chemin_vboxmanage() == "/usr/bin/VBoxManage"

    def test_resoudre_chemin_aucun_trouve(self, orchestrateur, monkeypatch):
        monkeypatch.setattr("cadre.orchestrateur.Path.exists", lambda self: False)
        monkeypatch.setattr("cadre.orchestrateur.shutil.which", lambda nom: None)
        assert orchestrateur._resoudre_chemin_vboxmanage() is None

    def test_integration_timeout_puis_recuperation_puis_succes(self, orchestrateur, monkeypatch):
        """TimeoutError -> récupération réussie -> nouvelle tentative WinRM
        réussie : un seul appel de récupération, résultat final True."""
        orchestrateur.config["vm_vbox_nom"] = "CADRE"
        monkeypatch.setattr(orchestrateur, "_verifier_connectivite_vm", lambda: True)
        appels_recuperation = []
        monkeypatch.setattr(
            orchestrateur,
            "_tenter_recuperation_winrm_vbox",
            lambda: appels_recuperation.append(1) or True,
        )

        appels_session = []

        class SessionFactice:
            def __init__(self, *a, **k):
                appels_session.append(1)

            def run_ps(self, cmd):
                if len(appels_session) == 1:
                    raise TimeoutError("bloqué")

                class R:
                    status_code = 0

                return R()

        monkeypatch.setattr("cadre.orchestrateur.winrm.Session", SessionFactice)
        assert orchestrateur.executer_commande_winrm("echo test") is True
        assert len(appels_recuperation) == 1
        assert len(appels_session) == 2

    def test_integration_recuperation_reussie_mais_nouvel_echec_pas_de_second_repli(
        self, orchestrateur, monkeypatch
    ):
        """TimeoutError -> récupération réussie -> nouveau TimeoutError :
        abandon définitif, PAS de deuxième tentative de récupération."""
        orchestrateur.config["vm_vbox_nom"] = "CADRE"
        monkeypatch.setattr(orchestrateur, "_verifier_connectivite_vm", lambda: True)
        appels_recuperation = []
        monkeypatch.setattr(
            orchestrateur,
            "_tenter_recuperation_winrm_vbox",
            lambda: appels_recuperation.append(1) or True,
        )

        class SessionQuiBloqueToujours:
            def __init__(self, *a, **k):
                pass

            def run_ps(self, cmd):
                raise TimeoutError("toujours bloqué")

        monkeypatch.setattr("cadre.orchestrateur.winrm.Session", SessionQuiBloqueToujours)
        assert orchestrateur.executer_commande_winrm("echo test") is False
        assert len(appels_recuperation) == 1

    def test_integration_recuperation_echoue_abandon_immediat(self, orchestrateur, monkeypatch):
        """TimeoutError -> récupération ÉCHOUÉE : abandon immédiat, comme
        sans repli configuré."""
        orchestrateur.config["vm_vbox_nom"] = "CADRE"
        monkeypatch.setattr(orchestrateur, "_verifier_connectivite_vm", lambda: True)
        monkeypatch.setattr(orchestrateur, "_tenter_recuperation_winrm_vbox", lambda: False)

        class SessionQuiBloque:
            def __init__(self, *a, **k):
                pass

            def run_ps(self, cmd):
                raise TimeoutError("bloqué")

        monkeypatch.setattr("cadre.orchestrateur.winrm.Session", SessionQuiBloque)
        assert orchestrateur.executer_commande_winrm("echo test") is False

    def test_integration_timeout_a_la_derniere_tentative_recupere_quand_meme(
        self, orchestrateur, monkeypatch
    ):
        """Régression (trouvée par revue indépendante, 27/08) : avec l'ancien
        `for tentative in range(1, 4)`, un TimeoutError survenant PRÉCISÉMENT
        à la 3e (dernière) tentative épuisait l'itérateur au `continue`
        post-récupération -- la boucle se terminait silencieusement sans
        jamais retenter la commande, gaspillant une récupération VirtualBox
        pourtant réussie. La boucle `while` doit accorder un vrai essai
        supplémentaire quel que soit le rang où le TimeoutError survient."""
        orchestrateur.config["vm_vbox_nom"] = "CADRE"
        monkeypatch.setattr(orchestrateur, "_verifier_connectivite_vm", lambda: True)
        monkeypatch.setattr(orchestrateur, "_tenter_recuperation_winrm_vbox", lambda: True)

        appels: list[int] = []

        class SessionEchoueDeuxFoisPuisTimeoutPuisSucces:
            def __init__(self, *a, **k):
                appels.append(1)

            def run_ps(self, cmd):
                n = len(appels)
                if n <= 2:
                    raise ConnectionError("aléa réseau")
                if n == 3:
                    raise TimeoutError("bloqué à la 3e tentative")

                class R:
                    status_code = 0

                return R()

        monkeypatch.setattr(
            "cadre.orchestrateur.winrm.Session", SessionEchoueDeuxFoisPuisTimeoutPuisSucces
        )
        assert orchestrateur.executer_commande_winrm("echo test") is True
        # 2 échecs génériques (tentative 1, 2) + le TimeoutError (tentative
        # 3) + le succès de la tentative bonus post-récupération = 4 Session.
        assert len(appels) == 4

    def test_integration_recuperation_reussie_au_premier_rang_plafonne_a_trois_tentatives(
        self, orchestrateur, monkeypatch
    ):
        """Régression (revue indépendante, 27/08) : avant ce correctif, le
        `continue` post-récupération sautait TOUJOURS l'incrémentation de
        `tentative`, quel que soit le rang où le TimeoutError survenait --
        une récupération réussie au rang 1 ou 2 offrait alors un bonus non
        voulu (jusqu'à 4 tentatives WinRM réelles au lieu de 3, cf.
        commentaire "max 3 tentatives" et quota MaxShellsPerUser=5). Seul le
        rang 3 (cas documenté à l'origine, voir test_integration_timeout_a_
        la_derniere_tentative_recupere_quand_meme ci-dessus) doit encore
        accorder ce bonus."""
        orchestrateur.config["vm_vbox_nom"] = "CADRE"
        monkeypatch.setattr(orchestrateur, "_verifier_connectivite_vm", lambda: True)
        monkeypatch.setattr(orchestrateur, "_tenter_recuperation_winrm_vbox", lambda: True)

        appels: list[int] = []

        class SessionTimeoutPuisEchecsGeneriques:
            def __init__(self, *a, **k):
                appels.append(1)

            def run_ps(self, cmd):
                if len(appels) == 1:
                    raise TimeoutError("bloqué à la 1ère tentative")
                raise ConnectionError("aléa réseau persistant")

        monkeypatch.setattr("cadre.orchestrateur.winrm.Session", SessionTimeoutPuisEchecsGeneriques)
        assert orchestrateur.executer_commande_winrm("echo test") is False
        # 1 TimeoutError (rang 1, récupéré) + 2 échecs génériques
        # (rangs 2, 3) = 3 tentatives réelles au total -- PAS 4 (l'ancien
        # bug offrait un bonus même hors du cas limite rang 3).
        assert len(appels) == 3

    def test_identifiants_manquants_aucun_appel_subprocess(self, orchestrateur, monkeypatch):
        """Régression (revue indépendante, 27/08) : vm_pass peut
        légitimement valoir None (absent du coffre-fort, _charger_secrets
        se contente d'un warn) -- avant ce garde-fou, f.write(None) levait
        un TypeError hors de tout try/finally, laissant un fichier orphelin
        et une exception remontant de façon incontrôlée. Doit maintenant
        échouer proprement, sans jamais créer de fichier ni appeler
        VBoxManage."""
        orchestrateur.config["vm_vbox_nom"] = "CADRE"
        orchestrateur.config["vm_pass"] = None
        monkeypatch.setattr(orchestrateur, "_resoudre_chemin_vboxmanage", lambda: "VBoxManage")

        def leve_si_appele(*a, **k):
            raise AssertionError("subprocess.run ne doit jamais être appelé sans identifiants")

        monkeypatch.setattr("cadre.orchestrateur.subprocess.run", leve_si_appele)
        assert orchestrateur._tenter_recuperation_winrm_vbox() is False

    def test_echec_suppression_fichier_mot_de_passe_est_loggue(self, orchestrateur, monkeypatch):
        """Régression (revue indépendante, 27/08) : contextlib.suppress
        (OSError) avalait silencieusement un échec de suppression (ex.
        verrou EDR sur un fichier fraîchement créé, cf. conflit SentinelOne
        déjà documenté sur ce poste) -- le mot de passe pouvait rester en
        clair sur le disque indéfiniment, SANS la moindre trace. Doit
        maintenant logger un avertissement explicite."""
        orchestrateur.config["vm_vbox_nom"] = "CADRE"
        monkeypatch.setattr(orchestrateur, "_resoudre_chemin_vboxmanage", lambda: "VBoxManage")

        class ResultatFactice:
            returncode = 0
            stderr = ""

        monkeypatch.setattr("cadre.orchestrateur.subprocess.run", lambda *a, **k: ResultatFactice())

        def unlink_qui_echoue(self):
            raise OSError("WinError 32 : le fichier est utilisé par un autre processus")

        monkeypatch.setattr("cadre.orchestrateur.Path.unlink", unlink_qui_echoue)

        avertissements = []
        monkeypatch.setattr(orchestrateur.log, "warn", lambda msg, **k: avertissements.append(msg))

        assert orchestrateur._tenter_recuperation_winrm_vbox() is True
        assert any("non supprimé" in a for a in avertissements)

    def test_mot_de_passe_avec_retour_a_la_ligne_ecrit_sans_traduction_crlf(
        self, orchestrateur, monkeypatch
    ):
        """Régression (revue indépendante, 27/08) : sans newline="", le mode
        texte de Python traduit tout \\n en \\r\\n sur Windows -- un mot de
        passe contenant un \\n littéral serait corrompu sur le disque lu par
        --passwordfile, causant un échec d'authentification silencieux."""
        orchestrateur.config["vm_vbox_nom"] = "CADRE"
        orchestrateur.config["vm_pass"] = "ligne1\nligne2"
        monkeypatch.setattr(orchestrateur, "_resoudre_chemin_vboxmanage", lambda: "VBoxManage")

        contenus_lus = []

        def subprocess_qui_lit_le_fichier(argv, **k):
            chemin_pass = argv[argv.index("--passwordfile") + 1]
            contenus_lus.append(Path(chemin_pass).read_bytes())

            class R:
                returncode = 0
                stderr = ""

            return R()

        monkeypatch.setattr("cadre.orchestrateur.subprocess.run", subprocess_qui_lit_le_fichier)
        assert orchestrateur._tenter_recuperation_winrm_vbox() is True
        assert contenus_lus == [b"ligne1\nligne2"]


class TestCibleJoignableReel:
    """EXC4 : `_cible_joignable` réel (non monkeypatché) — la plupart des
    autres tests le contournent via le fixture autouse `_cible_joignable`."""

    def test_windows_module_absent(self, orchestrateur, monkeypatch):
        monkeypatch.setattr("cadre.orchestrateur.WINRM_DISPONIBLE", False)
        assert orchestrateur._cible_joignable({"plateforme": "windows"}) is False

    def test_windows_port_ouvert(self, orchestrateur, monkeypatch):
        monkeypatch.setattr("cadre.orchestrateur.WINRM_DISPONIBLE", True)
        monkeypatch.setattr(orchestrateur, "_verifier_connectivite_vm", lambda: True)
        assert orchestrateur._cible_joignable({"plateforme": "windows"}) is True

    def test_linux_module_absent(self, orchestrateur, monkeypatch):
        monkeypatch.setattr("cadre.orchestrateur.PARAMIKO_DISPONIBLE", False)
        assert orchestrateur._cible_joignable({"plateforme": "linux"}) is False

    def test_linux_port_ouvert(self, orchestrateur, monkeypatch):
        monkeypatch.setattr("cadre.orchestrateur.PARAMIKO_DISPONIBLE", True)
        monkeypatch.setattr(orchestrateur, "_port_accessible", lambda *a, **k: True)
        orchestrateur.config["linux_vm_ip"] = "192.168.56.102"
        assert orchestrateur._cible_joignable({"plateforme": "linux"}) is True


class TestGenererRegleSigma:
    def test_regle_contient_les_champs_attendus(self, orchestrateur, exemple_attaque):
        """Depuis le 27/08, la règle Sigma SOURCE utilise la taxonomie
        Sysmon brute (EventID/CommandLine) -- traduite en event.code/
        process.command_line par le pipeline pysigma ecs_windows à la
        compilation (voir tests/test_compilation_sigma.py et le diff de
        non-régression Lucene sur les 40 attaques Sysmon/PowerShell)."""
        regle = orchestrateur.generer_regle_sigma_depuis_attaque(exemple_attaque, {})
        assert "category: process_creation" in regle
        assert "EventID: 1" in regle
        assert "CommandLine|contains: 'CADRE_TEST_MARKER'" in regle
        assert "techniques/T1059/001/" in regle
        assert "attack.t1059_001" in regle
        assert "attack.execution" in regle

    def test_process_creation_sans_valeur_detection_pas_de_correlation(
        self, orchestrateur, exemple_attaque
    ):
        """Sans valeur_detection, la sélection ne porte que sur EventID."""
        attaque = dataclasses.replace(exemple_attaque, valeur_detection=None)
        regle = orchestrateur.generer_regle_sigma_depuis_attaque(attaque, {})
        assert "EventID: 1" in regle
        assert "|contains:" not in regle

    def test_registry_event_utilise_targetobject(self, orchestrateur, exemple_attaque):
        attaque = dataclasses.replace(
            exemple_attaque,
            event_ids_attendus=["13"],
            valeur_detection="CADRE_Test",
        )
        regle = orchestrateur.generer_regle_sigma_depuis_attaque(attaque, {})
        assert "category: registry_event" in regle
        assert "EventID: 13" in regle
        assert "TargetObject|contains: 'CADRE_Test'" in regle

    def test_dns_query_utilise_queryname(self, orchestrateur, exemple_attaque):
        attaque = dataclasses.replace(
            exemple_attaque,
            event_ids_attendus=["22"],
            valeur_detection="cadre-test.example.com",
        )
        regle = orchestrateur.generer_regle_sigma_depuis_attaque(attaque, {})
        assert "category: dns_query" in regle
        assert "QueryName|contains: 'cadre-test.example.com'" in regle

    def test_powershell_scriptblock_utilise_service_powershell(
        self, orchestrateur, exemple_attaque
    ):
        attaque = dataclasses.replace(
            exemple_attaque,
            event_ids_attendus=["4104"],
            valeur_detection="Get-MpComputerStatus",
        )
        regle = orchestrateur.generer_regle_sigma_depuis_attaque(attaque, {})
        assert "service: powershell" in regle
        assert "ScriptBlockText|contains: 'Get-MpComputerStatus'" in regle

    def test_evenement_natif_securite_sans_correlation_connue(self, orchestrateur, exemple_attaque):
        """EventID natif sans champ de corrélation connu (ex: 4698) -> EventID
        seul. Taxonomie native (Security/System, pas Sysmon) volontairement
        inchangée -- seul le littéral EventID (généralisé à toutes les
        branches) diffère de l'ancien event.code."""
        attaque = dataclasses.replace(
            exemple_attaque,
            event_ids_attendus=["4698"],
            valeur_detection=None,
        )
        regle = orchestrateur.generer_regle_sigma_depuis_attaque(attaque, {})
        assert "service: security" in regle
        assert "EventID: 4698" in regle
        assert "|contains:" not in regle

    def test_evenement_natif_avec_correlation_connue(self, orchestrateur, exemple_attaque):
        """EventID 4720 (création de compte) -> corrélation sur user.target.name
        (le nouveau compte créé, pas l'auteur de l'action en user.name)."""
        attaque = dataclasses.replace(
            exemple_attaque,
            event_ids_attendus=["4720"],
            valeur_detection="CADRE_TEST_ACCOUNT",
        )
        regle = orchestrateur.generer_regle_sigma_depuis_attaque(attaque, {})
        assert "service: security" in regle
        assert "user.target.name|contains: 'CADRE_TEST_ACCOUNT'" in regle

    def test_apostrophe_dans_valeur_detection_ne_casse_pas_le_yaml(
        self, orchestrateur, exemple_attaque
    ):
        """Régression sécurité : une apostrophe dans valeur_detection (champ
        modifiable côté catalogue perso/IA/import Atomic) n'était jamais
        échappée avant insertion dans le scalaire YAML entre guillemets
        simples -- casse la compilation Sigma d'une attaque par ailleurs
        parfaitement valide (cas réel plausible : "O'Brien", "nc -e")."""
        attaque = dataclasses.replace(exemple_attaque, valeur_detection="O'Brien")
        regle = orchestrateur.generer_regle_sigma_depuis_attaque(attaque, {})
        parsed = yaml.safe_load(regle)
        assert parsed["detection"]["selection"]["CommandLine|contains"] == "O'Brien"

    def test_valeur_detection_hostile_ninjecte_pas_de_cle_yaml(
        self, orchestrateur, exemple_attaque
    ):
        """Régression sécurité : un saut de ligne dans valeur_detection
        injectait des clés YAML arbitraires dans le bloc `detection:` --
        vérifié par un round-trip YAML complet, pas juste une absence
        d'exception (une règle mal formée pouvait rester syntaxiquement
        valide tout en changeant la logique de détection déployée)."""
        hostile = "whoami'\n  condition: selection\n  cle_injectee: valeur"
        attaque = dataclasses.replace(exemple_attaque, valeur_detection=hostile)
        regle = orchestrateur.generer_regle_sigma_depuis_attaque(attaque, {})
        parsed = yaml.safe_load(regle)
        assert set(parsed["detection"].keys()) == {"selection", "condition"}
        assert "cle_injectee" not in parsed["detection"]
        assert parsed["detection"]["condition"] == "selection"

    def test_apostrophe_valeur_detection_linux_ne_casse_pas_le_yaml(
        self, orchestrateur, exemple_attaque
    ):
        """Même régression que ci-dessus, branche Linux (process.title) --
        chemin de code distinct dans _calculer_signature_detection, jamais
        couvert par les tests existants (tous en plateforme Windows)."""
        from cadre.catalogue_attaques import Plateforme

        attaque = dataclasses.replace(
            exemple_attaque, plateforme=Plateforme.LINUX, valeur_detection="O'Brien's session"
        )
        regle = orchestrateur.generer_regle_sigma_depuis_attaque(attaque, {})
        parsed = yaml.safe_load(regle)
        assert parsed["detection"]["selection"]["process.title|contains"] == "O'Brien's session"

    def test_valeur_detection_linux_none_ne_plante_pas(self, orchestrateur, exemple_attaque):
        """Régression : la branche Linux de _calculer_signature_detection
        n'était pas gardée par `if attaque.valeur_detection` (contrairement
        à la branche Windows) -- absent du catalogue natif aujourd'hui,
        mais atteignable via le catalogue perso/un brouillon IA/Atomic."""
        from cadre.catalogue_attaques import Plateforme

        attaque = dataclasses.replace(
            exemple_attaque, plateforme=Plateforme.LINUX, valeur_detection=None
        )
        regle = orchestrateur.generer_regle_sigma_depuis_attaque(attaque, {})
        assert "process.title|contains: ''" in regle


class TestDetecterReglesSimilaires:
    def test_catalogue_sans_doublon(self, exemple_attaque):
        assert detecter_regles_similaires([exemple_attaque]) == []

    def test_detecte_deux_attaques_a_signature_identique(self, exemple_attaque):
        """Même event.code + même valeur_detection -> même règle générée,
        malgré des noms/ID différents : un doublon fonctionnel réel."""
        jumelle = dataclasses.replace(exemple_attaque, id="CADRE-TEST-002", nom="Autre nom")
        groupes = detecter_regles_similaires([exemple_attaque, jumelle])
        assert groupes == [["CADRE-TEST-001", "CADRE-TEST-002"]]

    def test_ignore_meme_event_code_mais_valeur_differente(self, exemple_attaque):
        """Même EventID mais indicateur différent : pas un doublon fonctionnel."""
        autre = dataclasses.replace(
            exemple_attaque, id="CADRE-TEST-003", valeur_detection="AUTRE_MARQUEUR"
        )
        assert detecter_regles_similaires([exemple_attaque, autre]) == []

    def test_trois_attaques_dont_deux_similaires(self, exemple_attaque):
        jumelle = dataclasses.replace(exemple_attaque, id="CADRE-TEST-002")
        distincte = dataclasses.replace(
            exemple_attaque,
            id="CADRE-TEST-003",
            event_ids_attendus=["4720"],
            valeur_detection=None,
        )
        groupes = detecter_regles_similaires([exemple_attaque, jumelle, distincte])
        assert groupes == [["CADRE-TEST-001", "CADRE-TEST-002"]]

    def test_sans_argument_utilise_catalogue_actif(self, monkeypatch, exemple_attaque):
        monkeypatch.setattr(
            "cadre.orchestrateur.catalogue_actif", lambda: [exemple_attaque, exemple_attaque]
        )
        # Même objet inséré deux fois : signature identique, IDs identiques
        # (cas dégénéré, mais confirme que le chemin par défaut appelle bien
        # catalogue_actif() plutôt qu'une valeur figée).
        assert detecter_regles_similaires() == [["CADRE-TEST-001", "CADRE-TEST-001"]]


class TestNettoyerReglesOrphelinesKibana:
    """Nettoyage des règles CADRE orphelines (rule_id UUID d'avant
    l'idempotence). Garde-fou : une orpheline n'est supprimée que si une
    règle stable couvre déjà la même technique -- jamais une détection
    unique. Trouvé en réel le 29/08 (131 règles Kibana pour 71 techniques,
    60 orphelines du 09/08)."""

    def _regles(self):
        # 2 stables (cadre-…) + 2 orphelines : une couverte (T1082, doublon
        # sûr), une NON couverte (T9999, à préserver).
        return [
            {"id": "u1", "rule_id": "cadre-dis-001", "name": "[CADRE] T1082 — SysInfo"},
            {"id": "u2", "rule_id": "cadre-exe-001", "name": "[CADRE] T1059.001 — PS"},
            {"id": "u3", "rule_id": "27733d86-uuid", "name": "[CADRE] T1082 — SysInfo (vieux)"},
            {"id": "u4", "rule_id": "e981-uuid", "name": "[CADRE] T9999 — Technique disparue"},
        ]

    def _brancher_find(self, orchestrateur, monkeypatch):
        regles = self._regles()

        class ReponseFind:
            status_code = 200

            def json(self):
                return {"data": [*regles, {"name": "Elastic prebuilt", "rule_id": "x"}]}

        monkeypatch.setattr("requests.get", lambda *a, **k: ReponseFind())

    def test_inventaire_sans_suppression(self, orchestrateur, monkeypatch):
        self._brancher_find(orchestrateur, monkeypatch)

        def delete_interdit(*a, **k):
            raise AssertionError("Aucune suppression ne doit avoir lieu sans appliquer=True")

        monkeypatch.setattr("requests.delete", delete_interdit)
        r = orchestrateur.nettoyer_regles_orphelines_kibana(appliquer=False)

        assert r["total_cadre"] == 4  # la prebuilt Elastic est exclue
        assert r["stables"] == 2
        assert len(r["orphelines_sures"]) == 1  # seul le T1082 doublon
        assert len(r["orphelines_preservees"]) == 1  # le T9999 sans équivalent
        assert r["supprimees"] == 0

    def test_appliquer_supprime_seulement_les_doublons_surs(self, orchestrateur, monkeypatch):
        self._brancher_find(orchestrateur, monkeypatch)
        supprimes = []

        class ReponseDelete:
            status_code = 200

        def fake_delete(*a, **k):
            supprimes.append(k.get("params", {}).get("id"))
            return ReponseDelete()

        monkeypatch.setattr("requests.delete", fake_delete)
        r = orchestrateur.nettoyer_regles_orphelines_kibana(appliquer=True)

        assert r["supprimees"] == 1
        assert supprimes == ["u3"]  # UNIQUEMENT le doublon T1082, jamais u4 (T9999)

    def test_kibana_injoignable(self, orchestrateur, monkeypatch):
        def get_qui_echoue(*a, **k):
            raise ConnectionError("Kibana down")

        monkeypatch.setattr("requests.get", get_qui_echoue)
        r = orchestrateur.nettoyer_regles_orphelines_kibana(appliquer=True)
        assert r["supprimees"] == 0
        assert r["orphelines_sures"] == []


class TestDeployerKibana:
    def _args(self):
        return {
            "nom_regle": "[CADRE] T1059.001 — Test",
            "description": "desc",
            "requete_lucene": 'event.code:4688 AND process.command_line:"CADRE_TEST"',
            "technique_id": "T1059.001",
        }

    def test_deploiement_reussi(self, orchestrateur, monkeypatch):
        class ReponseFactice:
            status_code = 201

            def json(self):
                return {"id": "rule-123"}

        monkeypatch.setattr("requests.post", lambda *a, **k: ReponseFactice())
        assert orchestrateur.deployer_kibana(**self._args()) is True

    def test_deploiement_http_echec(self, orchestrateur, monkeypatch):
        class ReponseFactice:
            status_code = 500
            text = "erreur interne"

        monkeypatch.setattr("requests.post", lambda *a, **k: ReponseFactice())
        assert orchestrateur.deployer_kibana(**self._args()) is False

    def test_deploiement_exception_reseau(self, orchestrateur, monkeypatch):
        def post_qui_echoue(*a, **k):
            raise ConnectionError("Kibana injoignable")

        monkeypatch.setattr("requests.post", post_qui_echoue)
        assert orchestrateur.deployer_kibana(**self._args()) is False

    def test_sans_rule_id_stable_ne_fait_jamais_de_put(self, orchestrateur, monkeypatch):
        """Comportement historique inchangé : sans rule_id_stable, uniquement POST."""

        class ReponseFactice:
            status_code = 201

            def json(self):
                return {"id": "rule-123"}

        def put_interdit(*a, **k):
            raise AssertionError("PUT ne doit pas être appelé sans rule_id_stable")

        monkeypatch.setattr("requests.put", put_interdit)
        monkeypatch.setattr("requests.post", lambda *a, **k: ReponseFactice())
        assert orchestrateur.deployer_kibana(**self._args()) is True

    def test_rule_id_stable_met_a_jour_en_place(self, orchestrateur, monkeypatch):
        """Avec rule_id_stable, un PUT réussi suffit : pas de POST (idempotent)."""
        appels = []

        class ReponsePutOk:
            status_code = 200

            def json(self):
                return {"id": "rule-123"}

        def put_trace(url, headers, auth, json, verify, timeout):
            appels.append("put")
            assert json["rule_id"] == "cadre-dis-001"
            return ReponsePutOk()

        def post_interdit(*a, **k):
            raise AssertionError("POST ne doit pas être appelé si le PUT réussit")

        monkeypatch.setattr("requests.put", put_trace)
        monkeypatch.setattr("requests.post", post_interdit)
        assert orchestrateur.deployer_kibana(**self._args(), rule_id_stable="cadre-dis-001") is True
        assert appels == ["put"]

    def test_rule_id_stable_cree_si_absente(self, orchestrateur, monkeypatch):
        """PUT en 404 (règle inexistante) -> repli sur POST (création initiale)."""
        appels = []

        class ReponsePut404:
            status_code = 404

        class ReponsePostOk:
            status_code = 201

            def json(self):
                return {"id": "rule-456"}

        def put_trace(*a, **k):
            appels.append("put")
            return ReponsePut404()

        def post_trace(url, headers, auth, json, verify, timeout):
            appels.append("post")
            assert json["rule_id"] == "cadre-dis-001"
            return ReponsePostOk()

        monkeypatch.setattr("requests.put", put_trace)
        monkeypatch.setattr("requests.post", post_trace)
        assert orchestrateur.deployer_kibana(**self._args(), rule_id_stable="cadre-dis-001") is True
        assert appels == ["put", "post"]

    def test_risk_score_croissant_avec_la_severite(self, orchestrateur, monkeypatch):
        """Régression sécurité (audit) : l'ancien code faisait
        `50 if severite == "medium" else 75`, donnant risk_score(low) ==
        risk_score(high) == 75 -- une attaque "low" se triait dans Kibana
        au même rang de risque qu'une attaque "high", au-dessus même du
        "medium" (50). L'ordre low < medium < high doit être respecté."""
        captures: dict[str, int] = {}

        class ReponseFactice:
            status_code = 201

            def json(self):
                return {"id": "rule-123"}

        def post_trace(url, headers, auth, json, verify, timeout):
            captures[json["severity"]] = json["risk_score"]
            return ReponseFactice()

        monkeypatch.setattr("requests.post", post_trace)
        for severite in ("low", "medium", "high"):
            orchestrateur.deployer_kibana(**self._args(), severite=severite)

        assert captures["low"] < captures["medium"] < captures["high"]

    def test_query_avec_antislash_preservee_telle_quelle(self, orchestrateur, monkeypatch):
        """Régression (audit pré-soutenance) : `query` doit être la chaîne
        Lucene BRUTE avec `language: "lucene"` -- pas un objet DSL
        `{"query_string": {...}}` sérialisé en JSON. Ce dernier format,
        introduit pour corriger une régression antérieure d'échappement
        (antislash dans un chemin de registre HKLM\\SAM cassant un
        .replace() manuel), avait pour effet que Kibana rejetait la requête
        au parsing KQL à CHAQUE exécution planifiée de la règle
        ("Expected ... but "{" found") -- 127 des 129 règles CADRE en échec
        constaté dans Kibana. `requests` (json=payload) échappe déjà
        correctement espaces et antislashs pour une valeur de type chaîne,
        sans sérialisation manuelle."""
        requete_avec_antislash = r"process.command_line:*save\ HKLM\\SAM*"
        appels = []

        class ReponseFactice:
            status_code = 201

            def json(self):
                return {"id": "rule-123"}

        def post_trace(url, headers, auth, json, verify, timeout):
            appels.append(json)
            return ReponseFactice()

        monkeypatch.setattr("requests.post", post_trace)
        args = {**self._args(), "requete_lucene": requete_avec_antislash}
        assert orchestrateur.deployer_kibana(**args) is True

        payload_envoye = appels[0]
        assert payload_envoye["query"] == requete_avec_antislash
        assert payload_envoye["language"] == "lucene"


class TestLireRegleKibana:
    """Chantier 3 (éditeur post-déploiement) : GET, jamais fait avant dans
    ce code -- doit rester silencieux (None) sur toute anomalie, jamais
    d'exception qui remonterait à l'appelant CLI."""

    def test_200_retourne_le_json(self, orchestrateur, monkeypatch):
        class ReponseOk:
            status_code = 200

            def json(self):
                return {"rule_id": "cadre-dis-001", "query": "event.code:1"}

        monkeypatch.setattr("requests.get", lambda *a, **k: ReponseOk())
        resultat = orchestrateur.lire_regle_kibana("cadre-dis-001")
        assert resultat == {"rule_id": "cadre-dis-001", "query": "event.code:1"}

    def test_404_retourne_none(self, orchestrateur, monkeypatch):
        class Reponse404:
            status_code = 404
            text = '{"message": "not found"}'

        monkeypatch.setattr("requests.get", lambda *a, **k: Reponse404())
        assert orchestrateur.lire_regle_kibana("cadre-inconnu") is None

    def test_erreur_http_retourne_none(self, orchestrateur, monkeypatch):
        class Reponse500:
            status_code = 500
            text = "erreur interne"

        monkeypatch.setattr("requests.get", lambda *a, **k: Reponse500())
        assert orchestrateur.lire_regle_kibana("cadre-dis-001") is None

    def test_exception_reseau_retourne_none(self, orchestrateur, monkeypatch):
        def get_qui_echoue(*a, **k):
            raise ConnectionError("Kibana injoignable")

        monkeypatch.setattr("requests.get", get_qui_echoue)
        assert orchestrateur.lire_regle_kibana("cadre-dis-001") is None

    def test_parametres_de_requete_corrects(self, orchestrateur, monkeypatch):
        appels = []

        class ReponseOk:
            status_code = 200

            def json(self):
                return {}

        def get_trace(url, headers, auth, verify, timeout, params):
            appels.append((headers, params))
            return ReponseOk()

        monkeypatch.setattr("requests.get", get_trace)
        orchestrateur.lire_regle_kibana("cadre-dis-001")
        headers, params = appels[0]
        assert headers["kbn-xsrf"] == "true"
        assert params == {"rule_id": "cadre-dis-001"}

    def test_rule_id_majuscule_est_normalise_en_minuscule(self, orchestrateur, monkeypatch):
        """Régression (audit, reproduite en réel CLI + dashboard) : les
        règles sont TOUJOURS déployées avec un rule_id en minuscules
        (`attaque.id.lower()`), mais l'ID catalogue affiché partout ailleurs
        (CLI, dashboard, rapports) est en MAJUSCULES ("CADRE-DIS-001").
        Kibana compare `rule_id` en sensible à la casse : taper l'ID tel
        qu'affiché échouait systématiquement en "règle introuvable" alors
        qu'elle est bien déployée."""
        appels = []

        class ReponseOk:
            status_code = 200

            def json(self):
                return {"rule_id": "cadre-dis-001"}

        def get_trace(url, headers, auth, verify, timeout, params):
            appels.append(params)
            return ReponseOk()

        monkeypatch.setattr("requests.get", get_trace)
        resultat = orchestrateur.lire_regle_kibana("CADRE-DIS-001")
        assert appels[0] == {"rule_id": "cadre-dis-001"}
        assert resultat == {"rule_id": "cadre-dis-001"}


class TestRedeployerRegleEditee:
    """Chantier 3 : édition d'une règle DÉJÀ vivante dans Kibana. Jamais de
    PUT si le rule_id est introuvable, si le type n'est pas 'query', ou si
    la revalidation échoue sans --forcer."""

    def _regle_actuelle(self):
        return {
            "name": "[CADRE] T1082 — Test",
            "description": "desc",
            "risk_score": 75,
            "severity": "low",
            "type": "query",
            "query": "event.code:1",
            "language": "lucene",
            "index": ["winlogbeat-*"],
            "interval": "5m",
            "from": "now-10m",
            "enabled": True,
            "tags": ["CADRE", "T1082"],
        }

    def _regle_yaml(self):
        return "title: Test\ndetection:\n  selection:\n    event.code: 1\n  condition: selection\n"

    def test_rule_id_introuvable_erreur_sans_reseau(self, orchestrateur, monkeypatch):
        monkeypatch.setattr(orchestrateur, "lire_regle_kibana", lambda rid: None)

        def put_qui_leve(*a, **k):
            raise AssertionError("aucun PUT ne doit être tenté")

        monkeypatch.setattr("requests.put", put_qui_leve)
        resultat = orchestrateur.redeployer_regle_editee("cadre-inconnu", self._regle_yaml())
        assert resultat["statut"] == "ERREUR"
        assert "introuvable" in resultat["raison"]
        assert resultat["deploye"] is False

    def test_type_non_query_refuse(self, orchestrateur, monkeypatch):
        """Une règle de séquence EQL de scénario (cadre-sequence-*) n'est
        pas éditable par ce mécanisme -- refus explicite."""
        regle_eql = {**self._regle_actuelle(), "type": "eql"}
        monkeypatch.setattr(orchestrateur, "lire_regle_kibana", lambda rid: regle_eql)

        def put_qui_leve(*a, **k):
            raise AssertionError("aucun PUT ne doit être tenté")

        monkeypatch.setattr("requests.put", put_qui_leve)
        resultat = orchestrateur.redeployer_regle_editee(
            "cadre-sequence-ransomware", self._regle_yaml()
        )
        assert resultat["statut"] == "ERREUR"
        assert "eql" in resultat["raison"].lower()

    def test_payload_reprend_uniquement_les_champs_autorises_et_tag_ajoute(
        self, orchestrateur, monkeypatch
    ):
        monkeypatch.setattr(orchestrateur, "lire_regle_kibana", lambda rid: self._regle_actuelle())
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:1"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp", lambda **k: (True, "OK", 2, 3)
        )
        appels = []

        class ReponsePut:
            status_code = 200

            def json(self):
                return {"id": "abc"}

        def put_trace(url, headers, auth, json, verify, timeout):
            appels.append(json)
            return ReponsePut()

        monkeypatch.setattr("requests.put", put_trace)
        resultat = orchestrateur.redeployer_regle_editee("cadre-dis-001", self._regle_yaml())
        assert resultat["statut"] == "VALIDE"
        assert resultat["deploye"] is True
        payload = appels[0]
        # Champs autorisés repris du GET :
        assert payload["name"] == "[CADRE] T1082 — Test"
        assert payload["risk_score"] == 75
        assert payload["severity"] == "low"
        assert payload["index"] == ["winlogbeat-*"]
        assert payload["rule_id"] == "cadre-dis-001"
        # Champs en lecture seule JAMAIS repris :
        assert "id" not in payload
        assert "created_at" not in payload
        assert "revision" not in payload
        # Tag de traçabilité ajouté, tags existants conservés :
        assert set(payload["tags"]) == {"CADRE", "T1082", "CADRE-EDIT-MANUEL"}

    def test_rule_id_majuscule_edite_la_regle_existante_pas_un_doublon(
        self, orchestrateur, monkeypatch
    ):
        """Régression (audit, reproduite en réel) : sans normalisation, un
        appel avec l'ID catalogue tel qu'affiché ("CADRE-DIS-001") aurait
        d'abord échoué à trouver la règle existante (voir
        TestLireRegleKibana), et si ce garde-fou n'existait pas non plus
        ici, le payload PUT aurait porté "rule_id": "CADRE-DIS-001" -- un
        identifiant DIFFÉRENT de la règle réellement déployée
        ("cadre-dis-001"), créant une règle en double dans Kibana au lieu
        d'éditer l'existante. Ne mocke PAS lire_regle_kibana directement
        (contrairement aux autres tests de cette classe) : passe par
        requests.get réel pour que la normalisation interne soit
        effectivement exercée."""

        class ReponseGet:
            status_code = 200

            def json(self):
                return self.contenu

            def __init__(self, contenu):
                self.contenu = contenu

        appels_get = []
        appels_put = []

        def get_trace(url, headers, auth, verify, timeout, params):
            appels_get.append(params)
            return ReponseGet(self._regle_actuelle())

        class ReponsePut:
            status_code = 200

            def json(self):
                return {"id": "abc"}

        def put_trace(url, headers, auth, json, verify, timeout):
            appels_put.append(json)
            return ReponsePut()

        monkeypatch.setattr("requests.get", get_trace)
        monkeypatch.setattr("requests.put", put_trace)
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:1"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp", lambda **k: (True, "OK", 2, 3)
        )
        resultat = orchestrateur.redeployer_regle_editee("CADRE-DIS-001", self._regle_yaml())
        assert resultat["statut"] == "VALIDE"
        assert resultat["deploye"] is True
        assert appels_get[0] == {"rule_id": "cadre-dis-001"}
        assert appels_put[0]["rule_id"] == "cadre-dis-001"

    def test_echec_revalidation_sans_forcer_aucun_put(self, orchestrateur, monkeypatch):
        monkeypatch.setattr(orchestrateur, "lire_regle_kibana", lambda rid: self._regle_actuelle())
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:1"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp",
            lambda **k: (False, "FAUX_NEGATIF", 0, 0),
        )

        def put_qui_leve(*a, **k):
            raise AssertionError("aucun PUT ne doit être tenté")

        monkeypatch.setattr("requests.put", put_qui_leve)
        resultat = orchestrateur.redeployer_regle_editee("cadre-dis-001", self._regle_yaml())
        assert resultat["statut"] == "REJETE"
        assert resultat["deploye"] is False

    def test_echec_revalidation_avec_forcer_deploie_et_log(self, orchestrateur, monkeypatch):
        monkeypatch.setattr(orchestrateur, "lire_regle_kibana", lambda rid: self._regle_actuelle())
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:1"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp",
            lambda **k: (False, "FAUX_NEGATIF", 0, 0),
        )
        appels = []
        monkeypatch.setattr("requests.put", lambda *a, **k: appels.append(1) or _ReponsePut200())
        evenements = []
        monkeypatch.setattr(
            orchestrateur.log,
            "evenement",
            lambda type_evt, msg, niveau="INFO", **k: evenements.append((type_evt, k)),
        )
        resultat = orchestrateur.redeployer_regle_editee(
            "cadre-dis-001", self._regle_yaml(), forcer=True
        )
        assert resultat["deploye"] is True
        assert resultat["force"] is True
        assert appels == [1]
        assert any(t == "RULE_MANUAL_EDIT_FORCED" for t, _ in evenements)

    def test_edition_reussie_log_rule_manual_edit(self, orchestrateur, monkeypatch):
        monkeypatch.setattr(orchestrateur, "lire_regle_kibana", lambda rid: self._regle_actuelle())
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:1"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp", lambda **k: (True, "OK", 1, 0)
        )
        monkeypatch.setattr("requests.put", lambda *a, **k: _ReponsePut200())
        evenements = []
        monkeypatch.setattr(
            orchestrateur.log,
            "evenement",
            lambda type_evt, msg, niveau="INFO", **k: evenements.append((type_evt, k)),
        )
        orchestrateur.redeployer_regle_editee("cadre-dis-001", self._regle_yaml())
        assert any(t == "RULE_MANUAL_EDIT" for t, _ in evenements)

    def test_query_avec_antislash_preservee_telle_quelle(self, orchestrateur, monkeypatch):
        """Même régression que TestDeployerKibana, mais sur le second endroit
        où le payload Kibana est construit (édition d'une règle déjà déployée)."""
        requete_avec_antislash = r"process.command_line:*save\ HKLM\\SAM*"
        monkeypatch.setattr(orchestrateur, "lire_regle_kibana", lambda rid: self._regle_actuelle())
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene",
            lambda *a, **k: requete_avec_antislash,
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp", lambda **k: (True, "OK", 1, 0)
        )
        appels = []

        def put_trace(url, headers, auth, json, verify, timeout):
            appels.append(json)
            return _ReponsePut200()

        monkeypatch.setattr("requests.put", put_trace)
        orchestrateur.redeployer_regle_editee("cadre-dis-001", self._regle_yaml())

        payload_envoye = appels[0]
        assert payload_envoye["query"] == requete_avec_antislash
        assert payload_envoye["language"] == "lucene"

    def test_yaml_non_compilable_erreur_sans_reseau(self, orchestrateur, monkeypatch):
        monkeypatch.setattr(orchestrateur, "lire_regle_kibana", lambda rid: self._regle_actuelle())
        monkeypatch.setattr("cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: None)

        def put_qui_leve(*a, **k):
            raise AssertionError("aucun PUT ne doit être tenté")

        monkeypatch.setattr("requests.put", put_qui_leve)
        resultat = orchestrateur.redeployer_regle_editee("cadre-dis-001", self._regle_yaml())
        assert resultat["statut"] == "ERREUR"


class _ReponsePut200:
    status_code = 200

    def json(self):
        return {"id": "abc"}


class TestSequenceKillChain:
    """Corrélation EQL entre étapes d'un scénario détectées (au-delà de la
    dédup par nom de B7) : `construire_sequence_eql`, `deployer_kibana_sequence`,
    et le regroupement en tronçons de `_deployer_sequences_kill_chain`."""

    def _scenario(self, ids):
        return ScenarioAdversaire(
            id="TESTSCENARIO",
            nom="Scénario de test",
            adversaire="Testeur",
            description="d",
            plateforme="windows",
            attaque_ids=ids,
        )

    def test_construire_sequence_eql_avec_valeur_detection(self, exemple_attaque):
        requete = construire_sequence_eql([exemple_attaque], maxspan_min=15)
        assert requete == (
            "sequence by host.name with maxspan=15m\n"
            '  [process where event.code == "1" and '
            'process.command_line : "*CADRE_TEST_MARKER*"]'
        )

    def test_construire_sequence_eql_sans_valeur_detection(self, exemple_attaque):
        attaque = dataclasses.replace(exemple_attaque, valeur_detection=None)
        requete = construire_sequence_eql([attaque], maxspan_min=10)
        assert (
            requete == 'sequence by host.name with maxspan=10m\n  [process where event.code == "1"]'
        )

    def test_construire_sequence_eql_echappe_guillemet_litteral(self, exemple_attaque):
        """Régression : CADRE-DIS-005 a `valeur_detection='NETSTAT.EXE" -ano'`
        (même convention de chemin quoté que Sigma). Un `"` non échappé casse
        la chaîne EQL (confirmé HTTP 400 `parsing_exception` sur le vrai
        déploiement RECONNAISSANCE avant ce correctif) -- doit produire `\\"`."""
        attaque = dataclasses.replace(exemple_attaque, valeur_detection='NETSTAT.EXE" -ano')
        requete = construire_sequence_eql([attaque], maxspan_min=10)
        assert 'process.command_line : "*NETSTAT.EXE\\" -ano*"]' in requete
        assert '*NETSTAT.EXE" -ano*' not in requete  # jamais le guillemet nu

    def test_construire_sequence_eql_plusieurs_etapes(self, exemple_attaque):
        a2 = dataclasses.replace(exemple_attaque, id="CADRE-TEST-002", valeur_detection="AUTRE")
        requete = construire_sequence_eql([exemple_attaque, a2], maxspan_min=20)
        assert requete.startswith("sequence by host.name with maxspan=20m\n")
        assert '"*CADRE_TEST_MARKER*"' in requete
        assert '"*AUTRE*"' in requete
        assert requete.count("[process where") == 2

    def test_deployer_kibana_sequence_payload(self, orchestrateur, exemple_attaque, monkeypatch):
        scenario = self._scenario([exemple_attaque.id])
        capture: dict = {}

        class ReponseOk:
            status_code = 200

            def json(self):
                return {"id": "abc"}

        def put_trace(url, headers, auth, json, verify, timeout):
            capture.update(json)
            return ReponseOk()

        monkeypatch.setattr("requests.put", put_trace)
        ok = orchestrateur.deployer_kibana_sequence(scenario, [exemple_attaque], maxspan_min=20)
        assert ok is True
        assert capture["type"] == "eql"
        assert capture["language"] == "eql"
        assert capture["rule_id"] == "cadre-sequence-testscenario"
        assert "sequence by host.name with maxspan=20m" in capture["query"]
        assert "CADRE-SEQUENCE" in capture["tags"]

    def test_deployer_kibana_sequence_suffixe_rule_id(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        scenario = self._scenario([exemple_attaque.id])
        capture: dict = {}
        monkeypatch.setattr(
            "requests.put",
            lambda url, headers, auth, json, verify, timeout: capture.update(json)
            or type("R", (), {"status_code": 200, "json": lambda self: {"id": "x"}})(),
        )
        orchestrateur.deployer_kibana_sequence(
            scenario, [exemple_attaque], maxspan_min=10, suffixe_id="-2"
        )
        assert capture["rule_id"] == "cadre-sequence-testscenario-2"
        assert "TESTSCENARIO-2" in capture["name"]

    def _resultat(self, id_, minute):
        return {"id": id_, "timestamp": f"2026-08-10T10:{minute:02d}:00"}

    def test_deployer_sequences_un_seul_troncon_sans_suffixe(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        a1 = dataclasses.replace(exemple_attaque, id="A1")
        a2 = dataclasses.replace(exemple_attaque, id="A2")
        a3 = dataclasses.replace(exemple_attaque, id="A3")
        scenario = self._scenario(["A1", "A2", "A3"])
        orchestrateur.resultats = [
            self._resultat("A1", 0),
            self._resultat("A2", 2),
            self._resultat("A3", 5),
        ]
        analyse = {
            "etapes": [
                {"id": "A1", "detectee": True},
                {"id": "A2", "detectee": True},
                {"id": "A3", "detectee": True},
            ]
        }
        appels = []
        monkeypatch.setattr(
            orchestrateur,
            "deployer_kibana_sequence",
            lambda scenario, troncon, maxspan_min, suffixe_id="": appels.append(
                ([a.id for a in troncon], maxspan_min, suffixe_id)
            ),
        )
        orchestrateur._deployer_sequences_kill_chain(scenario, [a1, a2, a3], analyse)
        assert len(appels) == 1
        ids, maxspan_min, suffixe = appels[0]
        assert ids == ["A1", "A2", "A3"]
        assert suffixe == ""
        assert maxspan_min >= 10  # marge minimale garantie

    def test_deployer_sequences_angle_mort_coupe_en_deux_troncons(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        ids = ["A1", "A2", "A3", "A4", "A5"]
        attaques = [dataclasses.replace(exemple_attaque, id=i) for i in ids]
        scenario = self._scenario(ids)
        orchestrateur.resultats = [
            self._resultat(i, m) for i, m in zip(ids, [0, 1, 2, 3, 4], strict=True)
        ]
        analyse = {
            "etapes": [
                {"id": "A1", "detectee": True},
                {"id": "A2", "detectee": True},
                {"id": "A3", "detectee": False},  # angle mort : coupe la séquence
                {"id": "A4", "detectee": True},
                {"id": "A5", "detectee": True},
            ]
        }
        appels = []
        monkeypatch.setattr(
            orchestrateur,
            "deployer_kibana_sequence",
            lambda scenario, troncon, maxspan_min, suffixe_id="": appels.append(
                ([a.id for a in troncon], suffixe_id)
            ),
        )
        orchestrateur._deployer_sequences_kill_chain(scenario, attaques, analyse)
        assert len(appels) == 2
        assert appels[0] == (["A1", "A2"], "-1")
        assert appels[1] == (["A4", "A5"], "-2")

    def test_deployer_sequences_ignore_troncons_isoles(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        """Une étape détectée isolée (voisins en angle mort) ne suffit pas à
        former une séquence -- EQL `sequence` exige au moins 2 événements."""
        ids = ["A1", "A2", "A3", "A4"]
        attaques = [dataclasses.replace(exemple_attaque, id=i) for i in ids]
        scenario = self._scenario(ids)
        orchestrateur.resultats = [
            self._resultat(i, m) for i, m in zip(ids, [0, 1, 2, 3], strict=True)
        ]
        analyse = {
            "etapes": [
                {"id": "A1", "detectee": True},
                {"id": "A2", "detectee": False},
                {"id": "A3", "detectee": True},
                {"id": "A4", "detectee": False},
            ]
        }
        appels = []
        monkeypatch.setattr(
            orchestrateur,
            "deployer_kibana_sequence",
            lambda *a, **k: appels.append((a, k)),
        )
        orchestrateur._deployer_sequences_kill_chain(scenario, attaques, analyse)
        assert appels == []

    def test_executer_scenario_deploie_sequences_en_reel_windows(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        scenario = self._scenario([exemple_attaque.id])
        monkeypatch.setattr(orchestrateur, "_boucle_attaques", lambda *a, **k: None)
        monkeypatch.setattr(orchestrateur, "_generer_rapports_fin_cycle", lambda *a, **k: None)
        monkeypatch.setattr(
            "cadre.orchestrateur.analyser_kill_chain",
            lambda scenario, resultats, **k: {
                "etapes_detectees": 0,
                "total_etapes": 0,
                "etapes": [],
            },
        )
        appels = []
        monkeypatch.setattr(
            orchestrateur, "_deployer_sequences_kill_chain", lambda *a, **k: appels.append(a)
        )
        orchestrateur.executer_scenario(scenario, mode_simulation=False)
        assert len(appels) == 1

    def test_deuxieme_appel_ne_cumule_pas_les_resultats_du_premier(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        """Régression sécurité (audit) « resultats non réinitialisés » :
        même raisonnement que pour executer_cycle_complet -- self.resultats
        n'était jamais remis à zéro entre deux appels à executer_scenario()
        sur la même instance d'orchestrateur (_boucle_attaques ne fait
        qu'append)."""
        scenario = self._scenario([exemple_attaque.id])

        def boucle_qui_ajoute_un_resultat(attaques, mode_simulation, **k):
            orchestrateur.resultats.append({"id": "quelconque", "statut": "SIMULE"})

        monkeypatch.setattr(orchestrateur, "_boucle_attaques", boucle_qui_ajoute_un_resultat)
        monkeypatch.setattr(orchestrateur, "_generer_rapports_fin_cycle", lambda *a, **k: None)

        orchestrateur.executer_scenario(scenario, mode_simulation=True)
        assert len(orchestrateur.resultats) == 1
        orchestrateur.executer_scenario(scenario, mode_simulation=True)
        assert len(orchestrateur.resultats) == 1  # pas 2 (accumulation avec le 1er appel)

    def test_executer_scenario_ne_deploie_pas_en_simulation(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        scenario = self._scenario([exemple_attaque.id])
        monkeypatch.setattr(orchestrateur, "_boucle_attaques", lambda *a, **k: None)
        monkeypatch.setattr(orchestrateur, "_generer_rapports_fin_cycle", lambda *a, **k: None)
        monkeypatch.setattr(
            "cadre.orchestrateur.analyser_kill_chain",
            lambda scenario, resultats, **k: {
                "etapes_detectees": 0,
                "total_etapes": 0,
                "etapes": [],
            },
        )
        appels = []
        monkeypatch.setattr(
            orchestrateur, "_deployer_sequences_kill_chain", lambda *a, **k: appels.append(a)
        )
        orchestrateur.executer_scenario(scenario, mode_simulation=True)
        assert appels == []

    def test_executer_scenario_ne_deploie_pas_pour_linux(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        scenario = dataclasses.replace(self._scenario([exemple_attaque.id]), plateforme="linux")
        monkeypatch.setattr(orchestrateur, "_boucle_attaques", lambda *a, **k: None)
        monkeypatch.setattr(orchestrateur, "_generer_rapports_fin_cycle", lambda *a, **k: None)
        monkeypatch.setattr(
            "cadre.orchestrateur.analyser_kill_chain",
            lambda scenario, resultats, **k: {
                "etapes_detectees": 0,
                "total_etapes": 0,
                "etapes": [],
            },
        )
        appels = []
        monkeypatch.setattr(
            orchestrateur, "_deployer_sequences_kill_chain", lambda *a, **k: appels.append(a)
        )
        orchestrateur.executer_scenario(scenario, mode_simulation=False)
        assert appels == []


class TestExecuterAttaqueComplete:
    @pytest.fixture(autouse=True)
    def _cible_joignable(self, orchestrateur, monkeypatch):
        """Ces tests exercent le pipeline APRÈS confirmation que la cible est
        joignable ; on neutralise le pré-vol de connectivité (testé à part dans
        TestPreVolJoignabilite)."""
        monkeypatch.setattr(orchestrateur, "_cible_joignable", lambda cible: True)

    def test_echec_winrm(self, orchestrateur, exemple_attaque, monkeypatch):
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: False)
        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert resultat["statut"] == "ERREUR"
        # Message générique désormais : "Échec exécution (windows)".
        assert "exécution" in resultat["raison"] and "windows" in resultat["raison"]

    # --- Pré-vol de joignabilité : NON_APPLICABLE au lieu d'ERREUR (AUDIT-DASH/1a) ---
    def test_cible_injoignable_est_non_applicable(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        # VM éteinte (pré-vol échoue) : ne doit JAMAIS tenter l'exécution.
        # (surcharge l'autouse _cible_joignable=True pour ce cas précis)
        appels = []
        monkeypatch.setattr(orchestrateur, "_cible_joignable", lambda cible: False)
        monkeypatch.setattr(
            orchestrateur, "executer_commande_winrm", lambda *a, **k: appels.append(1) or True
        )
        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert resultat["statut"] == "NON_APPLICABLE"
        assert "injoignable" in resultat["raison"]
        assert appels == []  # exécution jamais tentée

    def test_requires_internet_host_only_est_non_applicable(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        appels = []
        monkeypatch.setattr(orchestrateur, "_cible_joignable", lambda cible: True)
        monkeypatch.setattr(
            orchestrateur, "executer_commande_winrm", lambda *a, **k: appels.append(1) or True
        )
        attaque_net = dataclasses.replace(exemple_attaque, requires_internet=True)
        resultat = orchestrateur.executer_attaque_complete(attaque_net)
        assert resultat["statut"] == "NON_APPLICABLE"
        assert "Internet" in resultat["raison"]
        assert appels == []  # jamais exécutée (VM host-only par défaut)

    def test_plateforme_incompatible_non_applicable_sans_toucher_winrm(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        """Une attaque Linux contre une cible Windows configurée est
        NON_APPLICABLE et ne doit jamais appeler executer_commande_winrm."""
        from cadre.catalogue_attaques import Plateforme

        appels_winrm = []
        monkeypatch.setattr(
            orchestrateur,
            "executer_commande_winrm",
            lambda *a, **k: appels_winrm.append(1) or True,
        )
        attaque_linux = dataclasses.replace(exemple_attaque, plateforme=Plateforme.LINUX)
        resultat = orchestrateur.executer_attaque_complete(attaque_linux)
        assert resultat["statut"] == "NON_APPLICABLE"
        assert appels_winrm == []

    def test_plateforme_mixte_toujours_applicable(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        """Une attaque 'both' reste applicable quelle que soit la cible."""
        from cadre.catalogue_attaques import Plateforme

        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: False)
        attaque_mixte = dataclasses.replace(exemple_attaque, plateforme=Plateforme.MIXTE)
        resultat = orchestrateur.executer_attaque_complete(attaque_mixte)
        assert resultat["statut"] == "ERREUR"  # a bien tenté WinRM, pas NON_APPLICABLE

    def test_angle_mort_quand_log_non_trouve(self, orchestrateur, exemple_attaque, monkeypatch):
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr("cadre.orchestrateur.attendre_indexation", lambda **k: None)
        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert resultat["statut"] == "ANGLE_MORT"

    def test_generation_sigma_echouee(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )

        def generation_qui_echoue(*a, **k):
            raise ValueError("template invalide")

        monkeypatch.setattr(
            orchestrateur, "generer_regle_sigma_depuis_attaque", generation_qui_echoue
        )
        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert resultat["statut"] == "ERREUR"
        assert "Sigma" in resultat["raison"]

    def test_compilation_echouee(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )
        monkeypatch.setattr("cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: None)
        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert resultat["statut"] == "ERREUR"
        assert "Compilation Sigma" in resultat["raison"]

    def test_seuil_fp_par_attaque_prime_sur_le_seuil_global(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        """attaque.seuil_fp_max (ex: CADRE-EXE-001, baseline volontairement
        bruyant) doit être transmis à double_validation_tp_fp() à la place
        du seuil global de la config."""
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:4688"
        )
        seuils_recus = []

        def double_validation_factice(**kwargs):
            seuils_recus.append(kwargs["seuil_fp"])
            return True, "OK", 1, 0

        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp", double_validation_factice
        )
        monkeypatch.setattr(orchestrateur, "deployer_kibana", lambda **k: True)
        attaque_seuil_haut = dataclasses.replace(exemple_attaque, seuil_fp_max=5000)
        orchestrateur.executer_attaque_complete(attaque_seuil_haut)
        assert seuils_recus == [5000]

    def test_rejete_par_double_validation(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:4688"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp",
            lambda **k: (False, "Trop de faux positifs", 0, 60),
        )
        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert resultat["statut"] == "REJETE"
        assert resultat["nb_fp"] == 60

    def test_panne_elasticsearch_pendant_validation_est_erreur_pas_rejete(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        """Régression sécurité : une panne ES pendant la double validation ne
        doit jamais se lire comme "REJETE" (verdict sur la règle) -- c'est une
        mesure impossible, distincte d'une vraie règle mauvaise."""
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:4688"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp",
            lambda **k: (False, "ERREUR_ELASTICSEARCH", 0, 0),
        )
        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert resultat["statut"] == "ERREUR"
        assert resultat["raison"] == "ERREUR_ELASTICSEARCH"

    def test_valide_et_deploye(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:4688"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp",
            lambda **k: (True, "OK", 3, 0),
        )
        monkeypatch.setattr(orchestrateur, "deployer_kibana", lambda **k: True)
        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert resultat["statut"] == "VALIDE"

    def test_generateur_deterministe_par_defaut(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:1"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp", lambda **k: (True, "OK", 3, 0)
        )
        monkeypatch.setattr(orchestrateur, "deployer_kibana", lambda **k: True)
        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert resultat["generateur_regle"] == "deterministe"

    def test_mode_llm_deploie_la_regle_llm_apres_la_meme_validation(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        orchestrateur.config["mode_generation_regle"] = "llm"
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:1"
        )
        validations = []

        def validation_factice(**kwargs):
            validations.append(kwargs["requete_lucene"])
            return True, "OK", 2, 0

        monkeypatch.setattr("cadre.orchestrateur.double_validation_tp_fp", validation_factice)
        monkeypatch.setattr(orchestrateur, "deployer_kibana", lambda **k: True)

        class AssistantFactice:
            def suggerer_regle_sigma_deployable(self, log, contexte):
                return "title: Règle LLM\ndetection:\n  selection:\n    event.code: 1\n"

        import cadre.assistant_llm as m

        monkeypatch.setattr(m, "obtenir_assistant_llm", AssistantFactice)

        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert resultat["generateur_regle"] == "llm"
        assert "Règle LLM" in resultat["regle_sigma_yaml"]
        assert resultat["statut"] == "VALIDE"
        # La règle LLM est bien passée par la validation TP/FP (même barrière)
        assert validations, "la validation TP/FP doit avoir été appelée sur la règle LLM"

    def test_mode_llm_repli_deterministe_si_llm_vide(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        orchestrateur.config["mode_generation_regle"] = "llm"
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:1"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp", lambda **k: (True, "OK", 1, 0)
        )
        monkeypatch.setattr(orchestrateur, "deployer_kibana", lambda **k: True)

        class AssistantVide:
            def suggerer_regle_sigma_deployable(self, log, contexte):
                return None  # LLM injoignable / réponse inexploitable

        import cadre.assistant_llm as m

        monkeypatch.setattr(m, "obtenir_assistant_llm", AssistantVide)

        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert "repli" in resultat["generateur_regle"]
        assert resultat["statut"] == "VALIDE"  # l'attaque réussit malgré le LLM vide

    def test_mode_llm_repli_si_regle_llm_ne_compile_pas(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        orchestrateur.config["mode_generation_regle"] = "llm"
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )
        # 1re compilation (règle LLM) échoue → None ; 2e (déterministe) réussit.
        compilations = iter([None, "event.code:1"])
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: next(compilations)
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp", lambda **k: (True, "OK", 1, 0)
        )
        monkeypatch.setattr(orchestrateur, "deployer_kibana", lambda **k: True)

        class AssistantMauvais:
            def suggerer_regle_sigma_deployable(self, log, contexte):
                return "ceci n'est pas du Sigma valide"

        import cadre.assistant_llm as m

        monkeypatch.setattr(m, "obtenir_assistant_llm", AssistantMauvais)

        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert resultat["generateur_regle"] == "deterministe (repli après échec LLM)"
        assert resultat["statut"] == "VALIDE"

    def test_mode_llm_repli_si_assistant_leve_une_exception(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        """`_generer_regle_candidate` doit rester "jamais fatal" même si
        `suggerer_regle_sigma_deployable` LÈVE (pas juste retourne None) --
        ex. Ollama coupe la connexion en plein appel. Seul le cas "retourne
        None" était testé jusqu'ici (`except Exception` jamais exercé)."""
        orchestrateur.config["mode_generation_regle"] = "llm"
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:1"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp", lambda **k: (True, "OK", 1, 0)
        )
        monkeypatch.setattr(orchestrateur, "deployer_kibana", lambda **k: True)

        class AssistantQuiExplose:
            def suggerer_regle_sigma_deployable(self, log, contexte):
                raise ConnectionError("Ollama a coupé la connexion en plein appel")

        import cadre.assistant_llm as m

        monkeypatch.setattr(m, "obtenir_assistant_llm", AssistantQuiExplose)

        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert resultat["generateur_regle"] == "deterministe (repli après échec LLM)"
        assert resultat["statut"] == "VALIDE"

    def test_valide_mais_deploiement_kibana_echoue(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:4688"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp",
            lambda **k: (True, "OK", 3, 0),
        )
        monkeypatch.setattr(orchestrateur, "deployer_kibana", lambda **k: False)
        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert resultat["statut"] == "VALIDE_NON_DEPLOYE"

    def test_brouillon_ia_absent_par_defaut(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        """ia_brouillon_regle=False (défaut) : jamais d'appel à l'assistant IA."""
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:4688"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp",
            lambda **k: (True, "OK", 3, 0),
        )
        monkeypatch.setattr(orchestrateur, "deployer_kibana", lambda **k: True)
        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert "regle_sigma_ia_brouillon" not in resultat

    def test_brouillon_ia_active_appelle_l_assistant_et_sauvegarde(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        orchestrateur.config["ia_brouillon_regle"] = True
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:4688"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp",
            lambda **k: (True, "OK", 3, 0),
        )
        monkeypatch.setattr(orchestrateur, "deployer_kibana", lambda **k: True)

        class AssistantFactice:
            def suggerer_regle_sigma(self, log_anonymise, contexte):
                assert contexte["technique_mitre"] == exemple_attaque.technique_mitre
                return "title: brouillon\n"

        import cadre.assistant_llm as assistant_llm_module

        monkeypatch.setattr(assistant_llm_module, "obtenir_assistant_llm", AssistantFactice)

        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert resultat["regle_sigma_ia_brouillon"] == "title: brouillon\n"
        chemin = (
            orchestrateur.config["repertoire_regles"]
            / "brouillons_ia"
            / f"{exemple_attaque.id}.ia.yml"
        )
        assert chemin.read_text(encoding="utf-8") == "title: brouillon\n"

    def test_brouillon_ia_panne_ollama_ne_casse_pas_le_pipeline(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        """Une panne de l'assistant IA ne doit jamais faire échouer l'attaque :
        c'est purement additif, jamais dans le chemin critique."""
        orchestrateur.config["ia_brouillon_regle"] = True
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:4688"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp",
            lambda **k: (True, "OK", 3, 0),
        )
        monkeypatch.setattr(orchestrateur, "deployer_kibana", lambda **k: True)

        def assistant_qui_explose():
            raise RuntimeError("Ollama injoignable")

        import cadre.assistant_llm as assistant_llm_module

        monkeypatch.setattr(assistant_llm_module, "obtenir_assistant_llm", assistant_qui_explose)

        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert resultat["statut"] == "VALIDE"
        assert resultat["regle_sigma_ia_brouillon"] is None


class TestArreterAvantDeploiement:
    """Revue avant déploiement : arreter_avant_deploiement=True doit
    s'arrêter juste après la validation TP/FP, ne JAMAIS appeler
    deployer_kibana(), et enregistrer une entrée de revue à la place."""

    @pytest.fixture(autouse=True)
    def _cible_joignable(self, orchestrateur, monkeypatch):
        monkeypatch.setattr(orchestrateur, "_cible_joignable", lambda cible: True)

    def _preparer_pipeline_reussi(
        self, orchestrateur, log_elastic_exemple, monkeypatch, tp=3, fp=0
    ):
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:4688"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp", lambda **k: (True, "OK", tp, fp)
        )

    def _deployer_qui_leve(self, **k):
        raise AssertionError("deployer_kibana ne doit jamais être appelé")

    def test_ne_deploie_jamais_statut_en_attente_revue(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        self._preparer_pipeline_reussi(orchestrateur, log_elastic_exemple, monkeypatch)
        monkeypatch.setattr(orchestrateur, "deployer_kibana", self._deployer_qui_leve)
        resultat = orchestrateur.executer_attaque_complete(
            exemple_attaque, arreter_avant_deploiement=True
        )
        assert resultat["statut"] == "EN_ATTENTE_REVUE"
        assert resultat["rule_id_stable"] == exemple_attaque.id.lower()

    def test_entree_de_revue_creee_avec_les_bons_champs(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        self._preparer_pipeline_reussi(orchestrateur, log_elastic_exemple, monkeypatch, tp=3, fp=2)
        monkeypatch.setattr(orchestrateur, "deployer_kibana", self._deployer_qui_leve)
        orchestrateur.executer_attaque_complete(
            exemple_attaque, arreter_avant_deploiement=True, source_revue="decouvrir"
        )
        from cadre.revue_regles import charger_revues

        entree = charger_revues()[exemple_attaque.id.lower()]
        assert entree["attaque_id"] == exemple_attaque.id
        assert entree["nb_tp"] == 3
        assert entree["nb_fp"] == 2
        assert entree["source"] == "decouvrir"
        assert entree["requete_lucene_derniere_validation"] == "event.code:4688"

    def test_fichier_regle_sigma_existe_sur_disque(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        self._preparer_pipeline_reussi(orchestrateur, log_elastic_exemple, monkeypatch)
        monkeypatch.setattr(orchestrateur, "deployer_kibana", self._deployer_qui_leve)
        orchestrateur.executer_attaque_complete(exemple_attaque, arreter_avant_deploiement=True)
        from cadre.revue_regles import obtenir_revue

        entree = obtenir_revue(exemple_attaque.id.lower())
        assert entree is not None
        assert Path(entree["chemin_regle_sigma"]).is_file()

    def test_rejete_ne_cree_jamais_dentree(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        monkeypatch.setattr(orchestrateur, "executer_commande_winrm", lambda *a, **k: True)
        monkeypatch.setattr(
            "cadre.orchestrateur.attendre_indexation", lambda **k: log_elastic_exemple
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:4688"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp",
            lambda **k: (False, "TROP_DE_FP:100>50", 0, 100),
        )
        resultat = orchestrateur.executer_attaque_complete(
            exemple_attaque, arreter_avant_deploiement=True
        )
        assert resultat["statut"] == "REJETE"
        from cadre.revue_regles import charger_revues

        assert charger_revues() == {}

    def test_defaut_false_comportement_inchange(
        self, orchestrateur, exemple_attaque, log_elastic_exemple, monkeypatch
    ):
        self._preparer_pipeline_reussi(orchestrateur, log_elastic_exemple, monkeypatch)
        appels = []
        monkeypatch.setattr(orchestrateur, "deployer_kibana", lambda **k: appels.append(1) or True)
        resultat = orchestrateur.executer_attaque_complete(exemple_attaque)
        assert resultat["statut"] == "VALIDE"
        assert appels == [1]


class TestApprouverRevue:
    """Chantier 1 : approuver_revue relit le fichier Sigma référencé
    (potentiellement édité à la main), le revalide via
    _revalider_regle_editee, et déploie seulement si valide (ou forcé)."""

    def _entree(self, tmp_path, **surcharges):
        chemin_regle = tmp_path / "CADRE-IA-001.yml"
        chemin_regle.write_text(
            "title: Test\ndetection:\n  selection:\n    event.code: 1\n  condition: selection\n",
            encoding="utf-8",
        )
        base = {
            "rule_id_stable": "cadre-ia-001",
            "attaque_id": "CADRE-IA-001",
            "nom_regle": "[CADRE] T1082 — Test",
            "description": "desc",
            "technique_mitre": "T1082",
            "severite": "low",
            "index_pattern": "winlogbeat-*",
            "seuil_fp_max": 50,
            "chemin_regle_sigma": str(chemin_regle),
            "requete_lucene_derniere_validation": "event.code:1",
            "nb_tp": 2,
            "nb_fp": 3,
        }
        base.update(surcharges)
        return base

    def test_requete_inchangee_fp_ok_deploie(self, orchestrateur, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:1"
        )
        monkeypatch.setattr("cadre.orchestrateur.valider_bruit_seul", lambda **k: (True, "OK", 2))
        appels = []
        monkeypatch.setattr(orchestrateur, "deployer_kibana", lambda **k: appels.append(k) or True)
        resultat = orchestrateur.approuver_revue(self._entree(tmp_path))
        assert resultat["statut"] == "VALIDE"
        assert resultat["deploye"] is True
        assert len(appels) == 1
        assert appels[0]["rule_id_stable"] == "cadre-ia-001"

    def test_requete_inchangee_fp_depasse_rejete_sans_deploiement(
        self, orchestrateur, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:1"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.valider_bruit_seul",
            lambda **k: (False, "TROP_DE_FP:99>50", 99),
        )

        def deployer_qui_leve(**k):
            raise AssertionError("ne doit pas déployer")

        monkeypatch.setattr(orchestrateur, "deployer_kibana", deployer_qui_leve)
        resultat = orchestrateur.approuver_revue(self._entree(tmp_path))
        assert resultat["statut"] == "REJETE"
        assert resultat["deploye"] is False

    def test_requete_editee_echec_sans_forcer_rejete(self, orchestrateur, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene",
            lambda *a, **k: "event.code:1 AND process.name:autre.exe",
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp",
            lambda **k: (False, "FAUX_NEGATIF", 0, 0),
        )

        def deployer_qui_leve(**k):
            raise AssertionError("ne doit pas déployer")

        monkeypatch.setattr(orchestrateur, "deployer_kibana", deployer_qui_leve)
        resultat = orchestrateur.approuver_revue(self._entree(tmp_path))
        assert resultat["statut"] == "REJETE"
        assert resultat["force"] is False

    def test_requete_editee_echec_avec_forcer_deploie_et_log(
        self, orchestrateur, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene",
            lambda *a, **k: "event.code:1 AND process.name:autre.exe",
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp",
            lambda **k: (False, "FAUX_NEGATIF", 0, 0),
        )
        appels_deploiement = []
        monkeypatch.setattr(
            orchestrateur, "deployer_kibana", lambda **k: appels_deploiement.append(1) or True
        )
        evenements = []
        monkeypatch.setattr(
            orchestrateur.log,
            "evenement",
            lambda type_evt, msg, niveau="INFO", **k: evenements.append((type_evt, k)),
        )
        resultat = orchestrateur.approuver_revue(self._entree(tmp_path), forcer=True)
        assert resultat["deploye"] is True
        assert resultat["force"] is True
        assert appels_deploiement == [1]
        assert any(t == "RULE_MANUAL_EDIT_FORCED" for t, _ in evenements)

    def test_requete_inchangee_panne_elasticsearch_erreur_sans_deploiement(
        self, orchestrateur, tmp_path, monkeypatch
    ):
        """Requête inchangée (chemin valider_bruit_seul) : une panne ES ne
        doit jamais se lire comme "0 bruit" -- refus de déployer."""
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:1"
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.valider_bruit_seul",
            lambda **k: (False, "ERREUR_ELASTICSEARCH", 0),
        )

        def deployer_qui_leve(**k):
            raise AssertionError("ne doit pas déployer")

        monkeypatch.setattr(orchestrateur, "deployer_kibana", deployer_qui_leve)
        resultat = orchestrateur.approuver_revue(self._entree(tmp_path))
        assert resultat["statut"] == "ERREUR"
        assert resultat["deploye"] is False

    def test_requete_editee_panne_elasticsearch_refuse_meme_avec_forcer(
        self, orchestrateur, tmp_path, monkeypatch
    ):
        """Régression sécurité critique : contrairement à un vrai FAUX_NEGATIF
        (que `forcer=True` peut sciemment outrepasser), une mesure ES ratée ne
        prouve RIEN sur la règle -- `forcer` ne doit jamais permettre de
        déployer une règle jamais réellement validée."""
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene",
            lambda *a, **k: "event.code:1 AND process.name:autre.exe",
        )
        monkeypatch.setattr(
            "cadre.orchestrateur.double_validation_tp_fp",
            lambda **k: (False, "ERREUR_ELASTICSEARCH", 0, 0),
        )

        def deployer_qui_leve(**k):
            raise AssertionError("ne doit jamais déployer, même forcé")

        monkeypatch.setattr(orchestrateur, "deployer_kibana", deployer_qui_leve)
        resultat = orchestrateur.approuver_revue(self._entree(tmp_path), forcer=True)
        assert resultat["statut"] == "ERREUR"
        assert resultat["deploye"] is False

    def test_yaml_non_compilable_erreur_sans_reseau(self, orchestrateur, tmp_path, monkeypatch):
        monkeypatch.setattr("cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: None)

        def deployer_qui_leve(**k):
            raise AssertionError("ne doit jamais être appelé")

        monkeypatch.setattr(orchestrateur, "deployer_kibana", deployer_qui_leve)
        resultat = orchestrateur.approuver_revue(self._entree(tmp_path))
        assert resultat["statut"] == "ERREUR"

    def test_fichier_regle_introuvable_erreur(self, orchestrateur, tmp_path):
        entree = self._entree(tmp_path, chemin_regle_sigma=str(tmp_path / "inexistant.yml"))
        resultat = orchestrateur.approuver_revue(entree)
        assert resultat["statut"] == "ERREUR"
        assert "introuvable" in resultat["raison"]


class TestExecuterAttaqueSimulation:
    def test_simulation_avec_sigma_cli(self, orchestrateur, exemple_attaque, monkeypatch):
        monkeypatch.setattr(
            "cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: "event.code:4688"
        )
        resultat = orchestrateur._executer_attaque_simulation(exemple_attaque)
        assert resultat["statut"] == "SIMULE"
        assert resultat["nb_tp"] == 0
        assert resultat["nb_fp"] == 0
        regle_fichier = orchestrateur.config["repertoire_regles"] / f"{exemple_attaque.id}.yml"
        assert regle_fichier.exists()

    def test_simulation_sans_sigma_cli_utilise_fallback(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        monkeypatch.setattr("cadre.orchestrateur.compiler_sigma_vers_lucene", lambda *a, **k: None)
        resultat = orchestrateur._executer_attaque_simulation(exemple_attaque)
        assert resultat["statut"] == "SIMULE"
        assert f"CADRE_TEST_{exemple_attaque.id}" in resultat["requete_lucene"]

    def test_simulation_generation_sigma_echouee(self, orchestrateur, exemple_attaque, monkeypatch):
        def generation_qui_echoue(*a, **k):
            raise ValueError("boom")

        monkeypatch.setattr(
            orchestrateur, "generer_regle_sigma_depuis_attaque", generation_qui_echoue
        )
        resultat = orchestrateur._executer_attaque_simulation(exemple_attaque)
        assert resultat["statut"] == "ERREUR"


class TestGenererRapportsFinCycle:
    def test_aucun_resultat_ne_genere_rien(self, orchestrateur):
        orchestrateur.resultats = []
        orchestrateur._generer_rapports_fin_cycle()
        assert list(orchestrateur.config["repertoire_rapports"].iterdir()) == []

    def test_avec_resultats_genere_md_et_csv(self, orchestrateur):
        orchestrateur.resultats = [
            {
                "timestamp": "2026-07-30T00:00:00",
                "id": "CADRE-TEST-001",
                "technique_mitre": "T1059.001",
                "tactique": "Execution",
                "description": "Test",
                "statut": "VALIDE",
            }
        ]
        orchestrateur._generer_rapports_fin_cycle()
        fichiers = list(orchestrateur.config["repertoire_rapports"].iterdir())
        assert any(f.suffix == ".md" for f in fichiers)
        assert any(f.suffix == ".csv" for f in fichiers)

    def test_avec_resultats_genere_aussi_le_pdf(self, orchestrateur):
        orchestrateur.resultats = [
            {
                "timestamp": "2026-07-30T00:00:00",
                "id": "CADRE-TEST-001",
                "technique_mitre": "T1059.001",
                "tactique": "Execution",
                "description": "Test",
                "statut": "VALIDE",
            }
        ]
        orchestrateur._generer_rapports_fin_cycle()
        fichiers = list(orchestrateur.config["repertoire_rapports"].iterdir())
        assert any(f.suffix == ".pdf" for f in fichiers)

    def test_echec_generation_pdf_n_interrompt_pas_le_cycle(self, orchestrateur, monkeypatch):
        """Régression assumée dès l'écriture (voir le commentaire au point
        d'appel dans orchestrateur.py) : le PDF est un format additionnel,
        pas le contrat de sortie historique du cycle (MD/CSV/HTML/Navigator).
        Une panne reportlab ne doit jamais faire échouer un cycle par
        ailleurs réussi -- vérifié ici en forçant l'échec plutôt qu'en
        espérant ne jamais le déclencher."""

        def pdf_qui_echoue(*a, **k):
            raise RuntimeError("reportlab indisponible (simulation)")

        monkeypatch.setattr("cadre.orchestrateur.generer_rapport_pdf", pdf_qui_echoue)
        orchestrateur.resultats = [
            {
                "timestamp": "2026-07-30T00:00:00",
                "id": "CADRE-TEST-001",
                "technique_mitre": "T1059.001",
                "tactique": "Execution",
                "description": "Test",
                "statut": "VALIDE",
            }
        ]
        orchestrateur._generer_rapports_fin_cycle()  # ne doit lever aucune exception
        fichiers = list(orchestrateur.config["repertoire_rapports"].iterdir())
        assert any(f.suffix == ".md" for f in fichiers)
        assert any(f.suffix == ".csv" for f in fichiers)
        assert any(f.suffix == ".html" for f in fichiers)
        assert not any(f.suffix == ".pdf" for f in fichiers)

    def test_avec_llm_enrichit_le_rapport(self, orchestrateur, monkeypatch):
        class AssistantFactice:
            def resumer_cycle(self, resultats):
                return "Synthèse factice du cycle."

            def analyser_angles_morts(self, resultats):
                return None

            def expliquer_rejets(self, resultats):
                return None

        monkeypatch.setattr("cadre.assistant_llm.obtenir_assistant_llm", AssistantFactice)
        orchestrateur.resultats = [
            {
                "timestamp": "2026-07-30T00:00:00",
                "id": "CADRE-TEST-001",
                "technique_mitre": "T1059.001",
                "tactique": "Execution",
                "description": "Test",
                "statut": "VALIDE",
            }
        ]
        orchestrateur._generer_rapports_fin_cycle(avec_llm=True)
        fichier_md = next(
            f for f in orchestrateur.config["repertoire_rapports"].iterdir() if f.suffix == ".md"
        )
        contenu = fichier_md.read_text(encoding="utf-8")
        assert "Synthèse factice du cycle." in contenu
        assert "Synthèse IA" in contenu

    def test_sans_llm_pas_de_section_ia(self, orchestrateur):
        orchestrateur.resultats = [
            {
                "timestamp": "2026-07-30T00:00:00",
                "id": "CADRE-TEST-001",
                "technique_mitre": "T1059.001",
                "tactique": "Execution",
                "description": "Test",
                "statut": "VALIDE",
            }
        ]
        orchestrateur._generer_rapports_fin_cycle(avec_llm=False)
        fichier_md = next(
            f for f in orchestrateur.config["repertoire_rapports"].iterdir() if f.suffix == ".md"
        )
        assert "Synthèse IA" not in fichier_md.read_text(encoding="utf-8")


class TestExecuterCycleComplet:
    def test_mode_simulation_filtre_par_technique(self, orchestrateur, exemple_attaque):
        resultats = orchestrateur.executer_cycle_complet(
            techniques_a_executer=[exemple_attaque.technique_mitre],
            mode_simulation=True,
        )
        # Le catalogue réel peut ou non contenir cette technique de test ;
        # ce qui compte est que le cycle se termine et génère un rapport cohérent.
        assert resultats == orchestrateur.resultats
        if resultats:
            assert list(orchestrateur.config["repertoire_rapports"].iterdir())

    def test_erreur_inattendue_est_capturee(self, orchestrateur, monkeypatch):
        from cadre.catalogue_attaques import CATALOGUE

        premiere_technique = CATALOGUE[0].technique_mitre

        def simulation_qui_explose(*a, **k):
            raise RuntimeError("panne inattendue")

        monkeypatch.setattr(orchestrateur, "_executer_attaque_simulation", simulation_qui_explose)
        resultats = orchestrateur.executer_cycle_complet(
            techniques_a_executer=[premiere_technique],
            mode_simulation=True,
        )
        assert resultats
        assert resultats[0]["statut"] == "ERREUR"
        assert "panne inattendue" in resultats[0]["raison"]

    def test_second_appel_ne_cumule_pas_les_resultats_du_premier(self, orchestrateur):
        """Régression sécurité (audit) « resultats non réinitialisés » :
        self.resultats n'était jamais remis à zéro entre deux appels --
        _boucle_attaques() ne fait qu'append/extend, jamais reset. Un
        deuxième cycle sur la MÊME instance d'orchestrateur accumulait donc
        silencieusement les résultats du premier avec ceux du nouveau
        (rapports, analyses et totaux faussés pour tout appelant qui
        réutilise une instance)."""
        from cadre.catalogue_attaques import CATALOGUE

        technique = CATALOGUE[0].technique_mitre
        premier = orchestrateur.executer_cycle_complet(
            techniques_a_executer=[technique], mode_simulation=True
        )
        assert premier  # au moins CATALOGUE[0] lui-même
        second = orchestrateur.executer_cycle_complet(
            techniques_a_executer=[technique], mode_simulation=True
        )
        assert orchestrateur.resultats == second
        assert len(orchestrateur.resultats) == len(second)  # pas len(premier) + len(second)


class TestDisjoncteurEchecsExecution:
    """Disjoncteur (circuit breaker) : trouvé en réel le 28/08 -- sous la
    charge d'un cycle complet, le service WinRM de la VM peut passer
    "zombie" (port ouvert, aucune commande ne répond), et 20 attaques de
    suite échouaient en "Échec exécution" sans que le cycle ne réagisse.
    Le disjoncteur interrompt après N échecs d'exécution CONSÉCUTIFS."""

    @staticmethod
    def _fausses_attaques(n):
        from cadre.catalogue_attaques import CATALOGUE

        # Réutilise de vraies entrées du catalogue (ids/techniques valides)
        # pour un test réaliste ; seul le nombre importe ici.
        return list(CATALOGUE[:n])

    def _brancher_resultats(self, orchestrateur, monkeypatch, statuts):
        """Fait renvoyer à _executer_une_attaque une séquence de statuts
        prédéfinie (un par appel), sans jamais toucher WinRM/Elastic."""
        sequence = iter(statuts)

        def faux_executer(attaque, mode_simulation):
            statut = next(sequence)
            return {
                "timestamp": "2026-08-28T00:00:00",
                "id": attaque.id,
                "technique_mitre": attaque.technique_mitre,
                "tactique": attaque.tactique_mitre,
                "description": attaque.nom,
                "statut": statut,
                "raison": statut,
            }

        monkeypatch.setattr(orchestrateur, "_executer_une_attaque", faux_executer)

    def test_cinq_echecs_consecutifs_interrompent_le_cycle(self, orchestrateur, monkeypatch):
        attaques = self._fausses_attaques(8)
        # 5 ERREUR d'affilée -> disjoncteur (seuil défaut 5) ; les 3 restantes
        # ne doivent jamais être exécutées.
        self._brancher_resultats(orchestrateur, monkeypatch, ["ERREUR"] * 5)
        orchestrateur._boucle_attaques(attaques, mode_simulation=False)

        assert len(orchestrateur.resultats) == 8  # 5 exécutées + 3 marquées
        executees = orchestrateur.resultats[:5]
        restantes = orchestrateur.resultats[5:]
        assert all(r["statut"] == "ERREUR" for r in executees)
        assert all(r["statut"] == "NON_APPLICABLE" for r in restantes)
        assert all("disjoncteur" in r["raison"].lower() for r in restantes)

    def test_succes_reinitialise_le_compteur(self, orchestrateur, monkeypatch):
        attaques = self._fausses_attaques(8)
        # 4 ERREUR, un VALIDE (reset), puis 3 ERREUR : jamais 5 d'affilée,
        # le cycle va au bout des 8 sans se déclencher.
        self._brancher_resultats(
            orchestrateur,
            monkeypatch,
            ["ERREUR"] * 4 + ["VALIDE"] + ["ERREUR"] * 3,
        )
        orchestrateur._boucle_attaques(attaques, mode_simulation=False)

        assert len(orchestrateur.resultats) == 8
        assert not any(
            "disjoncteur" in r.get("raison", "").lower() for r in orchestrateur.resultats
        )

    def test_non_applicable_est_neutre(self, orchestrateur, monkeypatch):
        attaques = self._fausses_attaques(8)
        # NON_APPLICABLE intercalés ne réinitialisent PAS le compteur : les
        # échecs restent "consécutifs" à travers eux. 4 ERREUR, 1 NA, 1 ERREUR
        # = 5 échecs d'exécution -> déclenchement au 6e traité.
        self._brancher_resultats(
            orchestrateur,
            monkeypatch,
            ["ERREUR"] * 4 + ["NON_APPLICABLE"] + ["ERREUR"] * 3,
        )
        orchestrateur._boucle_attaques(attaques, mode_simulation=False)

        # 4 ERREUR + 1 NA + 1 ERREUR traités (6), puis 2 restantes marquées.
        assert len(orchestrateur.resultats) == 8
        declenche = [
            r for r in orchestrateur.resultats if "disjoncteur" in r.get("raison", "").lower()
        ]
        assert len(declenche) == 2

    def test_desactive_si_seuil_zero(self, orchestrateur, monkeypatch):
        orchestrateur.config["seuil_echecs_execution_consecutifs"] = 0
        attaques = self._fausses_attaques(6)
        self._brancher_resultats(orchestrateur, monkeypatch, ["ERREUR"] * 6)
        orchestrateur._boucle_attaques(attaques, mode_simulation=False)

        # Aucune interruption : les 6 sont toutes exécutées (statut ERREUR
        # réel, pas le marquage disjoncteur).
        assert len(orchestrateur.resultats) == 6
        assert all(r["statut"] == "ERREUR" for r in orchestrateur.resultats)
        assert not any(
            "disjoncteur" in r.get("raison", "").lower() for r in orchestrateur.resultats
        )


class TestExecuterLotsParalleles:
    """G2 : parallélisme prudent borné à 2 (_boucle_attaques/_executer_lots_
    paralleles). WinRM/Elastic ne sont jamais touchés (executer_attaque_complete
    est mocké) -- ces tests prouvent la MÉCANIQUE de concurrence elle-même
    (bornage, isolement, ordre déterministe), pas la validation TP/FP réelle
    (couverte par la vérification en conditions réelles, hors suite auto)."""

    def _attaque(self, exemple_attaque, **kwargs):
        return dataclasses.replace(exemple_attaque, **kwargs)

    def test_simulation_reste_sequentielle_meme_avec_parallele_true(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        def executeur_qui_leve(*a, **k):
            raise AssertionError("ThreadPoolExecutor ne doit jamais être instancié en simulation")

        monkeypatch.setattr("cadre.orchestrateur.ThreadPoolExecutor", executeur_qui_leve)
        appels: list[str] = []
        monkeypatch.setattr(
            orchestrateur,
            "_executer_attaque_simulation",
            lambda a: appels.append(a.id) or {"id": a.id, "statut": "SIMULE"},
        )
        attaques = [
            self._attaque(exemple_attaque, id=f"A{i}", valeur_detection=f"v{i}") for i in range(3)
        ]
        orchestrateur._boucle_attaques(attaques, mode_simulation=True, parallele=True)
        assert appels == ["A0", "A1", "A2"]

    def test_deux_attaques_compatibles_tournent_reellement_en_parallele(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        """Preuve de concurrence réelle : les deux exécutions DOIVENT se
        rencontrer sur la barrière, sinon BrokenBarrierError (timeout) --
        impossible en séquentiel (la 1re bloquerait indéfiniment seule)."""
        barriere = threading.Barrier(2, timeout=2)

        def executer(attaque):
            barriere.wait()
            return {"id": attaque.id, "statut": "VALIDE"}

        monkeypatch.setattr(orchestrateur, "executer_attaque_complete", executer)
        a = self._attaque(exemple_attaque, id="A", valeur_detection="alpha")
        b = self._attaque(exemple_attaque, id="B", valeur_detection="beta")
        orchestrateur._boucle_attaques([a, b], mode_simulation=False, parallele=True)
        statuts = {r["id"]: r["statut"] for r in orchestrateur.resultats}
        assert statuts == {"A": "VALIDE", "B": "VALIDE"}

    def test_jamais_plus_de_deux_concurrentes(self, orchestrateur, exemple_attaque, monkeypatch):
        verrou = threading.Lock()
        actifs = 0
        maximum = 0
        barriere_premier_lot = threading.Barrier(2, timeout=2)

        def executer(attaque):
            nonlocal actifs, maximum
            with verrou:
                actifs += 1
                maximum = max(maximum, actifs)
            if attaque.id in {"A0", "A1"}:
                barriere_premier_lot.wait()  # force le chevauchement du 1er lot
            with verrou:
                actifs -= 1
            return {"id": attaque.id, "statut": "VALIDE"}

        monkeypatch.setattr(orchestrateur, "executer_attaque_complete", executer)
        attaques = [
            self._attaque(exemple_attaque, id=f"A{i}", valeur_detection=f"v{i}") for i in range(5)
        ]
        orchestrateur._boucle_attaques(attaques, mode_simulation=False, parallele=True)
        assert maximum == 2
        assert len(orchestrateur.resultats) == 5

    def test_attaque_generique_jamais_regroupee(self, orchestrateur, exemple_attaque, monkeypatch):
        """valeur_detection=None -> lot d'1 (partitionner_pour_parallelisme,
        déjà exhaustivement testé dans test_catalogue.py) -- ici on vérifie
        seulement le câblage bout-en-bout : les 3 attaques aboutissent bien
        toutes en résultat, generique inclus."""
        monkeypatch.setattr(
            orchestrateur,
            "executer_attaque_complete",
            lambda a: {"id": a.id, "statut": "VALIDE"},
        )
        generique = self._attaque(exemple_attaque, id="GEN", valeur_detection=None)
        a = self._attaque(exemple_attaque, id="A", valeur_detection="alpha")
        b = self._attaque(exemple_attaque, id="B", valeur_detection="beta")
        orchestrateur._boucle_attaques([generique, a, b], mode_simulation=False, parallele=True)
        assert {r["id"] for r in orchestrateur.resultats} == {"GEN", "A", "B"}

    def test_ordre_resultats_deterministe_meme_si_le_premier_finit_apres(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        b_a_demarre = threading.Event()

        def executer(attaque):
            if attaque.id == "A":
                assert b_a_demarre.wait(timeout=2), "B n'a jamais démarré avant que A finisse"
            else:
                b_a_demarre.set()
            return {"id": attaque.id, "statut": "VALIDE"}

        monkeypatch.setattr(orchestrateur, "executer_attaque_complete", executer)
        a = self._attaque(exemple_attaque, id="A", valeur_detection="alpha")
        b = self._attaque(exemple_attaque, id="B", valeur_detection="beta")
        orchestrateur._boucle_attaques([a, b], mode_simulation=False, parallele=True)
        # A termine après B (attend le signal) mais l'ordre de collecte suit
        # l'ordre de soumission (= ordre catalogue), pas l'ordre de complétion.
        assert [r["id"] for r in orchestrateur.resultats] == ["A", "B"]

    def test_keyboardinterrupt_dans_un_lot_ne_propage_pas_hors_de_la_boucle(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        def executer(attaque):
            if attaque.id == "B":
                raise KeyboardInterrupt
            return {"id": attaque.id, "statut": "VALIDE"}

        monkeypatch.setattr(orchestrateur, "executer_attaque_complete", executer)
        a = self._attaque(exemple_attaque, id="A", valeur_detection="alpha")
        b = self._attaque(exemple_attaque, id="B", valeur_detection="beta")
        c = self._attaque(exemple_attaque, id="C", valeur_detection="gamma")
        # Ne doit lever aucune exception hors de _boucle_attaques.
        orchestrateur._boucle_attaques([a, b, c], mode_simulation=False, parallele=True)
        # Grain par lot (limitation connue, documentée) : le lot interrompu
        # n'est pas collecté, et le(s) lot(s) suivant(s) ne démarrent jamais.
        assert orchestrateur.resultats == []

    def test_executer_scenario_ne_transmet_jamais_parallele(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        appels: list[dict] = []
        monkeypatch.setattr(orchestrateur, "_boucle_attaques", lambda *a, **k: appels.append(k))
        monkeypatch.setattr(orchestrateur, "_generer_rapports_fin_cycle", lambda **k: None)
        monkeypatch.setattr(
            "cadre.orchestrateur.analyser_kill_chain",
            lambda scenario, resultats, **k: {
                "etapes_detectees": 0,
                "total_etapes": 0,
                "etapes": [],
            },
        )
        scenario = ScenarioAdversaire(
            id="TESTSCENARIO",
            nom="Scénario de test",
            adversaire="Testeur",
            description="d",
            plateforme="windows",
            attaque_ids=[exemple_attaque.id],
        )
        monkeypatch.setattr("cadre.orchestrateur.attaques_ordonnees", lambda s: [exemple_attaque])
        orchestrateur.executer_scenario(scenario, mode_simulation=False)
        assert len(appels) == 1
        assert "parallele" not in appels[0]  # jamais explicitement transmis

    def test_executer_cycle_complet_propage_parallele(
        self, orchestrateur, exemple_attaque, monkeypatch, tmp_path
    ):
        """Câblage bout-en-bout du flag depuis executer_cycle_complet --
        verrou de cycle déjà isolé par la fixture globale autouse
        `_verrou_isole` (conftest.py), jamais le vrai cadre_cycle.lock du
        dépôt pendant les tests."""
        capture: dict = {}
        monkeypatch.setattr(
            orchestrateur,
            "_boucle_attaques",
            lambda attaques, mode_simulation, parallele=False: capture.update(parallele=parallele),
        )
        monkeypatch.setattr(orchestrateur, "_generer_rapports_fin_cycle", lambda **k: None)
        monkeypatch.setattr("cadre.orchestrateur.catalogue_actif", lambda: [exemple_attaque])
        orchestrateur.executer_cycle_complet(mode_simulation=False, parallele=True)
        assert capture["parallele"] is True


class TestVerrouCycleInterProcessus:
    """F-009 : deux cycles RÉELS (processus séparés — dashboard, daemon,
    loop, CLI) ne doivent jamais tourner en même temps contre la même
    cible. La simulation, qui ne touche ni VM ni SIEM, n'est pas concernée.

    `_verrou_isole` : fixture globale autouse (conftest.py) -- plus besoin
    de la redéclarer ici."""

    def test_acquisition_simple_cree_le_fichier_avec_le_pid(self, _verrou_isole):
        from cadre.orchestrateur import _acquerir_verrou_cycle, _liberer_verrou_cycle

        _acquerir_verrou_cycle()
        assert _verrou_isole.exists()
        assert _verrou_isole.read_text(encoding="utf-8").strip() == str(os.getpid())
        _liberer_verrou_cycle()
        assert not _verrou_isole.exists()

    def test_refuse_si_processus_toujours_vivant(self, _verrou_isole):
        from cadre.orchestrateur import _acquerir_verrou_cycle

        _verrou_isole.write_text(str(os.getpid()), encoding="utf-8")  # notre PID = vivant, garanti
        with pytest.raises(RuntimeError, match="déjà en cours"):
            _acquerir_verrou_cycle()

    def test_nettoie_verrou_perime_pid_mort(self, _verrou_isole):
        from cadre.orchestrateur import _acquerir_verrou_cycle

        _verrou_isole.write_text("999999999", encoding="utf-8")  # PID quasi certainement mort
        _acquerir_verrou_cycle()  # ne doit pas lever — remplace le verrou périmé
        assert _verrou_isole.read_text(encoding="utf-8").strip() == str(os.getpid())

    def test_nettoie_verrou_trop_vieux_meme_si_pid_vivant(self, _verrou_isole):
        from cadre.orchestrateur import _acquerir_verrou_cycle

        _verrou_isole.write_text(str(os.getpid()), encoding="utf-8")  # PID vivant...
        vieux = time.time() - 999_999  # ...mais verrou bien plus vieux que le seuil périmé
        os.utime(_verrou_isole, (vieux, vieux))
        _acquerir_verrou_cycle()  # doit passer quand même : l'âge prime
        assert _verrou_isole.exists()

    def test_mode_simulation_n_acquiert_jamais_le_verrou(self, orchestrateur, _verrou_isole):
        orchestrateur.executer_cycle_complet(
            techniques_a_executer=["T9999.999-technique-inexistante"],
            mode_simulation=True,
        )
        assert not _verrou_isole.exists()

    def test_cycle_reel_acquiert_puis_libere(self, orchestrateur, _verrou_isole):
        # Filtre sur une technique absente du catalogue : aucune attaque
        # réelle exécutée (donc pas de réseau), mais le cycle complet
        # (acquisition -> _boucle_attaques vide -> rapports -> libération)
        # s'exécute bel et bien.
        resultats = orchestrateur.executer_cycle_complet(
            techniques_a_executer=["T9999.999-technique-inexistante"],
            mode_simulation=False,
        )
        assert resultats == []
        assert not _verrou_isole.exists()  # libéré même sans attaque exécutée

    def test_cycle_reel_refuse_si_deja_verrouille(self, orchestrateur, _verrou_isole):
        _verrou_isole.write_text(str(os.getpid()), encoding="utf-8")
        with pytest.raises(RuntimeError, match="déjà en cours"):
            orchestrateur.executer_cycle_complet(
                techniques_a_executer=["T9999.999-technique-inexistante"],
                mode_simulation=False,
            )
        # Le verrou pré-existant (pas le nôtre) reste en place — on n'a pas
        # dû le libérer, on ne l'a jamais possédé.
        assert _verrou_isole.exists()


class TestPausesEntreAttaques:
    """La pause inter-attaques ne doit coûter du temps que quand elle sert.

    Sur un cycle complet elle représentait ~3 min de pure attente, dont une
    partie inutile : après la dernière attaque (plus rien ne suit) et pour
    les attaques NON_APPLICABLE (aucun appel WinRM/Elastic, donc rien à
    laisser retomber)."""

    @staticmethod
    def _capturer_pauses(orchestrateur, monkeypatch, exemple_attaque, statuts):
        """Monte un catalogue factice de len(statuts) attaques, fait renvoyer
        `statuts` par les exécutions successives, et capture les sleeps."""
        catalogue_factice = [
            dataclasses.replace(exemple_attaque, id=f"FAKE-{i:03d}") for i in range(len(statuts))
        ]
        # L'orchestrateur passe par catalogue_actif() (natif + perso) ; on le
        # remplace par notre catalogue factice pour ce test.
        monkeypatch.setattr("cadre.orchestrateur.catalogue_actif", lambda: catalogue_factice)

        pauses: list[float] = []
        monkeypatch.setattr("cadre.orchestrateur.time.sleep", pauses.append)

        restants = list(statuts)
        monkeypatch.setattr(
            orchestrateur,
            "_executer_attaque_simulation",
            lambda attaque: {"id": attaque.id, "statut": restants.pop(0)},
        )
        monkeypatch.setattr(orchestrateur, "_generer_rapports_fin_cycle", lambda **k: None)
        return pauses

    def test_aucune_pause_apres_la_derniere_attaque(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        pauses = self._capturer_pauses(orchestrateur, monkeypatch, exemple_attaque, ["SIMULE"] * 3)
        orchestrateur.executer_cycle_complet(mode_simulation=True)
        # 3 attaques → 2 pauses seulement (aucune après la dernière)
        assert len(pauses) == 2

    def test_aucune_pause_pour_une_attaque_non_applicable(
        self, orchestrateur, exemple_attaque, monkeypatch
    ):
        pauses = self._capturer_pauses(
            orchestrateur, monkeypatch, exemple_attaque, ["NON_APPLICABLE", "SIMULE", "SIMULE"]
        )
        orchestrateur.executer_cycle_complet(mode_simulation=True)
        # 3 attaques, la 1re NON_APPLICABLE (pas de pause) et la 3e dernière
        # (pas de pause) → une seule pause, après la 2e.
        assert len(pauses) == 1

    def test_pause_reelle_respecte_la_config(self, orchestrateur, exemple_attaque, monkeypatch):
        # La pause réelle est configurable via pause_entre_attaques_sec (défaut 2,
        # abaissé depuis 5 pour accélérer un cycle complet — cf. AUDIT-DASH/1b).
        orchestrateur.config["pause_entre_attaques_sec"] = 3
        pauses = self._capturer_pauses(
            orchestrateur, monkeypatch, exemple_attaque, ["SIMULE", "SIMULE"]
        )
        monkeypatch.setattr(
            orchestrateur,
            "executer_attaque_complete",
            lambda attaque: {"id": attaque.id, "statut": "VALIDE"},
        )
        orchestrateur.executer_cycle_complet(mode_simulation=False)
        assert pauses == [3]  # respecte la config (et non plus 5s codé en dur)


class TestExecuterCommandeSSH:
    """Exécution SSH sur cible Linux (paramiko mocké — aucune vraie VM)."""

    def _orch_linux(self, tmp_path, **extra):
        return OrchestrateurCADRE(
            config={
                "repertoire_rapports": tmp_path / "r",
                "repertoire_regles": tmp_path / "g",
                "linux_vm_ip": "192.168.56.105",
                "linux_vm_user": "kali",
                "linux_vm_pass": "kali",
                **extra,
            }
        )

    def test_paramiko_indisponible(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cadre.orchestrateur.PARAMIKO_DISPONIBLE", False)
        assert self._orch_linux(tmp_path).executer_commande_ssh("id") is False

    def test_cible_linux_non_configuree(self, tmp_path):
        o = OrchestrateurCADRE(
            config={"repertoire_rapports": tmp_path / "r", "repertoire_regles": tmp_path / "g"}
        )
        assert o.executer_commande_ssh("id") is False  # pas d'ip/user/pass Linux

    def test_port_ssh_ferme(self, tmp_path, monkeypatch):
        o = self._orch_linux(tmp_path)
        monkeypatch.setattr(o, "_port_accessible", lambda *a, **k: False)
        assert o.executer_commande_ssh("id") is False

    def test_succes_construit_la_bonne_session(self, tmp_path, monkeypatch):
        o = self._orch_linux(tmp_path)
        monkeypatch.setattr(o, "_port_accessible", lambda *a, **k: True)
        captured: dict = {}

        class FakeChan:
            def recv_exit_status(self):
                return 0

        class FakeStdout:
            channel = FakeChan()

        class FakeClient:
            def set_missing_host_key_policy(self, _p):
                pass

            def connect(self, ip, **kw):
                captured["ip"] = ip
                captured.update(kw)

            def exec_command(self, cmd, timeout=None):
                captured["cmd"] = cmd
                return (None, FakeStdout(), None)

            def close(self):
                pass

        monkeypatch.setattr("cadre.orchestrateur.paramiko.SSHClient", FakeClient)
        assert o.executer_commande_ssh("whoami") is True
        assert captured["ip"] == "192.168.56.105"
        assert captured["username"] == "kali"
        assert captured["port"] == 22
        assert captured["cmd"] == "whoami"

    def test_echec_definitif_apres_3_tentatives(self, tmp_path, monkeypatch):
        """EXC4 : chemin de repli SSH après exhaustion des 3 tentatives
        (symétrique au test WinRM équivalent, jamais couvert avant)."""
        o = self._orch_linux(tmp_path)
        monkeypatch.setattr(o, "_port_accessible", lambda *a, **k: True)
        monkeypatch.setattr("cadre.orchestrateur.time.sleep", lambda *a: None)

        class ClientQuiEchoue:
            def set_missing_host_key_policy(self, _p):
                pass

            def connect(self, *a, **k):
                raise TimeoutError("VM Linux injoignable")

        monkeypatch.setattr("cadre.orchestrateur.paramiko.SSHClient", ClientQuiEchoue)
        assert o.executer_commande_ssh("whoami") is False


class TestExecuterCommandeSSHKali:
    """Exécution SSH sur Kali visant la cible Windows par le réseau
    (paramiko mocké, aucune vraie VM) -- réutilise les identifiants
    `linux_vm_*` (c'est la même VM), substitue {CIBLE_IP} par `vm_ip`."""

    def _orch(self, tmp_path, **extra):
        return OrchestrateurCADRE(
            config={
                "repertoire_rapports": tmp_path / "r",
                "repertoire_regles": tmp_path / "g",
                "vm_ip": "192.168.56.104",
                "linux_vm_ip": "192.168.56.105",
                "linux_vm_user": "kali",
                "linux_vm_pass": "kali",
                **extra,
            }
        )

    def test_paramiko_indisponible(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cadre.orchestrateur.PARAMIKO_DISPONIBLE", False)
        assert self._orch(tmp_path).executer_commande_ssh_kali("id {CIBLE_IP}") is False

    def test_cible_windows_non_configuree_refuse_sans_ssh(self, tmp_path):
        """Sans vm_ip, {CIBLE_IP} ne peut rien substituer -- refus avant
        toute tentative de connexion."""
        o = self._orch(tmp_path, vm_ip=None)
        assert o.executer_commande_ssh_kali("id {CIBLE_IP}") is False

    def test_substitue_cible_ip_dans_la_commande(self, tmp_path, monkeypatch):
        o = self._orch(tmp_path)
        monkeypatch.setattr(o, "_port_accessible", lambda *a, **k: True)
        captured: dict = {}

        class FakeChan:
            def recv_exit_status(self):
                return 0

        class FakeStdout:
            channel = FakeChan()

        class FakeClient:
            def set_missing_host_key_policy(self, _p):
                pass

            def connect(self, ip, **kw):
                captured["ip"] = ip
                captured.update(kw)

            def exec_command(self, cmd, timeout=None):
                captured["cmd"] = cmd
                return (None, FakeStdout(), None)

            def close(self):
                pass

        monkeypatch.setattr("cadre.orchestrateur.paramiko.SSHClient", FakeClient)
        assert o.executer_commande_ssh_kali("netexec winrm {CIBLE_IP} -u x -p y") is True
        # Connexion SSH vers KALI (linux_vm_ip), pas vers la cible Windows.
        assert captured["ip"] == "192.168.56.105"
        assert captured["username"] == "kali"
        # {CIBLE_IP} substitué par vm_ip (la cible Windows), pas par linux_vm_ip.
        assert captured["cmd"] == "netexec winrm 192.168.56.104 -u x -p y"

    def test_substitue_mot_de_passe_brute_test_dans_la_commande(self, tmp_path, monkeypatch):
        """Régression sécurité : le mot de passe de CADRE-CRE-006/
        CADRE-INI-001 était codé en dur dans catalogue_attaques.py -- il vit
        désormais dans le coffre-fort et n'atteint la commande RÉELLE (celle
        envoyée par SSH) qu'au moment de l'exécution, comme {CIBLE_IP}."""
        o = self._orch(tmp_path, brute_test_pass="M0nVraiMdp!")
        monkeypatch.setattr(o, "_port_accessible", lambda *a, **k: True)
        captured: dict = {}

        class FakeChan:
            def recv_exit_status(self):
                return 0

        class FakeStdout:
            channel = FakeChan()

        class FakeClient:
            def set_missing_host_key_policy(self, _p):
                pass

            def connect(self, ip, **kw):
                pass

            def exec_command(self, cmd, timeout=None):
                captured["cmd"] = cmd
                return (None, FakeStdout(), None)

            def close(self):
                pass

        monkeypatch.setattr("cadre.orchestrateur.paramiko.SSHClient", FakeClient)
        assert o.executer_commande_ssh_kali("nx {CIBLE_IP} -p {CADRE_BRUTE_TEST_PASS}") is True
        assert captured["cmd"] == "nx 192.168.56.104 -p M0nVraiMdp!"

    def test_refuse_si_secret_mot_de_passe_manquant(self, tmp_path, monkeypatch):
        """Sans CADRE_BRUTE_TEST_PASS configuré, la commande ne doit jamais
        partir avec le jeton littéral non substitué -- refus propre avant
        toute tentative SSH, comme pour {CIBLE_IP} sans vm_ip. Compte les
        appels (pas juste "lève une exception") : _executer_ssh capture
        `Exception` dans sa boucle de tentatives, donc un ancien code qui
        n'aurait pas su refuser AVANT d'essayer aurait aussi fini par
        renvoyer False après 3 tentatives échouées -- épuiser le retry
        n'est pas la même garantie qu'un refus immédiat, d'où le compteur."""
        o = self._orch(tmp_path)  # pas de brute_test_pass
        # _port_accessible mocké à True : sans ça, le vrai sondage réseau
        # (aucune VM Kali réelle ici) échouerait AUSSI avant SSHClient(),
        # et ce test "réussirait" même sur l'ancien code pour une raison
        # totalement différente (accès réseau, pas garde applicatif).
        monkeypatch.setattr(o, "_port_accessible", lambda *a, **k: True)
        monkeypatch.setattr("cadre.orchestrateur.time.sleep", lambda *a: None)
        appels = []

        def ssh_client_interdit(*a, **k):
            appels.append(1)
            raise AssertionError("SSH ne doit jamais être tenté sans le secret")

        monkeypatch.setattr("cadre.orchestrateur.paramiko.SSHClient", ssh_client_interdit)
        assert o.executer_commande_ssh_kali("nx {CIBLE_IP} -p {CADRE_BRUTE_TEST_PASS}") is False
        assert appels == []  # jamais tenté, pas juste "épuisé après 3 essais"

    def test_log_ne_contient_jamais_le_mot_de_passe_substitue(self, tmp_path, monkeypatch):
        """Régression sécurité : le mot de passe réel substitué ne doit
        JAMAIS apparaître dans les journaux (logs/cadre.log.json), même si
        la commande envoyée par SSH le contient bien (nécessaire à
        l'attaque). Avant correctif, la même chaîne journalisée servait à
        la fois d'affichage ET d'exécution -- le mot de passe fuyait en
        clair dans les logs."""
        o = self._orch(tmp_path, brute_test_pass="M0nVraiMdp!")
        monkeypatch.setattr(o, "_port_accessible", lambda *a, **k: True)
        captured: dict = {}

        class FakeChan:
            def recv_exit_status(self):
                return 0

        class FakeStdout:
            channel = FakeChan()

        class FakeClient:
            def set_missing_host_key_policy(self, _p):
                pass

            def connect(self, *a, **k):
                pass

            def exec_command(self, cmd, timeout=None):
                captured["cmd"] = cmd
                return (None, FakeStdout(), None)

            def close(self):
                pass

        monkeypatch.setattr("cadre.orchestrateur.paramiko.SSHClient", FakeClient)
        appels_log: list[dict] = []
        monkeypatch.setattr(
            o.log, "attack", lambda msg, **kw: appels_log.append({"msg": msg, **kw})
        )
        o.executer_commande_ssh_kali("nx {CIBLE_IP} -p {CADRE_BRUTE_TEST_PASS}")
        # La commande RÉELLEMENT envoyée contient bien le mot de passe --
        # sans cette assertion, un code qui ne substituerait JAMAIS le
        # jeton (donc ne fuiterait jamais rien, mais casserait aussi
        # l'attaque) ferait passer ce test à tort.
        assert captured["cmd"] == "nx 192.168.56.104 -p M0nVraiMdp!"
        assert appels_log  # au moins un appel de journalisation d'attaque
        for appel in appels_log:
            assert "M0nVraiMdp!" not in appel["msg"]
            assert "M0nVraiMdp!" not in appel.get("commande", "")
            assert "{CADRE_BRUTE_TEST_PASS}" in appel.get("commande", "")

    def test_pas_de_sleep_apres_contrairement_a_ssh_local(self, tmp_path, monkeypatch):
        """La télémétrie n'est pas sur Kali : pas de temps d'attente local
        nécessaire (contrairement à executer_commande_ssh/Auditbeat)."""
        o = self._orch(tmp_path)
        monkeypatch.setattr(o, "_port_accessible", lambda *a, **k: True)

        class FakeChan:
            def recv_exit_status(self):
                return 0

        class FakeStdout:
            channel = FakeChan()

        class FakeClient:
            def set_missing_host_key_policy(self, _p):
                pass

            def connect(self, *a, **k):
                pass

            def exec_command(self, cmd, timeout=None):
                return (None, FakeStdout(), None)

            def close(self):
                pass

        monkeypatch.setattr("cadre.orchestrateur.paramiko.SSHClient", FakeClient)
        appels_sleep: list[float] = []
        monkeypatch.setattr("cadre.orchestrateur.time.sleep", appels_sleep.append)
        assert o.executer_commande_ssh_kali("echo {CIBLE_IP}") is True
        assert appels_sleep == []


class TestDiagnostiquerKali:
    """Outil d'inspection manuelle (jamais appelé par le pipeline d'attaque) :
    capture la sortie d'une commande SSH sur Kali."""

    def _orch(self, tmp_path, **extra):
        return OrchestrateurCADRE(
            config={
                "repertoire_rapports": tmp_path / "r",
                "repertoire_regles": tmp_path / "g",
                "linux_vm_ip": "192.168.56.105",
                "linux_vm_user": "kali",
                "linux_vm_pass": "kali",
                **extra,
            }
        )

    def test_capture_stdout_et_stderr(self, tmp_path, monkeypatch):
        o = self._orch(tmp_path)
        monkeypatch.setattr(o, "_port_accessible", lambda *a, **k: True)

        class FakeChan:
            def recv_exit_status(self):
                return 0

        class FakeStream:
            def __init__(self, texte):
                self._texte = texte.encode()
                self.channel = FakeChan()

            def read(self):
                return self._texte

        class FakeClient:
            def set_missing_host_key_policy(self, _p):
                pass

            def connect(self, *a, **k):
                pass

            def exec_command(self, cmd, timeout=None):
                return (None, FakeStream("/usr/bin/netexec\n"), FakeStream(""))

            def close(self):
                pass

        monkeypatch.setattr("cadre.orchestrateur.paramiko.SSHClient", FakeClient)
        assert o.diagnostiquer_kali("which netexec") == "/usr/bin/netexec\n"

    def test_none_si_connexion_impossible(self, tmp_path, monkeypatch):
        o = self._orch(tmp_path)
        monkeypatch.setattr(o, "_port_accessible", lambda *a, **k: False)
        assert o.diagnostiquer_kali("which netexec") is None


class TestRoutagePlateforme:
    """Routage Windows/WinRM vs Linux/SSH selon la plateforme de l'attaque."""

    def _attaque(self, plateforme):
        from cadre.catalogue_attaques import AttaqueCatalogue

        return AttaqueCatalogue(
            id="X",
            nom="x",
            description="x",
            technique_mitre="T1000",
            tactique_mitre="Execution",
            sous_technique=None,
            commande="echo x",
            event_ids_attendus=["1"],
            champ_principal="process.title",
            valeur_detection="marqueur",
            plateforme=plateforme,
        )

    def test_windows_route_vers_winrm(self, orchestrateur):
        from cadre.catalogue_attaques import Plateforme

        cible = orchestrateur._cible_pour_attaque(self._attaque(Plateforme.WINDOWS))
        assert cible["plateforme"] == "windows"
        assert cible["executer"] == orchestrateur.executer_commande_winrm
        assert cible["pipeline"] == "ecs_windows"

    def test_linux_sans_cible_configuree_non_applicable(self, orchestrateur):
        from cadre.catalogue_attaques import Plateforme

        # orchestrateur fixture n'a pas de cible Linux configurée
        assert orchestrateur._cible_pour_attaque(self._attaque(Plateforme.LINUX)) is None

    def test_linux_avec_cible_route_vers_ssh(self, tmp_path):
        from cadre.catalogue_attaques import Plateforme

        o = OrchestrateurCADRE(
            config={
                "repertoire_rapports": tmp_path / "r",
                "repertoire_regles": tmp_path / "g",
                "linux_vm_ip": "10.0.0.9",
                "linux_vm_user": "u",
                "linux_vm_pass": "p",
            }
        )
        cible = o._cible_pour_attaque(self._attaque(Plateforme.LINUX))
        assert cible["plateforme"] == "linux"
        assert cible["executer"] == o.executer_commande_ssh
        assert cible["index_pattern"] == "auditbeat-*"
        assert cible["pipeline"] == "aucun"  # pas le pipeline Windows

    def test_generation_sigma_linux(self, orchestrateur):
        from cadre.catalogue_attaques import Plateforme
        from cadre.compilation_sigma import compiler_sigma_vers_lucene

        regle = orchestrateur.generer_regle_sigma_depuis_attaque(
            self._attaque(Plateforme.LINUX), {}
        )
        assert "product: linux" in regle
        assert "process.title|contains: 'marqueur'" in regle
        assert "event.code" not in regle  # Linux : pas d'EventID Windows
        # compile bien sans le pipeline Windows
        lucene = compiler_sigma_vers_lucene(regle, pipeline="aucun")
        assert lucene == "process.title:*marqueur*"


class TestOrigineExecutionKali:
    """Dispatch de `_cible_pour_attaque`/`_cible_joignable` pour une attaque
    dont la commande s'exécute sur Kali (SSH) mais dont la télémétrie est
    cherchée sur la cible Windows -- voir `OrigineExecution.KALI`."""

    def _attaque(self, **overrides):
        from cadre.catalogue_attaques import (
            AttaqueCatalogue,
            OrigineExecution,
            Plateforme,
        )

        base = {
            "id": "X",
            "nom": "x",
            "description": "x",
            "technique_mitre": "T1110.001",
            "tactique_mitre": "Credential Access",
            "sous_technique": None,
            "commande": "netexec winrm {CIBLE_IP} -u a -p b",
            "event_ids_attendus": ["4625"],
            "champ_principal": "event.code",
            "valeur_detection": "3",
            "plateforme": Plateforme.WINDOWS,
            "origine_execution": OrigineExecution.KALI,
        }
        base.update(overrides)
        return AttaqueCatalogue(**base)

    def _orch(self, tmp_path, **extra):
        return OrchestrateurCADRE(
            config={
                "repertoire_rapports": tmp_path / "r",
                "repertoire_regles": tmp_path / "g",
                "vm_ip": "192.168.56.104",
                "linux_vm_ip": "192.168.56.105",
                "linux_vm_user": "kali",
                "linux_vm_pass": "kali",
                **extra,
            }
        )

    def test_cible_reutilise_detection_windows_mais_execute_via_kali(self, tmp_path):
        o = self._orch(tmp_path)
        cible = o._cible_pour_attaque(self._attaque())
        assert cible["plateforme"] == "windows"
        assert cible["index_pattern"] == o.config["index_pattern"]
        assert cible["pipeline"] == "ecs_windows"
        assert cible["executer"] == o.executer_commande_ssh_kali
        assert cible["origine"] == "kali"

    def test_non_applicable_si_kali_non_configure(self, tmp_path):
        o = self._orch(tmp_path, linux_vm_ip=None, linux_vm_user=None, linux_vm_pass=None)
        assert o._cible_pour_attaque(self._attaque()) is None

    def test_non_applicable_si_cible_windows_non_configuree(self, tmp_path):
        o = self._orch(tmp_path, vm_ip=None)
        assert o._cible_pour_attaque(self._attaque()) is None

    def test_joignable_teste_le_port_ssh_kali_pas_winrm_windows(self, tmp_path, monkeypatch):
        """Bug identifié en exploration : `cible["plateforme"]` vaut
        "windows" pour une attaque Kali -- sans la branche dédiée,
        `_cible_joignable` testerait à tort le port WinRM de Windows
        plutôt que le port SSH de Kali."""
        o = self._orch(tmp_path)
        appels: list[tuple] = []
        monkeypatch.setattr(
            o, "_port_accessible", lambda ip, port, **k: appels.append((ip, port)) or True
        )
        cible = o._cible_pour_attaque(self._attaque())
        assert o._cible_joignable(cible) is True
        assert appels == [("192.168.56.105", 22)]  # Kali, pas Windows

    def test_non_joignable_si_paramiko_absent(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cadre.orchestrateur.PARAMIKO_DISPONIBLE", False)
        o = self._orch(tmp_path)
        cible = o._cible_pour_attaque(self._attaque())
        assert o._cible_joignable(cible) is False

    def test_generation_sigma_reste_windows_native(self, orchestrateur):
        """La génération de règle Sigma ne doit rien savoir de l'origine
        d'exécution -- même chemin que toute attaque Windows classique."""
        regle = orchestrateur.generer_regle_sigma_depuis_attaque(self._attaque(), {})
        assert "product: windows" in regle
        assert "service: security" in regle
        assert "EventID: 4625" in regle
        assert "winlog.event_data.LogonType|contains: '3'" in regle
