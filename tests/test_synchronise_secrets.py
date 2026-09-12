"""
Tests pour la resynchronisation des agents de télémétrie après rotation de
CADRE_ELASTIC_PASS (src/cadre/synchronise_secrets.py). WinRM et SSH sont
mockés : ce module ne doit jamais toucher un vrai réseau pendant les tests.
"""

from __future__ import annotations

import pytest

from cadre.coffre_fort import ErreurSecurite
from cadre.orchestrateur import OrchestrateurCADRE
from cadre.synchronise_secrets import (
    _remplacer_mot_de_passe_yaml,
    synchroniser_auditbeat,
    synchroniser_secrets_beats,
    synchroniser_winlogbeat,
)


class TestRemplacerMotDePasseYaml:
    """Logique la plus sensible du module : un motif qui ne matche rien doit
    être détecté (nb_remplacements == 0), jamais confondu avec un succès."""

    def test_ligne_quotee_format_documente(self):
        """Format exact de docs/INSTALL.md."""
        contenu = (
            'output.elasticsearch:\n  hosts: ["x"]\n  username: "elastic"\n'
            '  password: "ancien"\n'  # pragma: allowlist secret
        )
        resultat, n = _remplacer_mot_de_passe_yaml(contenu, "nouveau")
        assert n == 1
        assert 'password: "nouveau"' in resultat  # pragma: allowlist secret
        assert "ancien" not in resultat
        # les autres lignes ne doivent pas être touchées
        assert 'username: "elastic"' in resultat

    def test_ligne_non_quotee(self):
        """auditbeat.yml peut aussi avoir une valeur non quotée -- doit être
        reconnue tout aussi bien (c'était le bug trouvé en relecture : un
        motif exigeant des guillemets ratait ce cas et rapportait quand même
        un succès)."""
        contenu = "output.elasticsearch:\n  password: ancien_sans_guillemets\n"
        resultat, n = _remplacer_mot_de_passe_yaml(contenu, "nouveau")
        assert n == 1
        assert 'password: "nouveau"' in resultat  # pragma: allowlist secret

    def test_aucune_ligne_password_nb_remplacements_zero(self):
        """Fichier de config dans un format totalement inattendu (ex. déjà
        corrompu, ou chemin pointant vers le mauvais fichier) : doit
        retourner 0, jamais lever d'exception ni prétendre avoir réussi."""
        contenu = 'output.elasticsearch:\n  hosts: ["x"]\n  username: "elastic"\n'
        resultat, n = _remplacer_mot_de_passe_yaml(contenu, "nouveau")
        assert n == 0
        assert resultat == contenu  # contenu inchangé

    def test_mot_de_passe_avec_guillemet_interne_echappe(self):
        """Un mot de passe contenant un guillemet ne doit jamais casser le
        YAML résultant (guillemet interne échappé)."""
        contenu = 'password: "ancien"\n'  # pragma: allowlist secret
        mdp = 'mot"de"passe'  # pragma: allowlist secret
        resultat, n = _remplacer_mot_de_passe_yaml(contenu, mdp)
        assert n == 1
        assert 'password: "mot\\"de\\"passe"' in resultat  # pragma: allowlist secret

    def test_plusieurs_lignes_password_toutes_remplacees(self):
        """Si le fichier a plusieurs lignes password: (ex. Winlogbeat ET un
        module additionnel), toutes doivent être mises à jour -- pas
        seulement la première."""
        contenu = "password: ancien1\nautre: x\npassword: ancien2\n"
        resultat, n = _remplacer_mot_de_passe_yaml(contenu, "nouveau")
        assert n == 2
        assert resultat.count('password: "nouveau"') == 2  # pragma: allowlist secret


class CoffreFactice:
    """Coffre-fort qui ne trouve jamais de secret (sauf valeur par défaut)."""

    def obtenir(self, cle, defaut=None):
        if defaut is not None:
            return defaut
        raise ErreurSecurite(f"{cle} manquant")


@pytest.fixture(autouse=True)
def coffre_factice(monkeypatch):
    monkeypatch.setattr("cadre.orchestrateur.obtenir_coffre", CoffreFactice)


def _orch(tmp_path, **extra):
    return OrchestrateurCADRE(
        config={
            "repertoire_rapports": tmp_path / "r",
            "repertoire_regles": tmp_path / "g",
            "vm_ip": "192.168.56.104",
            "vm_user": "CadreUser",
            "vm_pass": "ancien_mdp",
            "linux_vm_ip": "192.168.56.105",
            "linux_vm_user": "kali",
            "linux_vm_pass": "ancien_mdp",
            "elastic_pass": "nouveau_mdp_rotate",
            **extra,
        }
    )


class TestSynchroniserWinlogbeat:
    def test_succes(self, tmp_path, monkeypatch):
        o = _orch(tmp_path)
        appels = []

        class FakeResult:
            std_out = b"CADRE_RESULTAT:Running"

        class FakeSession:
            def __init__(self, *a, **k):
                pass

            def run_ps(self, script):
                appels.append(script)
                return FakeResult()

        monkeypatch.setattr("cadre.synchronise_secrets.winrm.Session", FakeSession)
        resultat = synchroniser_winlogbeat(o, "nouveau_mdp_rotate")
        assert resultat.ok is True
        assert "Running" in resultat.detail
        # le mot de passe ne doit apparaître QUE dans le script de dépôt
        # (Set-Content), jamais ailleurs -- et jamais loggué en clair.
        assert any("nouveau_mdp_rotate" in a for a in appels)

    def test_echec_service_non_actif(self, tmp_path, monkeypatch):
        o = _orch(tmp_path)

        class FakeResult:
            std_out = b"CADRE_RESULTAT:Stopped"

        class FakeSession:
            def __init__(self, *a, **k):
                pass

            def run_ps(self, script):
                return FakeResult()

        monkeypatch.setattr("cadre.synchronise_secrets.winrm.Session", FakeSession)
        resultat = synchroniser_winlogbeat(o, "nouveau_mdp_rotate")
        assert resultat.ok is False

    def test_erreur_distante_remontee(self, tmp_path, monkeypatch):
        o = _orch(tmp_path)

        class FakeResult:
            std_out = b"CADRE_RESULTAT:ERREUR:fichier introuvable"

        class FakeSession:
            def __init__(self, *a, **k):
                pass

            def run_ps(self, script):
                return FakeResult()

        monkeypatch.setattr("cadre.synchronise_secrets.winrm.Session", FakeSession)
        resultat = synchroniser_winlogbeat(o, "nouveau_mdp_rotate")
        assert resultat.ok is False
        assert "fichier introuvable" in resultat.detail

    def test_connexion_impossible(self, tmp_path, monkeypatch):
        o = _orch(tmp_path)

        class SessionQuiEchoue:
            def __init__(self, *a, **k):
                raise TimeoutError("VM injoignable")

        monkeypatch.setattr("cadre.synchronise_secrets.winrm.Session", SessionQuiEchoue)
        resultat = synchroniser_winlogbeat(o, "nouveau_mdp_rotate")
        assert resultat.ok is False
        assert "nouveau_mdp_rotate" not in resultat.detail

    def test_vm_non_configuree(self, tmp_path):
        o = _orch(tmp_path, vm_pass=None)
        resultat = synchroniser_winlogbeat(o, "nouveau_mdp_rotate")
        assert resultat.ok is False
        assert "non configurée" in resultat.detail

    def test_aucune_ligne_password_trouvee_cote_distant(self, tmp_path, monkeypatch):
        """Le script distant lui-même détecte 0 remplacement (fichier de
        config dans un format inattendu) -- ne doit JAMAIS remonter comme un
        succès malgré un service qui pourrait rester 'Running'."""
        o = _orch(tmp_path)

        class FakeResult:
            std_out = b"CADRE_RESULTAT:ERREUR:aucune ligne 'password:' trouvee dans winlogbeat.yml"

        class FakeSession:
            def __init__(self, *a, **k):
                pass

            def run_ps(self, script):
                return FakeResult()

        monkeypatch.setattr("cadre.synchronise_secrets.winrm.Session", FakeSession)
        resultat = synchroniser_winlogbeat(o, "nouveau_mdp_rotate")
        assert resultat.ok is False
        assert "aucune ligne" in resultat.detail

    def test_mot_de_passe_avec_apostrophe_echappe(self, tmp_path, monkeypatch):
        """Un mot de passe contenant une apostrophe ne doit jamais casser le
        littéral PowerShell (échappement `'` -> `''`)."""
        o = _orch(tmp_path)
        scripts = []

        class FakeResult:
            std_out = b"CADRE_RESULTAT:Running"

        class FakeSession:
            def __init__(self, *a, **k):
                pass

            def run_ps(self, script):
                scripts.append(script)
                return FakeResult()

        monkeypatch.setattr("cadre.synchronise_secrets.winrm.Session", FakeSession)
        resultat = synchroniser_winlogbeat(o, "mot'de'passe")
        assert resultat.ok is True
        assert any("mot''de''passe" in s for s in scripts)


class TestSynchroniserAuditbeat:
    def test_succes(self, tmp_path, monkeypatch):
        o = _orch(tmp_path)
        fichiers_ecrits = {}

        class FakeSFTPFile:
            def __init__(self, store, nom):
                self.store = store
                self.nom = nom

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

            def write(self, data):
                self.store[self.nom] = data

        class FakeSFTP:
            def open(self, chemin, mode):
                return FakeSFTPFile(fichiers_ecrits, chemin)

            def chmod(self, chemin, mode):
                pass

            def close(self):
                pass

        class FakeStdout:
            channel = type("C", (), {"recv_exit_status": lambda self: 0})()

            def read(self):
                return b"CADRE_RESULTAT:active"

        class FakeStderr:
            def read(self):
                return b""

        class FakeClient:
            def set_missing_host_key_policy(self, _p):
                pass

            def connect(self, *a, **k):
                pass

            def open_sftp(self):
                return FakeSFTP()

            def exec_command(self, cmd, timeout=None):
                return (None, FakeStdout(), FakeStderr())

            def close(self):
                pass

        monkeypatch.setattr("cadre.synchronise_secrets.paramiko.SSHClient", FakeClient)
        resultat = synchroniser_auditbeat(o, "nouveau_mdp_rotate")
        assert resultat.ok is True
        assert "actif" in resultat.detail
        # le mot de passe part par SFTP dans un fichier temporaire, jamais
        # comme argument de exec_command.
        assert "nouveau_mdp_rotate" in list(fichiers_ecrits.values())

    def test_echec_service_inactif(self, tmp_path, monkeypatch):
        o = _orch(tmp_path)

        class FakeSFTP:
            def open(self, chemin, mode):
                class F:
                    def __enter__(self):
                        return self

                    def __exit__(self, *a):
                        pass

                    def write(self, data):
                        pass

                return F()

            def chmod(self, chemin, mode):
                pass

            def close(self):
                pass

        class FakeStdout:
            channel = type("C", (), {"recv_exit_status": lambda self: 0})()

            def read(self):
                return b"CADRE_RESULTAT:failed"

        class FakeStderr:
            def read(self):
                return b""

        class FakeClient:
            def set_missing_host_key_policy(self, _p):
                pass

            def connect(self, *a, **k):
                pass

            def open_sftp(self):
                return FakeSFTP()

            def exec_command(self, cmd, timeout=None):
                return (None, FakeStdout(), FakeStderr())

            def close(self):
                pass

        monkeypatch.setattr("cadre.synchronise_secrets.paramiko.SSHClient", FakeClient)
        resultat = synchroniser_auditbeat(o, "nouveau_mdp_rotate")
        assert resultat.ok is False

    def test_connexion_impossible(self, tmp_path, monkeypatch):
        o = _orch(tmp_path)

        class ClientQuiEchoue:
            def set_missing_host_key_policy(self, _p):
                pass

            def connect(self, *a, **k):
                raise TimeoutError("VM Linux injoignable")

            def close(self):
                pass

        monkeypatch.setattr("cadre.synchronise_secrets.paramiko.SSHClient", ClientQuiEchoue)
        resultat = synchroniser_auditbeat(o, "nouveau_mdp_rotate")
        assert resultat.ok is False
        assert "nouveau_mdp_rotate" not in resultat.detail

    def test_vm_linux_non_configuree(self, tmp_path):
        o = _orch(tmp_path, linux_vm_pass=None)
        resultat = synchroniser_auditbeat(o, "nouveau_mdp_rotate")
        assert resultat.ok is False
        assert "non configurée" in resultat.detail

    def test_aucune_ligne_password_trouvee_cote_distant(self, tmp_path, monkeypatch):
        o = _orch(tmp_path)

        class FakeSFTP:
            def open(self, chemin, mode):
                class F:
                    def __enter__(self):
                        return self

                    def __exit__(self, *a):
                        pass

                    def write(self, data):
                        pass

                return F()

            def chmod(self, chemin, mode):
                pass

            def close(self):
                pass

        class FakeStdout:
            channel = type("C", (), {"recv_exit_status": lambda self: 0})()

            def read(self):
                return b"CADRE_RESULTAT:ERREUR:aucune ligne 'password:' trouvee dans auditbeat.yml"

        class FakeStderr:
            def read(self):
                return b""

        class FakeClient:
            def set_missing_host_key_policy(self, _p):
                pass

            def connect(self, *a, **k):
                pass

            def open_sftp(self):
                return FakeSFTP()

            def exec_command(self, cmd, timeout=None):
                return (None, FakeStdout(), FakeStderr())

            def close(self):
                pass

        monkeypatch.setattr("cadre.synchronise_secrets.paramiko.SSHClient", FakeClient)
        resultat = synchroniser_auditbeat(o, "nouveau_mdp_rotate")
        assert resultat.ok is False
        assert "aucune ligne" in resultat.detail


class TestSynchroniserSecretsBeats:
    def test_sans_elastic_pass_dans_le_coffre(self, tmp_path):
        o = _orch(tmp_path, elastic_pass=None)
        resultats = synchroniser_secrets_beats(o)
        assert len(resultats) == 1
        assert resultats[0].ok is False
        assert "CADRE_ELASTIC_PASS" in resultats[0].detail

    def test_appelle_les_deux_cibles(self, tmp_path, monkeypatch):
        o = _orch(tmp_path)
        appels = []
        monkeypatch.setattr(
            "cadre.synchronise_secrets.synchroniser_winlogbeat",
            lambda orch, mdp, **k: appels.append(("winlogbeat", mdp)) or _resultat_ok("winlogbeat"),
        )
        monkeypatch.setattr(
            "cadre.synchronise_secrets.synchroniser_auditbeat",
            lambda orch, mdp, **k: appels.append(("auditbeat", mdp)) or _resultat_ok("auditbeat"),
        )
        resultats = synchroniser_secrets_beats(o)
        assert len(resultats) == 2
        assert appels == [
            ("winlogbeat", "nouveau_mdp_rotate"),
            ("auditbeat", "nouveau_mdp_rotate"),
        ]


def _resultat_ok(cible):
    from cadre.synchronise_secrets import ResultatSynchronisation

    r = ResultatSynchronisation(cible)
    r.ok = True
    r.detail = "test"
    return r
