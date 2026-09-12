"""
Tests pour le coffre-fort de credentials.
"""

import pytest

from cadre.coffre_fort import (
    CHEMIN_COFFRE,
    CoffreFortCADRE,
    ErreurSecurite,
    obtenir_coffre,
)


@pytest.fixture
def coffre_tmp(tmp_path, monkeypatch):
    """Crée un coffre-fort temporaire pour les tests."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr("cadre.coffre_fort.CHEMIN_COFFRE", tmp_path / ".cadre")
    monkeypatch.setattr("cadre.coffre_fort.FICHIER_ENV", tmp_path / ".cadre" / ".env")
    monkeypatch.setattr("cadre.coffre_fort.FICHIER_MASTER_KEY", tmp_path / ".cadre" / "master.key")
    return CoffreFortCADRE(utiliser_keychain=False)


@pytest.fixture
def keyring_factice(monkeypatch):
    """Trousseau système en mémoire — ne touche jamais le vrai Credential Manager."""
    magasin: dict[str, str] = {}
    monkeypatch.setattr(
        "cadre.coffre_fort.keyring.set_password",
        lambda service, cle, valeur: magasin.__setitem__(cle, valeur),
    )
    monkeypatch.setattr(
        "cadre.coffre_fort.keyring.get_password",
        lambda service, cle: magasin.get(cle),
    )

    def supprimer(service, cle):
        del magasin[cle]  # KeyError si absent, comme un vrai trousseau

    monkeypatch.setattr("cadre.coffre_fort.keyring.delete_password", supprimer)
    return magasin


@pytest.fixture
def coffre_keychain(tmp_path, monkeypatch, keyring_factice):
    """Coffre-fort avec keychain activé (mocké)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr("cadre.coffre_fort.CHEMIN_COFFRE", tmp_path / ".cadre")
    monkeypatch.setattr("cadre.coffre_fort.FICHIER_ENV", tmp_path / ".cadre" / ".env")
    monkeypatch.setattr("cadre.coffre_fort.FICHIER_MASTER_KEY", tmp_path / ".cadre" / "master.key")
    return CoffreFortCADRE(utiliser_keychain=True)


class TestCleMaitre:
    """EXC4 : génération/rechargement de la clé Fernet locale (jamais
    couvert avant) — mécanique de fichier, aucun secret réel manipulé."""

    def test_generation_puis_rechargement(self, tmp_path, monkeypatch):
        from cadre.coffre_fort import _charger_cle_maitre, _generer_cle_maitre

        chemin_master = tmp_path / ".cadre" / "master.key"
        monkeypatch.setattr("cadre.coffre_fort.CHEMIN_COFFRE", tmp_path / ".cadre")
        monkeypatch.setattr("cadre.coffre_fort.FICHIER_MASTER_KEY", chemin_master)

        cle = _generer_cle_maitre()
        assert chemin_master.exists()
        assert _charger_cle_maitre() == cle  # rechargement = même clé, pas régénérée

    def test_charger_genere_si_absente(self, tmp_path, monkeypatch):
        from cadre.coffre_fort import _charger_cle_maitre

        monkeypatch.setattr("cadre.coffre_fort.CHEMIN_COFFRE", tmp_path / ".cadre")
        monkeypatch.setattr(
            "cadre.coffre_fort.FICHIER_MASTER_KEY", tmp_path / ".cadre" / "master.key"
        )
        cle = _charger_cle_maitre()  # aucun fichier au départ
        assert isinstance(cle, bytes) and len(cle) > 0

    def test_generation_sans_cryptography_leve(self, tmp_path, monkeypatch):
        from cadre.coffre_fort import ErreurSecurite, _generer_cle_maitre

        monkeypatch.setattr("cadre.coffre_fort.CRYPTO_DISPONIBLE", False)
        with pytest.raises(ErreurSecurite):
            _generer_cle_maitre()


class TestCoffreFort:
    def test_repertoire_cree(self, coffre_tmp, monkeypatch):
        """Régression : l'assertion d'origine (`CHEMIN_COFFRE.exists() or
        True`) était vraie par construction quoi qu'il arrive -- ne
        prouvait rien. Le répertoire n'est créé que lors du premier
        stockage réel (repli env), jamais à la simple construction du
        coffre -- ce test doit donc en déclencher un pour avoir un sens."""
        monkeypatch.setattr("cadre.coffre_fort.DOTENV_DISPONIBLE", True)
        coffre_tmp.stocker("CLE_TEST", "valeur", methode="env")
        assert CHEMIN_COFFRE.exists()

    def test_obtenir_secret_manquant(self, coffre_tmp, monkeypatch):
        monkeypatch.delenv("TEST_SECRET", raising=False)
        with pytest.raises(ErreurSecurite):
            coffre_tmp.obtenir("TEST_SECRET")

    def test_obtenir_avec_defaut(self, coffre_tmp):
        resultat = coffre_tmp.obtenir("CLE_INEXISTANTE", defaut="defaut")
        assert resultat == "defaut"

    def test_variable_environnement_prioritaire(self, coffre_tmp, monkeypatch):
        monkeypatch.setenv("TEST_KEY", "valeur_env")
        resultat = coffre_tmp.obtenir("TEST_KEY")
        assert resultat == "valeur_env"

    def test_stocker_et_lire_env(self, coffre_tmp, monkeypatch):
        """Régression : l'assertion d'origine comparait à `os.environ.get(...)`
        -- que `methode="env"` ne peuple JAMAIS (elle écrit dans le fichier
        .env, pas dans l'environnement du process) -- donc toujours None,
        masqué par un `or True` qui rendait le test vrai quoi qu'il arrive.
        Round-trip réel : stocker puis relire via le coffre lui-même."""
        monkeypatch.setattr("cadre.coffre_fort.DOTENV_DISPONIBLE", True)
        coffre_tmp.stocker("MA_CLE", "MA_VALEUR", methode="env")
        assert coffre_tmp.obtenir("MA_CLE") == "MA_VALEUR"

    def test_stocker_valeur_vide(self, coffre_tmp):
        with pytest.raises(ErreurSecurite):
            coffre_tmp.stocker("CLE", "")

    def test_stocker_cle_avec_saut_de_ligne_est_rejetee(self, coffre_tmp, monkeypatch):
        """Régression sécurité : `cle` n'était jamais validée -- le repli
        .env écrit `cle` BRUTE via dotenv.set_key(), qui ne neutralise pas
        un saut de ligne (vérifié empiriquement : une clé contenant
        "\\nCADRE_ELASTIC_URL=http://attaquant/" injectait réellement une
        seconde variable arbitraire dans ~/.cadre/.env, relue au prochain
        load_dotenv()). Rejetée AVANT toute écriture."""
        monkeypatch.setattr("cadre.coffre_fort.DOTENV_DISPONIBLE", True)
        cle_malicieuse = "FOO\nCADRE_ELASTIC_URL=http://attaquant.example/"
        with pytest.raises(ErreurSecurite):
            coffre_tmp.stocker(cle_malicieuse, "valeur", methode="env")
        from cadre.coffre_fort import FICHIER_ENV

        assert not FICHIER_ENV.exists() or "attaquant" not in FICHIER_ENV.read_text(
            encoding="utf-8"
        )

    @pytest.mark.parametrize(
        "cle_invalide",
        [
            "clé-minuscule",  # minuscules non autorisées
            "CLE AVEC ESPACE",
            "CLE-AVEC-TIRET",
            "1CLE_COMMENCE_PAR_CHIFFRE",
            "",
            "CLE=INJECTION",
        ],
    )
    def test_stocker_cle_mal_formee_est_rejetee(self, coffre_tmp, cle_invalide):
        with pytest.raises(ErreurSecurite):
            coffre_tmp.stocker(cle_invalide, "valeur", methode="env")

    def test_stocker_cle_bien_formee_acceptee(self, coffre_tmp, monkeypatch):
        """Non-régression : la convention réelle (MAJUSCULES/chiffres/_,
        ex. CADRE_BRUTE_TEST_PASS) doit continuer à fonctionner."""
        monkeypatch.setattr("cadre.coffre_fort.DOTENV_DISPONIBLE", True)
        coffre_tmp.stocker("CADRE_BRUTE_TEST_PASS", "valeur", methode="env")
        assert coffre_tmp.obtenir("CADRE_BRUTE_TEST_PASS") == "valeur"

    def test_methode_inconnue(self, coffre_tmp):
        with pytest.raises(ErreurSecurite):
            coffre_tmp.stocker("CLE", "VALEUR", methode="inexistant")

    def test_stocker_keychain_module_indisponible(self, coffre_tmp):
        """coffre_tmp a utiliser_keychain=False : forcer methode='keychain' doit échouer."""
        with pytest.raises(ErreurSecurite):
            coffre_tmp.stocker("CLE", "VALEUR", methode="keychain")

    def test_supprimer_secret_env(self, coffre_tmp, monkeypatch):
        monkeypatch.setattr("cadre.coffre_fort.DOTENV_DISPONIBLE", True)
        coffre_tmp.stocker("CLE_A_SUPPRIMER", "valeur", methode="env")
        assert "CLE_A_SUPPRIMER" in coffre_tmp.lister_cles()

        supprime = coffre_tmp.supprimer("CLE_A_SUPPRIMER")

        assert supprime is True
        assert "CLE_A_SUPPRIMER" not in coffre_tmp.lister_cles()

    def test_supprimer_cle_inexistante(self, coffre_tmp, monkeypatch):
        monkeypatch.setattr("cadre.coffre_fort.DOTENV_DISPONIBLE", True)
        assert coffre_tmp.supprimer("CLE_JAMAIS_STOCKEE") is False

    def test_lister_cles_ignore_commentaires_et_lignes_vides(self, coffre_tmp, monkeypatch):
        monkeypatch.setattr("cadre.coffre_fort.DOTENV_DISPONIBLE", True)
        from cadre.coffre_fort import FICHIER_ENV

        FICHIER_ENV.parent.mkdir(parents=True, exist_ok=True)
        FICHIER_ENV.write_text("# commentaire\n\nCLE_VALIDE=valeur\n", encoding="utf-8")
        assert "CLE_VALIDE" in coffre_tmp.lister_cles()

    def test_stocker_env_chiffre_sur_disque(self, coffre_tmp, monkeypatch):
        """Régression critique : le repli .env stockait les secrets EN CLAIR
        sur disque -- le chiffrement Fernet annoncé par le docstring du
        module n'était jamais appelé (_charger_cle_maitre n'avait aucun
        appelant). Le fichier .env réel ne doit JAMAIS contenir la valeur en
        clair, seulement un jeton préfixé "cadre-enc:"."""
        from cadre.coffre_fort import FICHIER_ENV

        monkeypatch.setattr("cadre.coffre_fort.DOTENV_DISPONIBLE", True)
        coffre_tmp.stocker("CLE_SENSIBLE", "valeur-tres-secrete-123", methode="env")

        contenu_disque = FICHIER_ENV.read_text(encoding="utf-8")
        assert "valeur-tres-secrete-123" not in contenu_disque
        assert "cadre-enc:" in contenu_disque

        # Round-trip : relu et déchiffré correctement (nouvelle instance,
        # pas de cache en mémoire -- preuve que la clé maître persiste bien).
        monkeypatch.delenv("CLE_SENSIBLE", raising=False)
        assert coffre_tmp.obtenir("CLE_SENSIBLE") == "valeur-tres-secrete-123"

    def test_lecture_secret_env_en_clair_herite_reste_lisible(self, coffre_tmp, monkeypatch):
        """Compatibilité ascendante : un .env écrit par une installation
        antérieure à ce correctif (valeur en clair, sans préfixe) doit rester
        lisible sans erreur -- pas de blocage au premier lancement après mise
        à jour."""
        from cadre.coffre_fort import FICHIER_ENV

        monkeypatch.setattr("cadre.coffre_fort.DOTENV_DISPONIBLE", True)
        FICHIER_ENV.parent.mkdir(parents=True, exist_ok=True)
        FICHIER_ENV.write_text("CLE_HERITEE=valeur-en-clair-ancienne\n", encoding="utf-8")

        monkeypatch.delenv("CLE_HERITEE", raising=False)
        assert coffre_tmp.obtenir("CLE_HERITEE") == "valeur-en-clair-ancienne"

    def test_dechiffrement_avec_mauvaise_cle_maitre_leve(self, coffre_tmp, monkeypatch):
        """Une valeur chiffrée avec une AUTRE clé maître (ex. master.key
        perdu/remplacé) doit lever une erreur claire, jamais retourner un
        déchiffrement silencieusement corrompu."""
        from cadre.coffre_fort import FICHIER_MASTER_KEY, ErreurSecurite

        monkeypatch.setattr("cadre.coffre_fort.DOTENV_DISPONIBLE", True)
        coffre_tmp.stocker("CLE_PERDUE", "valeur", methode="env")

        FICHIER_MASTER_KEY.unlink()  # simule une clé maître perdue/régénérée
        monkeypatch.delenv("CLE_PERDUE", raising=False)
        with pytest.raises(ErreurSecurite):
            coffre_tmp.obtenir("CLE_PERDUE")

    def test_lister_cles_ne_fuit_pas_les_variables_systeme(self, coffre_tmp, monkeypatch):
        """Régression : lister_cles() unionnait tout `os.environ`, exposant
        des centaines de variables système (PATH, USERNAME...) sans rapport
        avec les secrets CADRE — découvert en exposant cette méthode via le
        dashboard web. Seules les clés CADRE_* (env) ou déjà dans le .env
        doivent apparaître."""
        monkeypatch.setenv("PATH", "/usr/bin")
        monkeypatch.setenv("USERNAME", "quelqu_un")
        monkeypatch.setenv("CADRE_VM_IP", "192.168.56.104")
        cles = coffre_tmp.lister_cles()
        assert "PATH" not in cles
        assert "USERNAME" not in cles
        assert "CADRE_VM_IP" in cles


class TestCoffreFortKeychain:
    """Tests du chemin keychain (trousseau système mocké, jamais le vrai)."""

    def test_stocker_puis_obtenir_via_keychain(self, coffre_keychain, monkeypatch):
        monkeypatch.delenv("CLE_KEYCHAIN", raising=False)
        coffre_keychain.stocker("CLE_KEYCHAIN", "secret123", methode="keychain")
        assert coffre_keychain.obtenir("CLE_KEYCHAIN") == "secret123"

    def test_methode_auto_utilise_keychain_si_disponible(
        self, coffre_keychain, keyring_factice, monkeypatch
    ):
        monkeypatch.delenv("CLE_AUTO", raising=False)
        coffre_keychain.stocker("CLE_AUTO", "valeur_auto", methode="auto")
        assert "CLE_AUTO" in keyring_factice

    def test_supprimer_keychain(self, coffre_keychain, monkeypatch):
        monkeypatch.delenv("CLE_A_EFFACER", raising=False)
        coffre_keychain.stocker("CLE_A_EFFACER", "valeur", methode="keychain")
        assert coffre_keychain.supprimer("CLE_A_EFFACER") is True

    def test_env_prioritaire_meme_avec_keychain_actif(
        self, coffre_keychain, keyring_factice, monkeypatch
    ):
        keyring_factice["CLE_PARTAGEE"] = "valeur_keychain"
        monkeypatch.setenv("CLE_PARTAGEE", "valeur_env")
        assert coffre_keychain.obtenir("CLE_PARTAGEE") == "valeur_env"

    def test_lecture_keychain_exception_replie_sur_defaut(self, coffre_keychain, monkeypatch):
        """EXC4 : keyring.get_password lève (trousseau système indisponible/
        verrouillé) — doit être absorbé, pas remonter."""
        monkeypatch.delenv("CLE_KEYRING_KO", raising=False)

        def get_password_qui_leve(service, cle):
            raise RuntimeError("trousseau verrouillé")

        monkeypatch.setattr("cadre.coffre_fort.keyring.get_password", get_password_qui_leve)
        assert coffre_keychain.obtenir("CLE_KEYRING_KO", defaut="repli") == "repli"

    def test_suppression_keychain_exception_absorbee(self, coffre_keychain, monkeypatch):
        """EXC4 : keyring.delete_password lève (clé absente du trousseau) —
        ne doit jamais faire planter supprimer()."""

        def delete_qui_leve(service, cle):
            raise RuntimeError("clé absente")

        monkeypatch.setattr("cadre.coffre_fort.keyring.delete_password", delete_qui_leve)
        assert coffre_keychain.supprimer("CLE_JAMAIS_STOCKEE") is False


@pytest.fixture
def journal_tmp(tmp_path, monkeypatch):
    """Redirige le logger utilisé par le coffre-fort vers un fichier JSON temporaire."""
    from cadre.logger import CADRELogger

    log_file = tmp_path / "audit.log.json"
    logger_factice = CADRELogger(fichier_log=log_file)
    monkeypatch.setattr("cadre.coffre_fort.obtenir_logger", lambda: logger_factice)
    return log_file


def _lire_evenements(log_file):
    import json

    if not log_file.exists():
        return []
    return [json.loads(ligne) for ligne in log_file.read_text(encoding="utf-8").strip().split("\n")]


class TestAuditCoffreFort:
    """Le coffre-fort doit journaliser chaque accès (clé/source), jamais la valeur."""

    def test_lecture_reussie_journalisee(self, coffre_tmp, monkeypatch, journal_tmp):
        monkeypatch.setenv("CLE_AUDIT", "secret-tres-sensible")
        coffre_tmp.obtenir("CLE_AUDIT")

        evenements = _lire_evenements(journal_tmp)
        lectures = [e for e in evenements if e["type"] == "SECRET_READ"]
        assert len(lectures) == 1
        assert lectures[0]["cle"] == "CLE_AUDIT"
        assert lectures[0]["source"] == "env"
        assert "secret-tres-sensible" not in journal_tmp.read_text(encoding="utf-8")

    def test_lecture_echouee_journalisee_en_warn(self, coffre_tmp, monkeypatch, journal_tmp):
        monkeypatch.delenv("CLE_ABSENTE", raising=False)
        with pytest.raises(ErreurSecurite):
            coffre_tmp.obtenir("CLE_ABSENTE")

        evenements = _lire_evenements(journal_tmp)
        lectures = [e for e in evenements if e["type"] == "SECRET_READ"]
        assert len(lectures) == 1
        assert lectures[0]["trouve"] is False
        assert lectures[0]["niveau"] == "WARN"

    def test_ecriture_journalisee_sans_la_valeur(self, coffre_tmp, monkeypatch, journal_tmp):
        monkeypatch.setattr("cadre.coffre_fort.DOTENV_DISPONIBLE", True)
        coffre_tmp.stocker("CLE_ECRITE", "valeur-ultra-secrete", methode="env")

        evenements = _lire_evenements(journal_tmp)
        ecritures = [e for e in evenements if e["type"] == "SECRET_WRITE"]
        assert len(ecritures) == 1
        assert ecritures[0]["cle"] == "CLE_ECRITE"
        assert ecritures[0]["methode"] == "env"
        assert "valeur-ultra-secrete" not in journal_tmp.read_text(encoding="utf-8")

    def test_suppression_journalisee(self, coffre_tmp, monkeypatch, journal_tmp):
        monkeypatch.setattr("cadre.coffre_fort.DOTENV_DISPONIBLE", True)
        coffre_tmp.stocker("CLE_A_EFFACER", "valeur", methode="env")
        coffre_tmp.supprimer("CLE_A_EFFACER")

        evenements = _lire_evenements(journal_tmp)
        suppressions = [e for e in evenements if e["type"] == "SECRET_DELETE"]
        assert len(suppressions) == 1
        assert suppressions[0]["supprime"] is True

    def test_suppression_inexistante_journalisee_en_warn(self, coffre_tmp, journal_tmp):
        coffre_tmp.supprimer("CLE_JAMAIS_VUE")

        evenements = _lire_evenements(journal_tmp)
        suppressions = [e for e in evenements if e["type"] == "SECRET_DELETE"]
        assert len(suppressions) == 1
        assert suppressions[0]["supprime"] is False
        assert suppressions[0]["niveau"] == "WARN"


class TestObtenirCoffreSingleton:
    def test_obtenir_coffre_retourne_toujours_la_meme_instance(self, monkeypatch):
        monkeypatch.setattr("cadre.coffre_fort._coffre_instance", None)
        premiere = obtenir_coffre()
        deuxieme = obtenir_coffre()
        assert premiere is deuxieme


class TestSecretOrNone:
    """EXC4 : helper `secret_or_none` (jamais couvert avant)."""

    def test_secret_absent_retourne_none(self, tmp_path, monkeypatch):
        from cadre.coffre_fort import secret_or_none

        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        monkeypatch.setattr("cadre.coffre_fort._coffre_instance", None)
        monkeypatch.setattr("cadre.coffre_fort.CHEMIN_COFFRE", tmp_path / ".cadre")
        monkeypatch.setattr("cadre.coffre_fort.FICHIER_ENV", tmp_path / ".cadre" / ".env")
        monkeypatch.setattr(
            "cadre.coffre_fort.FICHIER_MASTER_KEY", tmp_path / ".cadre" / "master.key"
        )
        monkeypatch.delenv("CLE_JAMAIS_DEFINIE_XYZ", raising=False)
        assert secret_or_none("CLE_JAMAIS_DEFINIE_XYZ") is None

    def test_secret_present_retourne_la_valeur(self, tmp_path, monkeypatch):
        from cadre.coffre_fort import secret_or_none

        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        monkeypatch.setattr("cadre.coffre_fort._coffre_instance", None)
        monkeypatch.setattr("cadre.coffre_fort.CHEMIN_COFFRE", tmp_path / ".cadre")
        monkeypatch.setattr("cadre.coffre_fort.FICHIER_ENV", tmp_path / ".cadre" / ".env")
        monkeypatch.setattr(
            "cadre.coffre_fort.FICHIER_MASTER_KEY", tmp_path / ".cadre" / "master.key"
        )
        monkeypatch.setenv("CLE_PRESENTE_XYZ", "valeur_test")
        assert secret_or_none("CLE_PRESENTE_XYZ") == "valeur_test"
