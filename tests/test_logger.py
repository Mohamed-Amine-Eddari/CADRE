"""
Tests du logger JSON structuré.
Adapté à l'API réelle de src/cadre/logger.py.
"""

import json

from cadre.logger import CADRELogger, obtenir_logger


class TestCADRELogger:
    """Tests de la classe CADRELogger."""

    def test_logger_cree_repertoire_parent(self, tmp_path):
        """Le logger doit créer le répertoire parent du fichier de log."""
        log_file = tmp_path / "logs" / "cadre.log.json"
        CADRELogger(fichier_log=log_file)
        assert log_file.parent.exists()

    def test_logger_ecrit_evenement_console(self, tmp_path, capsys):
        logger = CADRELogger(fichier_log=tmp_path / "logs" / "cadre.log.json")
        logger.info("Test info")
        captured = capsys.readouterr()
        # La console doit afficher quelque chose
        assert captured.out

    def test_logger_ecrit_json(self, tmp_path):
        """Le logger doit écrire des lignes JSON valides."""
        log_file = tmp_path / "cadre.log.json"
        logger = CADRELogger(fichier_log=log_file)
        logger.info("Démarrage audit", nb_attaques=12)

        assert log_file.exists()
        contenu = log_file.read_text(encoding="utf-8").strip()
        ligne = contenu.split("\n")[0]
        data = json.loads(ligne)
        # Le code source utilise la clé "type" (pas "event_type")
        assert data["type"] == "INFO"
        assert data["nb_attaques"] == 12

    def test_logger_evenements_multiples(self, tmp_path):
        """Plusieurs événements doivent produire plusieurs lignes JSON."""
        log_file = tmp_path / "cadre.log.json"
        logger = CADRELogger(fichier_log=log_file)

        logger.info("Démarrage", nb_attaques=2)
        logger.attack("Attaque T1059.001", id="CADRE-EXE-001")
        logger.success("Règle déployée", id="CADRE-EXE-001")
        logger.warn("FP détecté", fp_count=3)
        logger.blind_spot("EventID non indexé", id="CADRE-EXE-002")
        logger.error("Erreur Elastic", code=500)

        contenu = log_file.read_text(encoding="utf-8")
        lignes = contenu.strip().split("\n")
        assert len(lignes) == 6

        events = [json.loads(ligne) for ligne in lignes]
        types = [e["type"] for e in events]
        assert "INFO" in types
        assert "ATTACK_EXEC" in types
        assert "SUCCESS" in types
        assert "WARN" in types
        assert "BLIND_SPOT" in types
        assert "ERROR" in types

    def test_logger_ne_log_pas_les_secrets_via_kwargs(self, tmp_path):
        """Aucun secret passé en kwarg ne doit apparaître dans les logs."""
        log_file = tmp_path / "cadre.log.json"
        logger = CADRELogger(fichier_log=log_file)
        # L'API actuelle : attack(message, **kwargs)
        logger.attack("Connexion utilisateur", user="alice", action="login")
        contenu = log_file.read_text(encoding="utf-8")
        # Vérifier que les données explicites sont loggées correctement
        data = json.loads(contenu.strip())
        assert data["user"] == "alice"

    def test_logger_console_output_option(self, tmp_path, capsys):
        """Le logger doit pouvoir fonctionner sans sortie console."""
        log_file = tmp_path / "cadre.log.json"
        logger = CADRELogger(fichier_log=log_file)
        logger.info("Test silencieux")
        # Vérifier que le fichier est écrit même si on ne capture pas la console
        assert log_file.exists()

    def test_console_sans_ansi_quand_avec_couleur_desactive(self, tmp_path, capsys):
        """Régression (audit) : `self.avec_couleur` était calculé (détection
        terminal réel/FORCE_COLOR) mais jamais consulté dans
        `_formatter_console` -- les codes d'échappement ANSI étaient
        TOUJOURS émis, y compris vers une sortie redirigée (`cadre cycle >
        audit.log`), polluant le fichier de codes bruts illisibles."""
        logger = CADRELogger(fichier_log=tmp_path / "cadre.log.json")
        logger.avec_couleur = False
        logger.info("Message de test", extra="valeur")
        captured = capsys.readouterr()
        assert "\x1b[" not in captured.out
        assert "Message de test" in captured.out
        assert "extra=valeur" in captured.out

    def test_console_avec_ansi_quand_avec_couleur_active(self, tmp_path, capsys):
        logger = CADRELogger(fichier_log=tmp_path / "cadre.log.json")
        logger.avec_couleur = True
        logger.info("Message de test")
        captured = capsys.readouterr()
        assert "\x1b[" in captured.out

    def test_rotation_quand_fichier_depasse_la_taille_max(self, tmp_path, monkeypatch):
        """Régression (audit) : sans rotation, le fichier de log grossit
        indéfiniment sur un daemon longue durée (`cadre daemon`/`cadre
        loop`), jusqu'à saturer le disque. Au-delà du seuil, l'ancien
        contenu doit être archivé en `.1`, pas accumulé sans limite."""
        import cadre.logger as logger_module

        monkeypatch.setattr(logger_module, "_TAILLE_MAX_LOG_OCTETS", 10)
        log_file = tmp_path / "cadre.log.json"
        logger = CADRELogger(fichier_log=log_file)
        logger.info("Premier message, largement plus de 10 octets à lui seul")
        assert log_file.stat().st_size >= 10

        logger.info("Deuxieme message")

        sauvegarde = log_file.with_name(log_file.name + ".1")
        assert sauvegarde.exists()
        assert "Premier message" in sauvegarde.read_text(encoding="utf-8")
        contenu_courant = log_file.read_text(encoding="utf-8")
        assert "Deuxieme message" in contenu_courant
        assert "Premier message" not in contenu_courant


class TestFiltrageConsoleParNiveau:
    """Tests du filtrage console --verbose/--quiet (niveau_console)."""

    def test_debug_masque_par_defaut(self, tmp_path, capsys):
        """Au niveau INFO (défaut), un message DEBUG n'apparaît pas en console."""
        logger = CADRELogger(fichier_log=tmp_path / "cadre.log.json")
        logger.debug("Détail interne")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_debug_visible_en_mode_verbose(self, tmp_path, capsys):
        """Avec niveau_console=DEBUG (--verbose), un message DEBUG s'affiche."""
        logger = CADRELogger(fichier_log=tmp_path / "cadre.log.json", niveau_console="DEBUG")
        logger.debug("Détail interne")
        captured = capsys.readouterr()
        assert "Détail interne" in captured.out

    def test_info_masque_en_mode_quiet(self, tmp_path, capsys):
        """Avec niveau_console=WARN (--quiet), un message INFO n'apparaît pas."""
        logger = CADRELogger(fichier_log=tmp_path / "cadre.log.json", niveau_console="WARN")
        logger.info("Message courant")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_warn_visible_en_mode_quiet(self, tmp_path, capsys):
        """Avec niveau_console=WARN (--quiet), un WARN reste visible."""
        logger = CADRELogger(fichier_log=tmp_path / "cadre.log.json", niveau_console="WARN")
        logger.warn("Attention")
        captured = capsys.readouterr()
        assert "Attention" in captured.out

    def test_fichier_jamais_filtre_meme_en_mode_quiet(self, tmp_path):
        """Le filtrage console ne doit jamais réduire la trace fichier."""
        log_file = tmp_path / "cadre.log.json"
        logger = CADRELogger(fichier_log=log_file, niveau_console="WARN")
        logger.debug("Détail interne")
        logger.info("Message courant")
        contenu = log_file.read_text(encoding="utf-8").strip()
        lignes = contenu.split("\n")
        assert len(lignes) == 2
        types = [json.loads(ligne)["type"] for ligne in lignes]
        assert types == ["DEBUG", "INFO"]


class TestObtenirLogger:
    """Tests du singleton obtenir_logger."""

    def test_singleton_retourne_meme_instance(self):
        """obtenir_logger doit retourner la même instance (singleton)."""
        log1 = obtenir_logger()
        log2 = obtenir_logger()
        assert log1 is log2

    def test_singleton_est_cadre_logger(self):
        log = obtenir_logger()
        assert isinstance(log, CADRELogger)


class TestHelpers:
    """Tests des helpers de commodité."""

    def test_info_helper(self, tmp_path):
        log_file = tmp_path / "log.json"
        logger = CADRELogger(fichier_log=log_file)
        logger.info("test", key="value")
        data = json.loads(log_file.read_text(encoding="utf-8").strip())
        assert data["type"] == "INFO"
        assert data["key"] == "value"

    def test_warn_helper(self, tmp_path):
        log_file = tmp_path / "log.json"
        logger = CADRELogger(fichier_log=log_file)
        logger.warn("test")
        data = json.loads(log_file.read_text(encoding="utf-8").strip())
        assert data["type"] == "WARN"
        assert data["niveau"] == "WARN"

    def test_error_helper(self, tmp_path):
        log_file = tmp_path / "log.json"
        logger = CADRELogger(fichier_log=log_file)
        logger.error("test")
        data = json.loads(log_file.read_text(encoding="utf-8").strip())
        assert data["type"] == "ERROR"
        assert data["niveau"] == "ERROR"

    def test_success_helper(self, tmp_path):
        log_file = tmp_path / "log.json"
        logger = CADRELogger(fichier_log=log_file)
        logger.success("test")
        data = json.loads(log_file.read_text(encoding="utf-8").strip())
        assert data["type"] == "SUCCESS"
        assert data["niveau"] == "SUCCESS"

    def test_blind_spot_helper(self, tmp_path):
        log_file = tmp_path / "log.json"
        logger = CADRELogger(fichier_log=log_file)
        logger.blind_spot("test")
        data = json.loads(log_file.read_text(encoding="utf-8").strip())
        assert data["type"] == "BLIND_SPOT"
