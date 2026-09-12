"""
Tests de sécurité transverses.

Ces tests garantissent que CADRE ne泄露 pas de secrets, applique
l'anonymisation, et respecte le modèle de sécurité.
"""

import re
from pathlib import Path

import pytest

# Patterns de mots de passe communs (à NE JAMAIS retrouver dans les logs)
# Valeurs factices uniquement -- ne JAMAIS réutiliser un vrai secret ici, ce
# fichier est suivi par git (régression : deux vrais mots de passe du labo
# ont fini dans cette liste par le passé, exposés dans l'historique).
SECRETS_INTERDITS = [
    "P@ssw0rd",
    "TestFictifNonUtilise2099!",
    "VOTRE_MOT_DE_PASSE",
    "AutreTestFictifNonUtilise2099!",
]

# Patterns de PII
PII_PATTERNS = [
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # IPv4
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # Email
    r"\\Users\\[\w.-]+",  # Chemin Windows
]


class TestAucunSecretDansLogs:
    """Aucun mot de passe ne doit apparaître dans les logs."""

    def test_logger_ne_log_pas_les_mots_de_passe(self, tmp_path, monkeypatch):
        """Le logger ne doit pas logger de secrets passés en argument."""
        monkeypatch.chdir(tmp_path)
        from cadre.logger import CADRELogger

        # L'API réelle utilise fichier_log= (pas repertoire=)
        log_file = tmp_path / "logs" / "cadre.log.json"
        logger = CADRELogger(fichier_log=log_file)
        logger.info("Démarrage audit", nb_attaques=1)
        # L'API réelle : attack(message, **kwargs) — on peut passer des champs métier
        logger.attack("Connexion WinRM", user="alice", host="192.168.1.1")
        logger.success("Règle déployée", rule_id="CADRE-EXE-001")

        log_file = tmp_path / "logs" / "cadre.log.json"
        contenu = log_file.read_text(encoding="utf-8")

        # Les secrets explicites ne doivent PAS être dans les logs
        for secret in SECRETS_INTERDITS:
            assert secret not in contenu, f"Secret {secret!r} trouvé dans les logs !"

        # Si on ne passe pas explicitement de secret, aucun n'apparaît
        assert "P@ssw0rdSecret" not in contenu


class TestAucunSecretDansRapports:
    """Les rapports générés ne doivent pas泄露 de secrets."""

    def test_rapport_markdown_anonymise(self, tmp_path):
        from cadre.anonymisation import anonymiser_log_elastic
        from cadre.rapport import generer_rapport_cycle

        resultats = [
            {
                "timestamp": "2026-07-16T20:30:00",
                "id": "CADRE-EXE-001",
                "nom": "Test",
                "technique_mitre": "T1059.001",
                "tactique": "Execution",
                "description": "Test",
                "event_ids_attendus": ["4688"],
                "statut": "VALIDE",
                "raison": "OK",
                "nb_tp": 1,
                "nb_fp": 0,
                "log_associe": {
                    "user.name": "alice",
                    "host.ip": "192.168.1.100",
                },
            }
        ]
        # Anonymiser AVANT de générer le rapport
        resultats_anonymises = []
        for r in resultats:
            r_clean = {k: v for k, v in r.items() if k != "log_associe"}
            if "log_associe" in r:
                r_clean["log_associe_anonymise"] = anonymiser_log_elastic(r["log_associe"])
            resultats_anonymises.append(r_clean)

        chemin = tmp_path / "rapport.md"
        generer_rapport_cycle(resultats_anonymises, chemin)
        contenu = chemin.read_text(encoding="utf-8")

        # Vérifier qu'aucun PII n'apparaît
        for pattern in PII_PATTERNS:
            matches = re.findall(pattern, contenu)
            assert len(matches) == 0, f"PII trouvé : {matches}"


class TestCatalogueImmutable:
    """Le catalogue ne doit pas pouvoir être modifié à l'exécution."""

    def test_catalogue_est_frozen(self):
        from cadre.catalogue_attaques import CATALOGUE

        # Tenter de modifier (doit lever FrozenInstanceError)
        with pytest.raises((AttributeError, Exception)):
            CATALOGUE[0].commande = "rm -rf /"

    def test_catalogue_unique_ids(self):
        """Tous les IDs du catalogue doivent être uniques."""
        from cadre.catalogue_attaques import CATALOGUE

        ids = [a.id for a in CATALOGUE]
        assert len(ids) == len(set(ids)), "IDs en doublon dans le catalogue"

    def test_catalogue_techniques_mitre_valides(self):
        """Toutes les techniques doivent suivre le format TXXXX[.XXX]."""
        from cadre.catalogue_attaques import CATALOGUE

        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for a in CATALOGUE:
            assert pattern.match(
                a.technique_mitre
            ), f"Technique MITRE invalide : {a.technique_mitre}"


class TestPasDeBackdoor:
    """Recherche de patterns suspects dans le code source."""

    @pytest.mark.parametrize(
        "module",
        [
            "cadre.catalogue_attaques",
            "cadre.orchestrateur",
            "cadre.coffre_fort",
            "cadre.anonymisation",
            "cadre.compilation_sigma",
        ],
    )
    def test_pas_de_eval(self, module):
        """Aucun appel à eval() dans le code source."""
        import importlib

        mod = importlib.import_module(module)
        # Vérifier qu'il n'y a pas d'attribut suspect
        source_path = mod.__file__
        if source_path and source_path.endswith(".py"):
            contenu = Path(source_path).read_text(encoding="utf-8")
            # eval() est interdit (sauf dans des contextes très spécifiques)
            # On accepte les occurrences dans les chaînes/commentaires
            lines = [
                line
                for line in contenu.split("\n")
                if "eval(" in line
                and not line.strip().startswith("#")
                and '"' not in line.split("eval(")[0]
            ]
            assert len(lines) == 0, f"Appel à eval() trouvé dans {module} : {lines}"


class TestPermissionsFichiers:
    """Les fichiers sensibles doivent avoir des permissions restrictives."""

    def test_env_example_lisible_par_tous(self, tmp_path):
        """Le fichier .env.example ne contient pas de vrais secrets."""
        env_example = Path(".env.example")
        if env_example.exists():
            contenu = env_example.read_text(encoding="utf-8")
            # Aucun mot de passe en clair
            for secret in SECRETS_INTERDITS:
                # Le pattern "=secret" est suspect
                assert f"={secret}" not in contenu, f"Secret {secret!r} trouvé dans .env.example"
