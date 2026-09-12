"""
Configuration pytest pour CADRE.

Ce fichier :
- Configure les fixtures partagées
- Définit des markers personnalisés
- Configure le comportement global des tests
"""

import contextlib
import os
import sys
from pathlib import Path

import pytest

# Ajouter le répertoire src/ au PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# ============================================
# Fixtures globales
# ============================================


@pytest.fixture(scope="session")
def repertoire_test():
    """Répertoire de travail pour les tests."""
    return Path(__file__).parent / "_artifacts"


@pytest.fixture(autouse=True)
def isolation_environnement(monkeypatch, tmp_path):
    """Isole chaque test dans un environnement temporaire."""
    # HOME/USERPROFILE → tmp_path
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    # Empêcher l'accès à de vrais secrets
    for key in [
        "CADRE_VM_PASS",
        "CADRE_ELASTIC_PASS",
        "CADRE_KIBANA_TOKEN",
        "CADRE_DASHBOARD_PASSWORD",
    ]:
        monkeypatch.delenv(key, raising=False)
    # `coffre_fort.obtenir()` cherche env > keychain OS > .env AVANT de lever
    # (ordre documenté dans coffre_fort.py). Supprimer la variable d'env ne
    # neutralise que le premier palier : un secret réellement stocké dans le
    # trousseau OS (ex. `cadre init --set CADRE_DASHBOARD_PASSWORD=...` sur
    # la machine de dev) reste lisible par `keyring.get_password()`, qui
    # interroge le Gestionnaire d'identification Windows/Keychain/Secret
    # Service directement -- complètement hors de portée de `monkeypatch` sur
    # `os.environ`. Régression constatée : dès qu'un vrai mot de passe
    # dashboard est configuré sur le poste, `TestServeurHTTP` bascule en 401
    # partout (les requêtes de test n'envoient jamais d'en-tête `Authorization`),
    # sans lien avec le code testé. Neutralisé ici pour la durée de chaque
    # test, quel que soit l'état réel du trousseau de la machine.
    with contextlib.suppress(ImportError):
        import cadre.coffre_fort as cf

        if cf.KEYRING_DISPONIBLE:
            monkeypatch.setattr(cf.keyring, "get_password", lambda service, cle: None)
    # Isoler le catalogue perso : pointer vers un fichier inexistant dans
    # tmp_path pour que catalogue_actif() == catalogue natif (34) par défaut,
    # quel que soit l'état réel de la machine de dev. Les tests qui exercent
    # le catalogue perso surchargent explicitement ce chemin.
    with contextlib.suppress(ImportError):
        import cadre.catalogue_utilisateur as cu

        monkeypatch.setattr(cu, "CHEMIN_CATALOGUE_PERSO", tmp_path / "catalogue_perso.json")
    # Isoler les raffinements de règle (mêmes raisons que le catalogue perso
    # ci-dessus) : jamais le vrai ~/.cadre/raffinements.json d'un poste de dev.
    with contextlib.suppress(ImportError):
        import cadre.raffinement as rf

        monkeypatch.setattr(rf, "CHEMIN_RAFFINEMENTS", tmp_path / "raffinements.json")
    # Isoler la file d'attente de revue (mêmes raisons que ci-dessus) —
    # jamais le vrai ~/.cadre/revues_en_attente.json d'un poste de dev.
    with contextlib.suppress(ImportError):
        import cadre.revue_regles as rv

        monkeypatch.setattr(rv, "CHEMIN_REVUES", tmp_path / "revues_en_attente.json")
    return tmp_path


@pytest.fixture(autouse=True)
def _verrou_isole(tmp_path, monkeypatch):
    """Jamais le vrai `cadre_cycle.lock` du dépôt pendant les tests --
    isolation totale, aucun risque de collision entre tests parallèles ou
    de fichier résiduel dans le dépôt.

    Factorisé ici (régression, audit) : dupliqué à l'identique dans 4
    fichiers de test (TestVerrouCycleInterProcessus, test_boucle.py,
    test_dashboard.py, test_decouverte_ia.py), chacun le déclarant
    `autouse=True` sur sa propre classe -- un futur test touchant
    `_acquerir_verrou_cycle()` en dehors de ces 4 classes n'était protégé
    par rien, sans même un rappel pour y penser. Autouse global ici :
    protection inconditionnelle, jamais une case à cocher par fichier de
    test. Retourne le chemin isolé pour les tests qui l'inspectent
    directement (ex. `assert not _verrou_isole.exists()`).
    """
    chemin = tmp_path / "cadre_cycle.lock"
    monkeypatch.setattr("cadre.orchestrateur._CHEMIN_VERROU_CYCLE", chemin)
    return chemin


@pytest.fixture
def exemple_attaque():
    """Une attaque type pour les tests."""
    from cadre.catalogue_attaques import AttaqueCatalogue, NiveauRisque, Plateforme

    return AttaqueCatalogue(
        id="CADRE-TEST-001",
        nom="Test Attaque",
        description="Une attaque de test",
        technique_mitre="T1059.001",
        tactique_mitre="Execution",
        sous_technique="Test",
        commande="echo test",
        event_ids_attendus=["1"],
        champ_principal="process.command_line",
        valeur_detection="CADRE_TEST_MARKER",
        faux_positifs_connus=[],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1059/001/"],
        prerequisites=[],
        duree_estimee_sec=1,
    )


@pytest.fixture
def log_elastic_exemple():
    """Un log Elastic ECS type pour les tests."""
    return {
        "@timestamp": "2026-07-16T20:00:00.000Z",
        "event": {
            "code": 4720,
            "category": ["iam"],
            "action": "created-user-account",
            "outcome": "success",
        },
        "host": {
            "name": "CADRE-Victim",
            "os": {"family": "windows"},
            "ip": ["192.168.1.100"],
        },
        "user": {
            "name": "alice",
            "domain": "CORP",
            "email": "alice@corp.com",
        },
        "process": {
            "name": "net.exe",
            "command_line": "net user test /add P@ssw0rd",
        },
        "source": {
            "ip": "10.0.0.50",
            "port": 49152,
        },
    }


# ============================================
# Hooks pytest
# ============================================


def pytest_configure(config):
    """Configuration globale de pytest."""
    # Créer le répertoire d'artefacts
    repertoire = Path(__file__).parent / "_artifacts"
    repertoire.mkdir(exist_ok=True)


def pytest_collection_modifyitems(config, items):
    """Marque automatiquement les tests lents."""
    for item in items:
        # Tests qui contiennent "complet" ou "integration" → slow
        if "complet" in item.nodeid.lower() or "integration" in item.nodeid.lower():
            item.add_marker(pytest.mark.slow)
        # Tests dans test_securite.py → security
        if "securite" in item.nodeid.lower():
            item.add_marker(pytest.mark.security)


def pytest_report_header(config):
    """Header personnalisé dans le rapport."""
    return [
        "CADRE — Test Suite",
        f"Python : {sys.version.split()[0]}",
        f"Répertoire : {os.getcwd()}",
        "",
    ]
