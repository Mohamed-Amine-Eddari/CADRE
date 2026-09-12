"""
Tests du helper de politique TLS (src/cadre/reseau.py).

Défaut sûr pour le labo local (pas de vérification TLS sur 127.0.0.1),
activable en production via la variable d'environnement.
"""

from __future__ import annotations

import pytest

from cadre.reseau import verifier_tls


@pytest.fixture(autouse=True)
def _env_propre(monkeypatch):
    monkeypatch.delenv("CADRE_VERIFY_TLS", raising=False)


def test_defaut_desactive():
    assert verifier_tls() is False


@pytest.mark.parametrize("valeur", ["1", "true", "TRUE", "yes", "on", " On "])
def test_active_par_env(monkeypatch, valeur):
    monkeypatch.setenv("CADRE_VERIFY_TLS", valeur)
    assert verifier_tls() is True


@pytest.mark.parametrize("valeur", ["0", "false", "no", "", "nope"])
def test_valeurs_negatives_restent_desactivees(monkeypatch, valeur):
    monkeypatch.setenv("CADRE_VERIFY_TLS", valeur)
    assert verifier_tls() is False
