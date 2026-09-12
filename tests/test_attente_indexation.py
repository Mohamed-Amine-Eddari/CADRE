"""
Tests du module d'attente d'indexation.
Adapté à l'API réelle de src/cadre/attente_indexation.py
qui utilise requests + URL Elastic directement.
"""

import time
from unittest.mock import MagicMock, patch

import pytest

from cadre.attente_indexation import (
    ErreurComptageElastic,
    attendre_indexation,
    compter_evenements,
)


class TestAttendreIndexation:
    """Tests de la fonction attendre_indexation."""

    def test_retourne_immediatement_si_log_present(self):
        """Si l'event est déjà dans Elastic, on retourne sans attendre."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "hits": {"total": {"value": 1}, "hits": [{"_source": {"x": 1}}]}
        }
        mock_response.raise_for_status = MagicMock()

        with patch(
            "cadre.attente_indexation.requests.post", return_value=mock_response
        ) as mock_post:
            resultat = attendre_indexation(
                elastic_url="http://localhost:9200",
                index_pattern="winlogbeat-*",
                event_ids=["4720"],
                timeout_max_sec=10,
            )
            assert resultat is not None
            assert mock_post.call_count == 1

    def test_timeout_si_jamais_present(self):
        """Si aucun log n'arrive, on retourne None après timeout."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
        mock_response.raise_for_status = MagicMock()

        with (
            patch("cadre.attente_indexation.requests.post", return_value=mock_response),
            patch("cadre.attente_indexation.time.sleep"),
        ):  # Accélérer le test
            debut = time.monotonic()
            resultat = attendre_indexation(
                elastic_url="http://localhost:9200",
                index_pattern="winlogbeat-*",
                event_ids=["4720"],
                timeout_max_sec=2,  # Court pour le test
            )
            duree = time.monotonic() - debut
            assert resultat is None
            # On vérifie qu'on a bien attendu (au moins ~2s)
            assert duree >= 1.5

    def test_polling_adaptatif_delais_croissants(self):
        """Le polling doit s'espacer au fur et à mesure (3s → 15s)."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
        mock_response.raise_for_status = MagicMock()

        delais_observes = []

        def mock_sleep(duree):
            delais_observes.append(duree)

        with (
            patch("cadre.attente_indexation.requests.post", return_value=mock_response),
            patch("cadre.attente_indexation.time.sleep", side_effect=mock_sleep),
        ):
            attendre_indexation(
                elastic_url="http://localhost:9200",
                index_pattern="winlogbeat-*",
                event_ids=["4720"],
                timeout_max_sec=5,
                intervalle_initial_sec=0.5,
                intervalle_max_sec=2.0,
            )

        # Au moins 2 polls et délais croissants
        assert len(delais_observes) >= 2
        # Le dernier délai doit être >= au premier (backoff progressif)
        assert delais_observes[-1] >= delais_observes[0]

    def test_gestion_erreur_requete_sans_crash(self):
        """Une erreur réseau ne doit pas faire crasher la fonction."""
        with (
            patch("cadre.attente_indexation.requests.post", side_effect=Exception("Network error")),
            patch("cadre.attente_indexation.time.sleep"),
        ):
            resultat = attendre_indexation(
                elastic_url="http://localhost:9200",
                index_pattern="winlogbeat-*",
                event_ids=["4720"],
                timeout_max_sec=2,
            )
            # Retourne None en cas d'erreur persistante
            assert resultat is None

    def test_utilise_fenetre_glissante(self):
        """La requête doit contenir une fenêtre temporelle glissante."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
        mock_response.raise_for_status = MagicMock()

        with (
            patch(
                "cadre.attente_indexation.requests.post", return_value=mock_response
            ) as mock_post,
            patch("cadre.attente_indexation.time.sleep"),
        ):
            attendre_indexation(
                elastic_url="http://localhost:9200",
                index_pattern="winlogbeat-*",
                event_ids=["4720"],
                timeout_max_sec=2,
                fenetre_glissante_sec=600,
            )

        call_args = mock_post.call_args
        body = call_args.kwargs.get("json") or call_args.args[1]
        # Vérifier qu'il y a bien une range query
        assert "range" in str(body)


class TestCompterEvenements:
    """Tests de la fonction compter_evenements."""

    def test_comptage_simple(self):
        """Compte le nombre de documents correspondants."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"count": 42}
        mock_response.raise_for_status = MagicMock()

        with patch(
            "cadre.attente_indexation.requests.post", return_value=mock_response
        ) as mock_post:
            nb = compter_evenements(
                elastic_url="http://localhost:9200",
                index_pattern="winlogbeat-*",
                requete_dsl={"query": {"match_all": {}}},
            )
            assert nb == 42
            assert mock_post.call_count == 1

    def test_comptage_zero(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"count": 0}
        mock_response.raise_for_status = MagicMock()

        with patch("cadre.attente_indexation.requests.post", return_value=mock_response):
            nb = compter_evenements(
                elastic_url="http://localhost:9200",
                index_pattern="winlogbeat-*",
                requete_dsl={"query": {"match_all": {}}},
            )
            assert nb == 0

    def test_comptage_erreur_leve_erreur_comptage_elastic(self):
        """Régression sécurité (audit) : une panne renvoyait auparavant 0,
        indiscernable d'un VRAI zéro résultat -- une panne PENDANT la
        mesure de faux positifs se lisait alors comme "aucun bruit", et
        une règle non prouvée était validée/déployée (fail OPEN). Doit
        maintenant lever, jamais retourner silencieusement 0."""
        with (
            patch("cadre.attente_indexation.requests.post", side_effect=Exception("Network")),
            pytest.raises(ErreurComptageElastic),
        ):
            compter_evenements(
                elastic_url="http://localhost:9200",
                index_pattern="winlogbeat-*",
                requete_dsl={"query": {"match_all": {}}},
            )
