"""Tests de la validation d'une règle Sigma existante (validation_regle.py).

Le réseau (compter_evenements) est mocké : les tests sont rapides et
déterministes, sans Elasticsearch réel.
"""

from __future__ import annotations

from cadre.attente_indexation import ErreurComptageElastic
from cadre.validation_regle import valider_fichier_regle, valider_regle_sigma

REGLE_SIGMA_VALIDE = """title: Test PowerShell
id: 11111111-1111-1111-1111-111111111111
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    event.code: '1'
    process.command_line|contains: 'foobar'
  condition: selection
level: medium
"""


class TestValiderRegleSigma:
    def test_non_compilable(self, monkeypatch):
        # Force l'échec de compilation (champ non mappé / syntaxe non supportée).
        monkeypatch.setattr("cadre.validation_regle.compiler_sigma_vers_lucene", lambda _y: None)
        res = valider_regle_sigma(REGLE_SIGMA_VALIDE, "http://x:9200", None)
        assert res["verdict"] == "NON_COMPILABLE"
        assert res["compilable"] is False
        assert res["hits"] is None

    def test_silencieuse_zero_hit(self, monkeypatch):
        monkeypatch.setattr("cadre.validation_regle.compter_evenements", lambda *a, **k: 0)
        res = valider_regle_sigma(REGLE_SIGMA_VALIDE, "http://x:9200", None)
        assert res["compilable"] is True
        assert res["verdict"] == "SILENCIEUSE"
        assert res["hits"] == 0
        assert res["requete_lucene"]

    def test_active_bruit_modere(self, monkeypatch):
        monkeypatch.setattr("cadre.validation_regle.compter_evenements", lambda *a, **k: 5)
        res = valider_regle_sigma(REGLE_SIGMA_VALIDE, "http://x:9200", None, seuil_bruit=100)
        assert res["verdict"] == "ACTIVE"
        assert res["hits"] == 5

    def test_bruyante_au_dessus_du_seuil(self, monkeypatch):
        monkeypatch.setattr("cadre.validation_regle.compter_evenements", lambda *a, **k: 500)
        res = valider_regle_sigma(REGLE_SIGMA_VALIDE, "http://x:9200", None, seuil_bruit=100)
        assert res["verdict"] == "BRUYANTE"
        assert res["hits"] == 500

    def test_erreur_elasticsearch_ne_se_lit_pas_comme_silencieuse(self, monkeypatch):
        """Régression sécurité : une panne ES affichait auparavant le verdict
        SILENCIEUSE ("bon signe") -- une mesure ratée n'est pas un vrai zéro.
        Doit produire ERREUR, sans jamais toucher `hits` (reste None : aucune
        mesure n'a réellement eu lieu)."""

        def echoue(*a, **k):
            raise ErreurComptageElastic("Elasticsearch injoignable")

        monkeypatch.setattr("cadre.validation_regle.compter_evenements", echoue)
        res = valider_regle_sigma(REGLE_SIGMA_VALIDE, "http://x:9200", None)
        assert res["verdict"] == "ERREUR"
        assert res["hits"] is None
        assert res["compilable"] is True

    def test_valider_fichier(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cadre.validation_regle.compter_evenements", lambda *a, **k: 0)
        f = tmp_path / "regle.yml"
        f.write_text(REGLE_SIGMA_VALIDE, encoding="utf-8")
        res = valider_fichier_regle(f, "http://x:9200", None)
        assert res["fichier"] == str(f)
        assert res["verdict"] == "SILENCIEUSE"
