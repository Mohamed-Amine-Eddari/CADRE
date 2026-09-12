"""Tests de l'export des règles au format Sigma (export_sigma.py).

L'export réel compile toutes les règles du catalogue vers 3 formats — coûteux.
On l'exécute donc
UNE seule fois par classe (fixture `export_partage`), et chaque test lit le
résultat, plutôt que de relancer l'export à chaque cas.
"""

from __future__ import annotations

import json

import pytest
import yaml

from cadre.catalogue_attaques import CATALOGUE
from cadre.export_sigma import exporter_regles_sigma


@pytest.fixture(scope="class")
def export_partage(tmp_path_factory):
    """Exporte une seule fois vers un dossier temporaire partagé par la classe."""
    repertoire = tmp_path_factory.mktemp("export_sigma")
    resultat = exporter_regles_sigma(repertoire)
    return repertoire, resultat


class TestExportSigma:
    def test_exporte_toutes_les_regles(self, export_partage):
        repertoire, res = export_partage
        assert res["nb"] == len(CATALOGUE)
        assert len(list(repertoire.glob("*.yml"))) == len(CATALOGUE)

    def test_genere_un_index(self, export_partage):
        repertoire, _ = export_partage
        contenu = (repertoire / "index.md").read_text(encoding="utf-8")
        assert "Règles Sigma générées par CADRE" in contenu
        assert CATALOGUE[0].id in contenu

    def test_chaque_fichier_est_un_sigma_valide(self, export_partage):
        repertoire, _ = export_partage
        for chemin in repertoire.glob("*.yml"):
            regle = yaml.safe_load(chemin.read_text(encoding="utf-8"))
            assert isinstance(regle, dict)
            assert "title" in regle
            assert "detection" in regle
            assert "condition" in regle["detection"]

    def test_produit_les_formats_multi_siem(self, export_partage):
        repertoire, res = export_partage
        noms = {f["format"] for f in res["formats"]}
        # lucene et es-dsl sont 100% hors-ligne : toujours produits.
        assert {"lucene", "es-dsl"} <= noms
        assert (repertoire / "cadre_lucene.txt").exists()
        assert (repertoire / "cadre_es_dsl.json").exists()
        # kibana nécessite les données MITRE (téléchargées puis mises en cache) :
        # produit seulement si disponible ; sinon dégradation propre (voir F-006).
        if "kibana" in noms:
            assert (repertoire / "cadre_kibana_import.ndjson").exists()

    def test_es_dsl_est_un_json_valide(self, export_partage):
        repertoire, _ = export_partage
        data = json.loads((repertoire / "cadre_es_dsl.json").read_text(encoding="utf-8"))
        assert isinstance(data, list) and len(data) == len(CATALOGUE)

    def test_bundle_kibana_est_un_ndjson_valide(self, export_partage):
        repertoire, _ = export_partage
        bundle = repertoire / "cadre_kibana_import.ndjson"
        # Bundle kibana absent hors-ligne (données MITRE non chargées) : on saute
        # plutôt que d'échouer sur l'environnement (déterminisme — cf. F-006).
        if not bundle.exists():
            pytest.skip("bundle kibana indisponible hors-ligne (données MITRE ATT&CK)")
        lignes = bundle.read_text(encoding="utf-8").strip().splitlines()
        assert len(lignes) == len(CATALOGUE)  # une règle importable par attaque
        for ligne in lignes:
            regle = json.loads(ligne)  # chaque ligne est un objet JSON valide
            assert "rule_id" in regle
            assert "query" in regle
