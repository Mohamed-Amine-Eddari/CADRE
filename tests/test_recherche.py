"""
Tests pour la recherche par mot-clé (src/cadre/recherche.py).
"""

from __future__ import annotations

import dataclasses

from cadre.recherche import rechercher_atomic, rechercher_attaques, rechercher_catalogue


class TestRechercherCatalogue:
    def test_trouve_par_nom_insensible_a_la_casse(self, exemple_attaque):
        a = dataclasses.replace(exemple_attaque, id="A1", nom="Test Attaque Whoami")
        assert rechercher_catalogue("WHOAMI", [a]) == [a]

    def test_trouve_par_technique(self, exemple_attaque):
        a = dataclasses.replace(exemple_attaque, id="A1", technique_mitre="T1059.001")
        assert rechercher_catalogue("t1059", [a]) == [a]

    def test_trouve_par_description(self, exemple_attaque):
        a = dataclasses.replace(exemple_attaque, id="A1", description="Énumère les tâches")
        assert rechercher_catalogue("tâches", [a]) == [a]

    def test_aucun_resultat_liste_vide(self, exemple_attaque):
        a = dataclasses.replace(exemple_attaque, id="A1")
        assert rechercher_catalogue("xyzzy-inexistant", [a]) == []

    def test_priorite_nom_avant_description(self, exemple_attaque):
        """Une attaque qui matche par le NOM doit apparaître avant une qui
        ne matche que par la description."""
        par_nom = dataclasses.replace(exemple_attaque, id="A1", nom="whoami test", description="x")
        par_description = dataclasses.replace(
            exemple_attaque, id="A2", nom="autre", description="contient whoami quelque part"
        )
        resultats = rechercher_catalogue("whoami", [par_description, par_nom])
        assert [a.id for a in resultats] == ["A1", "A2"]

    def test_catalogue_actif_par_defaut_inclut_le_perso(
        self, tmp_path, monkeypatch, exemple_attaque
    ):
        import cadre.catalogue_utilisateur as cu

        chemin = tmp_path / "perso.json"
        monkeypatch.setattr(cu, "CHEMIN_CATALOGUE_PERSO", chemin)
        cu.enregistrer_attaque_utilisateur(
            {
                "id": "CADRE-PERSO-999",
                "nom": "Attaque perso unique xyzzyperso",
                "description": "d",
                "technique_mitre": "T1082",
                "tactique_mitre": "Discovery",
                "commande": "echo test",
                "event_ids_attendus": ["1"],
                "champ_principal": "process.name",
            }
        )
        resultats = rechercher_catalogue("xyzzyperso")
        assert [a.id for a in resultats] == ["CADRE-PERSO-999"]


class TestRechercherAtomic:
    def test_trouve_un_atomic_retenu(self):
        resultat = rechercher_atomic("Process Discovery")
        assert any("Process Discovery" in b["nom"] for b in resultat["retenus"])

    def test_aucun_atomic_dangereux_dans_les_retenus(self):
        """Le filtre anti-destruction de importer_atomics() reste actif --
        une recherche ne doit jamais faire remonter une commande dangereuse
        parmi les résultats retenus."""
        resultat = rechercher_atomic("Clear Security event log")
        assert resultat["retenus"] == []
        assert any("Clear Security" in r["nom"] for r in resultat["refuses"])

    def test_aucun_resultat_liste_vide(self):
        resultat = rechercher_atomic("xyzzy-inexistant-atomic")
        assert resultat["retenus"] == []
        assert resultat["refuses"] == []


class TestRechercherAttaques:
    def test_trouve_dans_le_catalogue_sans_atomic(self):
        resultat = rechercher_attaques("whoami", inclure_atomic=False)
        assert resultat["trouve"] is True
        assert resultat["atomic_red_team"] == []

    def test_rien_trouve_partout(self):
        resultat = rechercher_attaques("xyzzy-introuvable-partout", inclure_atomic=True)
        assert resultat["trouve"] is False
        assert resultat["catalogue"] == []
        assert resultat["atomic_red_team"] == []

    def test_inclure_atomic_false_ne_cherche_pas_atomic(self):
        """Sans --inclure-atomic, aucune tentative d'import Atomic Red Team
        (pas de coût inutile si l'utilisateur ne le demande pas)."""
        resultat = rechercher_attaques("Process Discovery", inclure_atomic=False)
        assert resultat["atomic_red_team"] == []

    def test_deja_importe_correct(self, tmp_path, monkeypatch):
        """Un atomic déjà enregistré au catalogue perso (même id que
        atomic_vers_brouillon générerait) doit être marqué deja_importe."""
        import cadre.catalogue_utilisateur as cu

        chemin = tmp_path / "perso.json"
        monkeypatch.setattr(cu, "CHEMIN_CATALOGUE_PERSO", chemin)

        resultat = rechercher_attaques("Process Discovery", inclure_atomic=True)
        assert resultat["atomic_red_team"]
        assert all(b["deja_importe"] is False for b in resultat["atomic_red_team"])

        premier_id = resultat["atomic_red_team"][0]["id"]
        cu.enregistrer_attaque_utilisateur(resultat["atomic_red_team"][0])

        resultat2 = rechercher_attaques("Process Discovery", inclure_atomic=True)
        marque = next(b for b in resultat2["atomic_red_team"] if b["id"] == premier_id)
        assert marque["deja_importe"] is True
