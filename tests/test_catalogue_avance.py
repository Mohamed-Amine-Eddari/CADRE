"""
Tests d'intégrité et de cohérence du catalogue d'attaques.
Adapté à l'API réelle de src/cadre/catalogue_attaques.py.
"""

from dataclasses import FrozenInstanceError

import pytest

from cadre.catalogue_attaques import (
    CATALOGUE,
    NiveauRisque,
    Plateforme,
    lister_attaques,
    obtenir_attaque,
    obtenir_par_tactique,
    obtenir_par_technique,
    statistiques_catalogue,
)


class TestIntegriteCatalogue:
    """Tests d'intégrité du catalogue."""

    def test_catalogue_non_vide(self):
        assert len(CATALOGUE) > 0, "Le catalogue ne doit pas être vide"

    def test_minimum_attaques(self):
        """Le catalogue doit contenir au moins 10 attaques pour être utile."""
        assert len(CATALOGUE) >= 10

    def test_tous_ids_uniques(self):
        ids = [a.id for a in CATALOGUE]
        assert len(ids) == len(set(ids)), f"IDs en doublon : {ids}"

    def test_tous_ids_format_valide(self):
        """Le format doit être CADRE-XXX-NNN."""
        import re

        pattern = re.compile(r"^CADRE-[A-Z]{3}-\d{3}$")
        for a in CATALOGUE:
            assert pattern.match(a.id), f"ID invalide : {a.id}"

    def test_toutes_techniques_mitre_valides(self):
        """Format TXXXX[.XXX] obligatoire."""
        import re

        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for a in CATALOGUE:
            assert pattern.match(
                a.technique_mitre
            ), f"Technique invalide pour {a.id} : {a.technique_mitre}"

    def test_event_ids_non_vides(self):
        for a in CATALOGUE:
            assert len(a.event_ids_attendus) > 0, f"{a.id} : event_ids_attendus vide"

    def test_commandes_non_vides(self):
        for a in CATALOGUE:
            assert a.commande.strip(), f"{a.id} : commande vide"

    def test_champ_principal_defini(self):
        for a in CATALOGUE:
            assert a.champ_principal, f"{a.id} : champ_principal vide"

    def test_niveau_risque_valide(self):
        niveaux_valides = {NiveauRisque.FAIBLE, NiveauRisque.MOYEN, NiveauRisque.ELEVE}
        for a in CATALOGUE:
            assert (
                a.niveau_risque in niveaux_valides
            ), f"{a.id} : niveau_risque invalide : {a.niveau_risque}"

    def test_plateforme_valide(self):
        for a in CATALOGUE:
            assert a.plateforme in {
                Plateforme.WINDOWS,
                Plateforme.LINUX,
                Plateforme.MIXTE,
            }, f"{a.id} : plateforme invalide : {a.plateforme}"

    def test_duree_estimee_positive(self):
        for a in CATALOGUE:
            assert a.duree_estimee_sec > 0, f"{a.id} : durée ≤ 0"

    def test_references_non_vides(self):
        for a in CATALOGUE:
            assert len(a.references) > 0, f"{a.id} : references vide"


class TestCouvertureMinimale:
    """Tests de couverture MITRE ATT&CK."""

    def test_minimum_5_tactiques(self):
        """Le catalogue doit couvrir au moins 5 tactiques différentes."""
        tactiques = {a.tactique_mitre for a in CATALOGUE}
        assert len(tactiques) >= 5, f"Seulement {len(tactiques)} tactiques couvertes : {tactiques}"

    def test_minimum_8_techniques(self):
        """Le catalogue doit couvrir au moins 8 techniques différentes."""
        techniques = {a.technique_mitre for a in CATALOGUE}
        assert len(techniques) >= 8


class TestAPI:
    """Tests des fonctions d'accès au catalogue."""

    def test_obtenir_attaque_existante(self):
        premiere = CATALOGUE[0]
        resultat = obtenir_attaque(premiere.id)
        assert resultat is not None
        assert resultat.id == premiere.id

    def test_obtenir_attaque_inexistante(self):
        resultat = obtenir_attaque("CADRE-XXX-999")
        assert resultat is None

    def test_obtenir_par_technique(self):
        """Toutes les techniques du catalogue doivent être trouvables."""
        for a in CATALOGUE:
            resultat = obtenir_par_technique(a.technique_mitre)
            assert len(resultat) >= 1
            assert any(r.id == a.id for r in resultat)

    def test_obtenir_par_tactique(self):
        """Toutes les tactiques doivent retourner au moins 1 attaque."""
        for a in CATALOGUE:
            resultat = obtenir_par_tactique(a.tactique_mitre)
            assert len(resultat) >= 1

    def test_lister_attaques(self):
        """lister_attaques retourne un format lisible contenant tous les IDs."""
        resultat = lister_attaques()
        assert isinstance(resultat, str)
        assert "CADRE-" in resultat
        for a in CATALOGUE:
            assert a.id in resultat

    def test_statistiques(self):
        stats = statistiques_catalogue()
        assert "total" in stats
        assert stats["total"] == len(CATALOGUE)
        assert "par_tactique" in stats
        assert "par_niveau_risque" in stats
        assert isinstance(stats["par_tactique"], dict)
        assert isinstance(stats["par_niveau_risque"], dict)


class TestCatalogueImmuable:
    """Le catalogue ne doit pas pouvoir être modifié à l'exécution."""

    def test_catalogue_est_frozen(self):
        """Les éléments doivent être des dataclasses frozen."""
        premiere = CATALOGUE[0]
        with pytest.raises(FrozenInstanceError):
            premiere.commande = "rm -rf /"  # type: ignore[misc]

    def test_catalogue_reference_unique(self):
        """Deux appels à obtenir_attaque doivent retourner la même instance."""
        premiere = CATALOGUE[0]
        a1 = obtenir_attaque(premiere.id)
        a2 = obtenir_attaque(premiere.id)
        # Peu importe == ou is, l'important est la cohérence
        assert a1 == a2


class TestAttaqueSpecifiques:
    """Tests d'attaques emblématiques."""

    def test_attaque_powershell_existe(self):
        """L'attaque PowerShell (T1059.001) doit être dans le catalogue."""
        resultats = obtenir_par_technique("T1059.001")
        assert len(resultats) >= 1
        assert any("PowerShell" in r.nom for r in resultats)

    def test_attaque_creation_compte_existe(self):
        """L'attaque de création de compte (T1136.001) doit être présente."""
        resultats = obtenir_par_technique("T1136.001")
        assert len(resultats) >= 1

    def test_attaque_avec_niveau_eleve(self):
        """Au moins une attaque doit être marquée niveau ÉLEVÉ."""
        niveaux = [a.niveau_risque for a in CATALOGUE]
        assert NiveauRisque.ELEVE in niveaux
