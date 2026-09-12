"""
Tests pour le raffinement de règle en place (src/cadre/raffinement.py).
"""

from __future__ import annotations

import dataclasses

import pytest

from cadre.raffinement import (
    ErreurRaffinement,
    appliquer_raffinements,
    charger_raffinements,
    enregistrer_raffinement,
    supprimer_raffinement,
)


class TestChargerRaffinements:
    def test_fichier_absent_retourne_vide(self, tmp_path):
        assert charger_raffinements(tmp_path / "inexistant.json") == {}

    def test_fichier_illisible_retourne_vide(self, tmp_path):
        chemin = tmp_path / "raffinements.json"
        chemin.write_text("{ceci n'est pas du json", encoding="utf-8")
        assert charger_raffinements(chemin) == {}

    def test_fichier_mal_forme_retourne_vide(self, tmp_path):
        chemin = tmp_path / "raffinements.json"
        chemin.write_text("[1, 2, 3]", encoding="utf-8")  # liste, pas un objet
        assert charger_raffinements(chemin) == {}


class TestEnregistrerRaffinement:
    def test_enregistrement_simple(self, tmp_path):
        chemin = tmp_path / "raffinements.json"
        enregistrer_raffinement("CADRE-DIS-001", {"seuil_fp_max": 20}, chemin)
        assert charger_raffinements(chemin) == {"CADRE-DIS-001": {"seuil_fp_max": 20}}

    def test_champ_non_raffinable_refuse(self, tmp_path):
        chemin = tmp_path / "raffinements.json"
        with pytest.raises(ErreurRaffinement, match="commande"):
            enregistrer_raffinement("CADRE-DIS-001", {"commande": "whoami"}, chemin)
        assert charger_raffinements(chemin) == {}  # rien écrit

    def test_seuil_fp_negatif_refuse(self, tmp_path):
        chemin = tmp_path / "raffinements.json"
        with pytest.raises(ErreurRaffinement, match="strictement positif"):
            enregistrer_raffinement("CADRE-DIS-001", {"seuil_fp_max": -5}, chemin)

    def test_seuil_fp_zero_refuse(self, tmp_path):
        chemin = tmp_path / "raffinements.json"
        with pytest.raises(ErreurRaffinement):
            enregistrer_raffinement("CADRE-DIS-001", {"seuil_fp_max": 0}, chemin)

    def test_seuil_fp_non_entier_refuse(self, tmp_path):
        chemin = tmp_path / "raffinements.json"
        with pytest.raises(ErreurRaffinement):
            enregistrer_raffinement("CADRE-DIS-001", {"seuil_fp_max": "beaucoup"}, chemin)

    def test_deuxieme_enregistrement_fusionne_pas_ecrase(self, tmp_path):
        """Deux appels successifs sur la même attaque doivent fusionner les
        champs, pas perdre le premier raffinement."""
        chemin = tmp_path / "raffinements.json"
        enregistrer_raffinement("CADRE-DIS-001", {"seuil_fp_max": 20}, chemin)
        enregistrer_raffinement("CADRE-DIS-001", {"valeur_detection": "nouveau"}, chemin)
        assert charger_raffinements(chemin) == {
            "CADRE-DIS-001": {"seuil_fp_max": 20, "valeur_detection": "nouveau"}
        }

    def test_deux_attaques_independantes(self, tmp_path):
        chemin = tmp_path / "raffinements.json"
        enregistrer_raffinement("CADRE-DIS-001", {"seuil_fp_max": 20}, chemin)
        enregistrer_raffinement("CADRE-DIS-002", {"seuil_fp_max": 10}, chemin)
        raffinements = charger_raffinements(chemin)
        assert raffinements["CADRE-DIS-001"]["seuil_fp_max"] == 20
        assert raffinements["CADRE-DIS-002"]["seuil_fp_max"] == 10


class TestSupprimerRaffinement:
    def test_supprime_existant(self, tmp_path):
        chemin = tmp_path / "raffinements.json"
        enregistrer_raffinement("CADRE-DIS-001", {"seuil_fp_max": 20}, chemin)
        assert supprimer_raffinement("CADRE-DIS-001", chemin) is True
        assert charger_raffinements(chemin) == {}

    def test_supprime_inexistant_retourne_false(self, tmp_path):
        chemin = tmp_path / "raffinements.json"
        assert supprimer_raffinement("CADRE-DIS-999", chemin) is False

    def test_ne_touche_pas_les_autres_attaques(self, tmp_path):
        chemin = tmp_path / "raffinements.json"
        enregistrer_raffinement("CADRE-DIS-001", {"seuil_fp_max": 20}, chemin)
        enregistrer_raffinement("CADRE-DIS-002", {"seuil_fp_max": 10}, chemin)
        supprimer_raffinement("CADRE-DIS-001", chemin)
        assert charger_raffinements(chemin) == {"CADRE-DIS-002": {"seuil_fp_max": 10}}


class TestAppliquerRaffinements:
    def test_aucun_raffinement_retourne_liste_inchangee(self, tmp_path, exemple_attaque):
        chemin = tmp_path / "raffinements.json"
        assert appliquer_raffinements([exemple_attaque], chemin) == [exemple_attaque]

    def test_applique_le_bon_champ_sur_la_bonne_attaque(self, tmp_path, exemple_attaque):
        chemin = tmp_path / "raffinements.json"
        enregistrer_raffinement(exemple_attaque.id, {"seuil_fp_max": 7}, chemin)
        resultat = appliquer_raffinements([exemple_attaque], chemin)
        assert resultat[0].seuil_fp_max == 7
        # Rien d'autre ne change -- même id, même commande, même technique.
        assert resultat[0].id == exemple_attaque.id
        assert resultat[0].commande == exemple_attaque.commande
        assert resultat[0].technique_mitre == exemple_attaque.technique_mitre

    def test_ne_cree_jamais_de_nouvelle_entree(self, tmp_path, exemple_attaque):
        """Le point central de la fonctionnalité : raffiner une attaque
        modifie l'entrée existante, n'en ajoute jamais une deuxième."""
        chemin = tmp_path / "raffinements.json"
        enregistrer_raffinement(exemple_attaque.id, {"seuil_fp_max": 7}, chemin)
        resultat = appliquer_raffinements([exemple_attaque], chemin)
        assert len(resultat) == 1

    def test_ignore_champ_inconnu_sans_planter(self, tmp_path, exemple_attaque):
        """Fichier raffinements.json édité à la main (ou version antérieure)
        avec un champ qui n'existe plus/pas -- ne doit jamais faire planter
        tout le chargement du catalogue."""
        chemin = tmp_path / "raffinements.json"
        chemin.write_text(
            f'{{"{exemple_attaque.id}": {{"champ_fantome": "x", "seuil_fp_max": 7}}}}',
            encoding="utf-8",
        )
        resultat = appliquer_raffinements([exemple_attaque], chemin)
        assert resultat[0].seuil_fp_max == 7  # le champ valide est bien appliqué

    def test_attaque_sans_raffinement_dans_liste_mixte(self, tmp_path, exemple_attaque):
        chemin = tmp_path / "raffinements.json"
        autre = dataclasses.replace(exemple_attaque, id="CADRE-AUTRE-001")
        enregistrer_raffinement(exemple_attaque.id, {"seuil_fp_max": 7}, chemin)
        resultat = appliquer_raffinements([exemple_attaque, autre], chemin)
        par_id = {a.id: a for a in resultat}
        assert par_id[exemple_attaque.id].seuil_fp_max == 7
        assert par_id["CADRE-AUTRE-001"].seuil_fp_max == autre.seuil_fp_max  # inchangé


class TestConcurrenceEcritureFichier:
    """Même régression que revue_regles.py::TestConcurrenceEcritureFichier :
    enregistrer_raffinement faisait un cycle lecture-modification-écriture
    SANS verrou -- des écritures concurrentes pouvaient silencieusement en
    perdre certaines (dernier écrivain gagne sur tout le fichier)."""

    def test_20_threads_raffinent_chacun_une_attaque_aucune_perdue(self, tmp_path):
        import threading

        chemin = tmp_path / "raffinements.json"
        nb_threads = 20
        barriere = threading.Barrier(nb_threads)

        def travail(i):
            barriere.wait()  # maximise le chevauchement réel entre threads
            enregistrer_raffinement(f"CADRE-STRESS-{i:03d}", {"seuil_fp_max": i + 1}, chemin)

        threads = [threading.Thread(target=travail, args=(i,)) for i in range(nb_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        raffinements = charger_raffinements(chemin)
        assert len(raffinements) == nb_threads  # aucune entrée perdue
        assert set(raffinements) == {f"CADRE-STRESS-{i:03d}" for i in range(nb_threads)}
