"""
Tests pour la revue humaine avant déploiement (src/cadre/revue_regles.py).
"""

from __future__ import annotations

import pytest

from cadre.revue_regles import (
    ErreurRevue,
    charger_revues,
    enregistrer_revue,
    lister_revues,
    obtenir_revue,
    supprimer_revue,
)


def _entree(**surcharges):
    base = {
        "rule_id_stable": "cadre-ia-001",
        "attaque_id": "CADRE-IA-001",
        "nom_regle": "[CADRE] T1082 — Test",
        "description": "Une attaque de test",
        "technique_mitre": "T1082",
        "severite": "low",
        "index_pattern": "winlogbeat-*",
        "chemin_regle_sigma": "rules_generees/CADRE-IA-001.yml",
        "requete_lucene_derniere_validation": "event.code:1",
        "nb_tp": 1,
        "nb_fp": 3,
    }
    base.update(surcharges)
    return base


class TestChargerRevues:
    def test_fichier_absent_retourne_vide(self, tmp_path):
        assert charger_revues(tmp_path / "inexistant.json") == {}

    def test_fichier_illisible_retourne_vide(self, tmp_path):
        chemin = tmp_path / "revues.json"
        chemin.write_text("{ceci n'est pas du json", encoding="utf-8")
        assert charger_revues(chemin) == {}

    def test_fichier_mal_forme_retourne_vide(self, tmp_path):
        chemin = tmp_path / "revues.json"
        chemin.write_text("[1, 2, 3]", encoding="utf-8")  # liste, pas un objet
        assert charger_revues(chemin) == {}


class TestEnregistrerRevue:
    def test_enregistrement_simple(self, tmp_path):
        chemin = tmp_path / "revues.json"
        enregistrer_revue(_entree(), chemin)
        revues = charger_revues(chemin)
        assert "cadre-ia-001" in revues
        assert revues["cadre-ia-001"]["statut"] == "EN_ATTENTE"
        assert revues["cadre-ia-001"]["nb_tp"] == 1

    def test_champ_requis_manquant_refuse(self, tmp_path):
        chemin = tmp_path / "revues.json"
        incomplete = _entree()
        del incomplete["nb_fp"]
        with pytest.raises(ErreurRevue, match="nb_fp"):
            enregistrer_revue(incomplete, chemin)
        assert charger_revues(chemin) == {}  # rien écrit

    def test_cree_le_conserve_maj_le_avance(self, tmp_path):
        """Ré-enregistrer la même règle (ex. après édition du YAML) doit
        garder la date de création d'origine et avancer seulement la date
        de mise à jour."""
        chemin = tmp_path / "revues.json"
        enregistrer_revue(_entree(nb_tp=1), chemin)
        premiere = charger_revues(chemin)["cadre-ia-001"]
        enregistrer_revue(_entree(nb_tp=2), chemin)
        seconde = charger_revues(chemin)["cadre-ia-001"]
        assert seconde["cree_le"] == premiere["cree_le"]
        assert seconde["nb_tp"] == 2

    def test_deux_regles_independantes(self, tmp_path):
        chemin = tmp_path / "revues.json"
        enregistrer_revue(_entree(), chemin)
        enregistrer_revue(_entree(rule_id_stable="cadre-ia-002", attaque_id="CADRE-IA-002"), chemin)
        revues = charger_revues(chemin)
        assert set(revues) == {"cadre-ia-001", "cadre-ia-002"}


class TestObtenirEtListerRevues:
    def test_obtenir_inexistant_retourne_none(self, tmp_path):
        assert obtenir_revue("cadre-inconnu", tmp_path / "revues.json") is None

    def test_obtenir_existant(self, tmp_path):
        chemin = tmp_path / "revues.json"
        enregistrer_revue(_entree(), chemin)
        entree = obtenir_revue("cadre-ia-001", chemin)
        assert entree is not None
        assert entree["attaque_id"] == "CADRE-IA-001"

    def test_lister_vide(self, tmp_path):
        assert lister_revues(tmp_path / "revues.json") == []

    def test_lister_plusieurs(self, tmp_path):
        chemin = tmp_path / "revues.json"
        enregistrer_revue(_entree(), chemin)
        enregistrer_revue(_entree(rule_id_stable="cadre-ia-002", attaque_id="CADRE-IA-002"), chemin)
        assert len(lister_revues(chemin)) == 2


class TestSupprimerRevue:
    def test_supprime_existant(self, tmp_path):
        chemin = tmp_path / "revues.json"
        enregistrer_revue(_entree(), chemin)
        assert supprimer_revue("cadre-ia-001", chemin) is True
        assert charger_revues(chemin) == {}

    def test_supprime_inexistant_retourne_false(self, tmp_path):
        chemin = tmp_path / "revues.json"
        assert supprimer_revue("cadre-inconnu", chemin) is False

    def test_ne_touche_pas_les_autres_regles(self, tmp_path):
        chemin = tmp_path / "revues.json"
        enregistrer_revue(_entree(), chemin)
        enregistrer_revue(_entree(rule_id_stable="cadre-ia-002", attaque_id="CADRE-IA-002"), chemin)
        supprimer_revue("cadre-ia-001", chemin)
        revues = charger_revues(chemin)
        assert set(revues) == {"cadre-ia-002"}


class TestConcurrenceEcritureFichier:
    """Régression : enregistrer_revue faisait un cycle lecture-modification-
    écriture SANS verrou -- deux threads qui enregistrent chacun une entrée
    différente en même temps (ex. le thread d'arrière-plan d'une découverte
    IA + le thread HTTP d'une approbation) pouvaient se marcher dessus,
    l'un écrasant le fichier juste après l'avoir relu, avant que l'autre
    n'ait fini d'écrire -- perte silencieuse d'une des deux entrées."""

    def test_20_threads_enregistrent_chacun_une_entree_aucune_perdue(self, tmp_path):
        import threading

        chemin = tmp_path / "revues.json"
        nb_threads = 20
        barriere = threading.Barrier(nb_threads)

        def travail(i):
            barriere.wait()  # maximise le chevauchement réel entre threads
            enregistrer_revue(
                _entree(rule_id_stable=f"cadre-ia-{i:03d}", attaque_id=f"CADRE-IA-{i:03d}"),
                chemin,
            )

        threads = [threading.Thread(target=travail, args=(i,)) for i in range(nb_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        revues = charger_revues(chemin)
        assert len(revues) == nb_threads  # aucune entrée perdue
        assert set(revues) == {f"cadre-ia-{i:03d}" for i in range(nb_threads)}
