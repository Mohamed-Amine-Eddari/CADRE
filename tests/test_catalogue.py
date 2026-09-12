"""
Tests pour le catalogue d'attaques.
"""

import dataclasses
from dataclasses import FrozenInstanceError

import pytest

from cadre.catalogue_attaques import (
    CATALOGUE,
    NiveauRisque,
    calculer_score_confiance,
    catalogue_actif,
    categorie_detection,
    obtenir_attaque,
    obtenir_par_tactique,
    obtenir_par_technique,
    partitionner_pour_parallelisme,
    statistiques_catalogue,
)


class TestIntegriteCatalogue:
    def test_catalogue_non_vide(self):
        assert len(CATALOGUE) >= 5, "Le catalogue doit contenir au moins 5 attaques"

    def test_toutes_les_attaques_ont_un_id_unique(self):
        ids = [a.id for a in CATALOGUE]
        assert len(ids) == len(set(ids)), "Les IDs doivent être uniques"

    def test_toutes_les_attaques_ont_une_technique_mitre(self):
        for a in CATALOGUE:
            assert a.technique_mitre.startswith(
                "T"
            ), f"{a.id} : technique MITRE invalide ({a.technique_mitre})"

    def test_toutes_les_attaques_ont_au_moins_un_event_id(self):
        for a in CATALOGUE:
            assert len(a.event_ids_attendus) > 0, f"{a.id} : aucun EventID attendu défini"

    def test_toutes_les_attaques_ont_une_commande(self):
        for a in CATALOGUE:
            assert a.commande.strip(), f"{a.id} : commande vide"

    def test_toutes_les_attaques_ont_un_niveau_de_risque(self):
        niveaux = {NiveauRisque.FAIBLE, NiveauRisque.MOYEN, NiveauRisque.ELEVE}
        for a in CATALOGUE:
            assert a.niveau_risque in niveaux, f"{a.id} : niveau de risque invalide"

    def test_couverture_minimale_mitre(self):
        """Le catalogue doit couvrir au moins 5 tactiques MITRE différentes."""
        tactiques = {a.tactique_mitre for a in CATALOGUE}
        assert len(tactiques) >= 5, f"Couverture tactique insuffisante : {len(tactiques)} (min 5)"

    def test_couverture_minimale_techniques(self):
        """Au moins 8 techniques distinctes."""
        techniques = {a.technique_mitre for a in CATALOGUE}
        assert len(techniques) >= 8, f"Pas assez de techniques : {len(techniques)} (min 8)"


class TestFonctionsRecherche:
    def test_obtenir_attaque_existe(self):
        premiere = CATALOGUE[0]
        resultat = obtenir_attaque(premiere.id)
        assert resultat is not None
        assert resultat.id == premiere.id

    def test_obtenir_attaque_inexistante(self):
        resultat = obtenir_attaque("CADRE-FAKE-999")
        assert resultat is None

    def test_obtenir_par_technique(self):
        resultats = obtenir_par_technique("T1059.001")
        assert all(a.technique_mitre == "T1059.001" for a in resultats)
        assert len(resultats) > 0

    def test_obtenir_par_tactique(self):
        resultats = obtenir_par_tactique("Execution")
        assert all(a.tactique_mitre.lower() == "execution" for a in resultats)
        assert len(resultats) > 0


class TestScoreConfiance:
    """categorie_detection / calculer_score_confiance -- score de confiance
    par règle (idée innovante, EXC/1-ttp-first.md §6 comme source de vérité)."""

    def test_repartition_totale_68(self):
        """Régression de comptage : 54 indicateur_reel + 12 validation_pipeline
        + 2 generique = 68 (67 + CADRE-EVA-004, T1036.005 Masquerading --
        svchost.exe renommé hors System32, indicateur réel dès sa création
        car le chemin+nom incohérent est le signal qu'un vrai attaquant
        présenterait aussi, pas un artefact de l'outil de test -- voir
        commentaire dans catalogue_attaques.py), cohérent avec le comptage
        programmatique A4/B5."""
        compte = {"indicateur_reel": 0, "validation_pipeline": 0, "generique": 0}
        for a in CATALOGUE:
            compte[categorie_detection(a)] += 1
        assert compte == {"indicateur_reel": 54, "validation_pipeline": 12, "generique": 2}

    def test_categorie_generique_sans_valeur_detection(self):
        a = obtenir_attaque("CADRE-PER-001")
        assert a is not None
        assert a.valeur_detection is None
        assert categorie_detection(a) == "generique"

    def test_categorie_validation_pipeline(self):
        a = obtenir_attaque("CADRE-EXE-002")
        assert a is not None
        assert categorie_detection(a) == "validation_pipeline"

    def test_categorie_indicateur_reel(self):
        a = obtenir_attaque("CADRE-DIS-001")
        assert a is not None
        assert categorie_detection(a) == "indicateur_reel"

    def test_score_zero_si_aucun_vrai_positif(self):
        a = obtenir_attaque("CADRE-DIS-001")
        assert a is not None
        assert calculer_score_confiance(a, nb_tp=0, nb_fp=0, seuil_fp=50) == 0

    def test_score_maximal_sans_faux_positif(self):
        a = obtenir_attaque("CADRE-DIS-001")
        assert a is not None
        assert calculer_score_confiance(a, nb_tp=1, nb_fp=0, seuil_fp=50) == 100

    def test_score_indicateur_reel_superieur_a_validation_pipeline(self):
        """Même TP/FP/seuil : un indicateur réel doit toujours scorer plus
        haut qu'une validation de pipeline -- le signal que ce score sert à
        rendre visible."""
        reel = obtenir_attaque("CADRE-DIS-001")
        pipeline = obtenir_attaque("CADRE-EXE-002")
        assert reel is not None and pipeline is not None
        score_reel = calculer_score_confiance(reel, nb_tp=1, nb_fp=10, seuil_fp=50)
        score_pipeline = calculer_score_confiance(pipeline, nb_tp=1, nb_fp=10, seuil_fp=50)
        assert score_reel > score_pipeline

    def test_score_plafonne_a_50_si_seuil_depasse(self):
        """Un FP au-delà du seuil (rejeté par double_validation_tp_fp) ne
        doit jamais faire chuter le score sous les points de catégorie."""
        a = obtenir_attaque("CADRE-DIS-001")
        assert a is not None
        assert calculer_score_confiance(a, nb_tp=1, nb_fp=999, seuil_fp=50) == 50

    def test_score_seuil_zero_ne_plante_pas(self):
        a = obtenir_attaque("CADRE-DIS-001")
        assert a is not None
        assert calculer_score_confiance(a, nb_tp=1, nb_fp=0, seuil_fp=0) == 50


class TestCouverturePrivilegeEscalation:
    """Les 3 nouvelles attaques (CADRE-PRI-002/003/004) qui portent
    Privilege Escalation de 1 à 4 entrées -- intégrité, classification,
    et statistiques agrégées."""

    def test_quatre_attaques_privilege_escalation(self):
        assert len(obtenir_par_tactique("Privilege Escalation")) == 4

    def test_pri_002_suid_indicateur_reel(self):
        a = obtenir_attaque("CADRE-PRI-002")
        assert a is not None
        assert a.technique_mitre == "T1548.001"
        assert a.plateforme.value == "linux"
        assert categorie_detection(a) == "indicateur_reel"

    def test_pri_003_sudo_indicateur_reel(self):
        a = obtenir_attaque("CADRE-PRI-003")
        assert a is not None
        assert a.technique_mitre == "T1548.003"
        assert a.plateforme.value == "linux"
        assert categorie_detection(a) == "indicateur_reel"

    def test_pri_004_account_manipulation_indicateur_reel(self):
        a = obtenir_attaque("CADRE-PRI-004")
        assert a is not None
        assert a.technique_mitre == "T1098"
        assert a.plateforme.value == "windows"
        assert a.champ_principal == "user.target.group.name"
        assert a.valeur_detection == "Administrateurs"
        assert categorie_detection(a) == "indicateur_reel"

    def test_aucune_technique_dupliquee_sur_la_meme_plateforme(self):
        """Le catalogue réutilise volontairement le même technique_mitre pour
        des paires Windows/Linux de la même technique (T1082, T1016...) --
        ce n'est PAS un doublon. Ce qui compte : jamais deux entrées de la
        MÊME plateforme sur la même technique. CADRE-PRI-004 (T1098) ne doit
        pas dupliquer une technique Windows déjà couverte (ex. T1136.001,
        création de compte -- CADRE-PER-001, une technique différente)."""
        for plateforme in ("windows", "linux"):
            techniques = [a.technique_mitre for a in CATALOGUE if a.plateforme.value == plateforme]
            assert len(techniques) == len(set(techniques)), plateforme

    def test_statistiques_refletent_le_nombre_reel_d_attaques(self):
        """Régression (audit) : le nom du test et l'assertion figeaient
        littéralement "67" -- toute évolution légitime du catalogue (ex.
        CADRE-EVA-004 ajoutée, perspective d'évolution n°4 du rapport)
        cassait ce test sans raison de fond. Compare `statistiques_catalogue`
        à `len(CATALOGUE)` (la source de vérité), jamais à une constante
        codée en dur."""
        stats = statistiques_catalogue()
        assert stats["total"] == len(CATALOGUE)
        assert stats["total"] >= 67  # plancher historique, jamais une régression à la baisse


class TestPartitionnementParallelisme:
    """partitionner_pour_parallelisme -- découpage du catalogue en lots
    exécutables en parallèle (G2) sans risque de contamination de la
    fenêtre de validation TP (double_validation_tp_fp, now-600s)."""

    def _attaque(self, exemple_attaque, **kwargs):
        return dataclasses.replace(exemple_attaque, **kwargs)

    def test_valeur_detection_none_isolee(self, exemple_attaque):
        generique = self._attaque(exemple_attaque, id="A", valeur_detection=None)
        voisine = self._attaque(exemple_attaque, id="B", valeur_detection="totalement_different")
        lots = partitionner_pour_parallelisme([generique, voisine])
        assert lots == [[generique], [voisine]]

    def test_deux_valeurs_disjointes_meme_lot(self, exemple_attaque):
        a = self._attaque(exemple_attaque, id="A", valeur_detection="systeminfo.exe")
        b = self._attaque(exemple_attaque, id="B", valeur_detection="whoami.exe")
        lots = partitionner_pour_parallelisme([a, b])
        assert lots == [[a, b]]

    def test_collision_sous_chaine_jamais_meme_lot(self, exemple_attaque):
        a = self._attaque(exemple_attaque, id="A", valeur_detection="net")
        b = self._attaque(exemple_attaque, id="B", valeur_detection="net user")
        lots = partitionner_pour_parallelisme([a, b])
        assert lots == [[a], [b]]

    def test_collision_insensible_a_la_casse(self, exemple_attaque):
        a = self._attaque(exemple_attaque, id="A", valeur_detection="CertUtil")
        b = self._attaque(exemple_attaque, id="B", valeur_detection="certutil -decode")
        lots = partitionner_pour_parallelisme([a, b])
        assert lots == [[a], [b]]

    def test_lots_bornes_a_max_concurrentes(self, exemple_attaque):
        a = self._attaque(exemple_attaque, id="A", valeur_detection="alpha")
        b = self._attaque(exemple_attaque, id="B", valeur_detection="beta")
        c = self._attaque(exemple_attaque, id="C", valeur_detection="gamma")
        lots = partitionner_pour_parallelisme([a, b, c], max_concurrentes=2)
        assert lots == [[a, b], [c]]

    def test_invariant_ordre_preserve(self, exemple_attaque):
        attaques = [
            self._attaque(exemple_attaque, id=f"A{i}", valeur_detection=f"valeur_{i}")
            for i in range(7)
        ]
        lots = partitionner_pour_parallelisme(attaques)
        aplati = [a for lot in lots for a in lot]
        assert aplati == attaques

    def test_liste_vide(self):
        assert partitionner_pour_parallelisme([]) == []

    def test_liste_a_un_element(self, exemple_attaque):
        a = self._attaque(exemple_attaque, id="A", valeur_detection="seule")
        assert partitionner_pour_parallelisme([a]) == [[a]]

    def test_catalogue_reel_aucune_collision_dans_un_lot(self):
        """Non-régression : sur le vrai catalogue actif, deux attaques du
        même lot ne doivent jamais avoir de valeur_detection en collision --
        garde-fou si le catalogue grossit (plan G2, couverture future)."""
        from cadre.catalogue_attaques import _valeurs_correlation_collisionnent

        lots = partitionner_pour_parallelisme(catalogue_actif())
        for lot in lots:
            valeurs = [a.valeur_detection for a in lot if a.valeur_detection is not None]
            for i, v1 in enumerate(valeurs):
                for v2 in valeurs[i + 1 :]:
                    assert not _valeurs_correlation_collisionnent(v1, v2)

    def test_collision_detectee_meme_apres_flush_du_lot_qui_la_contenait(self, exemple_attaque):
        """Régression sécurité (audit) : la comparaison de collision ne
        vérifiait que le lot en cours d'accumulation (`lot_courant`) -- une
        fois une attaque flushée dans un lot précédent, elle n'était plus
        jamais comparée aux suivantes, alors que les lots s'enchaînent en
        quelques secondes/minutes, largement DANS la fenêtre glissante de
        600 s de `double_validation_tp_fp`.

        Repro minimale (max_concurrentes=2) : A(valeur="xyz"), B1/B2 (aucune
        collision), C(valeur="xyz_more", collision avec A). Trace de
        l'ancien algorithme (bug) : lot=[A] -> +B1 (pas de collision) ->
        lot=[A,B1] -> B2 force un flush (lot plein) AVANT toute comparaison
        avec A -> lots=[[A,B1]], lot=[B2] -> C comparé SEULEMENT à [B2] (pas
        de collision détectée, A a été oublié) -> lot=[B2,C] : bugué, C
        rejoint B2 sans jamais avoir été comparé à A.

        Avec la correction (comparaison contre TOUT l'historique) : C est
        comparé à A (toujours présente dans `historique`) -> collision
        détectée -> C est isolé dans son propre lot, jamais regroupé avec B2
        sur la seule foi d'une case de lot encore libre."""
        a = self._attaque(exemple_attaque, id="A", valeur_detection="xyz")
        b1 = self._attaque(exemple_attaque, id="B1", valeur_detection="totalement_disjoint_1")
        b2 = self._attaque(exemple_attaque, id="B2", valeur_detection="totalement_disjoint_2")
        c = self._attaque(exemple_attaque, id="C", valeur_detection="xyz_more")
        lots = partitionner_pour_parallelisme([a, b1, b2, c], max_concurrentes=2)

        assert lots == [[a, b1], [b2], [c]]

    def test_concatenation_lots_egale_liste_dorigine_sur_catalogue_reel(self):
        catalogue = catalogue_actif()
        lots = partitionner_pour_parallelisme(catalogue)
        assert [a for lot in lots for a in lot] == catalogue


class TestRaffinementIntegration:
    """catalogue_actif()/obtenir_attaque() doivent appliquer les raffinements
    de bout en bout -- l'isolation (tmp_path) est déjà posée par la fixture
    autouse `isolation_environnement` de conftest.py."""

    def test_obtenir_attaque_reflete_le_raffinement(self):
        from cadre.raffinement import enregistrer_raffinement

        original = obtenir_attaque("CADRE-DIS-001")
        assert original is not None
        assert original.seuil_fp_max != 7

        enregistrer_raffinement("CADRE-DIS-001", {"seuil_fp_max": 7})
        raffinee = obtenir_attaque("CADRE-DIS-001")
        assert raffinee is not None
        assert raffinee.seuil_fp_max == 7
        assert raffinee.id == original.id  # même attaque, pas une nouvelle

    def test_catalogue_actif_garde_le_meme_nombre_d_entrees(self):
        from cadre.raffinement import enregistrer_raffinement

        avant = len(catalogue_actif())
        enregistrer_raffinement("CADRE-DIS-001", {"seuil_fp_max": 7})
        apres = len(catalogue_actif())
        assert avant == apres  # jamais de doublon créé par un raffinement


class TestStatistiques:
    def test_stats_coherentes(self):
        stats = statistiques_catalogue()
        assert stats["total"] == len(CATALOGUE)
        assert (stats["risque_faible"] + stats["risque_moyen"] + stats["risque_eleve"]) == stats[
            "total"
        ]
        assert stats["tactiques_uniques"] >= 5
        assert stats["techniques_uniques"] >= 8


class TestAtomicite:
    """Les dataclasses doivent être immutables."""

    def test_attaque_immuable(self):
        a = CATALOGUE[0]
        with pytest.raises(FrozenInstanceError):
            a.id = "MODIFIE"
