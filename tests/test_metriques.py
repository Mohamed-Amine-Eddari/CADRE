"""
Tests des métriques de valeur (src/cadre/metriques.py).

Le "temps gagné" est une estimation dérivée d'une hypothèse explicite : ces
tests vérifient le calcul, pas la justesse de l'hypothèse (qui est un choix
documenté, pas un fait mesuré).
"""

from __future__ import annotations

import csv

from cadre.metriques import (
    HEURES_PAR_REGLE_MANUELLE,
    calculer_metriques_valeur,
    calculer_tendance_cumulative,
    detecter_derive_regle,
    detecter_derive_toutes_regles,
)

RESULTATS = [
    {"statut": "VALIDE", "technique_mitre": "T1059.001", "tactique": "Execution", "nb_fp": 3},
    {"statut": "VALIDE", "technique_mitre": "T1136.001", "tactique": "Persistence", "nb_fp": 7},
    {"statut": "REJETE", "technique_mitre": "T1003.002", "tactique": "Cred Access", "nb_fp": 0},
    {"statut": "ANGLE_MORT", "technique_mitre": "T1053.005", "tactique": "Persistence", "nb_fp": 0},
    {
        "statut": "NON_APPLICABLE",
        "technique_mitre": "T1059.004",
        "tactique": "Execution",
        "nb_fp": None,
    },
]


class TestCalculerMetriquesValeur:
    def test_regles_produites_ne_compte_que_les_succes(self):
        m = calculer_metriques_valeur(RESULTATS)
        assert m["regles_produites"] == 2  # 2 VALIDE

    def test_en_attente_revue_compte_comme_succes(self):
        """Régression (audit) : une règle validée TP/FP mais dont le
        déploiement est différé pour revue humaine (`cadre cycle --revue`)
        est une règle produite avec succès -- son absence sous-évaluait le
        temps gagné et la couverture MITRE dans les rapports de valeur."""
        resultats = [
            *RESULTATS,
            {
                "statut": "EN_ATTENTE_REVUE",
                "technique_mitre": "T1082",
                "tactique": "Discovery",
                "nb_fp": 1,
            },
        ]
        m = calculer_metriques_valeur(resultats)
        assert m["regles_produites"] == 3  # 2 VALIDE + 1 EN_ATTENTE_REVUE

    def test_non_applicables_exclus_des_applicables(self):
        m = calculer_metriques_valeur(RESULTATS)
        assert m["total_attaques"] == 5
        assert m["non_applicables"] == 1
        assert m["applicables"] == 4

    def test_taux_reussite_sur_applicables(self):
        m = calculer_metriques_valeur(RESULTATS)
        assert m["taux_reussite_pct"] == 50.0  # 2 / 4

    def test_temps_gagne_suit_l_hypothese(self):
        m = calculer_metriques_valeur(RESULTATS, heures_par_regle_manuelle=2.0)
        assert m["temps_gagne_heures"] == 4.0  # 2 regles x 2 h
        assert m["hypothese_heures_par_regle"] == 2.0

    def test_temps_gagne_defaut(self):
        m = calculer_metriques_valeur(RESULTATS)
        assert m["temps_gagne_heures"] == round(2 * HEURES_PAR_REGLE_MANUELLE, 1)

    def test_couverture_tactiques_distinctes(self):
        m = calculer_metriques_valeur(RESULTATS)
        # 2 règles validées : Execution + Persistence = 2 tactiques distinctes
        assert m["tactiques_couvertes"] == 2
        assert m["total_tactiques_catalogue"] == 12  # catalogue réel
        assert m["couverture_tactiques_pct"] == round(2 / 12 * 100, 1)

    def test_faux_positifs_median_sur_regles_validees(self):
        m = calculer_metriques_valeur(RESULTATS)
        assert m["faux_positifs_median"] == 5.0  # (3 + 7) / 2

    def test_aucune_attaque_applicable_ne_plante_pas(self):
        resultats = [{"statut": "NON_APPLICABLE", "technique_mitre": "T1", "tactique": "X"}]
        m = calculer_metriques_valeur(resultats)
        assert m["applicables"] == 0
        assert m["taux_reussite_pct"] == 0.0
        assert m["temps_gagne_heures"] == 0.0

    def test_nb_fp_absent_ne_plante_pas(self):
        resultats = [{"statut": "VALIDE", "technique_mitre": "T1", "tactique": "X"}]
        m = calculer_metriques_valeur(resultats)
        assert m["regles_produites"] == 1
        assert m["faux_positifs_median"] == 0.0


class TestCalculerTendanceCumulative:
    def test_cumulatif_vide_retourne_dict_vide(self):
        assert calculer_tendance_cumulative({}) == {}
        assert calculer_tendance_cumulative({"autre_cle": 1}) == {}

    def test_agrege_temps_et_taux(self):
        cumul = {"total_cycles": 3, "total_attaques": 90, "validees": 45}
        t = calculer_tendance_cumulative(cumul)
        assert t["total_cycles"] == 3
        assert t["regles_validees_cumul"] == 45
        assert t["temps_gagne_heures_cumul"] == round(45 * HEURES_PAR_REGLE_MANUELLE, 1)
        assert t["taux_reussite_cumul_pct"] == 50.0


def _ecrire_cycle_csv(chemin, lignes):
    champs = ["timestamp", "id", "technique_mitre", "nb_tp", "nb_fp"]
    with chemin.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=champs)
        writer.writeheader()
        for ligne in lignes:
            writer.writerow(ligne)


class TestDetecterDeriveRegle:
    """Idée innovante : suivre si une règle déjà validée se dégrade dans le
    temps (perte de détection / dérive de bruit) plutôt que de la considérer
    acquise une fois déployée."""

    def test_aucun_repertoire(self, tmp_path):
        d = detecter_derive_regle("CADRE-DIS-001", tmp_path / "inexistant")
        assert d["statut"] == "INSUFFISANT"

    def test_une_seule_mesure_insuffisant(self, tmp_path):
        _ecrire_cycle_csv(
            tmp_path / "cycle_20260101_000000.csv",
            [
                {
                    "timestamp": "t1",
                    "id": "CADRE-DIS-001",
                    "technique_mitre": "T1082",
                    "nb_tp": 1,
                    "nb_fp": 5,
                }
            ],
        )
        d = detecter_derive_regle("CADRE-DIS-001", tmp_path)
        assert d["statut"] == "INSUFFISANT"
        assert d["nb_mesures"] == 1

    def test_stable(self, tmp_path):
        _ecrire_cycle_csv(
            tmp_path / "cycle_20260101_000000.csv",
            [
                {
                    "timestamp": "t1",
                    "id": "CADRE-DIS-001",
                    "technique_mitre": "T1082",
                    "nb_tp": 1,
                    "nb_fp": 5,
                }
            ],
        )
        _ecrire_cycle_csv(
            tmp_path / "cycle_20260102_000000.csv",
            [
                {
                    "timestamp": "t2",
                    "id": "CADRE-DIS-001",
                    "technique_mitre": "T1082",
                    "nb_tp": 1,
                    "nb_fp": 6,
                }
            ],
        )
        d = detecter_derive_regle("CADRE-DIS-001", tmp_path)
        assert d["statut"] == "STABLE"
        assert d["nb_mesures"] == 2

    def test_perte_detection(self, tmp_path):
        """tp passe de 1 à 0 -- la règle a cessé de détecter quoi que ce soit."""
        _ecrire_cycle_csv(
            tmp_path / "cycle_20260101_000000.csv",
            [
                {
                    "timestamp": "t1",
                    "id": "CADRE-DIS-005",
                    "technique_mitre": "T1049",
                    "nb_tp": 1,
                    "nb_fp": 9,
                }
            ],
        )
        _ecrire_cycle_csv(
            tmp_path / "cycle_20260102_000000.csv",
            [
                {
                    "timestamp": "t2",
                    "id": "CADRE-DIS-005",
                    "technique_mitre": "T1049",
                    "nb_tp": 0,
                    "nb_fp": 0,
                }
            ],
        )
        d = detecter_derive_regle("CADRE-DIS-005", tmp_path)
        assert d["statut"] == "PERTE_DETECTION"

    def test_derive_bruit(self, tmp_path):
        """fp plus que doublé (>1.5x) -- l'environnement est devenu plus bruyant."""
        _ecrire_cycle_csv(
            tmp_path / "cycle_20260101_000000.csv",
            [
                {
                    "timestamp": "t1",
                    "id": "CADRE-DIS-001",
                    "technique_mitre": "T1082",
                    "nb_tp": 1,
                    "nb_fp": 10,
                }
            ],
        )
        _ecrire_cycle_csv(
            tmp_path / "cycle_20260102_000000.csv",
            [
                {
                    "timestamp": "t2",
                    "id": "CADRE-DIS-001",
                    "technique_mitre": "T1082",
                    "nb_tp": 1,
                    "nb_fp": 30,
                }
            ],
        )
        d = detecter_derive_regle("CADRE-DIS-001", tmp_path)
        assert d["statut"] == "DERIVE_BRUIT"

    def test_ignore_les_lignes_d_autres_attaques(self, tmp_path):
        _ecrire_cycle_csv(
            tmp_path / "cycle_20260101_000000.csv",
            [
                {
                    "timestamp": "t1",
                    "id": "CADRE-DIS-001",
                    "technique_mitre": "T1082",
                    "nb_tp": 1,
                    "nb_fp": 5,
                },
                {
                    "timestamp": "t1",
                    "id": "CADRE-AUTRE",
                    "technique_mitre": "T1000",
                    "nb_tp": 1,
                    "nb_fp": 999,
                },
            ],
        )
        d = detecter_derive_regle("CADRE-DIS-001", tmp_path)
        assert d["statut"] == "INSUFFISANT"
        assert d["nb_mesures"] == 1


class TestDetecterDeriveToutesRegles:
    """Version multi-attaques (vue d'ensemble dashboard) -- même logique que
    detecter_derive_regle, mais en une seule passe sur tous les fichiers."""

    def test_aucun_repertoire_retourne_vide(self, tmp_path):
        assert detecter_derive_toutes_regles(tmp_path / "inexistant") == {}

    def test_aucun_cycle_retourne_vide(self, tmp_path):
        assert detecter_derive_toutes_regles(tmp_path) == {}

    def test_exclut_les_attaques_a_une_seule_mesure(self, tmp_path):
        _ecrire_cycle_csv(
            tmp_path / "cycle_20260101_000000.csv",
            [
                {
                    "timestamp": "t1",
                    "id": "CADRE-DIS-001",
                    "technique_mitre": "T1082",
                    "nb_tp": 1,
                    "nb_fp": 5,
                }
            ],
        )
        assert detecter_derive_toutes_regles(tmp_path) == {}

    def test_plusieurs_attaques_statuts_independants(self, tmp_path):
        _ecrire_cycle_csv(
            tmp_path / "cycle_20260101_000000.csv",
            [
                {
                    "timestamp": "t1",
                    "id": "CADRE-STABLE",
                    "technique_mitre": "T1",
                    "nb_tp": 1,
                    "nb_fp": 5,
                },
                {
                    "timestamp": "t1",
                    "id": "CADRE-BRUIT",
                    "technique_mitre": "T2",
                    "nb_tp": 1,
                    "nb_fp": 5,
                },
                {
                    "timestamp": "t1",
                    "id": "CADRE-PERTE",
                    "technique_mitre": "T3",
                    "nb_tp": 1,
                    "nb_fp": 5,
                },
            ],
        )
        _ecrire_cycle_csv(
            tmp_path / "cycle_20260102_000000.csv",
            [
                {
                    "timestamp": "t2",
                    "id": "CADRE-STABLE",
                    "technique_mitre": "T1",
                    "nb_tp": 1,
                    "nb_fp": 6,
                },
                {
                    "timestamp": "t2",
                    "id": "CADRE-BRUIT",
                    "technique_mitre": "T2",
                    "nb_tp": 1,
                    "nb_fp": 30,
                },
                {
                    "timestamp": "t2",
                    "id": "CADRE-PERTE",
                    "technique_mitre": "T3",
                    "nb_tp": 0,
                    "nb_fp": 0,
                },
            ],
        )
        resultats = detecter_derive_toutes_regles(tmp_path)
        assert resultats["CADRE-STABLE"]["statut"] == "STABLE"
        assert resultats["CADRE-BRUIT"]["statut"] == "DERIVE_BRUIT"
        assert resultats["CADRE-PERTE"]["statut"] == "PERTE_DETECTION"

    def test_coherent_avec_la_version_par_attaque(self, tmp_path):
        """Même jeu de données -- doit produire exactement le même résultat
        que detecter_derive_regle appelée attaque par attaque."""
        _ecrire_cycle_csv(
            tmp_path / "cycle_20260101_000000.csv",
            [
                {
                    "timestamp": "t1",
                    "id": "CADRE-DIS-001",
                    "technique_mitre": "T1082",
                    "nb_tp": 1,
                    "nb_fp": 5,
                }
            ],
        )
        _ecrire_cycle_csv(
            tmp_path / "cycle_20260102_000000.csv",
            [
                {
                    "timestamp": "t2",
                    "id": "CADRE-DIS-001",
                    "technique_mitre": "T1082",
                    "nb_tp": 1,
                    "nb_fp": 6,
                }
            ],
        )
        individuel = detecter_derive_regle("CADRE-DIS-001", tmp_path)
        vue_ensemble = detecter_derive_toutes_regles(tmp_path)["CADRE-DIS-001"]
        assert individuel == vue_ensemble
