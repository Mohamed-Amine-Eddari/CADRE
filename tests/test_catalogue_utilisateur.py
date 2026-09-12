"""
Tests du catalogue utilisateur extensible (src/cadre/catalogue_utilisateur.py).

Le socle natif (CATALOGUE) reste intact ; ces tests vérifient
que les attaques perso s'ajoutent, se valident et se persistent proprement,
sans jamais masquer ni corrompre le catalogue natif.
"""

from __future__ import annotations

import json

import pytest

from cadre.catalogue_attaques import (
    CATALOGUE,
    NiveauRisque,
    OrigineExecution,
    Plateforme,
    catalogue_actif,
)
from cadre.catalogue_utilisateur import (
    ErreurCatalogueUtilisateur,
    brouillon_vers_attaque,
    charger_attaques_utilisateur,
    enregistrer_attaque_utilisateur,
)

BROUILLON_VALIDE = {
    "id": "CADRE-PERSO-001",
    "nom": "Test perso",
    "description": "Une attaque de test personnelle",
    "technique_mitre": "T1059.001",
    "tactique_mitre": "Execution",
    "commande": "whoami",
    "event_ids_attendus": ["1"],
    "champ_principal": "process.command_line",
    "niveau_risque": "medium",
    # clés parasites typiques de l'assistant LLM, doivent être ignorées :
    "brouillon_ia": True,
    "modele": "llama3.1:8b",
}


class TestBrouillonVersAttaque:
    def test_brouillon_valide_devient_attaque(self):
        a = brouillon_vers_attaque(BROUILLON_VALIDE)
        assert a.id == "CADRE-PERSO-001"
        assert a.niveau_risque == NiveauRisque.MOYEN
        assert a.plateforme == Plateforme.WINDOWS  # défaut appliqué

    def test_cles_parasites_ignorees(self):
        # brouillon_ia / modele ne sont pas des champs d'AttaqueCatalogue
        a = brouillon_vers_attaque(BROUILLON_VALIDE)
        assert not hasattr(a, "brouillon_ia")

    def test_champ_requis_manquant_leve_erreur(self):
        brouillon = {k: v for k, v in BROUILLON_VALIDE.items() if k != "commande"}
        with pytest.raises(ErreurCatalogueUtilisateur, match="commande"):
            brouillon_vers_attaque(brouillon)

    def test_defauts_appliques(self):
        minimal = {
            "id": "X",
            "nom": "X",
            "technique_mitre": "T1",
            "tactique_mitre": "Execution",
            "commande": "whoami",
        }
        a = brouillon_vers_attaque(minimal)
        assert a.event_ids_attendus == ["1"]
        assert a.champ_principal == "process.command_line"
        assert a.niveau_risque == NiveauRisque.FAIBLE

    def test_event_ids_scalaire_normalise_en_liste(self):
        brouillon = {**BROUILLON_VALIDE, "event_ids_attendus": 4688}
        a = brouillon_vers_attaque(brouillon)
        assert a.event_ids_attendus == ["4688"]

    def test_niveau_risque_inconnu_retombe_sur_defaut(self):
        brouillon = {**BROUILLON_VALIDE, "niveau_risque": "catastrophique"}
        a = brouillon_vers_attaque(brouillon)
        assert a.niveau_risque == NiveauRisque.FAIBLE

    def test_valeur_enum_non_reconnue_est_journalisee(self, monkeypatch):
        """Régression : `_normaliser_enum` retombait SILENCIEUSEMENT sur le
        défaut. Une `plateforme` "ubuntu" non reconnue devenait `windows`
        sans aucun signal — une commande Linux serait alors envoyée vers la
        VM Windows. Le repli reste (tolérance voulue envers le LLM), mais
        il doit désormais laisser une trace."""
        avertissements = []

        class LoggerFactice:
            def warn(self, message, **kwargs):
                avertissements.append(message)

        monkeypatch.setattr("cadre.catalogue_utilisateur.obtenir_logger", LoggerFactice)
        brouillon = {**BROUILLON_VALIDE, "plateforme": "ubuntu"}
        a = brouillon_vers_attaque(brouillon)

        assert a.plateforme == Plateforme.WINDOWS  # repli inchangé
        assert any("ubuntu" in m for m in avertissements)

    def test_champ_enum_absent_ne_journalise_rien(self, monkeypatch):
        """Le champ absent est le cas NORMAL (le défaut s'applique) : il ne
        doit pas polluer les journaux, contrairement à une valeur fournie
        mais non reconnue."""
        avertissements = []

        class LoggerFactice:
            def warn(self, message, **kwargs):
                avertissements.append(message)

        monkeypatch.setattr("cadre.catalogue_utilisateur.obtenir_logger", LoggerFactice)
        brouillon = {k: v for k, v in BROUILLON_VALIDE.items() if k != "plateforme"}
        a = brouillon_vers_attaque(brouillon)

        assert a.plateforme == Plateforme.WINDOWS
        assert avertissements == []

    def test_origine_execution_normalisee_en_enum(self):
        """Régression (audit, reproduite en réel sur un cycle complet) :
        origine_execution n'était jamais normalisé ici, contrairement à
        niveau_risque/plateforme ci-dessus -- une valeur JSON ("cible")
        restait une chaîne Python brute. Sans effet au chargement, mais
        `_cible_pour_attaque` (orchestrateur.py) appelle
        `attaque.origine_execution.value`, qu'un str n'a pas :
        AttributeError sur la toute première attaque perso d'un cycle réel."""
        brouillon = {**BROUILLON_VALIDE, "origine_execution": "cible"}
        a = brouillon_vers_attaque(brouillon)
        assert isinstance(a.origine_execution, OrigineExecution)
        assert a.origine_execution == OrigineExecution.CIBLE
        assert a.origine_execution.value == "cible"

    def test_origine_execution_absente_retombe_sur_cible(self):
        brouillon = {k: v for k, v in BROUILLON_VALIDE.items() if k != "origine_execution"}
        a = brouillon_vers_attaque(brouillon)
        assert a.origine_execution == OrigineExecution.CIBLE

    def test_linux_sans_valeur_detection_refuse(self):
        """Régression (audit) : une attaque Linux sans `valeur_detection`
        générerait une règle Sigma `process.title|contains: ''`, qui
        compile en `process.title:*` (pysigma) -- un filtre qui matche
        quasiment tout événement de création de processus Linux, faute de
        tout autre champ de corrélation possible côté Auditbeat (contrairement
        à Windows, qui retombe sur `event.code` seul). Vérifié par
        compilation réelle avant ce correctif : la règle produite matchait
        tout. Refusé désormais dès l'entrée dans le catalogue utilisateur."""
        brouillon = {
            **BROUILLON_VALIDE,
            "id": "CADRE-PERSO-LIN-001",
            "plateforme": "linux",
        }
        assert "valeur_detection" not in brouillon
        with pytest.raises(ErreurCatalogueUtilisateur, match="valeur_detection"):
            brouillon_vers_attaque(brouillon)

    def test_linux_avec_valeur_detection_accepte(self):
        brouillon = {
            **BROUILLON_VALIDE,
            "id": "CADRE-PERSO-LIN-002",
            "plateforme": "linux",
            "valeur_detection": "CADRE_TEST_MARKER",
        }
        a = brouillon_vers_attaque(brouillon)
        assert a.plateforme == Plateforme.LINUX
        assert a.valeur_detection == "CADRE_TEST_MARKER"


class TestEnregistrerEtCharger:
    def test_enregistrer_puis_charger(self, tmp_path):
        chemin = tmp_path / "perso.json"
        enregistrer_attaque_utilisateur(BROUILLON_VALIDE, chemin=chemin)
        chargees = charger_attaques_utilisateur(chemin)
        assert len(chargees) == 1
        assert chargees[0].id == "CADRE-PERSO-001"

    def test_fichier_absent_retourne_liste_vide(self, tmp_path):
        assert charger_attaques_utilisateur(tmp_path / "inexistant.json") == []

    def test_refuse_id_deja_natif(self, tmp_path):
        brouillon = {**BROUILLON_VALIDE, "id": CATALOGUE[0].id}
        with pytest.raises(ErreurCatalogueUtilisateur, match="natif"):
            enregistrer_attaque_utilisateur(brouillon, chemin=tmp_path / "perso.json")

    @pytest.mark.parametrize(
        "id_malveillant",
        [
            "/evil",
            "../../evil",
            "..\\..\\evil",
            "sous-dossier/evil",
            "..",
        ],
    )
    def test_refuse_id_avec_separateur_de_chemin(self, tmp_path, id_malveillant):
        # Régression (audit sécurité) : `attaque.id` sert de nom de fichier
        # de règle sans validation -- un id "rooté" (commençant par `/` ou
        # `\`) contourne `repertoire_regles` entièrement via l'opérateur
        # `/` de pathlib. Vecteur concret : un dépôt Atomic Red Team
        # malveillant forgeant `attack_technique` (voir
        # `atomic_red_team._id_atomic`).
        brouillon = {**BROUILLON_VALIDE, "id": id_malveillant}
        with pytest.raises(ErreurCatalogueUtilisateur, match="invalide"):
            enregistrer_attaque_utilisateur(brouillon, chemin=tmp_path / "perso.json")
        # La tentative rejetée n'a rien écrit sur disque.
        assert not (tmp_path / "perso.json").exists()

    def test_refuse_doublon_perso(self, tmp_path):
        chemin = tmp_path / "perso.json"
        enregistrer_attaque_utilisateur(BROUILLON_VALIDE, chemin=chemin)
        with pytest.raises(ErreurCatalogueUtilisateur, match="déjà"):
            enregistrer_attaque_utilisateur(BROUILLON_VALIDE, chemin=chemin)

    def test_entree_invalide_ignoree_pas_de_crash(self, tmp_path):
        chemin = tmp_path / "perso.json"
        # une entrée valide + une entrée corrompue (sans commande)
        chemin.write_text(
            json.dumps([BROUILLON_VALIDE, {"id": "CASSE", "nom": "x"}]),
            encoding="utf-8",
        )
        chargees = charger_attaques_utilisateur(chemin)
        assert len(chargees) == 1  # la corrompue est ignorée, pas fatale

    def test_json_illisible_retourne_liste_vide(self, tmp_path):
        chemin = tmp_path / "perso.json"
        chemin.write_text("ceci n'est pas du JSON", encoding="utf-8")
        assert charger_attaques_utilisateur(chemin) == []

    def test_commande_dangereuse_editee_directement_est_ignoree_au_chargement(self, tmp_path):
        """Régression sécurité (audit) : `enregistrer_attaque_utilisateur()`
        filtre les commandes dangereuses à l'ÉCRITURE, mais catalogue_perso.json
        reste un fichier texte modifiable directement (édition manuelle, bug
        ailleurs) -- sans revérification au CHARGEMENT, une commande
        destructrice ajoutée hors du chemin normal deviendrait silencieusement
        exécutable par `cadre cycle` en mode réel. Le fichier est écrit
        directement ici pour simuler exactement ce contournement (jamais via
        enregistrer_attaque_utilisateur, qui l'aurait refusée en amont)."""
        chemin = tmp_path / "perso.json"
        brouillon_dangereux = {
            **BROUILLON_VALIDE,
            "id": "CADRE-PERSO-EVIL",
            "commande": "Remove-Item -Recurse -Force C:\\Windows\\System32",
        }
        chemin.write_text(json.dumps([BROUILLON_VALIDE, brouillon_dangereux]), encoding="utf-8")

        chargees = charger_attaques_utilisateur(chemin)

        assert len(chargees) == 1
        assert chargees[0].id == "CADRE-PERSO-001"
        assert not any(a.id == "CADRE-PERSO-EVIL" for a in chargees)

    def test_id_avec_separateur_de_chemin_edite_directement_est_ignore_au_chargement(
        self, tmp_path
    ):
        """Régression sécurité (audit) : `enregistrer_attaque_utilisateur()`
        refuse un id contenant un séparateur de chemin à l'ÉCRITURE (protection
        contre `repertoire_regles / f"{id}.yml"` qui sortirait de son dossier),
        mais catalogue_perso.json reste modifiable directement -- sans
        revérification au CHARGEMENT, ce contournement redeviendrait possible.
        Le fichier est écrit directement ici pour simuler exactement ce
        contournement (jamais via enregistrer_attaque_utilisateur, qui l'aurait
        refusé en amont)."""
        chemin = tmp_path / "perso.json"
        brouillon_malveillant = {**BROUILLON_VALIDE, "id": "../../evil"}
        chemin.write_text(json.dumps([BROUILLON_VALIDE, brouillon_malveillant]), encoding="utf-8")

        chargees = charger_attaques_utilisateur(chemin)

        assert len(chargees) == 1
        assert chargees[0].id == "CADRE-PERSO-001"
        assert not any(a.id == "../../evil" for a in chargees)


class TestConcurrenceEcritureFichier:
    """Même régression que revue_regles.py/raffinement.py::
    TestConcurrenceEcritureFichier : enregistrer_attaque_utilisateur faisait
    un cycle lecture-modification-écriture SANS verrou sur catalogue_perso.json
    -- des écritures concurrentes (le thread d'arrière-plan d'une découverte
    IA et un thread HTTP du dashboard traitant /api/suggest/enregistrer ou un
    import Atomic Red Team écrivent ce même fichier) pouvaient silencieusement
    en perdre certaines (dernier écrivain gagne sur tout le fichier)."""

    def test_20_threads_enregistrent_chacun_une_attaque_aucune_perdue(self, tmp_path):
        import threading

        chemin = tmp_path / "perso.json"
        nb_threads = 20
        barriere = threading.Barrier(nb_threads)

        def travail(i):
            barriere.wait()  # maximise le chevauchement réel entre threads
            brouillon = {**BROUILLON_VALIDE, "id": f"CADRE-STRESS-{i:03d}"}
            enregistrer_attaque_utilisateur(brouillon, chemin=chemin)

        threads = [threading.Thread(target=travail, args=(i,)) for i in range(nb_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        chargees = charger_attaques_utilisateur(chemin)
        assert len(chargees) == nb_threads  # aucune entrée perdue
        assert {a.id for a in chargees} == {f"CADRE-STRESS-{i:03d}" for i in range(nb_threads)}


class TestCatalogueActif:
    def test_sans_perso_egale_catalogue_natif(self, tmp_path, monkeypatch):
        # conftest isole déjà le chemin ; on confirme la valeur par défaut.
        assert len(catalogue_actif()) == len(CATALOGUE)

    def test_avec_perso_ajoute_les_attaques(self, tmp_path, monkeypatch):
        import cadre.catalogue_utilisateur as cu

        chemin = tmp_path / "perso.json"
        monkeypatch.setattr(cu, "CHEMIN_CATALOGUE_PERSO", chemin)
        enregistrer_attaque_utilisateur(BROUILLON_VALIDE, chemin=chemin)

        actif = catalogue_actif()
        assert len(actif) == len(CATALOGUE) + 1
        assert any(a.id == "CADRE-PERSO-001" for a in actif)
        # Le socle natif n'est pas muté (invariant déjà prouvé relationnellement
        # ci-dessus par len(actif) == len(CATALOGUE) + 1).
        assert len(CATALOGUE) >= 34
