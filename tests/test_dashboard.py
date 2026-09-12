"""
Tests pour le dashboard web local (src/cadre/dashboard.py).

Le serveur HTTP réel n'est testé qu'au strict minimum (un thread local sur
un port OS-assigné, jamais de réseau externe) ; l'essentiel de la logique
(lister_cycles, detail_cycle, chemin_securise, tail_logs, EtatCycle,
verifier_statut_stack, lister_catalogue, secrets, brouillon IA) est testé
directement, sans passer par HTTP.
"""

from __future__ import annotations

import base64
import csv
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from cadre.dashboard import (
    EtatCycle,
    apercu_atomic_dashboard,
    approuver_revue_dashboard,
    chemin_securise,
    creer_gestionnaire,
    definir_secret,
    demarrer_attaque_unique,
    demarrer_cycle,
    dernier_cycle,
    detail_attaque,
    detail_cycle,
    exporter_sigma_dashboard,
    generer_brouillon_ia,
    importer_atomic_dashboard,
    lire_regle_dashboard,
    lister_catalogue,
    lister_cycles,
    lister_revues_dashboard,
    lister_secrets,
    page_index_rapports,
    pousser_regle_dashboard,
    preparer_edition_regle_dashboard,
    raffiner_attaque_dashboard,
    rejeter_revue_dashboard,
    tail_logs,
    valider_regle_dashboard,
    verifier_statut_stack,
)

# Capturée au chargement du module, AVANT tout monkeypatch de test : référence
# stable vers la vraie classe, utilisable même dans un test dont la fixture
# `serveur_test` a déjà patché "cadre.orchestrateur.OrchestrateurCADRE".
from cadre.orchestrateur import OrchestrateurCADRE as OrchestrateurCADREReelle


def _ecrire_cycle_csv(repertoire, horodatage, lignes):
    repertoire.mkdir(parents=True, exist_ok=True)
    fichier = repertoire / f"cycle_{horodatage}.csv"
    champs = [
        "timestamp",
        "id",
        "technique_mitre",
        "tactique",
        "description",
        "statut",
        "nb_tp",
        "nb_fp",
        "raison",
    ]
    with fichier.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=champs)
        writer.writeheader()
        for ligne in lignes:
            writer.writerow(ligne)
    return fichier


LIGNES_EXEMPLE = [
    {
        "timestamp": "2026-08-01T10:00:00",
        "technique_mitre": "T1059.001",
        "tactique": "Execution",
        "description": "PowerShell",
        "statut": "VALIDE",
        "nb_tp": 3,
        "nb_fp": 0,
        "raison": "OK",
    },
    {
        "timestamp": "2026-08-01T10:01:00",
        "technique_mitre": "T1136.001",
        "tactique": "Persistence",
        "description": "Création de compte",
        "statut": "ANGLE_MORT",
        "nb_tp": 0,
        "nb_fp": 0,
        "raison": "Aucun log",
    },
]


class TestListerCycles:
    def test_repertoire_absent_retourne_liste_vide(self, tmp_path):
        assert lister_cycles(tmp_path / "inexistant") == []

    def test_aucun_cycle_retourne_liste_vide(self, tmp_path):
        assert lister_cycles(tmp_path) == []

    def test_un_cycle_est_resume_correctement(self, tmp_path):
        _ecrire_cycle_csv(tmp_path, "20260801_100000", LIGNES_EXEMPLE)
        cycles = lister_cycles(tmp_path)
        assert len(cycles) == 1
        assert cycles[0]["horodatage"] == "20260801_100000"
        assert cycles[0]["total"] == 2
        assert cycles[0]["compteurs"] == {"VALIDE": 1, "ANGLE_MORT": 1}

    def test_tri_du_plus_recent_au_plus_ancien(self, tmp_path):
        _ecrire_cycle_csv(tmp_path, "20260801_090000", LIGNES_EXEMPLE)
        _ecrire_cycle_csv(tmp_path, "20260801_110000", LIGNES_EXEMPLE)
        cycles = lister_cycles(tmp_path)
        assert [c["horodatage"] for c in cycles] == ["20260801_110000", "20260801_090000"]

    def test_detecte_les_rapports_associes_disponibles(self, tmp_path):
        _ecrire_cycle_csv(tmp_path, "20260801_100000", LIGNES_EXEMPLE)
        (tmp_path / "cycle_20260801_100000.html").write_text("<html></html>", encoding="utf-8")
        cycles = lister_cycles(tmp_path)
        assert cycles[0]["html_disponible"] is True
        assert cycles[0]["markdown_disponible"] is False

    def test_scenario_html_absent_par_defaut(self, tmp_path):
        _ecrire_cycle_csv(tmp_path, "20260801_100000", LIGNES_EXEMPLE)
        assert lister_cycles(tmp_path)[0]["scenario_html"] is None

    def test_scenario_html_lie_au_bon_cycle_parmi_plusieurs(self, tmp_path):
        """Régression : le lien scenario_html est désormais construit via un
        index global (un seul glob("scenario_*.html") avant la boucle,
        au lieu d'un glob PAR cycle à l'intérieur -- voir dernier_cycle()
        pour le même motif) -- il doit rester associé au BON horodatage,
        pas au premier match trouvé ni à un cycle voisin. L'ID de scénario
        contient lui-même un "_" (RANSOMWARE_KIT), cas volontairement
        piégeux pour l'extraction des 15 derniers caractères."""
        _ecrire_cycle_csv(tmp_path, "20260801_090000", LIGNES_EXEMPLE)
        _ecrire_cycle_csv(tmp_path, "20260801_100000", LIGNES_EXEMPLE)
        (tmp_path / "scenario_RANSOMWARE_KIT_20260801_100000.html").write_text(
            "<html></html>", encoding="utf-8"
        )
        cycles = {c["horodatage"]: c for c in lister_cycles(tmp_path)}
        assert cycles["20260801_100000"]["scenario_html"] == (
            "scenario_RANSOMWARE_KIT_20260801_100000.html"
        )
        assert cycles["20260801_090000"]["scenario_html"] is None


class TestDernierCycle:
    """dernier_cycle() : équivalent lister_cycles()[0] sans lire tout
    l'historique -- consommé par vue-ensemble.js/detections.js/erreurs.js,
    qui n'ont jamais besoin que du cycle le plus récent."""

    def test_repertoire_absent_retourne_none(self, tmp_path):
        assert dernier_cycle(tmp_path / "inexistant") is None

    def test_aucun_cycle_retourne_none(self, tmp_path):
        assert dernier_cycle(tmp_path) is None

    def test_meme_forme_qu_un_element_de_lister_cycles(self, tmp_path):
        _ecrire_cycle_csv(tmp_path, "20260801_100000", LIGNES_EXEMPLE)
        (tmp_path / "cycle_20260801_100000.html").write_text("<html></html>", encoding="utf-8")
        assert dernier_cycle(tmp_path) == lister_cycles(tmp_path)[0]

    def test_retourne_le_plus_recent_parmi_plusieurs(self, tmp_path):
        _ecrire_cycle_csv(tmp_path, "20260801_090000", LIGNES_EXEMPLE)
        _ecrire_cycle_csv(tmp_path, "20260801_110000", LIGNES_EXEMPLE)
        assert dernier_cycle(tmp_path)["horodatage"] == "20260801_110000"

    def test_scenario_html_lie_au_dernier_cycle(self, tmp_path):
        _ecrire_cycle_csv(tmp_path, "20260801_090000", LIGNES_EXEMPLE)
        _ecrire_cycle_csv(tmp_path, "20260801_110000", LIGNES_EXEMPLE)
        (tmp_path / "scenario_RANSOMWARE_KIT_20260801_110000.html").write_text(
            "<html></html>", encoding="utf-8"
        )
        assert dernier_cycle(tmp_path)["scenario_html"] == (
            "scenario_RANSOMWARE_KIT_20260801_110000.html"
        )


class TestPageIndexRapports:
    """EXC4 : page HTML autonome listant les cycles (jamais couverte avant)."""

    def test_aucun_cycle_message_vide(self, tmp_path):
        html = page_index_rapports(tmp_path)
        assert "Aucun rapport pour l'instant." in html
        assert "<!doctype html>" in html

    def test_un_cycle_avec_liens_disponibles(self, tmp_path):
        _ecrire_cycle_csv(tmp_path, "20260801_100000", LIGNES_EXEMPLE)
        (tmp_path / "cycle_20260801_100000.html").write_text("<html></html>", encoding="utf-8")
        (tmp_path / "cycle_20260801_100000.md").write_text("# rapport", encoding="utf-8")
        html = page_index_rapports(tmp_path)
        assert "2026-08-01 10:00:00" in html  # horodatage lisible
        assert "2 attaque(s)" in html
        assert 'href="/rapports/cycle_20260801_100000.html"' in html
        assert 'href="/rapports/cycle_20260801_100000.md"' in html
        assert 'href="/rapports/cycle_20260801_100000_navigator.json"' not in html

    def test_en_attente_revue_apparait_dans_les_pastilles(self, tmp_path):
        """Régression (audit) : EN_ATTENTE_REVUE était absent de la liste
        `familles` -- une règle validée en attente de revue humaine
        disparaissait silencieusement des compteurs affichés sur /rapports/."""
        lignes = [{**LIGNES_EXEMPLE[0], "statut": "EN_ATTENTE_REVUE"}]
        _ecrire_cycle_csv(tmp_path, "20260801_100000", lignes)
        html = page_index_rapports(tmp_path)
        assert "en attente de revue" in html

    def test_lien_kill_chain_si_scenario_present(self, tmp_path):
        _ecrire_cycle_csv(tmp_path, "20260801_100000", LIGNES_EXEMPLE)
        (tmp_path / "scenario_RANSOMWARE_20260801_100000.html").write_text(
            "<html></html>", encoding="utf-8"
        )
        html = page_index_rapports(tmp_path)
        assert "Kill chain" in html
        assert "scenario_RANSOMWARE_20260801_100000.html" in html


class TestDetailCycle:
    def test_cycle_inconnu_retourne_none(self, tmp_path):
        assert detail_cycle(tmp_path, "inexistant") is None

    def test_detail_groupe_par_statut(self, tmp_path):
        _ecrire_cycle_csv(tmp_path, "20260801_100000", LIGNES_EXEMPLE)
        detail = detail_cycle(tmp_path, "20260801_100000")
        assert detail["total"] == 2
        assert "VALIDE" in detail["groupes"]
        assert "ANGLE_MORT" in detail["groupes"]
        assert detail["groupes"]["VALIDE"][0]["technique_mitre"] == "T1059.001"

    def test_path_traversal_via_horodatage_est_bloque(self, tmp_path):
        """Régression sécurité : `horodatage` vient tel quel de l'URL
        cliente (route GET /api/cycles/<horodatage>, sans garde CSRF
        puisque c'est un GET) et était concaténé directement en
        `f"cycle_{horodatage}.csv"`, SANS passer par `chemin_securise()`
        -- contrairement à /rapports/<fichier> qui, elle, est protégée.
        Le préfixe "cycle_" ne bloque pas la traversée : un premier segment
        arbitraire ("x") absorbe le préfixe, puis deux "../" ramènent hors
        de `repertoire_rapports`. Un fichier RÉEL est placé à la cible de
        l'évasion, un niveau au-dessus de `repertoire_rapports` : sans la
        protection, son contenu aurait fuité dans la réponse JSON."""
        secret = tmp_path.parent / "secret.csv"
        contenu_secret = "CADRE_VM_PASS=ne-doit-jamais-fuiter"  # pragma: allowlist secret
        secret.write_text(contenu_secret, encoding="utf-8")
        assert detail_cycle(tmp_path, "x/../../secret") is None


class TestCheminSecurise:
    def test_fichier_existant_dans_le_repertoire(self, tmp_path):
        (tmp_path / "rapport.html").write_text("ok", encoding="utf-8")
        resultat = chemin_securise(tmp_path, "rapport.html")
        assert resultat == (tmp_path / "rapport.html").resolve()

    def test_fichier_inexistant_retourne_none(self, tmp_path):
        assert chemin_securise(tmp_path, "absent.html") is None

    def test_path_traversal_est_bloque(self, tmp_path):
        secret = tmp_path.parent / "secret.txt"
        secret.write_text("ne doit jamais être servi", encoding="utf-8")
        assert chemin_securise(tmp_path, "../secret.txt") is None

    def test_chemin_absolu_est_bloque(self, tmp_path):
        assert chemin_securise(tmp_path, "C:/Windows/win.ini") is None


class TestTailLogs:
    def test_fichier_absent_retourne_liste_vide(self, tmp_path):
        assert tail_logs(tmp_path / "absent.json") == []

    def test_retourne_les_n_derniers_evenements(self, tmp_path):
        fichier = tmp_path / "cadre.log.json"
        lignes = [json.dumps({"type": "INFO", "message": f"evt-{i}"}) for i in range(5)]
        fichier.write_text("\n".join(lignes), encoding="utf-8")
        evenements = tail_logs(fichier, n=2)
        assert [e["message"] for e in evenements] == ["evt-3", "evt-4"]

    def test_ligne_json_invalide_est_ignoree(self, tmp_path):
        fichier = tmp_path / "cadre.log.json"
        contenu = '{"type": "INFO", "message": "ok"}\nceci n\'est pas du JSON\n'
        fichier.write_text(contenu, encoding="utf-8")
        evenements = tail_logs(fichier, n=10)
        assert len(evenements) == 1
        assert evenements[0]["message"] == "ok"

    def test_ligne_vide_est_ignoree(self, tmp_path):
        """EXC4 : une ligne blanche (fin de fichier, écriture concurrente)
        ne doit pas produire d'entrée ni faire planter le parsing."""
        fichier = tmp_path / "cadre.log.json"
        contenu = '{"type": "INFO", "message": "a"}\n\n{"type": "INFO", "message": "b"}\n'
        fichier.write_text(contenu, encoding="utf-8")
        evenements = tail_logs(fichier, n=10)
        assert [e["message"] for e in evenements] == ["a", "b"]

    def test_n_zero_ne_renvoie_rien(self, tmp_path):
        """Régression sécurité : `lignes[-0:]` vaut `lignes[0:]` (TOUT le
        fichier) en Python -- /api/logs?n=0 renvoyait donc l'intégralité du
        journal au lieu de "les 0 derniers événements" (l'attente
        intuitive : rien)."""
        fichier = tmp_path / "cadre.log.json"
        lignes = [json.dumps({"type": "INFO", "message": f"evt-{i}"}) for i in range(5)]
        fichier.write_text("\n".join(lignes), encoding="utf-8")
        assert tail_logs(fichier, n=0) == []

    def test_n_negatif_ne_renvoie_rien(self, tmp_path):
        """Même régression : un `n` négatif produit aussi un résultat
        surprenant via le slicing Python (`lignes[-(-5):]` == `lignes[5:]`,
        quasiment tout le fichier)."""
        fichier = tmp_path / "cadre.log.json"
        lignes = [json.dumps({"type": "INFO", "message": f"evt-{i}"}) for i in range(5)]
        fichier.write_text("\n".join(lignes), encoding="utf-8")
        assert tail_logs(fichier, n=-1) == []

    def test_n_excessif_est_borne(self, tmp_path):
        """Un n démesuré (ex. envoyé par erreur ou volontairement) ne doit
        pas forcer la lecture/le renvoi d'un fichier de journal arbitrairement
        gros -- borné à 1000."""
        fichier = tmp_path / "cadre.log.json"
        lignes = [json.dumps({"type": "INFO", "message": f"evt-{i}"}) for i in range(5)]
        fichier.write_text("\n".join(lignes), encoding="utf-8")
        evenements = tail_logs(fichier, n=10_000_000)
        assert len(evenements) == 5  # borné par le contenu réel, pas de plantage

    def test_entrees_debug_exclues_mais_n_toujours_respecte(self, tmp_path):
        """Régression (audit navigateur réel, 07/09) : SECRET_READ (niveau
        DEBUG, ré-émis à chaque vérification d'auth HTTP -- donc à chaque
        sondage du dashboard, toutes les 2-9 s) noyait le journal affiché en
        moins d'une minute d'ouverture du dashboard. Le fichier sur disque
        doit rester complet (trace d'audit), mais /api/logs -- une surface
        de suivi en direct comme la console, pas la trace elle-même -- ne
        doit renvoyer QUE des événements de niveau visible, et toujours en
        renvoyer `n` si le fichier en contient assez une fois le bruit
        DEBUG écarté (pas `n` lignes brutes dont la plupart seraient du
        bruit filtré après coup)."""
        fichier = tmp_path / "cadre.log.json"
        lignes = []
        for i in range(20):
            lignes.append(
                json.dumps({"type": "SECRET_READ", "niveau": "DEBUG", "message": f"bruit-{i}"})
            )
            lignes.append(json.dumps({"type": "INFO", "niveau": "INFO", "message": f"utile-{i}"}))
        fichier.write_text("\n".join(lignes), encoding="utf-8")

        evenements = tail_logs(fichier, n=3)

        assert [e["message"] for e in evenements] == ["utile-17", "utile-18", "utile-19"]
        assert all(e["niveau"] != "DEBUG" for e in evenements)


class TestTechniquesParStatut:
    """EXC4 : agrégation de couverture pour la matrice ATT&CK (jamais
    couverte directement avant, seulement via la vue matrice de haut niveau)."""

    def test_repertoire_absent_retourne_ensembles_vides(self, tmp_path):
        from cadre.dashboard import _techniques_par_statut

        validees, testees = _techniques_par_statut(tmp_path / "absent")
        assert validees == set()
        assert testees == set()

    def test_non_applicable_et_technique_manquante_ignorees(self, tmp_path):
        from cadre.dashboard import _techniques_par_statut

        lignes = [
            {**LIGNES_EXEMPLE[0], "technique_mitre": "T1000", "statut": "VALIDE"},
            {**LIGNES_EXEMPLE[0], "technique_mitre": "T1105", "statut": "NON_APPLICABLE"},
            {**LIGNES_EXEMPLE[0], "technique_mitre": "", "statut": "VALIDE"},
        ]
        _ecrire_cycle_csv(tmp_path, "20260801_100000", lignes)
        validees, testees = _techniques_par_statut(tmp_path)
        assert testees == {"T1000"}  # ni NON_APPLICABLE, ni technique vide
        assert validees == {"T1000"}

    def test_en_attente_revue_compte_comme_validee(self, tmp_path):
        """Régression (audit) : une technique dont la seule règle produite
        est EN_ATTENTE_REVUE (cadre cycle --revue) est prouvée (TP/FP passés)
        -- elle doit apparaître validée dans la matrice ATT&CK, pas manquante."""
        from cadre.dashboard import _techniques_par_statut

        lignes = [{**LIGNES_EXEMPLE[0], "technique_mitre": "T1082", "statut": "EN_ATTENTE_REVUE"}]
        _ecrire_cycle_csv(tmp_path, "20260801_100000", lignes)
        validees, testees = _techniques_par_statut(tmp_path)
        assert testees == {"T1082"}
        assert validees == {"T1082"}


class TestVerifierStatutStack:
    def test_verifie_elasticsearch_kibana_et_vm(self, tmp_path, monkeypatch):
        class ReponseFactice:
            status_code = 200

        monkeypatch.setattr("requests.get", lambda *a, **k: ReponseFactice())

        class OrchestrateurFactice:
            def __init__(self, config):
                self.config = {
                    "elastic_url": "http://localhost:9200",
                    "kibana_url": "http://localhost:5601",
                    "vm_ip": "192.168.56.104",
                }
                self.auth_elastic = None

            def _verifier_connectivite_vm(self):
                return True

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurFactice)
        statut = verifier_statut_stack({"repertoire_rapports": tmp_path})

        assert statut["elasticsearch"]["ok"] is True
        assert statut["kibana"]["ok"] is True
        assert statut["vm"]["ok"] is True
        assert statut["vm"]["detail"] == "192.168.56.104"

    def test_service_injoignable_est_signale(self, tmp_path, monkeypatch):
        import requests

        def get_qui_echoue(*a, **k):
            raise requests.exceptions.ConnectionError("refused")

        monkeypatch.setattr("requests.get", get_qui_echoue)

        class OrchestrateurFactice:
            def __init__(self, config):
                self.config = {
                    "elastic_url": "http://localhost:9200",
                    "kibana_url": "http://localhost:5601",
                    "vm_ip": "",
                }
                self.auth_elastic = None

            def _verifier_connectivite_vm(self):
                return False

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurFactice)
        statut = verifier_statut_stack({"repertoire_rapports": tmp_path})

        assert statut["elasticsearch"]["ok"] is False
        assert statut["vm"]["ok"] is False
        assert statut["vm"]["detail"] == "non configurée"


class TestListerCatalogue:
    def test_retourne_le_catalogue_reel(self):
        from cadre.catalogue_attaques import CATALOGUE

        attaques = lister_catalogue()
        # Catalogue isolé (conftest) : perso vide → lister == natif.
        assert len(attaques) == len(CATALOGUE)
        assert all({"id", "technique_mitre", "tactique_mitre"} <= a.keys() for a in attaques)
        # Ne doit jamais inclure la commande brute (surface d'info, pas un secret,
        # mais hors du besoin d'affichage catalogue) ni faux_positifs_connus.
        assert "commande" not in attaques[0]


class TestDetailAttaque:
    def test_id_inconnu_retourne_none(self):
        assert detail_attaque("N-EXISTE-PAS") is None

    def test_detail_inclut_description_et_commande(self):
        from cadre.catalogue_attaques import CATALOGUE

        premiere = CATALOGUE[0]
        d = detail_attaque(premiere.id)
        assert d["description"] == premiere.description
        assert d["commande"] == premiere.commande
        assert d["nom"] == premiere.nom
        assert d["perso"] is False


class TestConstruireMatrice:
    def test_structure_14_tactiques_ordre_canonique(self, tmp_path):
        from cadre.dashboard import construire_matrice

        m = construire_matrice(tmp_path)  # aucun rapport → rien de validé
        assert len(m["colonnes"]) == 14
        # Les 2 premières colonnes sont les tactiques amont hors périmètre
        # (entièrement côté attaquant -- aucune télémétrie possible sur la
        # cible, même depuis Kali). Initial Access est dans le périmètre
        # depuis CADRE-INI-001 (T1133, origine Kali).
        assert [c["nom"] for c in m["colonnes"][:3]] == [
            "Reconnaissance",
            "Resource Development",
            "Initial Access",
        ]
        assert all(c["hors_scope"] for c in m["colonnes"][:2])
        assert all(not c["hors_scope"] for c in m["colonnes"][2:])

    def test_techniques_du_catalogue_placees_dans_leur_tactique(self, tmp_path):
        from cadre.dashboard import construire_matrice

        m = construire_matrice(tmp_path)
        par_nom = {c["nom"]: c for c in m["colonnes"]}
        codes_execution = {t["technique"] for t in par_nom["Execution"]["techniques"]}
        assert "T1059.001" in codes_execution
        # Sans aucun cycle, tout est "couverte", rien n'est "validee".
        assert all(t["etat"] == "couverte" for c in m["colonnes"] for t in c["techniques"])
        assert m["resume"]["techniques_validees"] == 0
        assert m["resume"]["techniques_couvertes"] > 0

    def test_un_cycle_valide_colore_la_technique_en_validee(self, tmp_path):
        from cadre.dashboard import construire_matrice

        _ecrire_cycle_csv(tmp_path, "20260801_100000", LIGNES_EXEMPLE)
        m = construire_matrice(tmp_path)
        par_nom = {c["nom"]: c for c in m["colonnes"]}
        exec_par_code = {t["technique"]: t for t in par_nom["Execution"]["techniques"]}
        # T1059.001 est VALIDE dans le cycle → validée ; T1136.001 est ANGLE_MORT
        # (testée mais non validée) → testee.
        assert exec_par_code["T1059.001"]["etat"] == "validee"
        pers_par_code = {t["technique"]: t for t in par_nom["Persistence"]["techniques"]}
        assert pers_par_code["T1136.001"]["etat"] == "testee"
        assert m["resume"]["techniques_validees"] >= 1


class TestSecrets:
    def test_lister_secrets_delegue_au_coffre(self, monkeypatch):
        class CoffreFactice:
            def lister_cles(self):
                return ["CADRE_VM_IP", "CADRE_ELASTIC_PASS"]

        monkeypatch.setattr("cadre.coffre_fort.obtenir_coffre", CoffreFactice)
        assert lister_secrets() == ["CADRE_VM_IP", "CADRE_ELASTIC_PASS"]

    def test_definir_secret_delegue_au_coffre(self, monkeypatch):
        appels = []

        class CoffreFactice:
            def stocker(self, cle, valeur):
                appels.append((cle, valeur))

        monkeypatch.setattr("cadre.coffre_fort.obtenir_coffre", CoffreFactice)
        definir_secret("CADRE_VM_PASS", "secret123")
        assert appels == [("CADRE_VM_PASS", "secret123")]

    def test_statut_secrets_reflete_la_resolution_reelle(self, monkeypatch):
        from cadre.dashboard import statut_secrets

        # CADRE_VM_PASS résolu (trousseau/env), le reste absent
        monkeypatch.setattr(
            "cadre.coffre_fort.secret_or_none",
            lambda cle: "valeur" if cle == "CADRE_VM_PASS" else None,
        )
        statut = statut_secrets()
        par_cle = {s["cle"]: s for s in statut}
        assert par_cle["CADRE_VM_PASS"]["configure"] is True
        assert par_cle["CADRE_ELASTIC_PASS"]["configure"] is False
        # jamais la valeur, seulement l'état
        assert "valeur" not in str(statut)


class TestGenererBrouillonIA:
    def test_delegue_a_l_assistant(self, monkeypatch):
        class AssistantFactice:
            def suggerer_attaque(self, description, technique_mitre=None):
                return {
                    "nom": "test",
                    "technique_mitre": technique_mitre,
                    "description_recue": description,
                }

        monkeypatch.setattr("cadre.assistant_llm.obtenir_assistant_llm", AssistantFactice)
        resultat = generer_brouillon_ia("dump SAM", "T1003.002")
        assert resultat["technique_mitre"] == "T1003.002"
        assert resultat["description_recue"] == "dump SAM"

    def test_echec_assistant_retourne_none(self, monkeypatch):
        class AssistantFactice:
            def suggerer_attaque(self, description, technique_mitre=None):
                return None

        monkeypatch.setattr("cadre.assistant_llm.obtenir_assistant_llm", AssistantFactice)
        assert generer_brouillon_ia("description", None) is None


class TestEtatCycle:
    def test_demarrer_reussit_si_inactif(self):
        etat = EtatCycle()
        assert etat.demarrer("simulation") is True
        snap = etat.snapshot()
        assert snap["en_cours"] is True
        assert snap["mode"] == "simulation"

    def test_demarrer_echoue_si_deja_en_cours(self):
        etat = EtatCycle()
        etat.demarrer("simulation")
        assert etat.demarrer("reel") is False

    def test_terminer_reinitialise_l_etat(self):
        etat = EtatCycle()
        etat.demarrer("simulation")
        etat.terminer()
        snap = etat.snapshot()
        assert snap["en_cours"] is False
        assert snap["termine_a"] is not None
        assert snap["erreur"] is None

    def test_terminer_avec_erreur_est_conservee(self):
        etat = EtatCycle()
        etat.demarrer("reel")
        etat.terminer(erreur="VM inaccessible")
        assert etat.snapshot()["erreur"] == "VM inaccessible"


class TestDemarrerCycle:
    def test_mode_invalide_leve_une_erreur(self):
        with pytest.raises(ValueError):
            demarrer_cycle({}, EtatCycle(), mode="magique")

    def test_mode_simulation_par_defaut(self, tmp_path, monkeypatch):
        appels = []

        class OrchestrateurFactice:
            def __init__(self, config):
                appels.append(config)

            def executer_cycle_complet(
                self,
                techniques_a_executer=None,
                mode_simulation=False,
                rapporteur=None,
                parallele=False,
            ):
                appels.append(mode_simulation)

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurFactice)
        etat = EtatCycle()
        config = {"repertoire_rapports": tmp_path, "repertoire_regles": tmp_path}

        assert demarrer_cycle(config, etat) is True
        _attendre_fin(etat)
        assert appels[0] == config
        assert appels[1] is True  # mode_simulation=True

    def test_mode_reel_appelle_mode_simulation_false(self, tmp_path, monkeypatch):
        appels = []

        class OrchestrateurFactice:
            def __init__(self, config):
                pass

            def executer_cycle_complet(
                self,
                techniques_a_executer=None,
                mode_simulation=False,
                rapporteur=None,
                parallele=False,
            ):
                appels.append(mode_simulation)

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurFactice)
        etat = EtatCycle()
        demarrer_cycle({"repertoire_rapports": tmp_path}, etat, mode="reel")
        _attendre_fin(etat)
        assert appels == [False]

    def test_refuse_si_deja_en_cours(self, tmp_path, monkeypatch):
        appels = []
        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE",
            lambda config: appels.append("appelé"),
        )
        etat = EtatCycle()
        etat.demarrer("simulation")  # simule un cycle déjà actif
        resultat = demarrer_cycle({"repertoire_rapports": tmp_path}, etat)
        assert resultat is False
        assert appels == []

    def test_erreur_pendant_le_cycle_est_capturee(self, tmp_path, monkeypatch):
        """Une exception inattendue (pas une collision de verrou F-009) ne
        doit JAMAIS exposer son message brut via /api/cycle/statut -- même
        discipline log-only que /api/secrets, /api/revue/approuver,
        /api/export-sigma."""

        class OrchestrateurQuiExplose:
            def __init__(self, config):
                pass

            def executer_cycle_complet(
                self,
                techniques_a_executer=None,
                mode_simulation=False,
                rapporteur=None,
                parallele=False,
            ):
                raise RuntimeError("VM injoignable (détail interne)")

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurQuiExplose)
        etat = EtatCycle()
        demarrer_cycle({"repertoire_rapports": tmp_path}, etat, mode="reel")
        _attendre_fin(etat)
        erreur = etat.snapshot()["erreur"]
        assert "injoignable" not in erreur  # détail interne jamais exposé
        assert "voir journaux serveur" in erreur

    def test_collision_de_verrou_expose_le_message_tel_quel(self, tmp_path, monkeypatch):
        """VerrouCycleActifError (F-009) est un cas à part : contrairement à
        une exception arbitraire, son message est rédigé par CADRE lui-même
        et sûr à afficher tel quel (pas de détail interne)."""
        from cadre.orchestrateur import VerrouCycleActifError

        class OrchestrateurQuiCollisionne:
            def __init__(self, config):
                pass

            def executer_cycle_complet(
                self,
                techniques_a_executer=None,
                mode_simulation=False,
                rapporteur=None,
                parallele=False,
            ):
                raise VerrouCycleActifError("Un autre cycle réel est déjà en cours (PID 4242)")

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurQuiCollisionne)
        etat = EtatCycle()
        demarrer_cycle({"repertoire_rapports": tmp_path}, etat, mode="reel")
        _attendre_fin(etat)
        assert etat.snapshot()["erreur"] == "Un autre cycle réel est déjà en cours (PID 4242)"

    def test_parallele_transmis_a_executer_cycle_complet(self, tmp_path, monkeypatch):
        """Régression : un cycle catalogue complet lancé depuis le dashboard
        restait toujours séquentiel, --parallel n'était jamais exposé côté
        HTTP contrairement à la CLI (`cadre cycle --parallel`)."""
        appels = []

        class OrchestrateurFactice:
            def __init__(self, config):
                pass

            def executer_cycle_complet(
                self,
                techniques_a_executer=None,
                mode_simulation=False,
                rapporteur=None,
                parallele=False,
            ):
                appels.append(parallele)

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurFactice)
        etat = EtatCycle()
        demarrer_cycle({"repertoire_rapports": tmp_path}, etat, parallele=True)
        _attendre_fin(etat)
        assert appels == [True]


class TestDemarrerAttaqueUnique:
    def test_mode_invalide_leve_une_erreur(self):
        from cadre.catalogue_attaques import catalogue_actif

        attaque = catalogue_actif()[0]
        with pytest.raises(ValueError):
            demarrer_attaque_unique({}, EtatCycle(), attaque, mode="magique")

    def test_mode_simulation_appelle_executer_attaque_simulation(self, tmp_path, monkeypatch):
        from cadre.catalogue_attaques import catalogue_actif

        appels = []

        class OrchestrateurFactice:
            def __init__(self, config):
                self._tls = threading.local()

            def _rapporter_etape(self, numero, nom):
                pass

            def _executer_attaque_simulation(self, attaque):
                appels.append(("simulation", attaque.id))
                return {"statut": "SIMULE", "id": attaque.id}

            def _generer_rapports_fin_cycle(self):
                appels.append("rapports")

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurFactice)
        attaque = catalogue_actif()[0]
        etat = EtatCycle()
        config = {"repertoire_rapports": tmp_path, "repertoire_regles": tmp_path}

        assert demarrer_attaque_unique(config, etat, attaque, mode="simulation") is True
        _attendre_fin(etat)
        assert appels == [("simulation", attaque.id), "rapports"]

    def test_mode_reel_appelle_executer_attaque_complete(self, tmp_path, monkeypatch):
        from cadre.catalogue_attaques import catalogue_actif

        appels = []

        class OrchestrateurFactice:
            def __init__(self, config):
                self._tls = threading.local()

            def _rapporter_etape(self, numero, nom):
                pass

            def executer_attaque_complete(self, attaque):
                appels.append(attaque.id)
                return {"statut": "VALIDE", "id": attaque.id}

            def _generer_rapports_fin_cycle(self):
                pass

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurFactice)
        attaque = catalogue_actif()[0]
        etat = EtatCycle()
        demarrer_attaque_unique({"repertoire_rapports": tmp_path}, etat, attaque, mode="reel")
        _attendre_fin(etat)
        assert appels == [attaque.id]

    def test_refuse_si_deja_en_cours(self, tmp_path, monkeypatch):
        from cadre.catalogue_attaques import catalogue_actif

        appels = []
        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE",
            lambda config: appels.append("appelé"),
        )
        attaque = catalogue_actif()[0]
        etat = EtatCycle()
        etat.demarrer("simulation")  # simule un cycle déjà actif
        resultat = demarrer_attaque_unique({"repertoire_rapports": tmp_path}, etat, attaque)
        assert resultat is False
        assert appels == []

    def test_erreur_est_capturee(self, tmp_path, monkeypatch):
        """Une exception inattendue (pas une collision de verrou F-009) ne
        doit JAMAIS exposer son message brut via /api/cycle/statut -- même
        discipline log-only que /api/secrets, /api/revue/approuver,
        /api/export-sigma (voir TestVerrouCycleInterProcessus ci-dessous
        pour le cas VerrouCycleActifError, seul cas où le message brut est
        sûr et bien affiché tel quel)."""
        from cadre.catalogue_attaques import catalogue_actif

        class OrchestrateurQuiExplose:
            def __init__(self, config):
                self._tls = threading.local()

            def _rapporter_etape(self, numero, nom):
                pass

            def _executer_attaque_simulation(self, attaque):
                raise RuntimeError("boom (détail interne, ex. chemin serveur)")

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurQuiExplose)
        attaque = catalogue_actif()[0]
        etat = EtatCycle()
        demarrer_attaque_unique({"repertoire_rapports": tmp_path}, etat, attaque)
        _attendre_fin(etat)
        erreur = etat.snapshot()["erreur"]
        assert "boom" not in erreur  # détail interne jamais exposé
        assert "voir journaux serveur" in erreur


class TestDemarrerAttaqueUniqueVerrouInterProcessus:
    """F-009 : demarrer_attaque_unique() réplique `cadre cycle --id` mais
    passait par `etat` (EtatCycle), qui n'exclut qu'À L'INTÉRIEUR du
    processus dashboard -- jamais contre un `cadre cycle`/`cadre decouvrir`
    réel lancé en parallèle dans un autre processus, le scénario que F-009
    doit empêcher. Le docstring affirmait à tort cette garantie depuis le
    début (jamais vraie avant ce correctif).

    `_verrou_isole` : fixture globale autouse (conftest.py) -- plus besoin
    de la redéclarer ici."""

    def test_mode_reel_acquiert_puis_libere_le_verrou(self, tmp_path, monkeypatch, _verrou_isole):
        from cadre.catalogue_attaques import catalogue_actif

        class OrchestrateurFactice:
            def __init__(self, config):
                self._tls = threading.local()

            def _rapporter_etape(self, numero, nom):
                pass

            def executer_attaque_complete(self, attaque):
                return {"statut": "VALIDE", "id": attaque.id}

            def _generer_rapports_fin_cycle(self):
                pass

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurFactice)
        attaque = catalogue_actif()[0]
        etat = EtatCycle()
        demarrer_attaque_unique({"repertoire_rapports": tmp_path}, etat, attaque, mode="reel")
        _attendre_fin(etat)
        assert etat.snapshot()["erreur"] is None
        assert not _verrou_isole.exists()  # libéré, jamais laissé traîner

    def test_mode_reel_refuse_si_deja_verrouille_par_un_autre_processus(
        self, tmp_path, monkeypatch, _verrou_isole
    ):
        from cadre.catalogue_attaques import catalogue_actif

        appels = []
        monkeypatch.setattr(
            "cadre.orchestrateur.OrchestrateurCADRE",
            lambda config: appels.append("appelé"),
        )
        _verrou_isole.write_text(str(os.getpid()), encoding="utf-8")  # notre PID = vivant, garanti
        attaque = catalogue_actif()[0]
        etat = EtatCycle()
        demarrer_attaque_unique({"repertoire_rapports": tmp_path}, etat, attaque, mode="reel")
        _attendre_fin(etat)
        assert "déjà en cours" in etat.snapshot()["erreur"]
        assert appels == []  # verrou refusé avant toute construction de l'orchestrateur
        assert _verrou_isole.exists()  # le verrou pré-existant (pas le nôtre) reste en place

    def test_mode_simulation_n_est_jamais_bloque_par_un_verrou_existant(
        self, tmp_path, monkeypatch, _verrou_isole
    ):
        from cadre.catalogue_attaques import catalogue_actif

        class OrchestrateurFactice:
            def __init__(self, config):
                self._tls = threading.local()

            def _rapporter_etape(self, numero, nom):
                pass

            def _executer_attaque_simulation(self, attaque):
                return {"statut": "SIMULE", "id": attaque.id}

            def _generer_rapports_fin_cycle(self):
                pass

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurFactice)
        _verrou_isole.write_text(str(os.getpid()), encoding="utf-8")  # notre PID = vivant, garanti
        attaque = catalogue_actif()[0]
        etat = EtatCycle()
        demarrer_attaque_unique({"repertoire_rapports": tmp_path}, etat, attaque, mode="simulation")
        _attendre_fin(etat)
        assert etat.snapshot()["erreur"] is None  # jamais bloquée : la simulation ignore le verrou


_ENTREE_REVUE_EXEMPLE = {
    "rule_id_stable": "cadre-ia-042",
    "attaque_id": "CADRE-IA-042",
    "nom_regle": "Règle de test",
    "description": "Une description",
    "technique_mitre": "T1059.001",
    "severite": "medium",
    "index_pattern": "winlogbeat-*",
    "chemin_regle_sigma": "rules_generees/CADRE-IA-042.yml",
    "requete_lucene_derniere_validation": "event.code:1",
    "nb_tp": 3,
    "nb_fp": 1,
}


class TestRevueDashboard:
    """`lister_revues_dashboard`/`approuver_revue_dashboard`/
    `rejeter_revue_dashboard` : le dashboard peut déjà CRÉER une entrée de
    revue (Découverte IA, `revue: true`) mais n'offrait jusqu'ici aucun
    moyen de la lister/traiter sans `cadre revue` en CLI."""

    def test_lister_revues_vide_par_defaut(self, tmp_path, monkeypatch):
        import cadre.revue_regles as rr

        monkeypatch.setattr(rr, "CHEMIN_REVUES", tmp_path / "revues.json")
        assert lister_revues_dashboard() == []

    def test_lister_revues_retourne_les_entrees_enregistrees(self, tmp_path, monkeypatch):
        import cadre.revue_regles as rr

        monkeypatch.setattr(rr, "CHEMIN_REVUES", tmp_path / "revues.json")
        rr.enregistrer_revue(_ENTREE_REVUE_EXEMPLE)
        entrees = lister_revues_dashboard()
        assert len(entrees) == 1
        assert entrees[0]["rule_id_stable"] == "cadre-ia-042"

    def test_approuver_revue_inconnue_retourne_trouve_false(self, tmp_path, monkeypatch):
        import cadre.revue_regles as rr

        monkeypatch.setattr(rr, "CHEMIN_REVUES", tmp_path / "revues.json")
        resultat = approuver_revue_dashboard({}, "n-existe-pas")
        assert resultat == {"trouve": False}

    def test_approuver_revue_deploie_et_retire_l_entree(self, tmp_path, monkeypatch):
        import cadre.revue_regles as rr

        monkeypatch.setattr(rr, "CHEMIN_REVUES", tmp_path / "revues.json")
        rr.enregistrer_revue(_ENTREE_REVUE_EXEMPLE)

        class OrchestrateurFactice:
            def __init__(self, config):
                pass

            def approuver_revue(self, entree, forcer=False):
                assert entree["rule_id_stable"] == "cadre-ia-042"
                assert forcer is False
                return {
                    "deploye": True,
                    "force": False,
                    "nb_tp": 3,
                    "nb_fp": 1,
                    "statut": "VALIDE",
                    "raison": "OK",
                }

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurFactice)
        resultat = approuver_revue_dashboard({}, "cadre-ia-042")
        assert resultat["trouve"] is True
        assert resultat["deploye"] is True
        # Déployée -> retirée de la file, comme `cadre revue approuver`.
        assert lister_revues_dashboard() == []

    def test_approuver_revue_echec_garde_l_entree_en_attente(self, tmp_path, monkeypatch):
        import cadre.revue_regles as rr

        monkeypatch.setattr(rr, "CHEMIN_REVUES", tmp_path / "revues.json")
        rr.enregistrer_revue(_ENTREE_REVUE_EXEMPLE)

        class OrchestrateurFactice:
            def __init__(self, config):
                pass

            def approuver_revue(self, entree, forcer=False):
                return {
                    "deploye": False,
                    "force": False,
                    "nb_tp": 0,
                    "nb_fp": 0,
                    "statut": "ERREUR",
                    "raison": "YAML invalide",
                }

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurFactice)
        resultat = approuver_revue_dashboard({}, "cadre-ia-042")
        assert resultat["deploye"] is False
        # Pas déployée -> reste en attente, l'opérateur peut corriger et réessayer.
        assert len(lister_revues_dashboard()) == 1

    def test_rejeter_revue_connue_retire_l_entree(self, tmp_path, monkeypatch):
        import cadre.revue_regles as rr

        monkeypatch.setattr(rr, "CHEMIN_REVUES", tmp_path / "revues.json")
        rr.enregistrer_revue(_ENTREE_REVUE_EXEMPLE)
        assert rejeter_revue_dashboard("cadre-ia-042") is True
        assert lister_revues_dashboard() == []

    def test_rejeter_revue_inconnue_retourne_false(self, tmp_path, monkeypatch):
        import cadre.revue_regles as rr

        monkeypatch.setattr(rr, "CHEMIN_REVUES", tmp_path / "revues.json")
        assert rejeter_revue_dashboard("n-existe-pas") is False


class TestRaffinerAttaqueDashboard:
    def test_attaque_introuvable_retourne_erreur(self):
        resultat = raffiner_attaque_dashboard("N-EXISTE-PAS", valeur_detection="x")
        assert "erreur" in resultat

    def test_sans_champ_retourne_erreur(self):
        from cadre.catalogue_attaques import CATALOGUE

        resultat = raffiner_attaque_dashboard(CATALOGUE[0].id)
        assert "erreur" in resultat

    def test_valeur_detection_enregistree(self, tmp_path, monkeypatch):
        import cadre.raffinement as raf
        from cadre.catalogue_attaques import CATALOGUE

        monkeypatch.setattr(raf, "CHEMIN_RAFFINEMENTS", tmp_path / "raffinements.json")
        attaque_id = CATALOGUE[0].id
        resultat = raffiner_attaque_dashboard(attaque_id, valeur_detection="nouvelle-valeur")
        assert resultat == {"enregistre": True}
        assert raf.charger_raffinements(tmp_path / "raffinements.json")[attaque_id] == {
            "valeur_detection": "nouvelle-valeur"
        }

    def test_seuil_fp_invalide_retourne_erreur(self, tmp_path, monkeypatch):
        import cadre.raffinement as raf
        from cadre.catalogue_attaques import CATALOGUE

        monkeypatch.setattr(raf, "CHEMIN_RAFFINEMENTS", tmp_path / "raffinements.json")
        resultat = raffiner_attaque_dashboard(CATALOGUE[0].id, seuil_fp_max=-5)
        assert "erreur" in resultat

    def test_reinitialiser_retire_le_raffinement(self, tmp_path, monkeypatch):
        import cadre.raffinement as raf
        from cadre.catalogue_attaques import CATALOGUE

        monkeypatch.setattr(raf, "CHEMIN_RAFFINEMENTS", tmp_path / "raffinements.json")
        attaque_id = CATALOGUE[0].id
        raffiner_attaque_dashboard(attaque_id, valeur_detection="x")
        resultat = raffiner_attaque_dashboard(attaque_id, reinitialiser=True)
        assert resultat == {"retire": True}
        assert raf.charger_raffinements(tmp_path / "raffinements.json") == {}


class TestExporterSigmaDashboard:
    def test_exporte_toutes_les_regles(self, tmp_path):
        from cadre.catalogue_attaques import CATALOGUE

        resultat = exporter_sigma_dashboard(str(tmp_path / "export"))
        assert resultat["nb"] == len(CATALOGUE)
        assert list((tmp_path / "export").glob("*.yml"))


class _OrchestrateurRegleFactice:
    """Fake minimal pour lire_regle_dashboard/preparer_edition_regle_dashboard/
    pousser_regle_dashboard -- ne parle jamais réellement à Kibana."""

    donnees_kibana: ClassVar[dict[str, dict]] = {}
    genere_appels: ClassVar[list] = []
    redeployer_appels: ClassVar[list] = []
    redeployer_resultat: ClassVar[dict] = {
        "deploye": True,
        "nb_tp": 1,
        "nb_fp": 0,
        "raison": "ok",
        "force": False,
    }

    def __init__(self, config):
        self.config = config

    def lire_regle_kibana(self, rule_id):
        return self.donnees_kibana.get(rule_id)

    def generer_regle_sigma_depuis_attaque(self, attaque, _log):
        self.genere_appels.append(attaque.id)
        return f"title: Régénérée pour {attaque.id}\n"

    def redeployer_regle_editee(
        self, rule_id, regle_sigma_yaml, pipeline="ecs_windows", forcer=False
    ):
        self.redeployer_appels.append((rule_id, regle_sigma_yaml, pipeline, forcer))
        return self.redeployer_resultat


class TestLireRegleDashboard:
    def test_introuvable_dans_kibana_retourne_erreur(self, monkeypatch):
        monkeypatch.setattr(_OrchestrateurRegleFactice, "donnees_kibana", {})
        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", _OrchestrateurRegleFactice)
        resultat = lire_regle_dashboard({}, "CADRE-CRE-006")
        assert "erreur" in resultat

    def test_trouvee_retourne_les_donnees(self, monkeypatch):
        monkeypatch.setattr(
            _OrchestrateurRegleFactice,
            "donnees_kibana",
            {"CADRE-CRE-006": {"name": "Brute Force", "enabled": True}},
        )
        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", _OrchestrateurRegleFactice)
        resultat = lire_regle_dashboard({}, "CADRE-CRE-006")
        assert resultat == {"trouve": True, "regle": {"name": "Brute Force", "enabled": True}}


class TestPreparerEditionRegleDashboard:
    def test_introuvable_dans_kibana_retourne_erreur(self, monkeypatch):
        monkeypatch.setattr(_OrchestrateurRegleFactice, "donnees_kibana", {})
        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", _OrchestrateurRegleFactice)
        resultat = preparer_edition_regle_dashboard({}, "CADRE-CRE-006")
        assert "erreur" in resultat

    def test_fichier_existant_est_relu_sans_regeneration(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            _OrchestrateurRegleFactice, "donnees_kibana", {"CADRE-CRE-006": {"name": "x"}}
        )
        monkeypatch.setattr(_OrchestrateurRegleFactice, "genere_appels", [])
        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", _OrchestrateurRegleFactice)
        fichier = tmp_path / "regle.yml"
        fichier.write_text("title: déjà là\n", encoding="utf-8")
        resultat = preparer_edition_regle_dashboard(
            {"repertoire_regles": tmp_path}, "CADRE-CRE-006", fichier=str(fichier)
        )
        assert resultat["contenu"] == "title: déjà là\n"
        assert resultat["chemin"] == str(fichier)
        assert _OrchestrateurRegleFactice.genere_appels == []

    def test_fichier_absent_genere_depuis_le_catalogue(self, tmp_path, monkeypatch):
        from cadre.catalogue_attaques import CATALOGUE

        attaque_id = CATALOGUE[0].id
        monkeypatch.setattr(
            _OrchestrateurRegleFactice, "donnees_kibana", {attaque_id: {"name": "x"}}
        )
        monkeypatch.setattr(_OrchestrateurRegleFactice, "genere_appels", [])
        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", _OrchestrateurRegleFactice)
        fichier = tmp_path / "regle.yml"
        resultat = preparer_edition_regle_dashboard(
            {"repertoire_regles": tmp_path}, attaque_id, fichier=str(fichier)
        )
        assert fichier.is_file()
        assert f"Régénérée pour {attaque_id}" in resultat["contenu"]
        assert _OrchestrateurRegleFactice.genere_appels == [attaque_id]

    def test_fichier_absent_et_hors_catalogue_retourne_erreur(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            _OrchestrateurRegleFactice, "donnees_kibana", {"CADRE-PERSO-INEXISTANT": {"name": "x"}}
        )
        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", _OrchestrateurRegleFactice)
        resultat = preparer_edition_regle_dashboard(
            {"repertoire_regles": tmp_path},
            "CADRE-PERSO-INEXISTANT",
            fichier=str(tmp_path / "absent.yml"),
        )
        assert "erreur" in resultat

    def test_chemin_invalide_retourne_erreur_sans_planter(self, tmp_path, monkeypatch):
        """Régression : `fichier` est un chemin fourni par le client -- un
        chemin invalide (ici : un composant de chemin qui est un FICHIER,
        pas un dossier, donc impossible à traverser) levait un OSError non
        rattrapé au lieu d'un {"erreur": ...} propre.

        Régression sécurité (fuite d'info) : le message d'erreur interpolait
        `str(OSError)` tel quel, qui inclut le chemin absolu serveur --
        exposé sans filtrage côté dashboard JS (`outils.js`/`revue.js`/...).
        Vérifié ici via les marqueurs internes du système ("WinError"/
        "Errno") plutôt qu'une correspondance exacte du chemin : sur
        Windows, `str(OSError)` peut échapper les antislashs différemment
        de `str(Path)`, rendant une comparaison de sous-chaîne peu fiable
        -- mais un message générique ne contient JAMAIS ces marqueurs."""
        monkeypatch.setattr(
            _OrchestrateurRegleFactice, "donnees_kibana", {"CADRE-CRE-006": {"name": "x"}}
        )
        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", _OrchestrateurRegleFactice)
        bloqueur = tmp_path / "bloqueur"
        bloqueur.write_text("je suis un fichier, pas un dossier", encoding="utf-8")
        fichier_impossible = bloqueur / "sous-dossier" / "regle.yml"
        resultat = preparer_edition_regle_dashboard(
            {"repertoire_regles": tmp_path}, "CADRE-CRE-006", fichier=str(fichier_impossible)
        )
        assert "erreur" in resultat
        assert "WinError" not in resultat["erreur"]
        assert "Errno" not in resultat["erreur"]
        assert bloqueur.name not in resultat["erreur"]

    def test_fichier_hors_repertoire_regles_est_rejete(self, tmp_path, monkeypatch):
        """Régression sécurité : `fichier` (fourni par le client HTTP,
        contrairement au `--fichier` de la CLI où l'opérateur est de
        confiance) était utilisé tel quel, SANS aucune contrainte -- un
        `fichier` pointant n'importe où sur le disque du serveur permettait
        une lecture arbitraire. Rejeté avant toute tentative de lecture."""
        monkeypatch.setattr(
            _OrchestrateurRegleFactice, "donnees_kibana", {"CADRE-CRE-006": {"name": "x"}}
        )
        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", _OrchestrateurRegleFactice)
        repertoire_regles = tmp_path / "rules_generees"
        repertoire_regles.mkdir()
        ailleurs = tmp_path / "ailleurs" / "secret.txt"
        ailleurs.parent.mkdir()
        ailleurs.write_text("contenu hors sandbox", encoding="utf-8")
        resultat = preparer_edition_regle_dashboard(
            {"repertoire_regles": repertoire_regles}, "CADRE-CRE-006", fichier=str(ailleurs)
        )
        assert "erreur" in resultat
        assert "contenu" not in resultat  # jamais lu

    def test_rule_id_avec_traversal_est_rejete(self, tmp_path, monkeypatch):
        """Régression sécurité : sans `fichier`, le chemin par défaut était
        `repertoire_regles / f"{rule_id.upper()}.yml"` -- `rule_id` n'était
        jamais validé, un identifiant du type "../evil" pouvait donc
        construire un chemin hors de `repertoire_regles`. Un fichier RÉEL
        est placé à la cible de l'évasion : sans validation, `.is_file()`
        suit correctement les ".." (aucun `.resolve()` requis pour ça) et
        son contenu aurait fuité dans la réponse -- une variante qui ne
        placerait pas de fichier réel "réussirait" aussi sur l'ancien code
        (juste une erreur "hors catalogue" différente), sans rien prouver."""
        monkeypatch.setattr(
            _OrchestrateurRegleFactice, "donnees_kibana", {"../evil": {"name": "x"}}
        )
        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", _OrchestrateurRegleFactice)
        repertoire_regles = tmp_path / "rules_generees"
        repertoire_regles.mkdir()
        (tmp_path / "EVIL.yml").write_text("contenu confidentiel", encoding="utf-8")
        resultat = preparer_edition_regle_dashboard(
            {"repertoire_regles": repertoire_regles}, "../evil"
        )
        assert "erreur" in resultat
        assert "contenu" not in resultat  # jamais lu


class TestPousserRegleDashboard:
    def test_ecrit_le_fichier_et_delegue_a_l_orchestrateur(self, tmp_path, monkeypatch):
        monkeypatch.setattr(_OrchestrateurRegleFactice, "redeployer_appels", [])
        monkeypatch.setattr(
            _OrchestrateurRegleFactice,
            "redeployer_resultat",
            {"deploye": True, "nb_tp": 2, "nb_fp": 0, "raison": "ok", "force": False},
        )
        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", _OrchestrateurRegleFactice)
        fichier = tmp_path / "regle.yml"
        resultat = pousser_regle_dashboard(
            {"repertoire_regles": tmp_path},
            "CADRE-CRE-006",
            "title: édité\n",
            fichier=str(fichier),
            pipeline="aucun",
            forcer=True,
        )
        assert resultat["deploye"] is True
        assert fichier.read_text(encoding="utf-8") == "title: édité\n"
        assert _OrchestrateurRegleFactice.redeployer_appels == [
            ("CADRE-CRE-006", "title: édité\n", "aucun", True)
        ]

    def test_chemin_invalide_retourne_deploye_false_sans_planter(self, tmp_path, monkeypatch):
        """Régression : même raisonnement que
        TestPreparerEditionRegleDashboard.test_chemin_invalide -- mais ici
        la route lit resultat["deploye"] sans garde, donc la forme de
        retour en cas d'erreur doit rester compatible (deploye=False), pas
        juste {"erreur": ...}.

        Régression sécurité (fuite d'info) : même raisonnement que
        TestPreparerEditionRegleDashboard -- `raison` ne doit jamais
        exposer les marqueurs d'erreur système internes (voir cette
        classe pour la raison du choix de marqueurs plutôt qu'un chemin
        littéral)."""
        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", _OrchestrateurRegleFactice)
        bloqueur = tmp_path / "bloqueur"
        bloqueur.write_text("je suis un fichier, pas un dossier", encoding="utf-8")
        fichier_impossible = bloqueur / "sous-dossier" / "regle.yml"
        resultat = pousser_regle_dashboard(
            {"repertoire_regles": tmp_path},
            "CADRE-CRE-006",
            "title: x\n",
            fichier=str(fichier_impossible),
        )
        assert resultat["deploye"] is False
        assert "erreur" in resultat.get("raison", "").lower() or resultat["statut"] == "ERREUR"
        assert "WinError" not in resultat["raison"]
        assert "Errno" not in resultat["raison"]
        assert bloqueur.name not in resultat["raison"]

    def test_fichier_hors_repertoire_regles_est_rejete_sans_ecrire(self, tmp_path, monkeypatch):
        """Régression sécurité (RCE) : `fichier` n'était contraint à aucun
        répertoire -- `contenu_yaml` (fourni par le client) était écrit TEL
        QUEL au chemin fourni par le client, un chemin ARBITRAIRE (ex. un
        script de démarrage) permettait donc une écriture de fichier
        arbitraire sur le serveur. Vérifié ici : le fichier hors sandbox
        n'est jamais créé/modifié."""
        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", _OrchestrateurRegleFactice)
        repertoire_regles = tmp_path / "rules_generees"
        repertoire_regles.mkdir()
        cible_malicieuse = tmp_path / "ailleurs" / "payload.txt"
        resultat = pousser_regle_dashboard(
            {"repertoire_regles": repertoire_regles},
            "CADRE-CRE-006",
            "contenu malicieux",
            fichier=str(cible_malicieuse),
        )
        assert resultat["deploye"] is False
        assert not cible_malicieuse.exists()  # jamais écrit


class TestApercuAtomicDashboard:
    """`importer_atomics()` est pure (lecture disque + filtre, jamais de
    réseau ni de VM) -- ces tests l'exercent réellement sur le jeu
    d'exemples embarqué, comme test_atomic_red_team.py."""

    def test_repertoire_invalide_retourne_erreur(self, tmp_path):
        resultat = apercu_atomic_dashboard(repo=str(tmp_path / "n-existe-pas"))
        assert "erreur" in resultat

    def test_plateforme_invalide_retourne_erreur(self):
        resultat = apercu_atomic_dashboard(platform="macos")
        assert "erreur" in resultat

    def test_jeu_embarque_par_defaut(self):
        resultat = apercu_atomic_dashboard()
        assert resultat["total_lus"] > 0
        assert "retenus" in resultat and "refuses" in resultat

    def test_filtre_par_technique(self):
        resultat = apercu_atomic_dashboard(techniques=["T1082"])
        assert all(b["technique_mitre"] == "T1082" for b in resultat["retenus"])


class TestImporterAtomicDashboard:
    def test_persiste_les_retenus_au_catalogue_perso(self, tmp_path, monkeypatch):
        import cadre.catalogue_utilisateur as cu

        monkeypatch.setattr(cu, "CHEMIN_CATALOGUE_PERSO", tmp_path / "perso.json")
        resultat = importer_atomic_dashboard(techniques=["T1082"])
        assert resultat["ajoutes"] > 0
        assert resultat["ajoutes"] == len(resultat["retenus"])
        ids_persistes = {a.id for a in cu.charger_attaques_utilisateur()}
        assert all(b["id"] in ids_persistes for b in resultat["retenus"])

    def test_reimport_compte_deja_presents(self, tmp_path, monkeypatch):
        import cadre.catalogue_utilisateur as cu

        monkeypatch.setattr(cu, "CHEMIN_CATALOGUE_PERSO", tmp_path / "perso.json")
        premier = importer_atomic_dashboard(techniques=["T1082"])
        second = importer_atomic_dashboard(techniques=["T1082"])
        assert second["ajoutes"] == 0
        assert second["deja_presents"] == len(premier["retenus"])


class TestValiderRegleDashboard:
    def test_delegue_a_valider_regle_sigma(self, monkeypatch):
        class OrchestrateurFactice:
            def __init__(self, config):
                self.config = {"elastic_url": "http://x:9200", "index_pattern": "winlogbeat-*"}
                self.auth_elastic = None

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurFactice)
        monkeypatch.setattr("cadre.validation_regle.compter_evenements", lambda *a, **k: 3)
        regle_yaml = (
            "title: Test\n"
            "id: 11111111-1111-1111-1111-111111111111\n"
            "status: experimental\n"
            "logsource:\n  category: process_creation\n  product: windows\n"
            "detection:\n  selection:\n    event.code: '1'\n  condition: selection\n"
            "level: medium\n"
        )
        resultat = valider_regle_dashboard({}, regle_yaml, jours=3, seuil=100)
        assert resultat["verdict"] == "ACTIVE"
        assert resultat["hits"] == 3


class TestDemarrerDecouverte:
    """`demarrer_decouverte` prend désormais UNE description fournie par
    l'utilisateur (plus de liste figée `_INTENTIONS_DECOUVERTE`)."""

    def test_appelle_decouvrir_attaques_avec_une_seule_description(self, tmp_path, monkeypatch):
        from cadre.dashboard import EtatDecouverte, demarrer_decouverte

        appels = []

        class OrchestrateurFactice:
            def __init__(self, config):
                appels.append(("config", config))

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurFactice)

        def decouvrir_factice(orchestrateur, descriptions, techniques=None, revue=False):
            appels.append((descriptions, techniques, revue))
            return {"decouvertes": [], "refusees": [], "echecs": []}

        monkeypatch.setattr("cadre.decouverte_ia.decouvrir_attaques", decouvrir_factice)

        etat = EtatDecouverte()
        config = {"repertoire_rapports": tmp_path}
        assert (
            demarrer_decouverte(config, etat, "Énumérer X", technique="T1059", revue=True) is True
        )
        _attendre_fin(etat)
        assert appels[1] == (["Énumérer X"], ["T1059"], True)
        assert etat.snapshot()["resultat"] == {"decouvertes": [], "refusees": [], "echecs": []}

    def test_technique_absente_ne_construit_pas_de_liste(self, tmp_path, monkeypatch):
        from cadre.dashboard import EtatDecouverte, demarrer_decouverte

        appels = []
        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", lambda config: None)

        def decouvrir_factice(orchestrateur, descriptions, techniques=None, revue=False):
            appels.append(techniques)
            return {"decouvertes": [], "refusees": [], "echecs": []}

        monkeypatch.setattr("cadre.decouverte_ia.decouvrir_attaques", decouvrir_factice)
        etat = EtatDecouverte()
        demarrer_decouverte({"repertoire_rapports": tmp_path}, etat, "desc")
        _attendre_fin(etat)
        assert appels == [None]

    def test_refuse_si_deja_en_cours(self, tmp_path):
        from cadre.dashboard import EtatDecouverte, demarrer_decouverte

        etat = EtatDecouverte()
        etat.demarrer()
        assert demarrer_decouverte({}, etat, "desc") is False

    def test_erreur_pendant_la_decouverte_est_capturee(self, tmp_path, monkeypatch):
        """Une exception inattendue (pas une collision de verrou F-009) ne
        doit JAMAIS exposer son message brut via /api/decouverte/statut --
        même discipline log-only que /api/secrets, /api/revue/approuver,
        /api/export-sigma."""
        from cadre.dashboard import EtatDecouverte, demarrer_decouverte

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", lambda config: None)

        def decouvrir_qui_explose(*a, **k):
            raise RuntimeError("Ollama injoignable (détail interne)")

        monkeypatch.setattr("cadre.decouverte_ia.decouvrir_attaques", decouvrir_qui_explose)
        etat = EtatDecouverte()
        demarrer_decouverte({}, etat, "desc")
        _attendre_fin(etat)
        erreur = etat.snapshot()["erreur"]
        assert "injoignable" not in erreur  # détail interne jamais exposé
        assert "voir journaux serveur" in erreur

    def test_collision_de_verrou_expose_le_message_tel_quel(self, tmp_path, monkeypatch):
        """VerrouCycleActifError (F-009) est un cas à part : contrairement à
        une exception arbitraire, son message est rédigé par CADRE lui-même
        et sûr à afficher tel quel (pas de détail interne)."""
        from cadre.dashboard import EtatDecouverte, demarrer_decouverte
        from cadre.orchestrateur import VerrouCycleActifError

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", lambda config: None)

        def decouvrir_qui_collisionne(*a, **k):
            raise VerrouCycleActifError("Un autre cycle réel est déjà en cours (PID 4242)")

        monkeypatch.setattr("cadre.decouverte_ia.decouvrir_attaques", decouvrir_qui_collisionne)
        etat = EtatDecouverte()
        demarrer_decouverte({}, etat, "desc")
        _attendre_fin(etat)
        assert etat.snapshot()["erreur"] == "Un autre cycle réel est déjà en cours (PID 4242)"


def _attendre_fin(etat, timeout_iterations=50):
    for _ in range(timeout_iterations):
        if not etat.snapshot()["en_cours"]:
            return
        time.sleep(0.05)


@pytest.fixture
def serveur_test(tmp_path, monkeypatch):
    """Serveur HTTP réel sur 127.0.0.1, port OS-assigné, dans un thread démon."""
    monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", lambda config: None)

    from cadre.dashboard import EtatDecouverte

    etat = EtatCycle()
    config_orchestrateur = {"repertoire_rapports": tmp_path, "repertoire_regles": tmp_path}
    gestionnaire = creer_gestionnaire(
        tmp_path, tmp_path / "cadre.log.json", config_orchestrateur, etat, EtatDecouverte()
    )
    # ThreadingHTTPServer (pas HTTPServer) : même classe que lancer_dashboard()
    # en production -- exerce le même modèle de concurrence dans ces tests.
    serveur = ThreadingHTTPServer(("127.0.0.1", 0), gestionnaire)
    thread = threading.Thread(target=serveur.serve_forever, daemon=True)
    thread.start()
    port = serveur.server_address[1]
    yield f"http://127.0.0.1:{port}", tmp_path
    serveur.shutdown()
    serveur.server_close()
    thread.join(timeout=2)


def _post_json(url, payload):
    """Petit helper : POST JSON via urllib, retourne (status_ou_code_erreur, data)."""
    import urllib.error

    data_brute = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data_brute,
        # X-CADRE-Local : en-tête custom exigé par le garde-fou CSRF (comme le
        # fait le frontend). Sans lui, toute action POST est refusée (403).
        headers={"Content-Type": "application/json", "X-CADRE-Local": "1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        data = json.loads(e.read())
        code = e.code
        e.close()
        return code, data


def _get_json_local(url):
    """GET avec l'en-tête X-CADRE-Local (comme le fait le frontend, `apiGet`
    dans api.js) -- requis par les routes GET à effet de bord (ex.
    /api/regle/<id>/editer). Retourne (status_ou_code_erreur, data)."""
    req = urllib.request.Request(url, headers={"X-CADRE-Local": "1"}, method="GET")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        data = json.loads(e.read())
        code = e.code
        e.close()
        return code, data


class TestLireCorpsJson:
    """`_lire_corps_json` est le point d'entrée partagé par TOUTES les
    routes POST -- une entrée invalide ici doit toujours dégrader vers
    `{}`, jamais laisser une exception remonter."""

    def test_content_length_non_numerique_retourne_dict_vide(self):
        from cadre.dashboard import _lire_corps_json

        class HandlerFactice:
            headers: ClassVar = {"Content-Length": "abc"}
            rfile = None

        assert _lire_corps_json(HandlerFactice()) == {}

    def test_content_length_absent_retourne_dict_vide(self):
        from cadre.dashboard import _lire_corps_json

        class HandlerFactice:
            headers: ClassVar = {}
            rfile = None

        assert _lire_corps_json(HandlerFactice()) == {}


class TestServeurHTTP:
    def test_page_accueil_repond_200(self, serveur_test):
        base_url, _ = serveur_test
        with urllib.request.urlopen(f"{base_url}/") as r:
            assert r.status == 200
            assert b"CADRE" in r.read()

    def test_api_cycles_repond_json(self, serveur_test):
        base_url, _ = serveur_test
        with urllib.request.urlopen(f"{base_url}/api/cycles") as r:
            data = json.loads(r.read())
            assert data == {"cycles": []}

    def test_api_cycle_dernier_repond_json(self, serveur_test):
        base_url, repertoire = serveur_test
        with urllib.request.urlopen(f"{base_url}/api/cycle/dernier") as r:
            assert json.loads(r.read()) == {"cycle": None}
        _ecrire_cycle_csv(repertoire, "20260801_100000", LIGNES_EXEMPLE)
        with urllib.request.urlopen(f"{base_url}/api/cycle/dernier") as r:
            data = json.loads(r.read())
        assert data["cycle"]["horodatage"] == "20260801_100000"

    def test_api_cycles_detail_repond_json(self, serveur_test):
        """Régression couverture : detail_cycle() était testée en isolation
        (TestDetailCycle) mais jamais via une vraie requête HTTP -- le
        découpage d'URL (/api/cycles/<horodatage>) n'était jamais exercé
        de bout en bout."""
        base_url, repertoire = serveur_test
        _ecrire_cycle_csv(repertoire, "20260801_100000", LIGNES_EXEMPLE)
        with urllib.request.urlopen(f"{base_url}/api/cycles/20260801_100000") as r:
            data = json.loads(r.read())
        assert data["total"] == 2
        assert "VALIDE" in data["groupes"]

    def test_api_cycles_detail_inconnu_retourne_404(self, serveur_test):
        base_url, _ = serveur_test
        code, data = 0, None
        try:
            urllib.request.urlopen(f"{base_url}/api/cycles/20990101_000000")
        except urllib.error.HTTPError as e:
            code = e.code
            data = json.loads(e.read())
        assert code == 404
        assert "erreur" in data

    def test_rapports_index_repond_html(self, serveur_test):
        """Régression couverture : page_index_rapports() était testée en
        isolation (TestPageIndexRapports) mais jamais via une vraie requête
        HTTP sur /rapports ou /rapports/."""
        base_url, _ = serveur_test
        with urllib.request.urlopen(f"{base_url}/rapports") as r:
            assert r.status == 200
            assert r.headers.get("Content-Type", "").startswith("text/html")
            corps = r.read()
        with urllib.request.urlopen(f"{base_url}/rapports/") as r:
            assert r.status == 200
            assert r.read() == corps  # même page, avec ou sans le / final

    def test_api_catalogue_repond_json(self, serveur_test):
        from cadre.catalogue_attaques import CATALOGUE

        base_url, _ = serveur_test
        with urllib.request.urlopen(f"{base_url}/api/catalogue") as r:
            data = json.loads(r.read())
            assert len(data["attaques"]) == len(CATALOGUE)

    def test_api_stats_repond_json(self, serveur_test):
        from cadre.catalogue_attaques import CATALOGUE

        base_url, _ = serveur_test
        with urllib.request.urlopen(f"{base_url}/api/stats") as r:
            data = json.loads(r.read())
            assert data["total"] == len(CATALOGUE)
            assert "regles_similaires" in data
            assert isinstance(data["regles_similaires"], list)

    def test_api_matrice_repond_json(self, serveur_test):
        base_url, _ = serveur_test
        with urllib.request.urlopen(f"{base_url}/api/matrice") as r:
            data = json.loads(r.read())
            assert len(data["colonnes"]) == 14
            assert data["resume"]["techniques_couvertes"] > 0

    def test_api_metriques_vide_sans_cycle(self, serveur_test):
        base_url, _ = serveur_test
        with urllib.request.urlopen(f"{base_url}/api/metriques") as r:
            assert json.loads(r.read()) == {}

    def test_api_metriques_calcule_depuis_le_dernier_cycle(self, serveur_test):
        base_url, repertoire = serveur_test
        _ecrire_cycle_csv(
            repertoire,
            "20260802_120000",
            [
                {**LIGNES_EXEMPLE[0], "statut": "VALIDE", "nb_fp": 3},
                {**LIGNES_EXEMPLE[1], "statut": "VALIDE", "nb_fp": 5},
            ],
        )
        with urllib.request.urlopen(f"{base_url}/api/metriques") as r:
            m = json.loads(r.read())
        assert m["regles_produites"] == 2
        assert m["faux_positifs_median"] == 4.0

    def test_api_derive_vide_sans_historique(self, serveur_test):
        base_url, _ = serveur_test
        with urllib.request.urlopen(f"{base_url}/api/derive") as r:
            assert json.loads(r.read()) == {"derives": {}}

    def test_api_derive_calcule_depuis_les_cycles_archives(self, serveur_test):
        base_url, repertoire = serveur_test
        _ecrire_cycle_csv(
            repertoire,
            "20260801_100000",
            [{**LIGNES_EXEMPLE[0], "id": "CADRE-DIS-001", "statut": "VALIDE", "nb_fp": 5}],
        )
        _ecrire_cycle_csv(
            repertoire,
            "20260802_100000",
            [{**LIGNES_EXEMPLE[0], "id": "CADRE-DIS-001", "statut": "VALIDE", "nb_fp": 20}],
        )
        with urllib.request.urlopen(f"{base_url}/api/derive") as r:
            data = json.loads(r.read())
        assert data["derives"]["CADRE-DIS-001"]["statut"] == "DERIVE_BRUIT"
        assert data["derives"]["CADRE-DIS-001"]["nb_mesures"] == 2

    def test_api_secrets_get_retourne_le_statut(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr(
            "cadre.dashboard.statut_secrets",
            lambda: [{"cle": "CADRE_VM_PASS", "libelle": "x", "critique": True, "configure": True}],
        )
        with urllib.request.urlopen(f"{base_url}/api/secrets") as r:
            data = json.loads(r.read())
        assert data["secrets"][0]["cle"] == "CADRE_VM_PASS"
        assert data["secrets"][0]["configure"] is True

    def test_api_secrets_post_sans_valeur_retourne_400(self, serveur_test):
        base_url, _ = serveur_test
        code, data = _post_json(f"{base_url}/api/secrets", {"cle": "CADRE_VM_PASS"})
        assert code == 400
        assert "erreur" in data

    def test_api_secrets_post_valide(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.definir_secret", lambda cle, valeur: appels.append((cle, valeur))
        )
        code, data = _post_json(f"{base_url}/api/secrets", {"cle": "CADRE_VM_PASS", "valeur": "x"})
        assert code == 200
        assert data == {"defini": True}
        assert appels == [("CADRE_VM_PASS", "x")]

    def test_api_secrets_post_exception_retourne_400(self, serveur_test, monkeypatch):
        """Régression couverture : le bloc `except Exception` de cette route
        n'était jamais déclenché par aucun test."""
        base_url, _ = serveur_test

        def leve(cle, valeur):
            raise RuntimeError("coffre-fort indisponible")

        monkeypatch.setattr("cadre.dashboard.definir_secret", leve)
        code, data = _post_json(f"{base_url}/api/secrets", {"cle": "CADRE_VM_PASS", "valeur": "x"})
        assert code == 400
        assert "erreur" in data

    def test_api_revue_get_repond_json(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr(
            "cadre.dashboard.lister_revues_dashboard",
            lambda: [{"rule_id_stable": "cadre-ia-001"}],
        )
        with urllib.request.urlopen(f"{base_url}/api/revue") as r:
            data = json.loads(r.read())
        assert data["revues"][0]["rule_id_stable"] == "cadre-ia-001"

    def test_api_revue_approuver_sans_rule_id_retourne_400(self, serveur_test):
        base_url, _ = serveur_test
        code, data = _post_json(f"{base_url}/api/revue/approuver", {})
        assert code == 400
        assert "erreur" in data

    def test_api_revue_approuver_inconnue_retourne_404(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr(
            "cadre.dashboard.approuver_revue_dashboard",
            lambda config, rule_id, forcer=False: {"trouve": False},
        )
        code, data = _post_json(f"{base_url}/api/revue/approuver", {"rule_id": "n-existe-pas"})
        assert code == 404
        assert "erreur" in data

    def test_api_revue_approuver_deployee_retourne_200(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.approuver_revue_dashboard",
            lambda config, rule_id, forcer=False: appels.append((rule_id, forcer))
            or {"trouve": True, "deploye": True, "nb_tp": 2, "nb_fp": 0},
        )
        code, data = _post_json(f"{base_url}/api/revue/approuver", {"rule_id": "cadre-ia-001"})
        assert code == 200
        assert data["deploye"] is True
        assert appels == [("cadre-ia-001", False)]

    def test_api_revue_approuver_exception_retourne_400(self, serveur_test, monkeypatch):
        """Régression couverture : le bloc `except Exception` de cette route
        n'était jamais déclenché par aucun test."""
        base_url, _ = serveur_test

        def leve(config, rule_id, forcer=False):
            raise RuntimeError("Kibana injoignable")

        monkeypatch.setattr("cadre.dashboard.approuver_revue_dashboard", leve)
        code, data = _post_json(f"{base_url}/api/revue/approuver", {"rule_id": "cadre-ia-001"})
        assert code == 400
        assert "erreur" in data

    def test_api_revue_rejeter_sans_rule_id_retourne_400(self, serveur_test):
        base_url, _ = serveur_test
        code, data = _post_json(f"{base_url}/api/revue/rejeter", {})
        assert code == 400
        assert "erreur" in data

    def test_api_revue_rejeter_inconnue_retourne_404(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr("cadre.dashboard.rejeter_revue_dashboard", lambda rule_id: False)
        code, data = _post_json(f"{base_url}/api/revue/rejeter", {"rule_id": "n-existe-pas"})
        assert code == 404
        assert "erreur" in data

    def test_api_revue_rejeter_connue_retourne_200(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr("cadre.dashboard.rejeter_revue_dashboard", lambda rule_id: True)
        code, data = _post_json(f"{base_url}/api/revue/rejeter", {"rule_id": "cadre-ia-001"})
        assert code == 200
        assert data == {"rejete": True}

    def test_api_raffiner_sans_attaque_id_retourne_400(self, serveur_test):
        base_url, _ = serveur_test
        code, data = _post_json(f"{base_url}/api/raffiner", {})
        assert code == 400
        assert "erreur" in data

    def test_api_raffiner_attaque_introuvable_retourne_400(self, serveur_test):
        base_url, _ = serveur_test
        code, data = _post_json(
            f"{base_url}/api/raffiner", {"attaque_id": "N-EXISTE-PAS", "valeur_detection": "x"}
        )
        assert code == 400
        assert "erreur" in data

    def test_api_raffiner_valide_retourne_200(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.raffiner_attaque_dashboard",
            lambda attaque_id, valeur_detection=None, seuil_fp_max=None, reinitialiser=False: (
                appels.append((attaque_id, valeur_detection, seuil_fp_max, reinitialiser))
                or {"enregistre": True}
            ),
        )
        code, data = _post_json(
            f"{base_url}/api/raffiner", {"attaque_id": "CADRE-CRE-006", "valeur_detection": "x"}
        )
        assert code == 200
        assert data == {"enregistre": True}
        assert appels == [("CADRE-CRE-006", "x", None, False)]

    def test_api_export_sigma_ecrit_dans_le_repertoire_fourni(
        self, serveur_test, tmp_path, monkeypatch
    ):
        base_url, _ = serveur_test
        # `exporter_regles_sigma()` instancie un OrchestrateurCADRE() SANS
        # config (donc sans les répertoires isolés de `serveur_test`) : le
        # fake `lambda config: None` de la fixture ne convient pas ici (il
        # exige un argument). On restaure la vraie classe, ET on se place
        # dans tmp_path pour que ses mkdir() de répertoires par défaut
        # (rapports/, rules_generees/) n'écrivent jamais dans le vrai dépôt.
        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurCADREReelle)
        monkeypatch.chdir(tmp_path)
        # Le format "kibana" télécharge les données MITRE ATT&CK puis les met
        # en cache via pysigma/diskcache (sqlite) -- déjà couvert par
        # test_export_sigma.py. Ici, appelé depuis le thread serveur du
        # dashboard, la connexion sqlite est finalisée hors de son thread
        # d'origine (le thread serveur s'arrête avant le GC), ce que sqlite3
        # refuse : "unraisable exception" qui fait échouer la session pytest.
        # On ne teste que lucene/es-dsl (100% hors-ligne) ici ; le format
        # kibana reste vérifié séparément, dans le bon contexte d'exécution.
        import cadre.compilation_sigma as compilation_sigma_mod

        formats_hors_ligne = {
            k: v for k, v in compilation_sigma_mod.FORMATS_SORTIE.items() if k != "kibana"
        }
        monkeypatch.setattr("cadre.compilation_sigma.FORMATS_SORTIE", formats_hors_ligne)
        repertoire = tmp_path / "export_http"
        code, data = _post_json(f"{base_url}/api/export-sigma", {"output": str(repertoire)})
        assert code == 200
        assert data["nb"] > 0
        assert list(repertoire.glob("*.yml"))

    def test_api_export_sigma_erreur_retourne_400(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test

        def leve(output):
            raise RuntimeError("échec export")

        monkeypatch.setattr("cadre.dashboard.exporter_sigma_dashboard", leve)
        code, data = _post_json(f"{base_url}/api/export-sigma", {"output": "peu-importe"})
        assert code == 400
        assert "erreur" in data

    def test_api_regle_get_delegue_a_lire_regle_dashboard(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr(
            "cadre.dashboard.lire_regle_dashboard",
            lambda config, rule_id: {"trouve": True, "regle": {"name": rule_id}},
        )
        with urllib.request.urlopen(f"{base_url}/api/regle/CADRE-CRE-006") as r:
            data = json.loads(r.read())
        assert data == {"trouve": True, "regle": {"name": "CADRE-CRE-006"}}

    def test_api_regle_get_introuvable_retourne_404(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr(
            "cadre.dashboard.lire_regle_dashboard",
            lambda config, rule_id: {"erreur": "introuvable"},
        )
        code, data = 0, None
        try:
            urllib.request.urlopen(f"{base_url}/api/regle/N-EXISTE-PAS")
        except urllib.error.HTTPError as e:
            code = e.code
            data = json.loads(e.read())
        assert code == 404
        assert "erreur" in data

    def test_api_regle_editer_get_delegue_avec_le_fichier(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.preparer_edition_regle_dashboard",
            lambda config, rule_id, fichier=None: appels.append((rule_id, fichier))
            or {"trouve": True, "chemin": fichier, "contenu": "title: x\n"},
        )
        chemin_qs = urllib.parse.quote("C:/tmp/regle.yml", safe="")
        code, data = _get_json_local(
            f"{base_url}/api/regle/CADRE-CRE-006/editer?fichier={chemin_qs}"
        )
        assert code == 200
        assert data["contenu"] == "title: x\n"
        assert appels == [("CADRE-CRE-006", "C:/tmp/regle.yml")]

    def test_api_regle_editer_erreur_retourne_404(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr(
            "cadre.dashboard.preparer_edition_regle_dashboard",
            lambda config, rule_id, fichier=None: {"erreur": "introuvable dans Kibana"},
        )
        code, data = _get_json_local(f"{base_url}/api/regle/N-EXISTE-PAS/editer")
        assert code == 404
        assert "erreur" in data

    def test_api_regle_editer_sans_entete_local_retourne_403(self, serveur_test, monkeypatch):
        """Régression critique : cette route GET lit/écrit un fichier serveur
        à un chemin fourni par le client (`fichier=`) -- sans le garde-fou
        CSRF, une simple balise <img src="...regle/X/editer?fichier=..."> sur
        une page tierce suffirait à déclencher une lecture/écriture arbitraire
        pendant que le dashboard tourne, sans authentification (bind loopback
        par défaut)."""
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.preparer_edition_regle_dashboard",
            lambda config, rule_id, fichier=None: appels.append(1)
            or {"trouve": True, "chemin": fichier, "contenu": "title: x\n"},
        )
        # Requête SANS X-CADRE-Local (simule une <img>/requête tierce) : urlopen
        # nu, pas _get_json_local qui pose l'en-tête.
        code, data = 0, None
        try:
            urllib.request.urlopen(f"{base_url}/api/regle/CADRE-CRE-006/editer")
        except urllib.error.HTTPError as e:
            code = e.code
            data = json.loads(e.read())
        assert code == 403
        assert "erreur" in data
        assert appels == []  # la fonction à effet de bord n'a jamais été appelée

    def test_api_regle_pousser_sans_rule_id_retourne_400(self, serveur_test):
        base_url, _ = serveur_test
        code, data = _post_json(f"{base_url}/api/regle/pousser", {"contenu": "title: x\n"})
        assert code == 400
        assert "erreur" in data

    def test_api_regle_pousser_sans_contenu_retourne_400(self, serveur_test):
        base_url, _ = serveur_test
        code, data = _post_json(f"{base_url}/api/regle/pousser", {"rule_id": "CADRE-CRE-006"})
        assert code == 400
        assert "erreur" in data

    def test_api_regle_pousser_deploye_retourne_200(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.pousser_regle_dashboard",
            lambda config, rule_id, contenu, fichier=None, pipeline="ecs_windows", forcer=False: (
                appels.append((rule_id, contenu, fichier, pipeline, forcer))
                or {"deploye": True, "nb_tp": 3, "nb_fp": 0, "raison": "ok", "force": False}
            ),
        )
        code, data = _post_json(
            f"{base_url}/api/regle/pousser",
            {"rule_id": "CADRE-CRE-006", "contenu": "title: édité\n", "pipeline": "aucun"},
        )
        assert code == 200
        assert data["deploye"] is True
        assert appels == [("CADRE-CRE-006", "title: édité\n", None, "aucun", False)]

    def test_api_regle_pousser_non_deploye_retourne_400(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr(
            "cadre.dashboard.pousser_regle_dashboard",
            lambda config, rule_id, contenu, fichier=None, pipeline="ecs_windows", forcer=False: {
                "deploye": False,
                "statut": "REJETEE",
                "raison": "trop de faux positifs",
                "nb_tp": 0,
                "nb_fp": 9,
                "force": False,
            },
        )
        code, data = _post_json(
            f"{base_url}/api/regle/pousser",
            {"rule_id": "CADRE-CRE-006", "contenu": "title: édité\n"},
        )
        assert code == 400
        assert data["deploye"] is False

    def test_api_atomic_apercu_get_delegue(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.apercu_atomic_dashboard",
            lambda repo=None, platform=None, techniques=None: appels.append(
                (repo, platform, techniques)
            )
            or {"retenus": [], "refuses": [], "total_lus": 0},
        )
        code, data = _get_json_local(
            f"{base_url}/api/atomic/apercu?platform=windows&technique=T1082,T1055"
        )
        assert code == 200
        assert data == {"retenus": [], "refuses": [], "total_lus": 0}
        assert appels == [(None, "windows", ["T1082", "T1055"])]

    def test_api_atomic_apercu_erreur_retourne_400(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr(
            "cadre.dashboard.apercu_atomic_dashboard",
            lambda repo=None, platform=None, techniques=None: {"erreur": "répertoire introuvable"},
        )
        code, data = _get_json_local(f"{base_url}/api/atomic/apercu?repo=n-existe-pas")
        assert code == 400
        assert "erreur" in data

    def test_api_atomic_apercu_sans_entete_locale_refusee(self, serveur_test, monkeypatch):
        """Régression sécurité : /api/atomic/apercu (GET à effet de bord --
        parcourt un répertoire arbitraire) n'avait pas la même garde CSRF
        que /api/regle/<id>/editer, l'autre route GET de ce genre -- une
        simple balise <img> sur une page tierce suffisait à la déclencher
        sans authentification, en mode par défaut (bind loopback)."""
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.apercu_atomic_dashboard",
            lambda repo=None, platform=None, techniques=None: appels.append(1)
            or {"retenus": [], "refuses": [], "total_lus": 0},
        )
        # Requête SANS X-CADRE-Local (simule une <img>/requête tierce) : urlopen
        # nu, pas _get_json_local qui pose l'en-tête.
        code, data = 0, None
        try:
            urllib.request.urlopen(f"{base_url}/api/atomic/apercu")
        except urllib.error.HTTPError as e:
            code = e.code
            data = json.loads(e.read())
        assert code == 403
        assert "erreur" in data
        assert appels == []  # la fonction à effet de bord n'a jamais été appelée

    def test_api_atomic_importer_delegue(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.importer_atomic_dashboard",
            lambda repo=None, platform=None, techniques=None: appels.append(
                (repo, platform, techniques)
            )
            or {"retenus": [], "refuses": [], "total_lus": 0, "ajoutes": 0, "deja_presents": 0},
        )
        code, data = _post_json(
            f"{base_url}/api/atomic/importer", {"techniques": ["T1082"], "platform": "windows"}
        )
        assert code == 200
        assert data["ajoutes"] == 0
        assert appels == [(None, "windows", ["T1082"])]

    def test_api_atomic_importer_erreur_retourne_400(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr(
            "cadre.dashboard.importer_atomic_dashboard",
            lambda repo=None, platform=None, techniques=None: {"erreur": "plateforme inconnue"},
        )
        code, data = _post_json(f"{base_url}/api/atomic/importer", {"platform": "macos"})
        assert code == 400
        assert "erreur" in data

    def test_api_atomic_importer_techniques_non_liste_retourne_400(self, serveur_test):
        """Régression : `techniques="T1110"` (chaîne au lieu de liste) est
        itérable caractère par caractère en Python -- silencieusement
        transformé en liste de lettres au lieu d'être rejeté proprement."""
        base_url, _ = serveur_test
        code, data = _post_json(f"{base_url}/api/atomic/importer", {"techniques": "T1110"})
        assert code == 400
        assert "erreur" in data

    def test_api_atomic_importer_liste_avec_elements_invalides_retourne_400(
        self, serveur_test, monkeypatch
    ):
        """Régression : `techniques=[1, 2, 3]` (éléments non-chaînes) était
        filtré silencieusement en liste VIDE, traitée plus loin comme
        « aucun filtre » -- la requête importait alors TOUT le référentiel
        Atomic Red Team au lieu d'être rejetée. Doit désormais renvoyer 400
        SANS jamais appeler importer_atomic_dashboard."""
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.importer_atomic_dashboard",
            lambda repo=None, platform=None, techniques=None: appels.append("appelé")
            or {"retenus": [], "refuses": [], "total_lus": 0, "ajoutes": 0, "deja_presents": 0},
        )
        code, data = _post_json(f"{base_url}/api/atomic/importer", {"techniques": [1, 2, 3]})
        assert code == 400
        assert "erreur" in data
        assert appels == []  # rejeté avant tout import -- jamais "tout importer"

    def test_api_atomic_importer_liste_vide_reste_sans_filtre(self, serveur_test, monkeypatch):
        """Non-régression : une liste réellement vide (aucune technique
        cochée côté UI) doit continuer à signifier « aucun filtre »,
        comportement distinct d'une liste malformée."""
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.importer_atomic_dashboard",
            lambda repo=None, platform=None, techniques=None: appels.append(techniques)
            or {"retenus": [], "refuses": [], "total_lus": 0, "ajoutes": 0, "deja_presents": 0},
        )
        code, _data = _post_json(f"{base_url}/api/atomic/importer", {"techniques": []})
        assert code == 200
        assert appels == [[]]

    def test_api_valider_regle_sans_contenu_retourne_400(self, serveur_test):
        base_url, _ = serveur_test
        code, data = _post_json(f"{base_url}/api/valider-regle", {})
        assert code == 400
        assert "erreur" in data

    def test_api_valider_regle_delegue(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.valider_regle_dashboard",
            lambda config, contenu, jours=7, seuil=100: appels.append((contenu, jours, seuil))
            or {"verdict": "ACTIVE", "hits": 3, "compilable": True},
        )
        code, data = _post_json(
            f"{base_url}/api/valider-regle", {"contenu": "title: x\n", "jours": 3, "seuil": 50}
        )
        assert code == 200
        assert data["verdict"] == "ACTIVE"
        assert appels == [("title: x\n", 3, 50)]

    def test_api_valider_regle_jours_non_numerique_retourne_400(self, serveur_test):
        """Régression : `int(corps.get("jours") or 7)` sans garde plantait
        (ValueError non rattrapé) sur une entrée non numérique."""
        base_url, _ = serveur_test
        code, data = _post_json(
            f"{base_url}/api/valider-regle", {"contenu": "title: x\n", "jours": "abc"}
        )
        assert code == 400
        assert "erreur" in data

    def test_api_suggest_sans_description_retourne_400(self, serveur_test):
        base_url, _ = serveur_test
        code, _data = _post_json(f"{base_url}/api/suggest", {})
        assert code == 400

    def test_api_suggest_echec_llm_retourne_502(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr("cadre.dashboard.generer_brouillon_ia", lambda d, t: None)
        code, _data = _post_json(f"{base_url}/api/suggest", {"description": "x"})
        assert code == 502

    def test_api_suggest_enregistrer_sans_brouillon_retourne_400(self, serveur_test):
        base_url, _ = serveur_test
        code, data = _post_json(f"{base_url}/api/suggest/enregistrer", {})
        assert code == 400
        assert data["ok"] is False

    def test_api_suggest_enregistrer_brouillon_non_dict_retourne_400(self, serveur_test):
        """Régression : {"brouillon": "texte"} est truthy (passe le seul
        `if not brouillon` d'avant) mais fait planter le {**brouillon}/
        brouillon.get(...) en aval avec un TypeError/AttributeError non
        rattrapé, jamais une réponse 400 propre."""
        base_url, _ = serveur_test
        code, data = _post_json(f"{base_url}/api/suggest/enregistrer", {"brouillon": "pas un dict"})
        assert code == 400
        assert data["ok"] is False

        code, data = _post_json(f"{base_url}/api/suggest/enregistrer", {"brouillon": [1, 2]})
        assert code == 400
        assert data["ok"] is False

    def test_api_suggest_enregistrer_persiste_l_attaque(self, serveur_test, monkeypatch, tmp_path):
        base_url, _ = serveur_test
        import cadre.catalogue_utilisateur as cu

        monkeypatch.setattr(cu, "CHEMIN_CATALOGUE_PERSO", tmp_path / "perso.json")
        brouillon = {
            "nom": "Test web",
            "description": "via dashboard",
            "technique_mitre": "T1033",
            "tactique_mitre": "Discovery",
            "commande": "whoami",
        }
        code, data = _post_json(
            f"{base_url}/api/suggest/enregistrer",
            {"brouillon": brouillon, "id": "CADRE-PERSO-WEB"},
        )
        assert code == 200
        assert data["ok"] is True
        assert data["id"] == "CADRE-PERSO-WEB"
        # Persisté et rechargeable
        assert any(a.id == "CADRE-PERSO-WEB" for a in cu.charger_attaques_utilisateur())

    def test_api_suggest_enregistrer_id_natif_refuse(self, serveur_test, monkeypatch, tmp_path):
        base_url, _ = serveur_test
        import cadre.catalogue_utilisateur as cu
        from cadre.catalogue_attaques import CATALOGUE

        monkeypatch.setattr(cu, "CHEMIN_CATALOGUE_PERSO", tmp_path / "perso.json")
        brouillon = {
            "nom": "x",
            "description": "x",
            "technique_mitre": "T1",
            "tactique_mitre": "Discovery",
            "commande": "whoami",
        }
        code, data = _post_json(
            f"{base_url}/api/suggest/enregistrer",
            {"brouillon": brouillon, "id": CATALOGUE[0].id},
        )
        assert code == 400
        assert data["ok"] is False

    def test_rapport_existant_est_servi(self, serveur_test):
        base_url, repertoire = serveur_test
        (repertoire / "cycle_x.html").write_text("<p>rapport</p>", encoding="utf-8")
        with urllib.request.urlopen(f"{base_url}/rapports/cycle_x.html") as r:
            assert r.status == 200
            assert b"rapport" in r.read()

    def test_fichier_hors_rapports_jamais_servi_via_http(self, serveur_test):
        """Bout-en-bout : une requête qui vise un fichier hors du répertoire
        de rapports ne renvoie jamais son contenu (404). La défense elle-même
        (résolution + is_relative_to) est testée unitairement dans
        TestCheminSecurise — ceci vérifie juste le comportement HTTP observable."""
        base_url, _ = serveur_test
        import urllib.error

        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(f"{base_url}/rapports/..%2F..%2Fsecret.txt")
        assert exc.value.code == 404
        exc.value.close()

    def test_route_inconnue_retourne_404(self, serveur_test):
        base_url, _ = serveur_test
        import urllib.error

        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(f"{base_url}/inexistant")
        assert exc.value.code == 404
        exc.value.close()

    def test_route_post_inconnue_retourne_404(self, serveur_test):
        """Régression couverture : le `else: 404` final de do_POST n'avait
        pas d'équivalent testé, contrairement au GET ci-dessus. Contrairement
        aux autres 404 de ce fichier, cette branche n'envoie aucun corps
        JSON (juste send_response + end_headers) -- _post_json() ne
        convient donc pas ici (elle décode toujours le corps en JSON)."""
        import urllib.error

        base_url, _ = serveur_test
        req = urllib.request.Request(
            f"{base_url}/api/inexistant",
            data=b"{}",
            headers={"Content-Type": "application/json", "X-CADRE-Local": "1"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req)
        assert exc.value.code == 404
        exc.value.close()

    def test_lancer_cycle_deja_en_cours_retourne_409(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr("cadre.dashboard.demarrer_cycle", lambda *a, **k: False)
        code, data = _post_json(f"{base_url}/api/cycle/lancer", {"mode": "simulation"})
        assert code == 409
        assert data["lance"] is False

    def test_lancer_cycle_simulation_reussit(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr("cadre.dashboard.demarrer_cycle", lambda *a, **k: True)
        code, data = _post_json(f"{base_url}/api/cycle/lancer", {"mode": "simulation"})
        assert code == 200
        assert data == {"lance": True, "mode": "simulation"}

    def test_lancer_cycle_reel_sans_confirmation_retourne_400(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.demarrer_cycle", lambda *a, **k: appels.append(1) or True
        )
        code, data = _post_json(f"{base_url}/api/cycle/lancer", {"mode": "reel"})
        assert code == 400
        assert "confirmation" in data["erreur"]
        assert appels == []  # le cycle réel n'a jamais été déclenché

    def test_lancer_cycle_reel_avec_confirmation_reussit(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        modes_recus = []

        def demarrer_cycle_factice(
            config, etat, mode="simulation", techniques=None, parallele=False
        ):
            modes_recus.append(mode)
            return True

        monkeypatch.setattr("cadre.dashboard.demarrer_cycle", demarrer_cycle_factice)
        code, data = _post_json(f"{base_url}/api/cycle/lancer", {"mode": "reel", "confirmer": True})
        assert code == 200
        assert data["mode"] == "reel"
        assert modes_recus == ["reel"]

    def test_lancer_cycle_mode_invalide_retourne_400(self, serveur_test):
        base_url, _ = serveur_test
        code, _data = _post_json(f"{base_url}/api/cycle/lancer", {"mode": "n_importe_quoi"})
        assert code == 400

    def test_lancer_cycle_techniques_non_liste_retourne_400(self, serveur_test):
        """Régression couverture : la validation liste blanche des
        techniques (isinstance + appartenance au catalogue) n'était
        exercée par aucun test HTTP -- tous omettaient ce champ."""
        base_url, _ = serveur_test
        code, data = _post_json(f"{base_url}/api/cycle/lancer", {"techniques": "T1059.001"})
        assert code == 400
        assert "erreur" in data

    def test_lancer_cycle_technique_inconnue_retourne_400(self, serveur_test):
        base_url, _ = serveur_test
        code, data = _post_json(
            f"{base_url}/api/cycle/lancer", {"techniques": ["T9999.999-inexistante"]}
        )
        assert code == 400
        assert "inconnue" in data["erreur"]

    def test_api_catalogue_detail_repond_200(self, serveur_test):
        import cadre.catalogue_attaques as ca

        base_url, _ = serveur_test
        with urllib.request.urlopen(f"{base_url}/api/catalogue/{ca.CATALOGUE[0].id}") as r:
            data = json.loads(r.read())
            assert data["commande"] == ca.CATALOGUE[0].commande

    def test_api_catalogue_detail_inconnu_retourne_404(self, serveur_test):
        import urllib.error

        base_url, _ = serveur_test
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(f"{base_url}/api/catalogue/N-EXISTE-PAS")
        assert exc.value.code == 404
        exc.value.close()

    def test_lancer_attaque_id_manquant_retourne_400(self, serveur_test):
        base_url, _ = serveur_test
        code, data = _post_json(f"{base_url}/api/attaque/lancer", {"mode": "simulation"})
        assert code == 400
        assert "id" in data["erreur"]

    def test_lancer_attaque_id_inconnu_retourne_404(self, serveur_test):
        base_url, _ = serveur_test
        code, _data = _post_json(f"{base_url}/api/attaque/lancer", {"id": "N-EXISTE-PAS"})
        assert code == 404

    def test_lancer_attaque_reel_sans_confirmation_retourne_400(self, serveur_test, monkeypatch):
        import cadre.catalogue_attaques as ca

        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.demarrer_attaque_unique", lambda *a, **k: appels.append(1) or True
        )
        code, data = _post_json(
            f"{base_url}/api/attaque/lancer", {"id": ca.CATALOGUE[0].id, "mode": "reel"}
        )
        assert code == 400
        assert "confirmation" in data["erreur"]
        assert appels == []

    def test_lancer_attaque_simulation_reussit(self, serveur_test, monkeypatch):
        import cadre.catalogue_attaques as ca

        base_url, _ = serveur_test
        monkeypatch.setattr("cadre.dashboard.demarrer_attaque_unique", lambda *a, **k: True)
        code, data = _post_json(
            f"{base_url}/api/attaque/lancer", {"id": ca.CATALOGUE[0].id, "mode": "simulation"}
        )
        assert code == 200
        assert data == {"lance": True, "mode": "simulation", "id": ca.CATALOGUE[0].id}

    def test_lancer_attaque_deja_en_cours_retourne_409(self, serveur_test, monkeypatch):
        import cadre.catalogue_attaques as ca

        base_url, _ = serveur_test
        monkeypatch.setattr("cadre.dashboard.demarrer_attaque_unique", lambda *a, **k: False)
        code, data = _post_json(
            f"{base_url}/api/attaque/lancer", {"id": ca.CATALOGUE[0].id, "mode": "simulation"}
        )
        assert code == 409
        assert data["lance"] is False

    def test_decouverte_sans_confirmation_retourne_400(self, serveur_test, monkeypatch):
        """Régression : ce test postait `{}` (ni description NI confirmer),
        donc échouait en réalité sur la garde "description requise"
        (vérifiée EN PREMIER par la route) sans jamais exercer la garde de
        confirmation que son nom prétend tester -- un `description` valide
        est désormais fourni pour isoler spécifiquement cette seconde garde."""
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.demarrer_decouverte", lambda *a, **k: appels.append(1) or True
        )
        code, data = _post_json(
            f"{base_url}/api/decouverte/lancer", {"description": "Énumérer les tâches planifiées"}
        )
        assert code == 400
        assert "confirmation" in data["erreur"]
        assert appels == []  # l'agent n'est jamais lancé sans confirmation

    def test_decouverte_avec_confirmation_reussit(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr("cadre.dashboard.demarrer_decouverte", lambda *a, **k: True)
        code, data = _post_json(
            f"{base_url}/api/decouverte/lancer",
            {"confirmer": True, "description": "Énumérer les tâches planifiées"},
        )
        assert code == 200
        assert data == {"lance": True}

    def test_decouverte_sans_description_retourne_400(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.demarrer_decouverte", lambda *a, **k: appels.append(1) or True
        )
        code, data = _post_json(f"{base_url}/api/decouverte/lancer", {"confirmer": True})
        assert code == 400
        assert "description" in data["erreur"]
        assert appels == []

    def test_decouverte_description_vide_retourne_400(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr("cadre.dashboard.demarrer_decouverte", lambda *a, **k: True)
        code, _data = _post_json(
            f"{base_url}/api/decouverte/lancer", {"confirmer": True, "description": "   "}
        )
        assert code == 400

    def test_decouverte_transmet_description_technique_revue(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.demarrer_decouverte",
            lambda config, etat, description, technique=None, revue=False: (
                appels.append((description, technique, revue)) or True
            ),
        )
        code, _data = _post_json(
            f"{base_url}/api/decouverte/lancer",
            {
                "confirmer": True,
                "description": "Lister les partages réseau",
                "technique": "T1135",
                "revue": True,
            },
        )
        assert code == 200
        assert appels == [("Lister les partages réseau", "T1135", True)]

    def test_decouverte_statut_repond(self, serveur_test):
        base_url, _ = serveur_test
        with urllib.request.urlopen(f"{base_url}/api/decouverte/statut") as r:
            data = json.loads(r.read())
            assert data["en_cours"] is False

    def test_api_statut_repond(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr(
            "cadre.dashboard.verifier_statut_stack",
            lambda config, orchestrateur=None: {
                "elasticsearch": {"ok": True, "detail": "HTTP 200", "url": "x"}
            },
        )
        with urllib.request.urlopen(f"{base_url}/api/statut") as r:
            data = json.loads(r.read())
            assert data["elasticsearch"]["ok"] is True

    def test_api_statut_ne_reconstruit_pas_l_orchestrateur_a_chaque_sondage(
        self, serveur_test, monkeypatch
    ):
        """Régression (audit, mesurée en réel) : la barre d'état sonde
        /api/statut toutes les 5s -- reconstruire un OrchestrateurCADRE à
        chaque sondage relit et rejournalise ~10 secrets à chaque appel,
        noyant le journal en quelques minutes (979/1000 dernières entrées =
        bruit SECRET_READ dans le test réel). Un seul orchestrateur doit
        être construit pour toute la durée de vie du serveur, quel que soit
        le nombre de sondages."""
        base_url, _ = serveur_test
        appels_construction = []

        class OrchestrateurFactice:
            def __init__(self, config):
                appels_construction.append(1)
                self.config = {
                    "elastic_url": "http://localhost:9200",
                    "kibana_url": "http://localhost:5601",
                    "vm_ip": "",
                }
                self.auth_elastic = None

            def _verifier_connectivite_vm(self):
                return False

        monkeypatch.setattr("cadre.orchestrateur.OrchestrateurCADRE", OrchestrateurFactice)
        monkeypatch.setattr(
            "requests.get",
            lambda *a, **k: type("R", (), {"status_code": 200})(),
        )

        for _ in range(3):
            with urllib.request.urlopen(f"{base_url}/api/statut") as r:
                assert json.loads(r.read())["elasticsearch"]["ok"] is True

        assert len(appels_construction) == 1
        with urllib.request.urlopen(f"{base_url}/api/statut") as r:
            data = json.loads(r.read())
            assert data["elasticsearch"]["ok"] is True

    def test_api_cycle_statut_reflete_l_etat_partage(self, serveur_test):
        base_url, _ = serveur_test
        with urllib.request.urlopen(f"{base_url}/api/cycle/statut") as r:
            data = json.loads(r.read())
            assert data["en_cours"] is False

    def test_api_logs_repond(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr(
            "cadre.dashboard.tail_logs", lambda fichier, n: [{"msg": "x"}] * min(n, 3)
        )
        with urllib.request.urlopen(f"{base_url}/api/logs?n=3") as r:
            data = json.loads(r.read())
        assert len(data["evenements"]) == 3

    def test_api_logs_n_invalide_replie_sur_50(self, serveur_test, monkeypatch):
        """Régression : `n=int(...)` sans garde plantait sur une valeur non
        numérique (`?n=abc`) au lieu de se replier sur le défaut (50)."""
        base_url, _ = serveur_test
        appels = []
        monkeypatch.setattr(
            "cadre.dashboard.tail_logs",
            lambda fichier, n: appels.append(n) or [],
        )
        with urllib.request.urlopen(f"{base_url}/api/logs?n=abc") as r:
            assert r.status == 200
        assert appels == [50]

    def test_api_verifier_repond(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        monkeypatch.setattr(
            "cadre.dashboard.verification_globale",
            lambda config: {
                "points": [{"nom": "x", "ok": True, "optionnel": False}],
                "tout_ok": True,
            },
        )
        with urllib.request.urlopen(f"{base_url}/api/verifier") as r:
            data = json.loads(r.read())
        assert data["tout_ok"] is True
        assert data["points"][0]["nom"] == "x"


class TestVerificationGlobale:
    def _stubs(self, monkeypatch, *, stack_ok=True, secret_ok=True, ollama_ok=True):
        monkeypatch.setattr(
            "cadre.dashboard.verifier_statut_stack",
            lambda config: {
                "elasticsearch": {"ok": stack_ok, "detail": "HTTP 200"},
                "kibana": {"ok": stack_ok, "detail": "HTTP 200"},
                "vm": {"ok": stack_ok, "detail": "192.168.56.104"},
            },
        )
        monkeypatch.setattr(
            "cadre.dashboard.statut_secrets",
            lambda: [
                {"cle": "CADRE_VM_PASS", "libelle": "x", "critique": True, "configure": secret_ok},
                {"cle": "CADRE_VM_IP", "libelle": "y", "critique": False, "configure": False},
            ],
        )

        class AssistantFactice:
            modele = "qwen2.5-coder:7b"

            def disponible(self):
                return ollama_ok

        monkeypatch.setattr("cadre.assistant_llm.obtenir_assistant_llm", AssistantFactice)

    def test_tout_ok_quand_briques_requises_pretes(self, monkeypatch):
        from cadre.dashboard import verification_globale

        self._stubs(monkeypatch, stack_ok=True, secret_ok=True, ollama_ok=True)
        res = verification_globale({"repertoire_rapports": Path()})
        assert res["tout_ok"] is True

    def test_ollama_absent_n_empeche_pas_tout_ok(self, monkeypatch):
        from cadre.dashboard import verification_globale

        self._stubs(monkeypatch, stack_ok=True, secret_ok=True, ollama_ok=False)
        res = verification_globale({"repertoire_rapports": Path()})
        # Ollama est optionnel : son absence ne casse pas le tout_ok
        assert res["tout_ok"] is True
        ollama = next(p for p in res["points"] if "Ollama" in p["nom"])
        assert ollama["optionnel"] is True

    def test_secret_critique_manquant_casse_tout_ok(self, monkeypatch):
        from cadre.dashboard import verification_globale

        self._stubs(monkeypatch, stack_ok=True, secret_ok=False, ollama_ok=True)
        res = verification_globale({"repertoire_rapports": Path()})
        assert res["tout_ok"] is False


class TestProtectionCSRF:
    """Garde-fou CSRF/DNS-rebinding sur les POST (F5). `_origine_locale_ok`
    est une méthode pure (lit seulement self.headers) : on l'instancie sans
    démarrer le serveur via object.__new__. L'en-tête custom X-CADRE-Local est
    désormais obligatoire (défense CSRF non forgeable en simple request)."""

    LOCAL = "1"

    def _handler(self, tmp_path):
        from cadre.dashboard import EtatCycle, EtatDecouverte, creer_gestionnaire

        cls = creer_gestionnaire(tmp_path, tmp_path / "log.json", {}, EtatCycle(), EtatDecouverte())
        return object.__new__(cls)

    def test_requete_locale_avec_entete_est_acceptee(self, tmp_path):
        h = self._handler(tmp_path)
        h.headers = {"Host": "127.0.0.1:8765", "X-CADRE-Local": self.LOCAL}
        assert h._origine_locale_ok() is True

    def test_sans_entete_custom_est_refuse(self, tmp_path):
        h = self._handler(tmp_path)
        h.headers = {"Host": "127.0.0.1:8765"}  # pas de X-CADRE-Local
        assert h._origine_locale_ok() is False

    def test_origin_tiers_est_refusee(self, tmp_path):
        h = self._handler(tmp_path)
        h.headers = {
            "Host": "127.0.0.1:8765",
            "X-CADRE-Local": self.LOCAL,
            "Origin": "http://evil.example.com",
        }
        assert h._origine_locale_ok() is False

    def test_host_falsifie_dns_rebinding_est_refuse(self, tmp_path):
        h = self._handler(tmp_path)
        h.headers = {"Host": "evil.example.com", "X-CADRE-Local": self.LOCAL}
        assert h._origine_locale_ok() is False

    def test_origin_loopback_est_acceptee(self, tmp_path):
        h = self._handler(tmp_path)
        h.headers = {
            "Host": "localhost:8765",
            "X-CADRE-Local": self.LOCAL,
            "Origin": "http://localhost:8765",
        }
        assert h._origine_locale_ok() is True

    def test_bout_en_bout_post_sans_entete_local_recoit_403(self, serveur_test):
        """Régression couverture : les tests ci-dessus vérifient
        `_origine_locale_ok()` en isolation, mais TOUS les tests HTTP du
        reste de la suite passent par `_post_json()` qui pose SYSTÉMATIQUEMENT
        X-CADRE-Local -- le vrai 403, de bout en bout via le serveur réel,
        n'était donc jamais observé. Requête POST brute (urllib nu, comme
        une page tierce), sans le garde-fou CSRF, sur une route réelle."""
        import urllib.error

        base_url, _ = serveur_test
        req = urllib.request.Request(
            f"{base_url}/api/cycle/lancer",
            data=json.dumps({"mode": "simulation"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},  # PAS de X-CADRE-Local
            method="POST",
        )
        code, data = 0, None
        try:
            urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            code = e.code
            data = json.loads(e.read())
        assert code == 403
        assert "erreur" in data


class TestRobustesseDashboard:
    def test_lire_csv_fichier_absent_retourne_liste_vide(self, tmp_path):
        """F4 : un CSV disparu (TOCTOU) ne fait pas crasher la requête."""
        from cadre.dashboard import _lire_csv

        assert _lire_csv(tmp_path / "nexiste_pas.csv") == []

    def test_corps_post_trop_grand_est_rejete(self):
        """F6 : un Content-Length géant est refusé sans allouer de mémoire."""
        import types

        from cadre.dashboard import _TAILLE_MAX_CORPS, _lire_corps_json

        # rfile=None ne doit JAMAIS être lu (rejet avant lecture).
        handler = types.SimpleNamespace(
            headers={"Content-Length": str(_TAILLE_MAX_CORPS + 1)}, rfile=None
        )
        assert _lire_corps_json(handler) == {}


class TestFrontendStatique:
    """Nouveau frontend multi-fichiers (dashboard/) : XSS structurelle (aucun
    innerHTML dynamique, aucun handler inline) + CSP servie + anti-traversée."""

    REP = Path(__file__).resolve().parents[1] / "dashboard"

    def _faux_handler(self):
        import io

        class Faux:
            def __init__(self):
                self.entetes = {}
                self.statut = None
                self.wfile = io.BytesIO()

            def send_response(self, s):
                self.statut = s

            def send_header(self, k, v):
                self.entetes[k] = v

            def end_headers(self):
                pass

        return Faux()

    def test_index_sert_avec_csp_stricte(self):
        from cadre.dashboard import _servir_statique

        h = self._faux_handler()
        assert _servir_statique(h, "/") is True
        assert h.statut == 200
        csp = h.entetes.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp
        assert "object-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp
        assert h.entetes.get("X-Content-Type-Options") == "nosniff"

    def test_js_sert_avec_bon_type(self):
        from cadre.dashboard import _servir_statique

        h = self._faux_handler()
        assert _servir_statique(h, "/js/app.js") is True
        assert h.entetes["Content-Type"].startswith("text/javascript")

    def test_traversee_de_chemin_bloquee(self):
        from cadre.dashboard import _servir_statique

        h = self._faux_handler()
        assert _servir_statique(h, "/../src/cadre/dashboard.py") is False

    def test_aucun_innerhtml_dynamique_dans_le_js(self):
        """Invariante XSS : aucune affectation .innerHTML dans tout js/."""
        import re

        for js in self.REP.glob("js/**/*.js"):
            contenu = js.read_text(encoding="utf-8")
            # Un vrai sink est toujours une affectation de propriété `.innerHTML =`
            # (le point exclut les mentions en commentaire).
            assert re.search(r"\.innerHTML\s*\+?=", contenu) is None, f"innerHTML dans {js.name}"

    def test_index_sans_script_ni_handler_inline(self):
        """CSP stricte : pas de <script> inline, pas de on*= inline."""
        import re

        html = (self.REP / "index.html").read_text(encoding="utf-8")
        # Tout <script> doit porter un src (aucun script inline).
        for balise in re.findall(r"<script[^>]*>", html):
            assert "src=" in balise, f"script inline détecté : {balise}"
        assert re.search(r"\son[a-z]+\s*=", html) is None, "handler inline détecté"


class TestAuthentificationDashboard:
    """Authentification HTTP Basic (opt-in via CADRE_DASHBOARD_PASSWORD,
    obligatoire dès que --bind n'est pas loopback). Comparaison en temps
    constant, verrouillage anti-brute-force par IP source. Même patron que
    TestProtectionCSRF : handler instancié via object.__new__ (pure, pas de
    vrai socket)."""

    IP = "203.0.113.1"  # TEST-NET-3 (RFC 5737) -- jamais une IP réelle

    def _handler(self, tmp_path, ip=None):
        from cadre.dashboard import EtatCycle, EtatDecouverte, creer_gestionnaire

        cls = creer_gestionnaire(tmp_path, tmp_path / "log.json", {}, EtatCycle(), EtatDecouverte())
        h = object.__new__(cls)
        h.client_address = (ip or self.IP, 54321)
        return h

    @staticmethod
    def _entete_basic(mot_de_passe, utilisateur="cadre"):
        jeton = base64.b64encode(f"{utilisateur}:{mot_de_passe}".encode()).decode()
        return f"Basic {jeton}"

    @pytest.fixture(autouse=True)
    def _echecs_auth_vides(self):
        """`_echecs_auth` est un dict module-level (partagé entre TOUTES les
        requêtes du process, par design -- c'est le but du verrouillage) :
        sans reset, les tests de cette classe se pollueraient entre eux."""
        import cadre.dashboard as m

        m._echecs_auth.clear()
        yield
        m._echecs_auth.clear()

    def _avec_mot_de_passe(self, monkeypatch, mot_de_passe):
        import cadre.coffre_fort as cf

        monkeypatch.setattr(
            cf,
            "secret_or_none",
            lambda cle: mot_de_passe if cle == "CADRE_DASHBOARD_PASSWORD" else None,
        )

    def test_sans_secret_configure_auth_toujours_ok(self, tmp_path, monkeypatch):
        """Opt-in : pas de secret défini = aucune authentification exigée
        (comportement actuel inchangé pour un usage solo local)."""
        import cadre.coffre_fort as cf

        monkeypatch.setattr(cf, "secret_or_none", lambda cle: None)
        h = self._handler(tmp_path)
        h.headers = {}
        assert h._auth_ok() is True

    def test_bon_mot_de_passe_accepte(self, tmp_path, monkeypatch):
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        h = self._handler(tmp_path)
        h.headers = {"Authorization": self._entete_basic("bonmdp")}
        assert h._auth_ok() is True

    def test_mauvais_mot_de_passe_refuse(self, tmp_path, monkeypatch):
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        h = self._handler(tmp_path)
        h.headers = {"Authorization": self._entete_basic("mauvais")}
        assert h._auth_ok() is False

    def test_entete_absente_refusee(self, tmp_path, monkeypatch):
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        h = self._handler(tmp_path)
        h.headers = {}
        assert h._auth_ok() is False

    def test_entete_malformee_refusee_sans_planter(self, tmp_path, monkeypatch):
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        h = self._handler(tmp_path)
        h.headers = {"Authorization": "Basic ###pas-du-base64###"}
        assert h._auth_ok() is False

    def test_nom_utilisateur_ignore_seul_le_mot_de_passe_compte(self, tmp_path, monkeypatch):
        """Un seul secret partagé, pas de multi-compte -- documenté dans
        _auth_ok. N'importe quel nom d'utilisateur passe si le mot de passe
        est bon."""
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        h = self._handler(tmp_path)
        h.headers = {"Authorization": self._entete_basic("bonmdp", utilisateur="peu-importe")}
        assert h._auth_ok() is True

    def test_mot_de_passe_accentue_ne_plante_pas(self, tmp_path, monkeypatch):
        """Régression sécurité : hmac.compare_digest() lève TypeError sur
        des str contenant un caractère non-ASCII -- non rattrapé, ça
        faisait planter CHAQUE requête authentifiée dès qu'un opérateur
        configurait un CADRE_DASHBOARD_PASSWORD avec un accent, rendant le
        dashboard réseau totalement inutilisable. Comparé en bytes UTF-8
        depuis ce correctif."""
        self._avec_mot_de_passe(monkeypatch, "café123!")
        h = self._handler(tmp_path)
        h.headers = {"Authorization": self._entete_basic("café123!")}
        assert h._auth_ok() is True
        h.headers = {"Authorization": self._entete_basic("mauvais-mdp")}
        assert h._auth_ok() is False

    def test_verrouillage_apres_echecs_repetes(self, tmp_path, monkeypatch):
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        h = self._handler(tmp_path)
        h.headers = {"Authorization": self._entete_basic("mauvais")}
        for _ in range(5):
            assert h._auth_ok() is False
        # 6e essai, même avec le BON mot de passe cette fois : verrouillé.
        h.headers = {"Authorization": self._entete_basic("bonmdp")}
        assert h._auth_ok() is False

    def test_verrouillage_est_par_ip_pas_global(self, tmp_path, monkeypatch):
        """Un attaquant qui épuise le seuil sur une IP ne doit pas bloquer
        un opérateur légitime depuis une autre IP."""
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        attaquant = self._handler(tmp_path, ip="203.0.113.66")
        attaquant.headers = {"Authorization": self._entete_basic("mauvais")}
        for _ in range(5):
            attaquant._auth_ok()

        operateur = self._handler(tmp_path, ip="203.0.113.99")
        operateur.headers = {"Authorization": self._entete_basic("bonmdp")}
        assert operateur._auth_ok() is True

    def test_succes_reinitialise_le_compteur_d_echecs(self, tmp_path, monkeypatch):
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        h = self._handler(tmp_path)
        h.headers = {"Authorization": self._entete_basic("mauvais")}
        for _ in range(3):
            h._auth_ok()
        h.headers = {"Authorization": self._entete_basic("bonmdp")}
        assert h._auth_ok() is True
        # Le compteur est retombé à zéro : 4 nouveaux échecs ne suffisent
        # pas à atteindre le seuil de 5.
        h.headers = {"Authorization": self._entete_basic("mauvais")}
        for _ in range(4):
            assert h._auth_ok() is False
        h.headers = {"Authorization": self._entete_basic("bonmdp")}
        assert h._auth_ok() is True

    def test_bout_en_bout_sans_authorization_recoit_401(self, serveur_test, monkeypatch):
        """Régression couverture : les tests ci-dessus vérifient `_auth_ok()`
        en isolation, mais aucun ne déclenche le vrai 401 via une requête
        HTTP réelle contre le serveur (`serveur_test` ne configure jamais de
        mot de passe). Ici, un mot de passe est injecté sur un serveur déjà
        démarré, puis une requête sans en-tête Authorization confirme le 401
        de bout en bout (routage do_GET -> _exiger_auth -> réponse)."""
        import urllib.error

        base_url, _ = serveur_test
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        code = 0
        try:
            urllib.request.urlopen(f"{base_url}/api/statut")
        except urllib.error.HTTPError as e:
            code = e.code
            assert e.headers.get("WWW-Authenticate", "").startswith("Basic")
            e.close()
        assert code == 401


class TestConnexionSession:
    """Session par cookie posée par la page de connexion (connexion.html),
    voie alternative à Basic Auth pour l'usage navigateur -- Basic Auth reste
    entièrement fonctionnel en parallèle (voir TestAuthentificationDashboard).
    Même patron double (handler nu pour la logique pure, serveur réel pour le
    parcours HTTP complet) que la classe ci-dessus."""

    IP = "203.0.113.1"

    def _handler(self, tmp_path, ip=None):
        from cadre.dashboard import EtatCycle, EtatDecouverte, creer_gestionnaire

        cls = creer_gestionnaire(tmp_path, tmp_path / "log.json", {}, EtatCycle(), EtatDecouverte())
        h = object.__new__(cls)
        h.client_address = (ip or self.IP, 54321)
        return h

    def _avec_mot_de_passe(self, monkeypatch, mot_de_passe):
        import cadre.coffre_fort as cf

        monkeypatch.setattr(
            cf,
            "secret_or_none",
            lambda cle: mot_de_passe if cle == "CADRE_DASHBOARD_PASSWORD" else None,
        )

    @pytest.fixture(autouse=True)
    def _etat_partage_vide(self):
        """`_echecs_auth` ET `_sessions` sont des dicts module-level partagés
        entre toutes les requêtes du process -- sans reset, les tests de
        cette classe (et les précédents/suivants) se pollueraient entre eux."""
        import cadre.dashboard as m

        m._echecs_auth.clear()
        m._sessions.clear()
        yield
        m._echecs_auth.clear()
        m._sessions.clear()

    @staticmethod
    def _post_avec_entetes(url, payload, entetes_extra=None):
        """Comme `_post_json`, mais retourne aussi les en-têtes de réponse
        (nécessaire pour lire `Set-Cookie`, absent du helper partagé)."""
        import urllib.error

        entetes = {
            "Content-Type": "application/json",
            "X-CADRE-Local": "1",
            **(entetes_extra or {}),
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=entetes,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read()), dict(r.headers)
        except urllib.error.HTTPError as e:
            data = json.loads(e.read())
            code = e.code
            entetes = dict(e.headers)
            e.close()
            return code, data, entetes

    # ---- Unité : _session_valide / _auth_ok --------------------------------

    def test_cookie_de_session_valide_suffit_sans_basic_auth(self, tmp_path, monkeypatch):
        from cadre.dashboard import _creer_session

        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        jeton = _creer_session()
        h = self._handler(tmp_path)
        h.headers = {"Cookie": f"cadre_session={jeton}"}
        assert h._auth_ok() is True

    def test_cookie_invalide_retombe_sur_basic_auth_qui_echoue(self, tmp_path, monkeypatch):
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        h = self._handler(tmp_path)
        h.headers = {"Cookie": "cadre_session=jeton-invente-au-hasard"}
        assert h._auth_ok() is False

    def test_session_expiree_refusee_et_nettoyee(self, tmp_path, monkeypatch):
        import cadre.dashboard as m

        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        jeton = "jeton-perime"
        m._sessions[jeton] = time.time() - 1  # déjà expiré
        assert m._session_valide(jeton) is False
        assert jeton not in m._sessions  # nettoyage à la lecture

    def test_revoquer_session_invalide_le_cookie(self, tmp_path, monkeypatch):
        from cadre.dashboard import _creer_session, _revoquer_session

        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        jeton = _creer_session()
        h = self._handler(tmp_path)
        h.headers = {"Cookie": f"cadre_session={jeton}"}
        assert h._auth_ok() is True
        _revoquer_session(jeton)
        assert h._auth_ok() is False

    # ---- Bout en bout : /api/login, /api/logout, page de connexion --------

    def test_login_bon_mot_de_passe_pose_un_cookie(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        statut, data, entetes = self._post_avec_entetes(
            f"{base_url}/api/login", {"mot_de_passe": "bonmdp"}
        )
        assert statut == 200
        assert data == {"ok": True}
        assert "cadre_session=" in entetes.get("Set-Cookie", "")
        assert "HttpOnly" in entetes["Set-Cookie"]

    def test_login_mauvais_mot_de_passe_refuse_sans_cookie(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        statut, data, entetes = self._post_avec_entetes(
            f"{base_url}/api/login", {"mot_de_passe": "mauvais"}
        )
        assert statut == 401
        assert "erreur" in data
        assert "Set-Cookie" not in entetes

    def test_login_sans_entete_local_refuse_403(self, serveur_test, monkeypatch):
        """Même garde CSRF que toute autre route POST -- la connexion ne
        contourne pas la protection, elle applique sa propre vérification
        (voir _gerer_login)."""
        import urllib.error
        import urllib.request

        base_url, _ = serveur_test
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        req = urllib.request.Request(
            f"{base_url}/api/login",
            data=json.dumps({"mot_de_passe": "bonmdp"}).encode(),
            headers={"Content-Type": "application/json"},  # pas de X-CADRE-Local
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req)
        assert exc.value.code == 403
        exc.value.close()

    def test_cookie_de_session_donne_acces_a_une_route_protegee(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        _, _, entetes = self._post_avec_entetes(f"{base_url}/api/login", {"mot_de_passe": "bonmdp"})
        cookie = entetes["Set-Cookie"].split(";")[0]

        # /api/cycles plutôt que /api/statut : ne dépend pas de l'orchestrateur
        # (mocké à `lambda config: None` par serveur_test), qui n'a jamais
        # besoin d'être exercé pour vérifier qu'une session ouvre l'accès.
        req = urllib.request.Request(
            f"{base_url}/api/cycles", headers={"X-CADRE-Local": "1", "Cookie": cookie}
        )
        with urllib.request.urlopen(req) as r:
            assert r.status == 200

    def test_logout_revoque_le_cookie(self, serveur_test, monkeypatch):
        import urllib.error

        base_url, _ = serveur_test
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        _, _, entetes = self._post_avec_entetes(f"{base_url}/api/login", {"mot_de_passe": "bonmdp"})
        cookie = entetes["Set-Cookie"].split(";")[0]

        self._post_avec_entetes(f"{base_url}/api/logout", {}, entetes_extra={"Cookie": cookie})

        req = urllib.request.Request(
            f"{base_url}/api/cycles", headers={"X-CADRE-Local": "1", "Cookie": cookie}
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req)
        assert exc.value.code == 401
        exc.value.close()

    def test_login_partage_le_verrouillage_avec_basic_auth(self, serveur_test, monkeypatch):
        """Le compteur d'échecs est partagé par IP entre Basic Auth et le
        formulaire -- un attaquant ne peut pas contourner le verrou en
        alternant les deux voies. Utilise un en-tête Basic Auth FAUX (pas
        absent) pour chaque tentative : une requête sans aucun en-tête n'est
        plus comptée comme un échec depuis la correction ci-dessous (simple
        chargement de page, personne n'a rien tenté) -- voir
        test_page_non_authentifiee_ne_consomme_pas_le_compteur."""
        import base64
        import urllib.error
        import urllib.request

        base_url, _ = serveur_test
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        jeton_faux = base64.b64encode(b"cadre:mauvais").decode()
        for _ in range(5):
            req = urllib.request.Request(
                f"{base_url}/api/statut", headers={"Authorization": f"Basic {jeton_faux}"}
            )
            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(req)
            exc.value.close()

        statut, _, _ = self._post_avec_entetes(f"{base_url}/api/login", {"mot_de_passe": "bonmdp"})
        assert statut == 429

    def test_page_non_authentifiee_ne_consomme_pas_le_compteur(self, serveur_test, monkeypatch):
        """Régression (constatée en test navigateur réel) : `_auth_ok()`
        comptait toute requête SANS en-tête `Authorization` comme un échec,
        y compris un simple chargement de page sans identifiants encore
        fournis -- rafraîchir la page de connexion plusieurs fois verrouillait
        l'utilisateur avant même sa première tentative de mot de passe. Un
        chargement de page ne doit jamais consommer le compteur ; seule une
        tentative EFFECTIVE (mot de passe soumis, faux ou Basic Auth erroné)
        le doit."""
        base_url, _ = serveur_test
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        for _ in range(10):  # largement au-dessus du seuil de verrouillage (5)
            with urllib.request.urlopen(f"{base_url}/") as r:
                assert r.status == 200

        statut, _, entetes = self._post_avec_entetes(
            f"{base_url}/api/login", {"mot_de_passe": "bonmdp"}
        )
        assert statut == 200
        assert "cadre_session=" in entetes.get("Set-Cookie", "")

    def test_page_racine_non_authentifiee_sert_la_page_de_connexion(
        self, serveur_test, monkeypatch
    ):
        """La popup Basic Auth générique du navigateur (pas de logo, pas de
        contexte) est remplacée par une page CADRE -- 200, jamais de
        WWW-Authenticate qui déclencherait cette popup."""
        base_url, _ = serveur_test
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        with urllib.request.urlopen(f"{base_url}/") as r:
            assert r.status == 200
            assert "WWW-Authenticate" not in r.headers
            corps = r.read().decode("utf-8")
            assert "CADRE" in corps
            assert 'id="form-connexion"' in corps

    def test_chemins_publics_accessibles_sans_authentification(self, serveur_test, monkeypatch):
        base_url, _ = serveur_test
        self._avec_mot_de_passe(monkeypatch, "bonmdp")
        for chemin in ("/css/tokens.css", "/css/connexion.css", "/js/connexion.js"):
            with urllib.request.urlopen(f"{base_url}{chemin}") as r:
                assert r.status == 200

    def test_sans_mot_de_passe_configure_page_racine_normale(self, serveur_test, monkeypatch):
        """Sans CADRE_DASHBOARD_PASSWORD (usage solo local), `/` sert
        l'application normale -- jamais la page de connexion, qui n'a pas de
        raison d'exister ici (comportement inchangé)."""
        import cadre.coffre_fort as cf

        base_url, _ = serveur_test
        monkeypatch.setattr(cf, "secret_or_none", lambda cle: None)
        with urllib.request.urlopen(f"{base_url}/") as r:
            corps = r.read().decode("utf-8")
            assert 'id="form-connexion"' not in corps


class TestLancerDashboardExigeAuthHorsLoopback:
    """`lancer_dashboard` (F-010) : sécurisé par défaut -- un bind non-
    loopback sans mot de passe configuré ne doit jamais démarrer en
    silence sans authentification."""

    def test_refuse_bind_non_loopback_sans_secret(self, monkeypatch):
        import cadre.coffre_fort as cf
        from cadre.coffre_fort import ErreurSecurite
        from cadre.dashboard import lancer_dashboard

        monkeypatch.setattr(cf, "secret_or_none", lambda cle: None)
        with pytest.raises(ErreurSecurite, match="authentification"):
            lancer_dashboard(bind="0.0.0.0")

    def test_message_erreur_cite_le_bon_flag_cli(self, monkeypatch):
        """Régression : le message citait `--set-secret`, qui n'existe pas
        (`cadre init` n'a que `--set`) -- l'utilisateur qui suivait
        l'instruction du garde-fou de sécurité se prenait une 2e erreur."""
        import cadre.coffre_fort as cf
        from cadre.coffre_fort import ErreurSecurite
        from cadre.dashboard import lancer_dashboard

        monkeypatch.setattr(cf, "secret_or_none", lambda cle: None)
        with pytest.raises(ErreurSecurite, match=r"cadre init --set CADRE_DASHBOARD_PASSWORD"):
            lancer_dashboard(bind="0.0.0.0")

    def test_demarre_bind_non_loopback_avec_secret(self, monkeypatch, tmp_path):
        """Avec un secret configuré, aucune exception -- on n'écoute pas
        vraiment (ThreadingHTTPServer + serve_forever remplacés par des
        factices), seul le garde-fou de démarrage est vérifié.

        Régression (audit) : l'absence d'exception ne suffit pas à prouver
        que l'exécution a dépassé le garde-fou -- un `return` accidentel
        juste après le `if bind not in _HOTES_LOCAUX` laisserait ce test
        passer silencieusement sans jamais démarrer de serveur. `appels`
        rend visible que `ThreadingHTTPServer(...)` ET `serve_forever()` ont
        bien été atteints."""
        import cadre.coffre_fort as cf
        import cadre.dashboard as m

        monkeypatch.setattr(cf, "secret_or_none", lambda cle: "bonmdp")

        appels: list[str] = []

        class ServeurFactice:
            def __init__(self, *a, **k):
                appels.append("init")

            def serve_forever(self):
                appels.append("serve_forever")

        monkeypatch.setattr(m, "ThreadingHTTPServer", ServeurFactice)
        m.lancer_dashboard(
            bind="0.0.0.0", repertoire_rapports=tmp_path, fichier_log=tmp_path / "l.json"
        )
        assert appels == ["init", "serve_forever"]

    def test_loopback_ne_requiert_toujours_rien(self, monkeypatch, tmp_path):
        """127.0.0.1 (défaut) reste sans authentification obligatoire --
        comportement inchangé pour l'usage solo local. Même renfort que
        ci-dessus : `appels` prouve que le serveur factice a réellement
        été instancié et démarré, pas seulement qu'aucune exception n'a
        été levée."""
        import cadre.coffre_fort as cf
        import cadre.dashboard as m

        monkeypatch.setattr(cf, "secret_or_none", lambda cle: None)

        appels: list[str] = []

        class ServeurFactice:
            def __init__(self, *a, **k):
                appels.append("init")

            def serve_forever(self):
                appels.append("serve_forever")

        monkeypatch.setattr(m, "ThreadingHTTPServer", ServeurFactice)
        m.lancer_dashboard(
            bind="127.0.0.1", repertoire_rapports=tmp_path, fichier_log=tmp_path / "l.json"
        )
        assert appels == ["init", "serve_forever"]
