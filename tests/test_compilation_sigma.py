"""
Tests pour la compilation et validation Sigma.
"""

import json

import pytest

from cadre.attente_indexation import ErreurComptageElastic
from cadre.compilation_sigma import (
    FORMATS_SORTIE,
    _phraser_wildcard_multimots,
    compiler_regles_multi,
    compiler_sigma_vers_lucene,
    double_validation_tp_fp,
    formats_sortie_disponibles,
    valider_bruit_seul,
    valider_syntaxe_lucene,
)

REGLE_SIGMA_MINIMALE = """title: Test CADRE
id: 11111111-1111-1111-1111-111111111111
status: experimental
description: Règle de test
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\cmd.exe'
  condition: selection
level: low
"""

REGLE_SIGMA_EVENT_CODE = """title: Test CADRE (event.code direct)
id: 22222222-2222-2222-2222-222222222222
status: experimental
description: Règle de test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    event.code: 1
    process.command_line|contains: CADRE_TEST_MARKER
  condition: selection
level: low
"""

REGLE_SIGMA_POWERSHELL_MULTIMOTS = """title: Test CADRE (PowerShell, motif multi-mots)
id: 33333333-3333-3333-3333-333333333333
status: experimental
description: Règle de test
logsource:
  product: windows
  service: powershell
detection:
  selection:
    event.code: 4104
    powershell.file.script_block_text|contains: 'Windows Defender\\Real-Time Protection'
  condition: selection
level: low
"""

REGLE_SIGMA_POWERSHELL_MONOMOT = """title: Test CADRE (PowerShell, motif mono-mot)
id: 44444444-4444-4444-4444-444444444444
status: experimental
description: Règle de test
logsource:
  product: windows
  service: powershell
detection:
  selection:
    event.code: 4104
    powershell.file.script_block_text|contains: WinDefend
  condition: selection
level: low
"""

REGLE_SIGMA_COMMAND_LINE_MULTIMOTS = """title: Test CADRE (process.command_line, motif multi-mots)
id: 55555555-5555-5555-5555-555555555555
status: experimental
description: Règle de test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    event.code: 1
    process.command_line|contains: 'save HKLM\\SAM'
  condition: selection
level: low
"""

REGLE_SIGMA_POWERSHELL_OR_GROUPE = """title: Test CADRE (PowerShell, contains OR groupé)
id: 66666666-6666-6666-6666-666666666666
status: experimental
description: Règle de test
logsource:
  product: windows
  service: powershell
detection:
  selection:
    event.code: 4104
    powershell.file.script_block_text|contains:
      - 'download string'
      - 'invoke expression'
  condition: selection
level: low
"""


class TestValidationSyntaxeLucene:
    def test_requete_valide(self):
        valide, erreur = valider_syntaxe_lucene("event.code:4720")
        assert valide
        assert erreur is None

    def test_requete_vide(self):
        valide, erreur = valider_syntaxe_lucene("")
        assert not valide
        assert "vide" in erreur.lower()

    def test_guillemets_non_fermes(self):
        valide, erreur = valider_syntaxe_lucene('event.code:"4720')
        assert not valide
        assert "guillemet" in erreur.lower()

    def test_guillemets_echappes_sont_valides(self):
        """Un guillemet échappé (\\") est un littéral valide et ne doit pas
        compter dans l'équilibre — régression : une requête pourtant valide
        (valeur de détection contenant un guillemet, ex. commande Windows
        normalisée `rundll32.exe" /?`) était rejetée en SYNTAXE_INVALIDE."""
        requete = r"event.code:1 AND process.command_line:*rundll32.exe\"\ \/?*"
        valide, erreur = valider_syntaxe_lucene(requete)
        assert valide, erreur

    def test_guillemet_echappe_seul_reste_invalide(self):
        # Un vrai guillemet non échappé restant doit toujours être rejeté.
        valide, _ = valider_syntaxe_lucene(r'event.code:1 AND x:*a\"b"c*')
        assert not valide

    def test_parentheses_non_equilibrees(self):
        valide, erreur = valider_syntaxe_lucene("(event.code:4720")
        assert not valide
        assert "parenth" in erreur.lower()


class TestCompilationSigma:
    """
    Depuis v1.5.0, la compilation passe par l'API Python de pysigma en
    mémoire (plus de sous-processus `sigma-cli`) — ces tests exercent donc
    la vraie bibliothèque plutôt que de mocker subprocess.run.
    """

    def test_compilation_yaml_invalide(self):
        """Une règle YAML mal formée doit retourner None, jamais planter."""
        resultat = compiler_sigma_vers_lucene("ceci n'est pas du YAML valide: : :")
        assert resultat is None

    def test_compilation_regle_sans_champs_obligatoires(self):
        """Un YAML valide mais qui n'est pas une règle Sigma valide -> None."""
        resultat = compiler_sigma_vers_lucene("juste: une_map\nyaml: valide\n")
        assert resultat is None

    def test_compilation_regle_valide(self):
        resultat = compiler_sigma_vers_lucene(REGLE_SIGMA_MINIMALE)
        assert isinstance(resultat, str)
        assert "cmd.exe" in resultat

    def test_compilation_event_code_direct(self):
        resultat = compiler_sigma_vers_lucene(REGLE_SIGMA_EVENT_CODE)
        assert resultat == "event.code:1 AND process.command_line:*CADRE_TEST_MARKER*"

    def test_pipeline_inconnu(self):
        resultat = compiler_sigma_vers_lucene(
            REGLE_SIGMA_MINIMALE, pipeline="pipeline_qui_nexiste_pas"
        )
        assert resultat is None


class TestPhraserWildcardMultimots:
    """Un motif Sigma `contains` multi-mots (espace) compilé en wildcard
    Lucene (`champ:*a b*`) ne matche JAMAIS un champ Elasticsearch `text`
    analysé (le wildcard opère au niveau terme, pas phrase) -- même quand le
    texte est présent littéralement dans le document. Reproduit et vérifié
    en réel le 27/08 sur CADRE-EVA-001 : Faux Négatif (tp=0) malgré un
    document indexé contenant le texte exact. Comparaison directe contre
    Elasticsearch : wildcard = 0 résultat, phrase quotée = résultats.
    `_phraser_wildcard_multimots` réécrit automatiquement ce cas précis,
    uniquement pour les champs `text` connus (CHAMPS_TEXTE_ANALYSE)."""

    def test_fonction_isolee_motif_multimots(self):
        avant = "event.code:4104 AND powershell.file.script_block_text:*a\\ b*"
        apres = _phraser_wildcard_multimots(avant)
        assert apres == 'event.code:4104 AND powershell.file.script_block_text:"a b"'

    def test_fonction_isolee_motif_monomot_inchange(self):
        requete = "event.code:4104 AND powershell.file.script_block_text:*WinDefend*"
        assert _phraser_wildcard_multimots(requete) == requete

    def test_fonction_isolee_champ_hors_liste_inchange(self):
        """process.command_line n'est pas dans CHAMPS_TEXTE_ANALYSE (mappé
        `wildcard`, pas `text`) -- un wildcard multi-mots y fonctionne déjà
        correctement, ne doit jamais être réécrit."""
        requete = "event.code:1 AND process.command_line:*save\\ HKLM\\\\SAM*"
        assert _phraser_wildcard_multimots(requete) == requete

    def test_fonction_isolee_antislash_litteral_reechappe(self):
        """Cas réel CADRE-EVA-001 : la valeur contient un antislash littéral
        (chemin de registre). Doit ressortir doublé (échappement phrase
        Lucene), jamais perdu ni laissé simple."""
        avant = (
            "event.code:4104 AND "
            "powershell.file.script_block_text:*Windows\\ Defender\\\\Real\\-Time\\ Protection*"
        )
        apres = _phraser_wildcard_multimots(avant)
        assert (
            apres == "event.code:4104 AND "
            'powershell.file.script_block_text:"Windows Defender\\\\Real-Time Protection"'
        )

    def test_fonction_isolee_plusieurs_occurrences(self):
        """Robustesse générale de la fonction sur deux clauses `champ:*...*`
        RÉPÉTÉES et séparées (forme "plate") -- NOTE : ce n'est PAS la forme
        que pysigma produit réellement pour un `contains` OR sur le MÊME
        champ (toujours groupée, `champ:(*a* OR *b*)` -- voir les tests
        `*_forme_groupee_*` ci-dessous, seuls représentatifs d'un cas réel)."""
        requete = (
            "powershell.file.script_block_text:*a\\ b* OR "
            "powershell.file.script_block_text:*c\\ d*"
        )
        attendu = (
            'powershell.file.script_block_text:"a b" OR ' 'powershell.file.script_block_text:"c d"'
        )
        assert _phraser_wildcard_multimots(requete) == attendu

    def test_fonction_isolee_forme_groupee_deux_multimots(self):
        """Cas RÉEL (trouvé par revue indépendante, 27/08) : pysigma produit
        `champ:(*a* OR *b*)`, jamais `champ:*a* OR champ:*b*`, pour un
        `contains` avec plusieurs valeurs sur le même champ (convert_or_
        as_in=True côté backend Lucene) -- confirmé par compilation réelle."""
        requete = "powershell.file.script_block_text:(*a\\ b* OR *c\\ d*)"
        attendu = 'powershell.file.script_block_text:("a b" OR "c d")'
        assert _phraser_wildcard_multimots(requete) == attendu

    def test_fonction_isolee_forme_groupee_mixte(self):
        """Un groupe peut mélanger une alternative mono-mot et une
        multi-mots -- chacune doit être convertie indépendamment."""
        requete = "powershell.file.script_block_text:(*WinDefend* OR *a\\ b*)"
        attendu = 'powershell.file.script_block_text:(*WinDefend* OR "a b")'
        assert _phraser_wildcard_multimots(requete) == attendu

    def test_fonction_isolee_forme_groupee_champ_hors_liste_inchangee(self):
        requete = "process.command_line:(*save\\ HKLM* OR *reg\\ export*)"
        assert _phraser_wildcard_multimots(requete) == requete

    def test_compilation_bout_en_bout_multimots_devient_phrase(self):
        resultat = compiler_sigma_vers_lucene(REGLE_SIGMA_POWERSHELL_MULTIMOTS)
        assert resultat is not None
        assert "powershell.file.script_block_text:*" not in resultat
        assert 'powershell.file.script_block_text:"Windows Defender' in resultat

    def test_compilation_bout_en_bout_monomot_reste_wildcard(self):
        resultat = compiler_sigma_vers_lucene(REGLE_SIGMA_POWERSHELL_MONOMOT)
        assert resultat is not None
        assert "powershell.file.script_block_text:*WinDefend*" in resultat

    def test_compilation_bout_en_bout_command_line_reste_wildcard(self):
        """Non-régression : process.command_line (champ `wildcard`, pas
        `text`) garde son wildcard même avec un motif multi-mots -- le
        correctif ne doit toucher QUE les champs text analysés connus."""
        resultat = compiler_sigma_vers_lucene(REGLE_SIGMA_COMMAND_LINE_MULTIMOTS)
        assert resultat is not None
        assert "process.command_line:*save" in resultat
        assert '"' not in resultat

    def test_compilation_bout_en_bout_or_groupe_deux_multimots(self):
        """Cas réel (trouvé par revue indépendante, 27/08) : un `contains`
        avec une LISTE de valeurs sur powershell.file.script_block_text
        compile en `champ:(*a* OR *b*)` (jamais `champ:*a* OR champ:*b*`)
        -- doit ressortir en deux phrases quotées, pas en wildcards
        inchangés."""
        resultat = compiler_sigma_vers_lucene(REGLE_SIGMA_POWERSHELL_OR_GROUPE)
        assert resultat is not None
        assert "powershell.file.script_block_text:*" not in resultat
        assert '"download string"' in resultat
        assert '"invoke expression"' in resultat


class TestDoubleValidationTPFP:
    def _kwargs(self, **overrides):
        base = {
            "requete_lucene": "event.code:4688",
            "elastic_url": "http://localhost:9200",
            "auth": None,
        }
        base.update(overrides)
        return base

    def test_syntaxe_invalide_court_circuite(self, monkeypatch):
        appels = []
        monkeypatch.setattr(
            "cadre.compilation_sigma.compter_evenements",
            lambda *a, **k: appels.append(1) or 0,
        )
        valide, raison, _tp, _fp = double_validation_tp_fp(**self._kwargs(requete_lucene=""))
        assert valide is False
        assert raison.startswith("SYNTAXE_INVALIDE")
        assert appels == []  # jamais interrogé Elastic

    def test_faux_negatif_si_aucun_tp(self, monkeypatch):
        monkeypatch.setattr("cadre.compilation_sigma.time.sleep", lambda *_: None)
        monkeypatch.setattr("cadre.compilation_sigma.compter_evenements", lambda *a, **k: 0)
        valide, raison, tp, _fp = double_validation_tp_fp(**self._kwargs())
        assert valide is False
        assert raison == "FAUX_NEGATIF"
        assert tp == 0

    def test_faux_negatif_retry_recupere_un_tp_tardif(self, monkeypatch):
        """Un TP=0 transitoire (latence d'indexation) est retenté une fois
        avant de conclure à un Faux Négatif définitif."""
        monkeypatch.setattr("cadre.compilation_sigma.time.sleep", lambda *_: None)
        reponses = iter([0, 2, 1])  # 1er TP=0 (latence) -> retry TP=2 -> FP=1
        monkeypatch.setattr(
            "cadre.compilation_sigma.compter_evenements", lambda *a, **k: next(reponses)
        )
        valide, raison, tp, fp = double_validation_tp_fp(**self._kwargs(seuil_fp=50))
        assert valide is True
        assert raison == "OK"
        assert tp == 2
        assert fp == 1

    def test_rejete_si_trop_de_fp(self, monkeypatch):
        reponses = iter([5, 100])  # 5 TP puis 100 FP
        monkeypatch.setattr(
            "cadre.compilation_sigma.compter_evenements", lambda *a, **k: next(reponses)
        )
        valide, raison, tp, fp = double_validation_tp_fp(**self._kwargs(seuil_fp=50))
        assert valide is False
        assert raison.startswith("TROP_DE_FP")
        assert tp == 5
        assert fp == 100

    def test_validation_reussie(self, monkeypatch):
        reponses = iter([3, 2])  # 3 TP puis 2 FP
        monkeypatch.setattr(
            "cadre.compilation_sigma.compter_evenements", lambda *a, **k: next(reponses)
        )
        valide, raison, tp, fp = double_validation_tp_fp(**self._kwargs(seuil_fp=50))
        assert valide is True
        assert raison == "OK"
        assert tp == 3
        assert fp == 2

    def test_erreur_elasticsearch_pendant_mesure_tp_fail_closed(self, monkeypatch):
        """Régression sécurité : une panne ES pendant la mesure TP ne doit
        jamais être traitée comme un vrai 0 -- raison distincte de
        FAUX_NEGATIF pour ne pas confondre "mesure impossible" et "règle
        mauvaise" côté rapport (statut ERREUR, pas REJETE)."""
        monkeypatch.setattr("cadre.compilation_sigma.time.sleep", lambda *_: None)

        def echoue(*a, **k):
            raise ErreurComptageElastic("Elasticsearch injoignable")

        monkeypatch.setattr("cadre.compilation_sigma.compter_evenements", echoue)
        valide, raison, tp, fp = double_validation_tp_fp(**self._kwargs())
        assert valide is False
        assert raison == "ERREUR_ELASTICSEARCH"
        assert tp == 0
        assert fp == 0

    def test_erreur_elasticsearch_pendant_mesure_fp_fail_closed(self, monkeypatch):
        """LE cas critique de cette régression : une panne ES PENDANT la
        mesure FP (après un TP déjà réussi) ne doit JAMAIS se comporter
        comme "0 bruit" -- sans ce correctif, la règle aurait été validée
        et déployée SANS aucune preuve d'absence de faux positifs."""
        reponses = iter([3])  # TP=3 réussi, puis la mesure FP échoue

        def compte_puis_echoue(*a, **k):
            try:
                return next(reponses)
            except StopIteration:
                raise ErreurComptageElastic("Elasticsearch injoignable") from None

        monkeypatch.setattr("cadre.compilation_sigma.compter_evenements", compte_puis_echoue)
        valide, raison, tp, fp = double_validation_tp_fp(**self._kwargs(seuil_fp=50))
        assert valide is False
        assert raison == "ERREUR_ELASTICSEARCH"
        assert tp == 3  # le TP déjà mesuré est préservé dans le résultat
        assert fp == 0


class TestValiderBruitSeul:
    """Revalidation sans exigence de fraîcheur TP (revue différée) --
    jamais utilisée sur un contenu de détection réellement modifié."""

    def _kwargs(self, **overrides):
        base = {
            "requete_lucene": "event.code:4688",
            "elastic_url": "http://localhost:9200",
            "auth": None,
        }
        base.update(overrides)
        return base

    def test_syntaxe_invalide_court_circuite(self, monkeypatch):
        appels = []
        monkeypatch.setattr(
            "cadre.compilation_sigma.compter_evenements",
            lambda *a, **k: appels.append(1) or 0,
        )
        valide, raison, _fp = valider_bruit_seul(**self._kwargs(requete_lucene=""))
        assert valide is False
        assert raison.startswith("SYNTAXE_INVALIDE")
        assert appels == []  # jamais interrogé Elastic

    def test_jamais_de_requete_tp_une_seule_requete_fp(self, monkeypatch):
        """Le point central de la fonctionnalité : aucune interrogation de
        fenêtre TP fraîche, une seule requête FP."""
        appels = []

        def espion(*a, **k):
            appels.append(1)
            return 3  # FP=3

        monkeypatch.setattr("cadre.compilation_sigma.compter_evenements", espion)
        valide, raison, fp = valider_bruit_seul(**self._kwargs(seuil_fp=50))
        assert valide is True
        assert raison == "OK"
        assert fp == 3
        assert len(appels) == 1  # une seule requête (FP), jamais TP, jamais retry

    def test_rejete_si_trop_de_fp(self, monkeypatch):
        monkeypatch.setattr("cadre.compilation_sigma.compter_evenements", lambda *a, **k: 100)
        valide, raison, fp = valider_bruit_seul(**self._kwargs(seuil_fp=50))
        assert valide is False
        assert raison.startswith("TROP_DE_FP")
        assert fp == 100

    def test_fp_exactement_au_seuil_est_accepte(self, monkeypatch):
        monkeypatch.setattr("cadre.compilation_sigma.compter_evenements", lambda *a, **k: 50)
        valide, _raison, fp = valider_bruit_seul(**self._kwargs(seuil_fp=50))
        assert valide is True
        assert fp == 50

    def test_erreur_elasticsearch_fail_closed(self, monkeypatch):
        """Même régression que double_validation_tp_fp : une panne ES ici
        (revalidation d'une revue différée) ne doit jamais se comporter
        comme "0 bruit" -- sinon une revue serait approuvable sans jamais
        avoir pu prouver l'absence de faux positifs."""

        def echoue(*a, **k):
            raise ErreurComptageElastic("Elasticsearch injoignable")

        monkeypatch.setattr("cadre.compilation_sigma.compter_evenements", echoue)
        valide, raison, fp = valider_bruit_seul(**self._kwargs(seuil_fp=50))
        assert valide is False
        assert raison == "ERREUR_ELASTICSEARCH"
        assert fp == 0


class TestCompilationMultiFormat:
    def test_formats_disponibles(self):
        formats = formats_sortie_disponibles()
        assert {"lucene", "es-dsl", "kibana"} <= set(formats)
        assert all(isinstance(desc, str) and desc for desc in formats.values())

    def test_format_inconnu_retourne_none(self):
        assert compiler_regles_multi([REGLE_SIGMA_MINIMALE], "format_bidon") is None

    def test_liste_vide_retourne_none(self):
        assert compiler_regles_multi([], "lucene") is None

    def test_lucene_une_requete_par_regle(self):
        out = compiler_regles_multi([REGLE_SIGMA_MINIMALE, REGLE_SIGMA_EVENT_CODE], "lucene")
        assert out is not None
        assert len(out.strip().splitlines()) == 2

    def test_lucene_corrige_wildcard_multimots_texte_analyse(self):
        """Ce chemin (compiler_regles_multi) compile via son propre backend,
        sans passer par compiler_sigma_vers_lucene() -- le même correctif
        doit donc s'appliquer ici aussi, séparément."""
        out = compiler_regles_multi([REGLE_SIGMA_POWERSHELL_MULTIMOTS], "lucene")
        assert out is not None
        assert "powershell.file.script_block_text:*" not in out
        assert 'powershell.file.script_block_text:"Windows Defender' in out

    def test_kibana_corrige_wildcard_multimots_texte_analyse(self):
        out = compiler_regles_multi([REGLE_SIGMA_POWERSHELL_MULTIMOTS], "kibana")
        if out is None:
            pytest.skip("format kibana indisponible hors-ligne (données MITRE ATT&CK non chargées)")
        assert "powershell.file.script_block_text:*" not in out
        assert 'powershell.file.script_block_text:\\"Windows Defender' in out

    def test_kibana_resultat_sans_cle_query_ne_plante_pas(self, monkeypatch):
        """EXC4 : garde défensive isinstance(r.get('query'), str) -- un
        résultat de forme inattendue (pas de clé 'query', ou valeur non
        str) ne doit jamais faire planter la réécriture, seulement la
        sauter pour ce résultat."""
        from sigma.backends.elasticsearch import LuceneBackend

        monkeypatch.setattr(
            LuceneBackend,
            "convert",
            lambda self, c, output_format=None: [{"rule_id": "sans-cle-query"}],
        )
        out = compiler_regles_multi([REGLE_SIGMA_MINIMALE], "kibana")
        assert out is not None
        assert "sans-cle-query" in out

    def test_es_dsl_est_un_json_array(self):
        out = compiler_regles_multi([REGLE_SIGMA_MINIMALE], "es-dsl")
        data = json.loads(out)  # doit être un JSON valide
        assert isinstance(data, list) and len(data) == 1

    def test_kibana_est_un_ndjson(self):
        out = compiler_regles_multi([REGLE_SIGMA_MINIMALE, REGLE_SIGMA_EVENT_CODE], "kibana")
        # Le format kibana (siem_rule_ndjson) enrichit avec les données MITRE
        # ATT&CK que pysigma télécharge puis met en cache. Hors-ligne et sans
        # cache, compiler_regles_multi dégrade en None (comportement voulu,
        # vérifié par ailleurs) : on saute plutôt que d'échouer sur l'environnement.
        if out is None:
            pytest.skip("format kibana indisponible hors-ligne (données MITRE ATT&CK non chargées)")
        lignes = out.strip().splitlines()
        assert len(lignes) == 2
        for ligne in lignes:
            assert "rule_id" in json.loads(ligne)  # chaque ligne = objet JSON

    def test_pipeline_inconnu_retourne_none(self):
        """EXC4 : nom de pipeline invalide (distinct du format inconnu)."""
        assert compiler_regles_multi([REGLE_SIGMA_MINIMALE], "lucene", pipeline="bidon") is None

    def test_regle_invalide_retourne_none(self):
        """EXC4 : SigmaError (règle malformée) absorbée proprement."""
        regle_cassee = "title: Cassé\nceci n'est pas un YAML Sigma valide"
        assert compiler_regles_multi([regle_cassee], "lucene") is None

    def test_degradation_hors_ligne_mitre_absorbee(self, monkeypatch):
        """EXC4 : une exception mentionnant MITRE/urlopen (téléchargement
        pysigma hors-ligne) doit dégrader en None avec un message clair,
        sans dépendre de l'état réseau réel (comportement forcé ici)."""
        from sigma.backends.elasticsearch import LuceneBackend

        def convert_qui_leve(self, collection, output_format=None):
            raise RuntimeError("urlopen error: MITRE ATT&CK data unavailable")

        monkeypatch.setattr(LuceneBackend, "convert", convert_qui_leve)
        assert compiler_regles_multi([REGLE_SIGMA_MINIMALE], "kibana") is None

    def test_exception_generique_absorbee(self, monkeypatch):
        """EXC4 : une exception SANS rapport avec le hors-ligne doit aussi
        dégrader en None (branche 'inattendu')."""
        from sigma.backends.elasticsearch import LuceneBackend

        def convert_qui_leve(self, collection, output_format=None):
            raise RuntimeError("erreur totalement différente")

        monkeypatch.setattr(LuceneBackend, "convert", convert_qui_leve)
        assert compiler_regles_multi([REGLE_SIGMA_MINIMALE], "lucene") is None

    def test_resultats_vides_retourne_none(self, monkeypatch):
        """EXC4 : le backend renvoie une liste vide -> None, pas de crash."""
        from sigma.backends.elasticsearch import LuceneBackend

        monkeypatch.setattr(LuceneBackend, "convert", lambda self, c, output_format=None: [])
        assert compiler_regles_multi([REGLE_SIGMA_MINIMALE], "lucene") is None

    def test_table_formats_coherente(self):
        # Chaque format déclaré a un nom de fichier et une description non vides.
        for _nom, (output_format, fichier, desc, mode) in FORMATS_SORTIE.items():
            assert output_format and fichier and desc
            assert mode in ("lignes", "json_array", "ndjson")
