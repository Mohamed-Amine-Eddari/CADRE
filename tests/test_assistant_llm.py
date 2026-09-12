"""
Tests pour l'assistant LLM (src/cadre/assistant_llm.py).

Ollama n'est jamais réellement appelé : requests.get/post sont mockés.
Ces tests vérifient surtout la dégradation gracieuse (Ollama absent ne doit
jamais faire planter CADRE) et le fait que l'assistant ne produit que des
brouillons, jamais des objets insérés dans le catalogue.
"""

from __future__ import annotations

import json

import pytest

from cadre.assistant_llm import AssistantLLM, obtenir_assistant_llm


@pytest.fixture
def assistant():
    return AssistantLLM(url="http://ollama-test:11434", modele="test-model")


class TestConfiguration:
    def test_url_par_defaut_et_fallback_modele_si_serveur_injoignable(self, monkeypatch):
        import requests

        monkeypatch.delenv("CADRE_OLLAMA_URL", raising=False)
        monkeypatch.delenv("CADRE_OLLAMA_MODEL", raising=False)

        def get_qui_echoue(*a, **k):
            raise requests.exceptions.ConnectionError("pas de serveur")

        monkeypatch.setattr("requests.get", get_qui_echoue)
        a = AssistantLLM()
        assert a.url == "http://127.0.0.1:11434"
        # Serveur injoignable → auto-détection impossible → défaut historique
        assert a.modele == "llama3.1:8b"

    def test_auto_detection_choisit_un_modele_installe(self, monkeypatch):
        monkeypatch.delenv("CADRE_OLLAMA_MODEL", raising=False)

        class ReponseTags:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return {"models": [{"name": "qwen2.5-coder:7b"}, {"name": "mistral:7b"}]}

        monkeypatch.setattr("requests.get", lambda *a, **k: ReponseTags())
        a = AssistantLLM()
        # Aucun llama3 installé → préférence suivante (qwen2.5) retenue
        assert a.modele == "qwen2.5-coder:7b"

    def test_auto_detection_retente_si_liste_vide_puis_disponible(self, monkeypatch):
        """Régression : juste après un (re)démarrage d'Ollama, `/api/tags` peut
        répondre AVANT que le registre de modèles ne soit chargé (liste vide
        alors que le serveur est joignable et les modèles bel et bien
        installés). Comme la détection est mise en cache à vie (singleton),
        une seule tentative ratée au mauvais moment pinnait durablement le
        mauvais modèle (`llama3.1:8b`, jamais installé sur ce poste) pour
        toute la durée du processus. `_detecter_modele()` doit retenter avant
        d'abandonner."""
        monkeypatch.delenv("CADRE_OLLAMA_MODEL", raising=False)
        monkeypatch.setattr("time.sleep", lambda *_a, **_k: None)

        appels = {"n": 0}

        class ReponseTags:
            status_code = 200

            def __init__(self, modeles):
                self._modeles = modeles

            def raise_for_status(self):
                pass

            def json(self):
                return {"models": [{"name": m} for m in self._modeles]}

        def get_avec_liste_vide_puis_peuplee(*_a, **_k):
            appels["n"] += 1
            if appels["n"] < 3:
                return ReponseTags([])
            return ReponseTags(["qwen2.5-coder:7b"])

        monkeypatch.setattr("requests.get", get_avec_liste_vide_puis_peuplee)
        a = AssistantLLM()
        assert a.modele == "qwen2.5-coder:7b"
        assert appels["n"] == 3

    def test_auto_detection_racine_tags_non_objet_retombe_sur_defaut(self, monkeypatch):
        """Régression (audit) : `/api/tags` peut répondre 200 avec un JSON
        syntaxiquement valide mais dont la racine n'est pas un objet (ex.
        `null`, une liste) -- `.get("models", [])` levait alors AttributeError,
        non rattrapée (seuls RequestException/ValueError/KeyError l'étaient),
        empêchant même l'instanciation de AssistantLLM (donc `cadre suggest`/
        `cadre decouvrir`) avec une trace Python brute."""
        monkeypatch.delenv("CADRE_OLLAMA_MODEL", raising=False)
        monkeypatch.setattr("time.sleep", lambda *_a, **_k: None)

        class ReponseTagsNonObjet:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return None

        monkeypatch.setattr("requests.get", lambda *a, **k: ReponseTagsNonObjet())
        a = AssistantLLM()
        assert a.modele == "llama3.1:8b"

    def test_env_modele_prioritaire_sur_auto_detection(self, monkeypatch):
        monkeypatch.setenv("CADRE_OLLAMA_URL", "http://autre-hote:11434/")
        monkeypatch.setenv("CADRE_OLLAMA_MODEL", "mistral:7b")
        a = AssistantLLM()
        assert a.url == "http://autre-hote:11434"  # slash final retiré
        assert a.modele == "mistral:7b"

    def test_parametres_explicites_prioritaires(self, monkeypatch):
        monkeypatch.setenv("CADRE_OLLAMA_URL", "http://autre-hote:11434")
        a = AssistantLLM(url="http://explicite:11434", modele="explicite:1b")
        assert a.url == "http://explicite:11434"
        assert a.modele == "explicite:1b"


class TestDisponibilite:
    def test_disponible_si_ollama_repond(self, assistant, monkeypatch):
        class ReponseFactice:
            status_code = 200

        monkeypatch.setattr("requests.get", lambda *a, **k: ReponseFactice())
        assert assistant.disponible() is True

    def test_indisponible_si_erreur_reseau(self, assistant, monkeypatch):
        import requests

        def get_qui_echoue(*a, **k):
            raise requests.exceptions.ConnectionError("refused")

        monkeypatch.setattr("requests.get", get_qui_echoue)
        assert assistant.disponible() is False


class TestSuggererAttaque:
    def test_brouillon_valide(self, assistant, monkeypatch):
        brouillon_json = json.dumps(
            {
                "nom": "Dump SAM via reg.exe",
                "description": "Extraction de la base SAM",
                "technique_mitre": "T1003.002",
                "tactique_mitre": "Credential Access",
                "commande": "reg save HKLM\\SAM sam.save",
                "event_ids_attendus": ["4688"],
                "champ_principal": "process.command_line",
                "faux_positifs_connus": [],
                "niveau_risque": "medium",
            }
        )

        class ReponseFactice:
            def raise_for_status(self):
                pass

            def json(self):
                return {"response": brouillon_json}

        monkeypatch.setattr("requests.post", lambda *a, **k: ReponseFactice())
        resultat = assistant.suggerer_attaque("Dump de la base SAM via reg.exe save")

        assert resultat is not None
        assert resultat["technique_mitre"] == "T1003.002"
        assert resultat["brouillon_ia"] is True
        assert resultat["modele"] == "test-model"

    def test_technique_imposee_est_incluse_dans_le_prompt(self, assistant, monkeypatch):
        prompts_captures = []

        class ReponseFactice:
            def raise_for_status(self):
                pass

            def json(self):
                return {"response": "{}"}

        def post_qui_capture(url, json, timeout):
            prompts_captures.append(json["prompt"])
            return ReponseFactice()

        monkeypatch.setattr("requests.post", post_qui_capture)
        assistant.suggerer_attaque("comportement suspect", technique_mitre="T1059.001")

        assert "T1059.001" in prompts_captures[0]

    def test_ollama_injoignable_retourne_none(self, assistant, monkeypatch):
        import requests

        def post_qui_echoue(*a, **k):
            raise requests.exceptions.Timeout("délai dépassé")

        monkeypatch.setattr("requests.post", post_qui_echoue)
        assert assistant.suggerer_attaque("une attaque") is None

    def test_reponse_non_json_retourne_none(self, assistant, monkeypatch):
        class ReponseFactice:
            def raise_for_status(self):
                pass

            def json(self):
                return {"response": "ceci n'est pas du JSON valide"}

        monkeypatch.setattr("requests.post", lambda *a, **k: ReponseFactice())
        assert assistant.suggerer_attaque("une attaque") is None

    def test_reponse_json_non_objet_retourne_none(self, assistant, monkeypatch):
        class ReponseFactice:
            def raise_for_status(self):
                pass

            def json(self):
                return {"response": json.dumps(["pas", "un", "objet"])}

        monkeypatch.setattr("requests.post", lambda *a, **k: ReponseFactice())
        assert assistant.suggerer_attaque("une attaque") is None

    def test_reponse_vide_retourne_none(self, assistant, monkeypatch):
        class ReponseFactice:
            def raise_for_status(self):
                pass

            def json(self):
                return {"response": "   "}

        monkeypatch.setattr("requests.post", lambda *a, **k: ReponseFactice())
        assert assistant.suggerer_attaque("une attaque") is None

    def test_reponse_http_racine_non_objet_retourne_none(self, assistant, monkeypatch):
        """Régression (audit) : `r.json()` peut réussir (JSON syntaxiquement
        valide) sans renvoyer un objet -- ex. `null`, une liste, un serveur
        non-Ollama derrière la même URL. `.get("response", ...)` sur autre
        chose qu'un dict levait alors AttributeError, non rattrapée par
        `except ValueError` (pas une sous-classe) -- trace Python brute au
        lieu du None attendu par tous les appelants."""

        class ReponseFactice:
            def raise_for_status(self):
                pass

            def json(self):
                return None  # racine JSON "null", pas un objet

        monkeypatch.setattr("requests.post", lambda *a, **k: ReponseFactice())
        assert assistant.suggerer_attaque("une attaque") is None

    def test_reponse_http_racine_liste_retourne_none(self, assistant, monkeypatch):
        class ReponseFactice:
            def raise_for_status(self):
                pass

            def json(self):
                return ["reponse", "inattendue"]

        monkeypatch.setattr("requests.post", lambda *a, **k: ReponseFactice())
        assert assistant.suggerer_attaque("une attaque") is None


class TestSuggererRegleSigma:
    """Brouillon de règle Sigma comparatif — jamais compilé/validé/déployé."""

    def test_brouillon_genere_avec_en_tete_avertissement(self, assistant, monkeypatch):
        class ReponseFactice:
            def raise_for_status(self):
                pass

            def json(self):
                return {"response": "title: Suspicious Process\nstatus: experimental\n"}

        monkeypatch.setattr("requests.post", lambda *a, **k: ReponseFactice())
        brouillon = assistant.suggerer_regle_sigma(
            {"process": {"command_line": "whoami"}},
            {"technique_mitre": "T1059.001", "nom": "Test"},
        )

        assert brouillon is not None
        assert "BROUILLON GÉNÉRÉ PAR IA" in brouillon
        assert "NON VALIDÉ, NON DÉPLOYÉ" in brouillon
        assert "title: Suspicious Process" in brouillon

    def test_log_et_technique_dans_le_prompt(self, assistant, monkeypatch):
        prompts_captures = []

        class ReponseFactice:
            def raise_for_status(self):
                pass

            def json(self):
                return {"response": "title: x\n"}

        def post_qui_capture(url, json, timeout):
            prompts_captures.append(json["prompt"])
            return ReponseFactice()

        monkeypatch.setattr("requests.post", post_qui_capture)
        assistant.suggerer_regle_sigma(
            {"process": {"command_line": "whoami /marqueur-unique"}},
            {"technique_mitre": "T1059.001", "nom": "Découverte"},
        )

        assert "T1059.001" in prompts_captures[0]
        assert "whoami /marqueur-unique" in prompts_captures[0]

    def test_ollama_injoignable_retourne_none(self, assistant, monkeypatch):
        import requests

        monkeypatch.setattr(
            "requests.post",
            lambda *a, **k: (_ for _ in ()).throw(requests.exceptions.ConnectionError()),
        )
        resultat = assistant.suggerer_regle_sigma(
            {"process": {"command_line": "whoami"}}, {"technique_mitre": "T1059.001"}
        )
        assert resultat is None

    def test_exemple_windows_par_defaut_sans_plateforme(self, assistant, monkeypatch):
        """Sans `plateforme` dans le contexte (rétrocompat), l'exemple reste
        Windows -- comportement inchangé pour tout appelant existant."""
        prompts_captures = []

        class ReponseFactice:
            def raise_for_status(self):
                pass

            def json(self):
                return {"response": "title: x\n"}

        def post_qui_capture(url, json, timeout):
            prompts_captures.append(json["prompt"])
            return ReponseFactice()

        monkeypatch.setattr("requests.post", post_qui_capture)
        assistant.suggerer_regle_sigma(
            {"process": {"command_line": "whoami"}}, {"technique_mitre": "T1059.001"}
        )
        assert "product: windows" in prompts_captures[0]
        assert "process.title|contains" not in prompts_captures[0]

    def test_exemple_linux_quand_plateforme_linux(self, assistant, monkeypatch):
        """L'exemple de structure DOIT correspondre à la plateforme réelle --
        sinon un exemple toujours Windows/event.code ancre le LLM dessus même
        pour une attaque Linux (même défaut déjà corrigé dans
        suggerer_attaque() pour l'EventID)."""
        prompts_captures = []

        class ReponseFactice:
            def raise_for_status(self):
                pass

            def json(self):
                return {"response": "title: x\n"}

        def post_qui_capture(url, json, timeout):
            prompts_captures.append(json["prompt"])
            return ReponseFactice()

        monkeypatch.setattr("requests.post", post_qui_capture)
        assistant.suggerer_regle_sigma(
            {"process": {"title": "cat /etc/passwd"}},
            {"technique_mitre": "T1087.001", "nom": "Reconnaissance", "plateforme": "linux"},
        )
        assert "product: linux" in prompts_captures[0]
        assert "product: windows" not in prompts_captures[0]
        assert "process.title|contains" in prompts_captures[0]
        assert "event.code: '1'" not in prompts_captures[0]


class TestLogCompact:
    def test_extrait_les_champs_pertinents(self):
        from cadre.assistant_llm import _log_compact

        log = {
            "event": {"code": 1},
            "process": {
                "command_line": "systeminfo.exe /fo CSV",
                "name": "systeminfo.exe",
                "hash": {"sha256": "abc..."},  # bruit à écarter
            },
            "pe": {"company": "Microsoft"},  # bruit
        }
        compact = _log_compact(log)
        assert compact["event.code"] == 1
        assert compact["process.command_line"] == "systeminfo.exe /fo CSV"
        assert compact["process.name"] == "systeminfo.exe"
        # Le bruit (hash, pe) est écarté
        assert not any("hash" in k or "pe" in k for k in compact)

    def test_log_sans_champ_connu_retourne_le_log_entier(self):
        from cadre.assistant_llm import _log_compact

        log = {"champ_exotique": "x"}
        assert _log_compact(log) == log


class TestSuggererRegleSigmaDeployable:
    """Règle candidate au déploiement : YAML propre, sans en-tête ni balises."""

    def _mock_reponse(self, monkeypatch, contenu):
        class R:
            def raise_for_status(self):
                pass

            def json(self):
                return {"response": contenu}

        monkeypatch.setattr("requests.post", lambda *a, **k: R())

    def test_retire_en_tete_et_balises_markdown(self, assistant, monkeypatch):
        self._mock_reponse(
            monkeypatch,
            "```yaml\ntitle: Detection\nstatus: experimental\ndetection:\n  x: 1\n```",
        )
        regle = assistant.suggerer_regle_sigma_deployable(
            {"process": {"command_line": "whoami"}}, {"technique_mitre": "T1059.001"}
        )
        assert regle is not None
        assert regle.startswith("title: Detection")  # pas d'en-tête, pas de ```
        assert "```" not in regle
        assert "BROUILLON" not in regle

    def test_ollama_injoignable_retourne_none(self, assistant, monkeypatch):
        import requests

        monkeypatch.setattr(
            "requests.post",
            lambda *a, **k: (_ for _ in ()).throw(requests.exceptions.ConnectionError()),
        )
        assert (
            assistant.suggerer_regle_sigma_deployable(
                {"process": {"command_line": "x"}}, {"technique_mitre": "T1"}
            )
            is None
        )

    def test_uuid_invalide_du_llm_est_remplace(self, assistant, monkeypatch):
        # UUID halluciné avec un 'g' non hexadécimal → doit être remplacé
        self._mock_reponse(
            monkeypatch,
            "title: X\nid: d3b54f6c-8a2b-4d7e-a9b1-f4c2d3e4f5g6\ndetection:\n  x: 1\n",
        )
        regle = assistant.suggerer_regle_sigma_deployable(
            {"process": {"command_line": "x"}}, {"technique_mitre": "T1"}
        )
        import uuid as uuid_mod

        ligne_id = next(ligne for ligne in regle.splitlines() if ligne.startswith("id:"))
        valeur_id = ligne_id.split("id:", 1)[1].strip()
        uuid_mod.UUID(valeur_id)  # ne lève pas → UUID valide
        assert "f5g6" not in regle


class TestResumerCycle:
    def test_aucun_resultat_retourne_none(self, assistant):
        assert assistant.resumer_cycle([]) is None

    def test_synthese_generee(self, assistant, monkeypatch):
        class ReponseFactice:
            def raise_for_status(self):
                pass

            def json(self):
                return {"response": "3 attaques testées, 2 règles validées."}

        monkeypatch.setattr("requests.post", lambda *a, **k: ReponseFactice())
        resultats = [
            {"technique_mitre": "T1059.001", "statut": "VALIDE"},
            {"technique_mitre": "T1136.001", "statut": "VALIDE"},
            {"technique_mitre": "T1003.002", "statut": "REJETE"},
        ]
        resume = assistant.resumer_cycle(resultats)
        assert resume == "3 attaques testées, 2 règles validées."

    def test_donnees_reelles_dans_le_prompt(self, assistant, monkeypatch):
        prompts_captures = []

        class ReponseFactice:
            def raise_for_status(self):
                pass

            def json(self):
                return {"response": "ok"}

        def post_qui_capture(url, json, timeout):
            prompts_captures.append(json["prompt"])
            return ReponseFactice()

        monkeypatch.setattr("requests.post", post_qui_capture)
        resultats = [{"technique_mitre": "T1059.001", "statut": "VALIDE"}]
        assistant.resumer_cycle(resultats)

        assert "T1059.001" in prompts_captures[0]
        assert "Attaques testées : 1" in prompts_captures[0]

    def test_ollama_injoignable_retourne_none(self, assistant, monkeypatch):
        import requests

        monkeypatch.setattr(
            "requests.post",
            lambda *a, **k: (_ for _ in ()).throw(requests.exceptions.ConnectionError()),
        )
        resultats = [{"technique_mitre": "T1059.001", "statut": "VALIDE"}]
        assert assistant.resumer_cycle(resultats) is None


class TestAnalyserAnglesMorts:
    def test_aucun_angle_mort_retourne_none(self, assistant):
        resultats = [{"technique_mitre": "T1059.001", "statut": "VALIDE"}]
        assert assistant.analyser_angles_morts(resultats) is None

    def test_analyse_generee_pour_angles_morts(self, assistant, monkeypatch):
        class ReponseFactice:
            def raise_for_status(self):
                pass

            def json(self):
                return {"response": "Vérifiez la configuration Sysmon."}

        monkeypatch.setattr("requests.post", lambda *a, **k: ReponseFactice())
        resultats = [
            {
                "technique_mitre": "T1003.002",
                "statut": "ANGLE_MORT",
                "event_ids_attendus": ["4688"],
            }
        ]
        analyse = assistant.analyser_angles_morts(resultats)
        assert analyse == "Vérifiez la configuration Sysmon."


class TestExpliquerRejets:
    """B4 : symétrique à TestAnalyserAnglesMorts, même garde-fous."""

    def test_aucun_rejet_retourne_none(self, assistant):
        resultats = [{"technique_mitre": "T1059.001", "statut": "VALIDE"}]
        assert assistant.expliquer_rejets(resultats) is None

    def test_explication_generee_pour_rejets(self, assistant, monkeypatch):
        class ReponseFactice:
            def raise_for_status(self):
                pass

            def json(self):
                return {"response": "Ajoutez un filtre sur le processus parent."}

        monkeypatch.setattr("requests.post", lambda *a, **k: ReponseFactice())
        resultats = [
            {
                "technique_mitre": "T1059.001",
                "statut": "REJETE",
                "nb_tp": 1,
                "nb_fp": 87,
                "raison": "Trop de faux positifs (87 > seuil 50)",
            }
        ]
        explication = assistant.expliquer_rejets(resultats)
        assert explication == "Ajoutez un filtre sur le processus parent."


class TestSingleton:
    def test_obtenir_assistant_llm_retourne_la_meme_instance(self, monkeypatch):
        monkeypatch.setattr("cadre.assistant_llm._assistant_instance", None)
        premiere = obtenir_assistant_llm()
        deuxieme = obtenir_assistant_llm()
        assert premiere is deuxieme


class _LoggerFactice:
    """Journal minimal capturant les messages, pour vérifier les avertissements."""

    def __init__(self):
        self.warnings: list[str] = []
        self.infos: list[str] = []
        self.debugs: list[str] = []

    def warn(self, m):
        self.warnings.append(str(m))

    def info(self, m):
        self.infos.append(str(m))

    def debug(self, m):
        self.debugs.append(str(m))

    def error(self, m):
        pass


def _capturer_payload(assistant, monkeypatch, appel):
    """Exécute `appel(assistant)` en capturant le payload POST envoyé à Ollama."""
    captures: list[dict] = []

    class R:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": "title: x\ndetection:\n  x: 1\n"}

    def post(url, json, timeout):
        captures.append(json)
        return R()

    monkeypatch.setattr("requests.post", post)
    appel(assistant)
    return captures[0]


class TestGardeFous:
    """Verrouille les 6 garde-fous de l'usage LLM (voir LLM/2-garde-fous.md)."""

    def test_gf1_url_non_locale_declenche_avertissement(self, monkeypatch):
        """Garde-fou 1 : un LLM non loopback (cloud) doit être signalé fort."""
        faux = _LoggerFactice()
        monkeypatch.setattr("cadre.assistant_llm.obtenir_logger", lambda: faux)
        AssistantLLM(url="http://llm-distant.example.com:11434", modele="m")
        assert any("NON LOCAL" in w for w in faux.warnings)

    def test_gf1_url_loopback_ne_declenche_aucun_avertissement(self, monkeypatch):
        faux = _LoggerFactice()
        monkeypatch.setattr("cadre.assistant_llm.obtenir_logger", lambda: faux)
        AssistantLLM(url="http://127.0.0.1:11434", modele="m")
        assert not any("NON LOCAL" in w for w in faux.warnings)

    def test_gf1_est_url_locale(self):
        from cadre.assistant_llm import _est_url_locale

        assert _est_url_locale("http://127.0.0.1:11434") is True
        assert _est_url_locale("http://localhost:11434") is True
        assert _est_url_locale("http://[::1]:11434") is True
        assert _est_url_locale("http://192.168.56.1:11434") is False
        assert _est_url_locale("https://api.openai.com") is False

    def test_gf3_telemetrie_delimitee_comme_donnee_non_fiable(self, assistant, monkeypatch):
        """Garde-fou 3 : la télémétrie injectée est encadrée + marquée « donnée »."""
        payload = _capturer_payload(
            assistant,
            monkeypatch,
            lambda a: a.suggerer_regle_sigma(
                {"process": {"command_line": "whoami"}},
                {"technique_mitre": "T1059.001", "nom": "Test"},
            ),
        )
        prompt = payload["prompt"]
        assert "<<<DONNEES>>>" in prompt
        assert "<<<FIN_DONNEES>>>" in prompt
        assert "JAMAIS à exécuter" in prompt
        # La valeur réelle reste bien présente à l'intérieur du bloc.
        assert "whoami" in prompt

    def test_gf3_description_operateur_delimitee(self, assistant, monkeypatch):
        payload = _capturer_payload(
            assistant,
            monkeypatch,
            lambda a: a.suggerer_attaque("dump SAM"),
        )
        assert "<<<DONNEES>>>" in payload["prompt"]

    def test_gf5_payload_contient_parametres_deterministes(self, assistant, monkeypatch):
        """Garde-fou 5 : température basse + seed fixe envoyés à Ollama."""
        from cadre.assistant_llm import (
            SEED_GENERATION,
            TEMPERATURE_GENERATION,
            TOP_P_GENERATION,
        )

        payload = _capturer_payload(assistant, monkeypatch, lambda a: a._generer("prompt test"))
        opts = payload["options"]
        assert opts["temperature"] == TEMPERATURE_GENERATION
        assert opts["temperature"] <= 0.3  # basse par construction
        assert opts["seed"] == SEED_GENERATION
        assert isinstance(opts["seed"], int)
        assert opts["top_p"] == TOP_P_GENERATION
        assert payload["stream"] is False

    def test_gf5_journal_audit_emis_sans_contenu_du_prompt(self, monkeypatch):
        """Garde-fou 5 : trace d'audit (modèle+empreinte) sans fuite du prompt."""
        faux = _LoggerFactice()
        monkeypatch.setattr("cadre.assistant_llm.obtenir_logger", lambda: faux)

        class R:
            def raise_for_status(self):
                pass

            def json(self):
                return {"response": "ok"}

        monkeypatch.setattr("requests.post", lambda *a, **k: R())
        a = AssistantLLM(url="http://127.0.0.1:11434", modele="m")
        a._generer("un prompt secret contenant whoami")
        trace = " ".join(faux.infos)
        assert "prompt_sha256=" in trace
        assert "modele=m" in trace
        # Le contenu du prompt ne doit jamais apparaître dans le journal.
        assert "whoami" not in trace

    def test_gf5_modele_auto_detecte_marque_non_epingle(self, monkeypatch):
        monkeypatch.delenv("CADRE_OLLAMA_MODEL", raising=False)

        class ReponseTags:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return {"models": [{"name": "qwen2.5-coder:7b"}]}

        monkeypatch.setattr("requests.get", lambda *a, **k: ReponseTags())
        a = AssistantLLM()
        assert a._modele_epingle is False

    def test_gf5_modele_explicite_marque_epingle(self):
        a = AssistantLLM(url="http://127.0.0.1:11434", modele="qwen2.5-coder:7b")
        assert a._modele_epingle is True

    def test_gf6_module_n_importe_aucun_outil_anonymisation(self):
        """Garde-fou 6 : le LLM n'anonymise rien — il ne reçoit que du déjà-anonymisé."""
        import inspect

        import cadre.assistant_llm as mod

        lignes_import = [
            ligne
            for ligne in inspect.getsource(mod).splitlines()
            if ligne.strip().startswith(("import ", "from "))
        ]
        assert not any("anonymis" in ligne.lower() for ligne in lignes_import)
