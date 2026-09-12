"""
Tests du module d'anonymisation RGPD.
"""

import re

from cadre.anonymisation import (
    CHAMPS_SENSIBLES,
    PATTERNS_PII,
    _hash_deterministe,
    anonymiser_chaine,
    anonymiser_dict,
    anonymiser_log_elastic,
)


class TestHashDeterministe:
    """Tests de la fonction de hash déterministe."""

    def test_meme_entree_meme_hash(self):
        h1 = _hash_deterministe("192.168.1.100")
        h2 = _hash_deterministe("192.168.1.100")
        assert h1 == h2

    def test_entrees_differentes_hashes_differents(self):
        h1 = _hash_deterministe("192.168.1.100")
        h2 = _hash_deterministe("192.168.1.101")
        assert h1 != h2

    def test_hash_anon_prefixe(self):
        h = _hash_deterministe("test")
        assert h.startswith("ANON-")

    def test_hash_longueur(self):
        h = _hash_deterministe("test")
        # Format : ANON-XXXXXXXXXXXX (5 caractères "ANON-" + 12 hex)
        assert len(h) == len("ANON-") + 12
        assert h.startswith("ANON-")

    def test_sel_different_donne_un_hash_different(self):
        """Un sel différent doit produire un hash différent pour la même entrée."""
        h1 = _hash_deterministe("test", sel="sel1")
        h2 = _hash_deterministe("test", sel="sel2")
        assert h1 != h2


class TestAnonymiserChaine:
    """Tests de l'anonymisation d'une chaîne."""

    def test_anonymiser_ipv4(self):
        resultat = anonymiser_chaine("Connexion depuis 192.168.1.100")
        assert "192.168.1.100" not in resultat
        assert "[IPV4_ANONYMISE]" in resultat

    def test_anonymiser_email(self):
        resultat = anonymiser_chaine("Contact: alice@example.com")
        assert "alice@example.com" not in resultat
        assert "[EMAIL_ANONYMISE]" in resultat

    def test_anonymiser_username_windows(self):
        """Régression : l'assertion d'origine (`"alice@example.com" not in
        resultat`) était vacuement vraie -- aucun email n'apparaît dans
        l'entrée, elle ne prouvait donc rien sur l'anonymisation du couple
        domaine\\utilisateur lui-même. Assertions précises : le couple
        original a disparu ET l'étiquette attendue est bien présente."""
        resultat = anonymiser_chaine("Login: CORP\\alice")
        assert "CORP\\alice" not in resultat
        assert "[DOMAIN_ANONYMISE]" in resultat

    def test_anonymiser_md5(self):
        md5 = "5d41402abc4b2a76b9719d911017c592"  # pragma: allowlist secret
        resultat = anonymiser_chaine(f"hash: {md5}")
        assert md5 not in resultat
        assert "[MD5_ANONYMISE]" in resultat

    def test_anonymiser_ntlm_pas_ecrase_par_md5(self):
        """Régression : `md5` (32 hex, générique) s'exécutait avant `ntlm`
        (32hex:32hex) -- le ':' crée une frontière de mot que `md5` matchait
        des deux côtés indépendamment, laissant `ntlm` sans jamais rien à
        matcher (code mort) et une étiquette [MD5_ANONYMISE]:[MD5_ANONYMISE]
        au lieu de [NTLM_ANONYMISE]. Pas une fuite (toujours anonymisé), mais
        le mauvais type de secret est rapporté."""
        # pragma: allowlist nextline secret
        ntlm = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        resultat = anonymiser_chaine(f"ntlm: {ntlm}")
        assert ntlm not in resultat
        assert "[NTLM_ANONYMISE]" in resultat
        assert "[MD5_ANONYMISE]" not in resultat

    def test_anonymiser_sha1(self):
        sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"  # pragma: allowlist secret
        resultat = anonymiser_chaine(f"sha1: {sha1}")
        assert sha1 not in resultat
        assert "[SHA1_ANONYMISE]" in resultat

    def test_anonymiser_sha256(self):
        # pragma: allowlist nextline secret
        sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        resultat = anonymiser_chaine(f"sha256: {sha256}")
        assert sha256 not in resultat
        assert "[SHA256_ANONYMISE]" in resultat

    def test_anonymiser_bearer_token(self):
        token = "Bearer abc123def456ghi789jkl012mno345pqr"  # pragma: allowlist secret
        resultat = anonymiser_chaine(f"Authorization: {token}")
        assert "abc123def456" not in resultat  # pragma: allowlist secret
        assert "[BEARER_TOKEN_ANONYMISE]" in resultat

    def test_anonymiser_jwt(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        resultat = anonymiser_chaine(f"token: {jwt}")
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in resultat

    def test_anonymiser_bearer_avec_vrai_jwt_ne_fait_pas_fuiter_le_payload(self):
        """Régression : `bearer_token` (générique, sans '.' dans sa classe de
        caractères) s'exécutait avant `jwt` (3 segments séparés par '.') --
        il ne consommait que le 1er segment du JWT, laissant le payload (qui
        peut contenir un nom, un sub id...) et la signature en clair juste
        après. Le payload ci-dessous décode en {"sub":"1234567890","name":
        "John Doe"} -- "John Doe" ne doit jamais apparaître dans le résultat,
        même encodé en base64url, sous aucune forme reconnaissable."""
        # pragma: allowlist nextline secret
        payload_b64 = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
        signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  # pragma: allowlist secret
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" f".{payload_b64}" f".{signature}"
        resultat = anonymiser_chaine(f"Authorization: Bearer {jwt}")
        assert payload_b64 not in resultat
        assert signature not in resultat
        assert "[JWT_ANONYMISE]" in resultat

    def test_anonymiser_password(self):
        resultat = anonymiser_chaine("password=SuperSecret123")
        # CADRE hash le password (corrélation) ou utilise un placeholder
        assert "SuperSecret123" not in resultat
        assert "[PASSWORD_ANONYMISE]" in resultat or "ANON-" in resultat

    def test_anonymiser_chemin_windows(self):
        resultat = anonymiser_chaine("Log file: C:\\Users\\alice\\AppData\\test.log")
        # Le username dans le chemin Windows est hashé (ANON-XXXX)
        assert "alice" not in resultat
        assert "[WINDOWS_PATH_ANONYMISE]" in resultat or "ANON-" in resultat

    def test_anonymiser_texte_sans_pii(self):
        """Un texte sans PII doit rester EXACTEMENT inchangé -- une simple
        sous-chaîne qui survit (assertion d'origine) n'exclut pas qu'une
        AUTRE partie du texte ait été altérée à tort."""
        texte = "Audit terminé avec succès"
        resultat = anonymiser_chaine(texte)
        assert resultat == texte

    def test_chaine_vide(self):
        assert anonymiser_chaine("") == ""

    def test_non_string_passe(self):
        """Une valeur non-chaîne (None, int...) doit être renvoyée telle
        quelle -- anonymiser_chaine ne s'applique qu'au texte."""
        assert anonymiser_chaine(None) is None
        assert anonymiser_chaine(42) == 42

    def test_anonymiser_plusieurs_pii(self):
        """Plusieurs PII dans la même chaîne doivent tous être anonymisés."""
        texte = "User alice@corp.com (192.168.1.50) logged in"
        resultat = anonymiser_chaine(texte)
        assert "alice@corp.com" not in resultat
        assert "192.168.1.50" not in resultat


class TestAnonymiserDict:
    """Tests de l'anonymisation d'un dictionnaire."""

    def test_champ_user_name(self):
        log = {"user.name": "alice", "event.code": 4720}
        resultat = anonymiser_dict(log)
        # CADRE utilise un hash déterministe (ANON-XXXX) pour préserver la corrélation
        assert resultat["user.name"] != "alice"
        assert resultat["user.name"].startswith("ANON-")
        assert resultat["event.code"] == 4720  # Non touché

    def test_champ_host_ip(self):
        log = {"host.ip": "192.168.1.100", "@timestamp": "2026-07-16"}
        resultat = anonymiser_dict(log)
        # host.ip matche le pattern IPV4 → placeholder [IPV4_ANONYMISE]
        assert resultat["host.ip"] == "[IPV4_ANONYMISE]"
        assert resultat["@timestamp"] == "2026-07-16"

    def test_champ_password(self):
        # Le pattern password requiert un préfixe explicite (password=secret)
        # Pour un password en clair dans une commande, on s'attend à ce qu'il soit
        # soit matché, soit laissé tel quel (limitation connue).
        log = {"process.command_line": "password=MyP@ss123"}
        resultat = anonymiser_dict(log)
        # Avec préfixe "password=", le pattern matche et le mot de passe est anonymisé
        assert "MyP@ss123" not in resultat["process.command_line"]

    def test_champs_non_sensibles_preservees(self):
        log = {
            "event.code": 4720,
            "@timestamp": "2026-07-16T20:00:00",
            "level": "high",
        }
        resultat = anonymiser_dict(log)
        # Les champs non-sensibles (event.code, @timestamp, level) sont préservés
        assert resultat["event.code"] == 4720
        assert resultat["@timestamp"] == "2026-07-16T20:00:00"
        assert resultat["level"] == "high"

    def test_valeur_non_string(self):
        """Les valeurs non-string (int, bool, list) doivent être préservées."""
        log = {"event.code": 4720, "level": "high", "tags": ["a", "b"]}
        resultat = anonymiser_dict(log)
        assert resultat["event.code"] == 4720
        assert resultat["tags"] == ["a", "b"]

    def test_recursion_profonde(self):
        # Nesting RÉEL (process.parent.command_line, 3 niveaux ECS réels) --
        # pas une clé synthétique à point littéral (`{"a": {"b": {"x.y": ...}}}`,
        # qui ne correspond à aucun document Elasticsearch réel).
        doc = {"process": {"parent": {"command_line": "net user alice@corp.local /add"}}}
        resultat = anonymiser_dict(doc)
        assert "alice@corp.local" not in str(resultat)

    def test_champ_sensible_imbrique_est_anonymise(self):
        """Régression critique : un document Elasticsearch réel est imbriqué
        (`{"user": {"name": "alice"}}`), jamais à clés plates
        (`{"user.name": "alice"}`). CHAMPS_SENSIBLES contient des chemins à
        points ("user.name") qui doivent matcher le CHEMIN RECONSTRUIT
        pendant la récursion, pas la clé du dernier niveau seule ("name",
        qui n'existe isolément dans aucune liste de champs sensibles) --
        sinon la PII traverse l'anonymisation sans être détectée."""
        doc = {"user": {"name": "alice", "domain": "CORP"}, "event": {"code": 4720}}
        resultat = anonymiser_dict(doc)
        assert resultat["user"]["name"] != "alice"
        assert resultat["user"]["name"].startswith("ANON-")
        assert resultat["user"]["domain"] != "CORP"
        assert resultat["event"]["code"] == 4720  # non-sensible, préservé

    def test_champs_a_garder_respecte_le_chemin_complet_imbrique(self):
        """Même bug que ci-dessus, côté `champs_a_garder` : sans chemin
        complet, "command_line" (clé du dernier niveau seule) ne matche
        jamais "process.parent.command_line", et la valeur finit quand même
        passée à `anonymiser_chaine` -- qui la modifie si elle contient une
        IP/un email/etc., malgré la demande explicite de la préserver."""
        doc = {"process": {"parent": {"command_line": "ping 10.0.0.5"}}}
        resultat = anonymiser_dict(doc, champs_a_garder={"process.parent.command_line"})
        assert resultat["process"]["parent"]["command_line"] == "ping 10.0.0.5"

    def test_profondeur_max(self):
        """Doit s'arrêter proprement si la profondeur est excessive --
        SANS jamais renvoyer le sous-document brut (fail-closed, pas
        fail-open : voir test_profondeur_max_ne_fuit_jamais_la_pii ci-dessous
        pour le scénario de fuite que ce comportement empêche)."""
        doc = {"a": {"b": {"c": {"d": "test"}}}}
        resultat = anonymiser_dict(doc, profondeur_max=0)
        assert resultat != doc
        assert resultat == {"_profondeur_max_atteinte": "[PROFONDEUR_MAX_ANONYMISE]"}

    def test_profondeur_max_ne_fuit_jamais_la_pii(self):
        """Régression (audit) : `_anonymiser_dict_recursif` renvoyait le
        sous-document BRUT (fail-open) dès que `profondeur_max` était
        atteint -- même une PII reconnaissable par pattern (IP, email...),
        qui aurait normalement été redigée par `anonymiser_chaine` si la
        récursion avait continué normalement, fuyait intégralement en clair
        car TOUT le sous-arbre à cette profondeur court-circuitait le
        traitement champ par champ. Un document Elasticsearch anormalement
        imbriqué (malformé, ou façonné par un attaquant -- un champ
        arbitraire type ScriptBlock/registre peut contenir un JSON structuré
        arbitrairement profond) n'a besoin que de dépasser la profondeur par
        défaut (10) pour que ce chemin fail-open s'exerce."""
        ip_sensible = "203.0.113.77"
        doc: dict = {"valeur": ip_sensible}
        for _ in range(12):  # dépasse largement profondeur_max=10 (défaut)
            doc = {"niveau": doc}

        resultat = anonymiser_dict(doc)

        import json

        assert ip_sensible not in json.dumps(resultat)


class TestAnonymiserLogElastic:
    """Tests spécifiques au format Elastic Common Schema (ECS)."""

    def test_log_ecs_complet(self):
        # Format plat avec les noms de champs ECS complets (en pointillés)
        log = {
            "@timestamp": "2026-07-16T20:00:00.000Z",
            "event.code": 4720,
            "host.name": "VM-Win10",
            "host.ip": "192.168.1.100",
            "user.name": "alice",
            "user.domain": "CORP",
            "process.name": "net.exe",
            "process.command_line": "net user test /add",
            "source.ip": "10.0.0.50",
        }
        resultat = anonymiser_log_elastic(log)
        # Les PII doivent être masqués (hash déterministe ou placeholder)
        assert resultat["host.ip"] == "[IPV4_ANONYMISE]"
        assert resultat["user.name"] != "alice"  # hash
        assert resultat["user.name"].startswith("ANON-")
        assert "192.168.1.100" not in str(resultat)
        assert "10.0.0.50" not in str(resultat)
        # Les non-PII doivent être préservés
        assert resultat["event.code"] == 4720
        # host.name est anonymisé (champ sensible)
        assert resultat["host.name"] != "VM-Win10"

    def test_log_avec_pii_dans_commande(self):
        # Le pattern password requiert un préfixe explicite
        log = {
            "process.command_line": "net user admin password=SecretP@ss123 /add",
            "event.code": 4720,
        }
        resultat = anonymiser_log_elastic(log)
        # Avec le préfixe password=, le mot de passe doit être anonymisé
        assert "SecretP@ss123" not in str(resultat)

    def test_evenement_ids_non_anonymises(self):
        """Les EventIDs ne sont PAS des PII."""
        log = {"event.code": 4720, "event.action": "created-user-account"}
        resultat = anonymiser_log_elastic(log)
        assert resultat["event.code"] == 4720
        assert resultat["event.action"] == "created-user-account"

    def test_document_es_reel_imbrique_ne_fait_pas_fuiter_la_pii(self, log_elastic_exemple):
        """Régression critique : `orchestrateur.py` appelle
        `anonymiser_log_elastic()` directement sur `hits[0]["_source"]`, un
        document Elasticsearch RÉEL -- imbriqué (voir `conftest.py`,
        `log_elastic_exemple`, la même fixture que `test_orchestrateur.py`),
        jamais à clés plates. Avant correctif, `user.name`/`user.domain`/
        `user.email`/`host.name` n'étaient jamais reconnus comme sensibles
        sur un tel document (la clé du dernier niveau seule, "name"/"domain"/
        "email", n'apparaît isolément dans aucune liste de champs sensibles)
        et fuyaient en clair -- vers un LLM et/ou un fichier disque
        (`rules_generees/brouillons_ia/*.ia.yml`) selon la configuration."""
        resultat = anonymiser_log_elastic(log_elastic_exemple)

        # PII imbriquée : entièrement absente du résultat, à tous les niveaux.
        resultat_str = str(resultat)
        assert "alice" not in resultat_str.lower()
        assert "corp.com" not in resultat_str
        assert "CADRE-Victim" not in resultat_str
        assert "192.168.1.100" not in resultat_str
        assert "10.0.0.50" not in resultat_str

        # Corrélation/EventID préservés (le but de l'anonymisation n'est pas
        # de détruire l'utilité analytique, seulement la PII).
        assert resultat["@timestamp"] == "2026-07-16T20:00:00.000Z"
        assert resultat["event"]["code"] == 4720
        assert resultat["event"]["outcome"] == "success"
        assert resultat["host"]["os"]["family"] == "windows"  # non-sensible, préservé


class TestPatternsPII:
    """Tests des patterns de détection PII."""

    def test_patterns_definis(self):
        # CADRE utilise "bearer_token" (nom du pattern dans le code source)
        assert "ipv4" in PATTERNS_PII
        assert "ipv6" in PATTERNS_PII
        assert "email" in PATTERNS_PII
        assert "md5" in PATTERNS_PII
        assert "sha1" in PATTERNS_PII
        assert "sha256" in PATTERNS_PII
        assert "ntlm" in PATTERNS_PII
        assert "bearer_token" in PATTERNS_PII
        assert "jwt" in PATTERNS_PII

    def test_champs_sensibles_definis(self):
        # CADRE utilise "host.name" (pas "host.ip") dans le code source
        assert len(CHAMPS_SENSIBLES) > 0
        assert "user.name" in CHAMPS_SENSIBLES
        assert "host.name" in CHAMPS_SENSIBLES
        assert "source.ip" in CHAMPS_SENSIBLES

    def test_patterns_sont_compiles(self):
        """Les patterns doivent être des regex compilés."""
        for key, pattern in PATTERNS_PII.items():
            assert isinstance(pattern, re.Pattern), f"Pattern {key} n'est pas un Pattern compilé"


class TestAnonymisationListes:
    """Couvre la branche liste d'anonymiser_dict (F-011, phase 6 audit) :
    un champ dont la valeur est une LISTE doit voir ses éléments traités
    (hash pour champs sensibles, anonymisation regex sinon), sans fuite."""

    def test_champ_sensible_liste_est_hashee(self):
        # Un champ sensible (source.ip) portant une liste d'IP : chaque IP hashée.
        doc = {"source.ip": ["192.168.1.10", "10.0.0.5"], "event.code": 1}
        out = anonymiser_log_elastic(doc)
        assert "192.168.1.10" not in str(out["source.ip"])
        assert "10.0.0.5" not in str(out["source.ip"])
        assert out["event.code"] == 1  # champ neutre préservé

    def test_liste_de_texte_libre_est_anonymisee(self):
        # Une liste de chaînes libres contenant une IP : l'IP est masquée.
        doc = {"message": ["connexion depuis 8.8.8.8", "ok"]}
        out = anonymiser_log_elastic(doc)
        assert "8.8.8.8" not in str(out["message"])

    def test_liste_valeurs_non_string_preservees(self):
        # Une liste d'entiers (ports) n'est pas altérée (branche else, ligne ~222).
        doc = {"destination.port": [80, 443], "event.code": 4688}
        out = anonymiser_log_elastic(doc)
        assert out["destination.port"] == [80, 443]

    def test_determinisme_sur_liste(self):
        doc = {"source.ip": ["1.2.3.4"]}
        assert anonymiser_log_elastic(doc) == anonymiser_log_elastic(doc)

    def test_liste_hors_groupe_toujours_hasher_reste_selective(self):
        """Régression : un champ sensible hors du groupe "toujours hasher"
        (user.name/domain/email/host.*) doit traiter chaque élément d'une
        LISTE exactement comme un scalaire -- anonymiser_chaine (sélectif),
        pas un hash intégral systématique. Avant : "whoami" (aucune PII)
        était détruit comme "net user admin /add" (qui contient une vraie
        PII, "admin"), les deux traités identiquement par erreur."""
        from cadre.anonymisation import anonymiser_dict

        doc = {"process.command_line": ["whoami", "net user admin /add"]}
        out = anonymiser_dict(doc)
        valeurs = out["process.command_line"]
        assert valeurs[0] == "whoami"  # aucune PII -> intact, comme le scalaire
        assert "admin" not in valeurs[1]  # la PII réelle reste masquée
        assert "net" in valeurs[1] and "user" in valeurs[1]  # contexte non-PII gardé
