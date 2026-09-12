# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Module d'anonymisation
==============================

Anonymisation des données sensibles (PII) avant traitement par un LLM ou
stockage dans les logs. Conforme aux principes RGPD (minimisation des
données) et aux bonnes pratiques de threat intelligence sharing.

Types de données anonymisées :
- Adresses IPv4/IPv6
- Noms d'utilisateur (préfixes courants)
- Noms de domaine
- Adresses email
- Mots de passe et hashes
- Noms de machines
- Chemins de fichiers contenant des noms d'utilisateur
"""

from __future__ import annotations

import hashlib
import re
from re import Pattern
from typing import Any

# Patterns compilés une seule fois pour la performance.
#
# ORDRE CRITIQUE (appliqués séquentiellement dans `anonymiser_chaine`, chaque
# `.sub()` mute la chaîne pour le pattern suivant) : un pattern « composite »
# (plusieurs segments séparés par un délimiteur non-alphanumérique comme `.`
# ou `:`) DOIT être essayé AVANT tout pattern plus générique dont les `\b`
# pourraient matcher un seul segment isolément -- le délimiteur crée une
# frontière de mot (`\b`) exploitable par le pattern générique, qui ne
# consomme alors qu'UNE PARTIE de la donnée sensible et laisse le reste en
# clair. Deux fuites réelles trouvées par ce défaut d'ordre : `jwt` (3
# segments séparés par `.`) après `bearer_token` (générique, sans `.` dans sa
# classe de caractères) faisait fuiter le payload+signature d'un jeton
# `Bearer <JWT>` ; `ntlm` (2 blocs hex séparés par `:`) après `md5` (générique,
# 32 hex) empêchait `ntlm` de jamais matcher (chaque bloc consommé par `md5`
# avant que `ntlm` ne s'exécute) -- pas une fuite (toujours anonymisé), mais
# une étiquette `[MD5_ANONYMISE]` incorrecte et du code mort. D'où : jwt avant
# bearer_token, ntlm avant les hash simples (sha256/sha1/md5, eux-mêmes sans
# conflit entre eux grâce à `\b` sur une plage hex continue sans délimiteur).
PATTERNS_PII: dict[str, Pattern[str]] = {
    "ipv4": re.compile(
        r"\b(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|"
        r"\b:(?::[0-9a-fA-F]{1,4}){1,7}\b"
    ),
    "username": re.compile(
        r"(?i)(?:user|utilisateur|admin|account|compte|login|usr)[:=\s]+([A-Za-z0-9_.-]{3,})"
    ),
    "domain": re.compile(r"(?i)(?:domain|domaine|host|hostname)[:=\s]+([A-Za-z0-9_.-]{3,})"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "bearer_token": re.compile(r"Bearer\s+[A-Za-z0-9\-_=]{20,}"),
    "ntlm": re.compile(r"\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "password": re.compile(
        r"(?i)(?:password|mot_de_passe|pwd|pass|secret|api[_-]?key)[:=\s]+[\"']?([^\s\"']{4,})[\"']?"
    ),
    "mac_address": re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    "windows_path": re.compile(r"C:\\Users\\([A-Za-z0-9_.-]+)", re.IGNORECASE),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
}

# Liste des champs Kibana/Elasticsearch qui contiennent typiquement des PII
CHAMPS_SENSIBLES = {
    "user.name",
    "user.domain",
    "user.email",
    "host.name",
    "host.hostname",
    "host.fqdn",
    "source.ip",
    "source.port",
    "destination.ip",
    "destination.port",
    "client.ip",
    "client.address",
    "server.ip",
    "server.address",
    "process.command_line",
    "process.executable",
    "process.parent.command_line",
    "file.path",
    "file.directory",
    "url.full",
    "url.original",
    "registry.path",
    "registry.key",
    "registry.value",
    "dns.question.name",
}

# Sous-ensemble de CHAMPS_SENSIBLES toujours hashé intégralement (jamais via
# anonymiser_chaine, même si la valeur ne matche aucun pattern PII) : un nom
# d'utilisateur ou de machine EST la donnée sensible dans son intégralité,
# contrairement à process.command_line/file.path où seule une PARTIE de la
# valeur (un nom inclus dedans) doit être masquée, le reste étant du contexte
# utile à l'analyste.
_CHAMPS_TOUJOURS_HASHER = {
    "user.name",
    "user.domain",
    "user.email",
    "host.name",
    "host.hostname",
    "host.fqdn",
}


def _hash_deterministe(valeur: str, sel: str = "CADRE") -> str:
    """
    Hash déterministe pour remplacer une PII tout en conservant la
    corrélation entre les logs (même IP = même hash, mais non réversible).
    """
    return (
        "ANON-"
        + hashlib.sha256((sel + valeur).encode("utf-8", errors="replace")).hexdigest()[:12].upper()
    )


def anonymiser_chaine(texte: str, sel: str = "CADRE") -> str:
    """
    Anonymise toutes les PII détectées dans une chaîne.

    Args:
        texte: Texte à anonymiser
        sel: Sel pour le hash (change-le pour réinitialiser les corrélations)

    Returns:
        Texte avec les PII remplacées par des hashes anonymes
    """
    if not isinstance(texte, str) or not texte:
        return texte

    resultat = texte

    # 1. Patterns structurés (IPs, emails, hashes)
    for nom, pattern in PATTERNS_PII.items():
        if nom in ("username", "domain", "password"):
            # Capture uniquement le groupe 1 (après le préfixe)
            resultat = pattern.sub(
                lambda m: m.group(0).replace(m.group(1), _hash_deterministe(m.group(1), sel)),
                resultat,
            )
        else:
            remplacement = f"[{nom.upper()}_ANONYMISE]"
            resultat = pattern.sub(remplacement, resultat)

    # 2. Noms de machines Windows (DOMAIN\user, MACHINE$)
    return re.sub(
        r"([A-Z][A-Z0-9_-]+)\\([A-Za-z0-9_.-]+)",
        lambda m: f"[DOMAIN_ANONYMISE]\\{_hash_deterministe(m.group(2), sel)}",
        resultat,
    )


def anonymiser_dict(
    document: dict[str, Any],
    champs_a_garder: set | None = None,
    sel: str = "CADRE",
    profondeur_max: int = 10,
) -> dict[str, Any]:
    """
    Anonymise récursivement un dictionnaire (log Elasticsearch typique).
    Par défaut, anonymise tous les champs reconnus comme sensibles.
    Les valeurs None, int, float, bool sont préservées.

    `CHAMPS_SENSIBLES`/`champs_a_garder` contiennent des chemins à points
    (ex. `"user.name"`) : ils sont comparés au CHEMIN COMPLET accumulé
    pendant la récursion (`user` puis `user.name`), pas seulement à la clé
    du niveau courant -- un vrai document Elasticsearch est imbriqué
    (`{"user": {"name": "alice"}}`), jamais à clés plates. Fonctionne aussi
    pour un document à clés plates (`{"user.name": "alice"}`) : le chemin
    accumulé au niveau racine est alors directement `"user.name"`.

    Args:
        document: Dictionnaire à anonymiser
        champs_a_garder: Set de clés (chemins à points) à NE PAS anonymiser
        sel: Sel pour le hashing
        profondeur_max: Limite de récursion (sécurité)
    """
    champs_a_garder_lower = {c.lower() for c in (champs_a_garder or set())}
    return _anonymiser_dict_recursif(document, champs_a_garder_lower, sel, profondeur_max, "")


_CHAMPS_SENSIBLES_LOWER = {c.lower() for c in CHAMPS_SENSIBLES}
_CHAMPS_TOUJOURS_HASHER_LOWER = {c.lower() for c in _CHAMPS_TOUJOURS_HASHER}

# Marqueur retourné à la place d'un sous-document dont la profondeur dépasse
# `profondeur_max` -- voir _anonymiser_dict_recursif ci-dessous.
_MARQUEUR_PROFONDEUR_MAX = "[PROFONDEUR_MAX_ANONYMISE]"


def _anonymiser_dict_recursif(
    document: dict[str, Any],
    champs_a_garder_lower: set[str],
    sel: str,
    profondeur_max: int,
    prefixe: str,
) -> dict[str, Any]:
    if profondeur_max <= 0:
        # Régression (audit) : retournait `document` -- le sous-document BRUT,
        # tel quel, absolument AUCUN champ anonymisé -- dès que la profondeur
        # dépassait `profondeur_max` (documentée "Limite de récursion
        # (sécurité)" dans `anonymiser_dict`). Fail-OPEN sur une garde de
        # sécurité : un document Elasticsearch/Kibana anormalement imbriqué
        # (malformé, ou façonné par un attaquant -- un champ arbitraire type
        # ScriptBlock/registre peut contenir un JSON structuré arbitrairement
        # profond) faisait fuiter TOUTE PII nichée au-delà de cette
        # profondeur -- user.name, host.name, IPs... -- en clair, aussi bien
        # vers le LLM local (suggerer_regle_sigma) que dans tout stockage en
        # aval. Fail-CLOSED : un marqueur explicite plutôt que la donnée
        # brute -- un consommateur en aval voit clairement qu'une portion du
        # document a été tronquée pour sécurité, jamais qu'elle était
        # "propre".
        return {"_profondeur_max_atteinte": _MARQUEUR_PROFONDEUR_MAX}

    resultat: dict[str, Any] = {}
    for cle, valeur in document.items():
        chemin = f"{prefixe}{cle}".lower()  # chemin complet accumulé, pas juste `cle`

        # Les clés None ou simples passent
        if valeur is None or isinstance(valeur, (bool, int, float)):
            resultat[cle] = valeur
            continue

        # Si le chemin est dans la liste d'exclusion, on garde tel quel
        if chemin in champs_a_garder_lower:
            resultat[cle] = valeur
            continue

        # Si le chemin est sensible, on anonymise
        if chemin in _CHAMPS_SENSIBLES_LOWER:
            # Pour les champs username/host sensibles, on hash TOUJOURS la
            # valeur (même si elle ne matche aucun pattern), pour respecter
            # RGPD ; les autres passent par anonymiser_chaine (sélectif,
            # garde le contexte non-PII utile à l'analyste). MÊME règle
            # pour un scalaire ou pour chaque élément d'une liste --
            # régression corrigée : la version précédente hashait TOUJOURS
            # intégralement les chaînes d'une liste, même hors de
            # _CHAMPS_TOUJOURS_HASHER (ex. "whoami" dans une liste
            # process.command_line, sans aucune PII, détruit sans raison).
            hasher_integralement = chemin in _CHAMPS_TOUJOURS_HASHER_LOWER
            if isinstance(valeur, str):
                resultat[cle] = (
                    _hash_deterministe(valeur, sel)
                    if hasher_integralement
                    else anonymiser_chaine(valeur, sel)
                )
            elif isinstance(valeur, list):
                resultat[cle] = [
                    (
                        (
                            _hash_deterministe(v, sel)
                            if hasher_integralement
                            else anonymiser_chaine(v, sel)
                        )
                        if isinstance(v, str)
                        else v
                    )
                    for v in valeur
                ]
            else:
                resultat[cle] = valeur
            continue

        # Sinon, on descend récursivement (chemin accumulé pour le niveau suivant)
        if isinstance(valeur, dict):
            resultat[cle] = _anonymiser_dict_recursif(
                valeur, champs_a_garder_lower, sel, profondeur_max - 1, chemin + "."
            )
        elif isinstance(valeur, list):
            resultat[cle] = [
                (
                    _anonymiser_dict_recursif(
                        v, champs_a_garder_lower, sel, profondeur_max - 1, chemin + "."
                    )
                    if isinstance(v, dict)
                    else (anonymiser_chaine(v, sel) if isinstance(v, str) else v)
                )
                for v in valeur
            ]
        elif isinstance(valeur, str):
            resultat[cle] = anonymiser_chaine(valeur, sel)
        else:
            resultat[cle] = valeur

    return resultat


def anonymiser_log_elastic(document: dict[str, Any], sel: str = "CADRE") -> dict[str, Any]:
    """
    Helper spécialisé pour anonymiser un document Elasticsearch issu
    de Winlogbeat. Préserve les EventIDs et les timestamps pour la
    corrélation, anonymise le reste par défaut.
    """
    garder = {
        "@timestamp",
        "event.code",
        "event.kind",
        "event.category",
        "event.action",
        "event.outcome",
        "log.level",
        "event.created",
    }
    return anonymiser_dict(document, champs_a_garder=garder, sel=sel)


if __name__ == "__main__":
    # Tests
    print("=== Tests d'anonymisation ===\n")

    test1 = "Connexion depuis 192.168.1.100 par admin@corp.local sur WORKSTATION-42"
    print(f"Original : {test1}")
    print(f"Anonyme  : {anonymiser_chaine(test1)}\n")

    test2 = {
        "@timestamp": "2026-07-16T20:00:00Z",
        "event.code": 4720,
        "host.name": "PC-JOHN-DOE",
        "user.name": "john.doe",
        "source.ip": "10.0.0.42",
        "process.command_line": 'net user john.doe "P@ss123" /add',
    }
    print("Log original :")
    import json

    print(json.dumps(test2, indent=2))
    print("\nLog anonymisé :")
    print(json.dumps(anonymiser_log_elastic(test2), indent=2))
