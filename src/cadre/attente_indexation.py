# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Attente d'indexation Elasticsearch
==========================================

Poll intelligent qui attend qu'un événement apparaisse dans Elasticsearch
après son exécution. Évite le problème classique "le SIEM est aveugle"
causé par un délai d'indexation sous-estimé.

Critères d'arrêt :
1. L'EventID attendu apparaît (succès)
2. Le timeout est atteint (échec)
3. L'utilisateur interrompt (Ctrl+C)

L'intervalle de polling est adaptatif : court au début, plus long ensuite
pour éviter de surcharger Elastic.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urljoin

import requests

from .logger import obtenir_logger
from .reseau import verifier_tls


class ErreurComptageElastic(Exception):
    """Levée par `compter_evenements()` quand la requête Elasticsearch
    échoue (réseau, auth, 5xx, timeout, JSON malformé...) -- distincte
    d'un VRAI 0 résultat. Voir son docstring pour le raisonnement complet."""


def attendre_indexation(
    elastic_url: str,
    index_pattern: str,
    event_ids: list[str],
    auth: tuple | None = None,
    timeout_max_sec: int = 180,
    fenetre_glissante_sec: int = 300,
    intervalle_initial_sec: float = 3.0,
    intervalle_max_sec: float = 15.0,
    taille_max: int = 1,
    contexte: dict[str, Any] | None = None,
    champ_texte: str | None = None,
    valeur_texte: str | None = None,
) -> dict[str, Any] | None:
    """
    Attend qu'au moins un événement pertinent soit indexé.

    Deux modes (combinables) :
    - par EventID (Windows/Sysmon) : `event_ids` — au moins un doit apparaître.
    - par correspondance texte (Linux/Auditbeat, qui n'a pas d'EventID Windows) :
      `champ_texte`+`valeur_texte` — un événement dont ce champ contient cette
      valeur (ex. `process.title` contenant le marqueur de l'attaque).

    Args:
        elastic_url: URL de base d'Elasticsearch (ex: http://localhost:9200)
        index_pattern: Pattern d'index (ex: winlogbeat-*, auditbeat-*)
        event_ids: EventIDs à chercher (liste vide en mode texte)
        auth: Tuple (user, password) pour l'authentification
        timeout_max_sec: Durée maximale d'attente
        fenetre_glissante_sec: Fenêtre temporelle de recherche
        intervalle_initial_sec: Intervalle entre polls au début
        intervalle_max_sec: Intervalle max entre polls
        taille_max: Nombre max d'événements à retourner
        contexte: Données contextuelles pour le logging
        champ_texte / valeur_texte: mode correspondance texte (Linux)

    Returns:
        Le document Elastic trouvé (dict) ou None si timeout
    """
    log = obtenir_logger()
    ctx = contexte or {}
    debut = time.monotonic()
    poll_courant = intervalle_initial_sec

    # Construire la requête booléenne selon le mode.
    bool_query: dict[str, Any] = {
        "filter": [{"range": {"@timestamp": {"gte": f"now-{fenetre_glissante_sec}s"}}}],
    }
    if event_ids:
        bool_query["should"] = [{"match": {"event.code": eid}} for eid in event_ids]
        bool_query["minimum_should_match"] = 1
    if champ_texte and valeur_texte:
        # `process.title` (Auditbeat) est un champ keyword : match/match_phrase
        # ne font PAS de sous-chaîne. On utilise un wildcard (aligné sur la
        # règle Sigma compilée `process.title:*valeur*`). case_insensitive par
        # robustesse aux différences de casse.
        bool_query.setdefault("must", []).append(
            {"wildcard": {champ_texte: {"value": f"*{valeur_texte}*", "case_insensitive": True}}}
        )
    query: dict[str, Any] = {
        "size": taille_max,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": bool_query},
    }

    url = urljoin(elastic_url.rstrip("/") + "/", f"{index_pattern}/_search")
    log.info(
        f"Attente d'indexation pour EventIDs {event_ids}",
        timeout_s=timeout_max_sec,
        **ctx,
    )

    while True:
        elapsed = time.monotonic() - debut
        if elapsed > timeout_max_sec:
            log.blind_spot(
                f"Timeout ({timeout_max_sec}s) — EventID(s) {event_ids} non indexé(s)",
                event_ids=event_ids,
                elapsed_s=int(elapsed),
                **ctx,
            )
            return None

        try:
            r = requests.post(
                url,
                json=query,
                auth=auth,
                verify=verifier_tls(),
                timeout=10,
            )
            r.raise_for_status()
            hits = r.json().get("hits", {}).get("hits", [])

            if hits:
                elapsed_int = int(elapsed)
                log.success(
                    f"EventID(s) {event_ids} indexé(s) en {elapsed_int}s",
                    event_ids=event_ids,
                    nb_hits=len(hits),
                    elapsed_s=elapsed_int,
                    **ctx,
                )
                return hits[0].get("_source")

        except requests.exceptions.Timeout:
            log.warn("Timeout requête Elastic, retry...", **ctx)
        except requests.exceptions.RequestException as e:
            log.error(f"Erreur Elastic: {e}", **ctx)
        except Exception as e:
            log.error(f"Erreur inattendue: {e}", **ctx)

        time.sleep(poll_courant)
        # Backoff progressif (3s → 5s → 8s → 12s → 15s)
        poll_courant = min(poll_courant * 1.4, intervalle_max_sec)


def compter_evenements(
    elastic_url: str,
    index_pattern: str,
    requete_dsl: dict[str, Any],
    auth: tuple | None = None,
    timeout_sec: int = 30,
) -> int:
    """
    Compte le nombre de documents correspondant à une requête DSL Elastic.

    Utilisé par la double validation TP/FP.

    Lève `ErreurComptageElastic` sur tout échec (réseau, auth, 5xx, timeout,
    JSON malformé) -- ne renvoie JAMAIS 0 pour signaler un échec.

    Régression sécurité (audit) : la version précédente attrapait `Exception`
    et renvoyait 0 -- indiscernable d'un VRAI zéro résultat. Sur le test FP
    (`double_validation_tp_fp`/`valider_bruit_seul`), une panne Elasticsearch
    PENDANT la mesure produisait donc `nb_fp=0` -- interprété comme « aucun
    bruit », la règle était validée et déployée SANS preuve d'absence de
    faux positifs. `cadre valider-regle` affichait symétriquement une panne
    réseau comme verdict SILENCIEUSE (« bon signe »). Aux appelants de
    décider explicitement de la conduite à tenir face à une mesure
    impossible -- jamais silencieusement équivalente à "aucun résultat".
    """
    url = urljoin(elastic_url.rstrip("/") + "/", f"{index_pattern}/_count")
    try:
        r = requests.post(
            url,
            json=requete_dsl,
            auth=auth,
            verify=verifier_tls(),
            timeout=timeout_sec,
        )
        r.raise_for_status()
        return r.json().get("count", 0)
    except Exception as e:
        obtenir_logger().error(f"Erreur comptage Elastic: {e}")
        raise ErreurComptageElastic(str(e)) from e
