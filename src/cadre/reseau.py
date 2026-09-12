# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Helpers réseau
======================

Petit module feuille (n'importe rien d'interne, donc importable partout sans
risque de cycle) centralisant la politique de vérification TLS des requêtes
sortantes vers Elasticsearch / Kibana.
"""

from __future__ import annotations

import os


def verifier_tls() -> bool:
    """
    Faut-il vérifier le certificat TLS des services (Elastic, Kibana) ?

    Défaut : **False**. En laboratoire local — le mode d'usage de CADRE — ces
    services tournent sur `127.0.0.1`, en HTTP clair ou avec un certificat
    auto-signé : la vérification TLS n'apporte alors aucune protection réelle
    (rien ne transite hors de la machine) et empêcherait simplement la
    connexion. C'est donc un choix **conscient et local**, pas un oubli.

    En production (services derrière de vrais certificats) : exporter
    `CADRE_VERIFY_TLS=1` pour réactiver la vérification. Source unique, pour
    ne jamais disséminer de `verify=False` codé en dur dans le code.
    """
    return os.environ.get("CADRE_VERIFY_TLS", "").strip().lower() in ("1", "true", "yes", "on")
