# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Logger structuré
=========================

Logger centralisé pour CADRE. Sortie :
- Console : format lisible, couleurs ANSI
- Fichier : JSON structuré (une ligne par événement) pour analyse ultérieure

Types d'événements tracés :
- AUDIT_START, AUDIT_END : cycle d'audit
- ATTACK_EXEC, ATTACK_SUCCESS, ATTACK_FAIL : exécution
- LOG_FOUND, LOG_NOT_FOUND : collecte
- RULE_GEN, RULE_COMPILE, RULE_DEPLOY : génération de règles
- VALIDATION_TP, VALIDATION_FP, RULE_REJECTED : double validation
- SECRET_READ, SECRET_WRITE, SECRET_DELETE : audit d'accès au coffre-fort
- ERROR, WARN, INFO : événements génériques
"""

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console as _RichConsole


# Couleurs ANSI pour la console
class Couleur:
    RESET = "\033[0m"
    ROUGE = "\033[91m"
    VERT = "\033[92m"
    JAUNE = "\033[93m"
    BLEU = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRIS = "\033[90m"


_COULEUR_PAR_NIVEAU = {
    "DEBUG": Couleur.GRIS,
    "INFO": Couleur.CYAN,
    "WARN": Couleur.JAUNE,
    "ERROR": Couleur.ROUGE,
    "SUCCESS": Couleur.VERT,
    "ATTACK": Couleur.MAGENTA,
}

# Sévérité relative des niveaux, pour le filtrage console (--verbose/--quiet).
# La sortie fichier JSON, elle, reçoit TOUJOURS tout : la verbosité ne filtre
# que le bruit console, jamais la trace d'audit complète.
_RANG_NIVEAU = {
    "DEBUG": 0,
    "INFO": 1,
    "ATTACK": 1,
    "SUCCESS": 1,
    "WARN": 2,
    "ERROR": 3,
}

_ICONE_PAR_TYPE = {
    "AUDIT_START": "[start]",
    "AUDIT_END": "[end]",
    "ATTACK_EXEC": "[exec]",
    "ATTACK_SUCCESS": "[ok]",
    "ATTACK_FAIL": "[fail]",
    "LOG_FOUND": "[found]",
    "LOG_NOT_FOUND": "[warn]",
    "RULE_GEN": "[gen]",
    "RULE_COMPILE": "[compile]",
    "RULE_DEPLOY": "[deploy]",
    "VALIDATION_TP": "[tp]",
    "VALIDATION_FP": "[fp]",
    "RULE_REJECTED": "[rejected]",
    "BLIND_SPOT": "[blind]",
    "SECRET_READ": "[sec:r]",  # nosec B105 - étiquette de log, pas un secret
    "SECRET_WRITE": "[sec:w]",  # nosec B105 - étiquette de log, pas un secret
    "SECRET_DELETE": "[sec:x]",  # nosec B105 - étiquette de log, pas un secret
    "INFO": "[i]",
    "WARN": "[warn]",
    "ERROR": "[error]",
    "SUCCESS": "[ok]",
    "DEBUG": "[debug]",
}

# Au-delà de cette taille, le fichier de log est archivé (voir
# _ecrire_fichier) plutôt que de grossir indéfiniment (daemon longue durée).
_TAILLE_MAX_LOG_OCTETS = 10 * 1024 * 1024  # 10 Mo


class CADRELogger:
    """
    Logger à deux sorties : console (couleurs ANSI si le terminal les
    supporte, texte brut sinon -- jamais de code d'échappement brut dans
    une sortie redirigée) + fichier JSON (avec rotation, voir
    `_ecrire_fichier`).

    Le fichier JSON est essentiel pour :
    - La traçabilité (audit forensic)
    - La génération automatique de rapports
    - L'intégration avec des outils SIEM tiers
    """

    def __init__(
        self,
        fichier_log: Path | None = None,
        niveau_console: str = "INFO",
        avec_couleur: bool = True,
    ):
        """
        Args:
            fichier_log: chemin du fichier JSON (créé si absent). None pour
                désactiver la sortie fichier (console uniquement).
            niveau_console: seuil de sévérité affiché en console
                (DEBUG/INFO/WARN/ERROR) -- ne filtre JAMAIS la sortie
                fichier, toujours complète (voir `evenement`).
            avec_couleur: intention de l'appelant ; la décision RÉELLE
                (`self.avec_couleur`, utilisée par `_formatter_console`)
                dépend aussi de la détection réelle du terminal -- jamais
                de couleur vers un fichier/pipe même si `avec_couleur=True`.
        """
        self.fichier_log = fichier_log
        self.niveau_console = niveau_console
        # Détection robuste (Windows Console API, NO_COLOR, CI, TERM=dumb...)
        # via rich plutôt que sys.stdout.isatty() seul, qui donne parfois un
        # faux positif sur Windows (isatty() vrai sans support ANSI réel) —
        # incohérent avec la CLI qui utilise déjà rich pour ses propres
        # tableaux/panneaux (cli.py). Une seule source de vérité pour
        # "ce flux supporte-t-il la couleur ?".
        self.avec_couleur = (avec_couleur and _RichConsole().is_terminal) or bool(
            os.environ.get("FORCE_COLOR")
        )

        if self.fichier_log:
            self.fichier_log.parent.mkdir(parents=True, exist_ok=True)
        # G2 : un cycle en mode --parallel loggue depuis 2 threads en même
        # temps -- sans ce verrou, deux open("a")/write()/close() concurrents
        # pourraient produire une ligne JSONL entrelacée/corrompue. N'affecte
        # pas la détection (ce fichier est un journal d'audit, pas une source
        # de vérité TP/FP), mais coûte rien à corriger une fois identifié.
        self._verrou_fichier = threading.Lock()

    def _formatter_console(self, type_evt: str, message: str, **kwargs: Any) -> str:
        """Formate un message pour la console.

        Régression (audit) : `self.avec_couleur` était calculé (détection
        terminal réel/FORCE_COLOR) mais jamais consulté ici -- les codes
        d'échappement ANSI (`\\033[...]`) étaient donc TOUJOURS émis, y
        compris vers une sortie redirigée (`cadre cycle > audit.log`),
        polluant le fichier de codes bruts illisibles hors terminal.
        """
        icone = _ICONE_PAR_TYPE.get(type_evt, "•")
        timestamp = datetime.now().strftime("%H:%M:%S")
        niveau = kwargs.get("niveau", "INFO")
        extras_str = ", ".join(f"{k}={v}" for k, v in kwargs.items() if k != "niveau")

        if not self.avec_couleur:
            extras = f" [{extras_str}]" if extras_str else ""
            return f"{timestamp} {icone} {message}{extras}"

        couleur = _COULEUR_PAR_NIVEAU.get(niveau, Couleur.RESET)
        extras = f" [{Couleur.GRIS}{extras_str}{Couleur.RESET}]" if extras_str else ""
        return (
            f"{Couleur.GRIS}{timestamp}{Couleur.RESET} {icone} "
            f"{couleur}{message}{Couleur.RESET}{extras}"
        )

    def _ecrire_fichier(self, entree: dict[str, Any]) -> None:
        """Écrit une entrée JSON dans le fichier de log, avec rotation.

        Rotation (régression, audit) : sans elle, un daemon tournant des
        jours (`cadre daemon`/`cadre loop`) fait grossir ce fichier
        indéfiniment jusqu'à saturer le disque -- exactement le genre de
        panne d'écriture dont `boucle.py::_mettre_a_jour_cumulatif` protège
        désormais le daemon (audit), mais qu'il vaut mieux éviter à la
        source. Un seul backup gardé (`<fichier>.1`, écrasé à chaque
        rotation) : suffisant pour une trace récente sans gérer plusieurs
        générations.
        """
        if not self.fichier_log:
            return
        try:
            with self._verrou_fichier:
                if (
                    self.fichier_log.exists()
                    and self.fichier_log.stat().st_size >= _TAILLE_MAX_LOG_OCTETS
                ):
                    sauvegarde = self.fichier_log.with_name(self.fichier_log.name + ".1")
                    self.fichier_log.replace(sauvegarde)
                with self.fichier_log.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entree, ensure_ascii=False, default=str) + "\n")
        except Exception as e:
            sys.stderr.write(f"Erreur écriture log: {e}\n")

    def evenement(self, type_evt: str, message: str, niveau: str = "INFO", **kwargs: Any) -> None:
        """
        Enregistre un événement structuré.

        Args:
            type_evt: Type d'événement (ex: ATTACK_EXEC, RULE_DEPLOY)
            message: Description lisible
            niveau: Niveau de log (DEBUG, INFO, WARN, ERROR, SUCCESS, ATTACK)
            **kwargs: Données additionnelles sérialisées en JSON
        """
        entree = {
            "timestamp": datetime.now(UTC).isoformat(),
            "type": type_evt,
            "niveau": niveau,
            "message": message,
            **kwargs,
        }

        # Sortie console — filtrée par sévérité (--verbose abaisse le seuil
        # à DEBUG, --quiet le relève à WARN). La sortie fichier ci-dessous
        # n'est jamais filtrée : la trace d'audit reste toujours complète.
        seuil = _RANG_NIVEAU.get(self.niveau_console, 1)
        if _RANG_NIVEAU.get(niveau, 1) >= seuil:
            try:
                print(self._formatter_console(type_evt, message, **kwargs))
            except UnicodeEncodeError:
                # Fallback pour les terminaux qui ne supportent pas l'UTF-8
                print(
                    self._formatter_console(type_evt, message, **kwargs)
                    .encode("ascii", "replace")
                    .decode()
                )

        # Sortie fichier
        self._ecrire_fichier(entree)

    # Helpers de commodité
    def info(self, message: str, **kwargs: Any) -> None:
        self.evenement("INFO", message, "INFO", **kwargs)

    def warn(self, message: str, **kwargs: Any) -> None:
        self.evenement("WARN", message, "WARN", **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        self.evenement("ERROR", message, "ERROR", **kwargs)

    def success(self, message: str, **kwargs: Any) -> None:
        self.evenement("SUCCESS", message, "SUCCESS", **kwargs)

    def debug(self, message: str, **kwargs: Any) -> None:
        self.evenement("DEBUG", message, "DEBUG", **kwargs)

    def attack(self, message: str, **kwargs: Any) -> None:
        self.evenement("ATTACK_EXEC", message, "ATTACK", **kwargs)

    def blind_spot(self, message: str, **kwargs: Any) -> None:
        self.evenement("BLIND_SPOT", message, "WARN", **kwargs)


# Instance globale
_logger_instance: CADRELogger | None = None


def obtenir_logger() -> CADRELogger:
    """Retourne l'instance singleton du logger.

    Le niveau de verbosité console lit `CADRE_LOG_LEVEL` (DEBUG/INFO/WARN/
    ERROR, défaut INFO) — positionné par `cadre --verbose`/`--quiet` avant
    la création du singleton (voir cli.py). Doit être lu à chaque appel,
    pas seulement à l'instanciation : les tests réinitialisent le
    singleton entre cas via monkeypatch sans forcément relire l'env var.
    """
    global _logger_instance
    if _logger_instance is None:
        log_path = Path("./logs/cadre.log.json")
        niveau = os.environ.get("CADRE_LOG_LEVEL", "INFO").upper()
        _logger_instance = CADRELogger(fichier_log=log_path, niveau_console=niveau)
    return _logger_instance


if __name__ == "__main__":
    log = CADRELogger(fichier_log=Path("./test_cadre.log.json"))
    log.info("Démarrage du test du logger", version="1.0.0")
    log.attack("Lancement attaque T1059.001", event_id_attendu="4104")
    log.success("Règle Sigma générée", technique="T1059.001", qualite="excellent")
    log.warn("Faux positif détecté", fp_count=12, seuil=10)
    log.error("Connexion Elastic refusée", endpoint="http://localhost:9200")
    log.blind_spot("EventID 4720 non trouvé après 120s", technique="T1136.001")
    print(f"\nLogs écrits dans : {log.fichier_log}")
