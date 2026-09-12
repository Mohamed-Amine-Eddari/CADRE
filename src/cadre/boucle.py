# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Boucle automatisée (mode daemon)
=========================================

Exécute des cycles d'audit en continu, avec :
- Intervalle configurable entre cycles
- Rotation des techniques (chaque cycle = sous-ensemble)
- Notification Slack/Discord/email (optionnel)
- Arrêt propre sur Ctrl+C
- Statistiques cumulatives
"""

from __future__ import annotations

import json
import signal
import smtplib
import time
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

import requests

from .catalogue_attaques import AttaqueCatalogue, catalogue_actif
from .logger import obtenir_logger
from .orchestrateur import (
    OrchestrateurCADRE,
    VerrouCycleActifError,
    _acquerir_verrou_cycle,
    _liberer_verrou_cycle,
)


class BoucleAutomatisee:
    """
    Boucle d'audit continue.

    Usage:
        boucle = BoucleAutomatisee(intervalle_sec=3600, webhooks=["https://..."])
        boucle.demarrer(max_cycles=24)  # 24 cycles d'1h = 24h
    """

    def __init__(
        self,
        intervalle_sec: int = 3600,
        webhooks: list[str] | None = None,
        email_dest: str | None = None,
        email_smtp: dict[str, Any] | None = None,
        rotation_techniques: bool = True,
        techniques_par_cycle: int = 4,
        rapport_cumulatif: Path | None = None,
    ):
        self.log = obtenir_logger()
        self.intervalle_sec = intervalle_sec
        self.webhooks = webhooks or []
        self.email_dest = email_dest
        self.email_smtp = email_smtp or {}
        self.rotation_techniques = rotation_techniques
        self.techniques_par_cycle = techniques_par_cycle
        self.rapport_cumulatif = rapport_cumulatif or Path("./rapports/cadre_cumulatif.json")

        self.orchestrateur = OrchestrateurCADRE()
        self._arret_demande: bool = False
        self._cycles_executes = 0
        self._statistiques_cumulatives: dict[str, Any] = {
            "total_cycles": 0,
            "total_attaques": 0,
            "validees": 0,
            "validees_non_deployees": 0,
            "rejetees": 0,
            "angles_morts": 0,
            "non_applicables": 0,
            "erreurs": 0,
            "par_technique": {},
        }

        # Gestionnaire de signal pour arrêt propre
        signal.signal(signal.SIGINT, self._handler_sigint)
        signal.signal(signal.SIGTERM, self._handler_sigint)

    def _handler_sigint(self, _signum, _frame):
        """Gestionnaire de Ctrl+C — arrêt propre après le cycle en cours."""
        self.log.warn("Signal d'arrêt reçu — fin du cycle en cours puis arrêt...")
        self._arret_demande = True

    def _selectionner_techniques_rotation(self) -> list[AttaqueCatalogue]:
        """Sélectionne un sous-ensemble d'attaques en rotation.

        Régression (audit) : utilisait le CATALOGUE natif figé, jamais
        `catalogue_actif()` (natif + attaques perso enregistrées via `cadre
        suggest --enregistrer`/le dashboard) -- `cadre cycle` teste bien les
        attaques perso (executer_cycle_complet() utilise déjà
        catalogue_actif()), mais le daemon (`cadre daemon`/`cadre loop`) ne
        les rotait JAMAIS, silencieusement. Appelé à chaque cycle (pas mis
        en cache) pour qu'une attaque perso ajoutée pendant que le daemon
        tourne soit prise en compte sans redémarrage.
        """
        catalogue = catalogue_actif()
        if not self.rotation_techniques:
            return list(catalogue)

        # Décaler l'index de rotation selon le cycle
        decalage = (self._cycles_executes * self.techniques_par_cycle) % len(catalogue)
        selection = []
        for i in range(self.techniques_par_cycle):
            idx = (decalage + i) % len(catalogue)
            selection.append(catalogue[idx])
        return selection

    def _notifier_webhook(self, message: str, stats: dict[str, Any]) -> bool:
        """Envoie une notification via webhook (Slack/Discord/Teams)."""
        if not self.webhooks:
            return False

        succes = False
        for url in self.webhooks:
            try:
                # Format Slack/Discord
                payload: dict[str, Any] = {
                    "text": message,
                    "attachments": [
                        {
                            "color": "#10b981" if stats["erreurs"] == 0 else "#ef4444",
                            "fields": [
                                {
                                    "title": "Validées",
                                    "value": str(stats.get("validees", 0)),
                                    "short": True,
                                },
                                {
                                    "title": "Validées (non déployées)",
                                    "value": str(stats.get("validees_non_deployees", 0)),
                                    "short": True,
                                },
                                {
                                    "title": "Rejetées",
                                    "value": str(stats.get("rejetees", 0)),
                                    "short": True,
                                },
                                {
                                    "title": "Angles morts",
                                    "value": str(stats.get("angles_morts", 0)),
                                    "short": True,
                                },
                                {
                                    "title": "Non applicables",
                                    "value": str(stats.get("non_applicables", 0)),
                                    "short": True,
                                },
                                {
                                    "title": "Erreurs",
                                    "value": str(stats.get("erreurs", 0)),
                                    "short": True,
                                },
                            ],
                        }
                    ],
                }
                r = requests.post(url, json=payload, timeout=10)
                if r.status_code in (200, 204):
                    succes = True
                    self.log.success(f"Notification webhook envoyée : {url[:50]}...")
                else:
                    self.log.warn(f"Webhook HTTP {r.status_code} : {url[:50]}")
            except Exception as e:
                self.log.error(f"Erreur webhook : {e}")
        return succes

    def _notifier_email(self, sujet: str, message: str) -> bool:
        """Envoie une notification par email."""
        if not self.email_dest or not self.email_smtp:
            return False
        try:
            msg = MIMEText(message)
            msg["Subject"] = sujet
            msg["From"] = self.email_smtp.get("from", "cadre@example.com")
            msg["To"] = self.email_dest

            with smtplib.SMTP(
                self.email_smtp["host"],
                self.email_smtp.get("port", 587),
            ) as server:
                server.starttls()
                if self.email_smtp.get("user") and self.email_smtp.get("password"):
                    server.login(self.email_smtp["user"], self.email_smtp["password"])
                server.send_message(msg)
            self.log.success(f"Email envoyé à {self.email_dest}")
            return True
        except Exception as e:
            self.log.error(f"Erreur email : {e}")
            return False

    def _calculer_stats_cycle(self, resultats: list[dict[str, Any]]) -> dict[str, Any]:
        """Calcule les statistiques d'un cycle.

        Les 6 statuts réels que `executer_attaque_complete` peut renvoyer
        (jamais SIMULE ici : cette boucle n'a pas de mode simulation) sont
        TOUS comptés -- une version antérieure n'en comptait que 4
        (validees/rejetees/angles_morts/erreurs), omettant silencieusement
        NON_APPLICABLE (cible non configurée, ex. attaque Linux sans VM
        Linux) et VALIDE_NON_DEPLOYE (validation TP/FP réussie mais échec du
        déploiement Kibana) : `total_attaques` ne se réconciliait alors plus
        avec la somme des catégories affichées dans les notifications."""
        return {
            "validees": sum(1 for r in resultats if r.get("statut") == "VALIDE"),
            "validees_non_deployees": sum(
                1 for r in resultats if r.get("statut") == "VALIDE_NON_DEPLOYE"
            ),
            "rejetees": sum(1 for r in resultats if r.get("statut") == "REJETE"),
            "angles_morts": sum(1 for r in resultats if r.get("statut") == "ANGLE_MORT"),
            "non_applicables": sum(1 for r in resultats if r.get("statut") == "NON_APPLICABLE"),
            "erreurs": sum(1 for r in resultats if r.get("statut") == "ERREUR"),
        }

    def _mettre_a_jour_cumulatif(
        self, resultats: list[dict[str, Any]], stats: dict[str, Any]
    ) -> None:
        """Met à jour les statistiques cumulatives."""
        self._statistiques_cumulatives["total_cycles"] += 1
        self._statistiques_cumulatives["total_attaques"] += len(resultats)
        for k in [
            "validees",
            "validees_non_deployees",
            "rejetees",
            "angles_morts",
            "non_applicables",
            "erreurs",
        ]:
            self._statistiques_cumulatives[k] += stats[k]
        for r in resultats:
            tech = r.get("technique_mitre", "?")
            if tech not in self._statistiques_cumulatives["par_technique"]:
                self._statistiques_cumulatives["par_technique"][tech] = {
                    "executions": 0,
                    "validees": 0,
                    "validees_non_deployees": 0,
                    "rejetees": 0,
                    "angles_morts": 0,
                    "non_applicables": 0,
                }
            t = self._statistiques_cumulatives["par_technique"][tech]
            t["executions"] += 1
            statut = r.get("statut", "")
            if statut == "VALIDE":
                t["validees"] += 1
            elif statut == "VALIDE_NON_DEPLOYE":
                t["validees_non_deployees"] += 1
            elif statut == "REJETE":
                t["rejetees"] += 1
            elif statut == "ANGLE_MORT":
                t["angles_morts"] += 1
            elif statut == "NON_APPLICABLE":
                t["non_applicables"] += 1

        # Sauvegarder -- régression (audit) « daemon meurt sur erreur
        # d'écriture » : une erreur ici (disque plein, antivirus qui verrouille
        # temporairement le fichier sous Windows, lecteur réseau déconnecté...)
        # n'est PAS fatale au cycle : les VRAIS rapports du cycle
        # (_generer_rapports_fin_cycle) sont déjà écrits sur disque à ce stade
        # (voir executer_un_cycle) -- seul ce fichier de stats CUMULATIVES
        # (secondaire, dérivable des rapports archivés) serait affecté. Sans
        # ce garde-fou, une erreur d'écriture transitoire remontait non
        # rattrapée jusqu'à demarrer(), tuant tout le daemon (potentiellement
        # des jours de cycles programmés) pour un problème local à CE fichier.
        try:
            self.rapport_cumulatif.parent.mkdir(parents=True, exist_ok=True)
            self.rapport_cumulatif.write_text(
                json.dumps(self._statistiques_cumulatives, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as e:
            self.log.error(f"Écriture du cumulatif échouée ({self.rapport_cumulatif}) : {e}")

    def executer_un_cycle(self) -> list[dict[str, Any]]:
        """Exécute un cycle d'audit (sous-ensemble des attaques)."""
        attaques = self._selectionner_techniques_rotation()
        numero_cycle = self._cycles_executes + 1
        self.log.info(
            f"[Cycle {numero_cycle}] Démarrage — {len(attaques)} attaques sélectionnées",
            techniques=[a.technique_mitre for a in attaques],
        )

        # F-009 : `cadre loop`/`cadre daemon` exécute toujours des attaques
        # RÉELLES (pas de mode simulation ici) mais appelle
        # `executer_attaque_complete()` directement plutôt que
        # `executer_cycle_complet()` -- le verrou inter-processus qui évite
        # qu'un `cadre cycle`/le dashboard ne tourne en même temps contre la
        # même cible n'était donc jamais acquis par ces deux commandes,
        # précisément celles que F-009 est censé protéger.
        _acquerir_verrou_cycle()
        try:
            resultats: list[dict[str, Any]] = []
            # Réinitialisé AVANT la boucle (pas seulement à l'intérieur) : si
            # `attaques` est vide (ex. techniques_par_cycle=0), le corps de la
            # boucle ne s'exécute jamais et self.orchestrateur.resultats
            # gardait silencieusement les résultats du cycle PRÉCÉDENT --
            # _generer_rapports_fin_cycle() dupliquait alors un ancien rapport
            # sous un nouvel horodatage pour un cycle qui n'a rien exécuté.
            self.orchestrateur.resultats = resultats
            for i, attaque in enumerate(attaques, 1):
                if self._arret_demande:
                    break
                self.log.info(f"[{i}/{len(attaques)}] {attaque.technique_mitre} — {attaque.nom}")
                try:
                    r = self.orchestrateur.executer_attaque_complete(attaque)
                except Exception as e:
                    r = {
                        "id": attaque.id,
                        "technique_mitre": attaque.technique_mitre,
                        "statut": "ERREUR",
                        "raison": str(e),
                    }
                resultats.append(r)
                self.orchestrateur.resultats = resultats
                # Pause inter-attaques
                if i < len(attaques):
                    time.sleep(3)

            # Sauvegarder les rapports
            self.orchestrateur._generer_rapports_fin_cycle()
        finally:
            _liberer_verrou_cycle()

        # Mettre à jour les stats cumulatives
        stats = self._calculer_stats_cycle(resultats)
        self._mettre_a_jour_cumulatif(resultats, stats)

        # Notifier
        msg = (
            f"CADRE — Cycle {self._cycles_executes + 1} terminé\n"
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Validées : {stats['validees']}\n"
            f"Validées (non déployées) : {stats['validees_non_deployees']}\n"
            f"Rejetées : {stats['rejetees']}\n"
            f"Angles morts : {stats['angles_morts']}\n"
            f"Non applicables : {stats['non_applicables']}\n"
            f"Erreurs : {stats['erreurs']}"
        )
        self._notifier_webhook(msg, stats)
        self._notifier_email(f"CADRE Cycle {self._cycles_executes + 1}", msg)

        return resultats

    def demander_arret(self):
        """Demande l'arrêt après le cycle en cours (thread-safe)."""
        self._arret_demande = True

    def demarrer(self, max_cycles: int | None = None) -> dict[str, Any]:
        """
        Démarre la boucle automatisée.

        Args:
            max_cycles: Nombre max de cycles (None = infini)

        Returns:
            Statistiques cumulatives finales
        """
        self.log.evenement(
            "BOUCLE_START",
            f"Démarrage boucle automatisée — intervalle {self.intervalle_sec}s",
            niveau="INFO",
            intervalle_sec=self.intervalle_sec,
            max_cycles=max_cycles,
        )

        self._arret_demande = False

        try:
            while not self._arret_demande:
                # Vérifiée AVANT d'exécuter (pas après) : `max_cycles=0` doit
                # arrêter sans lancer un seul cycle. `is not None` (pas la
                # simple troncature `if max_cycles`) : 0 est une limite
                # valide et distincte de "illimité", pas un synonyme de None
                # -- `0` est falsy en Python, `if max_cycles` le traitait
                # silencieusement comme "illimité".
                if max_cycles is not None and self._cycles_executes >= max_cycles:
                    self.log.info(f"Limite de {max_cycles} cycles atteinte — arrêt")
                    break
                # Incrémenté APRÈS l'exécution (pas avant) : executer_un_cycle()
                # lit self._cycles_executes pour calculer son propre numéro
                # affiché (+1) et le décalage de rotation du catalogue --
                # l'incrémenter avant décalait le tout premier cycle réel de 1
                # ("Cycle 2" affiché pour le 1er cycle, rotation démarrant déjà
                # au 2e lot d'attaques au lieu du 1er).
                try:
                    self.executer_un_cycle()
                except VerrouCycleActifError as e:
                    # F-009 : collision transitoire du verrou inter-processus
                    # (un `cadre cycle`/le dashboard tourne déjà contre la
                    # même cible) -- ne doit jamais tuer définitivement le
                    # daemon/la boucle, seulement reporter ce cycle au
                    # prochain intervalle. Ce cycle ne compte pas comme
                    # exécuté (pas d'incrément) : rien n'a réellement tourné.
                    self.log.warn(f"Cycle ignoré — verrou déjà pris par un autre processus : {e}")
                else:
                    self._cycles_executes += 1

                # _arret_demande peut passer à True de manière asynchrone via
                # _handler_sigint (SIGINT/SIGTERM) ; mypy ne modélise pas les
                # signaux et croit ces branches inatteignables — elles sont
                # nécessaires pour un arrêt propre.
                if self._arret_demande:
                    break  # type: ignore[unreachable]

                # Attente entre cycles (interruptible par Ctrl+C)
                self.log.info(
                    f"⏸ Prochain cycle dans {self.intervalle_sec}s " f"(Ctrl+C pour arrêter)"
                )
                for _ in range(self.intervalle_sec):
                    if self._arret_demande:
                        break  # type: ignore[unreachable]
                    time.sleep(1)
        finally:
            self.log.evenement(
                "BOUCLE_END",
                f"Arrêt boucle — {self._cycles_executes} cycles exécutés",
                niveau="SUCCESS",
                stats_cumulatives=self._statistiques_cumulatives,
            )

        return self._statistiques_cumulatives
