# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Orchestrateur principal
================================

Cerveau du système CADRE. Orchestre un cycle complet d'audit :
1. Sélection d'une attaque dans le catalogue
2. Exécution via WinRM sur la VM cible
3. Attente d'indexation dans Elastic
4. Anonymisation du log
5. Génération de règle Sigma — déterministe (défaut) OU LLM (opt-in)
6. Compilation Sigma → Lucene
7. Double validation TP/FP
8. Déploiement dans Kibana
9. Génération du rapport

Le générateur de règle est déterministe par défaut (catalogue + str.format,
reproductible). Un mode LLM opt-in (`mode_generation_regle="llm"`) laisse
l'IA rédiger la règle — MAIS elle passe alors par la MÊME compilation +
validation TP/FP avant déploiement (et retombe sur le déterministe si elle
échoue). La source de confiance est la validation, jamais le générateur :
aucune règle n'est déployée sans avoir prouvé qu'elle détecte l'attaque.
"""

from __future__ import annotations

import base64
import contextlib
import os
import re
import shutil
import socket
import subprocess  # nosec B404 - VBoxManage guestcontrol, repli WinRM opt-in (cf. vm_vbox_nom)
import tempfile
import threading
import time
import uuid as uuid_lib
from collections import defaultdict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

import requests
import urllib3

from .anonymisation import anonymiser_log_elastic
from .attente_indexation import attendre_indexation
from .catalogue_attaques import (
    AttaqueCatalogue,
    calculer_score_confiance,
    catalogue_actif,
    partitionner_pour_parallelisme,
)
from .coffre_fort import ErreurSecurite, obtenir_coffre
from .compilation_sigma import (
    compiler_sigma_vers_lucene,
    double_validation_tp_fp,
    valider_bruit_seul,
)
from .logger import obtenir_logger
from .rapport import (
    generer_csv,
    generer_layer_navigator,
    generer_rapport_cycle,
    generer_rapport_html,
    generer_rapport_kill_chain,
    generer_rapport_pdf,
)
from .reseau import verifier_tls
from .revue_regles import enregistrer_revue
from .scenarios import ScenarioAdversaire, analyser_kill_chain, attaques_ordonnees

# Tentative d'import de pywinrm (optionnel — exécution sur cible Windows)
try:
    import winrm

    WINRM_DISPONIBLE = True
except ImportError:
    WINRM_DISPONIBLE = False

# Tentative d'import de paramiko (optionnel — exécution SSH sur cible Linux)
try:
    import paramiko

    PARAMIKO_DISPONIBLE = True
except ImportError:
    PARAMIKO_DISPONIBLE = False

# Désactiver les warnings SSL (lab only)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Plafond de temps global dur pour un appel WinRM (audit, régression réelle) :
# read_timeout_sec/operation_timeout_sec de pywinrm ne bornent CHAQUE requête
# HTTP individuelle de sa boucle de sondage interne (Receive), pas la boucle
# entière -- si la commande distante ne se termine jamais réellement côté
# cible (ex. un appel WMI qui reste bloqué), pywinrm continue de sonder
# indéfiniment, sans borne de temps globale. Observé en conditions réelles :
# `Get-MpComputerStatus` a bloqué WinRM plusieurs minutes (jusqu'à 11 min lors
# d'une reproduction), rendant ensuite tout le reste du cycle inaccessible.
# Volontairement large (90s, contre 30s de read_timeout_sec par défaut) pour
# ne jamais couper une commande lente mais saine.
TIMEOUT_GLOBAL_WINRM_SEC = 90


SIGMA_TEMPLATE = """title: {titre}
id: {identifiant_uuid}
status: experimental
description: |
  {description}
references:
  - {reference_mitre}
author: CADRE PFA
date: {date}
tags:
  - attack.{tactique_mitre_tag}
  - attack.{technique_mitre_tag}
logsource:
  product: {produit}
  {logsource_ligne}
detection:
  selection:
{selection_lignes}
  condition: selection
falsepositives:
{liste_fp}
level: {niveau}
"""

# EventID Sysmon -> (logsource.category Sigma, champ SYSMON BRUT pour la
# règle Sigma générée -- traduit en champ ECS par le pipeline pysigma
# ecs_windows au moment de la compilation Sigma -> Lucene --, champ ECS
# pour la clause EQL de corrélation de kill chain -- envoyée TELLE QUELLE
# à Elasticsearch par _calculer_clause_eql, JAMAIS traduite par un
# pipeline pysigma, donc toujours le nom ECS réel). Vérifié champ par
# champ (27/08) contre `ecs_windows_field_mapping`/`ecs_windows_variable_
# mappings` (sigma/pipelines/elasticsearch/windows.py, tables EXPLICITES,
# pas le repli générique winlog.event_data.*) : la compilation Sigma ->
# Lucene doit produire un champ ECS strictement identique à l'ancien
# champ codé en dur ci-dessous, sans quoi une règle déjà déployée
# changerait de comportement -- confirmé par diff avant/après sur les
# ~40 attaques concernées, voir tests/test_orchestrateur.py.
_SYSMON_EVENT_INFO: dict[str, tuple[str, str | None, str | None]] = {
    "1": ("process_creation", "CommandLine", "process.command_line"),
    "3": ("network_connection", None, None),
    "7": ("image_load", "ImageLoaded", "file.path"),
    "10": ("process_access", "SourceImage", "process.executable"),
    "11": ("file_event", "TargetFilename", "file.path"),
    "13": ("registry_event", "TargetObject", "registry.path"),
    "22": ("dns_query", "QueryName", "dns.question.name"),
}

# EventID PowerShell Operational (canal séparé de Sysmon, pas un vrai
# événement Sysmon) -> (champ BRUT pour Sigma, champ ECS pour EQL). Même
# raisonnement que _SYSMON_EVENT_INFO ci-dessus.
_POWERSHELL_EVENT_INFO: dict[str, tuple[str, str]] = {
    "4104": ("ScriptBlockText", "powershell.file.script_block_text"),
}

# EventIDs natifs Windows (Security/System, pas Sysmon) -> service logsource.
_NATIVE_SERVICE_PAR_EVENT: dict[str, str] = {
    "4624": "security",
    "4625": "security",
    "4688": "security",
    "4697": "security",
    "4698": "security",
    "4702": "security",
    "4720": "security",
    "4726": "security",
    "4769": "security",
    "4776": "security",
    "4661": "security",
    "4732": "security",
    "7045": "system",
}

# Sous-ensemble des EventIDs natifs pour lesquels un champ de corrélation
# textuelle fiable est connu (mappé par le pipeline pysigma). Les autres
# (4625, 4688, 4698...) se contentent d'event.code — c'est déjà suffisamment
# spécifique, contrairement à l'EventID Sysmon "1" (ProcessCreate) qui est
# beaucoup trop générique pour être laissé sans corrélation.
_NATIVE_CHAMP_CORRELATION: dict[str, str] = {
    # user.name porte le compte AUTEUR de l'action (SubjectUserName) sur un
    # événement 4720 ; le nouveau compte créé est dans user.target.name
    # (TargetUserName) — confirmé par inspection d'un document réel indexé.
    "4720": "user.target.name",
    # "service.name" (ECS) n'existe PAS dans les documents winlogbeat réels
    # pour le provider "Service Control Manager" (channel System) — vérifié
    # par inspection directe : le champ est mappé nulle part, seul
    # winlog.event_data.ServiceName (non-ECS, propre à winlogbeat) porte
    # la valeur réelle.
    "7045": "winlog.event_data.ServiceName",
    # B5 (PLAN/JALON5.md) : LogonType=3 (réseau) est le signal générique et
    # réel d'une authentification via SMB/partage — vérifié sur des documents
    # réels, champ keyword (correspondance exacte fiable, pas de risque de
    # tokenisation sur une valeur numérique courte).
    "4625": "winlog.event_data.LogonType",
    # CADRE-CRE-006 (brute force WinRM depuis Kali, tentative réussie) :
    # 4624 seul est bien trop bruyant sur ce labo (voir commentaire 4732
    # ci-dessous, 922/931 hits/7j -- CADRE se connecte en admin à chaque
    # cycle). Corrélation sur le compte de TEST DÉDIÉ (jamais utilisé par
    # l'orchestrateur) plutôt que LogonType : rend 4624 exploitable sans
    # toucher au filtre existant. CONFIRMÉ par inspection d'un document 4624
    # réel indexé (event.code:4624, winlog.event_data.TargetUserName:
    # "CadreBruteTest", LogonType:3, channel:Security) ET par un cycle réel
    # complet (TP=1 FP=0/7j -- le bruit admin habituel est bien filtré,
    # winlog.event_data.IpAddress est vide sur ce type d'événement, donc une
    # corrélation par IP source n'aurait pas fonctionné ici).
    "4624": "winlog.event_data.TargetUserName",
    # G(PRI) : ajout à un groupe local security-enabled (ex. Administrateurs).
    # Vérifié sur un document réel indexé : `user.target.name` (ECS) est vide
    # ("-", mappé depuis MemberName, peu fiable côté 4732) -- le nom du
    # GROUPE cible est en réalité dans `user.target.group.name` (mappé
    # depuis TargetUserName), fiable et toujours peuplé. Vérifié aussi que
    # 4672/4624 (autres signaux "élévation" candidats) sont bien trop
    # bruyants sur ce labo (déclenchés par chaque connexion WinRM admin) --
    # 4732 est le seul des trois assez spécifique pour une règle exploitable.
    "4732": "user.target.group.name",
}

# Aligné sur la convention Elastic (mêmes bornes que les règles prépackagées
# Elastic Security -- interface Kibana : low=21, medium=47, high=73, critical=99).
# Bug corrigé (audit) : l'ancien code faisait `50 if severite == "medium" else 75`,
# ce qui donnait risk_score(low) == risk_score(high) == 75 et plaçait le "low"
# AU-DESSUS du "medium" (50) -- inversé par rapport à toute lecture triée par
# risque dans Kibana. `severite` inconnue (ne devrait pas arriver, NiveauRisque
# n'a que 3 valeurs) retombe sur "medium" (47), jamais sur le score le plus haut.
_RISK_SCORE_PAR_SEVERITE: dict[str, int] = {"low": 21, "medium": 47, "high": 73}


def _titre_sigma_yaml(nom: str) -> str:
    """Rend un nom sûr comme valeur de `title:` YAML sur une ligne.

    Double-quote (avec échappement) si le nom contient un caractère qui
    casserait un scalaire simple — indispensable pour ingérer des noms
    d'attaques arbitraires (ex. Atomic Red Team) contenant ':', '[', ']', '#'…
    Un nom déjà sûr (cas des attaques natives) est laissé tel quel, pour ne
    rien changer aux règles existantes.
    """
    nom = nom.replace("\n", " ").strip() or "Sans titre"
    caracteres_dangereux = set(":#[]{}'\"\\")
    debut_indicateur = nom[0] in "-?:&*!|>%@`,"
    if debut_indicateur or any(c in caracteres_dangereux for c in nom):
        echappe = nom.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{echappe}"'
    return nom


def _valeur_yaml_simple_quote(valeur: str | None) -> str:
    """Échappe `valeur` pour une insertion sûre dans un scalaire YAML entre
    guillemets SIMPLES ('...'), la convention utilisée par les motifs
    `contains:` générés depuis `attaque.valeur_detection`. Contrairement aux
    guillemets doubles (`_titre_sigma_yaml`) ou à EQL
    (`_calculer_clause_eql`), un scalaire YAML simple n'a qu'UNE règle
    d'échappement : un guillemet simple littéral se double (`''` représente
    `'`). Un saut de ligne littéral n'a aucune signification légitime dans
    une valeur de corrélation (jamais présent dans une ligne de commande
    réelle) et casserait le scalaire hors de son contexte -- injectant des
    clés YAML arbitraires dans le bloc `detection:` -- neutralisé en espace.
    `None` (attaque Linux sans `valeur_detection`, cas absent du catalogue
    natif mais possible côté perso/IA/Atomic) -> chaîne vide, jamais un
    plantage.

    Régression (audit sécurité) : ce champ vient du catalogue personnel
    (modifiable), d'un brouillon LLM ou d'un import Atomic Red Team --
    jamais échappé avant ce correctif, contrairement au chemin EQL voisin.
    """
    if valeur is None:
        return ""
    return valeur.replace("'", "''").replace("\n", " ").replace("\r", " ")


def _calculer_signature_detection(attaque: AttaqueCatalogue) -> tuple[str, str, str]:
    """
    Calcule le triplet `(produit, logsource_ligne, selection_lignes)` qui
    détermine la logique de détection RÉELLE d'une attaque — exactement ce
    que `generer_regle_sigma_depuis_attaque` transforme en règle Sigma.

    Extrait en fonction pure (aucun état d'instance requis) pour servir de
    source unique à la fois à la génération de règle ET à
    `detecter_regles_similaires` : deux attaques avec la même signature
    produisent une règle avec la même logique de déclenchement, quel que
    soit leur nom — un doublon fonctionnel que la dédup par nom (B7) ne
    peut pas voir.
    """
    if attaque.plateforme.value == "linux":
        return (
            "linux",
            "category: process_creation",
            f"    process.title|contains: '{_valeur_yaml_simple_quote(attaque.valeur_detection)}'",
        )

    event_id_principal = attaque.event_ids_attendus[0] if attaque.event_ids_attendus else "1"
    if event_id_principal in _SYSMON_EVENT_INFO:
        categorie, champ_correlation, _champ_ecs = _SYSMON_EVENT_INFO[event_id_principal]
        logsource_ligne = f"category: {categorie}"
    elif event_id_principal in _POWERSHELL_EVENT_INFO:
        champ_correlation, _champ_ecs = _POWERSHELL_EVENT_INFO[event_id_principal]
        logsource_ligne = "service: powershell"
    else:
        service = _NATIVE_SERVICE_PAR_EVENT.get(event_id_principal, "system")
        champ_correlation = _NATIVE_CHAMP_CORRELATION.get(event_id_principal)
        logsource_ligne = f"service: {service}"

    # EventID (pas event.code) : taxonomie Sysmon brute, traduite en champ
    # ECS par le pipeline pysigma ecs_windows à la compilation -- vérifié
    # (`"EventID": "event.code"` dans la table générique du pipeline,
    # appliquée à tout product:windows, donc y compris les branches
    # Security/System natives ci-dessus).
    selection_lignes = f"    EventID: {event_id_principal}"
    if attaque.valeur_detection and champ_correlation:
        valeur_echappee = _valeur_yaml_simple_quote(attaque.valeur_detection)
        selection_lignes += f"\n    {champ_correlation}|contains: '{valeur_echappee}'"

    return ("windows", logsource_ligne, selection_lignes)


def _calculer_clause_eql(attaque: AttaqueCatalogue) -> str:
    """
    Traduit la détection d'une attaque Windows en clause EQL `[process
    where ...]`, pour la corrélation de séquence entre étapes d'un
    scénario (`construire_sequence_eql`). Réutilise les mêmes tables
    EventID -> champ de corrélation que `_calculer_signature_detection`
    (même source de vérité, deux langages de sortie différents : Sigma
    pour la règle par attaque, EQL pour la séquence du scénario entier).

    Windows uniquement (vérifié : `event.category` n'est peuplé à
    "process" par le pipeline Sysmon/Winlogbeat que sur cette plateforme
    dans ce labo — la même hypothèse pour Linux/Auditbeat n'a pas été
    vérifiée, voir limite documentée sur `construire_sequence_eql`).
    """
    event_id_principal = attaque.event_ids_attendus[0] if attaque.event_ids_attendus else "1"
    if event_id_principal in _SYSMON_EVENT_INFO:
        champ_correlation = _SYSMON_EVENT_INFO[event_id_principal][2]
    elif event_id_principal in _POWERSHELL_EVENT_INFO:
        champ_correlation = _POWERSHELL_EVENT_INFO[event_id_principal][1]
    else:
        champ_correlation = _NATIVE_CHAMP_CORRELATION.get(event_id_principal)

    # event.code (pas EventID) : cette clause EQL part DIRECTEMENT vers
    # Elasticsearch, jamais traduite par un pipeline pysigma -- doit donc
    # toujours porter le champ ECS réel, contrairement à
    # _calculer_signature_detection ci-dessus (règle Sigma, brute, traduite
    # par ecs_windows à la compilation).
    clause = f'event.code == "{event_id_principal}"'
    if attaque.valeur_detection and champ_correlation:
        # Échappement EQL (vérifié contre l'API _eql/search réelle) : un
        # `"` littéral non échappé casse la chaîne EQL (ex. CADRE-DIS-005,
        # valeur_detection='NETSTAT.EXE" -ano' — même convention de chemin
        # quoté que Sigma, mais Sigma/YAML et EQL n'échappent pas pareil).
        valeur_echappee = attaque.valeur_detection.replace("\\", "\\\\").replace('"', '\\"')
        clause += f' and {champ_correlation} : "*{valeur_echappee}*"'
    return f"  [process where {clause}]"


def construire_sequence_eql(attaques: list[AttaqueCatalogue], maxspan_min: int) -> str:
    """
    Construit une requête EQL `sequence by host.name` à partir d'étapes de
    scénario DÉJÀ DÉTECTÉES, dans l'ordre de la kill chain — la corrélation
    demandée en plus de la dédup par nom (B7) : si les règles individuelles
    de chaque étape se déclenchent dans cet ordre sur le même hôte en moins
    de `maxspan_min` minutes, c'est un signal plus fort qu'une détection
    isolée (preuve de bout en bout de la kill chain, pas juste d'une étape).

    Windows uniquement pour l'instant (voir `_calculer_clause_eql`) —
    l'appelant (`executer_scenario`) ne construit une séquence que pour les
    scénarios `plateforme == "windows"`.
    """
    clauses = "\n".join(_calculer_clause_eql(a) for a in attaques)
    return f"sequence by host.name with maxspan={maxspan_min}m\n{clauses}"


def detecter_regles_similaires(
    catalogue: list[AttaqueCatalogue] | None = None,
) -> list[list[str]]:
    """
    Regroupe les attaques dont la règle générée aurait EXACTEMENT la même
    logique de détection (même produit, même logsource, même sélection) —
    des doublons fonctionnels malgré des noms différents. Ne retourne que
    les groupes de 2 attaques ou plus (les singletons ne sont pas des
    doublons). Par défaut, analyse `catalogue_actif()` (natif + attaques
    utilisateur) ; un catalogue explicite peut être injecté pour les tests.
    """
    if catalogue is None:
        catalogue = catalogue_actif()

    groupes: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    for attaque in catalogue:
        signature = _calculer_signature_detection(attaque)
        groupes[signature].append(attaque.id)

    return [ids for ids in groupes.values() if len(ids) > 1]


# --- Verrou de cycle inter-processus (F-009) --------------------------------
# `EtatCycle` (dashboard.py) empêche déjà deux cycles de tourner dans le MÊME
# processus (verrou en mémoire), mais rien n'empêchait `cadre daemon`/
# `cadre loop`/`cadre cycle` et le dashboard — des PROCESSUS séparés — de
# lancer un cycle réel chacun de leur côté contre la même VM/SIEM en même
# temps. Même convention que le pidfile de `cadre daemon` (cli.py:1060) :
# fichier contenant juste le PID, vérifié vivant via `os.kill(pid, 0)`.
_CHEMIN_VERROU_CYCLE = Path("./cadre_cycle.lock")
_VERROU_CYCLE_STALE_SEC = 7200  # 2h, largement > durée max mesurée (~18 min)


class VerrouCycleActifError(RuntimeError):
    """Un autre cycle réel tient déjà le verrou inter-processus F-009.

    Sous-classe dédiée (pas un RuntimeError brut) pour que les appelants
    puissent distinguer sans ambiguïté « collision de verrou, message
    opérationnel sûr à afficher tel quel » de toute autre exception
    inattendue à traiter avec la discipline log-only habituelle. Reste
    compatible avec `except RuntimeError`/`pytest.raises(RuntimeError)`
    existants (RuntimeError est une classe de base).
    """


def _acquerir_verrou_cycle() -> None:
    """Lève VerrouCycleActifError si un autre cycle RÉEL tourne déjà (autre processus).

    Nettoie silencieusement un verrou périmé (processus mort sans le
    libérer, ex. crash ou kill -9) plutôt que de bloquer indéfiniment.
    """
    chemin = _CHEMIN_VERROU_CYCLE
    try:
        fd = os.open(chemin, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        pid_existant = chemin.read_text(encoding="utf-8").strip()
        age_sec = time.time() - chemin.stat().st_mtime
        vivant = False
        if pid_existant.isdigit() and age_sec <= _VERROU_CYCLE_STALE_SEC:
            with contextlib.suppress(OSError):
                os.kill(int(pid_existant), 0)
                vivant = True
        if vivant:
            raise VerrouCycleActifError(
                f"Un autre cycle réel est déjà en cours (PID {pid_existant}, "
                f"verrou {chemin.absolute()}) — attendez sa fin ou vérifiez "
                f"qu'il n'est pas bloqué avant de relancer."
            ) from None
        # Verrou périmé (processus mort sans nettoyer, ou trop vieux) : remplacer.
        chemin.unlink(missing_ok=True)
        fd = os.open(chemin, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))


def _liberer_verrou_cycle() -> None:
    _CHEMIN_VERROU_CYCLE.unlink(missing_ok=True)


class OrchestrateurCADRE:
    """
    Orchestrateur principal d'un cycle d'audit CADRE.

    Configuration via :
    - Variables d'environnement
    - Fichier .env
    - Coffre-fort système
    - Arguments CLI
    """

    DEFAUT_CONFIG: ClassVar[dict[str, Any]] = {
        "vm_ip": "192.168.56.104",
        "vm_user": "CadreUser",
        "vm_pass": None,  # nosec B105 - défaut None, secret via coffre
        # --- Transport WinRM ---------------------------------------------
        # Défaut = laboratoire : HTTP en clair sur 5985, authentification
        # NTLM, certificat non vérifié. En PRODUCTION, on durcit via les
        # variables d'environnement CADRE_WINRM_* (voir _charger_config_env
        # et docs/SECURITY.md) : HTTPS sur 5986, Kerberos, certificat validé.
        # Ces valeurs par défaut laissent le comportement labo strictement
        # identique tant qu'aucune variable n'est positionnée.
        "vm_winrm_scheme": "http",  # "https" en production (port 5986)
        "vm_winrm_port": 5985,  # 5986 pour HTTPS
        "vm_winrm_transport": "ntlm",  # "kerberos" en environnement Active Directory
        "vm_winrm_cert_validation": "ignore",  # "validate" en production (certif de confiance)
        # --- Repli WinRM via VirtualBox (optionnel, désactivé par défaut) -----
        # Observé en réel le 27/08 : le service WinRM peut rester "Running"
        # côté Windows tout en ne répondant plus à aucune requête réseau
        # (timeout systématique). vm_vbox_nom = None -> mécanisme totalement
        # désactivé, comportement inchangé. Renseigné (nom exact de la VM
        # dans VirtualBox), un TimeoutError WinRM déclenche UNE tentative de
        # redémarrage du service via `VBoxManage guestcontrol` -- canal
        # indépendant de WinRM (Guest Additions) -- avant d'abandonner.
        # Suppose VirtualBox installé sur l'hôte CADRE lui-même (pas
        # applicable à VMware/Hyper-V/cloud). Réutilise vm_user/vm_pass.
        "vm_vbox_nom": None,
        # Chemin explicite de VBoxManage.exe si hors PATH et hors
        # l'emplacement d'installation Windows par défaut (voir
        # _resoudre_chemin_vboxmanage). None = résolution automatique.
        "vm_vbox_manage_chemin": None,
        # --- Cible LINUX (optionnelle) : exécution SSH, télémétrie Auditbeat ---
        # None = pas de cible Linux configurée -> les attaques Linux restent
        # NON_APPLICABLE. Renseigner ip/user/pass (via coffre) active le
        # routage : une attaque `linux` s'exécute par SSH sur cette VM et sa
        # détection se valide contre l'index Auditbeat (process.title).
        "linux_vm_ip": None,
        "linux_vm_user": None,
        "linux_vm_pass": None,  # nosec B105 - chargé du coffre (CADRE_LINUX_VM_PASS)
        "linux_vm_port": 22,
        "index_pattern_linux": "auditbeat-*",
        "elastic_url": "http://127.0.0.1:9200",
        "elastic_user": "elastic",
        "elastic_pass": None,  # nosec B105 - défaut None, secret via coffre
        "index_pattern": "winlogbeat-*",
        "kibana_url": "http://127.0.0.1:5601",
        "timeout_indexation_sec": 180,
        "seuil_fp_max": 50,
        # Pause entre deux attaques d'un cycle (laisse retomber la charge
        # cible/SIEM). 2 s par défaut : suffisant en labo, et ~3 s x62 gagnées
        # par rapport à l'ancien 5 s sur un cycle complet (voir AUDIT-DASH/1b).
        "pause_entre_attaques_sec": 2,
        # Disjoncteur (circuit breaker) : nombre d'échecs d'EXÉCUTION
        # WinRM/SSH consécutifs au-delà duquel un cycle s'interrompt au lieu
        # de s'acharner sur toutes les attaques restantes. Trouvé en réel le
        # 28/08 : sous la charge d'un cycle complet, le service WinRM de la
        # VM cible peut passer "zombie" (port ouvert, mais aucune commande
        # ne répond) -- 20 attaques de suite ont échoué en "Échec exécution"
        # (~50 min gaspillées) sans que le cycle ne réagisse. Un échec
        # d'exécution est reconnu par son statut ERREUR ; un NON_APPLICABLE
        # (plateforme sans cible) est neutre (ni incrément ni reset), et
        # tout succès réel (validé, angle mort, faux négatif -- preuve que
        # l'exécution fonctionne) remet le compteur à zéro. 0 désactive le
        # disjoncteur.
        "seuil_echecs_execution_consecutifs": 5,
        # La cible a-t-elle un accès Internet ? Défaut False = réseau host-only
        # (labo isolé, par design de sécurité). Les attaques `requires_internet`
        # sont alors NON_APPLICABLE (ex. certutil download) plutôt qu'en échec.
        "cible_a_internet": False,
        "repertoire_rapports": Path("./rapports"),
        "repertoire_regles": Path("./rules_generees"),
        # Plateforme de la cible réellement configurée ("windows" ou
        # "linux") — détermine quelles attaques du catalogue sont
        # applicables. Une attaque dont la plateforme ne correspond pas
        # est marquée NON_APPLICABLE sans jamais toucher WinRM, plutôt que
        # de remonter un faux "Échec exécution WinRM" trompeur.
        "plateforme_cible": "windows",
        # Si True, demande en plus à l'assistant LLM un brouillon de règle
        # Sigma à titre comparatif (jamais compilé/validé/déployé — voir
        # AssistantLLM.suggerer_regle_sigma). Coûteux (~1-2 min/attaque),
        # désactivé par défaut.
        "ia_brouillon_regle": False,
        # Générateur de la règle réellement candidate au déploiement :
        # "deterministe" (défaut, reproductible) ou "llm" (le LLM rédige la
        # règle). DANS LES DEUX CAS, la règle passe par la MÊME validation
        # TP/FP avant déploiement : la confiance vient de la validation, pas
        # du générateur. Le mode "llm" retombe automatiquement sur le
        # déterministe si le LLM échoue ou produit une règle non compilable.
        "mode_generation_regle": "deterministe",
    }

    # Config NON-SECRÈTE surchargeable par variable d'environnement.
    # (env var -> clé de config, convertisseur). Les mots de passe ne sont PAS
    # ici : ils passent par le coffre-fort (_charger_secrets), jamais par une
    # simple variable lisible. C'est ce qui permet un déploiement production
    # (docker-compose, CI) de pointer vers une autre VM / un autre SIEM et de
    # durcir WinRM sans modifier une ligne de code.
    _CONFIG_ENV: ClassVar[dict[str, tuple[str, Any]]] = {
        "CADRE_VM_IP": ("vm_ip", str),
        "CADRE_VM_USER": ("vm_user", str),
        "CADRE_ELASTIC_URL": ("elastic_url", str),
        "CADRE_ELASTIC_USER": ("elastic_user", str),
        "CADRE_KIBANA_URL": ("kibana_url", str),
        "CADRE_INDEX_PATTERN": ("index_pattern", str),
        "CADRE_WINRM_SCHEME": ("vm_winrm_scheme", str),
        "CADRE_WINRM_PORT": ("vm_winrm_port", int),
        "CADRE_WINRM_TRANSPORT": ("vm_winrm_transport", str),
        "CADRE_WINRM_CERT_VALIDATION": ("vm_winrm_cert_validation", str),
        "CADRE_VM_VBOX_NOM": ("vm_vbox_nom", str),
        "CADRE_VM_VBOX_MANAGE_CHEMIN": ("vm_vbox_manage_chemin", str),
        "CADRE_LINUX_VM_IP": ("linux_vm_ip", str),
        "CADRE_LINUX_VM_USER": ("linux_vm_user", str),
        "CADRE_LINUX_VM_PORT": ("linux_vm_port", int),
        "CADRE_INDEX_PATTERN_LINUX": ("index_pattern_linux", str),
    }

    def __init__(self, config: dict[str, Any] | None = None):
        self.log = obtenir_logger()
        # Priorité : DEFAUT_CONFIG < variables d'environnement < config passée
        # explicitement au constructeur (la plus spécifique gagne).
        self.config = dict(self.DEFAUT_CONFIG)
        self._charger_config_env()
        self.config.update(config or {})
        self._charger_secrets()
        self._initialiser_repertoires()
        self.resultats: list[dict[str, Any]] = []
        # G2 : contexte de progression par thread (dashboard) -- en séquentiel
        # (un seul thread) se comporte exactement comme un attribut d'instance ;
        # en parallèle, chaque thread worker a son propre espace, donc plus
        # d'écrasement croisé entre deux attaques exécutées en même temps.
        self._tls = threading.local()
        self.derniere_sortie_ssh: str | None = None  # voir diagnostiquer_kali()

    def _charger_config_env(self) -> None:
        """
        Surcharge la config non-secrète depuis les variables d'environnement
        (`CADRE_VM_IP`, `CADRE_ELASTIC_URL`, `CADRE_WINRM_*`…). Lue directement
        dans `os.environ` (pas le coffre-fort) : ce ne sont pas des secrets, et
        c'est le canal standard d'un déploiement conteneurisé. Absente = la
        valeur par défaut (laboratoire) est conservée.
        """
        for env_key, (cfg_key, conv) in self._CONFIG_ENV.items():
            brut = os.environ.get(env_key)
            if not brut:
                continue
            try:
                self.config[cfg_key] = conv(brut)
            except (ValueError, TypeError):
                self.log.warn(
                    f"{env_key}='{brut}' invalide — valeur par défaut conservée "
                    f"({cfg_key}={self.config[cfg_key]})"
                )

    def _charger_secrets(self):
        """Charge les secrets depuis le coffre-fort."""
        coffre = obtenir_coffre()
        try:
            if not self.config.get("vm_pass"):
                self.config["vm_pass"] = coffre.obtenir("CADRE_VM_PASS")
            if not self.config.get("elastic_pass"):
                self.config["elastic_pass"] = coffre.obtenir("CADRE_ELASTIC_PASS")
        except ErreurSecurite as e:
            self.log.warn(
                f"Secret manquant : {e}. "
                f"Définissez-le avec : cadre init --set CADRE_VM_PASS=..."
            )

        # Cible Linux — entièrement OPTIONNELLE (absente par défaut). Le mot de
        # passe est un secret ; l'IP et l'utilisateur peuvent aussi avoir été
        # stockés via `cadre init --set`. On les lit du MÊME coffre (mockable en
        # test), en repli après les variables d'environnement. Une clé absente
        # n'est pas une erreur : on la laisse à None sans alerte.
        #
        # CADRE_BRUTE_TEST_PASS / CADRE_INI_ACCESS_TEST_PASS : mots de passe
        # des comptes Windows de test dédiés utilisés par CADRE-CRE-006 /
        # CADRE-INI-001 (brute force / accès initial WinRM depuis Kali).
        # Autrefois codés en dur dans catalogue_attaques.py -- un secret
        # réel (même limité à un compte non-admin de labo) n'a pas sa place
        # en clair dans le code source, a fortiori un dépôt destiné à
        # devenir public. Même absence-silencieuse que les secrets Linux :
        # ces deux attaques restent dans le catalogue mais échouent
        # proprement (message clair) tant que le secret n'est pas défini.
        for cle, champ in (
            ("CADRE_LINUX_VM_PASS", "linux_vm_pass"),
            ("CADRE_LINUX_VM_IP", "linux_vm_ip"),
            ("CADRE_LINUX_VM_USER", "linux_vm_user"),
            ("CADRE_BRUTE_TEST_PASS", "brute_test_pass"),
            ("CADRE_INI_ACCESS_TEST_PASS", "ini_access_test_pass"),
        ):
            if not self.config.get(champ):
                # Clé absente = cible/attaque non configurée (cas normal par défaut).
                with contextlib.suppress(ErreurSecurite):
                    self.config[champ] = coffre.obtenir(cle)

    def _initialiser_repertoires(self):
        """Crée les répertoires de sortie."""
        self.config["repertoire_rapports"].mkdir(parents=True, exist_ok=True)
        self.config["repertoire_regles"].mkdir(parents=True, exist_ok=True)

    @property
    def auth_elastic(self) -> tuple | None:
        if self.config.get("elastic_user") and self.config.get("elastic_pass"):
            return (self.config["elastic_user"], self.config["elastic_pass"])
        return None

    def _executer_avec_timeout_dur(
        self, appel: Callable[[], Any], timeout_sec: float | None = None
    ) -> Any:
        """
        Exécute `appel()` (ex. `lambda: session.run_ps(...)` ou
        `lambda: session.run_cmd(...)`) dans un thread daemon, borné à
        `timeout_sec` (défaut : TIMEOUT_GLOBAL_WINRM_SEC -- voir la constante
        pour le contexte complet : régression réelle où pywinrm a sondé en
        boucle plusieurs minutes sans jamais abandonner, la commande distante
        ne rendant jamais la main).

        Généralisée (27/08, trouvé par revue indépendante) : codée en dur
        pour `session.run_ps()` à l'origine, mais `verifier_winrm_reel()`
        appelait `session.run_cmd()` DIRECTEMENT, sans ce garde-fou -- alors
        que c'est PRÉCISÉMENT le scénario "port ouvert, service figé" que
        cette méthode existe pour détecter qui déclenche la boucle sans
        borne de pywinrm (voir docstring de `verifier_winrm_reel`). Un
        `timeout_sec` explicite permet un plafond plus court qu'un cycle
        d'attaque pour un contrôle de santé rapide.

        Thread daemon + join(timeout=...), pas ThreadPoolExecutor : un futur
        dont le timeout expire n'annule PAS le thread sous-jacent (Python ne
        sait pas tuer un thread), et `with ThreadPoolExecutor(...)` attendrait
        ce thread bloqué à la sortie du bloc -- annulant le plafond.
        `daemon=True` garantit en plus qu'un thread abandonné (blocage
        réellement infini côté cible) ne retient jamais la sortie du
        processus `cadre` lui-même.
        """
        delai = TIMEOUT_GLOBAL_WINRM_SEC if timeout_sec is None else timeout_sec
        resultat_case: dict[str, Any] = {}
        erreur_case: dict[str, BaseException] = {}

        def _cible() -> None:
            try:
                resultat_case["r"] = appel()
            except BaseException as exc:
                erreur_case["e"] = exc

        thread_winrm = threading.Thread(target=_cible, daemon=True)
        thread_winrm.start()
        thread_winrm.join(timeout=delai)
        if thread_winrm.is_alive():
            raise TimeoutError(
                f"Appel WinRM bloqué au-delà de {delai}s "
                f"(commande distante probablement figée côté cible)"
            )
        if "e" in erreur_case:
            raise erreur_case["e"]
        return resultat_case["r"]

    def _prerequis_winrm_manquants(self) -> bool:
        """True si un prérequis (module pywinrm, identifiants, connectivité
        réseau) manque avant de tenter un appel WinRM -- logue la raison
        précise et laisse l'appelant (executer_commande_winrm) retourner
        False en un seul endroit. Extrait uniquement pour rester sous la
        limite ruff PLR0911 (6 points de sortie max) après l'ajout du
        branchement `except TimeoutError` dédié ci-dessous -- aucun
        changement de comportement, mêmes 3 vérifications qu'avant."""
        if not WINRM_DISPONIBLE:
            self.log.error("Module 'pywinrm' non installé. pip install pywinrm")
            return True

        if not all(
            [
                self.config.get("vm_ip"),
                self.config.get("vm_user"),
                self.config.get("vm_pass"),
            ]
        ):
            self.log.error("Identifiants VM manquants (CADRE_VM_*)")
            return True

        # Test de connectivité avant WinRM
        if not self._verifier_connectivite_vm():
            self.log.error(
                f"VM {self.config['vm_ip']} inaccessible. Vérifiez : "
                f"(1) VM allumée, (2) réseau Host-Only actif, "
                f"(3) WinRM activé: Enable-PSRemoting -Force, "
                f"(4) Pare-feu ouvert sur port {self.config['vm_winrm_port']}"
            )
            return True

        return False

    @staticmethod
    def _encoder_commande_powershell(commande_powershell: str) -> str:
        """Encode une commande PowerShell en Base64 UTF-16LE pour
        `-EncodedCommand` -- contourne le parsing PowerShell qui échoue sur
        les commandes avec `&& < > " ;`. Partagé entre `executer_commande_winrm`
        et `_tenter_recuperation_winrm_vbox`."""
        return base64.b64encode(commande_powershell.encode("utf-16-le")).decode("ascii")

    def executer_commande_winrm(
        self,
        commande: str,
        timeout_sec: int = 30,
    ) -> bool:
        """
        Exécute une commande sur la VM cible via WinRM.
        Retourne True si l'exécution a réussi (même si la commande cible échoue).
        """
        if self._prerequis_winrm_manquants():
            return False

        # Envelopper la commande pour la rendre silencieuse et sécurisée.
        # IMPORTANT : on encode en Base64 (UTF-16LE) pour contourner le parsing
        # PowerShell qui échoue sur les commandes avec && < > " ;
        # "; exit 0" final : sans ça, powershell.exe propage le
        # $LASTEXITCODE de la dernière commande native comme code de sortie
        # du PROCESSUS powershell.exe lui-même — ce qui fait échouer
        # executer_commande_winrm() (qui vérifie status_code==0) pour toute
        # attaque dont le scénario testé échoue *volontairement* (ex:
        # mot de passe erroné pour tester une détection d'échec
        # d'authentification). Le Try/Catch swallow déjà les exceptions ;
        # ce exit explicite garantit qu'un exit code natif non-nul ne fait
        # jamais échouer l'appel WinRM lui-même.
        commande_silencieuse = (
            f"$ProgressPreference = 'SilentlyContinue'; "
            f"$ErrorActionPreference = 'SilentlyContinue'; "
            f"Try {{ {commande} }} Catch {{ Write-Host 'CADRE_CAUGHT_ERROR' }}; exit 0"
        )
        commande_b64 = self._encoder_commande_powershell(commande_silencieuse)
        # Préfixe standard PowerShell -EncodedCommand
        cmd_securisee = f"powershell.exe -NoProfile -EncodedCommand {commande_b64}"

        # Repli WinRM (optionnel, cf. vm_vbox_nom) : au plus UNE tentative de
        # récupération via VirtualBox par appel -- jamais de boucle. Voir le
        # commentaire du except TimeoutError ci-dessous pour le raisonnement.
        recuperation_deja_tentee = False

        # Retry avec backoff exponentiel (max 3 tentatives). Boucle `while`
        # (pas `for tentative in range(1, 4)`) délibérément : le `continue`
        # après une récupération VirtualBox réussie (bloc `except TimeoutError`
        # ci-dessous) doit sauter l'incrémentation de `tentative` -- avec un
        # `for range()`, un TimeoutError survenant précisément à la 3e
        # tentative épuisait l'itérateur au `continue` et gaspillait
        # silencieusement une récupération pourtant réussie (bug trouvé par
        # revue indépendante, 27/08) : la boucle se terminait sans jamais
        # retenter la commande, ni même logguer l'abandon.
        tentative = 1
        while tentative <= 3:
            try:
                self.log.attack(
                    f"WinRM -> {self.config['vm_ip']} : {commande[:80]}...",
                    commande=commande[:120],
                    tentative=tentative,
                )
                # Endpoint construit depuis la config : en labo
                # http://<ip>:5985/wsman (identique au défaut pywinrm), en
                # production https://<ip>:5986/wsman. Le transport (ntlm ou
                # kerberos) et la validation du certificat sont eux aussi
                # configurables — voir DEFAUT_CONFIG et docs/SECURITY.md.
                endpoint = (
                    f"{self.config['vm_winrm_scheme']}://{self.config['vm_ip']}"
                    f":{self.config['vm_winrm_port']}/wsman"
                )
                session = winrm.Session(
                    endpoint,
                    auth=(self.config["vm_user"], self.config["vm_pass"]),
                    transport=self.config["vm_winrm_transport"],
                    server_cert_validation=self.config["vm_winrm_cert_validation"],
                    read_timeout_sec=timeout_sec,
                )

                def _lancer_run_ps(s: Any = session) -> Any:
                    return s.run_ps(cmd_securisee)

                resultat = self._executer_avec_timeout_dur(_lancer_run_ps)
                time.sleep(2)  # Laisse l'OS propager l'événement à Sysmon
                # Status 0 = OK. CADRE a Catch silencieux donc on accepte
                # même si la commande cible échoue — l'important est qu'elle
                # ait été lancée (événement Sysmon émis).
                if resultat.status_code == 0:
                    return True
                self.log.warn(
                    f"WinRM status {resultat.status_code} — retry {tentative}/3",
                    stderr=(
                        resultat.std_err.decode("utf-8", errors="replace")
                        if resultat.std_err
                        else ""
                    )[:200],
                )
            except TimeoutError as e:
                # Distinct du except Exception générique ci-dessous : un
                # TimeoutError ici vient EXCLUSIVEMENT de
                # _executer_avec_timeout_dur() -- le thread daemon a
                # été abandonné et, avec lui, le Shell WinRM distant n'a
                # JAMAIS été fermé proprement. pywinrm (winrm/__init__.py,
                # Session.run_cmd) n'appelle cleanup_command()/close_shell()
                # qu'APRÈS le retour de get_command_output() -- jamais
                # atteint sur ce chemin puisque get_command_output_raw()
                # boucle indéfiniment (winrm/protocol.py : "operation
                # timeouts while receiving output ... will be silently
                # retried indefinitely", confirmé en lisant la lib
                # installée). Le Shell reste donc ouvert côté cible jusqu'à
                # son IdleTimeout WinRM (2h par défaut).
                #
                # Réessayer ici rouvrirait un NOUVEAU Shell (nouvelle
                # winrm.Session ci-dessus) tout en laissant le premier
                # fuiter -- et la même commande a de fortes chances de
                # re-bloquer pour la même raison côté cible (ex.
                # Get-MpComputerStatus figé), contrairement aux autres
                # branches de ce retry qui visent un aléa réseau ponctuel.
                # Avec le défaut WinRM MaxShellsPerUser=5, les 3 tentatives
                # normales suffiraient À ELLES SEULES à épuiser le quota et
                # à rendre INDISPONIBLES toutes les commandes WinRM
                # suivantes du cycle (pas seulement celle-ci). On abandonne
                # donc immédiatement, sans retry ni backoff --
                #
                # SAUF repli optionnel (vm_vbox_nom configuré, cf.
                # _tenter_recuperation_winrm_vbox) : un redémarrage RÉUSSI du
                # service WinRM (confirmé par le code de retour VBoxManage,
                # pas juste tenté) rend un unique retry raisonnable dans CE
                # cas précis -- SEULE la connectivité retrouvée a été vérifiée
                # en conditions réelles (revue indépendante 27/08) ; que le
                # redémarrage du service tue aussi tout Shell WinRM orphelin
                # déjà ouvert côté cible AVANT le redémarrage n'a pas été
                # prouvé (plausible, pas confirmé empiriquement) -- à garder
                # en tête, pas à présenter comme établi. Borné à une seule
                # tentative de récupération par appel (recuperation_deja_
                # tentee), jamais de boucle.
                if not recuperation_deja_tentee and self.config.get("vm_vbox_nom"):
                    recuperation_deja_tentee = True
                    self.log.warn(f"WinRM : {e} — tentative de récupération via VirtualBox")
                    if self._tenter_recuperation_winrm_vbox():
                        self.log.attack("Récupération réussie — nouvelle tentative WinRM")
                        # Uniquement au rang 3 (cas décrit ci-dessus) le
                        # `continue` saute l'incrémentation, pour donner à la
                        # récupération le seul essai qu'elle mérite sans
                        # jamais dépasser 3 tentatives normales + 1 bonus
                        # borné (revue indépendante, 27/08 : sans ce garde-
                        # fou, un TimeoutError récupéré au rang 1 ou 2
                        # offrait aussi un bonus, portant le total à 4 dans
                        # des cas non voulus et non testés).
                        if tentative < 3:
                            tentative += 1
                        continue
                suffixe = (
                    "après échec de la récupération"
                    if recuperation_deja_tentee
                    else "immédiat sans retry"
                )
                self.log.error(
                    f"WinRM : {e} — abandon {suffixe} "
                    f"(évite de multiplier les Shells distants non fermés sur la cible)"
                )
                return False
            except Exception as e:
                self.log.warn(
                    f"Tentative {tentative}/3 échouée : {type(e).__name__}",
                    erreur=str(e)[:200],
                )
                if tentative < 3:
                    time.sleep(2**tentative)  # Backoff: 2s, 4s
                else:
                    self.log.error("WinRM définitivement inaccessible après 3 tentatives")
                    return False
            tentative += 1
        return False

    def _port_accessible(self, ip: str | None, port: int, timeout: float = 3.0) -> bool:
        """Teste rapidement qu'un port TCP est ouvert (évite d'attendre pour rien)."""
        if not ip:
            return False
        try:
            # U3/V1 : `with` garantit la fermeture du socket même si
            # settimeout()/connect_ex() lève une exception inattendue
            # (CWE-404 — avant : sock.close() n'était atteint que sur le
            # chemin de succès).
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                ouvert = sock.connect_ex((ip, port)) == 0
            if not ouvert:
                self.log.warn(f"Port {port} fermé ou filtré sur {ip}")
            return ouvert
        except Exception as e:
            self.log.warn(f"Erreur test connectivité {ip}:{port} : {e}")
            return False

    def _verifier_connectivite_vm(self) -> bool:
        """Connectivité de la VM Windows avant WinRM (port 5985/5986 configuré)."""
        return self._port_accessible(
            self.config.get("vm_ip", ""), int(self.config.get("vm_winrm_port", 5985))
        )

    def verifier_winrm_reel(self, timeout_sec: int = 8) -> tuple[bool, str]:
        """Test WinRM RÉEL (une commande minimale, un seul essai, pas de retry) --
        pas juste le port TCP. Observé en réel (27/08) : le port 5985 peut
        répondre "ouvert" alors que le service WinRM lui-même est figé (aucune
        commande n'aboutit, timeout systématique) -- un simple test de port ne
        détecte pas cette panne. Timeout volontairement court et sans retry
        (contrairement à executer_commande_winrm) : ceci sert à un contrôle de
        santé rapide (`cadre status`), pas à l'exécution d'une attaque.

        Passe par `_executer_avec_timeout_dur` (trouvé par revue indépendante,
        27/08) : `read_timeout_sec`/`operation_timeout_sec` de pywinrm ne
        bornent que CHAQUE requête HTTP individuelle -- pas la boucle de
        sondage interne de pywinrm (`get_command_output`), qui retente les
        timeouts d'opération INDÉFINIMENT sans jamais abandonner (confirmé
        dans le code source de pywinrm installé). Sans ce garde-fou, cette
        méthode pouvait bloquer indéfiniment dans EXACTEMENT le scénario
        "port ouvert, service figé" qu'elle existe pour diagnostiquer
        rapidement -- l'inverse de l'effet recherché."""
        if not WINRM_DISPONIBLE:
            return False, "pywinrm non installé"
        if not all(
            [self.config.get("vm_ip"), self.config.get("vm_user"), self.config.get("vm_pass")]
        ):
            return False, "identifiants VM manquants (CADRE_VM_*)"
        if not self._verifier_connectivite_vm():
            return False, f"port {self.config.get('vm_winrm_port', 5985)} fermé ou filtré"
        try:
            endpoint = (
                f"{self.config['vm_winrm_scheme']}://{self.config['vm_ip']}"
                f":{self.config['vm_winrm_port']}/wsman"
            )
            session = winrm.Session(
                endpoint,
                auth=(self.config["vm_user"], self.config["vm_pass"]),
                transport=self.config["vm_winrm_transport"],
                server_cert_validation=self.config["vm_winrm_cert_validation"],
                read_timeout_sec=timeout_sec,
                operation_timeout_sec=max(timeout_sec - 2, 1),
            )
            resultat = self._executer_avec_timeout_dur(
                lambda: session.run_cmd("echo CADRE_STATUS_CHECK"), timeout_sec=timeout_sec
            )
            if resultat.status_code == 0:
                return True, "OK"
            return False, f"commande d'echo a échoué (code {resultat.status_code})"
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"

    def _resoudre_chemin_vboxmanage(self) -> str | None:
        """Override explicite (vm_vbox_manage_chemin) > emplacement
        d'installation Windows par défaut > PATH (shutil.which). Jamais
        d'exception si introuvable -- None, le repli se désactive.

        Sécurité (trouvé par revue indépendante, 27/08) : `shutil.which`
        n'est atteint que si les deux étapes précédentes échouent (install
        VirtualBox hors de l'emplacement par défaut) -- résout alors selon
        le PATH du processus, sans validation, contrairement au chemin
        ABSOLU codé en dur pour l'exécutable côté invité juste en dessous
        (`_tenter_recuperation_winrm_vbox`). Un attaquant local capable
        d'altérer le PATH de ce processus pourrait faire exécuter un binaire
        arbitraire à sa place (avec les identifiants VM en downstream). Pas
        de vérification de signature ici (hors de portée pour un outil SOC
        mono-opérateur) -- au minimum, ce chemin moins sûr est tracé
        explicitement pour rester auditable plutôt que silencieux."""
        override = self.config.get("vm_vbox_manage_chemin")
        if override:
            return override if Path(override).exists() else None
        chemin_defaut_windows = Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")
        if chemin_defaut_windows.exists():
            return str(chemin_defaut_windows)
        chemin_path = shutil.which("VBoxManage")
        if chemin_path:
            self.log.warn(
                f"VBoxManage résolu via PATH ({chemin_path}), hors de l'emplacement "
                f"d'installation par défaut -- moins fiable, envisager "
                f"vm_vbox_manage_chemin pour fixer un chemin explicite"
            )
        return chemin_path

    def _prerequis_recuperation_vbox_manquants(self) -> str | None:
        """Retourne le chemin résolu de VBoxManage si tous les pré-requis
        sont réunis (VBoxManage trouvé, identifiants VM présents), sinon
        None -- logue la raison précise et laisse l'appelant retourner False
        en un seul endroit (même technique que _prerequis_winrm_manquants
        ci-dessus, pour rester sous la limite ruff PLR0911 après l'ajout de
        la validation des identifiants, revue indépendante 27/08 : vm_pass
        peut légitimement valoir None -- absent du coffre-fort,
        _charger_secrets se contente d'un warn -- et sans ce garde-fou,
        f.write(None) levait un TypeError hors de tout try/finally, laissant
        un fichier orphelin et une exception remontant de façon incontrôlée
        jusqu'à l'appelant)."""
        vboxmanage = self._resoudre_chemin_vboxmanage()
        if not vboxmanage:
            self.log.warn(
                "Récupération WinRM via VirtualBox demandée (vm_vbox_nom configuré) "
                "mais VBoxManage introuvable"
            )
            return None
        if not all([self.config.get("vm_user"), self.config.get("vm_pass")]):
            self.log.warn("Récupération WinRM via VirtualBox : identifiants VM manquants")
            return None
        return vboxmanage

    def _tenter_recuperation_winrm_vbox(self) -> bool:
        """Redémarre le service WinRM sur la VM via `VBoxManage guestcontrol`
        (canal VirtualBox Guest Additions, indépendant de WinRM) -- repli
        optionnel, actif uniquement si `vm_vbox_nom` est configuré. Observé
        en réel le 27/08 : WinRM peut rester "Running" côté Service Control
        Manager tout en ne répondant plus à aucune requête réseau ; un
        simple redémarrage du service, hors bande via ce canal indépendant,
        a suffi à rétablir la connectivité pour une fenêtre de quelques
        minutes.

        Sécurité (trouvé par revue indépendante, 27/08) : le mot de passe VM
        ne transite JAMAIS en argument de ligne de commande (`--password`
        l'aurait rendu visible via `wmic`/Process Explorer par tout process
        local le temps de l'exécution, CWE-214) -- écrit dans un fichier
        temporaire à permissions utilisateur (identifiants validés en amont,
        `newline=""` pour ne pas corrompre un mot de passe contenant un \n),
        supprimé systématiquement (`finally` ; un échec de suppression est
        loggé, jamais avalé en silence -- cf. conflit SentinelOne documenté
        sur ce poste, qui peut verrouiller un fichier fraîchement créé).
        `subprocess.TimeoutExpired` est capturée SÉPARÉMENT du cas générique,
        sans jamais logguer `e` directement : `TimeoutExpired.__str__()`
        réintègre l'argv complet (CWE-532) -- même sans mot de passe en
        clair désormais, ce chemin reste délibérément silencieux sur le
        contenu de l'exception."""
        vm_nom = self.config.get("vm_vbox_nom")
        if not vm_nom:
            return False
        vboxmanage = self._prerequis_recuperation_vbox_manquants()
        if vboxmanage is None:
            return False
        commande_b64 = self._encoder_commande_powershell("Restart-Service WinRM -Force")

        # newline="" (revue indépendante, 27/08) : sans cela, le mode texte
        # de Python traduit tout \n du mot de passe en \r\n sur Windows,
        # corrompant le fichier lu par --passwordfile et causant un échec
        # d'authentification silencieux si le mot de passe contient un \n
        # littéral.
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".tmp", delete=False, newline="", encoding="utf-8"
        ) as f:
            f.write(self.config["vm_pass"])
            chemin_pass = f.name
        # Fichier fermé ici (hors du `with`) : libère le verrou Windows avant
        # que VBoxManage n'essaie de le lire lui-même.
        try:
            try:
                resultat = subprocess.run(  # nosec B603 - argv liste, pas de shell, chemin résolu
                    [
                        vboxmanage,
                        "guestcontrol",
                        vm_nom,
                        "run",
                        "--username",
                        self.config["vm_user"],
                        "--passwordfile",
                        chemin_pass,
                        "--exe",
                        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        "--wait-stdout",
                        "--",
                        "powershell.exe",
                        "-NoProfile",
                        "-EncodedCommand",
                        commande_b64,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                # Ne JAMAIS logguer cette exception directement : son
                # __str__ natif réintègre l'argv complet (voir docstring).
                self.log.warn("Récupération WinRM via VirtualBox : timeout après 60s")
                return False
            except OSError as e:
                self.log.warn(f"Récupération WinRM via VirtualBox échouée : {type(e).__name__}")
                return False
        finally:
            # Pas de contextlib.suppress (revue indépendante, 27/08) : un
            # échec de suppression (ex. verrou EDR sur un fichier fraîchement
            # créé, cf. conflit SentinelOne déjà documenté sur ce poste)
            # laissait le mot de passe en clair sur le disque INDÉFINIMENT,
            # sans la moindre trace de log. Le nom du fichier n'est pas
            # sensible, seul son contenu l'est -- safe à logger.
            try:
                Path(chemin_pass).unlink()
            except OSError as e:
                self.log.warn(
                    f"Fichier temporaire du mot de passe non supprimé "
                    f"({chemin_pass}) : {type(e).__name__}"
                )

        if resultat.returncode == 0:
            self.log.attack(f"Service WinRM redémarré via VBoxManage guestcontrol ({vm_nom})")
            time.sleep(3)  # laisse le service redémarré se stabiliser avant de retenter
            return True
        self.log.warn(
            f"Récupération WinRM via VirtualBox : code retour {resultat.returncode}",
            stderr=(resultat.stderr or "")[:200],
        )
        return False

    def _cible_joignable(self, cible: dict[str, Any]) -> bool:
        """La cible est-elle RÉELLEMENT joignable (module client présent + port
        ouvert) ? Sert à distinguer une cible ABSENTE (VM éteinte, module non
        installé → NON_APPLICABLE, pas un échec CADRE) d'une cible joignable dont
        la commande échoue vraiment (→ ERREUR). Voir AUDIT-DASH/1a-erreurs.md :
        sans ce pré-vol, 20 attaques Linux dont la VM Kali est éteinte étaient
        classées à tort en ERREUR, effondrant le taux de réussite affiché."""
        if cible.get("origine") == "kali":
            # Origine Kali : c'est la joignabilité SSH de Kali qui compte,
            # pas celle de la cible Windows (cible["plateforme"] vaut
            # "windows" ici -- vérifier le mauvais port serait un faux négatif
            # de joignabilité).
            if not PARAMIKO_DISPONIBLE:
                return False
            return self._port_accessible(
                self.config.get("linux_vm_ip") or "", int(self.config.get("linux_vm_port", 22))
            )
        if cible["plateforme"] == "linux":
            if not PARAMIKO_DISPONIBLE:
                return False
            return self._port_accessible(
                self.config.get("linux_vm_ip") or "", int(self.config.get("linux_vm_port", 22))
            )
        # windows
        if not WINRM_DISPONIBLE:
            return False
        return self._verifier_connectivite_vm()

    def _executer_ssh(
        self,
        ip: str | None,
        user: str | None,
        pwd: str | None,
        port: int,
        commande: str,
        timeout_sec: int,
        contexte_log: str,
        sleep_apres: float = 0,
        capturer_sortie: bool = False,
        commande_log: str | None = None,
    ) -> bool:
        """
        Cœur SSH partagé (paramiko) : connexion + exécution + retry, sans
        connaître la sémantique de l'appelant (cible Linux locale ou Kali
        attaquant une cible tierce). Retourne True dès que la commande a pu
        être LANCÉE (même si elle échoue côté distant), False seulement si la
        connexion est impossible. `contexte_log` personnalise le message
        d'attaque ; `sleep_apres` laisse le temps à l'agent de télémétrie
        LOCAL de capter l'événement (pertinent seulement quand exécution et
        détection sont sur la même machine).

        `capturer_sortie=True` peuple `self.derniere_sortie_ssh` (stdout+
        stderr, tronqué) -- réservé au DIAGNOSTIC (ex. vérifier qu'un outil
        est installé sur Kali avant de figer une commande de catalogue),
        jamais utilisé sur le chemin d'attaque normal (`executer_attaque_complete`
        ignore cet attribut).

        `commande_log` : version à écrire dans les journaux si elle diffère
        de `commande` (celle réellement exécutée) -- utilisé par
        `executer_commande_ssh_kali()` pour ne jamais faire fuiter un mot de
        passe substitué (CADRE-CRE-006/CADRE-INI-001) dans `logs/cadre.log.json`.
        `None` (défaut) : `commande` sert aussi de version journalisée.
        """
        commande_affichee = commande_log if commande_log is not None else commande
        if capturer_sortie:
            self.derniere_sortie_ssh = None
        if not PARAMIKO_DISPONIBLE:
            self.log.error("Module 'paramiko' non installé. pip install paramiko")
            return False

        if not ip or not user or not pwd:
            self.log.error(f"Cible SSH non configurée pour : {contexte_log}")
            return False

        if not self._port_accessible(ip, port):
            self.log.error(
                f"Hôte SSH {ip}:{port} inaccessible. Vérifiez : "
                f"(1) VM allumée, (2) réseau host-only, (3) service sshd actif."
            )
            return False

        for tentative in range(1, 4):
            try:
                self.log.attack(
                    f"SSH -> {ip} ({contexte_log}) : {commande_affichee[:80]}...",
                    commande=commande_affichee[:120],
                    tentative=tentative,
                )
                client = paramiko.SSHClient()
                # nosec B507 : la cible est une VM de laboratoire jetable sur
                # réseau host-only (aucun tiers réseau) — accepter la clé d'hôte
                # inconnue est le pendant SSH de verify_tls=False côté HTTP,
                # acceptable dans ce périmètre isolé. En production, on
                # pré-provisionnerait known_hosts.
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507
                client.connect(
                    ip,
                    port=port,
                    username=user,
                    password=pwd,
                    timeout=timeout_sec,
                    banner_timeout=timeout_sec,
                    auth_timeout=timeout_sec,
                )
                # nosec B601 : `commande` provient du catalogue déterministe
                # audité (ou, pour l'agent IA, est passée par la denylist
                # anti-destruction AVANT d'arriver ici) — jamais une entrée
                # utilisateur arbitraire.
                _stdin, stdout, stderr = client.exec_command(  # nosec B601
                    commande, timeout=timeout_sec
                )
                stdout.channel.recv_exit_status()  # attendre la fin, quel que soit le code
                if capturer_sortie:
                    sortie = stdout.read().decode(errors="replace")
                    sortie += stderr.read().decode(errors="replace")
                    self.derniere_sortie_ssh = sortie[:4000]
                client.close()
                if sleep_apres:
                    time.sleep(sleep_apres)
                return True
            except Exception as e:
                self.log.warn(
                    f"SSH tentative {tentative}/3 échouée : {type(e).__name__}",
                    erreur=str(e)[:200],
                )
                if tentative < 3:
                    time.sleep(2**tentative)
        self.log.error("SSH définitivement inaccessible après 3 tentatives")
        return False

    def diagnostiquer_kali(self, commande: str, timeout_sec: int = 15) -> str | None:
        """
        Exécute une commande de DIAGNOSTIC sur Kali (ex. vérifier qu'un outil
        offensif est installé) et retourne sa sortie (stdout+stderr,
        tronquée). None si la connexion SSH elle-même a échoué. N'est
        JAMAIS appelée par le pipeline d'attaque normal -- outil d'inspection
        manuelle uniquement (voir `cadre` CLI ou script ad hoc)."""
        self.derniere_sortie_ssh = None
        ok = self._executer_ssh(
            ip=self.config.get("linux_vm_ip"),
            user=self.config.get("linux_vm_user"),
            pwd=self.config.get("linux_vm_pass"),
            port=int(self.config.get("linux_vm_port", 22)),
            commande=commande,
            timeout_sec=timeout_sec,
            contexte_log="diagnostic Kali",
            capturer_sortie=True,
        )
        return self.derniere_sortie_ssh if ok else None

    def executer_commande_ssh(self, commande: str, timeout_sec: int = 30) -> bool:
        """
        Exécute une commande sur la cible LINUX via SSH — l'important est
        qu'elle produise un événement `execve` capté par Auditbeat SUR CETTE
        MÊME machine, d'où le `sleep_apres=2` (laisse Auditbeat capter avant
        de rendre la main).
        """
        return self._executer_ssh(
            ip=self.config.get("linux_vm_ip"),
            user=self.config.get("linux_vm_user"),
            pwd=self.config.get("linux_vm_pass"),
            port=int(self.config.get("linux_vm_port", 22)),
            commande=commande,
            timeout_sec=timeout_sec,
            contexte_log="cible Linux",
            sleep_apres=2,
        )

    def executer_commande_ssh_kali(self, commande: str, timeout_sec: int = 30) -> bool:
        """
        Exécute une commande sur la VM Kali (réutilise les identifiants
        `linux_vm_*` — c'est la même VM, voir `catalogue_attaques.py`,
        `OrigineExecution.KALI`) qui attaque la cible Windows PAR LE RÉSEAU.
        Aucun `sleep_apres` : contrairement à `executer_commande_ssh`, la
        télémétrie attendue n'est PAS sur la machine où la commande s'exécute
        (Kali) mais sur la cible Windows -- c'est `attendre_indexation()` qui
        gère l'attente côté détection, pas cet exécuteur.

        Le jeton littéral `{CIBLE_IP}` dans `commande` est substitué par
        l'IP Windows réellement configurée (`vm_ip`) avant envoi -- mécanisme
        de templating du catalogue, nécessaire ici car l'IP cible n'est
        jamais connue au moment où l'attaque est définie (contrairement aux
        commandes existantes, toutes statiques). Deux jetons du même genre,
        `{CADRE_BRUTE_TEST_PASS}`/`{CADRE_INI_ACCESS_TEST_PASS}` (comptes de
        test dédiés de CADRE-CRE-006/CADRE-INI-001), sont substitués par le
        secret configuré -- mais JAMAIS dans la version envoyée aux
        journaux, qui garde le jeton littéral au lieu du mot de passe réel
        (voir `commande_log` de `_executer_ssh`).
        """
        cible_ip = self.config.get("vm_ip")
        if not cible_ip:
            self.log.error("Cible Windows non configurée (CADRE_VM_IP) -- requis pour {CIBLE_IP}")
            return False

        commande_finale = commande.replace("{CIBLE_IP}", str(cible_ip))
        commande_log = commande.replace("{CIBLE_IP}", str(cible_ip))
        for jeton, (champ, cle_env) in (
            ("{CADRE_BRUTE_TEST_PASS}", ("brute_test_pass", "CADRE_BRUTE_TEST_PASS")),
            (
                "{CADRE_INI_ACCESS_TEST_PASS}",
                ("ini_access_test_pass", "CADRE_INI_ACCESS_TEST_PASS"),
            ),
        ):
            if jeton not in commande:
                continue
            secret = self.config.get(champ)
            if not secret:
                self.log.error(
                    f"Secret manquant ({cle_env}) -- requis pour {jeton}. "
                    f"Définissez-le avec : cadre init --set {cle_env}=..."
                )
                return False
            commande_finale = commande_finale.replace(jeton, str(secret))
            # commande_log garde le jeton littéral -- jamais le mot de passe réel.

        return self._executer_ssh(
            ip=self.config.get("linux_vm_ip"),
            user=self.config.get("linux_vm_user"),
            pwd=self.config.get("linux_vm_pass"),
            port=int(self.config.get("linux_vm_port", 22)),
            commande=commande_finale,
            commande_log=commande_log,
            timeout_sec=timeout_sec,
            contexte_log=f"attaque réseau Kali -> Windows {cible_ip}",
        )

    def generer_regle_sigma_depuis_attaque(
        self,
        attaque: AttaqueCatalogue,
        _log_anonymise: dict[str, Any],
    ) -> str:
        """
        Génère une règle Sigma déterministe à partir d'une attaque connue
        et du log anonymisé. Cette version n'utilise PAS de LLM : la règle
        est dérivée mécaniquement du catalogue.

        Le champ de corrélation (quand il existe) et le type de logsource
        sont déduits de l'EventID principal de l'attaque via les tables
        _SYSMON_EVENT_INFO / _POWERSHELL_EVENT_INFO / _NATIVE_SERVICE_PAR_EVENT
        ci-dessus — jamais codés en dur sur process.command_line comme avant.
        """
        produit, logsource_ligne, selection_lignes = _calculer_signature_detection(attaque)

        liste_fp = (
            "\n".join(f"  - {fp}" for fp in attaque.faux_positifs_connus) or "  - Aucun connu"
        )

        uuid = str(uuid_lib.uuid4())
        chemin_technique = attaque.technique_mitre.replace(".", "/")
        reference_mitre = f"https://attack.mitre.org/techniques/{chemin_technique}/"

        return SIGMA_TEMPLATE.format(
            titre=_titre_sigma_yaml(attaque.nom),
            identifiant_uuid=uuid,
            description=attaque.description.replace("\n", " "),
            reference_mitre=reference_mitre,
            technique_mitre=attaque.technique_mitre,
            tactique_mitre_tag=attaque.tactique_mitre.lower().replace(" ", "_"),
            technique_mitre_tag=attaque.technique_mitre.lower().replace(".", "_"),
            date=datetime.now().strftime("%Y/%m/%d"),
            produit=produit,
            logsource_ligne=logsource_ligne,
            selection_lignes=selection_lignes,
            liste_fp=liste_fp,
            niveau=attaque.niveau_risque.value,
        )

    def _generer_regle_candidate(
        self, attaque: AttaqueCatalogue, log_anonymise: dict[str, Any]
    ) -> tuple[str, str]:
        """
        Produit la règle Sigma candidate au déploiement et le nom du
        générateur utilisé — `("<yaml>", "deterministe" | "llm")`.

        Mode `deterministe` (défaut) : `str.format()` reproductible.
        Mode `llm` : le LLM rédige la règle à partir du log réel ; si le LLM
        est injoignable ou ne renvoie rien d'exploitable, on retombe
        automatiquement sur le déterministe (le mode LLM ne peut jamais
        faire échouer une attaque). Dans TOUS les cas, la règle retournée
        subira ensuite la même validation TP/FP avant déploiement.
        """
        deterministe = self.generer_regle_sigma_depuis_attaque(attaque, log_anonymise)
        if self.config.get("mode_generation_regle") != "llm":
            return deterministe, "deterministe"

        try:
            from .assistant_llm import obtenir_assistant_llm  # noqa: PLC0415

            regle_llm = obtenir_assistant_llm().suggerer_regle_sigma_deployable(
                log_anonymise,
                {
                    "technique_mitre": attaque.technique_mitre,
                    "nom": attaque.nom,
                    "plateforme": attaque.plateforme.value,
                },
            )
        except Exception as e:  # défense en profondeur : jamais fatal
            self.log.warn(
                f"Génération LLM indisponible pour {attaque.id}, repli déterministe : {e}"
            )
            regle_llm = None

        if regle_llm:
            return regle_llm, "llm"
        self.log.warn(f"LLM sans règle exploitable pour {attaque.id} — repli déterministe")
        return deterministe, "deterministe (repli après échec LLM)"

    def _generer_brouillon_regle_ia(
        self, attaque: AttaqueCatalogue, log_anonymise: dict[str, Any]
    ) -> str | None:
        """
        Demande à l'assistant LLM un brouillon de règle Sigma comparatif —
        opt-in (`ia_brouillon_regle`), purement informatif. N'affecte
        jamais `resultat["statut"]` ni le chemin critique : une panne
        Ollama ici ne doit jamais faire échouer l'attaque.
        """
        try:
            from .assistant_llm import obtenir_assistant_llm  # noqa: PLC0415

            brouillon = obtenir_assistant_llm().suggerer_regle_sigma(
                log_anonymise,
                {
                    "technique_mitre": attaque.technique_mitre,
                    "nom": attaque.nom,
                    "plateforme": attaque.plateforme.value,
                },
            )
        except Exception as e:  # défense en profondeur : jamais fatal ici
            self.log.warn(f"Brouillon de règle IA indisponible pour {attaque.id} : {e}")
            return None

        if brouillon:
            chemin = self.config["repertoire_regles"] / "brouillons_ia" / f"{attaque.id}.ia.yml"
            chemin.parent.mkdir(parents=True, exist_ok=True)
            chemin.write_text(brouillon, encoding="utf-8")
        return brouillon

    def lire_regle_kibana(self, rule_id: str) -> dict[str, Any] | None:
        """
        Chantier 3 (éditeur post-déploiement) : GET
        `/api/detection_engine/rules?rule_id=...` -- jamais fait avant dans
        ce code (tout le reste du module est PUT/POST). Retourne le JSON
        complet de la règle telle qu'actuellement déployée, ou None si
        absente (404) ou erreur réseau -- jamais d'exception, cohérent avec
        le reste des méthodes réseau de cette classe.

        Régression (audit, testée en réel) : `rule_id` est toujours déployé
        en minuscules (`attaque.id.lower()`, voir `rule_id_stable` dans
        `deployer_kibana`/`_deployer_attaque`), mais l'ID catalogue affiché
        partout ailleurs (CLI, dashboard, rapports) est en MAJUSCULES
        (`CADRE-DIS-001`). Kibana compare `rule_id` en sensible à la casse
        -- taper l'ID tel qu'affiché échouait systématiquement en "règle
        introuvable" alors qu'elle est bien déployée. Normalisé ici, seul
        point d'entrée de toute lecture de règle par `rule_id` (CLI comme
        dashboard).
        """
        rule_id = rule_id.lower()
        url = f"{self.config['kibana_url'].rstrip('/')}/api/detection_engine/rules"
        try:
            r = requests.get(
                url,
                headers={"kbn-xsrf": "true"},
                auth=self.auth_elastic,
                verify=verifier_tls(),
                timeout=20,
                params={"rule_id": rule_id},
            )
            if r.status_code == 200:
                resultat: dict[str, Any] = r.json()
                return resultat
            if r.status_code != 404:
                self.log.error(
                    f"Erreur lecture règle Kibana (HTTP {r.status_code}) : {rule_id}",
                    body=r.text[:300],
                )
            return None
        except Exception as e:
            self.log.error(f"Erreur lecture règle Kibana : {e}")
            return None

    def deployer_kibana(
        self,
        nom_regle: str,
        description: str,
        requete_lucene: str,
        technique_id: str,
        severite: str = "medium",
        index_pattern: str | None = None,
        rule_id_stable: str | None = None,
    ) -> bool:
        """
        Déploie une règle de détection dans Kibana via l'API REST. `index_pattern`
        cible l'index à surveiller (winlogbeat-* pour Windows, auditbeat-* pour
        Linux) ; par défaut, l'index Windows de la config.

        `rule_id_stable` (ex. l'ID catalogue de l'attaque, `cadre-dis-001`) rend
        le déploiement idempotent : une règle avec ce `rule_id` est mise à jour
        en place (PUT) plutôt que redéployée en doublon à chaque cycle (POST
        créait un nouvel `id` Kibana à chaque appel — voir
        `REVUE/U3-corrections.md`, G3/V3). Sans `rule_id_stable`, comportement
        historique inchangé (toujours POST, pour compat appelants existants).
        """
        # `query` est une chaîne Lucene brute (pas un objet DSL) -- le contrat
        # de l'API Kibana Detection Engine pour une règle `type: query` est
        # `{"query": "<lucene ou KQL>", "language": "lucene"}`. La sérialiser
        # nous-mêmes en `{"query_string": {...}}` (ancien code) produisait une
        # chaîne que le parseur KQL de Kibana rejette au premier `{` rencontré
        # -- la règle se déployait (200/201) mais échouait à CHAQUE exécution
        # planifiée ("Expected ... but "{" found"), pour 127 des 129 règles
        # CADRE constatées en échec dans Kibana. `requests` (json=payload)
        # gère déjà tout l'échappement JSON nécessaire pour une valeur de
        # type chaîne, y compris espaces et antislashs Lucene.
        payload: dict[str, Any] = {
            "name": nom_regle,
            "description": description,
            "risk_score": _RISK_SCORE_PAR_SEVERITE.get(
                severite, _RISK_SCORE_PAR_SEVERITE["medium"]
            ),
            "severity": severite,
            "type": "query",
            "query": requete_lucene,
            "language": "lucene",
            "index": [index_pattern or self.config["index_pattern"]],
            "interval": "5m",
            "from": "now-10m",
            "enabled": True,
            "tags": ["CADRE", technique_id],
        }
        if rule_id_stable:
            payload["rule_id"] = rule_id_stable
        return self._deployer_regle_kibana(payload, nom_regle, rule_id_stable)

    def _deployer_regle_kibana(
        self,
        payload: dict[str, Any],
        nom_regle: str,
        rule_id_stable: str | None,
    ) -> bool:
        """
        Mécanique HTTP partagée par `deployer_kibana` (règles `type: query`,
        une par attaque) et `deployer_kibana_sequence` (règles `type: eql`,
        une par scénario) : PUT (mise à jour en place) si `rule_id_stable`
        est fourni, repli sur POST en 404 (première fois) ; toujours POST
        sinon. Voir `deployer_kibana` pour le détail du choix d'idempotence.
        """
        url = f"{self.config['kibana_url'].rstrip('/')}/api/detection_engine/rules"
        headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
        try:
            if rule_id_stable:
                r = requests.put(
                    url,
                    headers=headers,
                    auth=self.auth_elastic,
                    json=payload,
                    verify=verifier_tls(),
                    timeout=20,
                )
                if r.status_code == 404:
                    r = requests.post(
                        url,
                        headers=headers,
                        auth=self.auth_elastic,
                        json=payload,
                        verify=verifier_tls(),
                        timeout=20,
                    )
            else:
                r = requests.post(
                    url,
                    headers=headers,
                    auth=self.auth_elastic,
                    json=payload,
                    verify=verifier_tls(),
                    timeout=20,
                )
            if r.status_code in (200, 201):
                self.log.success(
                    f"Règle déployée dans Kibana : {nom_regle}",
                    rule_id=r.json().get("id", "?"),
                )
                return True
            self.log.error(
                f"Échec déploiement Kibana (HTTP {r.status_code})",
                body=r.text[:300],
            )
            return False
        except Exception as e:
            self.log.error(f"Erreur déploiement Kibana : {e}")
            return False

    def deployer_kibana_sequence(
        self,
        scenario: ScenarioAdversaire,
        attaques: list[AttaqueCatalogue],
        maxspan_min: int,
        index_pattern: str | None = None,
        suffixe_id: str = "",
    ) -> bool:
        """
        Déploie une règle Kibana `type: eql` qui corrèle plusieurs étapes
        d'un scénario déjà détectées individuellement — la corrélation
        demandée en plus de la dédup par nom (B7) : un signal plus fort que
        des alertes isolées quand la séquence complète se reproduit sur le
        même hôte. `attaques` doit être une sous-liste ORDONNÉE et déjà
        filtrée aux étapes réellement détectées par l'appelant
        (`executer_scenario`) — cette méthode ne filtre rien elle-même.

        Windows uniquement (voir `construire_sequence_eql`). `maxspan_min`
        n'est jamais deviné ici : l'appelant le dérive de la durée
        RÉELLEMENT mesurée de l'exécution du scénario. `suffixe_id` distingue
        plusieurs tronçons détectés d'un même scénario coupé par un angle
        mort (ex. `-1`, `-2`) ; vide si la chaîne est détectée d'un bloc.
        """
        requete_eql = construire_sequence_eql(attaques, maxspan_min)
        rule_id_stable = f"cadre-sequence-{scenario.id.lower()}{suffixe_id}"
        payload: dict[str, Any] = {
            "name": f"[CADRE] Séquence {scenario.id}{suffixe_id} — {scenario.nom}",
            "description": (
                f"Corrélation de {len(attaques)} étapes détectées de la kill chain "
                f"« {scenario.adversaire} » sur le même hôte, dans l'ordre, en moins "
                f"de {maxspan_min} min."
            ),
            "risk_score": _RISK_SCORE_PAR_SEVERITE["high"],
            "severity": "high",
            "type": "eql",
            "language": "eql",
            "query": requete_eql,
            "index": [index_pattern or self.config["index_pattern"]],
            "interval": "5m",
            "from": "now-10m",
            "enabled": True,
            "tags": ["CADRE", "CADRE-SEQUENCE", scenario.id],
            "rule_id": rule_id_stable,
        }
        return self._deployer_regle_kibana(payload, payload["name"], rule_id_stable)

    def _lister_regles_cadre_kibana(self) -> list[dict[str, Any]] | None:
        """Retourne toutes les règles CADRE présentes dans Kibana (nom
        préfixé « [CADRE] »), ou None si l'API est injoignable. Une seule
        requête paginée large -- il n'y a jamais des milliers de règles
        CADRE, et le catalogue plafonne bien en-dessous de la page."""
        url = f"{self.config['kibana_url'].rstrip('/')}/api/detection_engine/rules/_find"
        try:
            r = requests.get(
                url,
                headers={"kbn-xsrf": "true"},
                auth=self.auth_elastic,
                params={"per_page": 10000, "page": 1},
                verify=verifier_tls(),
                timeout=30,
            )
            if r.status_code != 200:
                self.log.error(f"Kibana : liste des règles indisponible (HTTP {r.status_code})")
                return None
            return [x for x in r.json().get("data", []) if "[CADRE]" in x.get("name", "")]
        except Exception as e:
            self.log.error(f"Kibana : erreur de listing des règles : {e}")
            return None

    def nettoyer_regles_orphelines_kibana(self, appliquer: bool = False) -> dict[str, Any]:
        """Détecte (et, si `appliquer`, supprime) les règles CADRE
        ORPHELINES dans Kibana : celles dont le `rule_id` n'est PAS de la
        forme stable `cadre-…`. Ce sont des vestiges de déploiements
        antérieurs au mécanisme d'idempotence (`rule_id_stable`, cf.
        `deployer_kibana`) -- déployés jadis avec un `rule_id` UUID aléatoire,
        jamais remis à jour depuis, et donc laissés en double à chaque cycle.

        GARDE-FOU DE SÛRETÉ : une orpheline n'est proposée à la suppression
        que si une règle STABLE (`cadre-…`) couvre déjà la MÊME technique
        MITRE -- jamais on ne supprime une détection qui serait unique. Les
        orphelines sans équivalent stable sont conservées et signalées.

        `appliquer=False` (défaut) = simple inventaire, aucune suppression
        (équivalent d'un dry-run). Retourne un dict de comptes et de listes
        pour l'affichage CLI comme pour les tests."""
        vide: dict[str, Any] = {
            "total_cadre": 0,
            "stables": 0,
            "orphelines_sures": [],
            "orphelines_preservees": [],
            "supprimees": 0,
        }
        regles = self._lister_regles_cadre_kibana()
        if regles is None:
            return {**vide, "erreur": "Kibana injoignable"}

        def _technique(nom: str) -> str:
            m = re.search(r"T\d{4}(?:\.\d{3})?", nom)
            return m.group(0) if m else nom

        techniques_stables = {
            _technique(x["name"]) for x in regles if str(x.get("rule_id", "")).startswith("cadre-")
        }
        orphelines = [x for x in regles if not str(x.get("rule_id", "")).startswith("cadre-")]
        # Sûres à supprimer : la technique est déjà couverte par une stable.
        a_supprimer = [x for x in orphelines if _technique(x["name"]) in techniques_stables]
        preservees = [x for x in orphelines if _technique(x["name"]) not in techniques_stables]

        supprimees = 0
        if appliquer:
            base = f"{self.config['kibana_url'].rstrip('/')}/api/detection_engine/rules"
            for regle in a_supprimer:
                try:
                    r = requests.delete(
                        base,
                        headers={"kbn-xsrf": "true"},
                        auth=self.auth_elastic,
                        params={"id": regle["id"]},
                        verify=verifier_tls(),
                        timeout=20,
                    )
                    if r.status_code == 200:
                        supprimees += 1
                    else:
                        self.log.warn(
                            f"Suppression refusée (HTTP {r.status_code}) : {regle['name'][:50]}"
                        )
                except Exception as e:
                    self.log.warn(f"Erreur suppression règle orpheline : {e}")
            self.log.success(f"Kibana nettoyé : {supprimees} règle(s) orpheline(s) supprimée(s)")

        return {
            "total_cadre": len(regles),
            "stables": len(regles) - len(orphelines),
            "orphelines_sures": [x["name"] for x in a_supprimer],
            "orphelines_preservees": [x["name"] for x in preservees],
            "supprimees": supprimees,
        }

    def _cible_pour_attaque(  # noqa: PLR0911 -- aiguillage à plat (early
        # return par cas), plus lisible qu'un if/elif imbriqué pour 4 origines
        self,
        attaque: AttaqueCatalogue,
    ) -> dict[str, Any] | None:
        """
        Choisit la cible (Windows/WinRM ou Linux/SSH) selon la plateforme de
        l'attaque ET les cibles réellement configurées. Retourne un descripteur
        `{plateforme, executer, index_pattern, pipeline}` ou None si aucune
        cible adaptée n'est configurée (→ NON_APPLICABLE, pas un échec).

        - attaque `windows` : cible Windows si `vm_ip` présent (cas par défaut).
        - attaque `linux`   : cible Linux UNIQUEMENT si `linux_vm_ip`+user+pass
          sont configurés (sinon NON_APPLICABLE, comportement historique).
        - attaque `both`    : suit `plateforme_cible` (Linux si demandé et
          configuré, Windows sinon).
        - `origine_execution == KALI` (n'importe quelle `plateforme`, en
          pratique toujours `windows`) : la commande s'exécute sur Kali (SSH,
          réutilise `linux_vm_*`) mais la télémétrie reste cherchée côté
          `plateforme` normalement -- seul `executer` change, `index_pattern`/
          `pipeline` restent ceux de la cible visée.
        """
        linux_ok = all(
            [
                self.config.get("linux_vm_ip"),
                self.config.get("linux_vm_user"),
                self.config.get("linux_vm_pass"),
            ]
        )
        windows_ok = bool(self.config.get("vm_ip"))

        def cible_windows() -> dict[str, Any]:
            return {
                "plateforme": "windows",
                "executer": self.executer_commande_winrm,
                "index_pattern": self.config["index_pattern"],
                "pipeline": "ecs_windows",
            }

        def cible_linux() -> dict[str, Any]:
            return {
                "plateforme": "linux",
                "executer": self.executer_commande_ssh,
                "index_pattern": self.config["index_pattern_linux"],
                # Auditbeat est déjà en ECS : on compile SANS le pipeline
                # Windows (qui renommerait les champs Sysmon Windows à tort).
                "pipeline": "aucun",
            }

        if attaque.origine_execution.value == "kali":
            if not (linux_ok and windows_ok):
                return None
            cible = cible_windows()
            cible["executer"] = self.executer_commande_ssh_kali
            cible["origine"] = "kali"
            return cible

        plat = attaque.plateforme.value
        if plat == "linux":
            return cible_linux() if linux_ok else None
        if plat == "windows":
            return cible_windows() if windows_ok else None
        # "both" : préférer la plateforme cible demandée si elle est disponible.
        if self.config.get("plateforme_cible") == "linux" and linux_ok:
            return cible_linux()
        if windows_ok:
            return cible_windows()
        return cible_linux() if linux_ok else None

    def executer_attaque_complete(  # noqa: PLR0911, PLR0915, PLR0912 -- retour anticipé
        # à chaque étape d'un pipeline séquentiel (voir docstring du module) ;
        # découper en sous-fonctions séparerait des étapes qui partagent le
        # même dict `resultat` en construction, sans gain de lisibilité réel.
        self,
        attaque: AttaqueCatalogue,
        arreter_avant_deploiement: bool = False,
        source_revue: str = "manuel",
    ) -> dict[str, Any]:
        """
        Exécute une attaque de bout en bout et retourne le résultat.

        `arreter_avant_deploiement` (défaut False, comportement inchangé) :
        si True, s'arrête juste après la double validation TP/FP réussie,
        AVANT tout appel à `deployer_kibana()` -- enregistre une entrée
        dans la file de revue humaine (`revue_regles`) au lieu de déployer.
        Réservé au contenu jamais éprouvé (IA, `cadre cycle --id --revue`)
        -- jamais utilisé sur le catalogue natif ni `--demo` (garde-fou
        côté CLI, pas ici). `source_revue` est purement informatif
        (traçabilité de l'origine dans l'entrée de revue).
        """
        resultat: dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "id": attaque.id,
            "technique_mitre": attaque.technique_mitre,
            "tactique": attaque.tactique_mitre,
            "description": attaque.nom,
            "event_ids_attendus": attaque.event_ids_attendus,
            "statut": "EN_COURS",
        }

        # 0a. Attaque nécessitant un egress Internet sur une cible en réseau
        # host-only (labo isolé, sans Internet par design) = NON_APPLICABLE, pas
        # un échec. Évite le faux "Échec exécution" de T1105 (certutil download).
        if attaque.requires_internet and not self.config.get("cible_a_internet", False):
            resultat["statut"] = "NON_APPLICABLE"
            resultat["raison"] = "Nécessite un accès Internet — VM en réseau host-only (labo isolé)"
            return resultat

        # 0b. Sélection de la cible (Windows/WinRM ou Linux/SSH) selon la
        # plateforme de l'attaque ET les cibles configurées. Aucune cible
        # adaptée = NON_APPLICABLE (incompatibilité structurelle, pas un échec).
        cible = self._cible_pour_attaque(attaque)
        if cible is None:
            resultat["statut"] = "NON_APPLICABLE"
            resultat["raison"] = (
                f"Attaque {attaque.plateforme.value} — aucune cible "
                f"{attaque.plateforme.value} configurée, non exécutée"
            )
            return resultat
        resultat["plateforme"] = cible["plateforme"]

        # 0c. Pré-vol de joignabilité : une cible configurée mais INJOIGNABLE
        # (VM éteinte, module client absent) n'est pas un échec CADRE mais une
        # non-applicabilité pour ce run — sinon le taux d'échec est faussé
        # (cf. AUDIT-DASH/1a : 20 attaques Linux, VM Kali éteinte).
        if not self._cible_joignable(cible):
            resultat["statut"] = "NON_APPLICABLE"
            resultat["raison"] = (
                f"Cible {cible['plateforme']} injoignable (VM éteinte ou module "
                f"client absent) — non exécutée"
            )
            return resultat

        # 1. Exécution sur la cible (WinRM pour Windows, SSH pour Linux). Si on
        # arrive ici la cible est joignable : un échec est un VRAI échec (ERREUR).
        self._rapporter_etape(1, "Exécution")
        if not cible["executer"](attaque.commande):
            resultat["statut"] = "ERREUR"
            resultat["raison"] = f"Échec exécution ({cible['plateforme']})"
            return resultat

        # 2. Attente d'indexation. Windows : on cible les EventID Sysmon/natifs.
        # Linux (Auditbeat) : pas d'EventID Windows — on attend qu'un événement
        # d'exécution portant la valeur de détection (dans process.title)
        # apparaisse.
        self._rapporter_etape(2, "Indexation")
        if cible["plateforme"] == "linux":
            log_brut = attendre_indexation(
                elastic_url=self.config["elastic_url"],
                index_pattern=cible["index_pattern"],
                event_ids=[],
                auth=self.auth_elastic,
                timeout_max_sec=self.config["timeout_indexation_sec"],
                contexte={"technique": attaque.technique_mitre, "id": attaque.id},
                champ_texte="process.title",
                valeur_texte=attaque.valeur_detection,
            )
        else:
            log_brut = attendre_indexation(
                elastic_url=self.config["elastic_url"],
                index_pattern=cible["index_pattern"],
                event_ids=attaque.event_ids_attendus,
                auth=self.auth_elastic,
                timeout_max_sec=self.config["timeout_indexation_sec"],
                contexte={"technique": attaque.technique_mitre, "id": attaque.id},
            )

        if not log_brut:
            resultat["statut"] = "ANGLE_MORT"
            resultat["raison"] = (
                f"Aucune télémétrie captée pour {attaque.id} "
                f"après {self.config['timeout_indexation_sec']}s "
                f"(cible {cible['plateforme']})"
            )
            return resultat

        # 3. Anonymisation
        self._rapporter_etape(3, "Anonymisation")
        log_anonymise = anonymiser_log_elastic(log_brut)

        # 4. Génération règle Sigma — déterministe (défaut) ou LLM (opt-in).
        # Dans les deux cas, la règle passera par la MÊME validation TP/FP.
        self._rapporter_etape(4, "Règle Sigma")
        try:
            regle_sigma_yaml, generateur = self._generer_regle_candidate(attaque, log_anonymise)
        except Exception as e:
            resultat["statut"] = "ERREUR"
            resultat["raison"] = f"Génération Sigma échouée : {e}"
            return resultat

        resultat["regle_sigma_yaml"] = regle_sigma_yaml
        resultat["generateur_regle"] = generateur

        # Sauvegarder la règle
        chemin_regle = self.config["repertoire_regles"] / f"{attaque.id}.yml"
        chemin_regle.write_text(regle_sigma_yaml, encoding="utf-8")

        # Brouillon IA comparatif (opt-in, indépendant du mode de génération).
        if self.config.get("ia_brouillon_regle"):
            resultat["regle_sigma_ia_brouillon"] = self._generer_brouillon_regle_ia(
                attaque, log_anonymise
            )

        # 5. Compilation Sigma → Lucene (pipeline selon la cible : ecs_windows
        # pour Windows, aucun pour Linux/Auditbeat déjà en ECS). Filet de
        # sécurité : si une règle LLM ne compile pas, on retombe sur le
        # déterministe plutôt que d'échouer.
        self._rapporter_etape(5, "Compilation Lucene")
        requete_lucene = compiler_sigma_vers_lucene(regle_sigma_yaml, pipeline=cible["pipeline"])
        if not requete_lucene and generateur == "llm":
            self.log.warn(f"Règle LLM non compilable pour {attaque.id} — repli déterministe")
            regle_sigma_yaml = self.generer_regle_sigma_depuis_attaque(attaque, log_anonymise)
            resultat["regle_sigma_yaml"] = regle_sigma_yaml
            resultat["generateur_regle"] = "deterministe (repli après échec LLM)"
            chemin_regle.write_text(regle_sigma_yaml, encoding="utf-8")
            requete_lucene = compiler_sigma_vers_lucene(
                regle_sigma_yaml, pipeline=cible["pipeline"]
            )
        if not requete_lucene:
            resultat["statut"] = "ERREUR"
            resultat["raison"] = "Compilation Sigma échouée"
            return resultat

        resultat["requete_lucene"] = requete_lucene

        # 6. Double validation TP/FP (seuil propre à l'attaque si défini,
        # sinon seuil global)
        seuil_fp = (
            attaque.seuil_fp_max
            if attaque.seuil_fp_max is not None
            else self.config["seuil_fp_max"]
        )
        self._rapporter_etape(6, "Validation TP")
        valide, raison, tp, fp = double_validation_tp_fp(
            requete_lucene=requete_lucene,
            elastic_url=self.config["elastic_url"],
            auth=self.auth_elastic,
            index_pattern=cible["index_pattern"],
            seuil_fp=seuil_fp,
            contexte={"technique": attaque.technique_mitre, "id": attaque.id},
        )
        self._rapporter_etape(7, "Validation FP")

        resultat["nb_tp"] = tp
        resultat["nb_fp"] = fp
        resultat["raison_validation"] = raison
        resultat["score_confiance"] = calculer_score_confiance(attaque, tp, fp, seuil_fp)

        if not valide:
            # ERREUR_ELASTICSEARCH (panne pendant la mesure TP/FP) n'est PAS
            # un jugement sur la règle -- contrairement à REJETE (FAUX_NEGATIF,
            # TROP_DE_FP), qui signifie "mesurée et jugée insuffisante".
            # Distinction utile côté rapport/dashboard : une panne réseau ne
            # doit jamais se lire comme "cette attaque n'est pas détectée".
            resultat["statut"] = "ERREUR" if raison == "ERREUR_ELASTICSEARCH" else "REJETE"
            resultat["raison"] = raison
            return resultat

        if arreter_avant_deploiement:
            rule_id_stable = attaque.id.lower()
            enregistrer_revue(
                {
                    "rule_id_stable": rule_id_stable,
                    "attaque_id": attaque.id,
                    "type_revue": "PRE_DEPLOIEMENT",
                    "source": source_revue,
                    "nom_regle": f"[CADRE] {attaque.technique_mitre} — {attaque.nom}",
                    "description": attaque.description,
                    "technique_mitre": attaque.technique_mitre,
                    "commande_executee": attaque.commande,
                    "severite": attaque.niveau_risque.value,
                    "index_pattern": cible["index_pattern"],
                    "seuil_fp_max": seuil_fp,
                    "chemin_regle_sigma": str(chemin_regle),
                    "requete_lucene_derniere_validation": requete_lucene,
                    "nb_tp": tp,
                    "nb_fp": fp,
                    "raison_validation": raison,
                    "score_confiance": resultat["score_confiance"],
                    "generateur_regle": generateur,
                }
            )
            resultat["statut"] = "EN_ATTENTE_REVUE"
            resultat["rule_id_stable"] = rule_id_stable
            resultat["raison"] = (
                f"Validée (TP={tp} FP={fp}) — en attente de revue : "
                f"cadre revue approuver {rule_id_stable}"
            )
            return resultat

        # 7. Déploiement dans Kibana (étape 8 du diagramme des 9 étapes)
        self._rapporter_etape(8, "Déploiement Kibana")
        deploye = self.deployer_kibana(
            nom_regle=f"[CADRE] {attaque.technique_mitre} — {attaque.nom}",
            description=attaque.description,
            requete_lucene=requete_lucene,
            technique_id=attaque.technique_mitre,
            severite=attaque.niveau_risque.value,
            index_pattern=cible["index_pattern"],
            rule_id_stable=attaque.id.lower(),
        )

        if deploye:
            resultat["statut"] = "VALIDE"
            resultat["raison"] = "Règle générée, validée et déployée"
        else:
            resultat["statut"] = "VALIDE_NON_DEPLOYE"
            resultat["raison"] = "Règle validée mais déploiement Kibana échoué"

        return resultat

    def _revalider_regle_editee(
        self,
        regle_sigma_yaml: str,
        index_pattern: str,
        seuil_fp: int,
        requete_reference: str | None = None,
        tp_deja_prouve: int | None = None,
        pipeline: str = "ecs_windows",
        contexte: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Recompile `regle_sigma_yaml` en Lucene et la revalide -- cœur
        partagé de la revue avant déploiement (`approuver_revue`) et de
        l'éditeur post-déploiement (`redeployer_regle_editee`). Jamais de
        déploiement aveugle d'un contenu édité par un humain sans repasser
        par cette fonction.

        Si `requete_reference` est fournie ET que la requête recompilée
        lui est IDENTIQUE, la requête n'a pas changé -- seule l'horloge a
        tourné depuis la première validation, `valider_bruit_seul()` est
        utilisée (pas d'exigence de fraîcheur TP, réutilise `tp_deja_prouve`).
        Sinon (contenu réellement modifié, ou `requete_reference=None` --
        cas de l'éditeur post-déploiement, toujours traité comme édité) :
        `double_validation_tp_fp()` complet, avec sa contrainte de
        fraîcheur (un contenu jamais prouvé doit l'être fraîchement).

        Retourne {"statut": VALIDE|REJETE|ERREUR, "raison", "requete_lucene",
        "nb_tp", "nb_fp", "edite"}. Aucun appel réseau si la compilation
        Sigma échoue.
        """
        requete_lucene = compiler_sigma_vers_lucene(regle_sigma_yaml, pipeline=pipeline)
        if not requete_lucene:
            return {
                "statut": "ERREUR",
                "raison": "SIGMA_NON_COMPILABLE",
                "requete_lucene": None,
                "nb_tp": 0,
                "nb_fp": 0,
                "edite": None,
            }

        edite = requete_reference is None or requete_lucene != requete_reference

        if not edite:
            valide, raison, fp = valider_bruit_seul(
                requete_lucene=requete_lucene,
                elastic_url=self.config["elastic_url"],
                auth=self.auth_elastic,
                index_pattern=index_pattern,
                seuil_fp=seuil_fp,
                contexte=contexte,
            )
            tp = tp_deja_prouve if tp_deja_prouve is not None else 0
        else:
            valide, raison, tp, fp = double_validation_tp_fp(
                requete_lucene=requete_lucene,
                elastic_url=self.config["elastic_url"],
                auth=self.auth_elastic,
                index_pattern=index_pattern,
                seuil_fp=seuil_fp,
                contexte=contexte,
            )

        if valide:
            statut = "VALIDE"
        elif raison == "ERREUR_ELASTICSEARCH":
            # Panne pendant la mesure, pas un jugement sur la règle -- ERREUR
            # (comme SIGMA_NON_COMPILABLE ci-dessus) plutôt que REJETE.
            # `approuver_revue()` refuse tout déploiement, y compris
            # `forcer=True`, dès que statut == "ERREUR" (voir ce garde-fou
            # juste après cet appel) : une panne réseau ne doit jamais
            # pouvoir être contournée par un forçage humain.
            statut = "ERREUR"
        else:
            statut = "REJETE"

        return {
            "statut": statut,
            "raison": raison,
            "requete_lucene": requete_lucene,
            "nb_tp": tp,
            "nb_fp": fp,
            "edite": edite,
        }

    def approuver_revue(self, entree: dict[str, Any], forcer: bool = False) -> dict[str, Any]:
        """
        Chantier 1 : relit le fichier Sigma référencé par une entrée de
        `cadre revue lister` (potentiellement édité à la main), la
        revalide via `_revalider_regle_editee`, et si valide (ou
        `forcer=True`, log WARN `RULE_MANUAL_EDIT_FORCED`) déploie dans
        Kibana avec les métadonnées déjà connues de l'entrée. Ne touche
        JAMAIS le réseau si le YAML ne compile pas.
        """
        chemin_regle = Path(entree["chemin_regle_sigma"])
        if not chemin_regle.is_file():
            return {
                "statut": "ERREUR",
                "revalidation": "ERREUR",
                "raison": f"Fichier de règle introuvable : {chemin_regle}",
                "nb_tp": 0,
                "nb_fp": 0,
                "deploye": False,
                "force": False,
            }

        regle_sigma_yaml = chemin_regle.read_text(encoding="utf-8")
        contexte = {"technique": entree["technique_mitre"], "id": entree["attaque_id"]}
        validation = self._revalider_regle_editee(
            regle_sigma_yaml=regle_sigma_yaml,
            index_pattern=entree["index_pattern"],
            seuil_fp=entree.get("seuil_fp_max") or self.config["seuil_fp_max"],
            requete_reference=entree["requete_lucene_derniere_validation"],
            tp_deja_prouve=entree["nb_tp"],
            contexte=contexte,
        )

        if validation["statut"] == "ERREUR":
            return {**validation, "revalidation": "ERREUR", "deploye": False, "force": False}

        force_effective = validation["statut"] == "REJETE" and forcer
        if validation["statut"] == "REJETE" and not forcer:
            return {
                "statut": "REJETE",
                "revalidation": "REJETE",
                "raison": validation["raison"],
                "nb_tp": validation["nb_tp"],
                "nb_fp": validation["nb_fp"],
                "deploye": False,
                "force": False,
            }

        if force_effective:
            self.log.evenement(
                "RULE_MANUAL_EDIT_FORCED",
                f"Déploiement forcé malgré échec de revalidation : {entree['rule_id_stable']}",
                niveau="WARN",
                rule_id=entree["rule_id_stable"],
                nb_tp=validation["nb_tp"],
                nb_fp=validation["nb_fp"],
            )

        deploye = self.deployer_kibana(
            nom_regle=entree["nom_regle"],
            description=entree["description"],
            requete_lucene=validation["requete_lucene"],
            technique_id=entree["technique_mitre"],
            severite=entree["severite"],
            index_pattern=entree["index_pattern"],
            rule_id_stable=entree["rule_id_stable"],
        )

        return {
            "statut": "VALIDE" if deploye else "VALIDE_NON_DEPLOYE",
            "revalidation": validation["statut"],
            "raison": validation["raison"],
            "nb_tp": validation["nb_tp"],
            "nb_fp": validation["nb_fp"],
            "deploye": deploye,
            "force": force_effective,
        }

    def redeployer_regle_editee(
        self,
        rule_id: str,
        regle_sigma_yaml: str,
        pipeline: str = "ecs_windows",
        forcer: bool = False,
    ) -> dict[str, Any]:
        """
        Chantier 3 : édite une règle DÉJÀ vivante dans Kibana. Lit son état
        actuel (`lire_regle_kibana`), revalide le YAML édité -- TOUJOURS en
        mode complet via `_revalider_regle_editee(requete_reference=None)`,
        une édition post-déploiement est par nature un contenu jamais
        prouvé, jamais un simple passage du temps -- puis repousse un
        payload PUT **reconstruit explicitement** à partir des champs
        renvoyés par le GET (`name/description/risk_score/severity/index/
        interval/from/enabled/tags`), jamais un spread aveugle : l'API GET
        renvoie des champs en lecture seule (`id/created_at/revision/...`)
        que PUT peut refuser. Seule `query` change (contenu édité), et le
        tag `CADRE-EDIT-MANUEL` est ajouté pour la traçabilité.

        Trace systématiquement (log WARN `RULE_MANUAL_EDIT`[_FORCED]) toute
        édition manuelle réussie -- distinct d'un déploiement normal du
        pipeline. Ne touche JAMAIS le réseau si `rule_id` est introuvable
        ou si le YAML ne compile pas.
        """
        # Même normalisation que lire_regle_kibana() -- indispensable ici en
        # plus : le payload PUT plus bas réutilise `rule_id` tel quel (ligne
        # "rule_id": rule_id). Sans ceci, un appel avec l'ID affiché en
        # majuscules aurait mis à jour... un nouveau rule_id inexistant,
        # créant une règle en double plutôt que d'éditer l'existante.
        rule_id = rule_id.lower()
        regle_actuelle = self.lire_regle_kibana(rule_id)
        if regle_actuelle is None:
            return {
                "statut": "ERREUR",
                "raison": f"rule_id introuvable dans Kibana : {rule_id}",
                "nb_tp": 0,
                "nb_fp": 0,
                "deploye": False,
                "force": False,
            }
        if regle_actuelle.get("type") != "query":
            return {
                "statut": "ERREUR",
                "raison": (
                    f"Type de règle non pris en charge par cet éditeur : "
                    f"{regle_actuelle.get('type')} (ex. séquence EQL de scénario "
                    f"cadre-sequence-* -- hors périmètre, jamais un fichier .yml "
                    f"par attaque)"
                ),
                "nb_tp": 0,
                "nb_fp": 0,
                "deploye": False,
                "force": False,
            }

        index_pattern = regle_actuelle.get("index", [self.config["index_pattern"]])[0]
        validation = self._revalider_regle_editee(
            regle_sigma_yaml=regle_sigma_yaml,
            index_pattern=index_pattern,
            seuil_fp=self.config["seuil_fp_max"],
            requete_reference=None,
            pipeline=pipeline,
            contexte={"id": rule_id},
        )

        if validation["statut"] == "ERREUR":
            return {**validation, "deploye": False, "force": False}

        force_effective = validation["statut"] == "REJETE" and forcer
        if validation["statut"] == "REJETE" and not forcer:
            return {
                "statut": "REJETE",
                "raison": validation["raison"],
                "nb_tp": validation["nb_tp"],
                "nb_fp": validation["nb_fp"],
                "deploye": False,
                "force": False,
            }

        type_evenement = "RULE_MANUAL_EDIT_FORCED" if force_effective else "RULE_MANUAL_EDIT"
        self.log.evenement(
            type_evenement,
            f"Règle Kibana modifiée manuellement : {rule_id}",
            niveau="WARN",
            rule_id=rule_id,
            nb_tp=validation["nb_tp"],
            nb_fp=validation["nb_fp"],
        )

        tags = list(regle_actuelle.get("tags", []))
        if "CADRE-EDIT-MANUEL" not in tags:
            tags.append("CADRE-EDIT-MANUEL")

        # Voir le commentaire équivalent dans deployer_kibana() : `query` est
        # une chaîne Lucene brute avec `language: "lucene"`, jamais un objet
        # DSL sérialisé (le parseur KQL de Kibana rejette un `{` en tête de
        # requête à chaque exécution planifiée).
        payload: dict[str, Any] = {
            "name": regle_actuelle.get("name", rule_id),
            "description": regle_actuelle.get("description", ""),
            "risk_score": regle_actuelle.get("risk_score", 50),
            "severity": regle_actuelle.get("severity", "medium"),
            "type": "query",
            "query": validation["requete_lucene"],
            "language": "lucene",
            "index": regle_actuelle.get("index", [self.config["index_pattern"]]),
            "interval": regle_actuelle.get("interval", "5m"),
            "from": regle_actuelle.get("from", "now-10m"),
            "enabled": regle_actuelle.get("enabled", True),
            "tags": tags,
            "rule_id": rule_id,
        }
        deploye = self._deployer_regle_kibana(payload, regle_actuelle.get("name", rule_id), rule_id)

        return {
            "statut": "VALIDE" if deploye else "VALIDE_NON_DEPLOYE",
            "raison": validation["raison"],
            "nb_tp": validation["nb_tp"],
            "nb_fp": validation["nb_fp"],
            "deploye": deploye,
            "force": force_effective,
        }

    def _rapporter_etape(self, numero: int, nom: str) -> None:
        """Signale l'étape courante (1-9) du pipeline au dashboard, s'il écoute.
        Alimente le diagramme des 9 étapes en temps réel via /api/cycle/statut.
        Silencieux et sans effet hors d'un cycle piloté par le dashboard."""
        rapporteur = getattr(self, "_rapporteur", None)
        if rapporteur is not None:
            ctx = getattr(self._tls, "ctx_progression", {})
            with contextlib.suppress(Exception):
                rapporteur({**ctx, "etape": numero, "etape_nom": nom})

    def executer_cycle_complet(
        self,
        techniques_a_executer: list[str] | None = None,
        mode_simulation: bool = False,
        avec_llm: bool = False,
        rapporteur: Any = None,
        parallele: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Exécute un cycle d'audit complet sur le catalogue (ou une sélection).

        Args:
            techniques_a_executer: Filtre par technique MITRE
            mode_simulation: Si True, simule l'exécution (utile pour dev/demo)
            avec_llm: Si True, enrichit le rapport d'une synthèse IA (Ollama).
                Purement additif au rapport ; n'affecte jamais la génération
                ou la validation des règles elles-mêmes.
            parallele: G2 -- parallélisme prudent borné à 2 exécutions WinRM/
                validations simultanées (voir `_executer_lots_paralleles`).
                Opt-in, jamais activé par défaut. Sans effet en simulation
                (aucun bénéfice, ne touche ni WinRM ni Elastic).
        """
        # F-009 : un cycle réel (jamais la simulation, qui ne touche ni VM ni
        # SIEM) acquiert un verrou inter-processus — évite qu'un daemon/loop
        # en arrière-plan et le dashboard ne se marchent dessus sur la même
        # cible. Libéré dans tous les cas (succès, erreur, ou exception).
        if not mode_simulation:
            _acquerir_verrou_cycle()
        try:
            # Régression (audit) « resultats non réinitialisés » : self.resultats
            # n'est jamais remis à zéro par _boucle_attaques() (qui ne fait
            # qu'append/extend) -- un DEUXIÈME appel à executer_cycle_complet()
            # sur la MÊME instance d'orchestrateur accumulerait silencieusement
            # les résultats du cycle précédent avec ceux du nouveau (rapports,
            # analyses et totaux faussés). `boucle.py` contournait déjà ce
            # problème pour SA propre boucle (voir son commentaire dans
            # executer_un_cycle), mais rien ne protégeait cette méthode elle-même
            # pour un futur appelant qui l'oublierait. Réinitialisé ici, à la
            # source, pour que la garantie ne dépende plus de la discipline de
            # chaque appelant.
            self.resultats = []
            self._rapporteur = rapporteur  # progression fine (dashboard) ; None sinon
            debut_cycle = time.monotonic()  # W8 : durée réelle du cycle (rapport)
            catalogue = catalogue_actif()  # 62 attaques natives + perso éventuelles
            self.log.evenement(
                "AUDIT_START",
                "Début du cycle d'audit CADRE",
                niveau="INFO",
                nb_attaques=len(techniques_a_executer) if techniques_a_executer else len(catalogue),
                mode_simulation=mode_simulation,
            )

            attaques_a_faire = catalogue
            if techniques_a_executer:
                attaques_a_faire = [
                    a for a in catalogue if a.technique_mitre in techniques_a_executer
                ]

            self._boucle_attaques(attaques_a_faire, mode_simulation, parallele=parallele)

            # Étape finale (9e du diagramme) : génération des rapports. Basé
            # sur la dernière attaque du catalogue filtré (connue du thread
            # principal) plutôt que sur le dernier `_tls.ctx_progression` écrit
            # -- qui, en mode parallèle, aurait été écrit par un thread worker,
            # pas le thread principal qui exécute ce bloc.
            if attaques_a_faire:
                derniere = attaques_a_faire[-1]
                self._tls.ctx_progression = {
                    "faites": len(attaques_a_faire),
                    "total": len(attaques_a_faire),
                    "attaque_id": derniere.id,
                    "technique": derniere.technique_mitre,
                    "nom": derniere.nom,
                }
            self._rapporter_etape(9, "Rapport")
            self._generer_rapports_fin_cycle(
                avec_llm=avec_llm, duree_sec=time.monotonic() - debut_cycle
            )
            self.log.evenement("AUDIT_END", "Fin du cycle d'audit", niveau="SUCCESS")

            return self.resultats
        finally:
            if not mode_simulation:
                _liberer_verrou_cycle()

    def _executer_une_attaque(
        self, attaque: AttaqueCatalogue, mode_simulation: bool
    ) -> dict[str, Any]:
        """Cœur d'exécution d'UNE attaque, partagé entre la boucle séquentielle
        et les lots parallèles (G2). `KeyboardInterrupt` n'est PAS interceptée
        ici (hérite de `BaseException`, pas `Exception`) -- elle remonte
        volontairement à l'appelant, seul responsable de décider de l'arrêt
        propre (séquentiel : coupe immédiatement ; lots parallèles : termine
        le lot en cours, voir `_executer_lots_paralleles`)."""
        try:
            if mode_simulation:
                return self._executer_attaque_simulation(attaque)
            return self.executer_attaque_complete(attaque)
        except Exception as e:
            self.log.error(f"Erreur inattendue sur {attaque.id} : {e}")
            return {
                "timestamp": datetime.now().isoformat(),
                "id": attaque.id,
                "technique_mitre": attaque.technique_mitre,
                "tactique": attaque.tactique_mitre,
                "description": attaque.nom,
                "statut": "ERREUR",
                "raison": str(e),
            }

    def _boucle_attaques(
        self,
        attaques_a_faire: list[AttaqueCatalogue],
        mode_simulation: bool,
        parallele: bool = False,
    ) -> None:
        """Exécute une liste ORDONNÉE d'attaques, en append à self.resultats.

        Cœur d'exécution partagé entre `executer_cycle_complet` (sélection
        sur le catalogue) et `executer_scenario` (kill chain ordonnée) : même
        logique d'exécution, de gestion d'erreur et de temporisation ; seule
        la façon de choisir/ordonner les attaques diffère en amont.

        `parallele` (G2) : jamais exposé par `executer_scenario`, qui n'appelle
        cette méthode qu'avec sa valeur par défaut `False` -- une kill chain
        dépend d'un ordre chronologique réel pour la corrélation EQL
        (`construire_sequence_eql`), le parallélisme casserait cette garantie
        par construction. Ignoré aussi en simulation (aucun bénéfice, ne
        touche ni WinRM ni Elastic).
        """
        if parallele and not mode_simulation and len(attaques_a_faire) > 1:
            self._executer_lots_paralleles(attaques_a_faire)
            return

        # Disjoncteur : compteur d'échecs d'exécution consécutifs (voir
        # seuil_echecs_execution_consecutifs dans DEFAUT_CONFIG). 0 = désactivé.
        seuil_disjoncteur = self.config.get("seuil_echecs_execution_consecutifs", 5)
        echecs_execution_consecutifs = 0

        for i, attaque in enumerate(attaques_a_faire, 1):
            self.log.info(
                f"[{i}/{len(attaques_a_faire)}] Attaque {attaque.technique_mitre}",
                nom=attaque.nom,
            )
            # Contexte de progression pour le dashboard (attaque courante + total).
            self._tls.ctx_progression = {
                "faites": i - 1,
                "total": len(attaques_a_faire),
                "attaque_id": attaque.id,
                "technique": attaque.technique_mitre,
                "nom": attaque.nom,
            }
            self._rapporter_etape(0, "Démarrage")

            try:
                resultat = self._executer_une_attaque(attaque, mode_simulation)
            except KeyboardInterrupt:
                self.log.warn("Interruption utilisateur (Ctrl+C)")
                break

            self.resultats.append(resultat)

            # Disjoncteur : un statut ERREUR = échec d'EXÉCUTION (WinRM/SSH
            # injoignable une fois le pré-vol passé). On compte les échecs
            # CONSÉCUTIFS ; tout succès réel (VALIDE, ANGLE_MORT, FAUX_NEGATIF
            # -- l'exécution a bien eu lieu) remet à zéro ; un NON_APPLICABLE
            # (plateforme sans cible) est neutre, il n'incrémente ni ne
            # réinitialise. Au-delà du seuil, on interrompt : inutile de
            # s'acharner sur les attaques restantes si l'infra d'exécution est
            # morte (cf. incident réel du 28/08, service WinRM zombie).
            statut = resultat.get("statut")
            if statut == "ERREUR":
                echecs_execution_consecutifs += 1
            elif statut != "NON_APPLICABLE":
                echecs_execution_consecutifs = 0
            if seuil_disjoncteur and echecs_execution_consecutifs >= seuil_disjoncteur:
                restantes = attaques_a_faire[i:]
                self.log.error(
                    f"Disjoncteur : {echecs_execution_consecutifs} échecs "
                    f"d'exécution consécutifs — infra d'exécution probablement "
                    f"défaillante (WinRM/SSH). Cycle interrompu, "
                    f"{len(restantes)} attaque(s) non exécutée(s).",
                )
                for restante in restantes:
                    self.resultats.append(
                        {
                            "timestamp": datetime.now().isoformat(),
                            "id": restante.id,
                            "technique_mitre": restante.technique_mitre,
                            "tactique": restante.tactique_mitre,
                            "description": restante.nom,
                            "statut": "NON_APPLICABLE",
                            "raison": (
                                "Cycle interrompu par le disjoncteur "
                                "(infra d'exécution défaillante) — non exécutée"
                            ),
                        }
                    )
                break

            # Pause entre attaques pour laisser retomber la charge côté
            # cible/SIEM — inutile dans deux cas où elle ne coûtait que du
            # temps : après la dernière attaque (plus rien ne suit), et
            # pour une attaque NON_APPLICABLE, qui n'a touché ni WinRM ni
            # Elasticsearch et n'a donc rien chargé du tout.
            derniere = i == len(attaques_a_faire)
            if not derniere and resultat.get("statut") != "NON_APPLICABLE":
                time.sleep(2 if mode_simulation else self.config.get("pause_entre_attaques_sec", 2))

    _MAX_WORKERS_PARALLELE_CYCLE: ClassVar[int] = 2  # borne dure (G2) --
    # décision explicite de ne PAS rendre ce nombre configurable : au-delà de
    # 2, le risque de charge sur la stack ES/Kibana locale redevient
    # significatif (voir PLAN/SOUTENANCE.md, incident réel du 2026-08-11).
    # Un changement de cette borne doit être un choix de conception
    # délibéré, jamais un réglage qu'on monte par erreur.

    def _executer_attaque_parallele_avec_contexte(
        self, attaque: AttaqueCatalogue, position: int, total: int
    ) -> dict[str, Any]:
        """Wrapper exécuté dans un thread worker : initialise le contexte de
        progression PROPRE À CE THREAD (`self._tls`, voir `__init__`) avant de
        déléguer à `_executer_une_attaque`."""
        self._tls.ctx_progression = {
            "faites": position - 1,
            "total": total,
            "attaque_id": attaque.id,
            "technique": attaque.technique_mitre,
            "nom": attaque.nom,
        }
        self._rapporter_etape(0, "Démarrage")
        return self._executer_une_attaque(attaque, mode_simulation=False)

    def _executer_lots_paralleles(self, attaques_a_faire: list[AttaqueCatalogue]) -> None:
        """G2 : exécute `attaques_a_faire` par lots d'au plus
        `_MAX_WORKERS_PARALLELE_CYCLE` exécutions WinRM/validations TP-FP
        simultanées. Le partitionnement (`partitionner_pour_parallelisme`)
        garantit qu'aucune paire dans un même lot ne peut se contaminer dans
        la fenêtre de validation TP -- voir ce module pour le détail du
        risque. Un lot entier se termine avant que le suivant démarre : donc
        jamais plus de `_MAX_WORKERS_PARALLELE_CYCLE` exécutions concurrentes,
        quel que soit le nombre de lots.

        `self.resultats` n'est écrit QUE depuis ce thread principal (jamais
        depuis un thread worker) : les résultats de chaque lot sont collectés
        via `future.result()` dans l'ordre de soumission (= ordre du
        catalogue), puis `extend()`-és ici. Ordre final déterministe, aucune
        écriture concurrente à protéger.
        """
        lots = partitionner_pour_parallelisme(attaques_a_faire, self._MAX_WORKERS_PARALLELE_CYCLE)
        total = len(attaques_a_faire)
        position = 0
        for indice_lot, lot in enumerate(lots):
            self.log.info(
                f"Lot {indice_lot + 1}/{len(lots)} ({len(lot)} en parallèle) : "
                f"{', '.join(a.id for a in lot)}"
            )
            positions = list(range(position + 1, position + len(lot) + 1))
            position += len(lot)

            try:
                if len(lot) == 1:
                    resultats_lot = [
                        self._executer_attaque_parallele_avec_contexte(lot[0], positions[0], total)
                    ]
                else:
                    with ThreadPoolExecutor(max_workers=self._MAX_WORKERS_PARALLELE_CYCLE) as ex:
                        futurs = [
                            ex.submit(self._executer_attaque_parallele_avec_contexte, a, p, total)
                            for a, p in zip(lot, positions, strict=True)
                        ]
                        resultats_lot = [f.result() for f in futurs]
            except KeyboardInterrupt:
                self.log.warn("Interruption utilisateur (Ctrl+C)")
                return

            self.resultats.extend(resultats_lot)

            dernier_lot = indice_lot == len(lots) - 1
            if not dernier_lot and any(r.get("statut") != "NON_APPLICABLE" for r in resultats_lot):
                time.sleep(self.config.get("pause_entre_attaques_sec", 2))

    def executer_scenario(
        self,
        scenario: ScenarioAdversaire,
        mode_simulation: bool = False,
        avec_llm: bool = False,
    ) -> dict[str, Any]:
        """Exécute une kill chain d'adversaire et retourne son analyse de couverture.

        Enchaîne les attaques du scénario DANS L'ORDRE, puis produit les
        rapports de cycle habituels PLUS un rapport « kill chain » dédié qui
        mesure combien de phases sont détectées et où sont les angles morts.
        C'est le livrable qui dépasse l'émulation seule (jouer la chaîne) :
        CADRE joue la chaîne ET homologue la détection de chaque étape.
        """
        # Régression (audit) « resultats non réinitialisés » -- même
        # raisonnement que executer_cycle_complet() : self.resultats n'est
        # jamais remis à zéro par _boucle_attaques(), qui ne fait qu'append.
        self.resultats = []
        attaques = attaques_ordonnees(scenario)
        self.log.evenement(
            "SCENARIO_START",
            f"Scénario {scenario.id} — {scenario.nom}",
            niveau="INFO",
            nb_attaques=len(attaques),
            mode_simulation=mode_simulation,
        )

        # F-009 : `cadre scenario` en mode réel exécute une VRAIE kill chain
        # sur la cible mais appelait _boucle_attaques() directement, comme
        # executer_cycle_complet() -- sans jamais acquérir le verrou
        # inter-processus que celui-ci acquiert bien. Un `cadre loop`/`cadre
        # cycle`/le dashboard réel et un scénario réel pouvaient donc
        # tourner en même temps contre la même cible, faussant TP/FP des
        # deux côtés -- exactement le trou que F-009 doit fermer.
        if not mode_simulation:
            _acquerir_verrou_cycle()
        try:
            self._boucle_attaques(attaques, mode_simulation)

            analyse = analyser_kill_chain(scenario, self.resultats, mode_simulation=mode_simulation)

            if not mode_simulation and scenario.plateforme == "windows":
                self._deployer_sequences_kill_chain(scenario, attaques, analyse)

            self._generer_rapports_fin_cycle(
                avec_llm=avec_llm, scenario=scenario, analyse_kill_chain=analyse
            )
            self.log.evenement(
                "SCENARIO_END",
                f"Fin du scénario {scenario.id} — "
                f"{analyse['etapes_detectees']}/{analyse['total_etapes']} phases détectées",
                niveau="SUCCESS",
            )
            return analyse
        finally:
            if not mode_simulation:
                _liberer_verrou_cycle()

    def _deployer_sequences_kill_chain(
        self,
        scenario: ScenarioAdversaire,
        attaques: list[AttaqueCatalogue],
        analyse: dict[str, Any],
    ) -> None:
        """
        Après un scénario réel (Windows) : déploie une règle EQL de
        séquence par tronçon de la kill chain effectivement détecté d'un
        bloc. Un angle mort au milieu casse la séquence en deux tronçons
        indépendants (ou l'annule si aucun tronçon n'a ≥2 étapes) — on ne
        corrèle jamais que ce qui est prouvé, jamais une supposition sur
        une étape qui n'a pas été détectée. `maxspan` n'est pas deviné :
        dérivé de l'écart réel entre le premier et le dernier horodatage du
        tronçon, avec une marge de sécurité (x1.5, minimum 10 min).
        """
        par_id_attaque = {a.id: a for a in attaques}
        par_id_resultat = {r.get("id"): r for r in self.resultats}

        troncons: list[list[AttaqueCatalogue]] = []
        courant: list[AttaqueCatalogue] = []
        for etape in analyse["etapes"]:
            if etape["detectee"]:
                courant.append(par_id_attaque[etape["id"]])
            else:
                if len(courant) >= 2:
                    troncons.append(courant)
                courant = []
        if len(courant) >= 2:
            troncons.append(courant)

        for i, troncon in enumerate(troncons, 1):
            horodatages = [
                datetime.fromisoformat(str(par_id_resultat[a.id]["timestamp"])) for a in troncon
            ]
            duree_min = (max(horodatages) - min(horodatages)).total_seconds() / 60
            maxspan_min = max(10, int(duree_min * 1.5) + 5)
            suffixe = f"-{i}" if len(troncons) > 1 else ""
            self.deployer_kibana_sequence(scenario, troncon, maxspan_min, suffixe_id=suffixe)

    def _executer_attaque_simulation(self, attaque: AttaqueCatalogue) -> dict[str, Any]:
        """
        Simule l'exécution d'une attaque (sans toucher la VM).
        Génère la règle Sigma, valide la syntaxe, mais marque comme SIMULE.
        """
        resultat: dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "id": attaque.id,
            "technique_mitre": attaque.technique_mitre,
            "tactique": attaque.tactique_mitre,
            "description": attaque.nom,
            "event_ids_attendus": attaque.event_ids_attendus,
            "statut": "EN_COURS",
        }

        # En mode simulation, on saute l'exécution réelle et l'attente
        log_simule = {
            "event.code": int(attaque.event_ids_attendus[0]),
            "@timestamp": datetime.now().isoformat(),
            "process.command_line": f"CADRE_SIMULATED {attaque.commande[:50]}",
            "host.name": "SIMULATED-VM",
            "user.name": "simulated_user",
        }
        self._rapporter_etape(1, "Exécution (simulée)")
        self._rapporter_etape(3, "Anonymisation")
        log_anonymise = anonymiser_log_elastic(log_simule)

        self._rapporter_etape(4, "Règle Sigma")
        try:
            regle_sigma_yaml = self.generer_regle_sigma_depuis_attaque(attaque, log_anonymise)
        except Exception as e:
            resultat["statut"] = "ERREUR"
            resultat["raison"] = f"Génération Sigma échouée : {e}"
            return resultat

        resultat["regle_sigma_yaml"] = regle_sigma_yaml
        chemin_regle = self.config["repertoire_regles"] / f"{attaque.id}.yml"
        chemin_regle.write_text(regle_sigma_yaml, encoding="utf-8")

        # Compilation
        self._rapporter_etape(5, "Compilation Lucene")
        requete_lucene = compiler_sigma_vers_lucene(regle_sigma_yaml)
        if not requete_lucene:
            # Sigma CLI pas installé : on utilise une requête Lucene simple dérivée
            requete_lucene = (
                f"event.code:{attaque.event_ids_attendus[0]} AND "
                f"process.command_line:*CADRE_TEST_{attaque.id}*"
            )

        resultat["requete_lucene"] = requete_lucene
        resultat["statut"] = "SIMULE"
        resultat["raison"] = "Mode simulation (pas d'exécution réelle)"
        resultat["nb_tp"] = 0
        resultat["nb_fp"] = 0

        self.log.success(
            f"[SIM] Règle générée pour {attaque.id}",
            technique=attaque.technique_mitre,
        )
        return resultat

    def _generer_rapports_fin_cycle(
        self,
        avec_llm: bool = False,
        scenario: ScenarioAdversaire | None = None,
        analyse_kill_chain: dict[str, Any] | None = None,
        duree_sec: float | None = None,
    ) -> None:
        """Génère tous les rapports de fin de cycle.

        Si un `scenario` et son `analyse_kill_chain` sont fournis, produit en
        plus un rapport HTML « kill chain » dédié (couverture phase par phase).
        """
        if not self.resultats:
            return

        resume_llm = None
        analyse_llm = None
        explication_rejets = None
        if avec_llm:
            # Import différé : l'assistant IA est une couche optionnelle,
            # jamais une dépendance dure du pipeline d'audit.
            from .assistant_llm import obtenir_assistant_llm  # noqa: PLC0415

            assistant = obtenir_assistant_llm()
            resume_llm = assistant.resumer_cycle(self.resultats)
            analyse_llm = assistant.analyser_angles_morts(self.resultats)
            explication_rejets = assistant.expliquer_rejets(self.resultats)

        horodatage = datetime.now().strftime("%Y%m%d_%H%M%S")
        generer_rapport_cycle(
            self.resultats,
            self.config["repertoire_rapports"] / f"cycle_{horodatage}.md",
            resume_llm=resume_llm,
            analyse_llm=analyse_llm,
            explication_rejets=explication_rejets,
            duree_sec=duree_sec,
        )
        generer_csv(
            self.resultats,
            self.config["repertoire_rapports"] / f"cycle_{horodatage}.csv",
        )
        generer_rapport_html(
            self.resultats,
            self.config["repertoire_rapports"] / f"cycle_{horodatage}.html",
        )
        try:
            generer_rapport_pdf(
                self.resultats,
                self.config["repertoire_rapports"] / f"cycle_{horodatage}.pdf",
                duree_sec=duree_sec,
            )
        except Exception as e:
            # Format additionnel, non bloquant : MD/CSV/HTML/Navigator sont le
            # contrat de sortie historique du cycle -- une panne reportlab (ex.
            # dépendance absente sur un poste non réinstallé) ne doit jamais
            # faire échouer un cycle par ailleurs réussi.
            self.log.warn(f"Génération du rapport PDF échouée (non bloquant) : {e}")
        generer_layer_navigator(
            self.resultats,
            self.config["repertoire_rapports"] / f"cycle_{horodatage}_navigator.json",
        )
        if scenario is not None and analyse_kill_chain is not None:
            generer_rapport_kill_chain(
                scenario,
                analyse_kill_chain,
                self.config["repertoire_rapports"] / f"scenario_{scenario.id}_{horodatage}.html",
            )
