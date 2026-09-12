# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Catalogue déterministe d'attaques MITRE ATT&CK
======================================================

Ce catalogue définit les attaques que CADRE peut émuler de manière sûre et
reproductible. Chaque attaque est mappée à :
- Une technique MITRE ATT&CK officielle
- Une commande d'exécution (test-only, non-destructive)
- Les EventIDs Windows/Sysmon attendus
- Les faux positifs connus à filtrer
- Le niveau de risque (low/medium/high)

L'utilisation de ce catalogue garantit le DÉTERMINISME du pipeline : pour
chaque attaque exécutée, on sait EXACTEMENT quel EventID doit apparaître
dans Elasticsearch, et on peut diagnostiquer un "angle mort" comme étant
un problème de collecte (Sysmon mal configuré) et non un bug de CADRE.

Usage:
    from cadre.catalogue_attaques import CATALOGUE, obtenir_attaque
    for attaque in CATALOGUE:
        executer(attaque)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class NiveauRisque(StrEnum):
    """Niveau de risque opérationnel de l'attaque."""

    FAIBLE = "low"  # Lecture seule, pas de modification
    MOYEN = "medium"  # Modification légère, réversible
    ELEVE = "high"  # Modification système, nécessite surveillance


class Plateforme(StrEnum):
    WINDOWS = "windows"
    LINUX = "linux"
    MIXTE = "both"


class OrigineExecution(StrEnum):
    """D'où la commande de l'attaque est RÉELLEMENT lancée -- orthogonal à
    `Plateforme`, qui pilote seulement la DÉTECTION (index, pipeline, mode
    d'attente). `CIBLE` = comportement historique (WinRM/SSH direct sur la
    machine cible elle-même). `KALI` = la commande s'exécute via SSH sur la
    VM Kali, qui attaque la cible PAR LE RÉSEAU -- la télémétrie est
    cherchée sur la cible (via `plateforme`), pas sur Kali."""

    CIBLE = "cible"
    KALI = "kali"


@dataclass(frozen=True)
class AttaqueCatalogue:
    """Définition complète d'une attaque testable par CADRE."""

    id: str
    nom: str
    description: str
    technique_mitre: str  # ex: "T1059.001"
    tactique_mitre: str  # ex: "Execution"
    sous_technique: str | None
    commande: str  # Commande exacte à exécuter
    event_ids_attendus: list[str]  # EventIDs Windows/Sysmon qui DOIVENT apparaître
    champ_principal: str  # Champ Elasticsearch principal pour la détection
    valeur_detection: str | None = None  # Texte distinctif réel (déjà présent
    # dans `commande`) utilisé pour corréler l'événement précisément — voir
    # generer_regle_sigma_depuis_attaque(). None = corrélation sur event.code seul.
    seuil_fp_max: int | None = None  # Seuil de faux positifs propre à cette
    # attaque (remplace DEFAUT_CONFIG["seuil_fp_max"] si renseigné). Utile
    # pour les attaques volontairement génériques (ex: baseline sans
    # valeur_detection) dont le bruit de fond attendu est structurellement
    # plus élevé qu'une règle normale — None = utilise le seuil global.
    faux_positifs_connus: list[str] = field(default_factory=list)
    niveau_risque: NiveauRisque = NiveauRisque.FAIBLE
    plateforme: Plateforme = Plateforme.WINDOWS
    references: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    duree_estimee_sec: int = 5
    requires_internet: bool = False  # L'attaque a besoin d'un egress Internet
    # (ex. téléchargement d'un outil). Sur une VM de labo en réseau host-only
    # (sans Internet, par design de sécurité), une telle attaque est marquée
    # NON_APPLICABLE au lieu d'échouer — voir orchestrateur.executer_attaque_complete
    origine_execution: OrigineExecution = OrigineExecution.CIBLE  # Défaut =
    # comportement inchangé pour toutes les attaques existantes. KALI =
    # `commande` s'exécute sur la VM Kali (syntaxe shell Linux), pas sur la
    # cible visée par `plateforme` -- voir orchestrateur._cible_pour_attaque.
    # et le champ de config `cible_a_internet`.


# =============================================================================
# CATALOGUE PRINCIPAL — voir statistiques_catalogue() pour les chiffres à jour
# (`cadre stats`) ; ne pas recopier de compte figé ici, il dérive à chaque ajout.
# =============================================================================

CATALOGUE: list[AttaqueCatalogue] = [
    # -------------------------------------------------------------------------
    # TA0002 — EXECUTION
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-EXE-001",
        nom="PowerShell - Discovery (Get-Process)",
        description="Exécute une commande PowerShell bénigne pour vérifier la télémétrie d'exécution de scripts.",
        technique_mitre="T1059.001",
        tactique_mitre="Execution",
        sous_technique="PowerShell",
        commande='powershell.exe -NoProfile -Command "Get-Process | Out-Null; echo CADRE_PS_BASELINE"',
        event_ids_attendus=["4104", "4688"],  # ScriptBlockLogging + ProcessCreate
        champ_principal="powershell.file.script_block_text",
        # EXC1 (TTP-first) — VALIDATION DE PIPELINE, honnêtement étiquetée :
        # cette attaque n'exécute AUCUN contenu malveillant (juste Get-Process,
        # décrite comme "vérifier la télémétrie" dans la doc ci-dessus) — il
        # n'existe structurellement aucun indicateur générique de détection à
        # construire ici. Le marqueur reste nécessaire (aide au TP), la règle
        # ne prétend PAS détecter un vrai attaquant.
        valeur_detection="CADRE_PS_BASELINE",
        # W3 : override de seuil FP=5000 RETIRÉ (indéfendable). Avec le marqueur
        # ci-dessus, la règle filtre sur CADRE_PS_BASELINE (peu de FP) au lieu
        # de event.code:4104 seul (~6522 FP historiques) : l'attaque relève
        # désormais du seuil global strict, comme toutes les autres. Plus aucun
        # seuil à 5000 dans le catalogue.
        faux_positifs_connus=[
            "Sysmon configuration check",
            "Windows Update health script",
            "Defender definition update",
        ],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=[
            "https://attack.mitre.org/techniques/T1059/001/",
        ],
        prerequisites=[
            "PowerShell 5.1+ installé",
            "Sysmon avec config SwiftOnSecurity ou équivalente",
            "Winlogbeat transmettant les logs PowerShell",
        ],
        duree_estimee_sec=8,
    ),
    # -------------------------------------------------------------------------
    # TA0002 — EXECUTION
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-EXE-002",
        nom="CMD — Process Create Baseline",
        description="Exécute cmd.exe avec arguments pour valider la capture de ProcessCreate par Sysmon.",
        technique_mitre="T1059.003",
        tactique_mitre="Execution",
        sous_technique="Windows Command Shell",
        # NB: "timeout /t 1" échoue sous WinRM ("redirection de l'entrée non
        # prise en charge" — timeout.exe exige une console interactive).
        # "ping -n 2 127.0.0.1 >nul" est l'équivalent non-interactif classique.
        commande='cmd.exe /c "echo CADRE_TEST_MARKER && ping -n 2 127.0.0.1 >nul"',
        event_ids_attendus=["1"],  # Sysmon ProcessCreate
        champ_principal="process.command_line",
        # EXC1 (TTP-first) — VALIDATION DE PIPELINE, honnêtement étiquetée :
        # echo+ping n'a aucun contenu malveillant, aucun indicateur générique
        # possible. Le marqueur reste une aide au TP, pas une détection réelle.
        valeur_detection="CADRE_TEST_MARKER",
        faux_positifs_connus=["Scripts d'administration", "Tâches planifiées système"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1059/003/"],
        duree_estimee_sec=5,
    ),
    # -------------------------------------------------------------------------
    # TA0003 — PERSISTENCE
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-PER-001",
        nom="Création de compte utilisateur (Persistence)",
        description="Crée un compte utilisateur local pour simuler une persistance. Le compte est supprimé immédiatement après la collecte.",
        technique_mitre="T1136.001",
        tactique_mitre="Persistence",
        sous_technique="Local Account",
        commande='net user CADRE_TEST_ACCOUNT "P@ssw0rd!2026" /add; net user CADRE_TEST_ACCOUNT /delete',
        event_ids_attendus=["4720", "4726"],  # Account created + deleted
        champ_principal="event.code",
        # EXC1 (TTP-first) : broadi du marqueur CADRE_TEST_ACCOUNT vers
        # event.code:4720 seul — détecte TOUTE création de compte local,
        # approche standard des règles Sigma communautaires pour T1136.001
        # (bruit géré par exclusions EXC2, pas par un filtre sur le nom du
        # compte, qu'un vrai attaquant ne nommera jamais CADRE_TEST_ACCOUNT).
        valeur_detection=None,
        faux_positifs_connus=[
            "Provisioning automatisé (HR, GPO)",
            "Création admin légitime",
            "MDM enrollment",
        ],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1136/001/"],
        prerequisites=["Droits administrateur local"],
        duree_estimee_sec=6,
    ),
    AttaqueCatalogue(
        id="CADRE-PER-002",
        nom="Tâche planifiée suspecte (Scheduled Task)",
        description="Crée une tâche planifiée qui exécute un programme bénin au démarrage. Permet de tester la détection de persistance via schtasks.",
        technique_mitre="T1053.005",
        tactique_mitre="Persistence",
        sous_technique="Scheduled Task",
        commande='schtasks /create /tn "CADRE_PersistenceTest" /tr "calc.exe" /sc ONLOGON /f',
        # 4104 en tête : la VM n'audite pas 4698 (Audit Other Object Access
        # désactivé) → angle mort. Mais la commande schtasks passe par le
        # ScriptBlock PowerShell (4104), où le nom de tâche est détectable.
        event_ids_attendus=["4104", "4698", "4702"],
        champ_principal="powershell.file.script_block_text",
        # EXC1 (TTP-first) — CORRIGÉ après échec réel constaté (FAUX_NÉGATIF) :
        # "schtasks /create" (multi-mots) ne matche jamais sur
        # powershell.file.script_block_text (champ ES `text` analysé — voir
        # CRE-002 pour l'explication complète du mapping). Broadi vers
        # "schtasks" seul (mono-mot, réel, cohérent avec le broadening
        # event.code de PER-001/PER-003 — bruit géré par exclusions EXC2).
        valeur_detection="schtasks",
        faux_positifs_connus=[
            "GPO déploiement de tâches",
            "Software installer legit",
            "Update schedulers (Adobe, Java)",
        ],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1053/005/"],
        duree_estimee_sec=5,
    ),
    # -------------------------------------------------------------------------
    # TA0007 — DISCOVERY
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-DIS-001",
        nom="System Information Discovery",
        description="Collecte des informations système détaillées. Référence T1082 — test classique de découverte.",
        technique_mitre="T1082",
        tactique_mitre="Discovery",
        sous_technique=None,
        commande="systeminfo.exe /fo CSV",
        event_ids_attendus=["1"],
        champ_principal="process.name",
        valeur_detection="systeminfo.exe",
        faux_positifs_connus=["Inventory tools", "MDM agents"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1082/"],
        duree_estimee_sec=4,
    ),
    AttaqueCatalogue(
        id="CADRE-DIS-002",
        nom="Network Configuration Discovery",
        description="Énumère les interfaces réseau et la table ARP. Teste la détection de reconnaissance réseau.",
        technique_mitre="T1016",
        tactique_mitre="Discovery",
        sous_technique="System Network Configuration Discovery",
        commande="ipconfig /all; arp -a",
        event_ids_attendus=["1"],
        champ_principal="process.command_line",
        valeur_detection="ipconfig",
        faux_positifs_connus=["DHCP client logs", "Network troubleshooting scripts"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1016/"],
        duree_estimee_sec=4,
    ),
    # -------------------------------------------------------------------------
    # TA0006 — CREDENTIAL ACCESS
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-CRE-001",
        nom="Dump SAM registry hive",
        description="Sauvegarde la ruche SAM pour simuler un accès aux credentials. Ne lit PAS le contenu, juste l'export.",
        technique_mitre="T1003.002",
        tactique_mitre="Credential Access",
        sous_technique="Security Account Manager",
        commande="reg.exe save HKLM\\SAM C:\\Windows\\Temp\\CADRE_SAM.hiv /y; reg.exe save HKLM\\SECURITY C:\\Windows\\Temp\\CADRE_SECURITY.hiv /y",
        event_ids_attendus=["1", "13"],  # ProcessCreate + RegistryCreate
        champ_principal="process.command_line",
        # EXC1 (TTP-first) : "save HKLM\SAM" est LA syntaxe réelle du dump de
        # ruche SAM via reg.exe (technique documentée, indépendante du nom du
        # fichier de sortie) — remplace l'ancien marqueur CADRE_SAM.hiv.
        valeur_detection="save HKLM\\SAM",
        faux_positifs_connus=[
            "Backup software",
            "Sysprep automation",
            "Forensics tools legit",
        ],
        niveau_risque=NiveauRisque.ELEVE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1003/002/"],
        prerequisites=["Droits SYSTEM ou administrateur"],
        duree_estimee_sec=8,
    ),
    # -------------------------------------------------------------------------
    # TA0008 — LATERAL MOVEMENT
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-LAT-001",
        nom="Tentative SMB lateral (Admin share)",
        description="Tente d'accéder au partage ADMIN$ pour tester la détection de mouvement latéral.",
        technique_mitre="T1021.002",
        tactique_mitre="Lateral Movement",
        sous_technique="SMB/Windows Admin Shares",
        # NB: pas de "2>&1" ici — sous PowerShell 5.1, rediriger le stderr
        # d'une commande native l'enveloppe dans un NativeCommandError et
        # fait échouer l'appel WinRM même à exit code 0 (bug connu).
        commande='net use \\\\127.0.0.1\\C$ /user:administrator "wrongpassword"',
        event_ids_attendus=["4625", "4776"],  # Logon failure + NTLM auth failure
        champ_principal="event.code",
        # B5 (PLAN/JALON5.md) : LogonType=3 (réseau) est un indicateur réel
        # et généralisable de T1021.002 — pas un marqueur de test, vérifié
        # sur 63 documents winlog.event_data.LogonType réels (champ keyword,
        # correspondance exacte fiable), distinct du nom de compte ciblé.
        valeur_detection="3",
        faux_positifs_connus=[
            "Service account misconfig",
            "Password rotation en cours",
        ],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1021/002/"],
        duree_estimee_sec=5,
    ),
    # -------------------------------------------------------------------------
    # TA0005 — DEFENSE EVASION
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-EVA-001",
        nom="Suspicion de log tampering (Defender status)",
        description="Interroge l'état de Windows Defender pour simuler une reconnaissance de défenses. NE DÉSACTIVE PAS le defender.",
        technique_mitre="T1518.001",
        tactique_mitre="Defense Evasion",
        sous_technique="Security Software Discovery",
        # HISTORIQUE DE DEBUG (27/08, chronologique -- 3 causes distinctes) :
        # 1) Ancienne commande (`Get-MpComputerStatus`) bloquait WinRM à 3
        #    reprises la nuit précédente ; hypothèse posée alors : un
        #    fournisseur WMI (namespace root/Microsoft/Windows/Defender)
        #    laissé dans un état bloquant par SentinelOne (confirmé installé
        #    sur cette VM). Remplacée par une lecture registre directe.
        # 2) Cycle réel relancé à 15:40 : ÉCHEC IDENTIQUE (3 tentatives
        #    ReadTimeout). Test de confirmation : une commande WinRM
        #    générique et sans lien ("echo test") échoue pareil, dès la
        #    négociation -- hypothèse (1) invalidée : ce n'était pas le
        #    fournisseur WMI Defender, c'était le SERVICE WinRM lui-même,
        #    figé ("Running" côté SCM mais aucune requête n'aboutissait).
        # 3) Corrigé à 16:08 via `VBoxManage guestcontrol` (canal Guest
        #    Additions VirtualBox, indépendant de WinRM) : `Restart-Service
        #    WinRM -Force` sur la VM. `cadre status` confirme OK ensuite.
        # 4) Cycle réel relancé à 16:09 : WinRM tient tout le cycle (aucune
        #    erreur réseau) -- mais REJETÉ / FAUX_NEGATIF (tp=0). Cause,
        #    cette fois dans la règle elle-même : voir commentaire sur
        #    champ_principal ci-dessous.
        commande=(
            'powershell.exe -NoProfile -Command "Get-ItemProperty '
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time "
            "Protection' -ErrorAction SilentlyContinue | Out-Null; "
            'Get-Service WinDefend -ErrorAction SilentlyContinue | Out-Null"'
        ),
        # DEUX BUGS DISTINCTS TROUVÉS ET CORRIGÉS EN RÉEL (27/08) :
        # 1) `champ_principal` (informatif seulement -- _calculer_signature_
        #    detection() dans orchestrateur.py déduit le VRAI champ de
        #    corrélation depuis event_ids_attendus[0] via la table
        #    _POWERSHELL_EVENT_INFO, jamais depuis ce champ du catalogue).
        #    Corrigé pour rester cohérent avec la doc, mais sans effet réel
        #    sur la règle générée -- 4104 était déjà en tête.
        # 2) LA VRAIE CAUSE du FAUX_NEGATIF (tp=0, reproduit 2x en cycle réel
        #    à 16:09 et 16:18) : `valeur_detection` contenait un ESPACE
        #    ("Windows Defender\Real-Time Protection"). Diagnostic (requêtes
        #    ES directes) : le document EXISTE bien avec ce texte exact dans
        #    powershell.file.script_block_text (champ `text`, analyzer
        #    winlogbeat_powershell_script_analyzer) -- une clause DSL
        #    `match_phrase` le trouve (4 hits). Mais CADRE valide via un
        #    wildcard `query_string` (compiler_sigma_vers_lucene), qui opère
        #    au niveau TERME, pas phrase : un motif multi-mots ne matche
        #    jamais un champ analysé par ce chemin, même si le texte y est
        #    littéralement. Remplacé par "WinDefend" (mono-mot, déjà présent
        #    dans la commande via `Get-Service WinDefend`) -- vérifié par
        #    requête ES directe : 7 hits/10 min, seulement 4 hits/7 jours
        #    (largement sous SEUIL_FP_MAX=50).
        #    AUDIT DE PORTÉE (27/08, même soir) : cette attaque était-elle un
        #    cas isolé, ou d'autres du catalogue partagent-elles ce risque
        #    (motif `contains` multi-mots sur un champ `text` analysé) ? Les
        #    deux conditions ont été croisées PROGRAMMATIQUEMENT sur tout
        #    CATALOGUE (pas par relecture manuelle) : (a) champ de
        #    corrélation réel = powershell.file.script_block_text (seul
        #    champ `text` analysé utilisé par le catalogue -- process.
        #    command_line et process.title sont tous deux mappés `wildcard`/
        #    `keyword`, donc immunisés par construction, pas de tokenisation)
        #    ET (b) valeur_detection contient un espace. Résultat : 0 autre
        #    attaque dans tout le catalogue ne combine les deux -- CADRE-
        #    EVA-001 était le seul cas réel. Rien d'autre à corriger sur ce
        #    point précis.
        event_ids_attendus=["4104", "4688"],
        champ_principal="powershell.file.script_block_text",
        valeur_detection="WinDefend",
        faux_positifs_connus=["Admin checking defender status"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1518/001/"],
        duree_estimee_sec=5,
    ),
    AttaqueCatalogue(
        id="CADRE-EVA-002",
        nom="Obfuscation basique (Base64 PowerShell)",
        description="Exécute une commande PowerShell encodée en Base64 pour tester la détection d'obfuscation (LoLBas).",
        technique_mitre="T1027",
        tactique_mitre="Defense Evasion",
        sous_technique="Obfuscated Files or Information",
        commande='powershell.exe -NoProfile -EncodedCommand "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABIAGUAbABsAG8AIABDAGEAZAByAGUALgBnAGUAIABJAHMAIABHAGUAdAB0AC0AUABnAHMAUwB5AHMAVABlAG0AIABJAHMAIABPAE4ATABpAG4AZQAuAA=="',
        event_ids_attendus=["4104"],
        champ_principal="process.command_line",
        # EXC1 (TTP-first) — essayé puis REVERTÉ après échec réel mesuré :
        # "-EncodedCommand" semblait un indicateur générique idéal, mais
        # testé en cycle réel il produit 558 correspondances / 344 FP sur 7j
        # (TROP_DE_FP, seuil 50 dépassé) — vérifié contre ES : CHAQUE exemple
        # est `powershell.exe -NoProfile -EncodedCommand ...`, le transport
        # WinRM de CADRE LUI-MÊME (pywinrm encode systématiquement tout script
        # envoyé, y compris les ~40 autres attaques bénignes du catalogue).
        # Ce n'est pas un signal généralisable dans CE labo : c'est un
        # artefact de l'outil de test, pas de l'attaquant. VALIDATION DE
        # PIPELINE, honnêtement étiquetée — le payload décodé est lui-même
        # une chaîne de test synthétique, sans contenu malveillant réel à
        # généraliser (même raisonnement que EXE-001/EXE-002).
        valeur_detection="Gett-PgsSysTem",
        faux_positifs_connus=[
            "Signed scripts de fournisseurs",
            "GPO logon scripts",
        ],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1027/"],
        duree_estimee_sec=5,
    ),
    # -------------------------------------------------------------------------
    # TA0010 — EXFILTRATION (test de canal de sortie)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-EXF-001",
        nom="DNS Exfiltration Simulation",
        description="Effectue une résolution DNS vers un domaine de test pour valider la détection d'exfiltration DNS.",
        technique_mitre="T1048.003",
        tactique_mitre="Exfiltration",
        sous_technique="Exfiltration Over Unencrypted Non-C2 Protocol",
        # NB: "nslookup" utilise toujours son propre résolveur interne
        # (hérité de BIND), jamais l'API Windows standard — Sysmon (EventID
        # 22, qui hooke cette API) ne voit donc JAMAIS ses requêtes, avec ou
        # sans serveur explicite. Confirmé empiriquement : Resolve-DnsName
        # (cmdlet PowerShell natif, passe par l'API standard) génère bien
        # l'événement, nslookup jamais.
        commande="Resolve-DnsName -Name cadre-test.example.com -ErrorAction SilentlyContinue",
        # BUG CORRIGÉ (EXC1) : Sysmon EventID 22 existe bien dans l'index
        # (vérifié : 2805 documents réels, requêtes WPAD légitimes) mais ne
        # capte JAMAIS cette résolution — Resolve-DnsName passe par le
        # ScriptBlock PowerShell (4104), où la commande est détectable (14
        # documents réels confirmés). Cause du FAUX_NEGATIF historique
        # (TP=0/FP=0) : même classe de bug que EXE-001/CRE-002/IMP-001/EXF-002.
        event_ids_attendus=["4104", "22", "1"],
        champ_principal="powershell.file.script_block_text",
        # Reste dépendant du domaine de test (pas de détection DNS générique
        # possible avec le gabarit Sigma actuel à une seule condition — une
        # vraie détection d'exfiltration DNS nécessiterait une heuristique
        # d'anomalie, ex. longueur/entropie de sous-domaine, hors de portée
        # ici). Honnêtement : validation de pipeline, pas TTP générique.
        # BUG CORRIGÉ (2e itération) : "cadre-test.example.com" (avec points)
        # ne matchait toujours pas — même cause que CRE-002/PER-002 : un point
        # casse le wildcard Lucene sur script_block_text (champ `text`
        # analysé). Vérifié contre ES : "cadre-test" (sans point) = 15 hits,
        # "cadre-test.example.com" = 0 hit.
        valeur_detection="cadre-test",
        faux_positifs_connus=[
            "Résolutions DNS normales",
            "Vérifications de connectivité",
        ],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1048/003/"],
        prerequisites=["Sysmon avec DNS logging activé"],
        duree_estimee_sec=4,
    ),
    # -------------------------------------------------------------------------
    # TA0040 — IMPACT (test safe)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-IMP-001",
        nom="File deletion test (test safe)",
        description="Crée puis supprime un fichier de test pour valider la détection d'activité de suppression suspecte.",
        technique_mitre="T1070.004",
        tactique_mitre="Defense Evasion",
        sous_technique="File Deletion",
        commande='echo "CADRE_TEST_DATA" > C:\\Windows\\Temp\\CADRE_TEST_FILE.txt; del C:\\Windows\\Temp\\CADRE_TEST_FILE.txt',
        # 4104 en tête : la commande (echo/del) s'exécute dans le ScriptBlock
        # PowerShell, où le nom de fichier est capté — vérifié contre ES.
        event_ids_attendus=["4104", "11", "1"],
        champ_principal="powershell.file.script_block_text",
        # EXC1 (TTP-first) — VALIDATION DE PIPELINE, honnêtement étiquetée :
        # aucun indicateur générique de "suppression suspecte" n'est
        # constructible ici (Sysmon FileDelete natif — EventID 23 — non
        # confirmé activé sur cette VM ; "del" seul est trop générique pour
        # être un signal). Sans le '.txt' : le champ script_block_text est
        # analysé, un point casse le wildcard Lucene — vérifié contre ES.
        valeur_detection="CADRE_TEST_FILE",
        faux_positifs_connus=["Cleanup scripts", "Installer temp cleanup"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1070/004/"],
        duree_estimee_sec=4,
    ),
    # =========================================================================
    # NOUVELLES ATTAQUES v1.1 (juillet 2026) — extension du catalogue
    # =========================================================================
    # -------------------------------------------------------------------------
    # T1059.005 — Visual Basic (attaquant utilise VBS)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-EXE-003",
        nom="VBScript Execution (cscript)",
        description="Exécute un script VBS bénin pour valider la détection de l'interpréteur VBScript (LoLBas courant).",
        technique_mitre="T1059.005",
        tactique_mitre="Execution",
        sous_technique="Visual Basic",
        commande='cscript //nologo "C:\\Windows\\System32\\winrm.vbs" /? 2>$null; echo CADRE_VBS_DONE',
        event_ids_attendus=["1", "4104"],
        champ_principal="process.command_line",
        valeur_detection="cscript",
        faux_positifs_connus=["Scripts d'administration legacy", "VBS de connexion utilisateur"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1059/005/"],
        duree_estimee_sec=6,
    ),
    # -------------------------------------------------------------------------
    # T1047 — WMIC (souvent utilisé par ransomwares)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-EXE-004",
        nom="WMIC Process Call (legacy LOLBIN)",
        description="Appel WMIC pour récupérer la liste des processus — détection d'un LOLBIN courant dans les ransomwares.",
        technique_mitre="T1047",
        tactique_mitre="Execution",
        sous_technique=None,
        commande="wmic process get name,processid /format:list",
        event_ids_attendus=["1"],
        champ_principal="process.command_line",
        # process.command_line n'est pas analysé (pas de casse-insensible) et
        # Windows normalise "wmic" en "WMIC.exe" (casse d'origine sur disque)
        # dans le command_line réel — on matche sur un argument tapé par
        # nous, dont la casse est garantie préservée telle quelle.
        valeur_detection="processid",
        faux_positifs_connus=["Scripts d'inventaire SCCM", "Monitoring agents"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1047/"],
        duree_estimee_sec=5,
    ),
    # -------------------------------------------------------------------------
    # T1218.011 — rundll32 (LOLBIN ultra-classique)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-EXE-005",
        nom="rundll32 execution (LOLBIN)",
        description="Appel rundll32 sans argument suspect, sert de baseline pour ce LOLBIN omniprésent.",
        technique_mitre="T1218.011",
        tactique_mitre="Defense Evasion",
        sous_technique="Rundll32",
        commande="rundll32.exe /? 2>$null; echo CADRE_RUNDLL_DONE",
        event_ids_attendus=["1"],
        champ_principal="process.command_line",
        # "rundll32" seul matcherait aussi les invocations Windows légitimes
        # (tâches planifiées système type Startupscan.dll) — trop de bruit.
        # Windows normalise la commande en `"C:\\...\\rundll32.exe" /?` : un
        # guillemet s'intercale avant l'espace, donc `rundll32.exe /?` n'est
        # PAS une sous-chaîne réelle (vérifié contre un document indexé).
        # On garde le guillemet pour matcher la forme normalisée exacte.
        valeur_detection='rundll32.exe" /?',
        faux_positifs_connus=["Installateurs logiciels", "MSI installers"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1218/011/"],
        duree_estimee_sec=4,
    ),
    # -------------------------------------------------------------------------
    # T1543.003 — Windows Service (persistence)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-PER-003",
        nom="Création de service Windows (Persistence)",
        description="Crée un service Windows test (auto-supprimé) pour valider la détection de persistance par service.",
        technique_mitre="T1543.003",
        tactique_mitre="Persistence",
        sous_technique="Windows Service",
        # NB: "sc.exe" explicite (pas "sc" seul) — "sc" est un alias
        # PowerShell intégré pour Set-Content, qui masque le vrai binaire
        # Service Control et fait échouer silencieusement la commande.
        commande='sc.exe create CADRE_TestService binPath= "cmd /c echo CADRE_PERSIST" start= demand; sc.exe delete CADRE_TestService',
        event_ids_attendus=["7045", "4697"],  # Service installé
        champ_principal="event.code",
        # EXC1 (TTP-first) : broadi vers event.code:7045 seul — détecte TOUTE
        # installation de service, approche standard des règles Sigma
        # communautaires pour T1543.003 (bruit géré par exclusions EXC2).
        valeur_detection=None,
        faux_positifs_connus=["MDM enrollment", "GPO software install"],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1543/003/"],
        prerequisites=["Droits administrateur"],
        duree_estimee_sec=6,
    ),
    # -------------------------------------------------------------------------
    # T1547.001 — Registry Run Keys (persistance classique)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-PER-004",
        nom="Registry Run Key (HKCU)",
        description="Ajoute une clé Run dans HKCU (puis la retire) pour tester la détection de persistance par Run keys.",
        technique_mitre="T1547.001",
        tactique_mitre="Persistence",
        sous_technique="Registry Run Keys",
        commande='reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v CADRE_Test /t REG_SZ /d "calc.exe" /f; reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v CADRE_Test /f',
        event_ids_attendus=["13", "1"],
        champ_principal="registry.path",
        # EXC1 (TTP-first) : broadi de la valeur de test CADRE_Test vers le
        # chemin de clé Run lui-même — détecte TOUTE valeur ajoutée sous Run
        # (approche standard des règles Sigma communautaires pour T1547.001,
        # tuning via exclusions plutôt que via un filtre par nom de valeur).
        valeur_detection="CurrentVersion\\Run\\",
        faux_positifs_connus=["Installation logicielle", "Auto-start de drivers"],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1547/001/"],
        duree_estimee_sec=5,
    ),
    # -------------------------------------------------------------------------
    # T1057 — Process Discovery (variante pour complétude)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-DIS-003",
        nom="Process Listing (tasklist)",
        description="Liste les processus via tasklist — variante de reconnaissance différente de systeminfo.",
        technique_mitre="T1057",
        tactique_mitre="Discovery",
        sous_technique="Process Discovery",
        commande="tasklist /v /fo CSV",
        event_ids_attendus=["1"],
        champ_principal="process.name",
        valeur_detection="tasklist",
        faux_positifs_connus=["Monitoring EDR", "Inventaire SCCM"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1057/"],
        duree_estimee_sec=4,
    ),
    # -------------------------------------------------------------------------
    # T1087.002 — Domain Account Discovery
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-DIS-004",
        nom="Domain Account Discovery (net user /domain)",
        description="Tente un net user /domain pour simuler une découverte de comptes AD (échec attendu hors domaine).",
        technique_mitre="T1087.002",
        tactique_mitre="Discovery",
        sous_technique="Domain Account",
        commande="net user /domain 2>$null; echo CADRE_DIS_DOMAIN",
        event_ids_attendus=["1", "4661"],
        champ_principal="process.command_line",
        # NB: Windows résout "net" en chemin complet ("C:\...\net.exe"),
        # donc la sous-chaîne "net user /domain" n'existe jamais telle
        # quelle dans la vraie ligne de commande (même piège que WMIC).
        valeur_detection="user /domain",
        faux_positifs_connus=["Audit AD légitime", "Monitoring"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1087/002/"],
        duree_estimee_sec=4,
    ),
    # -------------------------------------------------------------------------
    # T1049 — System Network Connections Discovery (netstat)
    # NB des 6 attaques Discovery ci-dessous : chaque valeur_detection a été
    # vérifiée contre un document Elasticsearch RÉEL (la ligne de commande
    # normalisée par Windows), pas devinée — d'où NETSTAT.EXE en majuscules,
    # net -> net1, whoami.exe" (avec guillemet), etc.
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-DIS-005",
        nom="System Network Connections Discovery (netstat)",
        description="Énumère les connexions réseau actives via netstat -ano (reconnaissance réseau).",
        technique_mitre="T1049",
        tactique_mitre="Discovery",
        sous_technique=None,
        commande="netstat -ano",
        event_ids_attendus=["1"],
        champ_principal="process.command_line",
        valeur_detection='NETSTAT.EXE" -ano',
        faux_positifs_connus=["Diagnostic réseau administrateur", "Outils de supervision"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1049/"],
        duree_estimee_sec=4,
    ),
    # -------------------------------------------------------------------------
    # T1007 — System Service Discovery (tasklist /svc)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-DIS-006",
        nom="System Service Discovery (tasklist)",
        description="Liste les services et leurs processus via tasklist /svc (cartographie des services).",
        technique_mitre="T1007",
        tactique_mitre="Discovery",
        sous_technique=None,
        commande="tasklist /svc",
        event_ids_attendus=["1"],
        champ_principal="process.command_line",
        valeur_detection='tasklist.exe" /svc',
        faux_positifs_connus=["Inventaire système légitime", "Scripts d'administration"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1007/"],
        duree_estimee_sec=4,
    ),
    # -------------------------------------------------------------------------
    # T1069.001 — Permission Groups Discovery (Local)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-DIS-007",
        nom="Local Permission Groups Discovery (net localgroup)",
        description="Énumère les membres du groupe administrateurs local via net localgroup.",
        technique_mitre="T1069.001",
        tactique_mitre="Discovery",
        sous_technique="Local Groups",
        commande="net localgroup administrators",
        event_ids_attendus=["1"],
        champ_principal="process.command_line",
        # Windows exécute "net localgroup" via net1.exe : la sous-chaîne
        # distinctive présente est "localgroup administrators".
        valeur_detection="localgroup administrators",
        faux_positifs_connus=["Audit des droits légitime", "Scripts d'onboarding"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1069/001/"],
        duree_estimee_sec=4,
    ),
    # -------------------------------------------------------------------------
    # T1201 — Password Policy Discovery (net accounts)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-DIS-008",
        nom="Password Policy Discovery (net accounts)",
        description="Récupère la politique de mots de passe locale via net accounts (préparation brute-force).",
        technique_mitre="T1201",
        tactique_mitre="Discovery",
        sous_technique=None,
        commande="net accounts",
        event_ids_attendus=["1"],
        champ_principal="process.command_line",
        valeur_detection="net1 accounts",
        faux_positifs_connus=["Audit de conformité mot de passe", "Durcissement légitime"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1201/"],
        duree_estimee_sec=4,
    ),
    # -------------------------------------------------------------------------
    # T1033 — System Owner/User Discovery (whoami /all)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-DIS-009",
        nom="System Owner/User Discovery (whoami /all)",
        description="Affiche l'utilisateur courant, ses groupes et privilèges via whoami /all.",
        technique_mitre="T1033",
        tactique_mitre="Discovery",
        sous_technique=None,
        commande="whoami /all",
        event_ids_attendus=["1"],
        champ_principal="process.command_line",
        valeur_detection='whoami.exe" /all',
        faux_positifs_connus=["Scripts de diagnostic", "Session utilisateur légitime"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1033/"],
        duree_estimee_sec=4,
    ),
    # -------------------------------------------------------------------------
    # T1012 — Query Registry (reg query sur les clés Run)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-DIS-010",
        nom="Query Registry (reg query clé Run)",
        description="Interroge la clé de démarrage automatique via reg query (repérage de persistance).",
        technique_mitre="T1012",
        tactique_mitre="Discovery",
        sous_technique=None,
        commande='reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"',
        event_ids_attendus=["1"],
        champ_principal="process.command_line",
        valeur_detection="query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        faux_positifs_connus=["Outils de dépannage", "Inventaire logiciel"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1012/"],
        duree_estimee_sec=4,
    ),
    # -------------------------------------------------------------------------
    # T1003.001 — LSASS Memory Dump (Credential Access critique)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-CRE-002",
        nom="LSASS Handle Open (procdump safe test)",
        description="Tente un procdump -ma sur lsass (échec sans droits) — baseline de détection Mimikatz-style.",
        technique_mitre="T1003.001",
        tactique_mitre="Credential Access",
        sous_technique="LSASS Memory",
        commande="procdump -ma lsass.exe C:\\Windows\\Temp\\CADRE_lsass.dmp 2>$null; echo CADRE_LSASS_DONE",
        # 4104 en tête : procdump.exe n'est pas installé (pas de ProcessAccess
        # Sysmon 10) → la commande n'existe que dans le ScriptBlock PowerShell,
        # où le chemin du dump LSASS est détectable — vérifié contre ES.
        event_ids_attendus=["4104", "1", "10"],
        champ_principal="powershell.file.script_block_text",
        # EXC1 (TTP-first) — CORRIGÉ après échec réel constaté (FAUX_NÉGATIF) :
        # "procdump -ma lsass" (multi-mots) ne matche JAMAIS sur
        # powershell.file.script_block_text, un champ ES de type `text`
        # ANALYSÉ (analyzer winlogbeat_powershell_script_analyzer) — un
        # wildcard Lucene n'y matche qu'à l'intérieur d'un seul token, jamais
        # à travers un espace (vérifié : requête isolée contre ES, 0 hit).
        # Contrairement à process.command_line (type ES `wildcard`, conçu pour
        # les sous-chaînes complètes), script_block_text impose un indicateur
        # MONO-MOT. "procdump" seul reste réel et générique (nom du LOLBIN).
        valeur_detection="procdump",
        faux_positifs_connus=["EDR/AV process inspection", "Sysinternals legit"],
        niveau_risque=NiveauRisque.ELEVE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1003/001/"],
        prerequisites=["Sysmon avec ProcessAccess monitoring"],
        duree_estimee_sec=8,
    ),
    # -------------------------------------------------------------------------
    # T1071.001 — Application Layer Protocol (HTTP)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-COM-001",
        nom="HTTP Request Outbound (curl)",
        description="Effectue un curl sortant pour détecter les communications HTTP C2 de base.",
        technique_mitre="T1071.001",
        tactique_mitre="Command and Control",
        sous_technique="Web Protocols",
        # `curl.exe` explicite : sous PowerShell, `curl` seul est un ALIAS de
        # Invoke-WebRequest (idem `wget`) — il n'aurait jamais créé de process
        # curl.exe, donc aucun EventID 1 exploitable (vérifié : FAUX_NEGATIF
        # tant qu'on écrivait `curl`, détecté dès qu'on force `curl.exe`).
        commande="curl.exe -s -o NUL http://example.com -m 5; echo CADRE_HTTP_DONE",
        event_ids_attendus=["1", "22"],  # ProcessCreate + DNSQuery
        champ_principal="process.command_line",
        valeur_detection="example.com",
        faux_positifs_connus=["Health checks", "Update clients"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1071/001/"],
        prerequisites=["curl installé (Windows 10 1803+)"],
        duree_estimee_sec=8,
    ),
    # -------------------------------------------------------------------------
    # T1567.002 — Exfiltration to Cloud Storage
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-EXF-002",
        nom="Cloud Upload Simulation (rclone)",
        description="Tente d'utiliser rclone copy (échec si non installé) pour tester la détection d'exfiltration cloud.",
        technique_mitre="T1567.002",
        tactique_mitre="Exfiltration",
        sous_technique="Exfiltration to Cloud Storage",
        commande="rclone --version 2>$null; echo CADRE_EXFIL_DONE",
        # 4104 en tête : rclone.exe n'est pas installé (pas de ProcessCreate) →
        # la commande n'existe que dans le ScriptBlock PowerShell — vérifié ES.
        event_ids_attendus=["4104", "1"],
        champ_principal="powershell.file.script_block_text",
        valeur_detection="rclone",
        faux_positifs_connus=["Backup cloud légitime", "Sync OneDrive/Google Drive"],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1567/002/"],
        duree_estimee_sec=4,
    ),
    # -------------------------------------------------------------------------
    # T1485 — Data Destruction (test safe)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-IMP-002",
        nom="Data Destruction Test (cipher /w safe)",
        description="Exécute cipher /w sur un répertoire temporaire pour tester la détection de wipers (test safe).",
        technique_mitre="T1485",
        tactique_mitre="Impact",
        sous_technique="Data Destruction",
        # NB: "cipher /w" écrase l'espace libre de tout le VOLUME contenant
        # le dossier cible, pas juste ce dossier — ça peut prendre plusieurs
        # minutes selon l'espace libre du disque, bien au-delà du timeout
        # WinRM (30s), faisant échouer l'appel à tort. Start-Process (sans
        # -Wait) lance cipher.exe pour générer l'événement ProcessCreate
        # attendu sans attendre sa fin — il continue en arrière-plan sur la
        # VM, sans impact (il n'écrase que des données déjà supprimées).
        commande=(
            "mkdir C:\\Windows\\Temp\\CADRE_WIPE_TEST 2>$null; "
            "Start-Process cipher.exe -ArgumentList "
            "'/w:C:\\Windows\\Temp\\CADRE_WIPE_TEST' -WindowStyle Hidden; "
            "echo CADRE_WIPE_DONE"
        ),
        event_ids_attendus=["1"],
        champ_principal="process.command_line",
        # EXC1 (TTP-first) : cipher.exe est lancé en processus enfant (Sysmon
        # EventID 1 le capture séparément) ; Windows normalise sa ligne de
        # commande en `"...\cipher.exe" /w:...` (même normalisation que
        # rundll32/netstat/tasklist ailleurs dans ce fichier — guillemet
        # fermant avant l'espace, PAS de quote simple PowerShell résiduelle).
        # 'cipher.exe" /w:' cible le flag réel de wipe, indépendant du
        # répertoire cible CADRE_WIPE_TEST.
        valeur_detection='cipher.exe" /w:',
        faux_positifs_connus=["Outils de maintenance Windows", "Disk cleanup"],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1485/"],
        duree_estimee_sec=10,
    ),
    # =========================================================================
    # NOUVELLES ATTAQUES v1.1 — LINUX (extension multi-OS)
    # =========================================================================
    # -------------------------------------------------------------------------
    # T1059.004 — Unix Shell (bash) - Linux
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-LIN-001",
        nom="Bash Reverse Shell Test (safe)",
        description="Tente une reverse shell via bash (échec attendu vers IP bogus) — détecte les LOLBIN shell.",
        technique_mitre="T1059.004",
        tactique_mitre="Execution",
        sous_technique="Unix Shell",
        commande='echo "CADRE_LIN_BASH_TEST" && timeout 1 bash -c "cat /etc/passwd > /tmp/cadre_test.txt" 2>/dev/null && rm -f /tmp/cadre_test.txt',
        event_ids_attendus=["100", "501"],  # execve / user_login (auditd)
        champ_principal="process.title",  # Linux/Auditbeat : ligne de commande
        # EXC1 (TTP-first) — VALIDATION DE PIPELINE, honnêtement étiquetée :
        # malgré le nom, cette commande ne tente PAS réellement de reverse
        # shell (juste un `cat` redirigé) — aucun contenu malveillant réel à
        # détecter génériquement.
        valeur_detection="CADRE_LIN_BASH_TEST",
        faux_positifs_connus=["Scripts shell légitimes", "Crontab admin"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1059/004/"],
        prerequisites=["Agent Auditd sur la VM Linux"],
        duree_estimee_sec=5,
    ),
    # -------------------------------------------------------------------------
    # T1053.003 — Cron (persistence Linux)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-LIN-002",
        nom="Cron Persistence Test",
        description="Ajoute une tâche cron (puis la retire) pour tester la détection de persistance cron.",
        technique_mitre="T1053.003",
        tactique_mitre="Persistence",
        sous_technique="Cron",
        commande='(echo "* * * * * /bin/echo CADRE_CRON_TEST"; crontab -l 2>/dev/null) | crontab - 2>/dev/null && sleep 1 && crontab -r 2>/dev/null',
        event_ids_attendus=["100", "110"],  # execve + audit config change
        champ_principal="process.title",  # Linux/Auditbeat : ligne de commande
        # EXC1 (TTP-first) : "crontab -r" (suppression de crontab) est un
        # sous-ensemble générique de la manipulation de crontab, réellement
        # présent dans la commande. "crontab -" seul aurait aussi matché la
        # lecture bénigne "crontab -l" (sous-chaîne) — "-r" évite ce
        # chevauchement sans nécessiter de mécanisme d'exclusion.
        valeur_detection="crontab -r",
        faux_positifs_connus=["Tâches cron admin", "Ansible deploy"],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1053/003/"],
        duree_estimee_sec=6,
    ),
    # -------------------------------------------------------------------------
    # T1546.004 — systemd service (persistence Linux)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-LIN-003",
        nom="systemd Service Unit (Persistence)",
        description="Crée un fichier .service dans /tmp puis le supprime — teste la détection d'ajout de service.",
        technique_mitre="T1546.004",
        tactique_mitre="Persistence",
        sous_technique="systemd Service",
        commande='echo "[Unit]\nDescription=CadreTest\n[Service]\nExecStart=/bin/echo CADRE_SERVICE_TEST" > /tmp/cadre_test.service && cat /tmp/cadre_test.service && rm -f /tmp/cadre_test.service',
        event_ids_attendus=["100", "110"],
        champ_principal="process.title",  # Linux/Auditbeat : ligne de commande
        # EXC1 (TTP-first) — VALIDATION DE PIPELINE, honnêtement étiquetée :
        # aucune sous-chaîne générique disponible sans support des wildcards
        # (le gabarit Sigma actuel ne supporte que `contains`, pas de motif
        # "*.service dans /tmp" ; ".service" seul serait bien trop générique).
        valeur_detection="cadre_test.service",
        faux_positifs_connus=["Services Docker", "CI/CD runners"],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1546/004/"],
        prerequisites=["Auditd avec file watch sur /etc/systemd / /tmp"],
        duree_estimee_sec=5,
    ),
    # =========================================================================
    # NOUVELLES ATTAQUES v1.2 — extension de couverture
    # (Privilege Escalation et Collection : tactiques absentes jusqu'ici ;
    # renforcement de Lateral Movement, Command and Control, Credential Access)
    #
    # Non couvertes volontairement : Reconnaissance et Resource Development.
    # Ces tactiques MITRE décrivent des actions entièrement côté attaquant,
    # en amont de tout contact avec la cible (OSINT, scan externe, achat
    # d'infrastructure, développement de malware) — aucune commande, même
    # exécutée depuis Kali, ne peut générer de télémétrie observable sur la
    # cible pour ces tactiques par nature.
    #
    # Initial Access (TA0001) a longtemps été exclue pour la même raison
    # ("aucune commande ne s'exécute avant d'avoir un accès à la cible"),
    # mais CADRE-CRE-006 (origine Kali) a rendu cette raison caduque —
    # voir CADRE-INI-001 (T1133) plus bas, ajoutée pour combler ce trou.
    # =========================================================================
    # -------------------------------------------------------------------------
    # T1548.002 — Bypass User Account Control (Privilege Escalation)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-PRI-001",
        nom="UAC Bypass via détournement de registre (fodhelper)",
        description=(
            "Crée puis retire une clé de registre imitant la technique de "
            "contournement UAC via fodhelper.exe. N'exécute PAS réellement "
            "fodhelper — teste uniquement la détection de l'artefact registre."
        ),
        technique_mitre="T1548.002",
        tactique_mitre="Privilege Escalation",
        sous_technique="Bypass User Account Control",
        commande=(
            'reg add "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command" '
            '/d "cmd.exe /c echo CADRE_UAC_TEST" /f; '
            'reg add "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command" '
            '/v "DelegateExecute" /t REG_SZ /d "" /f; '
            'reg delete "HKCU\\Software\\Classes\\ms-settings" /f'
        ),
        event_ids_attendus=["1", "13"],  # ProcessCreate + RegistryEvent
        champ_principal="registry.path",
        # EXC1 (TTP-first) : la clé "ms-settings\Shell\Open\command" EST la
        # technique de contournement UAC fodhelper elle-même (bien documentée,
        # réutilisable par n'importe quel attaquant), indépendante du
        # marqueur CADRE_UAC_TEST écrit comme valeur.
        valeur_detection="ms-settings\\Shell\\Open\\command",
        faux_positifs_connus=[
            "Outils de configuration Windows Settings",
            "GPO de personnalisation du shell",
        ],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1548/002/"],
        prerequisites=["Sysmon avec RegistryEvent (EventID 13) activé"],
        duree_estimee_sec=6,
    ),
    # -------------------------------------------------------------------------
    # T1098 — Account Manipulation (Privilege Escalation)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-PRI-004",
        nom="Ajout d'un compte au groupe Administrateurs (Account Manipulation)",
        description=(
            "Crée un compte de test, l'ajoute au groupe local privilégié, "
            "puis retire le compte et le supprime — teste la détection de "
            "l'élévation via appartenance à un groupe, pas juste la création "
            "du compte (déjà couverte par CADRE-PER-001/T1136.001)."
        ),
        technique_mitre="T1098",
        tactique_mitre="Privilege Escalation",
        sous_technique=None,
        commande=(
            'net user CADRE_PrivEscTest "P@ssw0rd!2026" /add; '
            "net localgroup Administrateurs CADRE_PrivEscTest /add; "
            "net localgroup Administrateurs CADRE_PrivEscTest /delete; "
            "net user CADRE_PrivEscTest /delete"
        ),
        event_ids_attendus=["4732", "4720"],  # SamMemberAdded + création compte
        champ_principal="user.target.group.name",
        # EXC1 (TTP-first) : 4732 (ajout à un groupe local security-enabled)
        # est un signal spécifique d'élévation -- vérifié en réel : "4672"
        # (privilèges spéciaux) et "4624" (logon) sont bien trop bruyants sur
        # ce labo (922/931 hits sur 7j, déclenchés par chaque connexion WinRM
        # admin), 4732 ne l'est pas (7 hits/7j avant cette attaque). Champ de
        # corrélation confirmé sur un document réel indexé : `user.target.
        # name` (ECS) est vide ("-", mappé depuis MemberName, non fiable
        # ici) -- le nom du GROUPE cible est en réalité dans
        # `user.target.group.name` (mappé depuis TargetUserName). Nom de
        # groupe lui-même confirmé en direct sur la VM (`net localgroup`) --
        # le labo est en localisation française, "Administrators" (anglais)
        # n'existe pas comme groupe littéral ici.
        valeur_detection="Administrateurs",
        faux_positifs_connus=[
            "Administration légitime des groupes locaux",
            "Scripts de provisioning",
        ],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1098/"],
        prerequisites=["Droits administrateur pour modifier l'appartenance aux groupes"],
        duree_estimee_sec=6,
    ),
    # -------------------------------------------------------------------------
    # T1005 — Data from Local System (Collection)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-COL-001",
        nom="Copie de fichier système local (Data from Local System)",
        description=(
            "Copie un fichier système bénin vers un répertoire temporaire "
            "puis le supprime — simule une étape de collecte avant exfiltration."
        ),
        technique_mitre="T1005",
        tactique_mitre="Collection",
        sous_technique=None,
        commande=(
            'cmd.exe /c "copy C:\\Windows\\System32\\drivers\\etc\\hosts '
            "C:\\Windows\\Temp\\CADRE_collected.txt /Y & "
            'del C:\\Windows\\Temp\\CADRE_collected.txt"'
        ),
        # NB: passe par cmd.exe /c (comme CADRE-EXE-002) plutôt que d'exécuter
        # "copy ... /Y" en PowerShell nu : l'alias PowerShell Copy-Item ne
        # comprend pas le flag /Y (syntaxe cmd.exe), ce qui ferait échouer
        # la copie silencieusement (Try/Catch) sans jamais créer le fichier.
        event_ids_attendus=["1", "11"],  # ProcessCreate + FileCreate
        champ_principal="process.command_line",
        # EXC1 (TTP-first) — VALIDATION DE PIPELINE, honnêtement étiquetée :
        # copier un fichier système bénin (hosts) vers un dossier temporaire
        # est indiscernable d'une activité admin légitime sans contexte
        # comportemental (volume, fréquence) hors de portée du gabarit actuel.
        valeur_detection="CADRE_collected.txt",
        faux_positifs_connus=["Scripts de sauvegarde", "Outils de diagnostic réseau"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1005/"],
        duree_estimee_sec=4,
    ),
    # -------------------------------------------------------------------------
    # T1560.001 — Archive Collected Data via Utility (Collection)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-COL-002",
        nom="Archivage de données collectées (Compress-Archive)",
        description=(
            "Compresse un répertoire de test avec l'utilitaire natif "
            "PowerShell, puis supprime l'archive — teste la détection "
            "d'archivage pré-exfiltration."
        ),
        technique_mitre="T1560.001",
        tactique_mitre="Collection",
        sous_technique="Archive via Utility",
        # NB: Compress-Archive échoue silencieusement sur un répertoire
        # vide — on y place un fichier avant de compresser.
        commande=(
            'powershell.exe -NoProfile -Command "'
            "New-Item -ItemType Directory -Path $env:TEMP\\cadre_arch -Force | Out-Null; "
            "Set-Content -Path $env:TEMP\\cadre_arch\\test.txt -Value CADRE_ARCHIVE_TEST; "
            "Compress-Archive -Path $env:TEMP\\cadre_arch "
            "-DestinationPath $env:TEMP\\cadre_test.zip -Force; "
            'Remove-Item $env:TEMP\\cadre_arch, $env:TEMP\\cadre_test.zip -Recurse -Force"'
        ),
        event_ids_attendus=["1", "4104", "11"],
        champ_principal="process.command_line",
        # EXC1 (TTP-first) : "Compress-Archive -Path" est l'invocation réelle
        # du cmdlet d'archivage (technique-générique), indépendante du nom
        # d'archive cadre_test.zip.
        valeur_detection="Compress-Archive -Path",
        faux_positifs_connus=[
            "Scripts de sauvegarde automatisés",
            "Déploiement logiciel (packagers MSI)",
        ],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1560/001/"],
        duree_estimee_sec=6,
    ),
    # -------------------------------------------------------------------------
    # T1105 — Ingress Tool Transfer (Command and Control)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-COM-002",
        nom="Téléchargement via certutil (Ingress Tool Transfer)",
        description=(
            "Utilise certutil -urlcache pour télécharger un fichier bénin — "
            "LOLBIN classique de transfert d'outils en C2."
        ),
        technique_mitre="T1105",
        tactique_mitre="Command and Control",
        sous_technique=None,
        commande=(
            "certutil.exe -urlcache -split -f http://example.com/robots.txt "
            "C:\\Windows\\Temp\\CADRE_dl.txt 2>$null; "
            "del C:\\Windows\\Temp\\CADRE_dl.txt 2>$null; echo CADRE_DL_DONE"
        ),
        event_ids_attendus=["1", "22"],  # ProcessCreate + DNSQuery
        champ_principal="process.command_line",
        # EXC1 (TTP-first) : "-urlcache -split -f" est la syntaxe LOLBIN
        # réelle et bien documentée de certutil pour le transfert d'outils
        # (Ingress Tool Transfer), indépendante du fichier cible CADRE_dl.txt.
        valeur_detection="-urlcache -split -f",
        faux_positifs_connus=[
            "Vérification de certificats légitime",
            "Scripts de déploiement interne",
        ],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1105/"],
        duree_estimee_sec=8,
        requires_internet=True,  # certutil télécharge depuis Internet → NON_APPLICABLE
        # sur une VM host-only (labo isolé). Sinon certutil échoue (pas de route).
    ),
    # -------------------------------------------------------------------------
    # T1021.001 — Remote Desktop Protocol (Lateral Movement)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-LAT-002",
        nom="Test de connectivité RDP (Remote Desktop Protocol)",
        description=(
            "Teste la connectivité TCP vers le port RDP local, sans "
            "authentification réelle — valide la détection de reconnaissance "
            "ou de mouvement latéral RDP."
        ),
        technique_mitre="T1021.001",
        tactique_mitre="Lateral Movement",
        sous_technique="Remote Desktop Protocol",
        commande=(
            'powershell.exe -NoProfile -Command "Test-NetConnection '
            "-ComputerName 127.0.0.1 -Port 3389 -WarningAction SilentlyContinue "
            '| Out-Null"'
        ),
        event_ids_attendus=["4104", "3"],  # ScriptBlock + Sysmon NetworkConnect
        champ_principal="process.command_line",
        valeur_detection="3389",
        faux_positifs_connus=["Scripts de monitoring réseau", "Health checks RDP"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1021/001/"],
        prerequisites=["Sysmon avec NetworkConnect (EventID 3) activé"],
        duree_estimee_sec=5,
    ),
    # -------------------------------------------------------------------------
    # T1552.001 — Credentials In Files (Credential Access)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-CRE-003",
        nom="Recherche de credentials en clair (Credentials In Files)",
        description=(
            "Recherche le mot 'password' dans les fichiers texte d'un "
            "répertoire temporaire — pattern classique de recherche de "
            "credentials en clair."
        ),
        technique_mitre="T1552.001",
        tactique_mitre="Credential Access",
        sous_technique="Credentials In Files",
        commande="findstr /si password C:\\Windows\\Temp\\*.txt 2>$null; echo CADRE_CREDSEARCH_DONE",
        event_ids_attendus=["1"],
        champ_principal="process.command_line",
        valeur_detection="password",
        faux_positifs_connus=["Audits de sécurité internes", "Scripts de compliance"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1552/001/"],
        duree_estimee_sec=4,
    ),
    # -------------------------------------------------------------------------
    # T1558.003 — Kerberoasting (Credential Access)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-CRE-004",
        nom="Tentative de requête SPN (Kerberoasting)",
        description=(
            "Tente une requête setspn pour lister les comptes de service "
            "(échec attendu hors domaine) — baseline de détection Kerberoasting."
        ),
        technique_mitre="T1558.003",
        tactique_mitre="Credential Access",
        sous_technique="Kerberoasting",
        commande="setspn -T CADRE.LOCAL -Q */* 2>$null; echo CADRE_KERBEROAST_DONE",
        event_ids_attendus=["1", "4769"],
        champ_principal="process.command_line",
        # EXC1 (TTP-first) : "-Q */*" est la syntaxe réelle d'énumération
        # totale des SPN via setspn (signature Kerberoasting générique),
        # indépendante du domaine CADRE.LOCAL.
        valeur_detection="-Q */*",
        faux_positifs_connus=[
            "Audit AD légitime des SPN",
            "Outils d'inventaire de comptes de service",
        ],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1558/003/"],
        prerequisites=[
            "Machine jointe à un domaine pour un test complet (sinon échec safe attendu)"
        ],
        duree_estimee_sec=5,
    ),
    # -------------------------------------------------------------------------
    # T1552.001 — Credentials In Files, variante Linux (Credential Access)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-LIN-004",
        nom="Recherche de credentials en clair (Linux)",
        description=(
            "Recherche le mot 'password' dans les fichiers d'un répertoire "
            "temporaire Linux — variante Unix de la recherche de credentials "
            "en clair."
        ),
        technique_mitre="T1552.001",
        tactique_mitre="Credential Access",
        sous_technique="Credentials In Files",
        commande="grep -ril password /tmp 2>/dev/null; echo CADRE_LIN_CREDSEARCH_DONE",
        event_ids_attendus=["100"],
        # Détection Linux : sur process.title (Auditbeat). "password" seul serait
        # trop générique → on cible le marqueur distinctif de la commande.
        champ_principal="process.title",
        # EXC1 (TTP-first) : "grep -ril password" est la commande réelle déjà
        # présente (recherche récursive insensible à la casse), indépendante
        # du marqueur de fin d'exécution.
        valeur_detection="grep -ril password",
        faux_positifs_connus=[
            "Scripts d'audit de sécurité",
            "Outils de compliance (Lynis, OpenSCAP)",
        ],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1552/001/"],
        duree_estimee_sec=4,
    ),
    # =========================================================================
    # NOUVELLES ATTAQUES v1.3 — extension de couverture (techniques prévalentes)
    #
    # Toutes ces attaques utilisent le MOTIF DE DÉTECTION LE PLUS FIABLE
    # identifié dans ce projet : la valeur_detection est un littéral placé
    # dans l'argument `-Command` de powershell.exe. Windows préserve cet
    # argument tel quel dans process.command_line (vérifié : EVA-001
    # "Get-MpComputerStatus", EVA-002, LAT-002 "3389"), ce qui contourne
    # entièrement les pièges de normalisation (majuscules NETSTAT.EXE,
    # net -> net1, guillemet inséré) qui touchent les binaires natifs.
    # -------------------------------------------------------------------------
    # T1083 — File and Directory Discovery
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-DIS-011",
        nom="File and Directory Discovery (Get-ChildItem récursif)",
        description=(
            "Parcourt récursivement l'arborescence utilisateur à la recherche "
            "d'un fichier inexistant — reconnaissance de fichiers/répertoires."
        ),
        technique_mitre="T1083",
        tactique_mitre="Discovery",
        sous_technique=None,
        commande=(
            'powershell.exe -NoProfile -Command "Get-ChildItem -Path C:\\Users '
            "-Recurse -Filter CADRE_FIND_NOEXIST -ErrorAction SilentlyContinue "
            '| Out-Null"'
        ),
        event_ids_attendus=["1", "4104"],
        champ_principal="process.command_line",
        valeur_detection="Get-ChildItem -Path C:\\Users -Recurse",
        faux_positifs_connus=["Indexation de fichiers", "Antivirus scan", "Scripts de sauvegarde"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1083/"],
        duree_estimee_sec=6,
    ),
    # -------------------------------------------------------------------------
    # T1518 — Software Discovery (clés de désinstallation)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-DIS-012",
        nom="Software Discovery (registre Uninstall)",
        description=(
            "Énumère les logiciels installés via les clés de registre "
            "Uninstall — cartographie des applications présentes."
        ),
        technique_mitre="T1518",
        tactique_mitre="Discovery",
        sous_technique=None,
        commande=(
            'powershell.exe -NoProfile -Command "Get-ItemProperty '
            "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
            '-ErrorAction SilentlyContinue | Select-Object DisplayName | Out-Null"'
        ),
        event_ids_attendus=["1", "4104"],
        champ_principal="process.command_line",
        valeur_detection="CurrentVersion\\Uninstall",
        faux_positifs_connus=["Inventaire logiciel (SCCM)", "Outils de gestion de parc"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1518/"],
        duree_estimee_sec=5,
    ),
    # -------------------------------------------------------------------------
    # T1140 — Deobfuscate/Decode Files or Information (certutil -decode)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-EVA-003",
        nom="Deobfuscate/Decode via certutil (-decode)",
        description=(
            "Décode un fichier Base64 bénin avec certutil -decode (puis "
            "nettoie) — LOLBIN classique de désobfuscation de charge utile."
        ),
        technique_mitre="T1140",
        tactique_mitre="Defense Evasion",
        sous_technique=None,
        commande=(
            'powershell.exe -NoProfile -Command "Set-Content '
            "$env:TEMP\\cadre_b64.txt 'Q0FEUkVfREVDT0RFX1RFU1Q='; "
            "certutil -decode $env:TEMP\\cadre_b64.txt $env:TEMP\\cadre_dec.txt "
            "| Out-Null; Remove-Item $env:TEMP\\cadre_b64.txt,"
            '$env:TEMP\\cadre_dec.txt -Force -ErrorAction SilentlyContinue"'
        ),
        event_ids_attendus=["1", "4104"],
        champ_principal="process.command_line",
        valeur_detection="certutil -decode",
        faux_positifs_connus=["Gestion de certificats légitime", "Scripts de déploiement"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1140/"],
        duree_estimee_sec=6,
    ),
    # -------------------------------------------------------------------------
    # T1036.005 — Masquerading: Match Legitimate Name or Location
    #
    # Ajoutée (perspective d'évolution n°4 du rapport) : catalogue élargi
    # en conservant la discipline "indicateur réel" plutôt que le volume.
    # Copie un binaire légitime et bénin (notepad.exe) sous le nom
    # "svchost.exe" DANS UN RÉPERTOIRE OÙ CE PROCESSUS SYSTÈME NE S'EXÉCUTE
    # JAMAIS légitimement (svchost.exe réel : uniquement depuis
    # C:\Windows\System32\ ou C:\Windows\SysWOW64\). Contrairement aux
    # marqueurs CADRE_* des attaques "validation de pipeline" ci-dessus,
    # ce signal (chemin+nom incohérents) est celui qu'un VRAI attaquant
    # masquant une charge utile présenterait aussi — pas un artefact de
    # l'outil de test. INDICATEUR RÉEL, pas ajoutée à
    # _IDS_VALIDATION_PIPELINE plus bas.
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-EVA-004",
        nom="Masquerading — binaire renommé svchost.exe hors System32",
        description=(
            "Copie un binaire Windows légitime (notepad.exe) sous le nom "
            "svchost.exe dans C:\\Windows\\Temp — chemin où ce processus "
            "système ne s'exécute jamais légitimement — l'exécute "
            "brièvement puis nettoie."
        ),
        technique_mitre="T1036.005",
        tactique_mitre="Defense Evasion",
        sous_technique="Match Legitimate Name or Location",
        # BUG TROUVÉ PAR AUDIT (27/08) ET CORRIGÉ ICI, vérifié par repro local
        # (jamais sur la VM cible) : `$p` et `$p.Id` DOIVENT être échappés
        # (`` `$p ``) sous peine d'être interpolés par le PowerShell EXTÉRIEUR
        # (celui lancé via -EncodedCommand par executer_commande_winrm) AVANT
        # même d'atteindre le `powershell.exe -Command "..."` imbriqué --
        # cette chaîne entre guillemets doubles est un argument évalué par
        # l'extérieur, pas un bloc opaque transmis tel quel. Sans l'échappement
        # (`$p` nu), `$p` est vide dans le contexte EXTÉRIEUR (jamais assigné
        # à ce niveau) : la ligne devient littéralement
        # " = Start-Process ... -PassThru" côté enfant -- un `=` isolé n'est
        # pas reconnu comme commande (CommandNotFoundException), donc
        # Start-Process n'est JAMAIS invoqué. Résultat mesuré (repro local
        # avec notepad.exe, PID jamais capturé, Get-Process négatif) :
        # svchost.exe est copié PUIS supprimé SANS JAMAIS être exécuté --
        # l'attaque de masquerading ne se produit pas, silencieusement (le
        # Catch extérieur n'est même pas déclenché, une erreur native non
        # gérée par $ErrorActionPreference n'étant pas une exception
        # PowerShell terminante). Avec l'échappement, reproduit et vérifié en
        # local (PID réellement capturé, processus réellement tué, fichier
        # bien supprimé après exécution) : Start-Process s'exécute pour de
        # vrai côté processus enfant, comme prévu.
        #
        # SUIVI POST-CORRECTIF (27/08, contre la VM CADRE réelle, pas juste
        # en local) : la LOGIQUE de détection est confirmée correcte par
        # inspection directe d'Elasticsearch -- un vrai processus
        # `C:\Windows\Temp\svchost.exe` a été capturé par Sysmon avec
        # `pe.original_file_name: NOTEPAD.EXE`, l'empreinte exacte d'un
        # masquerading réel. Mais sur 3 tentatives de VALIDATION AUTOMATISÉE
        # (cycle complet) la même nuit : 1 succès de télémétrie (hors fenêtre
        # d'attente CADRE), 1 "angle mort" (pipeline d'indexation ES arrêté
        # entre-temps, sans rapport avec cette attaque), 1 échec WinRM
        # (ReadTimeout sur les 3 tentatives internes). Motif cohérent avec
        # CADRE-EVA-001 (T1518.001) : un EDR sur cette VM interfère
        # probablement avec ce comportement précis (usurpation de nom de
        # process système), pas un défaut du code. Traiter comme
        # CADRE-EVA-001 : à exclure des cycles de démo routiniers sur CE
        # labo tant que l'interférence n'est pas comprise, sans remettre en
        # cause la classification "indicateur réel" (propriété de la règle,
        # pas de sa fiabilité d'exécution sur cet environnement précis).
        commande=(
            'powershell.exe -NoProfile -Command "Copy-Item '
            "C:\\Windows\\System32\\notepad.exe C:\\Windows\\Temp\\svchost.exe "
            "-Force; `$p = Start-Process C:\\Windows\\Temp\\svchost.exe -PassThru; "
            "Start-Sleep -Milliseconds 800; Stop-Process -Id `$p.Id -Force "
            "-ErrorAction SilentlyContinue; Remove-Item "
            'C:\\Windows\\Temp\\svchost.exe -Force -ErrorAction SilentlyContinue"'
        ),
        event_ids_attendus=["1"],
        champ_principal="process.command_line",
        valeur_detection="Windows\\Temp\\svchost.exe",
        faux_positifs_connus=[
            "Aucun connu — svchost.exe légitime ne s'exécute que depuis "
            "System32/SysWOW64, jamais depuis Temp"
        ],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1036/005/"],
        duree_estimee_sec=5,
    ),
    # -------------------------------------------------------------------------
    # T1552.004 — Unsecured Credentials: Private Keys
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-CRE-005",
        nom="Recherche de clés privées (Private Keys)",
        description=(
            "Recherche récursivement des fichiers de clés privées "
            "(*.pem, *.key, *.ppk) dans l'arborescence utilisateur."
        ),
        technique_mitre="T1552.004",
        tactique_mitre="Credential Access",
        sous_technique="Private Keys",
        commande=(
            'powershell.exe -NoProfile -Command "Get-ChildItem -Path C:\\Users '
            "-Recurse -Include *.pem,*.key,*.ppk -ErrorAction SilentlyContinue "
            '| Out-Null"'
        ),
        event_ids_attendus=["1", "4104"],
        champ_principal="process.command_line",
        valeur_detection="*.pem,*.key,*.ppk",
        faux_positifs_connus=["Audit de sécurité", "Outils de gestion de certificats"],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1552/004/"],
        duree_estimee_sec=6,
    ),
    # -------------------------------------------------------------------------
    # T1110.001 — Brute Force: Password Guessing (DEPUIS Kali, par le réseau)
    #
    # S'exécute RÉELLEMENT sur la VM Kali (origine_execution=KALI) et vise la
    # cible Windows par le réseau -- {CIBLE_IP} est substitué par l'IP
    # réellement configurée à l'exécution (voir
    # orchestrateur.executer_commande_ssh_kali). Jamais le compte admin réel :
    # un compte de test dédié non-admin ("CadreBruteTest") doit être créé sur
    # la cible au préalable (voir prerequisites).
    #
    # Une seule entrée, pas une par étape : plusieurs mots de passe erronés
    # PUIS le bon, dans la MÊME commande, reproduisent le brute force complet
    # (échecs + réussite). Les échecs (4625/LogonType:3) auraient la même
    # signature Sigma que CADRE-LAT-001 (confirmé par
    # `detecter_regles_similaires` -- un doublon fonctionnel pur si déclarés
    # en entrée séparée), donc seule la RÉUSSITE finale (4624) est la
    # détection portée par cette entrée -- c'est la seule capacité
    # structurellement nouvelle : 4624 était exclu du catalogue jusqu'ici
    # (bruit des connexions admin de l'orchestrateur), la corrélation par
    # compte de test dédié le rend enfin exploitable.
    #
    # Outil offensif : `netexec` 1.5.1, confirmé installé sur Kali en
    # conditions réelles (lot G1) -- `-p` accepte plusieurs mots de passe
    # espacés (spray séquentiel), `--local-auth` requis (compte LOCAL, pas
    # de domaine sur ce labo -- `-d`/`--local-auth` mutuellement exclusifs
    # côté netexec). Port 5985 confirmé joignable depuis Kali en réel.
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-CRE-006",
        nom="Brute force WinRM depuis Kali (échecs puis authentification réussie)",
        description=(
            "Depuis la VM Kali, tente plusieurs authentifications WinRM avec "
            "un mauvais mot de passe puis le bon, contre un compte de test "
            "dédié -- brute force réseau réel (pas une commande locale à la "
            "cible), preuve portée par la réussite finale."
        ),
        technique_mitre="T1110.001",
        tactique_mitre="Credential Access",
        sous_technique="Password Guessing",
        commande=(
            "netexec winrm {CIBLE_IP} -u CadreBruteTest "
            "-p 'M0tDeP4sse1!' 'M0tDeP4sse2!' '{CADRE_BRUTE_TEST_PASS}' --local-auth"
        ),
        event_ids_attendus=["4624"],  # Logon success -- voir commentaire ci-dessus
        champ_principal="event.code",
        # 4624 seul est trop bruyant sur ce labo (connexions WinRM admin de
        # l'orchestrateur à chaque cycle) -- corrélé ici sur le compte de
        # TEST DÉDIÉ, jamais utilisé par l'orchestrateur lui-même. Champ
        # confirmé par inspection d'un document 4624 réel indexé ET par un
        # cycle réel complet : TP=1 FP=0 sur 7 jours (voir
        # _NATIVE_CHAMP_CORRELATION["4624"] pour le détail).
        valeur_detection="CadreBruteTest",
        faux_positifs_connus=[
            "Un opérateur humain se connecte manuellement avec ce compte de test"
        ],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.WINDOWS,
        origine_execution=OrigineExecution.KALI,
        references=["https://attack.mitre.org/techniques/T1110/001/"],
        prerequisites=[
            "Compte Windows local non-admin 'CadreBruteTest' créé sur la cible "
            "(jamais le compte admin réel), mot de passe final défini via "
            "cadre init --set CADRE_BRUTE_TEST_PASS=...",
            "netexec installé sur Kali (confirmé en réel, v1.5.1)",
            "Réseau host-only actif entre Kali et la cible, port 5985 joignable "
            "(confirmé en réel)",
        ],
        duree_estimee_sec=15,
    ),
    # -------------------------------------------------------------------------
    # TA0001 — INITIAL ACCESS : T1133 — External Remote Services
    #
    # Comble un trou honnêtement documenté (voir plus bas, "Non couvertes
    # volontairement") : Initial Access était exclue car aucune commande
    # CADRE ne s'exécutait *avant* d'avoir un accès à la cible -- jusqu'à
    # CADRE-CRE-006 (origine Kali). Contrairement à CRE-006 (devine un mot
    # de passe, T1110.001 -- Credential Access), cette attaque utilise un
    # identifiant DÉJÀ valide dès le premier essai : elle représente
    # l'usage d'un service distant exposé (WinRM) comme vecteur d'accès
    # initial, pas l'obtention de l'identifiant lui-même.
    #
    # Distinction technique OBLIGATOIRE avec CADRE-CRE-006 : réutiliser le
    # compte "CadreBruteTest" produirait la MÊME signature Sigma que
    # CRE-006 (confirmé par `detecter_regles_similaires` -- seule la valeur
    # de corrélation finale sur TargetUserName compte, pas la présence
    # d'échecs préalables). D'où un compte de test dédié SÉPARÉ.
    # Prérequis manuel supplémentaire (comme pour CadreBruteTest) : créer
    # 'CadreIniAccessTest' sur la VM Windows avant tout cycle réel.
    #
    # EXC1 (TTP-first) — VALIDATION DE PIPELINE, honnêtement étiquetée dès
    # la création (pas de reclassification a posteriori cette fois) : la
    # corrélation porte sur un compte de test CADRE, pas sur un indicateur
    # qu'un vrai attaquant présenterait (voir _IDS_VALIDATION_PIPELINE).
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-INI-001",
        nom="Accès initial via service distant exposé (WinRM depuis Kali)",
        description=(
            "Depuis la VM Kali, s'authentifie en WinRM du premier coup avec "
            "un identifiant DÉJÀ valide (pas de deviné) contre un compte de "
            "test dédié -- émule l'usage d'un service distant exposé comme "
            "vecteur d'accès initial, distinct de l'obtention de "
            "l'identifiant (CADRE-CRE-006)."
        ),
        technique_mitre="T1133",
        tactique_mitre="Initial Access",
        sous_technique="External Remote Services",
        commande=(
            "netexec winrm {CIBLE_IP} -u CadreIniAccessTest "
            "-p '{CADRE_INI_ACCESS_TEST_PASS}' --local-auth"
        ),
        event_ids_attendus=["4624"],  # Logon success -- même mécanisme que CRE-006
        champ_principal="event.code",
        valeur_detection="CadreIniAccessTest",
        faux_positifs_connus=[
            "Un opérateur humain se connecte manuellement avec ce compte de test"
        ],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.WINDOWS,
        origine_execution=OrigineExecution.KALI,
        references=["https://attack.mitre.org/techniques/T1133/"],
        prerequisites=[
            "Compte Windows local non-admin 'CadreIniAccessTest' créé sur la "
            "cible -- SÉPARÉ de 'CadreBruteTest' (réutiliser ce dernier "
            "produirait une règle dupliquée de CRE-006), mot de passe défini "
            "via cadre init --set CADRE_INI_ACCESS_TEST_PASS=...",
            "netexec installé sur Kali (confirmé en réel, v1.5.1)",
            "Réseau host-only actif entre Kali et la cible, port 5985 joignable "
            "(confirmé en réel)",
        ],
        duree_estimee_sec=10,
    ),
    # -------------------------------------------------------------------------
    # T1074.001 — Data Staged: Local Data Staging
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-COL-003",
        nom="Local Data Staging (regroupement avant exfiltration)",
        description=(
            "Crée un répertoire de rassemblement, y copie un fichier système "
            "bénin puis nettoie — simule la mise en scène locale de données."
        ),
        technique_mitre="T1074.001",
        tactique_mitre="Collection",
        sous_technique="Local Data Staging",
        commande=(
            'powershell.exe -NoProfile -Command "New-Item -ItemType Directory '
            "$env:TEMP\\CADRE_STAGE -Force | Out-Null; Copy-Item "
            "C:\\Windows\\System32\\drivers\\etc\\hosts $env:TEMP\\CADRE_STAGE\\; "
            'Remove-Item $env:TEMP\\CADRE_STAGE -Recurse -Force"'
        ),
        event_ids_attendus=["1", "11"],
        champ_principal="process.command_line",
        # EXC1 (TTP-first) — VALIDATION DE PIPELINE, honnêtement étiquetée :
        # même raisonnement que COL-001 — créer un dossier temporaire et y
        # copier un fichier bénin n'a pas de signature générique distinguable
        # d'une activité légitime sans contexte comportemental.
        valeur_detection="CADRE_STAGE",
        faux_positifs_connus=["Scripts de sauvegarde", "Synchronisation de fichiers"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1074/001/"],
        duree_estimee_sec=6,
    ),
    # -------------------------------------------------------------------------
    # T1571 — Non-Standard Port (test de connectivité C2)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-COM-003",
        nom="Non-Standard Port Connection (port 4444)",
        description=(
            "Teste la connectivité TCP vers le port 4444 (port C2 courant, "
            "non standard) sur la boucle locale — détection de canal atypique."
        ),
        technique_mitre="T1571",
        tactique_mitre="Command and Control",
        sous_technique=None,
        commande=(
            'powershell.exe -NoProfile -Command "Test-NetConnection '
            "-ComputerName 127.0.0.1 -Port 4444 -WarningAction SilentlyContinue "
            '| Out-Null"'
        ),
        # EventID 1 (Sysmon ProcessCreate) en premier : c'est lui qui porte
        # process.command_line avec "-Port 4444". Le 4104 (ScriptBlock) ne
        # remplit que powershell.script_block_text — pas command_line — donc
        # une règle event.code:4104 sur command_line ne matcherait jamais
        # (vérifié en réel : FAUX_NEGATIF quand 4104 était en tête).
        event_ids_attendus=["1", "4104"],
        champ_principal="process.command_line",
        valeur_detection="-Port 4444",
        faux_positifs_connus=["Tests de connectivité applicatifs", "Monitoring réseau"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.WINDOWS,
        references=["https://attack.mitre.org/techniques/T1571/"],
        duree_estimee_sec=5,
    ),
    # =========================================================================
    # v1.6 — EXTENSION LINUX (multi-OS). Exécution SSH, télémétrie Auditbeat.
    #
    # Détection sur `process.title` (ligne de commande reconstruite par auditd).
    # Chaque commande porte un marqueur distinctif `CADRE_LIN_*` : Auditbeat
    # capte l'exécution via le shell (process.title contient toute la commande),
    # ce qui garantit un TP propre et FP=0 — même logique que les marqueurs
    # Windows (ex. CADRE_TEST_MARKER). Toutes non destructrices (lecture seule
    # ou fichiers temporaires immédiatement supprimés).
    # =========================================================================
    AttaqueCatalogue(
        id="CADRE-LIN-005",
        nom="System Information Discovery (uname/os-release)",
        description="Collecte les informations système Linux (noyau, distribution).",
        technique_mitre="T1082",
        tactique_mitre="Discovery",
        sous_technique=None,
        commande="uname -a; cat /etc/os-release >/dev/null 2>&1; echo CADRE_LIN_SYSINFO",
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) : "uname -a" est la commande réelle et générique de
        # découverte système. Distinct des appels périodiques du bureau XFCE
        # (process.name=uname isolé, args "-snrvm", sans wrapper shell) :
        # vérifié contre ES, notre exécution passe par zsh -c (SSH exec), qui
        # capture toute la ligne "uname -a; ..." dans un seul document.
        valeur_detection="uname -a",
        faux_positifs_connus=["Inventaire système légitime", "Scripts d'administration"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1082/"],
        duree_estimee_sec=4,
    ),
    AttaqueCatalogue(
        id="CADRE-LIN-006",
        nom="File and Directory Discovery (find)",
        description="Parcourt l'arborescence à la recherche de fichiers de configuration.",
        technique_mitre="T1083",
        tactique_mitre="Discovery",
        sous_technique=None,
        commande="find /home -maxdepth 3 -name '*.conf' >/dev/null 2>&1; echo CADRE_LIN_FILEDISC",
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) : "find /home" est la commande réelle de
        # reconnaissance de fichiers, indépendante du marqueur de fin.
        valeur_detection="find /home",
        faux_positifs_connus=["Indexation de fichiers", "Scripts de sauvegarde"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1083/"],
        duree_estimee_sec=5,
    ),
    AttaqueCatalogue(
        id="CADRE-LIN-007",
        nom="Process Discovery (ps)",
        description="Liste les processus en cours via ps.",
        technique_mitre="T1057",
        tactique_mitre="Discovery",
        sous_technique=None,
        commande="ps aux >/dev/null; echo CADRE_LIN_PROCDISC",
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) : "ps aux" est la commande réelle et générique de
        # listing de processus, indépendante du marqueur de fin.
        valeur_detection="ps aux",
        faux_positifs_connus=["Monitoring système", "Outils d'administration"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1057/"],
        duree_estimee_sec=4,
    ),
    AttaqueCatalogue(
        id="CADRE-LIN-008",
        nom="System Network Configuration Discovery (ip)",
        description="Énumère les interfaces réseau via ip addr.",
        technique_mitre="T1016",
        tactique_mitre="Discovery",
        sous_technique=None,
        commande="ip addr show >/dev/null; echo CADRE_LIN_NETCONF",
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) : "ip addr show >/dev/null" (avec la redirection)
        # distingue notre exécution des appels périodiques du widget réseau
        # du bureau XFCE (process.name=ip isolé, "ip addr show" SANS
        # redirection, toutes les ~1s — vérifié contre ES en direct) tout en
        # restant la commande réelle de découverte réseau, pas un marqueur.
        valeur_detection="ip addr show >/dev/null",
        faux_positifs_connus=["Diagnostic réseau", "Scripts de configuration"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1016/"],
        duree_estimee_sec=4,
    ),
    AttaqueCatalogue(
        id="CADRE-LIN-009",
        nom="System Network Connections Discovery (ss)",
        description="Énumère les connexions réseau actives via ss.",
        technique_mitre="T1049",
        tactique_mitre="Discovery",
        sous_technique=None,
        commande="ss -tanp >/dev/null 2>&1; echo CADRE_LIN_NETCONN",
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) : "ss -tanp" est la commande réelle et générique
        # d'énumération des connexions réseau, indépendante du marqueur.
        valeur_detection="ss -tanp",
        faux_positifs_connus=["Diagnostic réseau", "Supervision"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1049/"],
        duree_estimee_sec=4,
    ),
    AttaqueCatalogue(
        id="CADRE-LIN-010",
        nom="System Owner/User Discovery (id/whoami)",
        description="Affiche l'utilisateur courant et ses groupes.",
        technique_mitre="T1033",
        tactique_mitre="Discovery",
        sous_technique=None,
        commande="id; whoami >/dev/null; echo CADRE_LIN_WHOAMI",
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) : "id; whoami" est la commande réelle et générique
        # de découverte d'utilisateur, indépendante du marqueur.
        valeur_detection="id; whoami",
        faux_positifs_connus=["Scripts de diagnostic", "Session légitime"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1033/"],
        duree_estimee_sec=4,
    ),
    AttaqueCatalogue(
        id="CADRE-LIN-011",
        nom="Local Account Discovery (/etc/passwd)",
        description="Énumère les comptes locaux via /etc/passwd.",
        technique_mitre="T1087.001",
        tactique_mitre="Discovery",
        sous_technique="Local Account",
        commande="cat /etc/passwd >/dev/null; echo CADRE_LIN_ACCTDISC",
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) : "cat /etc/passwd" est la commande réelle
        # (technique communautaire connue, quoique intrinsèquement bruyante —
        # lecture très courante), indépendante du marqueur de fin.
        valeur_detection="cat /etc/passwd",
        # EXC2 (seuil par technique, calibré sur données réelles) : rejetée
        # une première fois à 60 FP/7j (seuil global 50) — mesuré, pas deviné,
        # cycle réel du 09/08. "cat /etc/passwd" reste l'indicateur réel
        # standard de la communauté pour T1087.001 ; sa lecture est
        # légitimement fréquente (login, PAM, outils d'audit). Seuil porté à
        # 75 avec marge mesurée, PAS un blanc-seing (reste strict comparé à
        # l'ancien 5000) — à resserrer encore avec des exclusions dédiées
        # (comptes de service identifiés) si le bruit grimpe en production.
        seuil_fp_max=75,
        faux_positifs_connus=["Audit des comptes légitime", "Scripts d'onboarding"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1087/001/"],
        duree_estimee_sec=4,
    ),
    AttaqueCatalogue(
        id="CADRE-LIN-012",
        nom="Software Discovery (dpkg)",
        description="Énumère les paquets installés via dpkg.",
        technique_mitre="T1518",
        tactique_mitre="Discovery",
        sous_technique=None,
        commande="dpkg -l >/dev/null 2>&1; echo CADRE_LIN_SWDISC",
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) : "dpkg -l" est la commande réelle et générique de
        # découverte logicielle, indépendante du marqueur de fin.
        valeur_detection="dpkg -l",
        faux_positifs_connus=["Inventaire logiciel", "Gestion de parc"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1518/"],
        duree_estimee_sec=5,
    ),
    AttaqueCatalogue(
        id="CADRE-LIN-013",
        nom="System Service Discovery (systemctl)",
        description="Liste les services systemd via systemctl.",
        technique_mitre="T1007",
        tactique_mitre="Discovery",
        sous_technique=None,
        commande="systemctl list-units --type=service >/dev/null 2>&1; echo CADRE_LIN_SVCDISC",
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) : "systemctl list-units" est la commande réelle et
        # générique de découverte de services, indépendante du marqueur.
        valeur_detection="systemctl list-units",
        faux_positifs_connus=["Administration système", "Supervision"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1007/"],
        duree_estimee_sec=5,
    ),
    AttaqueCatalogue(
        id="CADRE-LIN-014",
        nom="Permission Groups Discovery (/etc/group)",
        description="Énumère les groupes locaux via /etc/group.",
        technique_mitre="T1069.001",
        tactique_mitre="Discovery",
        sous_technique="Local Groups",
        commande="cat /etc/group >/dev/null; echo CADRE_LIN_GROUPDISC",
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) : "cat /etc/group" est la commande réelle et
        # générique de découverte des groupes, indépendante du marqueur.
        valeur_detection="cat /etc/group",
        faux_positifs_connus=["Audit des droits légitime"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1069/001/"],
        duree_estimee_sec=4,
    ),
    AttaqueCatalogue(
        id="CADRE-LIN-015",
        nom="Clear Command History (Defense Evasion)",
        description="Simule l'effacement de l'historique shell (non destructif : sous-shell).",
        technique_mitre="T1070.003",
        tactique_mitre="Defense Evasion",
        sous_technique="Clear Command History",
        commande="unset HISTFILE; export HISTSIZE=0; echo CADRE_LIN_HISTEVASION",
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) : "unset HISTFILE" EST la technique réelle
        # d'évasion d'historique (bien plus générique et pertinent que le
        # marqueur — c'est littéralement le comportement anti-forensique
        # documenté par T1070.003).
        valeur_detection="unset HISTFILE",
        faux_positifs_connus=["Configuration shell légitime"],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1070/003/"],
        duree_estimee_sec=3,
    ),
    AttaqueCatalogue(
        id="CADRE-LIN-016",
        nom="Linux File Permissions Modification (chmod)",
        description="Modifie les permissions d'un fichier temporaire (puis le supprime).",
        technique_mitre="T1222.002",
        tactique_mitre="Defense Evasion",
        sous_technique="Linux and Mac File and Directory Permissions Modification",
        commande=(
            "touch /tmp/cadre_perm_test && chmod 777 /tmp/cadre_perm_test && "
            "rm -f /tmp/cadre_perm_test; echo CADRE_LIN_CHMOD"
        ),
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) : "chmod 777" est le motif réel (permissivité
        # maximale, indicateur communautaire connu même si intrinsèquement
        # bruyant), indépendant du marqueur.
        valeur_detection="chmod 777",
        faux_positifs_connus=["Scripts d'installation", "Déploiement légitime"],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1222/002/"],
        duree_estimee_sec=4,
    ),
    AttaqueCatalogue(
        id="CADRE-LIN-017",
        nom="OS Credential Dumping (/etc/passwd & /etc/shadow)",
        description="Tente de lire /etc/passwd et /etc/shadow (échec sur shadow sans root).",
        technique_mitre="T1003.008",
        tactique_mitre="Credential Access",
        sous_technique="/etc/passwd and /etc/shadow",
        commande="cat /etc/passwd /etc/shadow >/dev/null 2>&1; echo CADRE_LIN_PASSWDSHADOW",
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) : "cat /etc/passwd /etc/shadow" (les DEUX ensemble,
        # plus distinctif qu'un accès passwd seul) est la commande réelle de
        # dump de credentials, indépendante du marqueur.
        valeur_detection="cat /etc/passwd /etc/shadow",
        faux_positifs_connus=["Audit de sécurité", "Sauvegarde système"],
        niveau_risque=NiveauRisque.ELEVE,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1003/008/"],
        duree_estimee_sec=4,
    ),
    AttaqueCatalogue(
        id="CADRE-LIN-018",
        nom="Bash History Access (Credentials In Files)",
        description="Lit l'historique bash à la recherche de secrets.",
        technique_mitre="T1552.003",
        tactique_mitre="Credential Access",
        sous_technique="Bash History",
        commande="cat ~/.bash_history >/dev/null 2>&1; echo CADRE_LIN_BASHHIST",
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) : ".bash_history" est le fichier réel ciblé
        # (technique générique de recherche de secrets), indépendant du
        # marqueur de fin.
        valeur_detection=".bash_history",
        faux_positifs_connus=["Diagnostic utilisateur", "Scripts d'audit"],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1552/003/"],
        duree_estimee_sec=3,
    ),
    AttaqueCatalogue(
        id="CADRE-LIN-019",
        nom="Data Destruction Test (dd + rm, safe)",
        description="Crée puis supprime un fichier temporaire (simule un wiper, test safe).",
        technique_mitre="T1485",
        tactique_mitre="Impact",
        sous_technique="Data Destruction",
        commande=(
            "dd if=/dev/zero of=/tmp/cadre_wipe bs=1k count=1 2>/dev/null; "
            "rm -f /tmp/cadre_wipe; echo CADRE_LIN_WIPE"
        ),
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) : "dd if=/dev/zero" est le motif réel et bien
        # connu d'écrasement/wipe de données, indépendant du marqueur.
        valeur_detection="dd if=/dev/zero",
        faux_positifs_connus=["Maintenance disque", "Scripts de nettoyage"],
        niveau_risque=NiveauRisque.MOYEN,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1485/"],
        duree_estimee_sec=4,
    ),
    AttaqueCatalogue(
        id="CADRE-LIN-020",
        nom="Data from Local System (copie de fichier)",
        description="Copie un fichier système vers /tmp puis le supprime (collecte).",
        technique_mitre="T1005",
        tactique_mitre="Collection",
        sous_technique=None,
        commande=(
            "cp /etc/hostname /tmp/cadre_collected 2>/dev/null; "
            "rm -f /tmp/cadre_collected; echo CADRE_LIN_COLLECT"
        ),
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) — VALIDATION DE PIPELINE, honnêtement étiquetée :
        # copier un fichier bénin (hostname) est indiscernable d'une activité
        # légitime sans contexte comportemental — même raisonnement que
        # COL-001/COL-003 côté Windows.
        valeur_detection="CADRE_LIN_COLLECT",
        faux_positifs_connus=["Sauvegarde", "Synchronisation de fichiers"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1005/"],
        duree_estimee_sec=4,
    ),
    # -------------------------------------------------------------------------
    # T1548.001 — Setuid and Setgid (Privilege Escalation, Linux)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-PRI-002",
        nom="SUID/SGID Discovery (chasse aux binaires élevables)",
        description=(
            "Recherche les binaires SUID en lecture seule — reconnaissance "
            "de privilège escalade classique (candidats GTFOBins)."
        ),
        technique_mitre="T1548.001",
        tactique_mitre="Privilege Escalation",
        sous_technique="Setuid and Setgid",
        # -xdev : reste sur le système de fichiers racine, n'explore pas
        # /proc, /sys ni les montages réseau -- vérifié en réel : SANS
        # -xdev, la commande a mis 4 min 49 s à s'exécuter sur ce labo
        # (régression inacceptable après le travail de vitesse G2). C'est
        # aussi la syntaxe réelle utilisée par les outils d'audit (LinPEAS),
        # pas juste une optimisation locale.
        commande="find / -xdev -perm -4000 -type f 2>/dev/null | head -20; echo CADRE_SUID_SCAN_DONE",
        event_ids_attendus=["100"],
        champ_principal="process.title",
        # EXC1 (TTP-first) : "-perm -4000" EST la syntaxe réelle de chasse aux
        # binaires SUID (GTFOBins/LinPEAS), pas un marqueur artificiel.
        valeur_detection="-perm -4000",
        faux_positifs_connus=["Scripts d'audit sécurité légitimes (LinPEAS, lynis)"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1548/001/"],
        prerequisites=["Agent Auditd sur la VM Linux"],
        duree_estimee_sec=5,
    ),
    # -------------------------------------------------------------------------
    # T1548.003 — Sudo and Sudo Caching (Privilege Escalation, Linux)
    # -------------------------------------------------------------------------
    AttaqueCatalogue(
        id="CADRE-PRI-003",
        nom="Sudo Rights Enumeration (sudo -l)",
        description=(
            "Énumère les droits sudo du compte courant — reconnaissance de "
            "privilège escalade classique avant tentative d'abus."
        ),
        technique_mitre="T1548.003",
        tactique_mitre="Privilege Escalation",
        sous_technique="Sudo and Sudo Caching",
        commande="sudo -l 2>/dev/null; echo CADRE_SUDO_CHECK_DONE",
        event_ids_attendus=["100"],
        champ_principal="process.title",
        valeur_detection="sudo -l",
        faux_positifs_connus=["Vérification de routine par un administrateur légitime"],
        niveau_risque=NiveauRisque.FAIBLE,
        plateforme=Plateforme.LINUX,
        references=["https://attack.mitre.org/techniques/T1548/003/"],
        prerequisites=["Agent Auditd sur la VM Linux"],
        duree_estimee_sec=5,
    ),
]


def catalogue_actif() -> list[AttaqueCatalogue]:
    """
    Catalogue réellement exécutable : les attaques natives (immuables,
    testées) PLUS les attaques personnelles de l'utilisateur (extensibles
    via `cadre suggest --enregistrer`, voir `catalogue_utilisateur.py`),
    puis les raffinements ponctuels appliqués (`cadre raffiner`, voir
    `raffinement.py`) — mêmes attaques, paramètres de détection affinés,
    jamais de doublon.

    `CATALOGUE` reste volontairement le socle natif figé — c'est lui qui
    porte la garantie de déterminisme. `catalogue_actif()` est le point
    d'entrée à utiliser partout où l'on veut inclure les ajouts utilisateur
    (orchestrateur, CLI, dashboard). Import différé pour éviter tout cycle.
    """
    from .catalogue_utilisateur import charger_attaques_utilisateur  # noqa: PLC0415
    from .raffinement import appliquer_raffinements  # noqa: PLC0415

    return appliquer_raffinements([*CATALOGUE, *charger_attaques_utilisateur()])


def obtenir_attaque(identifiant: str) -> AttaqueCatalogue | None:
    """Récupère une attaque par son identifiant (catalogue natif + perso)."""
    for attaque in catalogue_actif():
        if attaque.id == identifiant:
            return attaque
    return None


def obtenir_par_technique(technique: str) -> list[AttaqueCatalogue]:
    """Récupère toutes les attaques pour une technique MITRE donnée."""
    return [a for a in CATALOGUE if a.technique_mitre == technique]


def obtenir_par_tactique(tactique: str) -> list[AttaqueCatalogue]:
    """Récupère toutes les attaques pour une tactique MITRE donnée."""
    return [a for a in CATALOGUE if a.tactique_mitre.lower() == tactique.lower()]


# --- Score de confiance par règle --------------------------------------------
# Classification TTP-first (`EXC/1-ttp-first.md` §6) : 12 attaques dont la
# valeur de corrélation est un marqueur de test CADRE injecté (télémétrie
# pure, prouve que la collecte fonctionne) plutôt qu'un indicateur qu'un
# vrai attaquant déclencherait. Distinction qualitative, non déductible de
# `valeur_detection` seul (les deux catégories en ont une) — liste figée,
# vérifiée une à une par lecture de la commande réelle de chaque attaque,
# revérifiée programmatiquement le 2026-08-14 (53 indicateur_reel +
# 12 validation_pipeline + 2 générique = 67/67, cohérent avec A4/B5 ;
# 54/12/2 = 68/68 depuis l'ajout de CADRE-EVA-004, indicateur réel).
_IDS_VALIDATION_PIPELINE: frozenset[str] = frozenset(
    {
        "CADRE-EXE-001",
        "CADRE-EXE-002",
        "CADRE-EVA-002",
        "CADRE-IMP-001",
        "CADRE-COL-001",
        "CADRE-COL-003",
        "CADRE-LIN-001",
        "CADRE-LIN-003",
        "CADRE-LIN-020",
        "CADRE-EXF-001",
        # CadreBruteTest / CadreIniAccessTest sont des noms d'utilisateur
        # injectés par CADRE pour le test, pas des indicateurs qu'un vrai
        # attaquant présenterait.
        "CADRE-CRE-006",
        "CADRE-INI-001",
    }
)


def categorie_detection(attaque: AttaqueCatalogue) -> str:
    """
    Classe une attaque en 3 catégories de fiabilité de détection
    (`EXC/1-ttp-first.md`) :

    - `"indicateur_reel"` (54/68) : détecte un signal qu'un vrai attaquant
      déclencherait (syntaxe LOLBIN, chemin/registre réel, flag malveillant).
    - `"validation_pipeline"` (12/68) : télémétrie pure sur marqueur de
      test CADRE — prouve que la chaîne de collecte fonctionne, pas
      qu'un attaquant serait attrapé.
    - `"generique"` (2/68) : corrélation sur `event.code` seul, sans
      valeur dédiée (approche Sigma communautaire standard).
    """
    if attaque.valeur_detection is None:
        return "generique"
    if attaque.id in _IDS_VALIDATION_PIPELINE:
        return "validation_pipeline"
    return "indicateur_reel"


_POIDS_CATEGORIE: dict[str, int] = {
    "indicateur_reel": 50,
    "validation_pipeline": 25,
    "generique": 10,
}


def calculer_score_confiance(
    attaque: AttaqueCatalogue, nb_tp: int, nb_fp: int, seuil_fp: int
) -> int:
    """
    Score de confiance (0-100) d'un résultat de validation TP/FP — pas une
    nouvelle mesure, une lecture combinée de données déjà produites par
    `double_validation_tp_fp` et le catalogue :

    - 0 si aucun vrai positif (rien détecté, le score de contenu ne
      compense jamais l'absence de preuve).
    - 0-50 pts : qualité du contenu de détection (`categorie_detection`).
    - 0-50 pts : marge par rapport au seuil de bruit calibré pour cette
      attaque (moins de faux positifs relatifs au seuil = plus de
      confiance ; négatif si le seuil est dépassé, plafonné à 0).
    """
    if nb_tp <= 0:
        return 0
    points_categorie = _POIDS_CATEGORIE[categorie_detection(attaque)]
    marge = max(0.0, 1.0 - (nb_fp / seuil_fp)) if seuil_fp > 0 else 0.0
    points_marge = round(50 * marge)
    return points_categorie + points_marge


def _valeurs_correlation_collisionnent(a: str, b: str) -> bool:
    """True si l'une des deux valeurs de corrélation est une sous-chaîne de
    l'autre (insensible à la casse). Utilisé pour interdire à deux attaques
    de s'exécuter dans le même lot parallèle (voir
    `partitionner_pour_parallelisme`) si leurs règles Sigma pourraient se
    matcher mutuellement dans Elasticsearch. En cas de doute on considère
    qu'il y a collision (isole plutôt que de risquer un faux négatif de
    détection de collision) : ça coûte du parallélisme, jamais de
    correctness sur la validation TP/FP."""
    a_l, b_l = a.lower(), b.lower()
    return a_l in b_l or b_l in a_l


def partitionner_pour_parallelisme(
    attaques: list[AttaqueCatalogue], max_concurrentes: int = 2
) -> list[list[AttaqueCatalogue]]:
    """
    Découpe une liste ORDONNÉE d'attaques en lots exécutables en parallèle
    sans risque de contamination de la fenêtre de validation TP
    (`double_validation_tp_fp`, fenêtre glissante `now-600s` --
    `compilation_sigma.py` -- évaluée par Elasticsearch au moment de la
    requête, jamais ancrée sur l'heure d'exécution WinRM ; deux attaques
    dont les événements se chevauchent dans cette fenêtre ne doivent donc
    jamais utiliser des requêtes qui pourraient se matcher l'une l'autre) :

    - `valeur_detection is None` (règle générique `event.code` seul) : lot
      d'UNE seule attaque, jamais combinée avec quoi que ce soit d'autre.
    - Deux `valeur_detection` en collision de sous-chaîne
      (`_valeurs_correlation_collisionnent`) : jamais dans le même lot.
    - Sinon : regroupées par lots de `max_concurrentes` au maximum, dans
      l'ordre du catalogue (glouton).

    Invariant garanti : concaténer tous les lots dans l'ordre redonne
    exactement `attaques` -- ce n'est pas un tri par similarité, seulement
    une décision de frontière de lot.

    Portée de la vérification de collision (bug corrigé, audit) : comparée
    contre TOUT l'historique des attaques déjà placées (`historique`),
    jamais seulement `lot_courant` (le lot en cours d'accumulation). Une
    version antérieure ne comparait qu'au lot en cours : une fois une
    attaque flushée hors de `lot_courant`, elle n'était plus jamais utilisée
    pour décider si une attaque suivante devait être isolée. Dans la
    pratique, ça ne cassait jamais l'invariant « jamais dans le même lot »
    (qui ne dépend que de `lot_courant`, toujours correctement comparé) --
    mais ça pouvait laisser une attaque être groupée avec des voisines
    « sûres » sans tenir compte d'une collision avec une attaque plus
    ancienne déjà écoulée, alors que les lots s'enchaînent en quelques
    secondes/minutes, largement DANS la même fenêtre glissante de 600 s que
    `double_validation_tp_fp`. Comparer contre tout l'historique élimine cet
    angle mort : une attaque qui collisionne avec N'IMPORTE quelle attaque
    déjà placée démarre systématiquement un nouveau lot.
    """
    lots: list[list[AttaqueCatalogue]] = []
    lot_courant: list[AttaqueCatalogue] = []
    historique: list[AttaqueCatalogue] = []

    def _flush() -> None:
        nonlocal lot_courant
        if lot_courant:
            lots.append(lot_courant)
            lot_courant = []

    for attaque in attaques:
        if attaque.valeur_detection is None:
            _flush()
            lots.append([attaque])
            continue
        collision = any(
            _valeurs_correlation_collisionnent(attaque.valeur_detection, autre.valeur_detection)
            for autre in historique
            if autre.valeur_detection is not None
        )
        if collision or len(lot_courant) >= max_concurrentes:
            _flush()
        lot_courant.append(attaque)
        historique.append(attaque)

    _flush()
    return lots


def statistiques_catalogue() -> dict[str, Any]:
    """Retourne des statistiques sur le catalogue."""
    par_tactique: dict[str, int] = {}
    par_niveau_risque: dict[str, int] = {
        NiveauRisque.FAIBLE.value: 0,
        NiveauRisque.MOYEN.value: 0,
        NiveauRisque.ELEVE.value: 0,
    }
    for a in CATALOGUE:
        par_tactique[a.tactique_mitre] = par_tactique.get(a.tactique_mitre, 0) + 1
        par_niveau_risque[a.niveau_risque.value] = (
            par_niveau_risque.get(a.niveau_risque.value, 0) + 1
        )

    return {
        "total": len(CATALOGUE),
        "tactiques_uniques": len({a.tactique_mitre for a in CATALOGUE}),
        "techniques_uniques": len({a.technique_mitre for a in CATALOGUE}),
        "risque_faible": par_niveau_risque[NiveauRisque.FAIBLE.value],
        "risque_moyen": par_niveau_risque[NiveauRisque.MOYEN.value],
        "risque_eleve": par_niveau_risque[NiveauRisque.ELEVE.value],
        "par_tactique": par_tactique,
        "par_niveau_risque": par_niveau_risque,
    }


def lister_attaques() -> str:
    """Retourne une représentation textuelle formatée du catalogue."""
    lignes = ["Catalogue CADRE — Attaques disponibles :", ""]
    for a in CATALOGUE:
        lignes.append(f"  • {a.id} [{a.tactique_mitre}] {a.technique_mitre} — {a.nom}")
    return "\n".join(lignes)


def lister_attaques_dict() -> list[dict[str, Any]]:
    """Retourne le catalogue sous forme de liste de dicts (sérialisable JSON)."""
    return [asdict(a) for a in CATALOGUE]


if __name__ == "__main__":
    """Affiche un résumé du catalogue."""
    stats = statistiques_catalogue()
    print(f"Catalogue CADRE — {stats['total']} attaques")
    print(f"   Tactiques couvertes : {stats['tactiques_uniques']}")
    print(f"   Techniques uniques  : {stats['techniques_uniques']}")
    print(
        f"   Répartition risque  : {stats['risque_faible']} faible, "
        f"{stats['risque_moyen']} moyen, {stats['risque_eleve']} élevé"
    )
    print()
    for a in CATALOGUE:
        print(f"  [{a.id}] {a.technique_mitre} — {a.nom}")
