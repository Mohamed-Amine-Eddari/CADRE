# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Resynchronisation des agents de télémétrie après rotation de secret
============================================================================

Problème résolu : `CADRE_ELASTIC_PASS` (coffre-fort CADRE) et le mot de passe
utilisé par Winlogbeat (VM Windows) / Auditbeat (VM Linux) pour s'authentifier
auprès d'Elasticsearch sont DEUX choses distinctes. Winlogbeat/Auditbeat lisent
leur propre fichier de configuration (`winlogbeat.yml` / `auditbeat.yml`), où
le mot de passe est écrit une fois lors de l'installation initiale (voir
docs/INSTALL.md) et n'est JAMAIS relu depuis le coffre-fort CADRE.

Conséquence observée en réel : après une rotation de `CADRE_ELASTIC_PASS`
(`cadre init --set CADRE_ELASTIC_PASS=...` ou reset direct côté Elasticsearch),
les deux agents continuent à utiliser l'ANCIEN mot de passe, échouent
silencieusement à s'authentifier, et la télémétrie s'arrête — sans qu'aucune
erreur ne remonte côté CADRE (le cycle continue de tourner, mais plus aucune
attaque n'est détectée). C'est un mode de défaillance déjà rencontré et
documenté (voir Annexe D du rapport, section 5.6 « Limites assumées »).

Ce module pousse le NOUVEAU mot de passe vers les deux agents et les
redémarre. Le mot de passe ne transite JAMAIS comme argument de ligne de
commande shell (risque d'injection si la valeur contient des caractères
spéciaux) : il est écrit dans un fichier temporaire à permissions
restrictives sur chaque VM cible, lu directement par un script qui fait la
substitution, puis effacé.

Usage : `cadre secrets-sync-beats` (voir cli.py).
"""

from __future__ import annotations

import base64
import re
import uuid
from typing import TYPE_CHECKING

from .logger import obtenir_logger

if TYPE_CHECKING:
    from .orchestrateur import OrchestrateurCADRE

try:
    import winrm

    WINRM_DISPONIBLE = True
except ImportError:
    WINRM_DISPONIBLE = False

try:
    import paramiko

    PARAMIKO_DISPONIBLE = True
except ImportError:
    PARAMIKO_DISPONIBLE = False


CHEMIN_WINLOGBEAT_YML = r"C:\Program Files\Winlogbeat\winlogbeat.yml"
CHEMIN_AUDITBEAT_YML = "/etc/auditbeat/auditbeat.yml"

# Motif partagé (en substance) par le script PowerShell distant (Windows) et
# le script Python distant (Linux) : une ligne commençant par "password:",
# espaces optionnels, jusqu'à la fin de la ligne -- reconnaît aussi bien une
# valeur quotée (format documenté dans docs/INSTALL.md) qu'une valeur non
# quotée. Gardé ici, testé par `_remplacer_mot_de_passe_yaml`, plutôt que
# seulement dans les chaînes de script distantes : c'est la logique la plus
# sensible du module (un motif qui ne matche rien produirait un faux succès
# -- service relancé, mais toujours avec l'ANCIEN mot de passe).
MOTIF_LIGNE_PASSWORD = re.compile(r"password:.*")


def _remplacer_mot_de_passe_yaml(contenu: str, nouveau_mdp: str) -> tuple[str, int]:
    """Remplace la (les) ligne(s) `password: ...` de `contenu` par
    `password: "<nouveau_mdp>"`. Retourne (nouveau_contenu, nb_remplacements)
    -- un appelant DOIT traiter `nb_remplacements == 0` comme un échec
    (aucune ligne trouvée = fichier de config dans un format inattendu),
    jamais comme un succès silencieux.

    Logique testée directement ici ; les scripts PowerShell/Python distants
    (`_script_powershell_rotation`, `synchroniser_auditbeat`) appliquent le
    même motif -- toute évolution de cette fonction doit être répercutée
    dans les deux scripts distants."""
    valeur_echappee = nouveau_mdp.replace('"', '\\"')
    return MOTIF_LIGNE_PASSWORD.subn(f'password: "{valeur_echappee}"', contenu)


class ResultatSynchronisation:
    """Résultat d'une tentative de resynchronisation pour UNE cible."""

    def __init__(self, cible: str):
        self.cible = cible
        self.ok = False
        self.detail = ""

    def __repr__(self) -> str:
        etat = "OK" if self.ok else "ÉCHEC"
        return f"[{etat}] {self.cible} : {self.detail}"


def _script_powershell_rotation(chemin_temp: str, chemin_yml: str) -> str:
    """Script PowerShell exécuté sur la VM Windows. Le mot de passe n'apparaît
    dans AUCUN argument de ce script -- il est lu directement depuis le
    fichier temporaire déposé au préalable par SFTP-like (ici : WinRM lui
    encode le contenu, voir `synchroniser_winlogbeat`), jamais interpolé dans
    une commande shell."""
    return f"""
$ErrorActionPreference = 'Stop'
$cheminTemp = '{chemin_temp}'
$cheminYml  = '{chemin_yml}'
try {{
    $nouveau = (Get-Content -Raw -Path $cheminTemp).TrimEnd("`r", "`n")
    $contenu = Get-Content -Path $cheminYml
    # Motif identique (en substance) à MOTIF_LIGNE_PASSWORD côté Python --
    # voir _remplacer_mot_de_passe_yaml pour la justification et les tests.
    $motif = 'password:.*'
    $nbLignesTouchees = ($contenu | Select-String -Pattern $motif).Count
    if ($nbLignesTouchees -eq 0) {{
        Remove-Item -Path $cheminTemp -Force -ErrorAction SilentlyContinue
        Write-Output "CADRE_RESULTAT:ERREUR:aucune ligne 'password:' trouvee dans $cheminYml"
        exit
    }}
    Stop-Service winlogbeat -Force -ErrorAction SilentlyContinue
    $contenu = $contenu -replace $motif, ('password: "' + $nouveau + '"')
    Set-Content -Path $cheminYml -Value $contenu
    Remove-Item -Path $cheminTemp -Force -ErrorAction SilentlyContinue
    Start-Service winlogbeat
    Start-Sleep -Seconds 3
    $etat = (Get-Service winlogbeat).Status
    Write-Output "CADRE_RESULTAT:$etat"
}} catch {{
    Remove-Item -Path $cheminTemp -Force -ErrorAction SilentlyContinue
    Write-Output "CADRE_RESULTAT:ERREUR:$($_.Exception.Message)"
}}
"""


def synchroniser_winlogbeat(
    orchestrateur: OrchestrateurCADRE, nouveau_mdp: str, timeout_sec: int = 30
) -> ResultatSynchronisation:
    """Pousse `nouveau_mdp` dans winlogbeat.yml (VM Windows) et redémarre le
    service. Le mot de passe voyage dans le CORPS du script PowerShell
    encodé en Base64/UTF-16LE (mécanisme `-EncodedCommand` déjà utilisé par
    `executer_commande_winrm`), jamais comme argument de commande séparé."""
    resultat = ResultatSynchronisation("Winlogbeat (VM Windows)")
    if not WINRM_DISPONIBLE:
        resultat.detail = "Module 'pywinrm' non installé."
        return resultat

    cfg = orchestrateur.config
    if not cfg.get("vm_ip") or not cfg.get("vm_user") or not cfg.get("vm_pass"):
        resultat.detail = "VM Windows non configurée (CADRE_VM_IP/USER/PASS)."
        return resultat

    chemin_temp = f"C:\\Windows\\Temp\\cadre_rotate_{uuid.uuid4().hex}.txt"
    log = obtenir_logger()
    try:
        endpoint = f"{cfg['vm_winrm_scheme']}://{cfg['vm_ip']}:{cfg['vm_winrm_port']}/wsman"
        session = winrm.Session(
            endpoint,
            auth=(cfg["vm_user"], cfg["vm_pass"]),
            transport=cfg["vm_winrm_transport"],
            server_cert_validation=cfg["vm_winrm_cert_validation"],
            read_timeout_sec=timeout_sec,
        )

        # 1. Dépose le nouveau mot de passe dans un fichier temporaire distant
        #    via Set-Content -- la VALEUR passe dans le corps du script encodé
        #    en base64/UTF-16LE, jamais comme argument shell nu.
        mdp_ps_litteral = nouveau_mdp.replace("'", "''")  # échappement PowerShell
        script_depot = f"Set-Content -Path '{chemin_temp}' -Value '{mdp_ps_litteral}' -NoNewline"
        session.run_ps(script_depot)

        # 2. Script de substitution + redémarrage : relit le fichier temporaire
        #    lui-même (jamais le mot de passe en argument), puis l'efface.
        script = _script_powershell_rotation(chemin_temp, CHEMIN_WINLOGBEAT_YML)
        reponse = session.run_ps(script)
        sortie = reponse.std_out.decode(errors="replace")

        if "CADRE_RESULTAT:Running" in sortie:
            resultat.ok = True
            resultat.detail = "winlogbeat redémarré, service actif (Running)."
        elif "CADRE_RESULTAT:ERREUR" in sortie:
            resultat.detail = sortie.split("CADRE_RESULTAT:ERREUR:", 1)[-1].strip()[:200]
        else:
            resultat.detail = f"État inattendu : {sortie.strip()[:200]}"
    except Exception as e:  # nosec B110 - diagnostic best-effort, jamais le mdp dans le message
        resultat.detail = f"{type(e).__name__} : connexion WinRM impossible."
    finally:
        log.evenement(
            "SECRET_ROTATION_BEAT",
            f"Resynchronisation winlogbeat : {'OK' if resultat.ok else 'ÉCHEC'}",
            "INFO" if resultat.ok else "WARN",
            cible="winlogbeat",
            ok=resultat.ok,
        )
    return resultat


def synchroniser_auditbeat(
    orchestrateur: OrchestrateurCADRE, nouveau_mdp: str, timeout_sec: int = 30
) -> ResultatSynchronisation:
    """Pousse `nouveau_mdp` dans auditbeat.yml (VM Linux) et redémarre le
    service. Le mot de passe est déposé par SFTP dans un fichier temporaire
    à permissions 600, puis lu DIRECTEMENT par le script Python distant
    (jamais interpolé dans une ligne de commande shell)."""
    resultat = ResultatSynchronisation("Auditbeat (VM Linux)")
    if not PARAMIKO_DISPONIBLE:
        resultat.detail = "Module 'paramiko' non installé."
        return resultat

    cfg = orchestrateur.config
    ip = cfg.get("linux_vm_ip")
    user = cfg.get("linux_vm_user")
    pwd = cfg.get("linux_vm_pass")
    port = int(cfg.get("linux_vm_port", 22))
    if not ip or not user or not pwd:
        resultat.detail = "VM Linux non configurée (CADRE_LINUX_VM_IP/USER/PASS)."
        return resultat

    chemin_temp = (
        f"/tmp/.cadre_rotate_{uuid.uuid4().hex}"  # nosec B108 - effacé juste après lecture
    )
    log = obtenir_logger()
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507 - labo isolé
        client.connect(
            ip,
            port=port,
            username=user,
            password=pwd,
            timeout=timeout_sec,
            banner_timeout=timeout_sec,
            auth_timeout=timeout_sec,
        )

        # 1. Dépose le nouveau mot de passe par SFTP (jamais sur la ligne de
        #    commande), permissions restrictives.
        sftp = client.open_sftp()
        with sftp.open(chemin_temp, "w") as f:
            f.write(nouveau_mdp)
        sftp.chmod(chemin_temp, 0o600)
        sftp.close()

        # 2. Script Python distant : lit le fichier temporaire DIRECTEMENT
        #    (open() dans le script, pas de variable shell interpolée), fait
        #    la substitution, redémarre le service, puis efface le fichier.
        script_python = f"""
import re, subprocess
chemin_temp = {chemin_temp!r}
chemin_yml = {CHEMIN_AUDITBEAT_YML!r}
try:
    with open(chemin_temp) as f:
        nouveau = f.read()
    with open(chemin_yml) as f:
        contenu = f.read()
    # Motif identique a MOTIF_LIGNE_PASSWORD cote Python local -- voir
    # _remplacer_mot_de_passe_yaml (cadre.synchronise_secrets) pour les tests.
    contenu, nb_remplacements = re.subn(
        r'password:.*', 'password: "' + nouveau.replace('"', '\\\\"') + '"', contenu
    )
    if nb_remplacements == 0:
        print(f"CADRE_RESULTAT:ERREUR:aucune ligne 'password:' trouvee dans {{chemin_yml}}")
        raise SystemExit(0)
    with open(chemin_yml, 'w') as f:
        f.write(contenu)
    subprocess.run(['systemctl', 'restart', 'auditbeat'], check=True, timeout=15)
    import time as t
    t.sleep(2)
    etat = subprocess.run(
        ['systemctl', 'is-active', 'auditbeat'], capture_output=True, text=True, timeout=10
    ).stdout.strip()
    print(f"CADRE_RESULTAT:{{etat}}")
except Exception as e:
    print(f"CADRE_RESULTAT:ERREUR:{{e}}")
finally:
    import os
    try:
        os.remove(chemin_temp)
    except OSError:
        pass
"""
        commande_b64 = base64.b64encode(script_python.encode("utf-8")).decode("ascii")
        commande_distante = f"echo {commande_b64} | base64 -d | sudo python3 -"
        _stdin, stdout, stderr = (
            client.exec_command(  # nosec B601 - script fixe, pas d'entrée utilisateur
                commande_distante, timeout=timeout_sec + 20
            )
        )
        stdout.channel.recv_exit_status()
        sortie = stdout.read().decode(errors="replace") + stderr.read().decode(errors="replace")

        if "CADRE_RESULTAT:active" in sortie:
            resultat.ok = True
            resultat.detail = "auditbeat redémarré, service actif."
        elif "CADRE_RESULTAT:ERREUR" in sortie:
            resultat.detail = sortie.split("CADRE_RESULTAT:ERREUR:", 1)[-1].strip()[:200]
        else:
            resultat.detail = f"État inattendu : {sortie.strip()[:200]}"
    except Exception as e:  # nosec B110 - diagnostic best-effort, jamais le mdp dans le message
        resultat.detail = f"{type(e).__name__} : connexion SSH impossible."
    finally:
        if client is not None:
            client.close()
        log.evenement(
            "SECRET_ROTATION_BEAT",
            f"Resynchronisation auditbeat : {'OK' if resultat.ok else 'ÉCHEC'}",
            "INFO" if resultat.ok else "WARN",
            cible="auditbeat",
            ok=resultat.ok,
        )
    return resultat


def synchroniser_secrets_beats(
    orchestrateur: OrchestrateurCADRE,
) -> list[ResultatSynchronisation]:
    """Point d'entrée : relit `CADRE_ELASTIC_PASS` depuis le coffre-fort
    (déjà chargé dans `orchestrateur.config['elastic_pass']`) et le pousse
    vers winlogbeat ET auditbeat. Ne fait RIEN côté Elasticsearch/Kibana
    lui-même -- suppose que le nouveau mot de passe est déjà actif côté
    serveur (ex. après `elasticsearch-reset-password` ou
    `cadre init --set CADRE_ELASTIC_PASS=...`)."""
    nouveau_mdp = orchestrateur.config.get("elastic_pass")
    if not nouveau_mdp:
        r = ResultatSynchronisation("Coffre-fort")
        r.detail = "CADRE_ELASTIC_PASS introuvable dans le coffre-fort."
        return [r]

    return [
        synchroniser_winlogbeat(orchestrateur, nouveau_mdp),
        synchroniser_auditbeat(orchestrateur, nouveau_mdp),
    ]
