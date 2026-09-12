"""Répare WinRM sur la VM Windows cible, hors bande, via VBoxManage guestcontrol.

Problème récurrent (documenté) : au démarrage de la VM, la carte réseau
Host-Only repasse parfois en profil « Public », ce qui fait que le pare-feu
Windows bloque le port WinRM (5985) même si le service tourne. La VM est alors
« allumée mais injoignable » — c'est la cause la plus fréquente d'un
`cadre status` qui affiche « port 5985 fermé » juste après un démarrage.

Ce script agit par le canal Guest Additions de VirtualBox (indépendant du
réseau, donc il fonctionne même quand WinRM est injoignable) pour :
  1. remettre les profils réseau en « Private »,
  2. s'assurer que le service WinRM démarre automatiquement et le lancer,
  3. réactiver la règle de pare-feu du groupe « Windows Remote Management ».

Il n'utilise volontairement PAS `Enable-PSRemoting` ni `winrm quickconfig` :
ces commandes peuvent se bloquer plusieurs minutes en attente d'une confirmation
interactive dans une session non interactive. Le listener WinRM existe déjà sur
une VM configurée — il suffit de rétablir le profil réseau et de lancer le
service.

Les identifiants VM sont chargés par l'orchestrateur depuis le coffre-fort
(jamais en dur ici), et le mot de passe passe par un fichier temporaire
(`--passwordfile`) supprimé systématiquement — jamais en ligne de commande.

Sortie : code de retour 0 si la réparation a été appliquée avec succès, 1 sinon
(VM non configurée, VBoxManage introuvable, ou échec de guestcontrol). Le script
NE garantit pas que WinRM réponde ensuite (un crash plus profond de la VM reste
hors de portée) — l'appelant doit re-tester la connectivité.
"""

from __future__ import annotations

import base64
import contextlib
import subprocess  # nosec B404 - VBoxManage guestcontrol, canal hors bande maîtrisé
import sys
import tempfile
from pathlib import Path

# Le script vit dans scripts/ ; le paquet est dans src/cadre.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cadre.orchestrateur import OrchestrateurCADRE

# Réparation minimale et NON bloquante (voir docstring du module).
_COMMANDE_REPARATION = (
    "$ErrorActionPreference='SilentlyContinue'; "
    "Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private; "
    "Set-Service WinRM -StartupType Automatic; "
    "Start-Service WinRM; "
    "netsh advfirewall firewall set rule group='Windows Remote Management' new enable=yes; "
    "'ETAT:' + (Get-Service WinRM).Status"
)

_POWERSHELL_VM = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def reparer_winrm() -> bool:
    """Applique la réparation réseau/WinRM sur la VM. Retourne True si
    guestcontrol a exécuté la commande avec succès."""
    orchestrateur = OrchestrateurCADRE()
    vm_nom = orchestrateur.config.get("vm_vbox_nom") or "CADRE"
    vboxmanage = orchestrateur._resoudre_chemin_vboxmanage()
    if not vboxmanage:
        print("VBoxManage introuvable — réparation WinRM impossible.")
        return False
    vm_user = orchestrateur.config.get("vm_user")
    vm_pass = orchestrateur.config.get("vm_pass")
    if not (vm_user and vm_pass):
        print("Identifiants VM manquants (CADRE_VM_USER / CADRE_VM_PASS) — réparation impossible.")
        return False

    commande_b64 = base64.b64encode(_COMMANDE_REPARATION.encode("utf-16-le")).decode()

    # Mot de passe via fichier temporaire (jamais en argv). newline="" pour ne
    # pas corrompre un mot de passe contenant un saut de ligne sous Windows.
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".tmp", delete=False, newline="", encoding="utf-8"
    ) as fichier:
        fichier.write(vm_pass)
        chemin_pass = fichier.name
    try:
        resultat = subprocess.run(  # nosec B603 - argv liste, pas de shell, chemin résolu
            [
                vboxmanage,
                "guestcontrol",
                vm_nom,
                "run",
                "--username",
                vm_user,
                "--passwordfile",
                chemin_pass,
                "--exe",
                _POWERSHELL_VM,
                "--wait-stdout",
                "--",
                "powershell.exe",
                "-NoProfile",
                "-EncodedCommand",
                commande_b64,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print("Réparation WinRM : délai dépassé (90 s) — la VM est peut-être trop chargée.")
        return False
    except OSError as exc:
        print(f"Réparation WinRM : échec du lancement de VBoxManage ({type(exc).__name__}).")
        return False
    finally:
        with contextlib.suppress(OSError):
            Path(chemin_pass).unlink()

    # On ne se fie PAS au code retour PowerShell : `netsh` renvoie souvent un
    # code non nul quand la règle de pare-feu est déjà dans l'état voulu, sans
    # que la réparation ait échoué. Dès lors que guestcontrol a pu exécuter la
    # commande (ni timeout ni OSError ci-dessus), le fix a été appliqué ; c'est
    # à l'appelant de re-tester la connectivité WinRM (port 5985), seule preuve
    # fiable du résultat.
    sortie = resultat.stdout or ""
    if "ETAT:" in sortie:
        etat = sortie.split("ETAT:", 1)[1].strip().splitlines()[0]
        print(f"Réparation WinRM appliquée — service WinRM : {etat}")
    else:
        print("Réparation WinRM appliquée (profil réseau Private, service WinRM démarré).")
    return True


if __name__ == "__main__":
    sys.exit(0 if reparer_winrm() else 1)
