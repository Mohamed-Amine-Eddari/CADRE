"""Éteint proprement la VM Windows cible, via VBoxManage guestcontrol.

Utilisé en repli par scripts/arreter-environnement.ps1 quand le signal ACPI
(`acpipowerbutton`) n'a pas suffi dans le délai imparti — le bouton
d'alimentation émulé dépend d'une configuration du système d'exploitation
invité (action associée au bouton d'alimentation dans ses paramètres
d'énergie) qui n'est pas garantie sur toute VM, et un invité chargé peut
mettre du temps à la traiter (observé en réel : 2 min de délai dépassées
juste après un cycle complet de 71 attaques). `Stop-Computer -Force` lancé
DEPUIS l'intérieur de l'invité, lui, déclenche la séquence d'arrêt Windows
normale sans dépendre de cette configuration — même canal hors bande
(Guest Additions) et même mécanisme `-EncodedCommand` que
`reparer-winrm.py`. PowerShell plutôt que `shutdown.exe` en ligne de
commande directe : passer plusieurs arguments (`/s /t 0 /f`) après `--` à
`guestcontrol run` s'est avéré peu fiable en pratique (`shutdown.exe` a
reçu ses arguments mal formés et a affiché son aide au lieu de s'exécuter,
constaté en test réel) -- une seule commande encodée en base64 élimine
tout risque de découpage/quoting incorrect des arguments.

Identifiants VM chargés depuis le coffre-fort (jamais en dur ici), mot de
passe transmis par fichier temporaire (jamais en argv), supprimé
systématiquement.

Sortie : code de retour 0 si l'ordre d'arrêt a été transmis avec succès à
l'invité, 1 sinon. Ne garantit pas que l'extinction se termine (l'appelant
doit re-vérifier `VMState` après un court délai).
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

_POWERSHELL_VM = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
_COMMANDE_ARRET = "Stop-Computer -Force"


def arreter_vm_proprement() -> bool:
    """Déclenche un arrêt Windows normal (`Stop-Computer -Force`) à
    l'intérieur de la VM cible. Retourne True si guestcontrol a pu lancer
    la commande."""
    orchestrateur = OrchestrateurCADRE()
    vm_nom = orchestrateur.config.get("vm_vbox_nom") or "CADRE"
    vboxmanage = orchestrateur._resoudre_chemin_vboxmanage()
    if not vboxmanage:
        print("VBoxManage introuvable — arrêt propre impossible.")
        return False
    vm_user = orchestrateur.config.get("vm_user")
    vm_pass = orchestrateur.config.get("vm_pass")
    if not (vm_user and vm_pass):
        print(
            "Identifiants VM manquants (CADRE_VM_USER / CADRE_VM_PASS) — arrêt propre impossible."
        )
        return False

    # Mot de passe via fichier temporaire (jamais en argv). newline="" pour ne
    # pas corrompre un mot de passe contenant un saut de ligne sous Windows.
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".tmp", delete=False, newline="", encoding="utf-8"
    ) as fichier:
        fichier.write(vm_pass)
        chemin_pass = fichier.name
    commande_b64 = base64.b64encode(_COMMANDE_ARRET.encode("utf-16-le")).decode()
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
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print("Arrêt propre : délai dépassé (30 s) — VM peut-être trop chargée.")
        return False
    except OSError as exc:
        print(f"Arrêt propre : échec du lancement de VBoxManage ({type(exc).__name__}).")
        return False
    finally:
        with contextlib.suppress(OSError):
            Path(chemin_pass).unlink()

    if resultat.returncode != 0:
        print(f"Arrêt propre : guestcontrol a échoué (code {resultat.returncode}).")
        detail = (resultat.stderr or "").strip()
        if detail:
            print(detail)
        return False
    print(
        "Ordre d'arrêt Windows envoyé (Stop-Computer -Force) — extinction dans quelques secondes."
    )
    return True


if __name__ == "__main__":
    sys.exit(0 if arreter_vm_proprement() else 1)
