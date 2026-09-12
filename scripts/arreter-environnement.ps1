<#
.SYNOPSIS
    Arrete PROPREMENT tout l'environnement CADRE : dashboard, VM cible(s),
    SIEM (Elasticsearch + Kibana) -- symetrique de demarrer-environnement.ps1.

.DESCRIPTION
    Un poweroff brutal de la VM Windows est la cause connue et documentee
    d'une regression reseau (la carte Host-Only repasse en profil "Public"
    au demarrage suivant, ce qui bloque WinRM -- voir scripts/reparer-
    winrm.py). Ce script demande donc un arret ACPI propre ("clic sur le
    bouton d'alimentation" simule, comme un vrai Windows/Linux qui ferme
    ses sessions puis s'eteint) et ATTEND que la VM s'eteigne d'elle-meme,
    au lieu d'un VBoxManage poweroff immediat qui coupe le courant sans
    prevenir l'OS invite.

    Le SIEM est arrete via "docker compose stop" (jamais "down -v", qui
    supprimerait le volume nomme elasticsearch-data et donc TOUT
    l'historique de detections/regles indexees) : les conteneurs restent
    definis, prets a redemarrer instantanement au prochain "docker compose
    up -d" de demarrer-environnement.ps1, sans perte de donnees.

.PARAMETER SansVM
    Ne pas toucher aux VM (utile si elles sont deja eteintes ou gerees
    ailleurs) -- n'arrete que le dashboard et le SIEM.

.PARAMETER Force
    Si une VM ne s'est pas eteinte proprement apres le delai d'attente
    (2 min par defaut), la coupe immediatement (VBoxManage poweroff) au
    lieu de laisser la main a l'utilisateur. A n'utiliser qu'en dernier
    recours : ce chemin reproduit exactement la regression reseau decrite
    ci-dessus, corrigee ensuite par reparer-winrm.py au demarrage suivant.

.EXAMPLE
    .\scripts\arreter-environnement.ps1

.EXAMPLE
    .\scripts\arreter-environnement.ps1 -SansVM
#>

param(
    [switch]$SansVM,
    [switch]$Force
)

# Ne PAS mettre $ErrorActionPreference = "Stop" ici : meme raison que dans
# demarrer-environnement.ps1 (docker/VBoxManage ecrivent du texte de statut
# normal sur stderr).

$CheminCADRE = Split-Path $PSScriptRoot -Parent
$CheminSIEM  = Join-Path (Split-Path $CheminCADRE -Parent) "CADRE_SIEM"
$NomVM       = "CADRE"
$VBoxManage  = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$NomVMKali   = "Clone de kali-linux-2025.4-virtualbox-amd64"
$UrlDashboard = "http://127.0.0.1:8765/"

function Write-Etape($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}
function Write-Ok($msg) { Write-Host "    OK  $msg" -ForegroundColor Green }
function Write-Avertissement($msg) { Write-Host "    !!  $msg" -ForegroundColor Yellow }

# =============================================================================
# 1. Dashboard (processus python local, lance sans etat serveur a fermer
#    proprement -- un Stop-Process direct est sans risque, aucune ecriture
#    en cours n'est interrompue a mi-chemin par une simple fermeture HTTP).
# =============================================================================
Write-Etape "Dashboard"
$processusDashboard = Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" |
    Where-Object { $_.CommandLine -match "cadre\.cli\s+dashboard" }
if ($processusDashboard) {
    foreach ($p in $processusDashboard) {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Write-Ok "Dashboard arrete ($($processusDashboard.Count) processus)"
} else {
    Write-Ok "Aucun dashboard actif sur ce poste"
}

# =============================================================================
# 2. VM(s) -- arret ACPI propre, PAS un poweroff (voir .DESCRIPTION)
# =============================================================================
$vmAArreter = @()
if (-not $SansVM) {
    Write-Etape "VM(s) -- demande d'arret propre (ACPI)"
    foreach ($nom in @($NomVM, $NomVMKali)) {
        $info = & $VBoxManage showvminfo $nom --machinereadable 2>$null
        if ($info -and ($info -match 'VMState="running"')) {
            & $VBoxManage controlvm $nom acpipowerbutton *> $null
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "Signal d'arret envoye a '$nom'"
                $vmAArreter += $nom
            } else {
                Write-Avertissement "Echec de l'envoi du signal ACPI a '$nom' (VBoxManage a echoue)"
            }
        } elseif ($info) {
            Write-Ok "'$nom' deja eteinte"
        }
    }

    if ($vmAArreter.Count -gt 0) {
        Write-Etape "Attente de l'extinction complete (jusqu'a 2 min)"
        $t = 0
        do {
            Start-Sleep -Seconds 5
            $t++
            $vmAArreter = $vmAArreter | Where-Object {
                $info = & $VBoxManage showvminfo $_ --machinereadable 2>$null
                $info -and ($info -match 'VMState="running"')
            }
        } until ($vmAArreter.Count -eq 0 -or $t -gt 24)

        if ($vmAArreter.Count -eq 0) {
            Write-Ok "Toutes les VM sont eteintes proprement"
        } else {
            # Repli AVANT -Force : le bouton ACPI depend d'un reglage de
            # l'invite (action associee au bouton d'alimentation) qui n'est
            # pas garanti -- shutdown.exe lance DEPUIS l'invite (canal Guest
            # Additions, comme reparer-winrm.py) declenche la sequence
            # d'arret Windows normale sans en dependre. Kali n'est pas
            # concernee (SSH, pas de Guest Additions configurees).
            if ($NomVM -in $vmAArreter) {
                Write-Etape "Repli : ordre d'arret envoye depuis l'interieur de '$NomVM'"
                & "$CheminCADRE\.venv\Scripts\python.exe" "$PSScriptRoot\arreter-vm-proprement.py"
                Start-Sleep -Seconds 15
                $vmAArreter = $vmAArreter | Where-Object {
                    $info = & $VBoxManage showvminfo $_ --machinereadable 2>$null
                    $info -and ($info -match 'VMState="running"')
                }
            }

            if ($vmAArreter.Count -eq 0) {
                Write-Ok "Toutes les VM sont eteintes proprement"
            } elseif ($Force) {
                Write-Avertissement "Toujours allumee(s) : $($vmAArreter -join ', ') -- coupure forcee (-Force)"
                foreach ($nom in $vmAArreter) {
                    & $VBoxManage controlvm $nom poweroff *> $null
                }
            } else {
                Write-Avertissement "Toujours allumee(s) : $($vmAArreter -join ', ')"
                Write-Avertissement "Relance avec -Force pour couper immediatement (risque : regression reseau WinRM au prochain demarrage, voir reparer-winrm.py)."
            }
        }
    }
}

# =============================================================================
# 3. SIEM (Docker) -- stop, jamais down -v (le volume elasticsearch-data
#    doit survivre : c'est tout l'historique de detections/regles indexees).
# =============================================================================
Write-Etape "SIEM (Elasticsearch + Kibana)"
if (Test-Path $CheminSIEM) {
    docker info *> $null
    if ($LASTEXITCODE -eq 0) {
        Push-Location $CheminSIEM
        docker compose stop *> $null
        Pop-Location
        Write-Ok "Conteneurs SIEM arretes (donnees conservees dans le volume)"
    } else {
        Write-Avertissement "Docker Desktop n'est pas actif -- rien a arreter"
    }
} else {
    Write-Avertissement "Dossier SIEM introuvable ($CheminSIEM) -- etape ignoree"
}

# =============================================================================
# Resume
# =============================================================================
Write-Host ""
Write-Host "=== Environnement arrete. ===" -ForegroundColor Green
Write-Host ""
Write-Host "Pour tout relancer : .\scripts\demarrer-environnement.ps1 (ou DEMARRER-CADRE.bat)" -ForegroundColor DarkGray
