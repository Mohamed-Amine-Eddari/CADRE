<#
.SYNOPSIS
    Demarre automatiquement tout l'environnement CADRE : Docker Desktop, le SIEM
    (Elasticsearch + Kibana), la VM Windows cible, puis verifie que tout repond.

.DESCRIPTION
    Remplace la routine manuelle (ouvrir Docker Desktop, "docker compose up -d"
    dans CADRE_SIEM, allumer la VM dans VirtualBox, attendre, verifier...) par
    une seule commande. Chaque etape attend que la precedente soit vraiment
    prete avant de continuer (pas juste "lance", mais "qui repond").

.PARAMETER SansVM
    Ne pas demarrer/attendre la VM cible (utile si tu veux juste le SIEM,
    par exemple pour analyser des donnees deja indexees).

.EXAMPLE
    .\scripts\demarrer-environnement.ps1

.EXAMPLE
    .\scripts\demarrer-environnement.ps1 -SansVM
#>

param(
    [switch]$SansVM
)

# Ne PAS mettre $ErrorActionPreference = "Stop" ici : les commandes natives
# (docker, VBoxManage) ecrivent des messages de statut normaux sur stderr,
# que PowerShell 5.1 transformerait en erreurs fatales avec ce reglage.
# Le controle de flux de ce script se fait explicitement via $LASTEXITCODE.

# --- Configuration (adapter ici si les chemins changent) -------------------
# Derives du dossier du script (robuste a une copie/deplacement du projet) :
# scripts/ -> CADRE, et le SIEM est un dossier frere sur le meme Bureau.
$CheminCADRE   = Split-Path $PSScriptRoot -Parent
$CheminSIEM    = Join-Path (Split-Path $CheminCADRE -Parent) "CADRE_SIEM"
$NomVM         = "CADRE"
$IPVM          = "192.168.56.104"
# VM cible Linux (support multi-OS) — attaques Linux via SSH + télémétrie Auditbeat.
$NomVMKali     = "Clone de kali-linux-2025.4-virtualbox-amd64"
$IPKali        = "192.168.56.102"
$VBoxManage    = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$DockerDesktop = "C:\Program Files\Docker\Docker\Docker Desktop.exe"

function Write-Etape($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}
function Write-Ok($msg) { Write-Host "    OK  $msg" -ForegroundColor Green }
function Write-Avertissement($msg) { Write-Host "    !!  $msg" -ForegroundColor Yellow }
function Write-Erreur($msg) { Write-Host "    XX  $msg" -ForegroundColor Red }

# Regression (trouvee par un vrai cycle de demarrage le 2026-09-01) :
# Test-NetConnection prend ~21s PAR APPEL contre un port ferme/injoignable
# (mesure reel, pas juste "lent en theorie") -- avec 2 cibles verifiees a
# chaque tour de la boucle d'attente ci-dessous, le budget reellement promis
# "jusqu'a ~3 min" (36 x 5s) grimpait en pratique a 15-18 min tant que WinRM
# ne repondait pas, sans qu'aucun test unitaire ne puisse le voir (tout le
# reseau y est mocke). Connexion TCP brute avec timeout explicite court :
# quasi instantane sur un port ouvert, borne strictement par $TimeoutMs sur
# un port ferme/injoignable, au lieu de la latence interne non documentee
# de Test-NetConnection (resolution DNS, essais ICMP, etc.).
function Test-PortRapide {
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs = 2000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $tache = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $tache.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return $false
        }
        $client.EndConnect($tache)
        return $client.Connected
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

$echecs = @()

# =============================================================================
# 0. Pre-vol ressources hote (RAM/CPU) -- AVANT de lancer quoi que ce soit
# =============================================================================
# Trouve en reel le 07/09 : un hote sature (CPU ~95%, <5,2 Go RAM libre apres
# des heures avec plusieurs fenetres Chrome/VS Code ouvertes) fait degenerer
# la VM cible jusqu'a l'absurde -- meme "whoami" mettait 13s, "Get-Date"
# (rien de plus leger n'existe) timeoutait completement. Ce n'est PAS un bug
# CADRE ni une mauvaise config WinRM : la VM n'obtient simplement plus de
# temps CPU. Avertir ICI, avant de perdre 3-5 min sur un demarrage voue a
# l'echec, plutot que de laisser l'utilisateur decouvrir un WinRM "invisible"
# a la toute fin.
Write-Etape "Pre-vol ressources hote"
try {
    $ramLibreMo = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB
    $cpuPct = (Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction Stop).CounterSamples[0].CookedValue
    $ramOk = $ramLibreMo -ge 4096
    $cpuOk = $cpuPct -le 85
    if ($ramOk -and $cpuOk) {
        Write-Ok ("RAM libre : {0:N1} Go, CPU : {1:N0}%" -f ($ramLibreMo / 1024), $cpuPct)
    } else {
        Write-Avertissement ("Hote charge -- RAM libre : {0:N1} Go, CPU : {1:N0}%" -f ($ramLibreMo / 1024), $cpuPct)
        Write-Avertissement "La VM cible risque de devenir injoignable (WinRM) sous cette charge, independamment de CADRE."
        Write-Avertissement "Avant une demo/un cycle important : ferme les fenetres/apps inutiles. Processus les plus gourmands :"
        Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 -Property ProcessName,
            @{n = 'RAM_Mo'; e = { [math]::Round($_.WorkingSet64 / 1MB) } },
            @{n = 'CPU_s'; e = { [math]::Round($_.CPU, 0) } } |
            Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor DarkYellow
    }
} catch {
    Write-Avertissement "Pre-vol ressources ignore (mesure indisponible) -- ce n'est pas bloquant."
}

# =============================================================================
# 1. Docker Desktop
# =============================================================================
Write-Etape "Docker Desktop"
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Avertissement "Docker Desktop n'est pas lance - demarrage..."
    Start-Process $DockerDesktop
    $tentatives = 0
    do {
        Start-Sleep -Seconds 3
        $tentatives++
        docker info *> $null
    } until ($LASTEXITCODE -eq 0 -or $tentatives -gt 30)
}
if ($LASTEXITCODE -eq 0) {
    Write-Ok "Docker Desktop actif"
} else {
    Write-Erreur "Docker Desktop n'a pas demarre a temps (>90s)"
    $echecs += "Docker Desktop"
}

# =============================================================================
# 2. Demarrage EN PARALLELE : SIEM (Docker) + VMs (VirtualBox)
# =============================================================================
# On LANCE tout sans attendre, puis on ATTEND tout en parallele (section 3) :
# les temps de boot se recouvrent au lieu de s'additionner (~7 min -> ~3 min).
Write-Etape "Demarrage SIEM + VMs (en parallele)"

$siemLance = $false
if ($LASTEXITCODE -eq 0) {
    Push-Location $CheminSIEM
    docker compose up -d *> $null
    Pop-Location
    $siemLance = $true
    Write-Ok "SIEM lance (montee en puissance en arriere-plan)"
} else {
    Write-Avertissement "SIEM ignore (Docker Desktop indisponible)"
}

# VBoxManage startvm rend la main immediatement : on demarre les 2 VMs d'affilee,
# elles bootent pendant que le SIEM monte.
$vmWinAttendue  = $false
$vmKaliAttendue = $false
if (-not $SansVM) {
    $infoVM = & $VBoxManage showvminfo $NomVM --machinereadable 2>$null
    if ($infoVM) {
        $vmWinAttendue = $true
        if ($infoVM -match 'VMState="running"') {
            Write-Ok "VM Windows deja demarree"
        } else {
            & $VBoxManage startvm $NomVM *> $null
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "VM Windows en demarrage"
            } else {
                Write-Erreur "VM Windows n'a pas demarre (VBoxManage a echoue, code $LASTEXITCODE)"
                Write-Avertissement "Plantage VirtualBox connu apres mise a jour Windows : redemarre Windows, puis reessaie."
                $vmWinAttendue = $false
                $echecs += "VM Windows (demarrage)"
            }
        }
    }
    $infoKali = & $VBoxManage showvminfo $NomVMKali --machinereadable 2>$null
    if ($infoKali) {
        $vmKaliAttendue = $true
        if ($infoKali -match 'VMState="running"') {
            Write-Ok "VM Kali deja demarree"
        } else {
            & $VBoxManage startvm $NomVMKali --type headless *> $null
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "VM Kali en demarrage"
            } else {
                Write-Erreur "VM Kali n'a pas demarre (VBoxManage a echoue, code $LASTEXITCODE)"
                Write-Avertissement "Plantage VirtualBox connu apres mise a jour Windows : redemarre Windows, puis reessaie. Le reste marche quand meme (support Linux indisponible)."
                $vmKaliAttendue = $false
            }
        }
    } else {
        Write-Avertissement "VM Kali '$NomVMKali' introuvable - support Linux desactive (le reste marche)."
    }
}

# =============================================================================
# 3. Attente CONCURRENTE de tous les services (recouvrement des temps de boot)
# =============================================================================
# Une seule boucle poll les 3 cibles (SIEM sain, WinRM 5985, SSH 22) : chacune
# passe au vert des qu'elle repond, sans attendre les autres. On sort quand
# tout ce qui est attendu est pret, ou apres 3 min (36 x 5 s).
Write-Etape "Attente des services (parallele, jusqu'a ~3 min)"
$siemOk = -not $siemLance
$winOk  = -not $vmWinAttendue
$kaliOk = -not $vmKaliAttendue
$winReparationTentee = $false
$t = 0
do {
    Start-Sleep -Seconds 5
    $t++
    if ($siemLance -and -not $siemOk) {
        $es = docker inspect elasticsearch --format '{{.State.Health.Status}}' 2>$null
        $kb = docker inspect kibana --format '{{.State.Health.Status}}' 2>$null
        if ($es -eq "healthy" -and $kb -eq "healthy") { $siemOk = $true; Write-Ok "Elasticsearch et Kibana sains" }
    }
    if ($vmWinAttendue -and -not $winOk) {
        if (Test-PortRapide -ComputerName $IPVM -Port 5985) {
            $winOk = $true; Write-Ok "WinRM repond sur $IPVM"
        } elseif ($t -eq 18 -and -not $winReparationTentee) {
            # A mi-parcours du delai de 3 min (~90s) et une seule fois :
            # tente la reparation hors bande (profil reseau/service WinRM,
            # cause la plus frequente d'un WinRM injoignable juste apres
            # demarrage) avant d'attendre le timeout complet et d'echouer.
            $winReparationTentee = $true
            Write-Avertissement "WinRM ne repond toujours pas sur $IPVM - tentative de reparation automatique..."
            & "$CheminCADRE\.venv\Scripts\python.exe" "$PSScriptRoot\reparer-winrm.py"
        }
    }
    if ($vmKaliAttendue -and -not $kaliOk) {
        if (Test-PortRapide -ComputerName $IPKali -Port 22) {
            $kaliOk = $true; Write-Ok "SSH repond sur $IPKali (attaques Linux disponibles)"
        }
    }
} until (($siemOk -and $winOk -and $kaliOk) -or $t -gt 36)

if ($siemLance -and -not $siemOk) {
    Write-Erreur "SIEM pas sain apres 3 min"
    $echecs += "SIEM"
}
if ($vmWinAttendue -and -not $winOk) {
    if ($winReparationTentee) {
        # La reparation hors bande (jusqu'a 90s) s'ajoute au budget normal
        # de 3 min sans faire avancer $t : ne pas annoncer "apres 3 min" ici,
        # ce serait sous-estimer le delai reel ecoule.
        Write-Erreur "WinRM ne repond toujours pas sur $IPVM"
        Write-Avertissement "La reparation automatique a ete tentee sans succes. Verifie : reseau Host-Only, WinRM (Enable-PSRemoting -Force), carte 'Prive' (pas 'Public')."
    } else {
        Write-Erreur "WinRM ne repond pas sur $IPVM apres 3 min"
        Write-Avertissement "Verifie : reseau Host-Only, WinRM (Enable-PSRemoting -Force), carte 'Prive' (pas 'Public')."
    }
    $echecs += "VM / WinRM"
}
if ($vmKaliAttendue -and -not $kaliOk) {
    Write-Avertissement "SSH ne repond pas sur $IPKali - attaques Linux indisponibles (le reste marche)."
}

# =============================================================================
# 4. Ollama (assistant IA - optionnel, ne bloque rien)
# =============================================================================
Write-Etape "Ollama (assistant IA, optionnel)"
try {
    Invoke-WebRequest -Uri "http://127.0.0.1:11434" -TimeoutSec 3 -UseBasicParsing *> $null
    Write-Ok "Ollama repond"
} catch {
    Write-Avertissement "Ollama ne repond pas - 'cadre suggest' et '--llm' seront indisponibles, le reste marche quand meme"
}

# =============================================================================
# 5. Verification finale via CADRE lui-meme
# =============================================================================
Write-Etape "Verification finale (cadre status)"
Push-Location $CheminCADRE
& ".\.venv\Scripts\python.exe" -m cadre.cli status
Pop-Location

# =============================================================================
# Resume
# =============================================================================
Write-Host ""
if ($echecs.Count -eq 0) {
    Write-Host "=== Environnement pret. Tout fonctionne. ===" -ForegroundColor Green
} else {
    Write-Host "=== Environnement partiellement pret - a verifier : $($echecs -join ', ') ===" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "Pour lancer des commandes cadre dans CE terminal :" -ForegroundColor Cyan
Write-Host "  cd $CheminCADRE"
Write-Host "  .venv\Scripts\Activate.ps1"
Write-Host ""
Write-Host "(Astuce : lance ce script avec '. .\scripts\demarrer-environnement.ps1'" -ForegroundColor DarkGray
Write-Host " (dot-sourcing) pour que le venv reste actif directement dans ce terminal.)" -ForegroundColor DarkGray

if ($echecs.Count -gt 0) { exit 1 } else { exit 0 }
