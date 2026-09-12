<#
.SYNOPSIS
    Controle PRE-VOL go/no-go de la DEMO CADRE (lecture seule, ne change rien).

.DESCRIPTION
    A lancer juste avant de presenter, pour savoir en 10 secondes si la demo
    peut demarrer. Verifie uniquement ce dont LA DEMO a besoin :
      - Elasticsearch sain      (SIEM)
      - Kibana sain             (SIEM)
      - VM Windows / WinRM 5985  (les 5 techniques de demo sont Windows)
      - Ollama + modele charge   (pastille verte + assistant instantane)
      - Dashboard qui repond     (http://127.0.0.1:8765)
    Kali/SSH et Internet ne sont PAS requis (sous-ensemble 100% Windows).
    Affiche un verdict clair : "PRET POUR LA DEMO" ou la liste de ce qui manque.

.EXAMPLE
    .\scripts\demo-prevol.ps1
#>

# PS 5.1 : pas de $ErrorActionPreference="Stop" (docker ecrit sur stderr).
$IPVM         = "192.168.56.104"   # VM Windows cible (WinRM)
$UrlDashboard = "http://127.0.0.1:8765/"
$UrlOllama    = "http://127.0.0.1:11434"

function Write-Titre($m) { Write-Host ""; Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m)  { Write-Host "    [OK]     $m" -ForegroundColor Green }
function Ko($m)  { Write-Host "    [MANQUE] $m" -ForegroundColor Red }
function Info($m){ Write-Host "    [i]      $m" -ForegroundColor DarkGray }

$manquants = @()

Write-Titre "PRE-VOL DEMO CADRE (lecture seule)"

# --- 1. Elasticsearch (via l'etat de sante du conteneur : independant de l'auth)
$es = docker inspect elasticsearch --format '{{.State.Health.Status}}' 2>$null
if ($es -eq "healthy") { Ok "Elasticsearch sain" }
else { Ko "Elasticsearch (etat: '$es')"; $manquants += "Elasticsearch" }

# --- 2. Kibana
$kb = docker inspect kibana --format '{{.State.Health.Status}}' 2>$null
if ($kb -eq "healthy") { Ok "Kibana sain" }
else { Ko "Kibana (etat: '$kb')"; $manquants += "Kibana" }

# --- 3. VM Windows / WinRM (REQUISE : les 5 techniques de demo sont Windows)
if ((Test-NetConnection -ComputerName $IPVM -Port 5985 -WarningAction SilentlyContinue).TcpTestSucceeded) {
    Ok "VM Windows joignable (WinRM 5985 sur $IPVM)"
} else {
    Ko "VM Windows injoignable (WinRM 5985 sur $IPVM) - allume la VM"
    $manquants += "VM Windows / WinRM"
}

# --- 4. Ollama + modele charge en memoire
$modele = ""
try {
    $tags = Invoke-RestMethod -Uri "$UrlOllama/api/tags" -TimeoutSec 4
    if ($tags.models -and $tags.models.Count -gt 0) {
        $modele = ($tags.models | Select-Object -First 1).name
        Ok "Ollama repond (modele disponible : $modele)"
    } else {
        Ko "Ollama repond mais AUCUN modele installe"
        $manquants += "Modele Ollama"
    }
} catch {
    Ko "Ollama injoignable ($UrlOllama)"
    $manquants += "Ollama"
}

# --- 5. Dashboard
try {
    Invoke-WebRequest -Uri $UrlDashboard -TimeoutSec 3 -UseBasicParsing *> $null
    Ok "Dashboard repond ($UrlDashboard)"
} catch {
    Ko "Dashboard ne repond pas ($UrlDashboard) - lance le warm start"
    $manquants += "Dashboard"
}

# --- Verdict -----------------------------------------------------------------
Write-Host ""
if ($manquants.Count -eq 0) {
    Write-Host "  ============================" -ForegroundColor Green
    Write-Host "     PRET POUR LA DEMO" -ForegroundColor Green
    Write-Host "  ============================" -ForegroundColor Green
    Write-Host ""
    Info "Lance le cycle : bouton 'Demarrer' du dashboard, ou 'cadre cycle --demo'."
    exit 0
} else {
    Write-Host "  ================================" -ForegroundColor Yellow
    Write-Host "     PAS ENCORE PRET" -ForegroundColor Yellow
    Write-Host "  ================================" -ForegroundColor Yellow
    Write-Host "  A regler : $($manquants -join ', ')" -ForegroundColor Yellow
    Write-Host ""
    Info "Corrige les points ci-dessus (souvent : relancer le warm start), puis relance ce pre-vol."
    exit 1
}
