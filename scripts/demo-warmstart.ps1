<#
.SYNOPSIS
    WARM START de la DEMO CADRE : prepare TOUT ce qui est lent AVANT le public,
    pour que la partie live ne montre que le cycle et le dashboard.

.DESCRIPTION
    A lancer ~10 min avant de presenter. Enchaine, en reutilisant les scripts
    existants (aucune duplication de logique) :
      1. Environnement complet (Docker + SIEM + VM Windows) via
         demarrer-environnement.ps1, avec attentes de sante.
      2. Prechargement du modele Ollama en memoire (1er appel = lent ; on le
         paie maintenant, pas devant le public) + epinglage du modele pour la
         reproductibilite (CADRE_OLLAMA_MODEL).
      3. Dashboard lance et pret (http://127.0.0.1:8765).
      4. Cycle A BLANC (--simulate) pour rechauffer les caches Python/pysigma,
         SANS toucher au SIEM ni a la VM (donc sans risque).
      5. Pre-vol go/no-go final (verdict PRET / manquants).

.EXAMPLE
    .\scripts\demo-warmstart.ps1
#>

# PS 5.1 : pas de $ErrorActionPreference="Stop" (docker/VBox ecrivent sur stderr).
$CheminCADRE  = Split-Path $PSScriptRoot -Parent
$Python       = Join-Path $CheminCADRE ".venv\Scripts\python.exe"
$UrlDashboard = "http://127.0.0.1:8765/"
$UrlOllama    = "http://127.0.0.1:11434"

function Write-Titre($m) { Write-Host ""; Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m)  { Write-Host "    OK  $m" -ForegroundColor Green }
function Avert($m){ Write-Host "    !!  $m" -ForegroundColor Yellow }

Set-Location $CheminCADRE
Write-Host ""
Write-Host "  CADRE - WARM START DEMO" -ForegroundColor Cyan
Write-Host "  =======================" -ForegroundColor Cyan

# --- 1. Environnement complet (reutilise le script existant) -----------------
Write-Titre "1/5 Environnement (Docker + SIEM + VM Windows)"
& "$PSScriptRoot\demarrer-environnement.ps1"
# On ne bloque pas la suite meme si un point est jaune : le pre-vol final tranche.

# --- 2. Ollama : detecter, precharger, epingler ------------------------------
Write-Titre "2/5 Prechargement du modele Ollama"
$modele = ""
try {
    $tags = Invoke-RestMethod -Uri "$UrlOllama/api/tags" -TimeoutSec 5
    # Preference douce pour qwen2.5 (installe sur ce poste), sinon le premier.
    $pref = $tags.models | Where-Object { $_.name -like 'qwen2.5*' } | Select-Object -First 1
    if ($pref) { $modele = $pref.name } elseif ($tags.models.Count -gt 0) { $modele = ($tags.models | Select-Object -First 1).name }
} catch {
    Avert "Ollama injoignable - l'assistant IA sera indisponible (le reste marche)."
}
if ($modele -ne "") {
    Write-Host "    Chargement de '$modele' en memoire (peut prendre 30-90 s la 1re fois)..." -ForegroundColor White
    try {
        $body = @{ model = $modele; prompt = "ok"; stream = $false } | ConvertTo-Json
        Invoke-RestMethod -Uri "$UrlOllama/api/generate" -Method Post -Body $body -TimeoutSec 180 *> $null
        $env:CADRE_OLLAMA_MODEL = $modele   # epinglage : reproductibilite de la demo
        Ok "Modele '$modele' charge et epingle (CADRE_OLLAMA_MODEL)"
    } catch {
        Avert "Prechargement du modele echoue - il se chargera au 1er usage (plus lent)."
    }
}

# --- 3. Dashboard pret -------------------------------------------------------
Write-Titre "3/5 Dashboard"
$dashOk = $false
try { Invoke-WebRequest -Uri $UrlDashboard -TimeoutSec 2 -UseBasicParsing *> $null; $dashOk = $true } catch {}
if ($dashOk) {
    Ok "Dashboard deja actif ($UrlDashboard)"
} else {
    Write-Host "    Lancement du dashboard..." -ForegroundColor White
    Start-Process powershell -ArgumentList @(
        "-NoExit", "-NoProfile", "-Command",
        "cd '$CheminCADRE'; .\.venv\Scripts\python.exe -m cadre.cli dashboard"
    )
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Seconds 1
        try { Invoke-WebRequest -Uri $UrlDashboard -TimeoutSec 2 -UseBasicParsing *> $null; $dashOk = $true; break } catch {}
    }
    if ($dashOk) { Ok "Dashboard pret ($UrlDashboard)" } else { Avert "Dashboard pas encore pret - rafraichis dans quelques secondes." }
}

# --- 4. Cycle A BLANC pour rechauffer les caches (sans SIEM ni VM) ------------
Write-Titre "4/5 Cycle a blanc (--simulate, rechauffe les caches, ne touche rien)"
& $Python -m cadre.cli cycle --demo --simulate -o "DEMO\_warmup" *> $null
if ($LASTEXITCODE -eq 0) { Ok "Caches rechauffes (cycle simule sur le sous-ensemble de demo)" }
else { Avert "Cycle a blanc non termine - sans consequence pour la demo live." }

# --- 5. Pre-vol final --------------------------------------------------------
Write-Titre "5/5 Pre-vol go/no-go"
& "$PSScriptRoot\demo-prevol.ps1"
$codePreVol = $LASTEXITCODE

Write-Host ""
if ($codePreVol -eq 0) {
    Write-Host "  Warm start termine - PRET POUR LA DEMO." -ForegroundColor Green
} else {
    Write-Host "  Warm start termine - il reste des points a regler (voir ci-dessus)." -ForegroundColor Yellow
    Write-Host "  Le plus frequent : allumer la VM Windows, puis relancer .\scripts\demo-prevol.ps1" -ForegroundColor Yellow
}
Write-Host ""
exit $codePreVol
