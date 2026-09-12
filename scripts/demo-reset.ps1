<#
.SYNOPSIS
    Remet la DEMO CADRE dans un etat connu pour rejouer proprement.

.DESCRIPTION
    Non destructif pour les donnees : ne touche NI aux index Elasticsearch
    (telemetrie), NI aux regles deja deployees dans Kibana. Il se contente de :
      1. Redemarrer le dashboard (arrete le process qui ecoute sur 8765 puis le
         relance) : cela vide l'etat de cycle en memoire ET libere le verrou
         anti-concurrence si un cycle reel est reste bloque.
      2. Nettoyer les artefacts locaux du warm start (DEMO\_warmup).
    Apres reset : relance un cycle (en Simule d'abord si tu veux du garanti).

.EXAMPLE
    .\scripts\demo-reset.ps1
#>

$CheminCADRE = Split-Path $PSScriptRoot -Parent
$Port        = 8765
$UrlDash     = "http://127.0.0.1:$Port/"

function Titre($m) { Write-Host ""; Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m) { Write-Host "    OK  $m" -ForegroundColor Green }
function Info($m) { Write-Host "    i   $m" -ForegroundColor DarkGray }

Set-Location $CheminCADRE
Write-Host ""
Write-Host "  CADRE - RESET DEMO (non destructif)" -ForegroundColor Cyan
Write-Host "  ===================================" -ForegroundColor Cyan

# --- 1. Arreter le dashboard (libere l'etat de cycle + le verrou) ------------
Titre "1/3 Redemarrage du dashboard (vide l'etat de cycle, libere le verrou)"
$arretes = 0
try {
    $conns = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
        Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
        $arretes++
    }
} catch {}
if ($arretes -gt 0) { Ok "Dashboard arrete ($arretes process)" } else { Info "Aucun dashboard actif a arreter" }

# --- 2. Nettoyer les artefacts locaux du warm start --------------------------
Titre "2/3 Nettoyage des artefacts locaux du warm start"
$warmup = Join-Path $CheminCADRE "DEMO\_warmup"
if (Test-Path $warmup) {
    Remove-Item $warmup -Recurse -Force -ErrorAction SilentlyContinue
    Ok "DEMO\_warmup supprime"
} else {
    Info "Rien a nettoyer (DEMO\_warmup absent)"
}
Info "Index Elasticsearch et regles Kibana : INTACTS (redeploiement idempotent par id)."

# --- 3. Relancer le dashboard ------------------------------------------------
Titre "3/3 Relance du dashboard"
Start-Process powershell -ArgumentList @(
    "-NoExit", "-NoProfile", "-Command",
    "cd '$CheminCADRE'; .\.venv\Scripts\python.exe -m cadre.cli dashboard"
)
$pret = $false
for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 1
    try { Invoke-WebRequest -Uri $UrlDash -TimeoutSec 2 -UseBasicParsing *> $null; $pret = $true; break } catch {}
}
if ($pret) { Ok "Dashboard relance et pret ($UrlDash)" } else { Info "Dashboard en cours de demarrage - rafraichis dans quelques secondes." }

Write-Host ""
Write-Host "  Etat remis a zero. Pour repartir garanti : lance un cycle en mode 'Simule'." -ForegroundColor Green
Write-Host ""
