<#
.SYNOPSIS
    Verification complete de CADRE en une seule commande : qualite du code
    (tests, lint, formatage, typage), etat de l'environnement (SIEM + VM),
    puis un cycle d'audit reel sur tout le catalogue.

.DESCRIPTION
    Regroupe en une seule commande ce qui demandait avant plusieurs appels
    separes (pytest, ruff, black, mypy, demarrer-environnement.ps1, cadre
    cycle). S'arrete a la premiere famille d'echecs bloquante (le code
    doit etre propre avant de tester en reel) mais continue les etapes
    independantes pour donner un diagnostic complet en un seul passage.

.PARAMETER RapideSansCycle
    N'execute que la verification de code + l'etat de l'environnement,
    sans lancer le cycle complet sur tout le catalogue (qui prend 10 a 20
    minutes contre la vraie VM/SIEM). Utile pour une verification rapide
    avant de committer, par exemple.

.EXAMPLE
    .\scripts\verifier-tout.ps1

.EXAMPLE
    .\scripts\verifier-tout.ps1 -RapideSansCycle
#>

param(
    [switch]$RapideSansCycle
)

# Ne PAS mettre $ErrorActionPreference = "Stop" ici : meme raison que dans
# demarrer-environnement.ps1 (commandes natives + docker sur stderr).

# Derive du dossier du script (scripts/ -> parent = racine CADRE), comme
# demarrer-tout.ps1/demarrer-environnement.ps1 : robuste a une copie/
# deplacement du projet, au lieu d'un chemin en dur.
$CheminCADRE = Split-Path $PSScriptRoot -Parent
Set-Location $CheminCADRE

function Write-Etape($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}
function Write-Ok($msg) { Write-Host "    OK  $msg" -ForegroundColor Green }
function Write-Erreur($msg) { Write-Host "    XX  $msg" -ForegroundColor Red }

$echecs = @()
$python = ".\.venv\Scripts\python.exe"

# =============================================================================
# 1. Qualite du code (tests + couverture, lint, formatage, typage)
# =============================================================================
Write-Etape "Qualite du code"

& $python -m pytest tests/ -q --cov=cadre --cov-report=term-missing
if ($LASTEXITCODE -eq 0) { Write-Ok "Tests + couverture" } else { Write-Erreur "Tests"; $echecs += "Tests" }

& $python -m ruff check src tests
if ($LASTEXITCODE -eq 0) { Write-Ok "Ruff (lint)" } else { Write-Erreur "Ruff"; $echecs += "Ruff" }

& $python -m black --check src tests
if ($LASTEXITCODE -eq 0) { Write-Ok "Black (formatage)" } else { Write-Erreur "Black"; $echecs += "Black" }

& $python -m mypy src/cadre
if ($LASTEXITCODE -eq 0) { Write-Ok "Mypy (typage)" } else { Write-Erreur "Mypy"; $echecs += "Mypy" }

if ($echecs.Count -gt 0) {
    Write-Host ""
    Write-Host "=== Code non propre ($($echecs -join ', ')) - corrige avant de tester en reel ===" -ForegroundColor Red
    exit 1
}

# =============================================================================
# 2. Environnement (Docker/SIEM/VM/Ollama)
# =============================================================================
Write-Etape "Environnement (SIEM + VM)"
& "$CheminCADRE\scripts\demarrer-environnement.ps1"
if ($LASTEXITCODE -ne 0) { $echecs += "Environnement" }

# =============================================================================
# 3. Cycle d'audit reel sur tout le catalogue
# =============================================================================
if (-not $RapideSansCycle) {
    if ($echecs.Count -eq 0) {
        Write-Etape "Cycle d'audit complet (34 attaques, contre le vrai SIEM)"
        $dossier = "rapports_verification_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        & $python -m cadre.cli cycle -o $dossier
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Cycle termine - resume ci-dessus, rapport detaille dans $dossier\"
        } else {
            Write-Erreur "Cycle en erreur"
            $echecs += "Cycle"
        }
    } else {
        Write-Etape "Cycle d'audit complet"
        Write-Host "    Ignore : environnement pas pret (voir ci-dessus)" -ForegroundColor Yellow
    }
} else {
    Write-Host ""
    Write-Host "(Cycle complet ignore : -RapideSansCycle)" -ForegroundColor DarkGray
}

# =============================================================================
# Resume final
# =============================================================================
Write-Host ""
if ($echecs.Count -eq 0) {
    Write-Host "=== TOUT EST VERIFIE ET FONCTIONNE. ===" -ForegroundColor Green
    exit 0
} else {
    Write-Host "=== A CORRIGER : $($echecs -join ', ') ===" -ForegroundColor Yellow
    exit 1
}
