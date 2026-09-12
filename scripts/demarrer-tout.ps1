<#
.SYNOPSIS
    Demarre TOUT CADRE en un clic, en ouvrant le dashboard IMMEDIATEMENT.

.DESCRIPTION
    Le dashboard (serveur Python local) n'a besoin de rien pour s'afficher :
    on l'ouvre donc tout de suite, en ~5 secondes, pendant que Docker + le
    SIEM + la VM demarrent EN PARALLELE dans une fenetre a part. L'utilisateur
    ne fixe plus un ecran fige : il voit le dashboard aussitot et suit la
    montee en puissance de l'infra via le bouton "Tout verifier".

    Ordre :
      1. Lance le dashboard (instantane) + ouvre le navigateur
      2. Lance l'environnement (Docker/SIEM/VM) en arriere-plan, en parallele

    Concu pour un double-clic sur DEMARRER-CADRE.bat : aucune commande a taper.
#>

# Derive du dossier du script (scripts/ -> parent = racine CADRE) plutot que
# code en dur : le lanceur fonctionne alors depuis N'IMPORTE QUELLE copie du
# projet, sans piloter par erreur un autre dossier CADRE du Bureau.
$CheminCADRE = Split-Path $PSScriptRoot -Parent
$UrlDashboard = "http://127.0.0.1:8765/"

Write-Host ""
Write-Host "  CADRE - Demarrage" -ForegroundColor Cyan
Write-Host "  =================" -ForegroundColor Cyan
Write-Host ""

# --- 1. Environnement EN PARALLELE (Docker + SIEM + VM) --------------------
# Lance dans sa PROPRE fenetre, sans attendre : ces briques mettent du temps
# a demarrer a froid, mais le dashboard n'en a pas besoin pour s'afficher.
Write-Host "  Demarrage de l'environnement en arriere-plan (Docker, SIEM, VM)..." -ForegroundColor White
$envScript = Join-Path $PSScriptRoot "demarrer-environnement.ps1"
Start-Process powershell -ArgumentList @(
    "-NoExit", "-ExecutionPolicy", "Bypass", "-NoProfile", "-File", "`"$envScript`""
)

# --- 2. Dashboard web (instantane) -----------------------------------------
# Idempotent : si un dashboard repond deja sur le port, on NE lance PAS de
# seconde instance (sinon chaque double-clic empile un serveur qui ne peut pas
# reserver le port et laisse une fenetre en erreur). On reutilise l'existant.
$dashboardDejaLance = $false
try {
    Invoke-WebRequest -Uri $UrlDashboard -TimeoutSec 2 -UseBasicParsing *> $null
    $dashboardDejaLance = $true
} catch {
    # aucun dashboard actif : on va le demarrer
}

if ($dashboardDejaLance) {
    Write-Host "  Dashboard deja actif - reutilisation (pas de doublon)." -ForegroundColor Green
} else {
    Write-Host "  Lancement du dashboard..." -ForegroundColor White
    Start-Process powershell -ArgumentList @(
        "-NoExit", "-NoProfile", "-Command",
        "cd '$CheminCADRE'; .\.venv\Scripts\python.exe -m cadre.cli dashboard"
    )
}

# Le serveur Python demarre en quelques secondes : on attend juste qu'il
# reponde (max ~15 s) avant d'ouvrir le navigateur.
$pret = $false
for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 1
    try {
        Invoke-WebRequest -Uri $UrlDashboard -TimeoutSec 2 -UseBasicParsing *> $null
        $pret = $true
        break
    } catch {
        # pas encore pret
    }
}

# --- 3. Navigateur ---------------------------------------------------------
Start-Process $UrlDashboard

Write-Host ""
if ($pret) {
    Write-Host "  Dashboard ouvert : $UrlDashboard" -ForegroundColor Green
} else {
    Write-Host "  Le navigateur s'ouvre - rafraichis dans quelques secondes." -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  IMPORTANT : Docker, le SIEM et la VM demarrent encore en" -ForegroundColor Cyan
Write-Host "  arriere-plan (1 a 2 min a froid). Dans le dashboard, clique" -ForegroundColor Cyan
Write-Host "  'Tout verifier' de temps en temps : les points passent au vert" -ForegroundColor Cyan
Write-Host "  au fur et a mesure que chaque brique devient prete." -ForegroundColor Cyan
Write-Host ""
Write-Host "  (Cette fenetre peut etre fermee.)" -ForegroundColor DarkGray
Write-Host ""
Start-Sleep -Seconds 6
