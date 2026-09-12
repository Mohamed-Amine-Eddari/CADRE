@echo off
REM ===========================================================================
REM  CADRE - Lanceur en un double-clic
REM ---------------------------------------------------------------------------
REM  Double-clique ce fichier : il demarre tout l'environnement (Docker, SIEM,
REM  VM), lance le dashboard web, et ouvre le navigateur. Aucune commande a
REM  taper. Tout le reste (configurer, generer des attaques par IA, lancer des
REM  cycles, lire les rapports) se fait ensuite dans le dashboard.
REM ===========================================================================
title CADRE - Demarrage
powershell -ExecutionPolicy Bypass -NoProfile -File "%~dp0scripts\demarrer-tout.ps1"
