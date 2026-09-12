@echo off
REM ===========================================================================
REM  CADRE - Arret propre en un double-clic
REM ---------------------------------------------------------------------------
REM  Double-clique ce fichier : il arrete le dashboard, demande un arret
REM  propre (ACPI) des VM cibles, et arrete le SIEM (Docker) -- sans jamais
REM  supprimer de donnees. Symetrique de DEMARRER-CADRE.bat.
REM ===========================================================================
title CADRE - Arret
powershell -ExecutionPolicy Bypass -NoProfile -File "%~dp0scripts\arreter-environnement.ps1"
pause
