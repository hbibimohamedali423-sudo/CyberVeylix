@echo off
rem Double-cliquez pour installer le capteur CyberVeylix (Windows demandera les droits administrateur).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
