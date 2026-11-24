@echo off
rem Double-cliquez pour desinstaller completement le capteur CyberVeylix de ce PC.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1" %*
