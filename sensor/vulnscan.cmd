@echo off
rem Analyse immediate des vulnerabilites des appareils connus du capteur installe.
rem Droits administrateur requis (les donnees du capteur sont reservees aux administrateurs).
net session >nul 2>&1
if errorlevel 1 (
  echo Droits administrateur requis : clic droit sur vulnscan.cmd, puis Executer en tant qu administrateur.
  pause
  exit /b 1
)
set "NODE=%~dp0node.exe"
if not exist "%NODE%" set "NODE=node"
"%NODE%" "%~dp0vulnscan.mjs" --config="%ProgramData%\CyberVeylix\Sensor\config.json" %*
pause
