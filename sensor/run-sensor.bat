@echo off
rem Lancement du capteur CyberVeylix (ex. depuis le Planificateur de taches, au demarrage).
rem Les arguments supplementaires sont transmis : run-sensor.bat --gateway-mac=00:11:22:33:44:55
cd /d "%~dp0.."
if not exist sensor\data mkdir sensor\data
echo ==== %date% %time% >> sensor\data\sensor.log
if exist agent\.env (
  node --env-file=agent/.env sensor/listener.mjs --yes %* >> sensor\data\sensor.log 2>&1
) else (
  node sensor/listener.mjs --yes %* >> sensor\data\sensor.log 2>&1
)
