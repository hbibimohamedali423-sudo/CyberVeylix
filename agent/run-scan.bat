@echo off
cd /d "%~dp0.."
echo ==== %date% %time% >> agent\scan.log
node --env-file=agent/.env agent/scan.mjs --yes --local-only >> agent\scan.log 2>&1
