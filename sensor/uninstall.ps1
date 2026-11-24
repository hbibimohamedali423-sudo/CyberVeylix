#Requires -Version 5.1
<#
.SYNOPSIS
  Désinstalle complètement le capteur CyberVeylix de ce PC.

.DESCRIPTION
  Arrête le capteur, supprime la tâche planifiée, la règle de pare-feu des leurres, le programme, l'entrée « Applications installées »
  et, sauf -KeepData, les données du réseau du client (inventaire, alertes, identifiants).
  Peut d'abord exporter les données dans une archive à remettre au client (sans aucun mot de passe).
  Npcap n'est retiré que sur demande (-RemoveNpcap) : d'autres logiciels (ex. Wireshark) peuvent l'utiliser.

.EXAMPLE
  .\uninstall.ps1
  Désinstallation guidée.

.EXAMPLE
  .\uninstall.ps1 -Unattended -ExportTo "C:\Users\Public\cyberveylix-export.zip"
  Exporte les données puis désinstalle tout, sans questions.
#>
[CmdletBinding()]
param(
  [string]$InstallDir = (Join-Path $env:ProgramFiles 'CyberVeylix\Sensor'),
  [string]$DataDir = (Join-Path $env:ProgramData 'CyberVeylix\Sensor'),
  [string]$ExportTo = '',
  [switch]$KeepData,
  [switch]$RemoveNpcap,
  [switch]$Unattended
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

$ScriptParams = $PSBoundParameters
$TaskName = 'CyberVeylix Sensor'
$UninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CyberVeylixSensor'
$FirewallGroup = 'CyberVeylix'

function Write-Step([string]$Text) { Write-Host ''; Write-Host "==> $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text) { Write-Host "    [OK] $Text" -ForegroundColor Green }
function Write-Note([string]$Text) { Write-Host "    $Text" }
function Write-Attention([string]$Text) { Write-Host "    [!] $Text" -ForegroundColor Yellow }

function Read-YesNo([string]$Question, [bool]$Default) {
  if ($Unattended) { return $Default }
  $suffix = if ($Default) { '(O/n)' } else { '(o/N)' }
  while ($true) {
    $answer = (Read-Host "    $Question $suffix").Trim().ToLower()
    if ($answer -eq '') { return $Default }
    if ($answer -in @('o', 'oui', 'y', 'yes')) { return $true }
    if ($answer -in @('n', 'non', 'no')) { return $false }
  }
}

function Wait-BeforeClose {
  if (-not $Unattended) { Read-Host "`nAppuyez sur Entrée pour fermer" | Out-Null }
}

function Test-Admin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RelaunchArguments {
  $list = New-Object System.Collections.Generic.List[string]
  foreach ($a in @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'))) { $list.Add($a) }
  foreach ($key in $ScriptParams.Keys) {
    $value = $ScriptParams[$key]
    if ($value -is [System.Management.Automation.SwitchParameter]) {
      if ($value.IsPresent) { $list.Add("-$key") }
    } else {
      $list.Add("-$key")
      $list.Add('"' + ([string]$value -replace '"', '\"') + '"')
    }
  }
  return $list.ToArray()
}

# Supprime un dossier ; s'il est encore verrouillé, la suppression est confiée à un cmd.exe différé.
function Remove-Folder([string]$Path) {
  if (-not (Test-Path $Path)) { return $true }
  try {
    Remove-Item -Path $Path -Recurse -Force
    return $true
  } catch {
    $quoted = '"' + $Path + '"'
    Start-Process -FilePath 'cmd.exe' -WindowStyle Hidden -ArgumentList ('/d /c ping -n 6 127.0.0.1 >nul & rd /s /q ' + $quoted)
    return $false
  }
}

# =========================================================================================
try {
  Write-Host 'CyberVeylix — désinstallation du capteur' -ForegroundColor White

  if (-not (Test-Admin)) {
    if ($Unattended) { throw 'Droits administrateur requis : lancez PowerShell « En tant qu''administrateur ».' }
    Write-Note 'Droits administrateur nécessaires : relance avec confirmation Windows (UAC)...'
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList (Get-RelaunchArguments)
    exit 0
  }

  # Ce script tourne souvent DEPUIS le dossier à supprimer : on en sort d'abord.
  Set-Location -Path $env:SystemRoot

  $client = ''
  $configFile = Join-Path $DataDir 'config.json'
  if (Test-Path $configFile) {
    try { $client = [string](Get-Content -Raw -Encoding UTF8 $configFile | ConvertFrom-Json).client } catch { $client = '' }
  }
  $label = if ($client) { " (client : $client)" } else { '' }

  $installed = (Test-Path $InstallDir) -or (Test-Path $DataDir) -or
    ($null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) -or (Test-Path $UninstallKey) -or
    (@(Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue).Count -gt 0)
  if (-not $installed) {
    Write-Ok 'Le capteur CyberVeylix n''est pas installé sur ce PC.'
    Wait-BeforeClose
    exit 0
  }

  if (-not $Unattended) {
    if (-not (Read-YesNo "Désinstaller le capteur CyberVeylix de ce PC$label ?" $false)) {
      Write-Note 'Désinstallation annulée : rien n''a été modifié.'
      Wait-BeforeClose
      exit 0
    }
  }

  # --- 1. Arrêt ------------------------------------------------------------------------
  Write-Step 'Arrêt du capteur'
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
  }
  $procs = @(Get-CimInstance Win32_Process -Filter "Name = 'node.exe' OR Name = 'cmd.exe'" -ErrorAction SilentlyContinue |
    Where-Object {
      $_.CommandLine -and ($_.CommandLine -like ('*' + $InstallDir + '*')) -and
      (($_.CommandLine -like '*run-sensor.cmd*') -or ($_.CommandLine -like '*listener.mjs*'))
    })
  foreach ($p in $procs) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
  if ($procs.Count -gt 0) { Start-Sleep -Seconds 2 }
  Write-Ok 'Capteur arrêté, tâche planifiée supprimée'

  # --- 2. Export éventuel des données ------------------------------------------------------
  $removeData = -not $KeepData
  if ((Test-Path $DataDir) -and -not $KeepData) {
    if (-not $ExportTo -and -not $Unattended) {
      if (Read-YesNo 'Exporter d''abord les données (appareils, alertes) dans une archive pour le client ?' $false) {
        $ExportTo = Join-Path ([Environment]::GetFolderPath('Desktop')) ("cyberveylix-export-{0}.zip" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
      }
    }
    if ($ExportTo) {
      Write-Step 'Export des données'
      $staging = Join-Path $env:TEMP ('cyberveylix-export-' + [guid]::NewGuid().ToString('N'))
      New-Item -ItemType Directory -Force -Path $staging | Out-Null
      try {
        # agent.env contient un mot de passe : il n'est JAMAIS exporté.
        Get-ChildItem -Path $DataDir -File | Where-Object { $_.Name -ne 'agent.env' } |
          ForEach-Object { Copy-Item -Path $_.FullName -Destination $staging }
        if (Test-Path $ExportTo) { Remove-Item -Path $ExportTo -Force }
        Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $ExportTo
      } finally {
        Remove-Item -Path $staging -Recurse -Force -ErrorAction SilentlyContinue
      }
      Write-Ok "Archive : $ExportTo (sans identifiants)"
    }
    if (-not $Unattended) {
      $removeData = Read-YesNo 'Supprimer les données du réseau de ce PC (recommandé en fin de contrat) ?' $true
    }
  }

  # --- 3. Suppression ---------------------------------------------------------------------
  Write-Step 'Suppression'
  $pending = @()
  if (Remove-Folder $InstallDir) { Write-Ok "Programme supprimé : $InstallDir" } else { $pending += $InstallDir }

  if ($removeData) {
    if (Remove-Folder $DataDir) { Write-Ok "Données supprimées : $DataDir" } else { $pending += $DataDir }
  } else {
    Write-Attention "Données conservées : $DataDir"
  }

  # Dossiers parents « CyberVeylix » laissés vides.
  foreach ($parent in @((Split-Path $InstallDir -Parent), (Split-Path $DataDir -Parent))) {
    if ((Split-Path $parent -Leaf) -eq 'CyberVeylix' -and (Test-Path $parent) -and -not (Get-ChildItem -Path $parent -Force)) {
      Remove-Item -Path $parent -Force -ErrorAction SilentlyContinue
    }
  }

  if (Test-Path $UninstallKey) { Remove-Item -Path $UninstallKey -Recurse -Force }
  Write-Ok 'Entrée « Applications installées » supprimée'

  # Règles de pare-feu des leurres créées par install.ps1.
  $rules = @(Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue)
  if ($rules.Count -gt 0) {
    $rules | Remove-NetFirewallRule
    Write-Ok 'Règles du pare-feu Windows supprimées'
  }

  # --- 4. Npcap (facultatif) ----------------------------------------------------------------
  $npcapUninstaller = Join-Path $env:ProgramFiles 'Npcap\Uninstall.exe'
  if (Test-Path $npcapUninstaller) {
    $removeNpcapNow = $RemoveNpcap
    if (-not $RemoveNpcap -and -not $Unattended) {
      Write-Note 'Npcap peut servir à d''autres logiciels (ex. Wireshark) : ne le retirez que s''il a été installé pour CyberVeylix.'
      $removeNpcapNow = Read-YesNo 'Désinstaller aussi Npcap ?' $false
    }
    if ($removeNpcapNow) {
      Write-Step 'Désinstallation de Npcap'
      Start-Process -FilePath $npcapUninstaller -Wait
      Write-Ok 'Programme de désinstallation de Npcap terminé'
    }
  }

  # --- 5. Vérification -------------------------------------------------------------------
  Write-Step 'Vérification'
  $left = @()
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { $left += 'tâche planifiée' }
  if (Test-Path $UninstallKey) { $left += 'entrée « Applications installées »' }
  if (@(Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue).Count -gt 0) { $left += 'règle de pare-feu' }
  foreach ($p in $pending) { Write-Attention "Suppression de $p dans quelques secondes (fichier encore utilisé)." }
  if ($left.Count -gt 0) {
    Write-Attention ('Éléments restants : ' + ($left -join ', '))
    Wait-BeforeClose
    exit 1
  }
  Write-Host ''
  Write-Host 'Désinstallation terminée : le capteur CyberVeylix a été retiré de ce PC.' -ForegroundColor Green
  Wait-BeforeClose
  exit 0
} catch {
  Write-Host ''
  Write-Host "Désinstallation interrompue : $($_.Exception.Message)" -ForegroundColor Red
  Wait-BeforeClose
  exit 1
}
