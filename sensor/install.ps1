#Requires -Version 5.1
<#
.SYNOPSIS
  Installe le capteur passif CyberVeylix et le lance automatiquement au démarrage de Windows.

.DESCRIPTION
  - Vérifie Windows, les droits administrateur, Node.js et le module de capture.
  - Installe Npcap si nécessaire (programme officiel, quelques clics « Suivant »).
  - Détecte l'interface réseau, la passerelle et sa MAC, et vous les fait confirmer.
  - Enregistre l'autorisation écrite du client (nom, référence, date, technicien).
  - Active les leurres (honeypot) : services factices dont tout contact révèle une intrusion,
    avec une règle de pare-feu limitée au capteur et au réseau local (désactivables : -NoHoneypot).
  - Programme l'analyse non intrusive des vulnérabilités des appareils connus (désactivable : -NoVulnScan).
  - Installe l'interface (tableau de bord) : le capteur la sert lui-même sur http://<ce PC>:8710, avec une règle
    de pare-feu limitée au réseau local et un raccourci sur le Bureau (désactivable : -NoUi ; ce PC seulement : -UiLocalOnly).
  - Crée une tâche planifiée qui lance le capteur au démarrage, en compte SYSTEM,
    et le relance automatiquement s'il s'arrête.
  Aucun réglage du réseau du client n'est modifié. Relancer ce script met à jour l'installation.

.EXAMPLE
  .\install.ps1
  Installation guidée (questions à l'écran).

.EXAMPLE
  .\install.ps1 -Unattended -ClientName "Société X" -AuthorizationRef "Contrat 2026-014 du 20/11/2026"
  Installation sans questions (valeurs détectées automatiquement).
#>
[CmdletBinding()]
param(
  [string]$InstallDir = (Join-Path $env:ProgramFiles 'CyberVeylix\Sensor'),
  [string]$DataDir = (Join-Path $env:ProgramData 'CyberVeylix\Sensor'),
  [string]$NpcapInstaller = '',
  [string]$Interface = '',
  [string]$GatewayMac = '',
  [string]$ClientName = '',
  [string]$AuthorizationRef = '',
  [ValidateRange(0, 1440)][int]$LearnMinutes = 10,
  [switch]$Push,
  [switch]$NoHoneypot,
  [switch]$NoVulnScan,
  [switch]$NoUi,
  [switch]$UiLocalOnly,
  [ValidateRange(1024, 65535)][int]$UiPort = 8710,
  [ValidateRange(1, 168)][int]$VulnScanHours = 24,
  [string[]]$HoneypotAllow = @(),
  [string]$EnvFile = '',
  [switch]$Reconfigure,
  [switch]$Unattended
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Stop'

$ScriptParams = $PSBoundParameters
$TaskName = 'CyberVeylix Sensor'
$UninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CyberVeylixSensor'
$Source = $PSScriptRoot
$NpcapDir = Join-Path $env:SystemRoot 'System32\Npcap'
$FirewallGroup = 'CyberVeylix'
# Doit rester identique à DEFAULT_PORTS dans lib/honeypot-servers.mjs (vérifié par les tests).
$DefaultHoneypotPorts = @(21, 22, 23, 80, 1433, 2323, 3306, 3389, 5900, 8080)
$SidSystem = '*S-1-5-18'
$SidAdmins = '*S-1-5-32-544'

# --- Affichage ------------------------------------------------------------------------
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

# --- Droits administrateur (relance avec UAC si besoin) -----------------------------------
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

# --- Utilitaires -------------------------------------------------------------------------
function ConvertTo-Mac([string]$Value) {
  if (-not $Value) { return $null }
  $mac = $Value.Trim().ToLower() -replace '-', ':'
  if ($mac -match '^([0-9a-f]{2}:){5}[0-9a-f]{2}$') { return $mac }
  return $null
}

function Write-Utf8NoBom([string]$Path, [string]$Text) {
  [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function Format-EnvValue([string]$Value) {
  if ($Value -match "[`r`n]") { throw 'Valeur invalide dans agent.env (retour à la ligne interdit).' }
  if ($Value -notmatch '"') { return '"' + $Value + '"' }
  if ($Value -notmatch "'") { return "'" + $Value + "'" }
  throw 'Valeur invalide dans agent.env (guillemets simples et doubles à la fois).'
}

# Saisie masquée (identifiants SNMP) : la valeur n'apparaît jamais à l'écran.
function Read-Secret([string]$Prompt) {
  $secure = Read-Host "    $Prompt" -AsSecureString
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

# Lecture des switchs et points d'accès (SNMP, LECTURE SEULE) : identifiants enregistrés dans snmp.json du dossier
# de données (accès SYSTEM / administrateurs). Ils ne quittent jamais ce PC.
function Set-SnmpConfig([string]$Path) {
  $creds = New-Object System.Collections.ArrayList
  do {
    $v = ''
    while ($v -ne '2' -and $v -ne '3') { $v = (Read-Host '    Version SNMP de vos équipements : 2 (community) ou 3 (utilisateur)').Trim() }
    if ($v -eq '2') {
      do { $c = Read-Secret 'Community en lecture seule (celle configurée sur vos switchs)' } until ($c -and $c.Length -le 64 -and $c -notmatch '\s')
      [void]$creds.Add([ordered]@{ version = '2c'; community = $c })
    } else {
      do { $u = (Read-Host '    Utilisateur SNMPv3').Trim() } until ($u -and $u.Length -le 32)
      do { $ak = Read-Secret 'Clé d''authentification SHA (8 caractères au moins)' } until ($ak.Length -ge 8)
      do { $pk = Read-Secret 'Clé de chiffrement AES (8 caractères au moins ; vide = sans chiffrement)' } until ($pk.Length -eq 0 -or $pk.Length -ge 8)
      $entry = [ordered]@{ version = '3'; user = $u; authProtocol = 'sha'; authKey = $ak }
      if ($pk) { $entry.privProtocol = 'aes'; $entry.privKey = $pk }
      [void]$creds.Add($entry)
    }
  } while ($creds.Count -lt 5 -and (Read-YesNo 'Ajouter un autre identifiant (autre marque ou autre réglage) ?' $false))
  $raw = (Read-Host '    Adresses IP de vos switchs / points d''accès, séparées par des virgules (vide = découverte automatique)').Trim()
  $targets = @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  foreach ($t in $targets) {
    if ($t -notmatch '^\d{1,3}(\.\d{1,3}){3}(:\d{1,5}){0,1}$') { throw "Adresse d'équipement invalide : $t" }
  }
  $cfg = [ordered]@{ credentials = @($creds); targets = $targets; auto = $true }
  Write-Utf8NoBom $Path (($cfg | ConvertTo-Json -Depth 4) + "`n")
  $creds.Clear()
  Write-Ok "Lecture des switchs configurée : premier résultat 2 minutes après le démarrage, puis toutes les 15 minutes"
}

# Alertes instantanées Telegram : jeton du bot vérifié, conversation trouvée automatiquement (/start), message de test.
# Jeton enregistré dans notify.json du dossier de données (accès SYSTEM / administrateurs) ; jamais affiché.
function Set-TelegramConfig([string]$Path, [string]$Client) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  Write-Note '1. Dans Telegram, ouvrez la conversation avec @BotFather, envoyez /newbot et répondez à ses deux questions.'
  Write-Note '2. BotFather vous donne un jeton (de la forme 123456789:AA...). Collez-le ci-dessous.'
  do { $token = (Read-Secret 'Jeton du bot Telegram').Trim() } until ($token -match '^\d{5,15}:[A-Za-z0-9_-]{30,64}$')
  $api = "https://api.telegram.org/bot$token"
  try { $me = Invoke-RestMethod -Uri "$api/getMe" -TimeoutSec 20 } catch { throw 'Jeton refusé par Telegram : vérifiez-le auprès de @BotFather.' }
  $botName = [string]$me.result.username
  Write-Ok "Bot trouvé : @$botName"
  $chat = $null
  for ($i = 1; $i -le 3 -and -not $chat; $i++) {
    Read-Host "    3. Dans Telegram, ouvrez @$botName, appuyez sur Démarrer (ou envoyez /start), puis appuyez sur Entrée ici" | Out-Null
    try {
      $updates = Invoke-RestMethod -Uri "$api/getUpdates" -TimeoutSec 20
      $last = @($updates.result | Where-Object { $_.message } | Select-Object -Last 1)
      if ($last.Count -gt 0) { $chat = $last[0].message.chat }
    } catch { $chat = $null }
    if (-not $chat) { Write-Attention 'Le bot n''a encore reçu aucun message.' }
  }
  if (-not $chat) { throw 'Le bot n''a reçu aucun message (/start).' }
  $text = "CyberVeylix : les alertes importantes de $Client arriveront ici."
  $body = @{ chat_id = [string]$chat.id; text = $text } | ConvertTo-Json
  try {
    Invoke-RestMethod -Method Post -Uri "$api/sendMessage" -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 20 | Out-Null
  } catch { throw 'Envoi du message de test impossible.' }
  $cfg = [ordered]@{ telegram = [ordered]@{ token = $token; chatId = [string]$chat.id }; minSeverity = 'h' }
  Write-Utf8NoBom $Path (($cfg | ConvertTo-Json -Depth 4) + "`n")
  $token = $null
  Write-Ok 'Alertes Telegram configurées : un message de test vient d''être envoyé sur votre téléphone'
}

function Invoke-TelegramStep([string]$Path, [string]$Client) {
  Write-Step 'Alertes sur téléphone (Telegram, facultatif)'
  Write-Note 'Les alertes critiques et hautes arrivent aussitôt sur votre téléphone, même quand le tableau de bord est fermé.'
  if (Read-YesNo 'Recevoir les alertes importantes sur Telegram ?' $false) {
    try { Set-TelegramConfig $Path $Client }
    catch { Write-Attention ("Alertes Telegram non configurées : " + $_.Exception.Message + ' (possible plus tard avec -Reconfigure)') }
  }
}

function Test-Npcap {
  $service = Get-Service -Name 'npcap' -ErrorAction SilentlyContinue
  return ($null -ne $service) -and (Test-Path (Join-Path $NpcapDir 'wpcap.dll'))
}

function Find-Node {
  $bundled = Join-Path $Source 'node.exe'
  if (Test-Path $bundled) { return $bundled }
  $cmd = Get-Command node.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Path }
  return $null
}

function Stop-Sensor {
  if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  }
  # La tâche lance cmd.exe (boucle run-sensor.cmd) qui lance node.exe (listener.mjs) : on arrête
  # exactement ces deux-là, jamais une autre fenêtre (ex. celle qui a lancé install.cmd).
  $procs = @(Get-CimInstance Win32_Process -Filter "Name = 'node.exe' OR Name = 'cmd.exe'" -ErrorAction SilentlyContinue |
    Where-Object {
      $_.CommandLine -and ($_.CommandLine -like ('*' + $InstallDir + '*')) -and
      (($_.CommandLine -like '*run-sensor.cmd*') -or ($_.CommandLine -like '*listener.mjs*'))
    })
  foreach ($p in $procs) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
  if ($procs.Count -gt 0) { Start-Sleep -Seconds 2 } # libère les fichiers avant la copie
}

function Get-InterfaceCandidates {
  $list = @()
  foreach ($c in @(Get-NetIPConfiguration -ErrorAction SilentlyContinue)) {
    if (-not $c.IPv4DefaultGateway) { continue }
    if (-not $c.NetAdapter -or [string]$c.NetAdapter.Status -ne 'Up') { continue }
    $ip = @($c.IPv4Address)[0].IPAddress
    $gw = @($c.IPv4DefaultGateway)[0].NextHop
    if (-not $ip -or -not $gw -or $gw -eq '0.0.0.0') { continue }
    $virtual = [string]$c.InterfaceDescription -match 'Virtual|Hyper-V|VMware|VirtualBox|VPN|TAP|WireGuard|Tunnel'
    $list += [pscustomobject]@{
      Alias = $c.InterfaceAlias; Index = $c.InterfaceIndex; IP = $ip; Gateway = $gw
      Description = $c.InterfaceDescription; Virtual = $virtual
    }
  }
  # Cartes physiques d'abord : les cartes virtuelles/VPN ne voient pas le réseau local du client.
  return @($list | Sort-Object Virtual, Alias)
}

function Get-GatewayMac([string]$Gateway, [int]$IfIndex) {
  for ($try = 0; $try -lt 2; $try++) {
    $neighbor = Get-NetNeighbor -IPAddress $Gateway -AddressFamily IPv4 -InterfaceIndex $IfIndex -ErrorAction SilentlyContinue |
      Where-Object {
        $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and
        [string]$_.State -ne 'Unreachable' -and [string]$_.State -ne 'Incomplete'
      } | Select-Object -First 1
    if ($neighbor) { return (ConvertTo-Mac $neighbor.LinkLayerAddress) }
    # Un seul ping vers la passerelle remplit la table ARP de ce PC (trafic normal, aucun réglage modifié).
    Test-Connection -ComputerName $Gateway -Count 1 -Quiet -ErrorAction SilentlyContinue | Out-Null
  }
  return $null
}

# =========================================================================================
try {
  Write-Host 'CyberVeylix — installation du capteur passif' -ForegroundColor White

  if (-not (Test-Admin)) {
    if ($Unattended) { throw 'Droits administrateur requis : lancez PowerShell « En tant qu''administrateur ».' }
    Write-Note 'Droits administrateur nécessaires : relance avec confirmation Windows (UAC)...'
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList (Get-RelaunchArguments)
    exit 0
  }

  # --- 1. Système --------------------------------------------------------------------
  Write-Step 'Vérification du système'
  $os = [Environment]::OSVersion.Version
  if ($os.Major -lt 10) { throw "Windows 10, 11 ou Server 2016+ requis (version détectée : $os)." }
  if (-not [Environment]::Is64BitOperatingSystem) { throw 'Windows 64 bits requis.' }
  Write-Ok "Windows $os (64 bits), droits administrateur"

  if (-not (Test-Path (Join-Path $Source 'listener.mjs'))) {
    throw "Fichiers du capteur introuvables à côté de install.ps1 ($Source)."
  }
  $version = (Get-Content -Raw -Encoding UTF8 (Join-Path $Source 'package.json') | ConvertFrom-Json).version
  $bundled = Test-Path (Join-Path $Source 'node.exe')

  # --- 2. Node.js et module de capture -------------------------------------------------
  Write-Step 'Moteur du capteur'
  $nodeSource = Find-Node
  if (-not $nodeSource) {
    throw 'Node.js introuvable. Utilisez le paquet prêt à l''emploi (cyberveylix-sensor-windows-x64.zip), qui inclut tout.'
  }
  $nodeVersion = (& $nodeSource -p 'process.versions.node' | Out-String).Trim()
  if ([version]$nodeVersion -lt [version]'20.6.0') { throw "Node.js $nodeVersion trop ancien (20.6 minimum)." }
  if ($bundled) { Write-Ok "Node.js $nodeVersion inclus dans le paquet" } else { Write-Ok "Node.js $nodeVersion ($nodeSource)" }

  $capModule = Join-Path $Source 'node_modules\cap\build\Release\cap.node'
  if (-not (Test-Path $capModule)) {
    $npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if ($bundled -or -not $npm -or $Unattended) {
      throw 'Module de capture absent. Utilisez le paquet prêt à l''emploi, ou exécutez « npm install --prefix sensor » (Visual Studio Build Tools requis).'
    }
    Write-Attention 'Module de capture absent : compilation (nécessite Visual Studio Build Tools, quelques minutes)...'
    & $npm.Path install --prefix $Source --omit=dev
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $capModule)) { throw 'Compilation du module de capture impossible.' }
  }
  Write-Ok 'Module de capture présent'

  # --- 3. Npcap ---------------------------------------------------------------------
  Write-Step 'Pilote de capture Npcap'
  if (Test-Npcap) {
    Write-Ok 'Npcap déjà installé'
  } else {
    if ($NpcapInstaller) {
      $sig = Get-AuthenticodeSignature -FilePath $NpcapInstaller
      if ([string]$sig.Status -ne 'Valid') { throw "Signature numérique de l'installateur Npcap invalide ($($sig.Status)) : fichier refusé." }
      Write-Note ('Installateur signé par : ' + $sig.SignerCertificate.Subject)
      Write-Note 'Suivez les étapes de Npcap (« I Agree », « Install », « Finish »)...'
      Start-Process -FilePath $NpcapInstaller -Wait
    } elseif ($Unattended) {
      throw 'Npcap absent : fournissez -NpcapInstaller <chemin> ou installez-le depuis https://npcap.com.'
    } else {
      Write-Note "Npcap n'est pas installé. La page officielle de téléchargement va s'ouvrir."
      Write-Note 'Téléchargez « Npcap installer », lancez-le et gardez les options par défaut.'
      Start-Process 'https://npcap.com/#download'
      for ($i = 1; ($i -le 3) -and -not (Test-Npcap); $i++) {
        Read-Host '    Quand Npcap est installé, appuyez sur Entrée' | Out-Null
      }
    }
    if (-not (Test-Npcap)) { throw 'Npcap introuvable après installation. Installez-le puis relancez ce script.' }
    Write-Ok 'Npcap installé'
  }

  # --- 4. Fichiers du programme ----------------------------------------------------------
  Write-Step 'Copie des fichiers'
  Stop-Sensor
  $sameDir = [System.IO.Path]::GetFullPath($Source).TrimEnd('\') -ieq [System.IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
  if ($sameDir) {
    Write-Note 'Exécution depuis le dossier installé : fichiers conservés.'
  } else {
    if (Test-Path $InstallDir) { Remove-Item -Path $InstallDir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $items = @('listener.mjs', 'vulnscan.mjs', 'package.json', 'README.md', 'install.ps1', 'uninstall.ps1', 'install.cmd',
      'uninstall.cmd', 'vulnscan.cmd', 'lib', 'ui', 'node_modules', 'node.exe', 'node-LICENSE.txt')
    foreach ($item in $items) {
      $path = Join-Path $Source $item
      if (Test-Path $path) { Copy-Item -Path $path -Destination $InstallDir -Recurse -Force }
    }
    # Fichiers issus d'un zip téléchargé : Windows les marque « provenant d'Internet » et la copie
    # conserve cette marque. On la retire pour que node.exe et le module de capture ne soient pas bloqués.
    Get-ChildItem -Path $InstallDir -Recurse -File | Unblock-File
    Write-Ok "Programme : $InstallDir"
  }
  $node = if ($bundled) { Join-Path $InstallDir 'node.exe' } else { $nodeSource }

  New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
  # Données du client (inventaire, alertes, éventuel mot de passe) : SYSTEM et Administrateurs uniquement.
  # SID plutôt que noms : fonctionne aussi sur un Windows en français (« Administrateurs »).
  & icacls.exe $DataDir /inheritance:r /grant:r "$($SidSystem):(OI)(CI)F" "$($SidAdmins):(OI)(CI)F" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Impossible de protéger le dossier de données $DataDir (icacls)." }
  Write-Ok "Données : $DataDir (accès réservé à SYSTEM et aux administrateurs)"

  # --- 5. Configuration ------------------------------------------------------------------
  $configFile = Join-Path $DataDir 'config.json'
  $agentEnv = Join-Path $DataDir 'agent.env'
  $baselineFile = Join-Path $DataDir 'baseline.json'
  $existing = $null
  if (Test-Path $configFile) {
    try { $existing = Get-Content -Raw -Encoding UTF8 $configFile | ConvertFrom-Json } catch { $existing = $null }
  }

  $configure = $true
  if ($existing -and -not $Reconfigure) {
    Write-Step 'Configuration existante'
    Write-Note "Client : $($existing.client) — interface $($existing.interface), passerelle $($existing.gateway)"
    $configure = -not (Read-YesNo 'Conserver cette configuration ?' $true)
  }

  if ($configure) {
    Write-Step 'Interface réseau'
    $candidates = @(Get-InterfaceCandidates)
    if ($Interface) {
      $candidates = @($candidates | Where-Object { $_.IP -eq $Interface -or $_.Alias -eq $Interface })
      if ($candidates.Count -eq 0) { throw "Interface « $Interface » introuvable ou sans passerelle." }
    }
    if ($candidates.Count -eq 0) { throw 'Aucune interface connectée avec une passerelle. Branchez ce PC au réseau du client.' }
    if ($candidates.Count -eq 1 -or $Unattended) {
      $selected = $candidates[0]
    } else {
      for ($i = 0; $i -lt $candidates.Count; $i++) {
        $c = $candidates[$i]
        $mark = if ($c.Virtual) { ' (virtuelle)' } else { '' }
        Write-Host ('    [{0}] {1,-15}  {2}{3} — passerelle {4}' -f ($i + 1), $c.IP, $c.Alias, $mark, $c.Gateway)
      }
      do { $n = Read-Host '    Numéro de l''interface reliée au réseau du client' }
      until (($n -match '^\d+$') -and ([int]$n -ge 1) -and ([int]$n -le $candidates.Count))
      $selected = $candidates[[int]$n - 1]
    }
    Write-Ok "$($selected.IP) ($($selected.Alias)) — passerelle $($selected.Gateway)"

    Write-Step 'MAC de la passerelle'
    $mac = $null
    if ($GatewayMac) {
      $mac = ConvertTo-Mac $GatewayMac
      if (-not $mac) { throw "MAC invalide : $GatewayMac (ex. 00-11-22-33-44-55)." }
    } else {
      $mac = Get-GatewayMac $selected.Gateway $selected.Index
      if ($mac) {
        Write-Note "Détectée : $mac"
        Write-Note "Comparez-la à l'étiquette du routeur ou à sa page d'administration."
        if (-not (Read-YesNo 'Cette adresse est-elle correcte ?' $true)) {
          $manual = Read-Host '    MAC correcte (laisser vide pour l''apprendre pendant la surveillance)'
          $mac = ConvertTo-Mac $manual
          if ($manual -and -not $mac) { throw "MAC invalide : $manual" }
        }
      } else {
        Write-Attention "MAC non détectée : elle sera apprise au démarrage du capteur."
      }
    }
    if ($mac) { Write-Ok $mac }

    Write-Step 'Autorisation du client'
    if (-not $ClientName) {
      if ($Unattended) { throw '-ClientName est obligatoire en mode -Unattended.' }
      do { $ClientName = (Read-Host '    Nom du client').Trim() } until ($ClientName)
    }
    if (-not $AuthorizationRef) {
      if ($Unattended) { throw '-AuthorizationRef est obligatoire en mode -Unattended.' }
      do { $AuthorizationRef = (Read-Host '    Référence de l''autorisation écrite (contrat, date)').Trim() } until ($AuthorizationRef)
    }
    if (-not $Unattended) {
      Write-Note "La surveillance d'un réseau sans l'accord écrit de son propriétaire est illégale."
      $confirm = Read-Host "    Tapez OUI pour confirmer que $ClientName vous a autorisé par écrit"
      if ($confirm.Trim().ToUpper() -ne 'OUI') { throw 'Installation annulée : autorisation non confirmée.' }
    }
    Write-Ok "$ClientName — $AuthorizationRef"

    Write-Step 'Tableau de bord'
    Write-Note 'Recommandé : sans cette liaison, ni l''interface ni les actions depuis la page (analyse, blocage, correction) ne fonctionnent.'
    $pushEnabled = $false
    $wantPush = $Push -or (Read-YesNo 'Relier ce capteur au tableau de bord CyberVeylix ?' (-not $Unattended))
    if ($wantPush) {
      if ($EnvFile) {
        Copy-Item -Path $EnvFile -Destination $agentEnv -Force
      } elseif ($Unattended) {
        throw '-Push exige -EnvFile <agent.env> en mode -Unattended.'
      } else {
        # TLS 1.2 : certains Windows 10 avec PowerShell 5.1 ne l'activent pas par défaut.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $verified = $false
        for ($attempt = 1; $attempt -le 3 -and -not $verified; $attempt++) {
          do { $url = (Read-Host '    SUPABASE_URL (https://....supabase.co)').Trim().TrimEnd('/') } until ($url -match '^https://[A-Za-z0-9.-]+$')
          do { $key = (Read-Host '    SUPABASE_ANON_KEY (clé publique, jamais service_role)').Trim() } until ($key.Length -ge 20)
          do { $email = (Read-Host '    E-mail du compte').Trim() } until ($email -match '^[^@\s]+@[^@\s]+$')
          $secure = Read-Host '    Mot de passe du compte' -AsSecureString
          $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
          try { $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
          finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
          # Vérification immédiate : connexion au compte avec ces valeurs (rien n'est enregistré côté serveur).
          try {
            $body = @{ email = $email; password = $password } | ConvertTo-Json
            $session = Invoke-RestMethod -Method Post -Uri "$url/auth/v1/token?grant_type=password" -Headers @{ apikey = $key } `
              -ContentType 'application/json' -Body $body -TimeoutSec 20
            if ($session.access_token) { $verified = $true; Write-Ok "Connexion au tableau de bord vérifiée ($email)" }
          } catch {
            Write-Attention "Connexion refusée : $($_.Exception.Message)"
            if ($attempt -lt 3) { Write-Note 'Vérifiez l''adresse, la clé, l''e-mail et le mot de passe, puis recommencez.' }
          }
          $body = $null
          if (-not $verified) { $password = $null }
        }
        if (-not $verified) { throw 'Connexion au tableau de bord impossible après 3 essais : relancez install.cmd une fois les identifiants vérifiés.' }
        $envText = @(
          ('SUPABASE_URL=' + (Format-EnvValue $url)),
          ('SUPABASE_ANON_KEY=' + (Format-EnvValue $key)),
          ('CV_EMAIL=' + (Format-EnvValue $email)),
          ('CV_PASSWORD=' + (Format-EnvValue $password))
        ) -join "`n"
        Write-Utf8NoBom $agentEnv ($envText + "`n")
        $password = $null
      }
      $pushEnabled = $true
      Write-Ok 'Alertes envoyées au tableau de bord (identifiants protégés dans le dossier de données)'
    } else {
      if (Test-Path $agentEnv) { Remove-Item -Path $agentEnv -Force }
      Write-Ok 'Alertes locales uniquement'
    }

    Write-Step 'Leurres (honeypot)'
    Write-Note 'Le capteur ouvre des services factices (Telnet, FTP, SSH, portail web...) que personne ne doit utiliser.'
    Write-Note 'Tout contact révèle un appareil compromis, un malware qui se propage ou un attaquant sur le réseau.'
    Write-Note 'Un vrai service déjà présent sur ce PC (ex. Bureau à distance) n''est jamais perturbé : son leurre est ignoré.'
    $honeypotEnabled = (-not $NoHoneypot) -and (Read-YesNo 'Activer les leurres (recommandé) ?' $true)
    $honeypotAllow = @()
    if ($honeypotEnabled) {
      $rawAllow = @($HoneypotAllow)
      if ($rawAllow.Count -eq 0 -and -not $Unattended) {
        $answer = Read-Host '    IP des outils de scan légitimes du client à ignorer (séparées par des virgules, vide = aucune)'
        $rawAllow = @($answer -split ',')
      }
      foreach ($ip in $rawAllow) {
        $ip = $ip.Trim()
        if (-not $ip) { continue }
        $parsed = $null
        if (-not ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') -or -not [System.Net.IPAddress]::TryParse($ip, [ref]$parsed)) {
          throw "Adresse IP invalide pour les leurres : $ip"
        }
        $honeypotAllow += $ip
      }
      Write-Ok ('Leurres actifs sur les ports ' + ($DefaultHoneypotPorts -join ', '))
      if ($honeypotAllow.Count -gt 0) { Write-Ok ('Sources ignorées : ' + ($honeypotAllow -join ', ')) }
    } else {
      Write-Ok 'Leurres désactivés'
    }

    Write-Step 'Analyse des vulnérabilités'
    Write-Note 'Contrôle non intrusif des appareils connus : versions vulnérables (CVE), SMBv1, Bureau à distance sans NLA,'
    Write-Note 'services sans mot de passe... Aucun essai de mot de passe, aucune exploitation. Rapport HTML à chaque analyse.'
    $vulnScanEnabled = (-not $NoVulnScan) -and (Read-YesNo 'Activer l''analyse périodique (recommandé) ?' $true)
    if ($vulnScanEnabled) { Write-Ok "Analyse toutes les $VulnScanHours h (première analyse 5 min après l'apprentissage)" }
    else { Write-Ok 'Analyse périodique désactivée (possible à la demande avec vulnscan.cmd)' }

    Write-Step 'Interface (tableau de bord)'
    Write-Note "Le capteur affiche lui-même le tableau de bord dans le navigateur (port $UiPort)."
    $uiAvailable = Test-Path (Join-Path $InstallDir 'ui\index.html')
    $uiEnabled = $false
    if ($NoUi) {
      Write-Ok 'Interface désactivée'
    } elseif (-not $uiAvailable) {
      Write-Attention 'Dossier « ui » absent du paquet : interface non installée.'
    } elseif (-not $pushEnabled) {
      Write-Attention 'L''interface a besoin du compte du tableau de bord (étape précédente) : non activée. Relancez avec -Reconfigure.'
    } else {
      $uiEnabled = Read-YesNo 'Activer l''interface sur ce PC (recommandé) ?' $true
      if ($uiEnabled) {
        if ($UiLocalOnly) { Write-Ok "Interface : http://localhost:$UiPort (ce PC seulement)" }
        else { Write-Ok "Interface : http://$($env:COMPUTERNAME):$UiPort (visible depuis le réseau local, connexion par compte)" }
      } else { Write-Ok 'Interface désactivée' }
    }

    Write-Step 'Lecture des switchs et points Wi-Fi (facultatif)'
    Write-Note 'Avec un accès SNMP en lecture seule à vos switchs, la carte indique le port de chaque appareil, les liaisons'
    Write-Note 'entre switchs et les appareils Wi-Fi de chaque point d''accès. Rien n''est modifié sur les équipements.'
    $snmpFile = Join-Path $DataDir 'snmp.json'
    if ($pushEnabled -and -not $Unattended -and (Read-YesNo 'Configurer la lecture des switchs maintenant ?' $false)) {
      Set-SnmpConfig $snmpFile
    } elseif (Test-Path $snmpFile) {
      Write-Ok 'Lecture des switchs : configuration existante conservée'
    } else {
      Write-Ok 'Lecture des switchs non configurée (possible plus tard avec -Reconfigure)'
    }
    $notifyFile = Join-Path $DataDir 'notify.json'
    if (-not $Unattended) { Invoke-TelegramStep $notifyFile $ClientName }

    # Une référence apprise sur un autre réseau ou une autre passerelle n'est plus valable.
    if ((Test-Path $baselineFile) -and $existing -and ($existing.gateway -ne $selected.Gateway)) {
      Remove-Item -Path $baselineFile -Force
      Write-Attention 'Passerelle différente : la référence du réseau sera réapprise.'
    } elseif ((Test-Path $baselineFile) -and (Read-YesNo 'Réapprendre la référence du réseau (appareils connus) ?' $false)) {
      Remove-Item -Path $baselineFile -Force
    }

    $config = [ordered]@{
      interface = $selected.IP
      gateway = $selected.Gateway
      gatewayMac = $mac
      initialLearnMinutes = $LearnMinutes
      authorized = $true
      dataDir = $DataDir
      push = $pushEnabled
      honeypot = $honeypotEnabled
      honeypotPorts = $DefaultHoneypotPorts
      honeypotAllow = $honeypotAllow
      vulnScan = $vulnScanEnabled
      vulnScanHours = $VulnScanHours
      ui = $uiEnabled
      uiPort = $UiPort
      uiLan = (-not $UiLocalOnly)
      client = $ClientName
      authorizationRef = $AuthorizationRef
      authorizedBy = "$env:USERDOMAIN\$env:USERNAME"
      authorizedAt = (Get-Date).ToString('o')
      machine = $env:COMPUTERNAME
      version = $version
    }
    Write-Utf8NoBom $configFile (($config | ConvertTo-Json) + "`n")
  } else {
    $pushEnabled = [bool]$existing.push -and (Test-Path $agentEnv)
    $ClientName = [string]$existing.client
    $honeypotEnabled = [bool]$existing.honeypot
    $DefaultHoneypotPorts = @($existing.honeypotPorts | Where-Object { $_ })
    $uiEnabled = [bool]$existing.ui
    if ($existing.uiPort) { $UiPort = [int]$existing.uiPort }
    $UiLocalOnly = ($null -ne $existing.uiLan) -and (-not [bool]$existing.uiLan)
    if ($null -eq $existing.ui) {
      # Mise à jour depuis une version sans interface : on propose de l'activer sans tout reconfigurer.
      $uiReady = (-not $NoUi) -and $pushEnabled -and (Test-Path (Join-Path $InstallDir 'ui\index.html'))
      if ($uiReady) {
        Write-Step 'Interface (tableau de bord)'
        Write-Note "Nouveau : le capteur peut afficher le tableau de bord dans le navigateur (port $UiPort)."
        $uiEnabled = Read-YesNo 'Activer l''interface sur ce PC (recommandé) ?' $true
        $existing | Add-Member -NotePropertyName ui -NotePropertyValue $uiEnabled -Force
        $existing | Add-Member -NotePropertyName uiPort -NotePropertyValue $UiPort -Force
        $existing | Add-Member -NotePropertyName uiLan -NotePropertyValue (-not $UiLocalOnly) -Force
        Write-Utf8NoBom $configFile (($existing | ConvertTo-Json) + "`n")
        if ($uiEnabled) { Write-Ok "Interface activée : http://localhost:$UiPort" } else { Write-Ok 'Interface désactivée' }
      } else {
        Write-Attention 'Configuration d''une version précédente : relancez avec -Reconfigure pour activer l''interface (tableau de bord).'
      }
    }
    # Mise à jour : la lecture des switchs est proposée si elle n'a jamais été configurée.
    $snmpFile = Join-Path $DataDir 'snmp.json'
    if ($pushEnabled -and -not $Unattended -and -not (Test-Path $snmpFile)) {
      Write-Step 'Lecture des switchs et points Wi-Fi (facultatif)'
      Write-Note 'Nouveau : avec un accès SNMP en lecture seule, la carte indique le port et le point Wi-Fi de chaque appareil.'
      if (Read-YesNo 'Configurer la lecture des switchs maintenant ?' $false) { Set-SnmpConfig $snmpFile }
    }
    $notifyFile = Join-Path $DataDir 'notify.json'
    if (-not $Unattended -and -not (Test-Path $notifyFile)) { Invoke-TelegramStep $notifyFile $ClientName }
    if (($null -eq $existing.honeypot) -or ($null -eq $existing.vulnScan)) {
      Write-Attention 'Configuration d''une version précédente : relancez avec -Reconfigure pour activer les leurres et l''analyse des vulnérabilités.'
    }
  }

  # --- 6. Lanceur et tâche planifiée -------------------------------------------------------
  Write-Step 'Démarrage automatique'
  $launcher = Join-Path $InstallDir 'run-sensor.cmd'
  $listener = Join-Path $InstallDir 'listener.mjs'
  $cmdPath = { param([string]$p) $p -replace '%', '%%' } # « % » est spécial dans un fichier .cmd
  $envArg = if ($pushEnabled) { '--env-file="' + (& $cmdPath $agentEnv) + '" ' } else { '' }
  $lines = @(
    '@echo off',
    'rem Genere par install.ps1 : lance le capteur CyberVeylix et le relance s''il s''arrete.',
    ('set "DATA=' + (& $cmdPath $DataDir) + '"'),
    'set "PATH=%SystemRoot%\System32\Npcap;%PATH%"',
    ':loop',
    'if exist "%DATA%\sensor.log" for %%A in ("%DATA%\sensor.log") do if %%~zA GTR 10485760 move /y "%DATA%\sensor.log" "%DATA%\sensor.log.1" >nul',
    ('"' + (& $cmdPath $node) + '" ' + $envArg + '"' + (& $cmdPath $listener) + '" --config="%DATA%\config.json" >> "%DATA%\sensor.log" 2>&1'),
    'echo [%date% %time%] Capteur arrete (code %errorlevel%), relance dans 30 s >> "%DATA%\sensor.log"',
    'ping -n 31 127.0.0.1 >nul',
    'goto loop'
  )
  # cmd.exe lit les .cmd dans la page de code OEM : on écrit dans le même encodage.
  $oem = [System.Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
  [System.IO.File]::WriteAllText($launcher, (($lines -join "`r`n") + "`r`n"), $oem)

  $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\cmd.exe') -Argument ('/d /c ""' + $launcher + '""')
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
  $description = "Capteur passif CyberVeylix ($ClientName). Désinstallation : $InstallDir\uninstall.cmd"
  try {
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $description -Force | Out-Null
  } catch {
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $description -Force | Out-Null
  }
  Write-Ok "Tâche « $TaskName » : au démarrage de Windows, compte SYSTEM, relance automatique"

  # Pare-feu de CE PC uniquement : le pare-feu Windows bloque par défaut les connexions entrantes,
  # les leurres ne verraient donc rien. La règle n'ouvre que les ports des leurres, seulement pour
  # le programme du capteur, et seulement depuis le réseau local (jamais depuis Internet).
  Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  if ($uiEnabled -and -not $UiLocalOnly) {
    New-NetFirewallRule -DisplayName 'CyberVeylix Sensor - interface web (réseau local uniquement)' -Group $FirewallGroup `
      -Direction Inbound -Action Allow -Protocol TCP -LocalPort ([string]$UiPort) -Program $node `
      -RemoteAddress LocalSubnet -Profile Any | Out-Null
    Write-Ok "Pare-feu Windows : port $UiPort ouvert au réseau local pour l'interface"
  }
  if ($honeypotEnabled -and $DefaultHoneypotPorts.Count -gt 0) {
    $portList = @($DefaultHoneypotPorts | ForEach-Object { [string]$_ })
    New-NetFirewallRule -DisplayName 'CyberVeylix Sensor - leurres (réseau local uniquement)' -Group $FirewallGroup `
      -Direction Inbound -Action Allow -Protocol TCP -LocalPort $portList -Program $node `
      -RemoteAddress LocalSubnet -Profile Any | Out-Null
    Write-Ok 'Pare-feu Windows : ports des leurres ouverts au réseau local, pour le capteur uniquement'
    Write-Note 'Si un autre pare-feu (antivirus) est actif, autorisez-y aussi le capteur.'
  }

  # Raccourci « CyberVeylix » sur le Bureau de tous les utilisateurs (ouvre l'interface dans le navigateur).
  $desktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
  $shortcut = Join-Path $desktop 'CyberVeylix.url'
  if ($uiEnabled) {
    $shortcutText = "[InternetShortcut]`r`nURL=http://localhost:$UiPort/`r`n"
    [System.IO.File]::WriteAllText($shortcut, $shortcutText, [System.Text.Encoding]::ASCII)
    Write-Ok 'Raccourci « CyberVeylix » créé sur le Bureau'
  } elseif (Test-Path $shortcut) {
    Remove-Item -Path $shortcut -Force
  }

  # Entrée dans « Applications installées » : le client voit le logiciel et peut le désinstaller.
  New-Item -Path $UninstallKey -Force | Out-Null
  $uninstallScript = Join-Path $InstallDir 'uninstall.ps1'
  $strings = @{
    DisplayName = 'CyberVeylix Sensor'
    DisplayVersion = [string]$version
    Publisher = 'CyberVeylix'
    InstallLocation = $InstallDir
    InstallDate = (Get-Date).ToString('yyyyMMdd')
    UninstallString = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $uninstallScript + '"'
    QuietUninstallString = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $uninstallScript + '" -Unattended'
  }
  foreach ($name in $strings.Keys) { New-ItemProperty -Path $UninstallKey -Name $name -Value $strings[$name] -PropertyType String -Force | Out-Null }
  foreach ($name in @('NoModify', 'NoRepair')) { New-ItemProperty -Path $UninstallKey -Name $name -Value 1 -PropertyType DWord -Force | Out-Null }
  Write-Ok 'Visible dans « Applications installées » de Windows'

  # --- 7. Lancement et vérification --------------------------------------------------------
  Write-Step 'Lancement du capteur'
  $log = Join-Path $DataDir 'sensor.log'
  $marker = "==== Installation $(Get-Date -Format o) ===="
  Add-Content -Path $log -Value $marker -Encoding UTF8
  Start-ScheduledTask -TaskName $TaskName

  $started = $false
  $failure = $null
  for ($i = 0; $i -lt 25 -and -not $started -and -not $failure; $i++) {
    Start-Sleep -Seconds 1
    $all = @(Get-Content -Path $log -Encoding UTF8 -ErrorAction SilentlyContinue)
    $index = [array]::LastIndexOf($all, $marker)
    if ($index -ge 0 -and $index -lt ($all.Count - 1)) {
      $fresh = $all[($index + 1)..($all.Count - 1)]
      if ($fresh -match 'Surveillance active|Apprentissage pendant') { $started = $true }
      $bad = @($fresh -match '✖')
      if ($bad.Count -gt 0) { $failure = $bad[0] }
    }
  }

  if ($started) {
    Write-Ok 'Le capteur fonctionne'
  } elseif ($failure) {
    Write-Attention "Le capteur signale une erreur : $failure"
    Write-Attention 'Il sera relancé toutes les 30 s ; corrigez la cause puis relancez install.ps1.'
  } else {
    Write-Attention "Pas de confirmation après 25 s. Consultez le journal : $log"
  }

  if ($uiEnabled -and $started) {
    $uiOk = $false
    for ($i = 0; $i -lt 10 -and -not $uiOk; $i++) {
      try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$UiPort/config.js" -UseBasicParsing -TimeoutSec 3
        if ($r.StatusCode -eq 200) { $uiOk = $true }
      } catch { Start-Sleep -Seconds 1 }
    }
    if ($uiOk) { Write-Ok "Interface en ligne : http://localhost:$UiPort" }
    else { Write-Attention "L'interface ne répond pas sur le port $UiPort (port déjà utilisé ?). Voir le journal : $log" }
  }

  Write-Host ''
  Write-Host 'Installation terminée.' -ForegroundColor Green
  if ($uiEnabled) {
    Write-Note "Interface           : http://localhost:$UiPort  (raccourci « CyberVeylix » sur le Bureau)"
    if (-not $UiLocalOnly) { Write-Note "Depuis un autre PC  : http://$($env:COMPUTERNAME):$UiPort  (réseau local)" }
  }
  Write-Note "Journal en direct   : Get-Content '$log' -Wait -Tail 20"
  Write-Note "Alertes (JSON)      : $(Join-Path $DataDir 'events.jsonl')"
  Write-Note "Rapports            : $DataDir\rapport-vulnerabilites-*.html (ouvrir dans un navigateur, imprimable en PDF)"
  Write-Note "Analyse immédiate   : $(Join-Path $InstallDir 'vulnscan.cmd')"
  Write-Note "Reconfigurer        : $(Join-Path $InstallDir 'install.cmd') -Reconfigure"
  Write-Note "Désinstaller        : $(Join-Path $InstallDir 'uninstall.cmd')  (ou « Applications installées »)"
  if ($configure -and $LearnMinutes -gt 0) {
    Write-Note "Premières $LearnMinutes minutes : apprentissage du réseau normal, aucune alerte."
  }
  Wait-BeforeClose
  exit 0
} catch {
  Write-Host ''
  Write-Host "Installation interrompue : $($_.Exception.Message)" -ForegroundColor Red
  Wait-BeforeClose
  exit 1
}
