// CyberVeylix Sensor — lecture des options (pur, testable).
// Sources, de la plus faible à la plus forte : fichier --config (écrit par install.ps1), puis ligne de commande.
// Ne lève jamais d'exception : renvoie { options } ou { error } (message pour l'utilisateur).

const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/

// Texte JSON du fichier de configuration. Windows PowerShell 5.1 écrit souvent un BOM UTF-8 : on l'enlève.
export function parseConfigText(text) {
  let data
  try {
    data = JSON.parse(String(text).replace(/^﻿/, ''))
  } catch (e) {
    return { error: `Fichier de configuration illisible (JSON invalide : ${e.message}).` }
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return { error: 'Fichier de configuration invalide : un objet JSON est attendu.' }
  }
  return { config: data }
}

export function normalizeMac(value) {
  if (value === undefined || value === null || value === '') return null
  const mac = String(value).trim().toLowerCase().replaceAll('-', ':')
  return MAC_RE.test(mac) ? mac : undefined // undefined = invalide
}

// argv : process.argv.slice(2). config : objet issu de parseConfigText (ou {}).
export function resolveOptions(argv, config = {}) {
  const flag = (name) => argv.includes(`--${name}`)
  const value = (name) => {
    const a = argv.find((x) => x.startsWith(`--${name}=`))
    return a === undefined ? undefined : a.slice(name.length + 3)
  }
  const pick = (cliName, cfgName) => {
    const v = value(cliName)
    return v !== undefined ? v : config[cfgName]
  }

  const opts = {
    list: flag('list'),
    json: flag('json'),
    // L'autorisation peut venir de --yes ou de l'installateur (consigne écrite enregistrée dans config.json).
    authorized: flag('yes') || config.authorized === true,
    interface: pick('interface', 'interface') || null,
    gateway: pick('gateway', 'gateway') || null,
    push: flag('push') || config.push === true,
    resetBaseline: flag('reset-baseline'),
    dataDir: pick('data-dir', 'dataDir') || null,
    // learnMinutes : imposé à CE lancement (ligne de commande, ou valeur explicite).
    // initialLearnMinutes : durée du tout premier apprentissage seulement (config.json de l'installateur) ;
    // sans cela le capteur réapprendrait — donc serait aveugle — après chaque redémarrage du PC.
    learnMinutes: null,
    initialLearnMinutes: null,
    gatewayMac: null,
    // Leurres : désactivés par défaut en ligne de commande, activés par l'installateur (config.json).
    honeypot: flag('honeypot') || (config.honeypot === true && !flag('no-honeypot')),
    honeypotPorts: null, // null = ports par défaut
    honeypotAllow: [], // IP autorisées à toucher les leurres (scanner légitime du client)
    // Analyse périodique des vulnérabilités des appareils connus (désactivée par défaut en ligne de commande).
    vulnScan: flag('vuln-scan') || (config.vulnScan === true && !flag('no-vuln-scan')),
    vulnScanHours: 24,
    vulnFirstDelayMinutes: 5, // délai après l'apprentissage avant la première analyse
    // Interface web servie par le capteur (dossier « ui » à côté de listener.mjs). Réseau local par défaut.
    ui: flag('ui') || (config.ui === true && !flag('no-ui')),
    uiPort: 8710,
    uiLan: !flag('ui-local') && config.uiLan !== false,
  }

  const bounded = (raw, label, min, max) => {
    if (raw === undefined || raw === null || raw === '') return { value: null }
    const n = Number(raw)
    if (!Number.isFinite(n) || n < min || n > max) return { error: `${label} doit être un nombre entre ${min} et ${max}.` }
    return { value: n }
  }
  const hours = bounded(pick('vuln-scan-hours', 'vulnScanHours'), '--vuln-scan-hours', 1, 168)
  if (hours.error) return { error: hours.error }
  if (hours.value !== null) opts.vulnScanHours = hours.value
  const delay = bounded(pick('vuln-first-delay', 'vulnFirstDelayMinutes'), '--vuln-first-delay', 0, 1440)
  if (delay.error) return { error: delay.error }
  if (delay.value !== null) opts.vulnFirstDelayMinutes = delay.value

  const uiPort = bounded(pick('ui-port', 'uiPort'), '--ui-port', 1024, 65535)
  if (uiPort.error) return { error: uiPort.error }
  if (uiPort.value !== null) {
    if (!Number.isInteger(uiPort.value)) return { error: '--ui-port doit être un entier entre 1024 et 65535.' }
    opts.uiPort = uiPort.value
  }

  const list = (cliName, cfgName) => {
    const v = value(cliName)
    if (v !== undefined) return v.split(',').map((s) => s.trim()).filter(Boolean)
    const c = config[cfgName]
    if (Array.isArray(c)) return c.map((s) => String(s).trim()).filter(Boolean)
    // Windows PowerShell 5.1 peut écrire un tableau d'un seul élément comme simple valeur.
    if (typeof c === 'string' || typeof c === 'number') return String(c).split(',').map((s) => s.trim()).filter(Boolean)
    return null
  }
  const ports = list('honeypot-ports', 'honeypotPorts')
  if (ports) {
    const nums = ports.map(Number)
    if (!nums.length || nums.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) {
      return { error: '--honeypot-ports invalide (ex. 21,23,8080).' }
    }
    opts.honeypotPorts = [...new Set(nums)]
  }
  const allow = list('honeypot-allow', 'honeypotAllow') || []
  const badIp = allow.find((ip) => !IPV4_RE.test(ip))
  if (badIp) return { error: `--honeypot-allow : adresse invalide ${badIp}.` }
  opts.honeypotAllow = allow

  if (opts.gateway !== null && !IPV4_RE.test(String(opts.gateway))) {
    return { error: `Passerelle invalide : ${opts.gateway} (ex. 192.168.1.1).` }
  }

  const mac = normalizeMac(pick('gateway-mac', 'gatewayMac'))
  if (mac === undefined) return { error: '--gateway-mac invalide (ex. 00:11:22:33:44:55).' }
  opts.gatewayMac = mac

  const minutes = (raw, label) => {
    if (raw === undefined || raw === null || raw === '') return { value: null }
    const n = Number(raw)
    if (!Number.isFinite(n) || n < 0 || n > 24 * 60) return { error: `${label} doit être un nombre entre 0 et 1440.` }
    return { value: n }
  }
  const learn = minutes(pick('learn-minutes', 'learnMinutes'), '--learn-minutes')
  if (learn.error) return { error: learn.error }
  opts.learnMinutes = learn.value
  const initial = minutes(config.initialLearnMinutes, 'initialLearnMinutes')
  if (initial.error) return { error: initial.error }
  opts.initialLearnMinutes = initial.value

  return { options: opts }
}

// Durée d'apprentissage effective : valeur imposée, sinon 0 si une référence existe déjà,
// sinon la durée initiale configurée (10 min par défaut).
export function effectiveLearnMinutes(opts, hasBaseline) {
  if (opts.learnMinutes !== null) return opts.learnMinutes
  if (hasBaseline) return 0
  return opts.initialLearnMinutes !== null ? opts.initialLearnMinutes : 10
}
