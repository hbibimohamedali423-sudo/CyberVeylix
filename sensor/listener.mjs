// CyberVeylix Sensor — écoute passive du réseau local (Npcap sous Windows, libpcap sous Linux).
// N'ENVOIE AUCUN paquet : il écoute seulement ARP et les réponses DHCP diffusées sur le réseau.
//
//   node sensor/listener.mjs --list [--json]
//   node sensor/listener.mjs --yes [--interface=192.168.1.10] [--gateway=192.168.1.1]
//                            [--gateway-mac=00:11:22:33:44:55] [--learn-minutes=10]
//                            [--data-dir=C:\ProgramData\CyberVeylix\Sensor] [--push] [--reset-baseline]
//                            [--honeypot] [--honeypot-ports=21,23,8080] [--honeypot-allow=192.168.1.50]
//                            [--vuln-scan] [--vuln-scan-hours=24] [--vuln-first-delay=5]
//   node sensor/listener.mjs --config=C:\ProgramData\CyberVeylix\Sensor\config.json   (écrit par install.ps1)
import { createRequire } from 'node:module'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { mkdirSync, readFileSync, writeFileSync, appendFileSync, existsSync, rmSync, statSync, renameSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArp } from './lib/parse-arp.mjs'
import { parseDhcpServerReply } from './lib/parse-dhcp.mjs'
import { createDetectors } from './lib/detectors.mjs'
import { parseConfigText, resolveOptions, effectiveLearnMinutes } from './lib/options.mjs'
import { createHoneypotMonitor } from './lib/honeypot-monitor.mjs'
import { startHoneypots, DEFAULT_PORTS } from './lib/honeypot-servers.mjs'
import { isPrivateIpv4 } from './lib/vuln/scan.mjs'
import { runVulnScan } from './lib/vuln/run.mjs'
import { countBySeverity } from './lib/vuln/report.mjs'

const require = createRequire(import.meta.url)
const run = promisify(execFile)
const argv = process.argv.slice(2)
const die = (msg) => { console.error('✖ ' + msg); process.exit(1) }

// --- Options ---------------------------------------------------------------------------
const configPath = argv.find((a) => a.startsWith('--config='))?.slice('--config='.length)
let config = {}
if (configPath) {
  if (!existsSync(configPath)) die(`Fichier de configuration introuvable : ${configPath}`)
  const parsed = parseConfigText(readFileSync(configPath, 'utf8'))
  if (parsed.error) die(parsed.error)
  config = parsed.config
}
const resolved = resolveOptions(argv, config)
if (resolved.error) die(resolved.error)
const opts = resolved.options

const HERE = dirname(fileURLToPath(import.meta.url))
const DATA = opts.dataDir || join(HERE, 'data')
const BASELINE_FILE = join(DATA, 'baseline.json')
const EVENTS_FILE = join(DATA, 'events.jsonl')
const EVENTS_MAX_BYTES = 20 * 1024 * 1024
const FILTER = 'arp or (udp and src port 67)'

// --- Chargement de Npcap / libpcap ------------------------------------------
let Cap
try {
  ({ Cap } = require('cap'))
} catch (e) {
  die(`Module de capture indisponible (${e.code || e.message}). Sous Windows : installez Npcap (https://npcap.com). `
    + 'Depuis les sources : npm install --prefix sensor')
}

if (opts.list) {
  const devices = Cap.deviceList().map((d) => ({
    name: d.name,
    description: d.description || '',
    ipv4: d.addresses.map((a) => a.addr).filter((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a || '')),
  }))
  if (opts.json) {
    console.log(JSON.stringify(devices))
  } else {
    for (const d of devices) console.log(`${d.ipv4.join(', ') || '(pas d\'IPv4)'}\n    ${d.description}\n    ${d.name}\n`)
  }
  process.exit(0)
}

if (!opts.authorized) die('Ajoutez --yes pour confirmer que vous êtes autorisé à surveiller ce réseau (autorisation écrite du propriétaire).')

// --- Choix de l'interface ------------------------------------------------------
function pickDevice() {
  const list = Cap.deviceList()
  if (opts.interface) {
    const byIp = Cap.findDevice(opts.interface)
    if (byIp) return byIp
    const byName = list.find((d) => d.name === opts.interface)
    if (byName) return byName.name
    die(`Interface introuvable : ${opts.interface}. Utilisez --list pour voir les interfaces.`)
  }
  // Par défaut : première interface avec une IPv4 privée.
  const priv = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/
  const found = list.find((d) => d.addresses.some((a) => priv.test(a.addr || '')))
  if (!found) die('Aucune interface avec une adresse privée. Précisez --interface=<ip>.')
  return found.name
}

// --- Passerelle par défaut (meilleur effort) ------------------------------------
async function detectGateway() {
  try {
    if (process.platform === 'win32') {
      const { stdout } = await run('route', ['print', '-4', '0.0.0.0'], { timeout: 5000 })
      const m = /^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)/m.exec(stdout)
      return m ? m[1] : null
    }
    const { stdout } = await run('ip', ['route', 'show', 'default'], { timeout: 5000 })
    const m = /default via (\d+\.\d+\.\d+\.\d+)/.exec(stdout)
    return m ? m[1] : null
  } catch { return null }
}

// --- Référence locale -------------------------------------------------------------
mkdirSync(DATA, { recursive: true })
if (opts.resetBaseline && existsSync(BASELINE_FILE)) rmSync(BASELINE_FILE)

let saved = null
if (existsSync(BASELINE_FILE)) {
  try { saved = JSON.parse(readFileSync(BASELINE_FILE, 'utf8')) } catch { console.log('⚠ baseline.json illisible : nouvelle référence.') }
}

const gatewayIp = opts.gateway || saved?.gatewayIp || await detectGateway()
const learnMinutes = effectiveLearnMinutes(opts, Boolean(saved))

const detectors = createDetectors({
  alert: learnMinutes === 0,
  gatewayIp,
  // La MAC fixée à l'installation (vérifiée par le technicien) prime sur celle apprise.
  gatewayMac: opts.gatewayMac || saved?.gatewayMac || undefined,
  trustedDhcpServers: saved?.trustedDhcpServers || [],
  bindings: saved?.bindings || [],
})

function saveBaseline() {
  const s = detectors.snapshot()
  writeFileSync(BASELINE_FILE, JSON.stringify({ savedAt: new Date().toISOString(), gatewayIp, ...s }, null, 2))
}

// Journal des événements borné : au-delà de 20 Mo, l'ancien est conservé une fois (events.jsonl.1).
function appendEvent(line) {
  try {
    if (existsSync(EVENTS_FILE) && statSync(EVENTS_FILE).size > EVENTS_MAX_BYTES) {
      renameSync(EVENTS_FILE, EVENTS_FILE + '.1')
    }
  } catch { /* rotation impossible : on continue d'écrire */ }
  appendFileSync(EVENTS_FILE, line + '\n')
}

// --- Envoi optionnel vers le tableau de bord (--push) -------------------------------
let pushQueue = Promise.resolve()
let sb = null
async function ensureSupabase() {
  if (sb) return sb
  const env = process.env
  if (!env.SUPABASE_URL || !env.SUPABASE_ANON_KEY || !env.CV_EMAIL || !env.CV_PASSWORD) {
    console.log('⚠ --push : variables manquantes (lancez avec --env-file=agent/.env).')
    return null
  }
  const { createClient } = await import('@supabase/supabase-js')
  const client = createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, { auth: { persistSession: false } })
  const { error } = await client.auth.signInWithPassword({ email: env.CV_EMAIL, password: env.CV_PASSWORD })
  if (error) { console.log('⚠ --push : connexion refusée : ' + error.message); return null }
  sb = client
  return sb
}

async function pushAlert(e) {
  const client = await ensureSupabase()
  if (!client) return
  const { error } = await client.from('alerts').insert({ title: e.title, detail: e.detail, severity: e.severity })
  if (error) console.log('⚠ Alerte non envoyée : ' + error.message)
}

// Faiblesses vers la table « vulnerabilities » existante (colonnes title, severity, device_id).
// Sans doublon : une faiblesse déjà présente pour le même appareil n'est pas réinsérée.
async function pushVulnerabilities(findings) {
  if (!findings.length) return
  const client = await ensureSupabase()
  if (!client) return
  const devices = await client.from('devices').select('id,ip')
  const existing = await client.from('vulnerabilities').select('title,device_id')
  if (devices.error || existing.error) {
    console.log('⚠ Vulnérabilités non envoyées : ' + (devices.error || existing.error).message)
    return
  }
  const idByIp = new Map(devices.data.filter((d) => d.ip).map((d) => [d.ip, d.id]))
  const seen = new Set(existing.data.map((v) => `${v.title}|${v.device_id ?? ''}`))
  const rows = []
  for (const f of findings) {
    const row = { title: `${f.title} — ${f.ip}:${f.port}`.slice(0, 300), severity: f.severity, device_id: idByIp.get(f.ip) ?? null }
    const key = `${row.title}|${row.device_id ?? ''}`
    if (!seen.has(key)) { seen.add(key); rows.push(row) }
  }
  if (!rows.length) return
  const { error } = await client.from('vulnerabilities').insert(rows)
  if (error) console.log('⚠ Vulnérabilités non envoyées : ' + error.message)
  else console.log(`  ${rows.length} vulnérabilité(s) envoyée(s) au tableau de bord.`)
}

function report(events) {
  for (const e of events) {
    const at = new Date().toISOString()
    const tag = { c: 'CRITIQUE', h: 'HAUTE', m: 'MOYENNE', l: 'BASSE' }[e.severity] || e.severity
    console.log(`[${at}] ${tag.padEnd(8)} ${e.title} — ${e.detail}`)
    appendEvent(JSON.stringify({ at, ...e }))
    if (opts.push) pushQueue = pushQueue.then(() => pushAlert(e)).catch(() => {})
  }
}

// --- Capture -------------------------------------------------------------------------
const device = pickDevice()
const cap = new Cap()
const buffer = Buffer.alloc(65535)
let linkType
try {
  linkType = cap.open(device, FILTER, 10 * 1024 * 1024, buffer)
} catch (e) {
  die(`Ouverture de l'interface impossible (${e.message}). Sous Windows, vérifiez que Npcap est installé ; lancez en administrateur si Npcap est restreint aux administrateurs.`)
}
if (linkType !== 'ETHERNET') die(`Type de lien non pris en charge : ${linkType} (Ethernet ou Wi-Fi requis).`)
if (cap.setMinBytes) cap.setMinBytes(0)

console.log(`CyberVeylix Sensor — écoute passive sur ${device}`)
if (configPath) console.log(`Configuration : ${configPath}`)
console.log(`Données : ${DATA}`)
console.log(`Passerelle : ${gatewayIp || 'non détectée (contrôle d\'usurpation de passerelle désactivé)'}`)
if (saved) console.log(`Référence chargée : ${saved.bindings?.length || 0} appareil(s), ${saved.trustedDhcpServers?.length || 0} serveur(s) DHCP.`)

// --- Leurres (honeypot) ------------------------------------------------------------
// Ils écoutent sur l'adresse du capteur dans le réseau du client. Ils ne sont jamais en
// « apprentissage » : un contact avec un leurre est suspect dès la première seconde.
function interfaceIpv4(deviceName) {
  if (opts.interface && /^\d+\.\d+\.\d+\.\d+$/.test(opts.interface)) return opts.interface
  const d = Cap.deviceList().find((x) => x.name === deviceName)
  return d?.addresses.map((a) => a.addr).find((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a || '')) || null
}

let honeypots = null
if (opts.honeypot) {
  const hostIp = interfaceIpv4(device)
  if (!hostIp) die('Leurres : adresse IPv4 de l\'interface introuvable. Précisez --interface=<ip>.')
  const monitor = createHoneypotMonitor({
    ignoreIps: [hostIp, '127.0.0.1'], // le capteur lui-même (ex. agent de scan lancé sur ce PC)
    allowIps: opts.honeypotAllow,
    macOf: detectors.macOf,
  })
  honeypots = await startHoneypots({
    host: hostIp,
    services: (opts.honeypotPorts || DEFAULT_PORTS).map((port) => ({ port })),
    onActivity: (activity) => {
      const events = monitor.onActivity(activity, Date.now())
      if (events.length) report(events)
    },
  })
  const on = honeypots.listening.map((l) => `${l.port}/${l.service}`).join(', ')
  console.log(`Leurres actifs sur ${hostIp} : ${on || 'aucun'}`)
  for (const f of honeypots.failed) {
    const why = f.code === 'SERVICE_PRESENT' ? 'un vrai service utilise ce port sur ce PC (il n\'est jamais perturbé)'
      : f.code === 'EADDRINUSE' ? 'port déjà utilisé par ce PC'
        : f.code === 'EACCES' ? 'droits insuffisants' : f.code
    console.log(`  ⚠ Leurre ${f.service} (port ${f.port}) ignoré : ${why}.`)
  }
  if (opts.honeypotAllow.length) console.log(`  Sources autorisées (ignorées) : ${opts.honeypotAllow.join(', ')}`)
}


cap.on('packet', (nbytes) => {
  const frame = Buffer.from(buffer.subarray(0, nbytes)) // copie : le tampon est réutilisé
  const now = Date.now()
  const events = [
    ...detectors.onArp(parseArp(frame), now),
    ...detectors.onDhcp(parseDhcpServerReply(frame), now),
  ]
  if (events.length) report(events)
})

// --- Analyse périodique des vulnérabilités ------------------------------------------------
// Cibles : les appareils appris par le capteur (jamais le PC du capteur lui-même), réseaux privés seulement.
const sensorIp = interfaceIpv4(device)
let vulnRunning = false
async function vulnScanOnce() {
  if (vulnRunning) return // une analyse à la fois
  vulnRunning = true
  try {
    const targets = [...new Set(detectors.snapshot().bindings.map((b) => b.ip))]
      .filter((ip) => isPrivateIpv4(ip) && ip !== sensorIp)
    if (!targets.length) { console.log('Analyse de vulnérabilités : aucun appareil connu pour l\'instant.'); return }
    console.log(`Analyse de vulnérabilités de ${targets.length} appareil(s)…`)
    const r = await runVulnScan({ targets, dataDir: DATA, client: config.client || '' })
    const n = countBySeverity(r.report.findings)
    console.log(`✔ Analyse terminée : ${r.report.findings.length} faiblesse(s) (critiques ${n.c}, hautes ${n.h}, moyennes ${n.m}, basses ${n.l}). Rapport : ${r.htmlFile}`)
    if (r.events.length) report(r.events)
    if (opts.push) pushQueue = pushQueue.then(() => pushVulnerabilities(r.firstScan ? r.report.findings : r.added)).catch(() => {})
  } catch (e) {
    console.log('⚠ Analyse de vulnérabilités impossible : ' + e.message)
  } finally {
    vulnRunning = false
  }
}
function startVulnSchedule() {
  if (!opts.vulnScan) return
  console.log(`Analyse de vulnérabilités : dans ${opts.vulnFirstDelayMinutes} min, puis toutes les ${opts.vulnScanHours} h.`)
  setTimeout(() => {
    vulnScanOnce()
    setInterval(vulnScanOnce, opts.vulnScanHours * 3600 * 1000)
  }, opts.vulnFirstDelayMinutes * 60 * 1000)
}

if (learnMinutes > 0) {
  console.log(`Apprentissage pendant ${learnMinutes} min : aucune alerte, on mémorise le réseau normal…`)
  setTimeout(() => {
    detectors.setAlerting(true)
    saveBaseline()
    const s = detectors.snapshot()
    console.log(`✔ Référence enregistrée : ${s.deviceCount} appareil(s), DHCP de confiance : ${s.trustedDhcpServers.join(', ') || 'aucun vu'}.`)
    if (!s.trustedDhcpServers.length) console.log('  ⚠ Aucun serveur DHCP observé : le premier vu ensuite sera signalé. Relancez l\'apprentissage plus longtemps si besoin.')
    console.log('Surveillance active.')
    startVulnSchedule()
  }, learnMinutes * 60 * 1000)
} else {
  console.log('Surveillance active.')
  startVulnSchedule()
}

// Sauvegarde périodique de la référence. Les appareils déjà signalés y entrent aussi :
// après redémarrage ils ne seront plus « nouveaux » (l'alerte a déjà été émise et journalisée).
// La MAC de la passerelle, elle, reste verrouillée sur la valeur apprise.
setInterval(saveBaseline, 60 * 1000).unref()

function shutdown() {
  try { saveBaseline() } catch { /* ignore */ }
  try { cap.close() } catch { /* ignore */ }
  const closing = honeypots ? honeypots.close().catch(() => {}) : Promise.resolve()
  Promise.all([closing, pushQueue]).finally(() => process.exit(0))
}
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
