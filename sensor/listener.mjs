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
import { hostname, networkInterfaces } from 'node:os'
import { mkdirSync, readFileSync, writeFileSync, appendFileSync, existsSync, rmSync, statSync, renameSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArp } from './lib/parse-arp.mjs'
import { parseDhcpServerReply, parseDhcpClientRequest } from './lib/parse-dhcp.mjs'
import { createDetectors } from './lib/detectors.mjs'
import { parseConfigText, resolveOptions, effectiveLearnMinutes } from './lib/options.mjs'
import { createHoneypotMonitor } from './lib/honeypot-monitor.mjs'
import { startHoneypots, DEFAULT_PORTS } from './lib/honeypot-servers.mjs'
import { isPrivateIpv4 } from './lib/vuln/scan.mjs'
import { runVulnScan } from './lib/vuln/run.mjs'
import { countBySeverity } from './lib/vuln/report.mjs'
import { connectSupabase, createPusher } from './lib/push.mjs'
import { startWebServer } from './lib/web-server.mjs'
import { createCommandRunner } from './lib/commands.mjs'
import { createActions } from './lib/actions.mjs'
import { createLocalFixes } from './lib/fixes.mjs'
import { createInventory, cidrOf } from './lib/inventory.mjs'
import { createOui } from './lib/oui.mjs'
import { parseSnmpConfig } from './lib/snmp-config.mjs'
import { createSnmpClient } from './lib/snmp-client.mjs'
import { createTopologySync } from './lib/topo-sync.mjs'
import { createBlocker } from './lib/blocker.mjs'
import dns from 'node:dns/promises'

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
// ARP + DHCP (réponses des serveurs ET demandes des appareils : nom et système annoncés, pour l'inventaire).
const FILTER = 'arp or (udp and (src port 67 or src port 68))'

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

// Inventaire (lib/inventory.mjs) : créé AVANT la capture, connecté à la base plus tard (setClient).
const oui = createOui()
const inventory = createInventory({ oui })

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
// Alertes (origine capteur / leurre / analyse), vulnérabilités détaillées et état du capteur.
// Voir lib/push.mjs ; sans supabase/schema_r1_results.sql l'envoi se limite aux colonnes d'origine.
let pushQueue = Promise.resolve()
let pusherPromise = null
const enqueue = (task) => { pushQueue = pushQueue.then(task).catch((e) => console.log('⚠ Envoi : ' + e.message)) }
function pusher() {
  pusherPromise ||= connectSupabase(process.env).then((client) => client && createPusher(client, {
    gatewayMac: () => opts.gatewayMac || saved?.gatewayMac || (gatewayIp && detectors.macOf(gatewayIp)),
  }))
  return pusherPromise
}
const SENSOR_VERSION = (() => {
  try { return JSON.parse(readFileSync(join(HERE, 'package.json'), 'utf8')).version } catch { return null }
})()
const startedAt = new Date().toISOString()
let lastScanAt = null
function heartbeat() {
  if (!opts.push) return
  enqueue(async () => {
    const p = await pusher()
    if (p) await p.heartbeat({ name: hostname(), version: SENSOR_VERSION, ip: sensorIp, honeypot: Boolean(honeypots), vulnScan: opts.vulnScan, startedAt, lastScanAt })
  })
}

function report(events) {
  for (const e of events) {
    const at = new Date().toISOString()
    const tag = { c: 'CRITIQUE', h: 'HAUTE', m: 'MOYENNE', l: 'BASSE' }[e.severity] || e.severity
    console.log(`[${at}] ${tag.padEnd(8)} ${e.title} — ${e.detail}`)
    appendEvent(JSON.stringify({ at, ...e }))
  }
  if (opts.push && events.length) enqueue(async () => { const p = await pusher(); if (p) await p.pushAlerts(events) })
  // Blocage automatique (réglage « auto_block » du capteur, désactivé par défaut) : géré par lib/actions.mjs.
  if (opts.push && events.length) {
    for (const e of events) {
      Promise.resolve(autoActions && autoActions.maybeAutoBlock(e)).catch((err) => console.log('⚠ Blocage automatique : ' + err.message))
    }
  }
}
let autoActions = null // créé quand le lecteur de commandes démarre (nécessite la connexion au tableau de bord)

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
  const arp = parseArp(frame)
  const events = [
    ...detectors.onArp(arp, now),
    ...detectors.onDhcp(parseDhcpServerReply(frame), now),
  ]
  // Inventaire : l'émetteur réel d'une trame ARP cohérente (pas une usurpation) et les demandes DHCP.
  if (arp && arp.senderMac === arp.ethSrcMac) inventory.observe(arp.senderMac, arp.senderIp, now)
  else {
    const dhcpReq = parseDhcpClientRequest(frame)
    if (dhcpReq) inventory.observeDhcp(dhcpReq, now)
  }
  if (events.length) report(events)
})

// --- Analyse périodique des vulnérabilités ------------------------------------------------
// Cibles : les appareils appris par le capteur (jamais le PC du capteur lui-même), réseaux privés seulement.
const sensorIp = interfaceIpv4(device)
let vulnRunning = false

// Audit LOCAL de ce PC (lecture seule : SMBv1, Bureau à distance sans NLA, Telnet) : le capteur ne s'analyse pas
// par le réseau (ses leurres fausseraient le résultat), il lit directement son état. Voir lib/fixes.mjs.
const localFixes = createLocalFixes({ hostname: hostname(), ip: sensorIp, dataDir: DATA })
let localRunning = false
async function localAuditAndSync() {
  if (localRunning || !localFixes.supported) return { ran: false, findings: [] }
  localRunning = true
  try {
    const r = await localFixes.audit()
    if (r.ran) {
      if (r.findings.length) console.log(`Audit de ce PC : ${r.findings.length} faiblesse(s) (${r.findings.map((f) => f.rule.replace('local-', '')).join(', ')}).`)
      if (opts.push && (r.findings.length || r.fixed.length)) {
        enqueue(async () => {
          const p = await pusher()
          if (p) await p.syncVulnerabilities({ findings: r.findings, fixed: r.fixed })
        })
        heartbeat()
        await pushQueue
      }
    }
    return r
  } finally {
    localRunning = false
  }
}
// Premier audit 1 minute après le démarrage, puis toutes les 6 heures (et après chaque analyse / correction).
setTimeout(() => { localAuditAndSync().catch((e) => console.log('⚠ Audit local : ' + e.message)) }, 60 * 1000).unref()
setInterval(() => { localAuditAndSync().catch((e) => console.log('⚠ Audit local : ' + e.message)) }, 6 * 3600 * 1000).unref()

// Renvoie un résultat { code, ... } (affiché dans la page pour les demandes « Analyser maintenant »).
async function vulnScanOnce() {
  if (vulnRunning) return { code: 'busy' } // une analyse à la fois
  vulnRunning = true
  try {
    const local = await localAuditAndSync().catch(() => ({ ran: false, findings: [] }))
    const targets = [...new Set(detectors.snapshot().bindings.map((b) => b.ip))]
      .filter((ip) => isPrivateIpv4(ip) && ip !== sensorIp)
    if (!targets.length) {
      console.log('Analyse de vulnérabilités : aucun appareil connu pour l\'instant.')
      if (!local.ran) return { code: 'no_devices' }
      const n0 = countBySeverity(local.findings)
      return { code: 'scan_done', hosts: 0, findings: local.findings.length, ...n0 } // seul ce PC a été audité
    }
    console.log(`Analyse de vulnérabilités de ${targets.length} appareil(s)…`)
    const r = await runVulnScan({ targets, dataDir: DATA, client: config.client || '' })
    const n = countBySeverity([...r.report.findings, ...local.findings])
    console.log(`✔ Analyse terminée : ${r.report.findings.length} faiblesse(s) (critiques ${n.c}, hautes ${n.h}, moyennes ${n.m}, basses ${n.l}). Rapport : ${r.htmlFile}`)
    if (r.events.length) report(r.events)
    lastScanAt = new Date().toISOString()
    if (opts.push) {
      enqueue(async () => {
        const p = await pusher()
        if (!p) return
        await p.syncServices(r.report.hosts)
        await p.syncVulnerabilities({ findings: r.report.findings, fixed: r.fixed })
      })
      heartbeat()
      await pushQueue // résultats écrits dans la base avant d'annoncer « terminé »
    }
    return { code: 'scan_done', hosts: targets.length, findings: r.report.findings.length + local.findings.length, ...n }
  } catch (e) {
    console.log('⚠ Analyse de vulnérabilités impossible : ' + e.message)
    return { code: 'error', failed: true, message: String(e.message).slice(0, 300) }
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

// Interface web (tableau de bord) servie par le capteur lui-même : http://<ce PC>:<port>.
// Sans SUPABASE_URL / SUPABASE_ANON_KEY (agent.env) elle s'ouvre sur l'écran « Configuration requise ».
// Un port déjà pris ou un dossier « ui » absent n'arrête jamais la surveillance.
if (opts.ui) {
  const uiRoot = join(HERE, 'ui')
  if (!existsSync(join(uiRoot, 'index.html'))) {
    console.log(`⚠ Interface web : dossier ${uiRoot} absent, non démarrée.`)
  } else {
    startWebServer({ root: uiRoot, port: opts.uiPort, host: opts.uiLan ? '0.0.0.0' : '127.0.0.1' })
      .then((s) => console.log(`✔ Interface web : http://${hostname()}:${s.port}${opts.uiLan ? ' (réseau local)' : ' (ce PC seulement)'}`))
      .catch((e) => console.log(`⚠ Interface web non démarrée (port ${opts.uiPort}) : ${e.message}`))
  }
}

// Inventaire du réseau (réseau + appareils vus + identification) : toutes les 5 minutes, avec --push.
// Le réseau n'est enregistré que pour la MAC de passerelle CONFIRMÉE (installateur) ou verrouillée par l'apprentissage.
const ifaceInfo = (() => {
  const d = Cap.deviceList().find((x) => x.name === device)
  const a = d?.addresses.find((x) => x.addr === sensorIp && x.netmask)
  const fromOs = Object.values(networkInterfaces()).flat().find((x) => x && x.address === sensorIp)
  return { cidr: cidrOf(sensorIp, (a && a.netmask) || (fromOs && fromOs.netmask)), mac: fromOs && fromOs.mac ? fromOs.mac.toLowerCase() : null }
})()
inventory.setSubnet(ifaceInfo.cidr)
let inventoryRunning = false
async function inventoryOnce() {
  if (!opts.push || inventoryRunning) return
  inventoryRunning = true
  try {
    const p = await pusher()
    if (!p) return
    inventory.setClient(p.client)
    const gatewayMac = opts.gatewayMac || saved?.gatewayMac || null
    const networkId = await inventory.ensureNetwork({ gatewayMac, gatewayIp, name: config.client || null })
    await inventory.sync({ networkId, gatewayIp, gatewayMac, sensorMac: ifaceInfo.mac })
  } catch (e) {
    console.log('⚠ Inventaire : ' + e.message)
  } finally {
    inventoryRunning = false
  }
}
// Premier passage après 1 min (CV_TEST_INVENTORY_DELAY_MS : délai réduit pour le test d'intégration uniquement).
setTimeout(inventoryOnce, Number(process.env.CV_TEST_INVENTORY_DELAY_MS) || 60 * 1000).unref()
setInterval(inventoryOnce, 5 * 60 * 1000).unref()

// Lecture des switchs et points Wi-Fi (SNMP, LECTURE SEULE) si snmp.json existe dans le dossier de données :
// port de chaque appareil, liaisons entre équipements (LLDP / CDP), appareils Wi-Fi derrière leur point d'accès.
// Le fichier est relu à chaque passage (ajout possible sans redémarrer). Ses identifiants ne quittent jamais ce PC.
const SNMP_FILE = join(DATA, 'snmp.json')
let topoSync = null
let topoConfigText = null
let topoRunning = false
async function topologyOnce() {
  if (!opts.push || topoRunning || !existsSync(SNMP_FILE)) return
  topoRunning = true
  try {
    const text = readFileSync(SNMP_FILE, 'utf8')
    if (text !== topoConfigText) {
      topoConfigText = text
      const parsed = parseSnmpConfig(text)
      if (parsed.error) { topoSync = null; console.log('⚠ Lecture des switchs désactivée : ' + parsed.error); return }
      const p = await pusher()
      if (!p) return
      topoSync = createTopologySync({ db: p.client, snmp: createSnmpClient(), config: parsed.config, oui })
      console.log(`Lecture des switchs (SNMP) : ${parsed.config.credentials.length} identifiant(s), ${parsed.config.targets.length} équipement(s) listé(s), découverte ${parsed.config.auto ? 'automatique' : 'désactivée'}.`)
    }
    if (!topoSync) return
    const p = await pusher()
    if (!p) return
    inventory.setClient(p.client)
    const networkId = await inventory.ensureNetwork({ gatewayMac: opts.gatewayMac || saved?.gatewayMac || null, gatewayIp, name: config.client || null })
    await topoSync.run({ networkId, gatewayIp })
  } catch (e) {
    console.log('⚠ Lecture des switchs : ' + e.message)
  } finally {
    topoRunning = false
  }
}
setTimeout(topologyOnce, Number(process.env.CV_TEST_TOPOLOGY_DELAY_MS) || 2 * 60 * 1000).unref()
setInterval(topologyOnce, 15 * 60 * 1000).unref()

// Demandes de la page web (table sensor_commands) : « Analyser maintenant ». Liste blanche de gestionnaires ;
// tout autre type reçoit un refus explicite (les blocages et corrections arrivent dans une version ultérieure).
if (opts.push) {
  pusher().then((p) => {
    if (!p) return
    // Adresses du tableau de bord (Supabase) : jamais bloquables, sinon le capteur se couperait lui-même.
    let serviceCache = { at: 0, ips: [] }
    const serviceIps = async () => {
      if (Date.now() - serviceCache.at < 10 * 60 * 1000) return serviceCache.ips
      try {
        const host = new URL(process.env.SUPABASE_URL).hostname
        serviceCache = { at: Date.now(), ips: await dns.resolve4(host) }
      } catch { serviceCache = { at: Date.now(), ips: serviceCache.ips } }
      return serviceCache.ips
    }
    const runner = createCommandRunner({
      client: p.client,
      sensorName: hostname(),
      handlers: {
        // « Analyser maintenant » rafraîchit aussi la carte du réseau (lecture des switchs, si configurée).
        scan_now: async () => { const r = await vulnScanOnce(); topologyOnce().catch(() => {}); return r },
        block_ip: (params) => autoActions.handlers.block_ip(params),
        unblock_ip: (params) => autoActions.handlers.unblock_ip(params),
        // Corrections de la liste blanche (lib/fixes.mjs), sur CE PC seulement ; re-audit aussitôt après.
        fix: async (params) => {
          const r = await localFixes.applyFix(params && params.id)
          if (r.code === 'fix_done' || r.code === 'fix_already') await localAuditAndSync().catch(() => {})
          return r
        },
      },
    })
    autoActions = createActions({
      client: p.client,
      getSensorId: runner.getSensorId,
      blocker: createBlocker(),
      context: () => ({ gatewayIp, sensorIp, dhcp: detectors.snapshot().trustedDhcpServers || [] }),
      serviceIps,
    })
    runner.start()
    console.log('Commandes de la page web : à l\'écoute (analyse, blocage, déblocage et corrections ; toutes les 5 s).')
  })
}

// Pouls toutes les 5 minutes : l'application affiche « en service » ou « arrêté depuis… ».
heartbeat()
setInterval(heartbeat, 5 * 60 * 1000).unref()

function shutdown() {
  try { saveBaseline() } catch { /* ignore */ }
  try { cap.close() } catch { /* ignore */ }
  const closing = honeypots ? honeypots.close().catch(() => {}) : Promise.resolve()
  Promise.all([closing, pushQueue]).finally(() => process.exit(0))
}
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
