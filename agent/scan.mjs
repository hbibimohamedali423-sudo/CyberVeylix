// CyberVeylix — agent de découverte réseau (inventaire de VOTRE réseau uniquement)
import net from 'node:net'
import os from 'node:os'
import dns from 'node:dns/promises'
import { execFile, spawnSync } from 'node:child_process'
import { promisify } from 'node:util'
import { createHash } from 'node:crypto'
import { createClient } from '@supabase/supabase-js'
import { normalizeMac, createIndex, matchHost, devicePatch, sensitivePortAlerts, planOffline } from './lib/reconcile.mjs'

const run = promisify(execFile)
const WIN = process.platform === 'win32'
const env = process.env
const args = process.argv.slice(2)

// Certains réseaux n'arrivent pas à joindre le serveur avec la sélection automatique IPv4/IPv6 de Node
// (erreur « fetch failed »). On se relance donc une fois avec l'option qui corrige ce problème.
if (!process.execArgv.includes('--no-network-family-autoselection') && !env.CV_CHILD) {
  const r = spawnSync(process.execPath, ['--no-network-family-autoselection', ...process.argv.slice(1)], {
    stdio: 'inherit',
    env: { ...env, CV_CHILD: '1' },
  })
  process.exit(r.status ?? 1)
}

const NAMES = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3', 135: 'msrpc',
  139: 'netbios', 143: 'imap', 443: 'https', 445: 'smb', 554: 'rtsp', 993: 'imaps', 995: 'pop3s',
  1433: 'mssql', 3306: 'mysql', 3389: 'rdp', 5432: 'postgres', 5900: 'vnc', 8080: 'http-alt',
  8443: 'https-alt', 9100: 'jetdirect',
}

const die = (msg) => { console.error('✖ ' + msg); process.exit(1) }

const CHECK = args.includes('--check')
if (!CHECK && !args.includes('--yes')) die('Ajoutez --yes pour confirmer que vous êtes autorisé à scanner ce réseau (réseau personnel ou autorisation écrite).')
for (const k of ['SUPABASE_URL', 'SUPABASE_ANON_KEY', 'CV_EMAIL', 'CV_PASSWORD']) {
  if (!env[k]) die(`Variable manquante : ${k} (voir agent/.env.example)`)
}
const CIDR = args.find((a) => a.startsWith('--cidr='))?.split('=')[1] || env.SCAN_CIDR
if (!CHECK && !CIDR) die('Indiquez SCAN_CIDR (ex. 192.168.1.0/24) ou --cidr=...')

const toInt = (ip) => ip.split('.').reduce((a, o) => a * 256 + Number(o), 0)
const toIp = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.')

function parseCidr(c) {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(c)
  if (!m || m[1].split('.').some((o) => Number(o) > 255)) die('CIDR invalide (ex. 192.168.1.0/24)')
  const bits = Number(m[2])
  if (bits < 22 || bits > 30) die('Préfixe accepté : /22 à /30 (1 024 adresses maximum).')
  const size = 2 ** (32 - bits)
  const base = Math.floor(toInt(m[1]) / size) * size
  const priv = (base >= toInt('10.0.0.0') && base <= toInt('10.255.255.255'))
    || (base >= toInt('172.16.0.0') && base <= toInt('172.31.255.255'))
    || (base >= toInt('192.168.0.0') && base <= toInt('192.168.255.255'))
  if (!priv) die('Refusé : seules les plages privées (10/8, 172.16/12, 192.168/16) peuvent être scannées.')
  const hosts = []
  for (let i = base + 1; i < base + size - 1; i++) hosts.push(toIp(i))
  return {
    cidr: `${toIp(base)}/${bits}`,
    hosts,
    inRange: (ip) => { const n = toInt(ip); return n > base && n < base + size - 1 },
  }
}

async function pool(items, n, fn) {
  const out = []
  let i = 0
  await Promise.all(Array.from({ length: n }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k]) }
  }))
  return out
}

async function ping(ip) {
  try {
    const a = WIN ? ['-n', '1', '-w', '800', ip] : ['-c', '1', '-W', '1', ip]
    const { stdout } = await run('ping', a, { timeout: 4000 })
    return WIN ? /TTL=/i.test(stdout) : true
  } catch { return false }
}

function addArpLine(map, line) {
  const r = /(\d+\.\d+\.\d+\.\d+)\D+((?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})/i.exec(line)
  if (!r) return
  const mac = normalizeMac(r[2])
  if (!mac || mac === 'ff:ff:ff:ff:ff:ff' || mac === '00:00:00:00:00:00') return
  if (mac.startsWith('01:00:5e') || mac.startsWith('33:33')) return
  map.set(r[1], mac)
}

async function arpTable() {
  const map = new Map()
  try {
    const { stdout } = await run('arp', ['-a'], { timeout: 5000, maxBuffer: 1_000_000 })
    for (const line of stdout.split(/\r?\n/)) addArpLine(map, line)
  } catch { /* arp indisponible */ }
  if (!WIN) {
    try {
      const { stdout } = await run('ip', ['neigh', 'show'], { timeout: 5000, maxBuffer: 1_000_000 })
      for (const line of stdout.split(/\r?\n/)) addArpLine(map, line)
    } catch { /* ip neigh indisponible */ }
  }
  return map
}

function defaultGatewayFromRoute(stdout) {
  let best = null
  for (const line of stdout.split(/\r?\n/)) {
    const m = /^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+(\d+)/.exec(line)
    if (!m) continue
    const metric = Number(m[2])
    if (!best || metric < best.metric) best = { ip: m[1], metric }
  }
  return best?.ip || null
}

async function defaultGateway() {
  try {
    if (WIN) {
      const { stdout } = await run('route', ['print', '-4'], { timeout: 5000, maxBuffer: 1_000_000 })
      const ip = defaultGatewayFromRoute(stdout)
      if (ip) return ip
      const fallback = await run('route', ['print'], { timeout: 5000, maxBuffer: 1_000_000 })
      return defaultGatewayFromRoute(fallback.stdout)
    }
    const { stdout } = await run('ip', ['route', 'show', 'default'], { timeout: 5000, maxBuffer: 1_000_000 })
    const m = /default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})/.exec(stdout)
    return m?.[1] || null
  } catch {
    return null
  }
}

async function ssidName() {
  if (WIN) {
    try {
      const { stdout } = await run('netsh', ['wlan', 'show', 'interfaces'], { timeout: 5000, maxBuffer: 1_000_000 })
      const m = /^\s*SSID\s*:\s*(.+?)\s*$/im.exec(stdout)
      const value = m?.[1]?.trim()
      if (value) return value
    } catch { /* netsh indisponible */ }
    return null
  }
  try {
    const { stdout } = await run('iwgetid', ['-r'], { timeout: 5000, maxBuffer: 100_000 })
    const value = stdout.trim()
    if (value) return value
  } catch { /* iwgetid indisponible */ }
  try {
    const { stdout } = await run('nmcli', ['-t', '-f', 'active,ssid', 'dev', 'wifi'], { timeout: 5000, maxBuffer: 500_000 })
    const line = stdout.split(/\r?\n/).find((x) => x.startsWith('yes:'))
    const value = line?.slice(4).trim()
    if (value) return value
  } catch { /* nmcli indisponible */ }
  return null
}

const fingerprintOf = (cidr, gatewayMac) =>
  createHash('sha256').update(`${cidr}|${gatewayMac || ''}`).digest('hex').slice(0, 8)

async function detectNetworkIdentity() {
  const gatewayIp = await defaultGateway()
  if (gatewayIp) await ping(gatewayIp)
  const arp = await arpTable()
  const gatewayMac = gatewayIp ? arp.get(gatewayIp) || null : null
  const ssid = await ssidName()
  if (!gatewayMac && !ssid) {
    die('Identité du réseau introuvable : ni la MAC de la passerelle ni le SSID Wi-Fi ne sont disponibles. '
      + 'Scan annulé : aucune donnée n’a été écrite.')
  }
  if (!gatewayMac) {
    console.warn('⚠ WARNING : MAC de passerelle indisponible. Le SSID est utilisé comme identité de secours : '
      + 'cette identité est faible (SSID réutilisable ou masqué).')
  }
  return { gatewayIp, gatewayMac, ssid, arp }
}

const probe = (host, port, ms = 800) => new Promise((res) => {
  const s = new net.Socket()
  let done = false
  const end = (ok) => { if (!done) { done = true; s.destroy(); res(ok) } }
  s.setTimeout(ms)
  s.once('connect', () => end(true))
  s.once('timeout', () => end(false))
  s.once('error', () => end(false))
  s.connect(port, host)
})

const scanPorts = async (ip) =>
  (await pool(Object.keys(NAMES).map(Number), 12, (p) => probe(ip, p).then((ok) => (ok ? p : null)))).filter(Boolean)

async function hostname(ip) {
  try {
    const [n] = await Promise.race([dns.reverse(ip), new Promise((_, rej) => setTimeout(rej, 1500))])
    return n.split('.')[0]
  } catch { return null }
}

const SENSITIVE = {
  21: ['h', 'FTP, non chiffré'],
  23: ['h', 'Telnet, non chiffré'],
  3389: ['m', 'Bureau à distance RDP'],
  5900: ['h', 'VNC, accès à distance'],
  1433: ['m', 'base de données SQL Server'],
  3306: ['m', 'base de données MySQL'],
  5432: ['m', 'base de données PostgreSQL'],
}
const NO_ALERTS = args.includes('--no-alerts')

const must = (r) => {
  if (r.error) {
    const hint = /column|relation|schema|constraint|conflict/i.test(r.error.message)
      ? ' (avez-vous exécuté supabase/schema_scan.sql, schema_hardening.sql, schema_n2_prep.sql et schema_status.sql ?)'
      : ''
    die('Erreur base de données : ' + r.error.message + hint)
  }
  return r.data
}

const sb = createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, { auth: { persistSession: false } })

async function login() {
  let last
  for (let i = 1; i <= 3; i++) {
    const { error } = await sb.auth.signInWithPassword({ email: env.CV_EMAIL, password: env.CV_PASSWORD })
    if (!error) return
    last = error
    if (!/fetch failed|timeout|network/i.test(error.message)) break
    console.log(`    connexion impossible (tentative ${i}/3), nouvel essai…`)
    await new Promise((r) => setTimeout(r, 2000 * i))
  }
  const m = last.message
  if (/invalid login/i.test(m)) {
    die('Identifiants refusés : CV_EMAIL / CV_PASSWORD ne correspondent pas à un compte de l’application. '
      + 'Utilisez le même compte que dans la page de connexion (si le mot de passe contient #, mettez-le entre guillemets dans agent/.env).')
  }
  if (/fetch failed|timeout|network/i.test(m)) {
    die('Serveur injoignable : vérifiez SUPABASE_URL dans agent/.env, votre connexion Internet, un pare-feu ou un antivirus qui bloque node.exe.')
  }
  die('Connexion refusée : ' + m)
}

if (CHECK) {
  console.log('Configuration lue : OK')
  console.log(`Serveur : ${env.SUPABASE_URL}`)
  await login()
  console.log('Connexion Supabase : OK')
  const n = await sb.from('networks')
    .select('id,user_id,name,cidr,gateway_ip,gateway_mac,ssid,scan_allowed,last_seen', { count: 'exact', head: true })
  console.log(n.error ? '✖ Table networks : ' + n.error.message : `Table networks : OK (${n.count} réseau(x))`)
  const d = await sb.from('devices')
    .select('network_id,type,role,role_evidence,discovery_source', { count: 'exact', head: true })
  console.log(d.error ? '✖ Table devices (colonnes N2) : ' + d.error.message : `Table devices (colonnes N2) : OK (${d.count} appareil(s))`)
  const v = await sb.from('services').select('id', { count: 'exact', head: true })
  console.log(v.error ? '✖ Table services : ' + v.error.message + ' (exécutez supabase/schema_scan.sql)' : 'Table services : OK')
  const a = await sb.from('alerts')
    .select('network_id,device_id', { count: 'exact', head: true })
  console.log(a.error ? '✖ Table alerts (network_id, device_id) : ' + a.error.message + ' (exécutez supabase/schema_n2_prep.sql)' : 'Table alerts (network_id, device_id) : OK')
  // Colonnes de suivi utilisées par les boutons « Prise en compte » / « Résoudre » et la note.
  for (const [table, cols] of [['alerts', 'status,acknowledged_at,resolved_at'], ['vulnerabilities', 'status,acknowledged_at,resolved_at,note']]) {
    const r = await sb.from(table).select(cols, { count: 'exact', head: true })
    console.log(r.error ? `✖ Table ${table} (suivi) : ${r.error.message} (exécutez supabase/schema_status.sql)` : `Table ${table} (statut, dates${table === 'vulnerabilities' ? ', note' : ''}) : OK`)
  }
  await sb.auth.signOut()
  process.exit(0)
}

const { cidr: NET_CIDR, hosts, inRange } = parseCidr(CIDR)
console.log(`Réseau ${NET_CIDR} — ${hosts.length} adresses`)

// --local-only : pour les lancements automatiques. Si cet ordinateur n'est pas sur le réseau cible
// (autre Wi-Fi, déplacement), on ne scanne rien et on ne modifie aucune donnée.
if (args.includes('--local-only')) {
  const local = Object.values(os.networkInterfaces()).flat()
    .filter((i) => i && i.family === 'IPv4' && !i.internal)
  if (!local.some((i) => inRange(i.address))) {
    console.log('Cet ordinateur n’est pas connecté au réseau cible : scan ignoré (aucune donnée modifiée).')
    process.exit(0)
  }
}

// L'identité réseau est vérifiée AVANT toute écriture. Sans MAC de passerelle ni SSID,
// le scan est refusé : on ne crée ni ne scanne un réseau non identifiable.
const identity = await detectNetworkIdentity()
const fingerprint = fingerprintOf(NET_CIDR, identity.gatewayMac)
console.log(`Empreinte réseau : ${fingerprint}${identity.gatewayMac ? '' : ' (identité SSID, faible)'}`)

await login()

async function findNetworkRows({ cidr, gatewayMac, ssid, weakOnly = false }) {
  if (gatewayMac) {
    // La MAC peut avoir été saisie avec des tirets ou en majuscules : on compare sous forme normalisée.
    const rows = must(await sb.from('networks').select('*').eq('cidr', cidr)) || []
    return rows.filter((n) => normalizeMac(n.gateway_mac) === gatewayMac)
  }
  if (ssid) {
    let query = sb.from('networks').select('*').eq('cidr', cidr)
    if (weakOnly) query = query.is('gateway_mac', null)
    return must(await query.eq('ssid', ssid)) || []
  }
  return []
}

let network
{
  const now = new Date().toISOString()
  let rows = await findNetworkRows({ cidr: NET_CIDR, gatewayMac: identity.gatewayMac, ssid: identity.ssid })
  // Une ancienne ligne créée en secours SSID peut être enrichie avec la MAC désormais connue.
  if (!rows.length && identity.gatewayMac && identity.ssid) {
    const weak = await findNetworkRows({ cidr: NET_CIDR, gatewayMac: null, ssid: identity.ssid, weakOnly: true })
    if (weak.length === 1) rows = weak
  }

  if (!rows.length) {
    const created = await sb.from('networks').insert({
      name: identity.ssid || NET_CIDR,
      cidr: NET_CIDR,
      gateway_ip: identity.gatewayIp,
      gateway_mac: identity.gatewayMac,
      ssid: identity.ssid,
      scan_allowed: true,
      last_seen: now,
    }).select('*').single()
    network = must(created)
    console.log(`Nouveau réseau : ${network.name} — ${network.cidr}`)
  } else {
    network = rows[0]
    if (network.scan_allowed !== true) {
      console.log(`Scan désactivé pour le réseau « ${network.name} » (${network.cidr}) : aucune donnée modifiée.`)
      await sb.auth.signOut()
      process.exit(0)
    }
    const patch = { last_seen: now }
    if (!network.gateway_ip && identity.gatewayIp) patch.gateway_ip = identity.gatewayIp
    if (!network.ssid && identity.ssid) patch.ssid = identity.ssid
    if (!network.gateway_mac && identity.gatewayMac) patch.gateway_mac = identity.gatewayMac
    network = { ...network, ...patch }
    must(await sb.from('networks').update(patch).eq('id', network.id))
    console.log(`Réseau existant : ${network.name} — ${network.cidr}`)
  }
}

console.log('1/3 Découverte (ping + ARP)…')
const up = new Set((await pool(hosts, 50, async (ip) => ((await ping(ip)) ? ip : null))).filter(Boolean))
const arp = await arpTable()
for (const ip of arp.keys()) if (inRange(ip)) up.add(ip)
console.log(`    ${up.size} hôte(s) actif(s)`)

console.log('2/3 Ports TCP courants…')
const alive = await pool([...up].sort((a, b) => toInt(a) - toInt(b)), 8, async (ip) => ({
  ip, mac: arp.get(ip) || null, ports: await scanPorts(ip), name: await hostname(ip),
}))
for (const h of alive) console.log(`    ${h.ip.padEnd(15)} ${(h.name || '-').padEnd(20)} ${h.ports.join(',') || '-'}`)

console.log('3/3 Enregistrement…')
const existing = must(await sb.from('devices').select('*').eq('network_id', network.id)) || []
const unassigned = must(await sb.from('devices').select('id,ip').is('network_id', null)) || []
const unassignedIps = new Set(unassigned.map((d) => d.ip).filter(Boolean))
// Identité d'un appareil = sa MAC (voir agent/lib/reconcile.mjs, testé par scripts/agent-check.mjs) :
// une MAC connue est suivie même si son IP change ; une MAC nouvelle sur une IP connue est un NOUVEL
// appareil (l'ancien n'est jamais écrasé) ; une même MAC sur deux IP ne fait pas alterner un enregistrement.
const index = createIndex(existing)
const touched = new Set()
const now = new Date().toISOString()
// Premier inventaire de CE réseau : on enregistre tout comme référence, sans créer d'alertes.
const baseline = existing.length === 0
let alertCount = 0
let alertErrors = 0

// Alertes enregistrées immédiatement, appareil par appareil : si le scan s'interrompt plus loin
// (réseau, base), les alertes déjà dues ne sont plus perdues.
async function raise(list, deviceId) {
  if (baseline || NO_ALERTS || !list.length) return
  const r = await sb.from('alerts').insert(list.map((a) => ({ ...a, device_id: deviceId, network_id: network.id })))
  if (r.error) {
    alertErrors++
    console.log('⚠ Alertes non enregistrées : ' + r.error.message + ' (avez-vous exécuté supabase/schema_n2_prep.sql ?)')
  } else {
    alertCount += list.length
  }
}

for (const h of alive) {
  const match = matchHost(h, index, touched)
  const who = `${h.ip}${h.name ? ' — ' + h.name : ''}`
  // Ne jamais adopter une ligne network_id = null et ne pas créer de doublon :
  // le propriétaire l'assigne dans l'interface, puis le prochain scan la retrouve.
  if (!match.device && unassignedIps.has(h.ip)) {
    console.log(`    Candidat non assigné : ${h.ip}`)
    continue
  }
  const hostAlerts = []
  let id
  let prev = []
  if (match.device) {
    id = match.device.id
    // MAC écrite seulement si elle manquait ; IP mise à jour si la MAC connue a changé d'adresse.
    const patch = devicePatch(h, match.device, now)
    if (!match.device.discovery_source) patch.discovery_source = 'agent'
    must(await sb.from('devices').update(patch).eq('id', id))
    prev = (must(await sb.from('services').select('port').eq('device_id', id)) || []).map((x) => x.port)
  } else {
    const row = {
      name: h.name || h.ip,
      ip: h.ip,
      mac: normalizeMac(h.mac),
      network_id: network.id,
      // Aucun type deviné : null reste « inconnu » tant que l'utilisateur ne renseigne pas.
      type: null,
      role: null,
      status: 'on',
      last_seen: now,
      discovery_source: 'agent',
    }
    id = must(await sb.from('devices').insert(row).select('id').single()).id
    index.add({ id, ...row })
    let detail = who
    if (match.replaced) {
      detail += ` — a pris l'adresse ${h.ip} utilisée auparavant par ${match.replaced.name || 'un autre appareil'}`
        + ` (${normalizeMac(match.replaced.mac)}). Changement d'appareil ou usurpation d'adresse.`
    }
    hostAlerts.push({ title: 'Nouvel appareil détecté', detail, severity: 'm' })
  }
  touched.add(id)
  if (unassignedIps.has(h.ip)) console.log(`    Candidat non assigné : ${h.ip}`)
  hostAlerts.push(...sensitivePortAlerts(h, prev, SENSITIVE))
  await raise(hostAlerts, id)
  // upsert (nécessite l'index unique services_device_port_uq), puis suppression des seuls ports fermés :
  // une coupure en cours de route ne fait plus perdre toutes les données de l'appareil.
  if (h.ports.length) {
    must(await sb.from('services').upsert(
      h.ports.map((p) => ({ device_id: id, port: p, protocol: 'tcp', service: NAMES[p] })),
      { onConflict: 'device_id,port,protocol' },
    ))
  }
  const closed = prev.filter((p) => !h.ports.includes(p))
  if (closed.length) {
    must(await sb.from('services').delete().eq('device_id', id).in('port', closed))
  }
}

// Un appareil absent n'est déclaré « Hors ligne » qu'après 90 minutes sans être vu
// (évite le va-et-vient des téléphones et objets connectés qui s'endorment entre deux scans).
// L'absence se juge par appareil rapproché, pas par IP ; un appareil ajouté à la main et jamais vu
// par l'agent (last_seen vide) n'est jamais déclaré « Hors ligne ».
const GRACE_MS = 90 * 60 * 1000
const { off: offIds, pending } = planOffline(existing, touched, inRange, Date.now(), GRACE_MS)
for (const offId of offIds) {
  const d = existing.find((x) => x.id === offId)
  must(await sb.from('devices').update({ status: 'off', ...(d.discovery_source ? {} : { discovery_source: 'agent' }) }).eq('id', offId))
}
const off = offIds.length

if (baseline) {
  console.log('    Premier inventaire : aucune alerte créée (référence de départ).')
} else if (NO_ALERTS) {
  console.log('    Alertes désactivées pour ce lancement (--no-alerts).')
} else if (alertCount) {
  console.log(`    ${alertCount} alerte(s) créée(s)`)
} else if (!alertErrors) {
  console.log('    Aucune nouvelle alerte.')
}

await sb.auth.signOut()
console.log(`✔ Terminé : ${alive.length} appareil(s) en ligne, ${off} passé(s) hors ligne.`)
if (pending) console.log(`  ${pending} appareil(s) absent(s) depuis moins de 90 min : statut inchangé.`)
console.log('  Les appareils sans type connu restent « Inconnu » : corrigez-les dans « Réseau & Appareils ».')
