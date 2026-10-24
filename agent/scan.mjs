// CyberVeylix — agent de découverte réseau (inventaire de VOTRE réseau uniquement)
import net from 'node:net'
import dns from 'node:dns/promises'
import { execFile, spawnSync } from 'node:child_process'
import { promisify } from 'node:util'
import { createClient } from '@supabase/supabase-js'

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
  return { hosts, inRange: (ip) => { const n = toInt(ip); return n > base && n < base + size - 1 } }
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

async function arpTable() {
  const m = new Map()
  try {
    const { stdout } = await run('arp', ['-a'], { timeout: 5000 })
    for (const line of stdout.split('\n')) {
      const r = /(\d+\.\d+\.\d+\.\d+)\D+((?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})/i.exec(line)
      if (!r) continue
      const mac = r[2].toLowerCase().replaceAll('-', ':')
      if (mac === 'ff:ff:ff:ff:ff:ff' || mac.startsWith('01:00:5e')) continue
      m.set(r[1], mac)
    }
  } catch { /* arp indisponible */ }
  return m
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

const guessType = (p) =>
  p.includes(554) ? 'Caméra'
    : p.some((x) => [3389, 445, 135, 139].includes(x)) ? 'Poste'
      : p.some((x) => [22, 80, 443, 53, 3306, 5432, 1433, 8080, 8443].includes(x)) ? 'Serveur'
        : 'Poste'

const must = (r) => {
  if (r.error) {
    const hint = /column|relation|schema/i.test(r.error.message) ? ' (avez-vous exécuté supabase/schema_scan.sql ?)' : ''
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
  const d = await sb.from('devices').select('id', { count: 'exact', head: true })
  console.log(d.error ? '✖ Table devices : ' + d.error.message : `Table devices : OK (${d.count} appareil(s))`)
  const v = await sb.from('services').select('id', { count: 'exact', head: true })
  console.log(v.error ? '✖ Table services : ' + v.error.message + ' (exécutez supabase/schema_scan.sql)' : 'Table services : OK')
  await sb.auth.signOut()
  process.exit(0)
}

const { hosts, inRange } = parseCidr(CIDR)
console.log(`Réseau ${CIDR} — ${hosts.length} adresses`)
await login()

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
const existing = must(await sb.from('devices').select('id,ip,status')) || []
const byIp = new Map()
for (const d of existing) if (d.ip && !byIp.has(d.ip)) byIp.set(d.ip, d)
const now = new Date().toISOString()

for (const h of alive) {
  const ex = byIp.get(h.ip)
  let id
  if (ex) {
    must(await sb.from('devices').update({ status: 'on', mac: h.mac, last_seen: now }).eq('id', ex.id))
    id = ex.id
  } else {
    id = must(await sb.from('devices')
      .insert({ name: h.name || h.ip, ip: h.ip, mac: h.mac, type: guessType(h.ports), status: 'on', last_seen: now })
      .select('id').single()).id
  }
  must(await sb.from('services').delete().eq('device_id', id))
  if (h.ports.length) {
    must(await sb.from('services').insert(h.ports.map((p) => ({ device_id: id, port: p, service: NAMES[p] }))))
  }
}

const seen = new Set(alive.map((h) => h.ip))
let off = 0
for (const d of existing) {
  if (d.ip && inRange(d.ip) && !seen.has(d.ip) && d.status !== 'off') {
    must(await sb.from('devices').update({ status: 'off' }).eq('id', d.id))
    off++
  }
}

await sb.auth.signOut()
console.log(`✔ Terminé : ${alive.length} appareil(s) en ligne, ${off} passé(s) hors ligne.`)
console.log('  Le type des nouveaux appareils est une estimation : corrigez-le dans « Réseau & Appareils ».')
