// CyberVeylix Sensor — liste de menaces (pure, testable sans réseau).
// Compare une adresse IP / un domaine observé à une liste d'indicateurs connus comme malveillants
// (serveurs de commande, domaines de malware…). La liste est fournie par un fichier local que le
// capteur met à jour ; ce module ne télécharge rien et n'émet aucune alerte, il répond seulement
// « connu malveillant ou non ». IPv4 uniquement pour les adresses et plages.

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

export function ipToInt(ip) {
  const m = IPV4.exec(String(ip).trim())
  if (!m) return null
  let n = 0
  for (let i = 1; i <= 4; i++) {
    const part = Number(m[i])
    if (part > 255) return null
    n = n * 256 + part
  }
  return n >>> 0
}

// « 203.0.113.0/24 » -> { lo, hi } (bornes entières incluses), ou null si invalide.
export function parseCidr(text) {
  const [ip, bitsText] = String(text).trim().split('/')
  const base = ipToInt(ip)
  if (base === null) return null
  const bits = Number(bitsText)
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null
  if (bits === 0) return { lo: 0, hi: 0xffffffff }
  const mask = (0xffffffff << (32 - bits)) >>> 0
  const lo = (base & mask) >>> 0
  const hi = (lo + (~mask >>> 0)) >>> 0
  return { lo, hi }
}

const normDomain = (d) => String(d).trim().toLowerCase().replace(/\.$/, '')

// Chaque entrée est une chaîne : IP, plage CIDR, ou domaine. Les lignes vides et les
// commentaires (#) sont ignorés. On peut ajouter « ip,étiquette » : l'étiquette est conservée.
export function parseThreatFeed(text = '') {
  const out = []
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const [value, ...rest] = line.split(/[,;\t]/)
    const label = rest.join(',').trim() || null
    if (value.trim()) out.push({ value: value.trim(), label })
  }
  return out
}

export function createThreatList(entries = []) {
  const ips = new Map() // int -> label
  const cidrs = [] // { lo, hi, label }
  const domains = new Map() // domaine normalisé -> label
  let count = 0

  const addEntry = (e) => {
    const value = typeof e === 'string' ? e : e?.value
    const label = typeof e === 'string' ? null : (e?.label ?? null)
    if (!value) return
    const text = String(value).trim()
    if (text.includes('/')) {
      const r = parseCidr(text)
      if (r) { cidrs.push({ ...r, label }); count++ }
      return
    }
    const asInt = ipToInt(text)
    if (asInt !== null) { ips.set(asInt, label); count++; return }
    // Sinon : domaine (on vérifie qu'il ressemble à un nom d'hôte).
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(text)) { domains.set(normDomain(text), label); count++ }
  }
  for (const e of entries) addEntry(e)

  function matchIp(ip) {
    const n = ipToInt(ip)
    if (n === null) return null
    if (ips.has(n)) return { kind: 'ip', value: ip, label: ips.get(n) }
    for (const c of cidrs) if (n >= c.lo && n <= c.hi) return { kind: 'cidr', value: ip, label: c.label }
    return null
  }

  // Correspondance domaine : exacte ou sur un domaine parent (sub.bad.com correspond à bad.com).
  function matchDomain(name) {
    if (!name) return null
    const d = normDomain(name)
    if (domains.has(d)) return { kind: 'domain', value: d, label: domains.get(d) }
    const parts = d.split('.')
    for (let i = 1; i < parts.length - 1; i++) {
      const parent = parts.slice(i).join('.')
      if (domains.has(parent)) return { kind: 'domain', value: d, label: domains.get(parent) }
    }
    return null
  }

  function match({ ip, name } = {}) {
    return (ip && matchIp(ip)) || (name && matchDomain(name)) || null
  }

  return { match, matchIp, matchDomain, size: () => count, addEntry }
}
