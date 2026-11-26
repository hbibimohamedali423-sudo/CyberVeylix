// CyberVeylix Sensor — analyse des réponses de l'API FortiGate (FortiOS), pure et testable sans réseau.
//
// FortiOS renvoie du JSON dont les noms de champs varient selon la version. On lit donc plusieurs
// noms possibles et on tolère les champs manquants. Les formes exactes seront confirmées lors de
// l'essai sur un vrai FortiGate ; l'analyse reste défensive pour ne jamais planter sur une réponse.
// Lecture seule : ce module ne fait qu'interpréter des données déjà reçues.

const norm = (v) => (v === undefined || v === null ? null : v)
const first = (obj, keys) => { for (const k of keys) if (obj && obj[k] !== undefined && obj[k] !== null && obj[k] !== '') return obj[k]; return null }

export function normMac(mac) {
  if (!mac) return null
  const hex = String(mac).toLowerCase().replace(/[^0-9a-f]/g, '')
  if (hex.length !== 12) return null
  return hex.match(/.{2}/g).join(':')
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
export function isIpv4(ip) {
  const m = IPV4.exec(String(ip || '').trim())
  return Boolean(m) && m.slice(1).every((p) => Number(p) <= 255)
}

// Masque « 255.255.255.0 » -> longueur de préfixe (24), ou null.
export function maskToPrefix(mask) {
  if (!isIpv4(mask)) return null
  const bits = mask.split('.').map(Number).map((n) => n.toString(2).padStart(8, '0')).join('')
  if (!/^1*0*$/.test(bits)) return null // masque non contigu
  return bits.indexOf('0') === -1 ? 32 : bits.indexOf('0')
}

// FortiOS renvoie « results » sous forme de tableau ou d'objet { clé: valeur }. On ramène à un tableau.
export function toArray(payload) {
  const r = payload && payload.results !== undefined ? payload.results : payload
  if (Array.isArray(r)) return r
  if (r && typeof r === 'object') return Object.entries(r).map(([k, v]) => (v && typeof v === 'object' ? { name: k, ...v } : { name: k, value: v }))
  return []
}

// Interfaces et VLAN (cmdb/system/interface). « ip » peut être « 1.2.3.4 255.255.255.0 ».
export function parseInterfaces(payload) {
  const out = []
  for (const row of toArray(payload)) {
    const name = first(row, ['name', 'ifname'])
    if (!name) continue
    const rawVlan = first(row, ['vlanid', 'vlan_id', 'vlan'])
    const vlan = rawVlan != null && Number(rawVlan) > 0 ? Number(rawVlan) : null
    let ip = null
    let cidr = null
    const rawIp = first(row, ['ip', 'ipv4', 'address'])
    if (typeof rawIp === 'string' && rawIp.trim()) {
      const [addr, mask] = rawIp.trim().split(/\s+/)
      if (isIpv4(addr) && addr !== '0.0.0.0') {
        ip = addr
        const p = mask ? maskToPrefix(mask) : null
        cidr = p != null ? `${addr}/${p}` : null
      }
    }
    out.push({ name: String(name), vlan, parent: norm(first(row, ['interface', 'parent'])), ip, cidr })
  }
  return out
}

// Baux DHCP (monitor/system/dhcp) : chaque appareil ayant reçu une adresse, dans tous les VLAN.
export function parseDhcpLeases(payload) {
  const out = []
  for (const row of toArray(payload)) {
    const ip = first(row, ['ip', 'ipaddr', 'address'])
    const mac = normMac(first(row, ['mac', 'macaddr', 'hwaddr']))
    if (!isIpv4(ip) && !mac) continue
    out.push({
      ip: isIpv4(ip) ? ip : null,
      mac,
      hostname: norm(first(row, ['hostname', 'host', 'name'])),
      iface: norm(first(row, ['interface', 'ipsecvm', 'vdom'])),
      expires: norm(first(row, ['expire_time', 'expire', 'expiry'])),
    })
  }
  return out
}

// Table ARP (monitor/network/arp) : correspondance IP <-> MAC vue par le pare-feu (tous VLAN).
export function parseArpTable(payload) {
  const out = []
  for (const row of toArray(payload)) {
    const ip = first(row, ['ip', 'address'])
    const mac = normMac(first(row, ['mac', 'macaddr', 'hwaddr']))
    if (!isIpv4(ip) || !mac) continue
    out.push({ ip, mac, iface: norm(first(row, ['interface', 'ifname'])) })
  }
  return out
}

// Sessions actives (monitor/firewall/session) : « qui parle à qui » -> flux pour le moteur de comportement.
export function parseSessions(payload) {
  const out = []
  for (const row of toArray(payload)) {
    const src = first(row, ['source_address', 'src', 'saddr', 'srcip', 'source_ip'])
    const dst = first(row, ['destination_address', 'dst', 'daddr', 'dstip', 'destination_ip'])
    if (!isIpv4(src) || !isIpv4(dst)) continue
    const dstPort = first(row, ['destination_port', 'dport', 'dstport', 'destination_ports'])
    const protoRaw = first(row, ['protocol', 'proto'])
    out.push({
      src,
      dst,
      srcPort: toPort(first(row, ['source_port', 'sport', 'srcport'])),
      dstPort: toPort(dstPort),
      proto: protoRaw != null ? String(protoRaw).toLowerCase() : null,
    })
  }
  return out
}

function toPort(v) {
  const raw = Array.isArray(v) ? v[0] : v
  if (raw === null || raw === undefined || raw === '') return null
  const n = Number(raw)
  return Number.isInteger(n) && n >= 0 && n <= 65535 ? n : null
}

// Sessions -> flux pour behavior.observe (on ne garde que ce qui nous intéresse).
export const sessionsToFlows = (sessions, ts) => sessions.map((s) => ({ src: s.src, dst: s.dst, dstPort: s.dstPort, ts }))
