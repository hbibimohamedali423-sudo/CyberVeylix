// CyberVeylix Sensor — écoute PASSIVE de LLDP (IEEE 802.1AB) et CDP (Cisco), sans aucune émission.
// Les switchs et points d'accès diffusent ces trames sur chaque port : le capteur entend celle du switch
// AUQUEL IL EST BRANCHÉ (nom, modèle, adresse de gestion, et le port où le capteur est connecté). Aucun
// identifiant, aucune modification d'équipement. Lectures bornées : toute trame malformée renvoie null.
import { macToString, ipToString } from './format.mjs'

const ETH_HEADER_LEN = 14
const ETHERTYPE_LLDP = 0x88cc
const LLDP_MULTICAST = ['0180c2000000', '0180c2000003', '0180c200000e'] // 802.1AB (et deux groupes voisins)
const CDP_MULTICAST = '01000ccccccc'

const clean = (buf, max = 120) => {
  const s = Buffer.isBuffer(buf) ? buf.toString('utf8') : String(buf || '')
  const out = s.replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').replace(/\s+/g, ' ').trim()
  return out ? out.slice(0, max) : null
}
const hex = (buf, a, b) => buf.subarray(a, b).toString('hex')

// Capacités LLDP (champ System Capabilities, 2 octets de bits).
function lldpCaps(buf) {
  // Champ de 2 octets (gros-boutiste) : Bridge 0x04, WLAN AP 0x08, Router 0x10, Telephone 0x20.
  const v = buf.length >= 2 ? buf.readUInt16BE(0) : (buf[0] || 0)
  return { bridge: !!(v & 0x04), wlanAp: !!(v & 0x08), router: !!(v & 0x10), telephone: !!(v & 0x20) }
}

// Sous-type d'identifiant de châssis / port → texte lisible (MAC, adresse réseau, ou chaîne).
function idValue(subtype, buf) {
  if (subtype === 4 && buf.length === 6) return macToString(buf, 0) // MAC
  if (subtype === 5 && buf.length === 5 && buf[0] === 1) return ipToString(buf, 1) // adresse réseau IPv4
  return clean(buf, 64)
}

// Trame LLDP : suite de TLV {type(7 bits), longueur(9 bits), valeur}. type 0 = fin.
export function parseLldp(frame) {
  if (!Buffer.isBuffer(frame) || frame.length < ETH_HEADER_LEN + 4) return null
  const dst = hex(frame, 0, 6)
  if (!LLDP_MULTICAST.includes(dst)) return null
  if (frame.readUInt16BE(12) !== ETHERTYPE_LLDP) return null // pas de VLAN ici : LLDP n'est jamais étiqueté
  const out = { source: 'lldp', senderMac: macToString(frame, 6), chassisId: null, portId: null, sysName: null, sysDescr: null, mgmtIp: null, caps: {} }
  let i = ETH_HEADER_LEN
  while (i + 2 <= frame.length) {
    const header = frame.readUInt16BE(i)
    const type = header >> 9
    const len = header & 0x1ff
    const at = i + 2
    if (type === 0 || at + len > frame.length) break
    const value = frame.subarray(at, at + len)
    if (type === 1 && len >= 2) out.chassisId = idValue(value[0], value.subarray(1))
    else if (type === 2 && len >= 2) out.portId = idValue(value[0], value.subarray(1))
    else if (type === 5) out.sysName = clean(value, 80)
    else if (type === 6) out.sysDescr = clean(value, 200)
    else if (type === 7 && len >= 4) out.caps = lldpCaps(value.subarray(2))
    else if (type === 8 && len >= 1) {
      // Management Address TLV : longueur(1) + sous-type(1 : 1 = IPv4) + adresse.
      const alen = value[0]
      if (alen === 5 && value[1] === 1 && len >= 6) out.mgmtIp = ipToString(value, 2)
    }
    i = at + len
  }
  if (!out.chassisId && !out.sysName) return null
  return out
}

// Trame CDP (Cisco) : en-tête SNAP (AA AA 03 00 00 0C 20 00) puis version(1) ttl(1) somme(2) puis TLV 16 bits.
export function parseCdp(frame) {
  if (!Buffer.isBuffer(frame) || frame.length < ETH_HEADER_LEN + 8) return null
  if (hex(frame, 0, 6) !== CDP_MULTICAST) return null
  // 802.3 : longueur ≤ 1500 à l'offset 12, puis LLC/SNAP.
  let p = ETH_HEADER_LEN
  if (frame.readUInt16BE(12) > 1500) return null
  if (hex(frame, p, p + 8) !== 'aaaa0300000c2000') return null
  p += 8
  const out = { source: 'cdp', senderMac: macToString(frame, 6), sysName: null, sysDescr: null, portId: null, mgmtIp: null, caps: {} }
  p += 4 // version + ttl + checksum
  while (p + 4 <= frame.length) {
    const type = frame.readUInt16BE(p)
    const len = frame.readUInt16BE(p + 2)
    if (len < 4 || p + len > frame.length) break
    const value = frame.subarray(p + 4, p + len)
    if (type === 0x0001) out.sysName = clean(value, 80) // Device ID
    else if (type === 0x0003) out.portId = clean(value, 64) // Port ID
    else if (type === 0x0005) out.sysDescr = clean(value, 200) // Version / plateforme
    else if (type === 0x0004 && value.length >= 4) { const n = value.readUInt32BE(0); out.caps = { router: !!(n & 0x01), bridge: !!(n & 0x02) || !!(n & 0x08), wlanAp: false, telephone: !!(n & 0x80) } }
    else if (type === 0x0002 && value.length >= 9 && value.readUInt32BE(0) >= 1) {
      // Addresses TLV : nombre(4) puis {protoType(1) protoLen(1) proto addrLen(2) addr}. On prend la 1re IPv4.
      if (value[5] === 0xcc && value.readUInt16BE(6) === 4 && value.length >= 12) out.mgmtIp = ipToString(value, 8)
    }
    p += len
  }
  if (!out.sysName) return null
  return out
}
