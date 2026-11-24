// CyberVeylix Sensor — OID standard et décodage des tables SNMP (pur, testable sans réseau).
// Uniquement des MIB communes à toutes les marques (Cisco, Aruba, TP-Link, D-Link…) : SNMPv2-MIB, IF-MIB,
// BRIDGE-MIB, Q-BRIDGE-MIB, LLDP-MIB, IP-MIB ; plus CISCO-CDP-MIB et CISCO-VTP-MIB pour les anciens Cisco.
// Entrée : listes de { oid: '1.3.6…', value } telles que renvoyées par net-snmp. Les valeurs venant des
// équipements ne sont pas de confiance : longueurs vérifiées, textes nettoyés et bornés.

export const OID = {
  sysDescr: '1.3.6.1.2.1.1.1.0',
  sysObjectID: '1.3.6.1.2.1.1.2.0',
  sysName: '1.3.6.1.2.1.1.5.0',
  bridgeAddress: '1.3.6.1.2.1.17.1.1.0',
  lldpLocChassisId: '1.0.8802.1.1.2.1.3.2.0',
  lldpLocSysCapEnabled: '1.0.8802.1.1.2.1.3.6.0',
  ifDescr: '1.3.6.1.2.1.2.2.1.2',
  ifName: '1.3.6.1.2.1.31.1.1.1.1',
  basePortIfIndex: '1.3.6.1.2.1.17.1.4.1.2',
  dot1dTpFdbPort: '1.3.6.1.2.1.17.4.3.1.2',
  dot1qTpFdbPort: '1.3.6.1.2.1.17.7.1.2.2.1.2',
  lldpLocPortId: '1.0.8802.1.1.2.1.3.7.1.3',
  lldpLocPortDesc: '1.0.8802.1.1.2.1.3.7.1.4',
  lldpRem: '1.0.8802.1.1.2.1.4.1.1',
  lldpRemManAddrIfSubtype: '1.0.8802.1.1.2.1.4.2.1.3',
  cdpCache: '1.3.6.1.4.1.9.9.23.1.2.1.1',
  vtpVlanState: '1.3.6.1.4.1.9.9.46.1.3.1.1.2',
  ipNetToMediaPhysAddress: '1.3.6.1.2.1.4.22.1.2',
}

const hex2 = (n) => n.toString(16).padStart(2, '0')
export const macFromBytes = (b) => (Buffer.isBuffer(b) && b.length === 6 ? [...b].map(hex2).join(':') : null)
export const macFromParts = (parts) => (parts.length === 6 && parts.every((n) => Number.isInteger(n) && n >= 0 && n <= 255) ? parts.map(hex2).join(':') : null)
const ipv4FromBytes = (b) => (Buffer.isBuffer(b) && b.length === 4 ? [...b].join('.') : null)

export function cleanSnmpText(v, max = 120) {
  if (v === null || v === undefined) return null
  const s = (Buffer.isBuffer(v) ? v.toString('utf8') : String(v)).replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').replace(/\s+/g, ' ').trim()
  return s ? s.slice(0, max) : null
}
const num = (v) => (typeof v === 'number' ? v : Buffer.isBuffer(v) ? null : Number.isFinite(Number(v)) ? Number(v) : null)

// Suffixe numérique de l'OID après la base, ou null si l'OID n'est pas sous la base.
export function indexAfter(oid, base) {
  const o = String(oid)
  if (!o.startsWith(base + '.')) return null
  const parts = o.slice(base.length + 1).split('.').map(Number)
  return parts.every((n) => Number.isInteger(n) && n >= 0) ? parts : null
}

// LLDP sysCapEnabled (BITS) : premier octet, bit de poids fort = capacité 0.
export function lldpCaps(v) {
  const b = Buffer.isBuffer(v) ? v[0] || 0 : 0
  return { other: !!(b & 0x80), repeater: !!(b & 0x40), bridge: !!(b & 0x20), wlanAp: !!(b & 0x10), router: !!(b & 0x08), telephone: !!(b & 0x04), station: !!(b & 0x01) }
}
// CDP cdpCacheCapabilities : entier sur 4 octets (Router 0x01, Bridge 0x02, Switch 0x08, Host 0x10, Phone 0x80).
export function cdpCaps(v) {
  const n = Buffer.isBuffer(v) && v.length >= 4 ? v.readUInt32BE(0) : num(v) || 0
  return { router: !!(n & 0x01), bridge: !!(n & 0x02) || !!(n & 0x08), wlanAp: false, telephone: !!(n & 0x80), station: !!(n & 0x10) }
}

export function parseIfNames(ifName = [], ifDescr = []) {
  const names = new Map()
  for (const { oid, value } of ifDescr) { const i = indexAfter(oid, OID.ifDescr); if (i && i.length === 1) names.set(i[0], cleanSnmpText(value, 64)) }
  for (const { oid, value } of ifName) { const i = indexAfter(oid, OID.ifName); const t = cleanSnmpText(value, 64); if (i && i.length === 1 && t) names.set(i[0], t) }
  return names
}

export function parseBasePorts(vbs = []) {
  const m = new Map()
  for (const { oid, value } of vbs) { const i = indexAfter(oid, OID.basePortIfIndex); const n = num(value); if (i && i.length === 1 && n) m.set(i[0], n) }
  return m
}

// FDB : { mac, bridgePort, vlan } ; le port 0 (l'équipement lui-même) est ignoré.
export function parseFdb(qVbs = [], dVbs = []) {
  const out = []
  for (const { oid, value } of qVbs) {
    const i = indexAfter(oid, OID.dot1qTpFdbPort)
    const port = num(value)
    if (!i || i.length !== 7 || !port) continue
    const mac = macFromParts(i.slice(1))
    if (mac) out.push({ mac, bridgePort: port, vlan: i[0] })
  }
  if (out.length) return out
  for (const { oid, value } of dVbs) {
    const i = indexAfter(oid, OID.dot1dTpFdbPort)
    const port = num(value)
    if (!i || i.length !== 6 || !port) continue
    const mac = macFromParts(i)
    if (mac) out.push({ mac, bridgePort: port, vlan: null })
  }
  return out
}

function chassisToMac(subtype, value) {
  if (subtype === 4) return macFromBytes(value) // macAddress
  return null
}

// LLDP : voisins par port local ; mgmt : adresses IPv4 de gestion annoncées (découverte des autres switchs).
export function parseLldp({ rem = [], locPortId = [], locPortDesc = [], manAddr = [] } = {}) {
  const locNames = new Map()
  for (const { oid, value } of locPortDesc) { const i = indexAfter(oid, OID.lldpLocPortDesc); const t = cleanSnmpText(value, 64); if (i && i.length === 1 && t) locNames.set(i[0], t) }
  for (const { oid, value } of locPortId) { const i = indexAfter(oid, OID.lldpLocPortId); const t = cleanSnmpText(value, 64); if (i && i.length === 1 && t && !locNames.has(i[0])) locNames.set(i[0], t) }
  const rows = new Map()
  for (const { oid, value } of rem) {
    const i = indexAfter(oid, OID.lldpRem)
    if (!i || i.length !== 4) continue // colonne.timeMark.localPortNum.remIndex (LLDP-MIB lldpRemEntry)
    const [col, , localPort, remIndex] = i
    const key = `${localPort}.${remIndex}`
    if (!rows.has(key)) rows.set(key, { localPortNum: localPort })
    const r = rows.get(key)
    if (col === 4) r.chassisSubtype = num(value)
    else if (col === 5) r.chassisRaw = value
    else if (col === 7) r.portId = cleanSnmpText(value, 64)
    else if (col === 8) r.portDesc = cleanSnmpText(value, 64)
    else if (col === 9) r.sysName = cleanSnmpText(value, 80)
    else if (col === 10) r.sysDescr = cleanSnmpText(value, 200)
    else if (col === 12) r.caps = lldpCaps(value)
  }
  const mgmt = new Map()
  for (const { oid } of manAddr) {
    const i = indexAfter(oid, OID.lldpRemManAddrIfSubtype)
    // timeMark.localPort.remIndex.addrSubtype(1 = IPv4).longueur(4).a.b.c.d
    if (!i || i.length !== 9 || i[3] !== 1 || i[4] !== 4) continue
    if (i.slice(5).every((n) => n <= 255)) mgmt.set(`${i[1]}.${i[2]}`, i.slice(5).join('.'))
  }
  return [...rows.entries()].map(([key, r]) => ({
    localPort: locNames.get(r.localPortNum) || String(r.localPortNum),
    localPortNum: r.localPortNum,
    mac: chassisToMac(r.chassisSubtype, r.chassisRaw),
    remotePort: r.portDesc || r.portId || null,
    sysName: r.sysName || null,
    sysDescr: r.sysDescr || null,
    caps: r.caps || lldpCaps(null),
    mgmtIp: mgmt.get(key) || null,
    source: 'lldp',
  }))
}

// CDP (Cisco) : index ifIndex.deviceIndex ; colonnes 4 adresse, 6 nom, 7 port distant, 8 plate-forme, 9 capacités.
export function parseCdp(vbs = [], ifNames = new Map()) {
  const rows = new Map()
  for (const { oid, value } of vbs) {
    const i = indexAfter(oid, OID.cdpCache)
    if (!i || i.length !== 3) continue
    const [col, ifIndex, dev] = i
    const key = `${ifIndex}.${dev}`
    if (!rows.has(key)) rows.set(key, { ifIndex })
    const r = rows.get(key)
    if (col === 4) r.mgmtIp = ipv4FromBytes(value)
    else if (col === 6) r.sysName = cleanSnmpText(value, 80)
    else if (col === 7) r.remotePort = cleanSnmpText(value, 64)
    else if (col === 8) r.sysDescr = cleanSnmpText(value, 200)
    else if (col === 9) r.caps = cdpCaps(value)
  }
  return [...rows.values()].map((r) => ({
    localPort: ifNames.get(r.ifIndex) || String(r.ifIndex), localPortNum: null, ifIndex: r.ifIndex, mac: null,
    remotePort: r.remotePort || null, sysName: r.sysName || null, sysDescr: r.sysDescr || null,
    caps: r.caps || cdpCaps(0), mgmtIp: r.mgmtIp || null, source: 'cdp',
  }))
}

// Table ARP d'un routeur / switch de niveau 3 : adresse IP de chaque MAC (y compris des autres VLAN).
export function parseArpTable(vbs = []) {
  const out = []
  for (const { oid, value } of vbs) {
    const i = indexAfter(oid, OID.ipNetToMediaPhysAddress)
    if (!i || i.length !== 5 || i.slice(1).some((n) => n > 255)) continue
    const mac = macFromBytes(value)
    if (mac && mac !== '00:00:00:00:00:00' && mac !== 'ff:ff:ff:ff:ff:ff') out.push({ ip: i.slice(1).join('.'), mac })
  }
  return out
}

export function parseVlans(vbs = []) {
  const ids = []
  for (const { oid, value } of vbs) {
    const i = indexAfter(oid, OID.vtpVlanState)
    if (i && i.length === 2 && num(value) === 1 && i[1] >= 1 && i[1] <= 4094 && !(i[1] >= 1002 && i[1] <= 1005)) ids.push(i[1])
  }
  return [...new Set(ids)].slice(0, 64)
}
