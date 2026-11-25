// CyberVeylix Sensor — reconstruction de la topologie à partir des tables lues sur les switchs (pur, testable).
// Pour chaque adresse MAC, un switch indique sur quel PORT il l'a apprise. Une même MAC apparaît sur plusieurs
// switchs : sur les ports qui relient les switchs entre eux (« liaisons ») et sur le port « au bout du câble ».
// On écarte les liaisons (voisin LLDP/CDP de type switch/routeur, ou port menant à un autre switch interrogé) pour
// ne garder que le port réel de l'appareil. Rien n'est deviné : chaque lien porte sa preuve et son statut
// (« observed » = constaté, « inferred » = déduit).

// Clés d'un port pour rapprocher les numérotations : nom complet, forme courte (Gi1/0/1), numéro de port du pont.
export function portKeys({ name, bridgePort = null, ifIndex = null }) {
  const keys = new Set()
  const n = String(name || '').toLowerCase().replace(/\s+/g, '')
  if (n) {
    keys.add(`n:${n}`)
    const path = /(\d+(?:[/.:]\d+)*)$/.exec(n)
    if (path && /^[a-z]/.test(n)) keys.add(`s:${n[0]}${path[1]}`)
  }
  if (bridgePort !== null && bridgePort !== undefined) keys.add(`b:${bridgePort}`)
  if (ifIndex !== null && ifIndex !== undefined) keys.add(`i:${ifIndex}`)
  return keys
}
const overlap = (a, b) => { for (const k of a) if (b.has(k)) return true; return false }

// polled : [{ ip, ownMacs: [mac], sysName, sysDescr, ifNames: Map, basePorts: Map, fdb: [{mac, bridgePort, vlan}],
//            neighbors: [{ localPort, localPortNum, ifIndex, mac, remotePort, sysName, sysDescr, caps, mgmtIp, source }],
//            arp: [{ ip, mac }] }]
export function buildTopology(polled = []) {
  const arp = new Map()
  for (const p of polled) for (const a of p.arp || []) if (!arp.has(a.mac)) arp.set(a.mac, a.ip)
  const ipToMac = new Map([...arp.entries()].map(([m, ip]) => [ip, m]))

  const own = new Map() // mac → switch interrogé
  for (const p of polled) for (const m of p.ownMacs || []) own.set(m, p)
  const byIp = new Map(polled.map((p) => [p.ip, p]))
  const byName = new Map(polled.filter((p) => p.sysName).map((p) => [p.sysName.toLowerCase(), p]))

  // Ports de chaque switch, avec les MAC apprises.
  const ports = new Map() // switchIp → Map(portName → { name, keys, macs:Set })
  for (const p of polled) {
    const m = new Map()
    for (const e of p.fdb || []) {
      const ifIndex = p.basePorts?.get(e.bridgePort) ?? null
      const name = (ifIndex !== null && p.ifNames?.get(ifIndex)) || `port ${e.bridgePort}`
      if (!m.has(name)) m.set(name, { name, keys: portKeys({ name, bridgePort: e.bridgePort, ifIndex }), macs: new Set() })
      m.get(name).macs.add(e.mac)
    }
    ports.set(p.ip, m)
  }

  // Identité d'un voisin : MAC du châssis, sinon MAC de son adresse de gestion, sinon switch interrogé de même nom.
  const neighborIdentity = (n) => {
    const peer = (n.mgmtIp && byIp.get(n.mgmtIp)) || (n.sysName && byName.get(n.sysName.toLowerCase())) || null
    const mac = n.mac || (peer && peer.ownMacs && peer.ownMacs[0]) || (n.mgmtIp && ipToMac.get(n.mgmtIp)) || null
    return { mac, ip: n.mgmtIp || (peer && peer.ip) || (mac && arp.get(mac)) || null, peer }
  }
  const neighborRole = (n, id) => {
    if (n.caps?.wlanAp) return 'access_point'
    if (id.peer || n.caps?.bridge) return 'switch'
    if (n.caps?.router) return 'router'
    if (n.caps?.telephone) return 'phone'
    if (n.caps?.station) return 'workstation'
    return null
  }

  const links = []
  const devices = new Map() // mac (ou ip:x) → { mac, ip, name, role, roleEvidence, model }
  const note = (key, d) => { const cur = devices.get(key) || {}; devices.set(key, { ...cur, ...Object.fromEntries(Object.entries(d).filter(([, v]) => v !== null && v !== undefined)) }) }

  // Switchs interrogés : rôle d'après leurs propres capacités et description.
  for (const p of polled) {
    const isAp = /access ?point|\bap\b|wireless|instant|\beap\d|\buap\b|unifi|airos|omada/i.test(p.sysDescr || '')
    const role = isAp ? 'access_point' : 'switch'
    const mac = (p.ownMacs || [])[0] || null
    note(mac || `ip:${p.ip}`, { mac, ip: p.ip, name: p.sysName, role, model: p.sysDescr, roleEvidence: `SNMP : ${isAp ? 'point d\'accès' : 'switch'} interrogé (${(p.sysDescr || p.sysName || p.ip).slice(0, 80)})` })
  }

  // 1) Liaisons LLDP / CDP (constatées), dédoublonnées A↔B.
  const neighborPorts = new Map() // switchIp → [{ keys, role, mac }]
  const seenPairs = new Set()
  for (const p of polled) {
    const list = []
    for (const n of p.neighbors || []) {
      const id = neighborIdentity(n)
      const role = neighborRole(n, id)
      const keys = n.source === 'cdp' ? portKeys({ name: n.localPort, ifIndex: n.ifIndex }) : portKeys({ name: n.localPort, bridgePort: n.localPortNum })
      list.push({ keys, role, mac: id.mac, peer: id.peer, port: n.localPort })
      const fromMac = (p.ownMacs || [])[0] || null
      if (!id.mac && !id.ip) continue
      const toKey = id.mac || `ip:${id.ip}`
      if (!id.peer) {
        note(toKey, { mac: id.mac, ip: id.ip, name: n.sysName, role: role === 'router' ? null : role, model: n.sysDescr,
          roleEvidence: role ? `${n.source.toUpperCase()} : voisin annoncé comme ${role === 'access_point' ? 'point d\'accès Wi-Fi' : role} sur ${p.sysName || p.ip}` : null })
      }
      const pair = [fromMac || p.ip, toKey].sort().join('|')
      if (seenPairs.has(pair)) continue
      seenPairs.add(pair)
      links.push({ fromMac, fromIp: p.ip, fromPort: n.localPort, toMac: id.mac, toIp: id.ip, toPort: n.remotePort, medium: 'ethernet', source: n.source, status: 'observed',
        evidence: `${n.source.toUpperCase()} : ${n.sysName || id.ip || id.mac} annoncé sur le port ${n.localPort} de ${p.sysName || p.ip}` })
    }
    neighborPorts.set(p.ip, list)
  }
  const linkedByNeighbor = new Set(links.map((l) => l.toMac).filter(Boolean))

  // Port de liaison : voisin switch/routeur, ou port menant à un autre switch interrogé.
  const portInfo = (p, port) => {
    const nb = (neighborPorts.get(p.ip) || []).find((n) => overlap(n.keys, port.keys))
    const towardsSwitch = [...port.macs].some((m) => own.has(m) && own.get(m) !== p)
    const ap = nb && nb.role === 'access_point' ? nb : null
    const uplink = !ap && (towardsSwitch || (nb && (nb.role === 'switch' || nb.role === 'router')))
    return { uplink, ap }
  }

  // 2) Appareils d'extrémité : port réel d'après les tables MAC.
  const candidates = new Map() // mac → [{ p, port, info }]
  for (const p of polled) {
    for (const port of (ports.get(p.ip) || new Map()).values()) {
      const info = portInfo(p, port)
      if (info.uplink) continue
      for (const m of port.macs) {
        if (own.has(m)) continue // un switch interrogé n'est pas une extrémité
        if (!candidates.has(m)) candidates.set(m, [])
        candidates.get(m).push({ p, port, info })
      }
    }
  }
  for (const [mac, list] of candidates) {
    if (linkedByNeighbor.has(mac) && !list.some((c) => c.info.ap && c.info.ap.mac !== mac)) continue // déjà relié par LLDP/CDP
    const best = list.slice().sort((a, b) => a.port.macs.size - b.port.macs.size)[0]
    const { p, port, info } = best
    const sw = p.sysName || p.ip
    note(mac, { mac, ip: arp.get(mac) || null })
    if (info.ap && info.ap.mac && info.ap.mac !== mac) {
      links.push({ fromMac: info.ap.mac, fromIp: null, fromPort: null, toMac: mac, toIp: arp.get(mac) || null, toPort: null, medium: 'wifi', source: 'fdb', status: 'inferred',
        evidence: `vu derrière le port ${port.name} de ${sw}, où est branché le point d'accès Wi-Fi` })
      continue
    }
    const single = port.macs.size === 1
    links.push({ fromMac: (p.ownMacs || [])[0] || null, fromIp: p.ip, fromPort: port.name, toMac: mac, toIp: arp.get(mac) || null, toPort: null,
      medium: single ? 'ethernet' : 'unknown', source: 'fdb', status: single ? 'observed' : 'inferred',
      evidence: single
        ? `seule adresse apprise sur le port ${port.name} de ${sw}`
        : `port ${port.name} de ${sw} partagé par ${port.macs.size} appareils (switch non géré, hub ou point Wi-Fi sans LLDP)` })
  }

  return { links, devices: [...devices.values()], arp }
}
