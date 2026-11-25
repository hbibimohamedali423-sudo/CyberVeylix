// Vue « Branchements réels » de la topologie (pur, testable) : arbre passerelle → switchs → ports → appareils,
// construit UNIQUEMENT à partir des liens enregistrés (table links, lecture des switchs par le capteur).

const INFRA_ROLES = ['gateway', 'switch', 'access_point']
const byName = (a, b) => String(a.name || '').localeCompare(String(b.name || ''), 'fr', { numeric: true })
// Ports triés dans l'ordre naturel (Gi1/0/2 avant Gi1/0/10).
const portOrder = (a, b) => String(a || '').localeCompare(String(b || ''), 'fr', { numeric: true })

export function buildPhysical(devices = [], links = []) {
  const byId = new Map(devices.map((d) => [d.id, d]))
  const valid = links.filter((l) => byId.has(l.from_device_id) && byId.has(l.to_device_id) && l.from_device_id !== l.to_device_id)
  const infra = new Set(devices.filter((d) => INFRA_ROLES.includes(d.role)).map((d) => d.id))
  for (const l of valid) infra.add(l.from_device_id)
  // Une extrémité qui est elle-même la source d'autres liens est un équipement d'infrastructure.
  const isInfra = (id) => infra.has(id)

  // Liens entre équipements d'infrastructure (non orientés) et appareils rattachés à un port.
  const adj = new Map()
  const endpoints = new Map() // infraId → Map(port → [entry])
  const placed = new Set()
  for (const l of valid) {
    if (isInfra(l.to_device_id)) {
      for (const [a, b, ap, bp] of [[l.from_device_id, l.to_device_id, l.from_port, l.to_port], [l.to_device_id, l.from_device_id, l.to_port, l.from_port]]) {
        if (!adj.has(a)) adj.set(a, [])
        adj.get(a).push({ to: b, port: ap || null, remotePort: bp || null, link: l })
      }
      continue
    }
    const key = l.medium === 'wifi' ? '__wifi' : (l.from_port || '__unknown')
    if (!endpoints.has(l.from_device_id)) endpoints.set(l.from_device_id, new Map())
    const ports = endpoints.get(l.from_device_id)
    if (!ports.has(key)) ports.set(key, [])
    ports.get(key).push({ device: byId.get(l.to_device_id), medium: l.medium || 'unknown', status: l.status || null, evidence: l.evidence || null, source: l.source })
    placed.add(l.to_device_id)
  }

  // Racine : la passerelle reliée, sinon l'équipement le plus relié.
  const connected = [...infra].filter((id) => adj.has(id) || endpoints.has(id))
  const gateway = connected.find((id) => byId.get(id).role === 'gateway')
  const degree = (id) => (adj.get(id) || []).length + [...(endpoints.get(id) || new Map()).values()].reduce((n, l) => n + l.length, 0)
  const roots = []
  const visited = new Set()
  const makeNode = (id, via) => {
    visited.add(id)
    const ports = [...(endpoints.get(id) || new Map()).entries()]
      .map(([port, list]) => ({ port, wifi: port === '__wifi', entries: list.slice().sort((a, b) => byName(a.device, b.device)) }))
      .sort((a, b) => (a.wifi - b.wifi) || portOrder(a.port, b.port))
    const node = { device: byId.get(id), via, ports, children: [] }
    for (const e of (adj.get(id) || []).slice().sort((a, b) => portOrder(a.port, b.port))) {
      if (visited.has(e.to)) continue
      node.children.push(makeNode(e.to, { parentPort: e.port, port: e.remotePort, source: e.link.source, status: e.link.status, evidence: e.link.evidence }))
    }
    return node
  }
  const order = [gateway, ...connected.filter((id) => id !== gateway).sort((a, b) => degree(b) - degree(a))].filter(Boolean)
  for (const id of order) if (!visited.has(id)) roots.push(makeNode(id, null))

  const stats = { cable: 0, wifi: 0, unknown: 0 }
  for (const ports of endpoints.values()) for (const list of ports.values()) for (const e of list) {
    stats[e.medium === 'wifi' ? 'wifi' : e.medium === 'ethernet' ? 'cable' : 'unknown'] += 1
  }
  const unplaced = devices.filter((d) => !placed.has(d.id) && !visited.has(d.id)).sort(byName)
  return { roots, unplaced, stats, hasLinks: valid.length > 0 }
}

// Appareils regroupés par type affiché (inventaire détaillé) ; « Inconnu » pour un type absent.
export function groupByType(devices = []) {
  const groups = new Map()
  for (const d of devices) {
    const k = d.type || ''
    if (!groups.has(k)) groups.set(k, [])
    groups.get(k).push(d)
  }
  return [...groups.entries()].map(([type, list]) => ({ type, devices: list.sort(byName) })).sort((a, b) => b.devices.length - a.devices.length || a.type.localeCompare(b.type, 'fr'))
}
