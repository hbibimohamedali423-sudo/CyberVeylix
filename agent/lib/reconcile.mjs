// CyberVeylix — rapprochement des hôtes vus par l'agent avec les appareils enregistrés (pur, testable).
// Identité d'un appareil = son adresse MAC quand elle est connue ; l'adresse IP ne sert qu'à défaut.
//   - une MAC connue est suivie même si son IP change (bail DHCP) ;
//   - une MAC nouvelle sur une IP connue est un NOUVEL appareil (jamais fusionné avec l'ancien) ;
//   - un appareil créé à la main et jamais vu par l'agent n'est jamais déclaré « Hors ligne ».

export function normalizeMac(value) {
  if (!value) return null
  const mac = String(value).trim().toLowerCase().replaceAll('-', ':')
  return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac) ? mac : null
}

export function createIndex(devices) {
  const byMac = new Map()
  const byIp = new Map()
  const add = (d) => {
    const mac = normalizeMac(d.mac)
    if (mac && !byMac.has(mac)) byMac.set(mac, d)
    if (d.ip) {
      if (!byIp.has(d.ip)) byIp.set(d.ip, [])
      byIp.get(d.ip).push(d)
    }
  }
  for (const d of devices || []) add(d)
  return { byMac, byIp, add }
}

// → { device, reason: 'mac' | 'ip' | 'new', replaced? }
// touchedIds : appareils déjà rapprochés pendant ce scan (une même MAC sur deux IP — routeur à plusieurs
// adresses ou usurpation — ne doit pas faire alterner l'IP d'un seul enregistrement).
export function matchHost(host, index, touchedIds = new Set()) {
  const mac = normalizeMac(host.mac)
  const known = mac ? index.byMac.get(mac) : null
  if (known && !(touchedIds.has(known.id) && known.ip !== host.ip)) return { device: known, reason: 'mac' }
  const candidates = (index.byIp.get(host.ip) || []).filter((d) => !touchedIds.has(d.id))
  if (!mac) return candidates.length ? { device: candidates[0], reason: 'ip' } : { device: null, reason: 'new' }
  // MAC lue : on ne reprend qu'un enregistrement sans MAC (ancien inventaire ou ajout manuel).
  const compatible = candidates.find((d) => !normalizeMac(d.mac))
  if (compatible) return { device: compatible, reason: 'ip' }
  const other = (index.byIp.get(host.ip) || []).find((d) => normalizeMac(d.mac) && normalizeMac(d.mac) !== mac)
  return { device: null, reason: 'new', replaced: other || null }
}

// Mise à jour d'un appareil reconnu. La MAC n'est écrite que si elle a été lue et manquait.
export function devicePatch(host, device, nowIso) {
  const patch = { status: 'on', last_seen: nowIso }
  const mac = normalizeMac(host.mac)
  if (mac && !normalizeMac(device.mac)) patch.mac = mac
  if (host.ip && device.ip !== host.ip) patch.ip = host.ip // la MAC connue a changé d'adresse (DHCP)
  return patch
}

const who = (h) => `${h.ip}${h.name ? ' — ' + h.name : ''}`

export function newDeviceAlert(host, replaced) {
  const mac = normalizeMac(host.mac)
  let detail = `${who(host)}${mac ? ` (${mac})` : ''}`
  if (replaced) {
    detail += ` — a pris l'adresse ${host.ip} utilisée auparavant par ${replaced.name || 'un autre appareil'}`
      + ` (${normalizeMac(replaced.mac)}). Changement d'appareil ou usurpation d'adresse.`
  }
  return { title: 'Nouvel appareil détecté', detail, severity: 'm' }
}

// sensitive : { port: [gravité, libellé] }. Alerte seulement pour un port sensible nouvellement ouvert.
export function sensitivePortAlerts(host, previousPorts, sensitive) {
  return (host.ports || [])
    .filter((p) => sensitive[p] && !(previousPorts || []).includes(p))
    .map((p) => ({ title: `Port ${p} ouvert (${sensitive[p][1]})`, detail: who(host), severity: sensitive[p][0] }))
}

// Appareils de la plage non revus pendant ce scan → « Hors ligne » après le délai de grâce.
// Seuls les appareils déjà vus par l'agent (last_seen renseigné) sont concernés.
export function planOffline(devices, touchedIds, inRange, nowMs, graceMs) {
  const off = []
  let pending = 0
  for (const d of devices || []) {
    if (!d.ip || !inRange(d.ip) || touchedIds.has(d.id) || d.status === 'off') continue
    const seen = d.last_seen ? Date.parse(d.last_seen) : NaN
    if (!Number.isFinite(seen)) continue // ajout manuel jamais vu par l'agent : statut laissé à l'utilisateur
    if (nowMs - seen > graceMs) off.push(d.id)
    else pending++
  }
  return { off, pending }
}
