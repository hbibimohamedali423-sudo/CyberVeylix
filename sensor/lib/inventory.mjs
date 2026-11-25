// CyberVeylix Sensor — inventaire du réseau surveillé : réseau + chaque appareil vu, et son identification.
// Sources passives : ARP (adresse IP ↔ MAC) et demandes DHCP (nom, système annoncé), plus les ports déjà
// relevés par l'analyse (table services). Écrit dans networks / devices ; client Supabase injecté (testable).
// Règles :
//   - identité = MAC ; un appareil connu est mis à jour, jamais dupliqué ;
//   - un nom, un type ou un rôle choisis par l'utilisateur ne sont JAMAIS écrasés (seuls ceux posés par le
//     capteur, repérés par role_evidence « Capteur : … », sont mis à jour) ;
//   - « Hors ligne » seulement pour les appareils découverts par le capteur et absents depuis STALE_MS.
import { classify } from './classify.mjs'
import { isRandomMac } from './oui.mjs'

export const STALE_MS = 2 * 3600 * 1000
export const TOUCH_MS = 15 * 60 * 1000 // last_seen réécrit au plus toutes les 15 min par appareil
const MARK = 'Capteur : '
const MAX_TRACKED = 5000
const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/
const IP_RE = /^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$/

const ipToInt = (ip) => ip.split('.').reduce((n, x) => ((n << 8) | Number(x)) >>> 0, 0)
// 10.15.5.117 + 255.255.0.0 → 10.15.0.0/16 (null si masque invalide)
export function cidrOf(ip, netmask) {
  if (!IP_RE.test(ip || '') || !IP_RE.test(netmask || '')) return null
  const mask = ipToInt(netmask)
  const bits = mask.toString(2).replace(/0+$/, '')
  if (/0/.test(bits) || !bits.length) return null
  const net = (ipToInt(ip) & mask) >>> 0
  return `${[24, 16, 8, 0].map((s) => (net >>> s) & 255).join('.')}/${bits.length}`
}
export function inCidr(ip, cidr) {
  if (!IP_RE.test(ip || '') || !cidr) return false
  const [base, len] = cidr.split('/')
  const n = Number(len)
  const mask = n === 0 ? 0 : (0xffffffff << (32 - n)) >>> 0
  return ((ipToInt(ip) & mask) >>> 0) === ((ipToInt(base) & mask) >>> 0)
}
const usableMac = (mac) => MAC_RE.test(mac || '') && mac !== '00:00:00:00:00:00' && mac !== 'ff:ff:ff:ff:ff:ff' && !(parseInt(mac.slice(0, 2), 16) & 1)

// client peut être fourni plus tard (setClient) : le capteur observe le réseau avant d'être connecté à la base.
export function createInventory({ client = null, oui, log = console.log, now = () => new Date() }) {
  let db = client
  const seen = new Map() // mac → { mac, ip, lastSeen, hostname, vendorClass }
  const uplinks = new Map() // clé switch → voisin LLDP/CDP entendu (switch auquel CE PC est branché)
  let cidr = null

  function setSubnet(value) { cidr = value || null }
  function setClient(c) { db = c }

  function observe(mac, ip, at = now().getTime()) {
    if (!usableMac(mac)) return
    if (ip && (!IP_RE.test(ip) || ip === '0.0.0.0' || (cidr && !inCidr(ip, cidr)))) ip = null
    const e = seen.get(mac) || (seen.size < MAX_TRACKED ? { mac } : null)
    if (!e) return
    if (ip) e.ip = ip
    e.lastSeen = at
    seen.set(mac, e)
  }
  // Voisin LLDP / CDP entendu passivement : le switch (ou point d'accès) auquel le PC du capteur est branché.
  function observeUplink(n, at = now().getTime()) {
    if (!n) return
    const mac = MAC_RE.test(n.chassisId || '') ? n.chassisId : (usableMac(n.senderMac) ? n.senderMac : null)
    const key = `${n.source}:${(n.sysName || mac || n.mgmtIp || '').toLowerCase()}`
    if (!n.sysName && !mac && !n.mgmtIp) return
    uplinks.set(key, { source: n.source, mac, sysName: n.sysName || null, sysDescr: n.sysDescr || null,
      mgmtIp: n.mgmtIp && inCidr(n.mgmtIp, cidr || `${n.mgmtIp}/32`) ? n.mgmtIp : null, portId: n.portId || null, caps: n.caps || {}, at })
  }

  function observeDhcp(d, at = now().getTime()) {
    if (!d || !usableMac(d.mac)) return
    observe(d.mac, d.ip, at)
    const e = seen.get(d.mac)
    if (!e) return
    if (d.hostname) e.hostname = d.hostname
    if (d.vendorClass) e.vendorClass = d.vendorClass
  }

  // Réseau du capteur : retrouvé par la MAC de la passerelle confirmée à l'installation, créé sinon.
  async function ensureNetwork({ gatewayMac, gatewayIp, name }) {
    if (!db || !MAC_RE.test(gatewayMac || '')) return null
    const stamp = now().toISOString()
    const found = await db.from('networks').select('id,cidr,gateway_ip').eq('gateway_mac', gatewayMac)
    if (found.error) { log('⚠ Inventaire : ' + found.error.message); return null }
    if (found.data && found.data.length) {
      const n = found.data[0]
      const patch = { last_seen: stamp }
      if (!n.cidr && cidr) patch.cidr = cidr
      if (!n.gateway_ip && gatewayIp) patch.gateway_ip = gatewayIp
      await db.from('networks').update(patch).eq('id', n.id)
      return n.id
    }
    const ins = await db.from('networks')
      .insert({ name: String(name || `Réseau ${cidr || gatewayIp || ''}`).trim().slice(0, 80), cidr, gateway_ip: gatewayIp || null, gateway_mac: gatewayMac, last_seen: stamp })
      .select('id')
    if (ins.error || !ins.data || !ins.data.length) { log('⚠ Réseau non enregistré : ' + (ins.error && ins.error.message)); return null }
    log(`✔ Réseau enregistré dans le tableau de bord : ${name || cidr}`)
    return ins.data[0].id
  }

  // ctx : { networkId, gatewayIp, gatewayMac, sensorMac }
  async function sync(ctx) {
    const { networkId } = ctx
    if (!db || !networkId) return { inserted: 0, updated: 0, offline: 0 }
    const nowMs = now().getTime()
    const stamp = new Date(nowMs).toISOString()
    const res = await db.from('devices')
      .select('id,name,ip,mac,type,role,role_evidence,role_confidence,vendor,hostname,status,last_seen,discovery_source')
      .eq('network_id', networkId)
    if (res.error) { log('⚠ Inventaire : ' + res.error.message); return { inserted: 0, updated: 0, offline: 0 } }
    const existing = res.data || []
    const byMac = new Map(existing.filter((d) => d.mac).map((d) => [String(d.mac).toLowerCase(), d]))

    // Ports relevés par l'analyse (indices de type) pour les appareils de ce réseau.
    const portsOf = new Map()
    const ids = existing.map((d) => d.id)
    if (ids.length) {
      const sv = await db.from('services').select('device_id,port').in('device_id', ids.slice(0, 1000))
      for (const s of (sv && sv.data) || []) {
        if (!portsOf.has(s.device_id)) portsOf.set(s.device_id, [])
        portsOf.get(s.device_id).push(Number(s.port))
      }
    }

    const inserts = []
    const updates = []
    for (const e of seen.values()) {
      const old = byMac.get(e.mac)
      const vendor = oui ? oui.vendorOf(e.mac) : null
      const hostname = e.hostname || (old && old.hostname) || null
      const c = classify({
        vendor: vendor || (old && old.vendor) || null,
        randomMac: isRandomMac(e.mac),
        hostname,
        vendorClass: e.vendorClass || null,
        ports: old ? portsOf.get(old.id) || [] : [],
        isGateway: e.mac === ctx.gatewayMac,
        isSelf: e.mac === ctx.sensorMac,
      })
      const recent = nowMs - e.lastSeen < STALE_MS
      if (!old) {
        if (!recent) continue
        inserts.push({
          name: autoName({ hostname, vendor, ip: e.ip, mac: e.mac, gateway: e.mac === ctx.gatewayMac }),
          ip: e.ip || null, mac: e.mac, status: 'on', last_seen: new Date(e.lastSeen).toISOString(), network_id: networkId,
          discovery_source: 'sensor', vendor, hostname,
          role: c.role, type: c.type, role_confidence: c.confidence, role_evidence: c.evidence ? MARK + c.evidence : null,
        })
        continue
      }
      const patch = {}
      const ours = !old.role_evidence || String(old.role_evidence).startsWith(MARK)
      if (recent && old.status !== 'on') patch.status = 'on'
      if (recent && (!old.last_seen || e.lastSeen - Date.parse(old.last_seen) > TOUCH_MS)) patch.last_seen = new Date(e.lastSeen).toISOString()
      if (e.ip && e.ip !== old.ip) patch.ip = e.ip
      if (vendor && !old.vendor) patch.vendor = vendor
      if (e.hostname && e.hostname !== old.hostname) patch.hostname = e.hostname
      if (ours && c.role && (c.role !== old.role || c.confidence !== old.role_confidence || MARK + c.evidence !== old.role_evidence)) {
        Object.assign(patch, { role: c.role, role_confidence: c.confidence, role_evidence: MARK + c.evidence })
        if (!old.type || (old.discovery_source === 'sensor' && ours)) patch.type = c.type
      } else if (!old.type && c.type && ours) {
        patch.type = c.type
      }
      // Nom automatique remplacé quand le vrai nom de l'appareil apparaît (jamais un nom saisi à la main).
      if (old.discovery_source === 'sensor' && e.hostname && isAutoName(old.name, old) && old.name !== e.hostname) patch.name = e.hostname
      if (Object.keys(patch).length) updates.push([old.id, patch])
    }

    // Appareils découverts par le capteur et absents depuis longtemps : hors ligne.
    const offline = existing.filter((d) => d.discovery_source === 'sensor' && d.status === 'on'
      && !(seen.get(String(d.mac || '').toLowerCase()) && nowMs - seen.get(String(d.mac).toLowerCase()).lastSeen < STALE_MS)
      && (!d.last_seen || nowMs - Date.parse(d.last_seen) > STALE_MS))
    for (const d of offline) updates.push([d.id, { status: 'off' }])

    let inserted = 0
    for (let i = 0; i < inserts.length; i += 200) {
      const part = inserts.slice(i, i + 200)
      const r = await db.from('devices').insert(part)
      if (r.error) log('⚠ Appareils non enregistrés : ' + r.error.message)
      else inserted += part.length
    }
    let updated = 0
    for (let i = 0; i < updates.length; i += 5) {
      const results = await Promise.all(updates.slice(i, i + 5).map(([id, patch]) => db.from('devices').update(patch).eq('id', id)))
      updated += results.filter((r) => !r.error).length
    }
    if (inserted || updated) log(`Inventaire : ${inserted} appareil(s) ajouté(s), ${updated} mis à jour (${stamp}).`)
    return { inserted, updated, offline: offline.length }
  }

  // Écrit les switchs / points d'accès ENTENDUS (LLDP / CDP passif) et le lien « switch → PC du capteur ».
  // Sans aucun identifiant : seul ce qu'ils diffusent eux-mêmes est enregistré. Choix manuels jamais écrasés.
  async function syncUplinks(ctx) {
    const { networkId, sensorMac, writeLinks = true } = ctx
    if (!db || !networkId || !usableMac(sensorMac) || !uplinks.size) return { switches: 0, links: 0 }
    const stamp = now().toISOString()
    const res = await db.from('devices').select('id,name,ip,mac,type,role,role_evidence,role_confidence,hostname,model,discovery_source').eq('network_id', networkId)
    if (res.error) { log('⚠ Écoute LLDP : ' + res.error.message); return { switches: 0, links: 0 } }
    const devices = res.data || []
    const byMac = new Map(devices.filter((d) => d.mac).map((d) => [String(d.mac).toLowerCase(), d]))
    const byIp = new Map(devices.filter((d) => d.ip).map((d) => [d.ip, d]))
    const find = (mac, ip) => (mac && byMac.get(mac)) || (ip && byIp.get(ip)) || null

    // Appareil du PC du capteur : créé s'il manque (il ne s'observe pas lui-même par ARP).
    let self = byMac.get(sensorMac)
    if (!self) {
      const row = { name: `Ce PC (capteur)`, mac: sensorMac, ip: ctx.sensorIp || null, status: 'on', last_seen: stamp, network_id: networkId,
        discovery_source: 'sensor', role: 'workstation', type: 'Poste', role_confidence: 'certaine', role_evidence: MARK + 'ordinateur qui héberge le capteur' }
      const r = await db.from('devices').insert(row).select('id')
      if (r.error || !r.data || !r.data[0]) return { switches: 0, links: 0 }
      self = { ...row, id: r.data[0].id }
      byMac.set(sensorMac, self)
    }

    let switches = 0
    const linkRows = []
    for (const u of uplinks.values()) {
      const role = u.caps.wlanAp ? 'access_point' : (u.caps.bridge || u.caps.router) ? 'switch' : 'other'
      const type = role === 'access_point' || role === 'switch' ? 'Équipement réseau' : null
      const evidence = `${u.source.toUpperCase()} (écoute passive) : ${u.sysName || u.mac || u.mgmtIp} annoncé sur le port du capteur`
      let sw = find(u.mac, u.mgmtIp)
      if (!sw) {
        const row = { name: (u.sysName || (u.mgmtIp ? `Switch (${u.mgmtIp})` : `Switch ${String(u.mac || '').slice(-5)}`)).slice(0, 80),
          mac: u.mac || null, ip: u.mgmtIp || null, status: 'on', last_seen: stamp, network_id: networkId, discovery_source: 'sensor',
          hostname: u.sysName || null, model: u.sysDescr ? u.sysDescr.slice(0, 120) : null, role, type, role_confidence: 'certaine', role_evidence: MARK + evidence }
        const r = await db.from('devices').insert(row).select('id')
        if (r.error || !r.data || !r.data[0]) continue
        sw = { ...row, id: r.data[0].id }
        if (sw.mac) byMac.set(sw.mac, sw); if (sw.ip) byIp.set(sw.ip, sw)
        switches += 1
      } else {
        const ours = !sw.role_evidence || String(sw.role_evidence).startsWith(MARK)
        const patch = {}
        if (u.mgmtIp && !sw.ip) patch.ip = u.mgmtIp
        if (u.sysName && !sw.hostname) patch.hostname = u.sysName
        if (u.sysDescr && !sw.model) patch.model = u.sysDescr.slice(0, 120)
        if (ours && (sw.role !== role || sw.role_confidence !== 'certaine')) Object.assign(patch, { role, type: (!sw.type || sw.discovery_source !== 'agent') ? type : sw.type, role_confidence: 'certaine', role_evidence: MARK + evidence })
        if (Object.keys(patch).length) { await db.from('devices').update(patch).eq('id', sw.id); Object.assign(sw, patch) }
      }
      if (sw.id !== self.id) {
        linkRows.push({ network_id: networkId, from_device_id: sw.id, to_device_id: self.id, from_port: u.portId || null, to_port: null,
          medium: 'ethernet', source: u.source, status: 'observed', evidence: evidence.slice(0, 500), observed_at: stamp, last_seen: stamp })
      }
    }
    let links = 0
    for (const row of writeLinks ? linkRows : []) {
      // Idempotent : on remplace le lien passif précédent de ce switch vers ce PC.
      await db.from('links').delete().eq('network_id', networkId).eq('from_device_id', row.from_device_id).eq('to_device_id', row.to_device_id).eq('source', row.source)
      const r = await db.from('links').insert(row).select('id')
      if (!r.error && r.data && r.data.length) links += 1
    }
    if (switches || links) log(`Écoute LLDP / CDP : ${switches} switch(s) ajouté(s), ${links} liaison(s) directe(s).`)
    return { switches, links }
  }

  return { observe, observeDhcp, observeUplink, ensureNetwork, sync, syncUplinks, setSubnet, setClient, uplinkCount: () => uplinks.size, size: () => seen.size, entries: () => [...seen.values()] }
}

// Nom lisible tant que l'appareil n'a pas annoncé le sien : « Xiaomi (10.15.4.64) », « Appareil 54:8d (10.15.4.64) ».
export function autoName({ hostname, vendor, ip, mac, gateway }) {
  if (hostname) return hostname.slice(0, 80)
  const where = ip ? ` (${ip})` : ''
  if (gateway) return `Passerelle${vendor ? ' ' + vendor : ''}${where}`.slice(0, 80)
  if (vendor) return `${vendor}${where}`.slice(0, 80)
  return `Appareil ${String(mac || '').slice(-5)}${where}`.slice(0, 80)
}
const isAutoName = (name, d) => !name || name === d.ip || /\(\d{1,3}(\.\d{1,3}){3}\)$/.test(name) || /^Appareil [0-9a-f]{2}:[0-9a-f]{2}/.test(name)
