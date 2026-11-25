// CyberVeylix Sensor — lecture des switchs (SNMP, lecture seule) → appareils et liens dans la base.
// 1. Équipements à interroger : liste de snmp.json, passerelle, équipements réseau identifiés, puis voisins
//    LLDP/CDP découverts de proche en proche (adresses privées uniquement, nombre borné).
// 2. Lecture des tables standard (snmp-mibs.mjs), 3. topologie (topology.mjs),
// 4. écriture : appareils manquants créés, rôle des switchs / points d'accès précisé (jamais un choix manuel
//    écrasé), liens « fdb / lldp / cdp » du réseau remplacés par ceux de cette lecture.
import { OID, parseIfNames, parseBasePorts, parseFdb, parseLldp, parseCdp, parseArpTable, parseVlans, macFromBytes } from './snmp-mibs.mjs'
import { buildTopology } from './topology.mjs'
import { isAllowedTarget } from './snmp-config.mjs'
import { classify, ROLE_TYPES } from './classify.mjs'

const MARK = 'Capteur : '
export const MAX_DEVICES = 64
const SOURCES = ['fdb', 'lldp', 'cdp']

// Lecture complète d'un équipement (session déjà ouverte avec l'identifiant qui répond).
export async function pollDevice(snmp, session, target, cred) {
  const sys = await snmp.get(session, [OID.sysName, OID.sysDescr, OID.bridgeAddress, OID.lldpLocChassisId])
  const val = (oid) => (sys.rows.find((r) => r.oid === oid) || {}).value
  const text = (v) => (v === undefined || v === null ? null : (Buffer.isBuffer(v) ? v.toString('utf8') : String(v)).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 200) || null)
  const ownMacs = [macFromBytes(val(OID.bridgeAddress)), macFromBytes(val(OID.lldpLocChassisId))].filter((m) => m && m !== '00:00:00:00:00:00')
  const w = async (oid) => (await snmp.walk(session, oid)).rows
  const [ifName, ifDescr, base, fdbQ] = [await w(OID.ifName), await w(OID.ifDescr), await w(OID.basePortIfIndex), await w(OID.dot1qTpFdbPort)]
  let fdbD = fdbQ.length ? [] : await w(OID.dot1dTpFdbPort)
  let basePorts = parseBasePorts(base)
  const sysDescr = text(val(OID.sysDescr))
  // Anciens Cisco : table MAC par VLAN (« community@vlan »), seulement en SNMPv2c.
  if (!fdbQ.length && !fdbD.length && cred.version === '2c' && /cisco/i.test(sysDescr || '')) {
    for (const vlan of parseVlans(await w(OID.vtpVlanState))) {
      const s = snmp.open(target, cred, { context: String(vlan) })
      s.on?.('error', () => {})
      fdbD = fdbD.concat((await snmp.walk(s, OID.dot1dTpFdbPort)).rows)
      for (const [k, v] of parseBasePorts((await snmp.walk(s, OID.basePortIfIndex)).rows)) basePorts.set(k, v)
      snmp.close(s)
    }
  }
  const ifNames = parseIfNames(ifName, ifDescr)
  const neighbors = [
    ...parseLldp({ rem: await w(OID.lldpRem), locPortId: await w(OID.lldpLocPortId), locPortDesc: await w(OID.lldpLocPortDesc), manAddr: await w(OID.lldpRemManAddrIfSubtype) }),
    ...parseCdp(await w(OID.cdpCache), ifNames),
  ]
  return {
    ip: target.host, ownMacs: [...new Set(ownMacs)], sysName: text(val(OID.sysName)), sysDescr,
    ifNames, basePorts, fdb: parseFdb(fdbQ, fdbD), neighbors, arp: parseArpTable(await w(OID.ipNetToMediaPhysAddress)),
  }
}

export function createTopologySync({ db, snmp, config, oui = null, log = console.log, now = () => new Date(), maxDevices = MAX_DEVICES, concurrency = 4 }) {
  const working = new Map() // ip → identifiant qui a répondu la dernière fois (essayé en premier)

  async function run({ networkId, gatewayIp }) {
    if (!db || !networkId) return null
    const stamp = now().toISOString()
    const devRes = await db.from('devices').select('id,name,ip,mac,type,role,role_evidence,role_confidence,vendor,hostname,model,discovery_source').eq('network_id', networkId)
    if (devRes.error) { log('⚠ Topologie : ' + devRes.error.message); return null }
    const devices = devRes.data || []

    // Équipements à interroger.
    const queue = []
    const queued = new Set()
    const enqueue = (host, port = 161) => {
      const key = `${host}:${port}`
      if (!isAllowedTarget(host) || queued.has(key) || queued.size >= maxDevices) return
      queued.add(key); queue.push({ host, port })
    }
    for (const t of config.targets) enqueue(t.host, t.port)
    if (config.auto) {
      if (gatewayIp) enqueue(gatewayIp)
      for (const d of devices) if (d.ip && ['gateway', 'switch', 'access_point', 'other'].includes(d.role)) enqueue(d.ip)
    }

    const polled = []
    let unreachable = 0
    const credsFor = (ip) => { const w = working.get(ip); return w ? [w, ...config.credentials.filter((c) => c !== w)] : config.credentials }
    const worker = async () => {
      while (queue.length) {
        const target = queue.shift()
        let opened = null
        try {
          opened = await snmp.probe(target, credsFor(target.host))
          if (!opened) { unreachable += 1; continue }
          working.set(target.host, opened.cred)
          const p = await pollDevice(snmp, opened.session, target, opened.cred)
          polled.push(p)
          if (config.auto) for (const n of p.neighbors) if (n.mgmtIp && (n.caps.bridge || n.caps.wlanAp || n.caps.router)) enqueue(n.mgmtIp)
        } catch (e) {
          log(`⚠ SNMP ${target.host} : ${e && e.message}`)
        } finally {
          if (opened) snmp.close(opened.session)
        }
      }
    }
    // Les voisins découverts s'ajoutent à la file : on relance tant qu'elle n'est pas vide.
    while (queue.length) await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, worker))

    const topo = buildTopology(polled)

    // Appareils : retrouvés par MAC puis par IP ; créés s'ils manquent ; rôle précisé si posé par le capteur.
    const byMac = new Map(devices.filter((d) => d.mac).map((d) => [String(d.mac).toLowerCase(), d]))
    const byIp = new Map(devices.filter((d) => d.ip).map((d) => [d.ip, d]))
    const find = (mac, ip) => (mac && byMac.get(mac)) || (ip && byIp.get(ip)) || null
    let created = 0
    let updated = 0
    for (const t of topo.devices) {
      const vendor = t.mac && oui ? oui.vendorOf(t.mac) : null
      let role = t.role === 'router' ? null : t.role || null
      let confidence = role ? 'certaine' : null
      let evidence = t.roleEvidence || null
      if (!role) {
        const c = classify({ vendor, randomMac: t.mac ? (parseInt(t.mac.slice(0, 2), 16) & 2) === 2 : false })
        role = c.role; confidence = c.confidence; evidence = c.evidence
      }
      const type = role ? (role === 'other' ? 'Équipement réseau' : ROLE_TYPES[role] ?? null) : null
      const old = find(t.mac, t.ip)
      if (!old) {
        const name = (t.name || (vendor ? `${vendor}${t.ip ? ` (${t.ip})` : ''}` : (t.ip || `Appareil ${String(t.mac || '').slice(-5)}`))).slice(0, 80)
        const row = { name, ip: t.ip || null, mac: t.mac || null, status: 'on', last_seen: stamp, network_id: networkId, discovery_source: 'snmp',
          vendor, hostname: t.name || null, model: t.model ? t.model.slice(0, 120) : null,
          role, type, role_confidence: confidence, role_evidence: evidence ? MARK + evidence.slice(0, 480) : null }
        const r = await db.from('devices').insert(row).select('id')
        if (!r.error && r.data && r.data[0]) {
          const d = { ...row, id: r.data[0].id }
          devices.push(d)
          if (d.mac) byMac.set(d.mac, d)
          if (d.ip) byIp.set(d.ip, d)
          created += 1
        }
        continue
      }
      const ours = !old.role_evidence || String(old.role_evidence).startsWith(MARK)
      const patch = {}
      if (t.ip && !old.ip) patch.ip = t.ip
      if (t.mac && !old.mac) patch.mac = t.mac
      if (t.name && !old.hostname) patch.hostname = t.name
      if (t.model && !old.model) patch.model = t.model.slice(0, 120)
      // Un rôle constaté par SNMP / LLDP (switch, point d'accès…) remplace une identification par simple indice.
      if (ours && t.role && t.role !== 'router' && (old.role !== role || old.role_confidence !== 'certaine')) {
        Object.assign(patch, { role, role_confidence: 'certaine', role_evidence: MARK + String(evidence).slice(0, 480) })
        if (!old.type || old.discovery_source !== 'agent') patch.type = type
      }
      if (Object.keys(patch).length) {
        const r = await db.from('devices').update(patch).eq('id', old.id)
        if (!r.error) { Object.assign(old, patch); updated += 1 }
      }
    }

    // Liens : ceux de cette lecture remplacent les précédents (fdb / lldp / cdp) du réseau.
    const rows = []
    for (const l of topo.links) {
      const from = find(l.fromMac, l.fromIp)
      const to = find(l.toMac, l.toIp)
      if (!from || !to || from.id === to.id) continue
      rows.push({ network_id: networkId, from_device_id: from.id, to_device_id: to.id, from_port: l.fromPort || null, to_port: l.toPort || null,
        medium: l.medium, source: l.source, status: l.status, evidence: String(l.evidence || '').slice(0, 500), observed_at: stamp, last_seen: stamp })
    }
    let linked = 0
    if (polled.length) {
      // La lecture SNMP fournit la carte complète : elle remplace les liens fdb / lldp / cdp du réseau. La liaison
      // entendue passivement (LLDP / CDP) n'est écrite par le capteur que lorsque le SNMP n'est PAS configuré.
      const del = await db.from('links').delete().eq('network_id', networkId).in('source', SOURCES)
      if (del.error) { log('⚠ Liens non mis à jour : ' + del.error.message); return { polled: polled.length, unreachable, created, updated, links: 0 } }
      for (let i = 0; i < rows.length; i += 200) {
        const r = await db.from('links').insert(rows.slice(i, i + 200)).select('id')
        if (r.error) log('⚠ Liens non enregistrés : ' + r.error.message)
        else linked += (r.data || []).length
      }
    }
    log(`Topologie (SNMP) : ${polled.length} équipement(s) lu(s), ${unreachable} sans réponse, ${created} appareil(s) ajouté(s), ${linked} lien(s).`)
    return { polled: polled.length, unreachable, created, updated, links: linked }
  }

  return { run }
}
