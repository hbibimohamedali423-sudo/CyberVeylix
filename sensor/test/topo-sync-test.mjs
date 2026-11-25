// Chaîne complète « lecture des switchs → base » : faux switchs répondant aux OID standard, fausse base.
import assert from 'node:assert/strict'
import { OID } from '../lib/snmp-mibs.mjs'
import { createTopologySync } from '../lib/topo-sync.mjs'
import { createOui } from '../lib/oui.mjs'
import { mixedNetwork, MACS } from './snmp-test.mjs'

const parts = (mac) => mac.split(':').map((h) => parseInt(h, 16))
const buf = (mac) => Buffer.from(parts(mac))
const txt = (s) => Buffer.from(s)

// Scénario → réponses SNMP (OID → valeur) d'un switch, au format renvoyé par net-snmp.
function agentData(p) {
  const rows = []
  const add = (oid, value) => rows.push({ oid, value })
  add(OID.sysName, txt(p.sysName)); add(OID.sysDescr, txt(p.sysDescr)); add(OID.bridgeAddress, buf(p.ownMacs[0]))
  for (const [i, n] of p.ifNames) add(`${OID.ifName}.${i}`, txt(n))
  for (const [b, i] of p.basePorts) add(`${OID.basePortIfIndex}.${b}`, i)
  for (const e of p.fdb) add(`${OID.dot1qTpFdbPort}.${e.vlan}.${parts(e.mac).join('.')}`, e.bridgePort)
  p.neighbors.forEach((n, k) => {
    const idx = `0.${n.localPortNum}.${k + 1}`
    add(`${OID.lldpLocPortDesc}.${n.localPortNum}`, txt(n.localPort))
    add(`${OID.lldpRem}.4.${idx}`, 4); add(`${OID.lldpRem}.5.${idx}`, buf(n.mac))
    add(`${OID.lldpRem}.7.${idx}`, txt(n.remotePort)); add(`${OID.lldpRem}.9.${idx}`, txt(n.sysName))
    add(`${OID.lldpRem}.12.${idx}`, Buffer.from([(n.caps.bridge ? 0x20 : 0) | (n.caps.wlanAp ? 0x10 : 0), 0]))
    if (n.mgmtIp) add(`${OID.lldpRemManAddrIfSubtype}.${idx}.1.4.${n.mgmtIp}`, 2)
  })
  for (const a of p.arp) add(`${OID.ipNetToMediaPhysAddress}.3.${a.ip}`, buf(a.mac))
  return rows
}

function fakeSnmp(switches, { community = 'lecture' } = {}) {
  const data = new Map(switches.map((p) => [p.ip, agentData(p)]))
  const asked = []
  return {
    asked,
    probe: async (target, creds) => {
      asked.push(target.host)
      const cred = creds.find((c) => c.community === community)
      return data.has(target.host) && cred ? { session: { host: target.host }, cred } : null
    },
    get: async (s, oids) => ({ rows: data.get(s.host).filter((r) => oids.includes(r.oid)) }),
    walk: async (s, oid) => ({ rows: data.get(s.host).filter((r) => r.oid.startsWith(oid + '.')) }),
    open: () => ({ on() {} }), close: () => {},
  }
}

function fakeDb(devices = []) {
  const db = { devices: devices.map((d) => ({ ...d })), links: [] }
  let seq = 0
  const query = (rows, apply) => {
    const f = []
    const q = {
      eq: (c, v) => { f.push((r) => r[c] === v); return q },
      in: (c, v) => { f.push((r) => v.includes(r[c])); return q },
      select: () => q,
      then: (ok, ko) => Promise.resolve(apply(rows, (r) => f.every((x) => x(r)))).then(ok, ko),
    }
    return q
  }
  return {
    db,
    from: (t) => ({
      select: () => query(db[t], (rows, m) => ({ data: rows.filter(m).map((r) => ({ ...r })), error: null })),
      update: (patch) => query(db[t], (rows, m) => { rows.filter(m).forEach((r) => Object.assign(r, patch)); return { error: null } }),
      delete: () => query(db[t], (rows, m) => { db[t] = rows.filter((r) => !m(r)); return { error: null } }),
      insert: (row) => {
        const list = [].concat(row).map((r) => ({ id: `${t}-${++seq}`, ...r }))
        db[t].push(...list)
        const out = { error: null, data: list.map((r) => ({ id: r.id })) }
        return { select: () => Promise.resolve(out), then: (ok, ko) => Promise.resolve(out).then(ok, ko) }
      },
    }),
  }
}

const TABLE = { '38C0EA': 'Fortinet, Inc.', '001B54': 'Cisco Systems, Inc', BC071D: 'TP-Link Systems Inc.', '000048': 'Seiko Epson Corporation', '4419B6': 'Hangzhou Hikvision Digital Technology', '94B40F': 'Aruba, a Hewlett Packard Enterprise Company', '3C5282': 'Hewlett Packard' }
const CONFIG = { credentials: [{ version: '2c', community: 'faux' }, { version: '2c', community: 'lecture' }], targets: [{ host: '10.15.0.2', port: 161 }], auto: true }

export function topoSyncChecks(check, checkAsync) {
  checkAsync('lecture des switchs → base : switchs, point Wi-Fi et appareils créés, liens au bon port', async () => {
    const client = fakeDb([
      { id: 'gw', network_id: 'n1', name: 'Passerelle Fortinet (10.15.0.1)', mac: MACS.gw, ip: '10.15.0.1', role: 'gateway', type: 'Accès Internet', role_evidence: 'Capteur : passerelle', discovery_source: 'sensor' },
      { id: 's2', network_id: 'n1', name: 'TP-Link (10.15.0.3)', mac: MACS.s2, ip: '10.15.0.3', role: 'other', type: 'Équipement réseau', role_confidence: 'à vérifier', role_evidence: 'Capteur : fabricant TP-Link', discovery_source: 'sensor' },
      { id: 'pr', network_id: 'n1', name: 'Imprimante compta', mac: MACS.printer, ip: '10.15.2.9', role: 'printer', type: 'Imprimante', role_evidence: 'saisi à la main', discovery_source: 'agent' },
    ])
    const snmp = fakeSnmp(mixedNetwork())
    const sync = createTopologySync({ db: client, snmp, config: CONFIG, oui: createOui({ table: TABLE }), log: () => {} })
    const r = await sync.run({ networkId: 'n1', gatewayIp: '10.15.0.1' })
    // SW-CORE (liste) et SW-ETAGE (voisin LLDP) lus ; la passerelle et le point Wi-Fi (voisin LLDP) ne répondent pas.
    assert.deepEqual([r.polled, r.unreachable], [2, 2])
    assert.ok(snmp.asked.includes('10.15.0.3') && snmp.asked.includes('10.15.0.50')) // découverts par LLDP
    const dev = (mac) => client.db.devices.find((d) => d.mac === mac)
    assert.deepEqual([dev(MACS.s1).role, dev(MACS.s1).type, dev(MACS.s1).hostname], ['switch', 'Équipement réseau', 'SW-CORE'])
    assert.deepEqual([dev(MACS.s2).role, dev(MACS.s2).role_confidence], ['switch', 'certaine']) // indice « TP-Link » confirmé par SNMP
    assert.equal(dev(MACS.ap).role, 'access_point')
    assert.deepEqual([dev(MACS.printer).name, dev(MACS.printer).role_evidence], ['Imprimante compta', 'saisi à la main']) // jamais écrasé
    assert.equal(dev(MACS.camera).role, 'camera') // créé et identifié par son fabricant
    assert.equal(dev(MACS.phone1).ip, '10.15.4.38') // IP lue dans la table ARP
    const link = (mac) => client.db.links.filter((l) => l.to_device_id === dev(mac).id)
    assert.equal(link(MACS.printer)[0].from_port, 'Gi1/0/3')
    assert.equal(link(MACS.printer)[0].from_device_id, dev(MACS.s1).id)
    assert.deepEqual([link(MACS.camera)[0].from_device_id, link(MACS.camera)[0].from_port], [dev(MACS.s2).id, 'port 5'])
    assert.deepEqual([link(MACS.phone2)[0].from_device_id, link(MACS.phone2)[0].medium], [dev(MACS.ap).id, 'wifi'])
    assert.ok(client.db.links.every((l) => l.network_id === 'n1' && l.evidence))
  })

  checkAsync('lecture des switchs : relancée, les liens sont remplacés (pas de doublons) ; liens manuels conservés', async () => {
    const client = fakeDb()
    client.db.links.push({ id: 'manuel', network_id: 'n1', source: 'manual', from_device_id: 'a', to_device_id: 'b' })
    const sync = createTopologySync({ db: client, snmp: fakeSnmp(mixedNetwork()), config: CONFIG, oui: createOui({ table: TABLE }), log: () => {} })
    await sync.run({ networkId: 'n1', gatewayIp: null })
    const n1 = client.db.links.length
    await sync.run({ networkId: 'n1', gatewayIp: null })
    assert.equal(client.db.links.length, n1)
    assert.ok(client.db.links.some((l) => l.id === 'manuel'))
    assert.equal(new Set(client.db.devices.map((d) => d.mac)).size, client.db.devices.length) // aucun appareil en double
  })

  checkAsync('lecture des switchs : mauvais identifiants ou adresses publiques → rien n\'est modifié', async () => {
    const client = fakeDb()
    client.db.links.push({ id: 'ancien', network_id: 'n1', source: 'fdb' })
    const snmp = fakeSnmp(mixedNetwork(), { community: 'autre' })
    const sync = createTopologySync({ db: client, snmp, config: { ...CONFIG, targets: [{ host: '10.15.0.2', port: 161 }, { host: '8.8.8.8', port: 161 }] }, log: () => {} })
    const r = await sync.run({ networkId: 'n1', gatewayIp: '10.15.0.1' })
    assert.equal(r.polled, 0)
    assert.ok(!snmp.asked.includes('8.8.8.8'))
    assert.deepEqual(client.db.links.map((l) => l.id), ['ancien']) // aucune lecture : anciens liens gardés
    assert.equal(await sync.run({ networkId: null }), null)
  })
}
