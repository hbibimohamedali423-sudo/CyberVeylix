// Tests de la lecture des switchs : décodage des tables SNMP standard et reconstruction de la topologie.
import assert from 'node:assert/strict'
import { OID, parseFdb, parseIfNames, parseBasePorts, parseLldp, parseCdp, parseArpTable, parseVlans, lldpCaps, cleanSnmpText, indexAfter, macFromParts } from '../lib/snmp-mibs.mjs'
import { buildTopology, portKeys } from '../lib/topology.mjs'

const macParts = (mac) => mac.split(':').map((h) => parseInt(h, 16))
const macBuf = (mac) => Buffer.from(macParts(mac))
const vb = (oid, value) => ({ oid, value })

export const MACS = {
  gw: '38:c0:ea:0d:59:2a', s1: '00:1b:54:00:00:01', s2: 'bc:07:1d:00:00:02', printer: '00:00:48:aa:00:01', camera: '44:19:b6:00:00:01',
  ap: '94:b4:0f:00:00:0a', phone1: '2a:25:f9:09:7b:e7', phone2: '16:40:34:1c:d5:d9', pc1: '3c:52:82:00:00:11', pc2: '3c:52:82:00:00:12', pc3: '3c:52:82:00:00:13',
}

// Réseau mixte : S1 (Cisco, cœur) ↔ S2 (TP-Link) ; routeur, imprimante, point Wi-Fi (2 téléphones), petit switch non géré (3 PC).
export function mixedNetwork() {
  const ifNames = (names) => new Map(names.map((n, i) => [i + 1, n]))
  const s1 = {
    ip: '10.15.0.2', ownMacs: [MACS.s1], sysName: 'SW-CORE', sysDescr: 'Cisco IOS Software, C2960X',
    ifNames: ifNames(['Gi1/0/1', 'Gi1/0/2', 'Gi1/0/3', 'Gi1/0/4', 'Gi1/0/5']), basePorts: new Map([[1, 1], [2, 2], [3, 3], [4, 4], [5, 5]]),
    fdb: [
      ['gw', 1], ['s2', 2], ['camera', 2], ['printer', 3], ['ap', 4], ['phone1', 4], ['phone2', 4], ['pc1', 5], ['pc2', 5], ['pc3', 5],
    ].map(([k, port]) => ({ mac: MACS[k], bridgePort: port, vlan: 1 })),
    neighbors: [
      { localPort: 'GigabitEthernet1/0/2', localPortNum: 2, mac: MACS.s2, remotePort: 'port 1', sysName: 'SW-ETAGE', caps: { bridge: true }, mgmtIp: '10.15.0.3', source: 'lldp' },
      { localPort: 'GigabitEthernet1/0/4', localPortNum: 4, mac: MACS.ap, remotePort: 'eth0', sysName: 'AP-HALL', sysDescr: 'Aruba AP-305', caps: { bridge: true, wlanAp: true }, mgmtIp: '10.15.0.50', source: 'lldp' },
    ],
    arp: [{ ip: '10.15.0.1', mac: MACS.gw }, { ip: '10.15.2.9', mac: MACS.printer }, { ip: '10.15.4.38', mac: MACS.phone1 }],
  }
  const s2 = {
    ip: '10.15.0.3', ownMacs: [MACS.s2], sysName: 'SW-ETAGE', sysDescr: 'TP-Link JetStream T1600G',
    ifNames: ifNames(['port 1', 'port 2', 'port 3', 'port 4', 'port 5']), basePorts: new Map([[1, 1], [5, 5]]),
    fdb: [
      ['camera', 5], ['gw', 1], ['s1', 1], ['printer', 1], ['ap', 1], ['phone1', 1], ['phone2', 1], ['pc1', 1], ['pc2', 1], ['pc3', 1],
    ].map(([k, port]) => ({ mac: MACS[k], bridgePort: port, vlan: 1 })),
    neighbors: [{ localPort: 'port 1', localPortNum: 1, mac: MACS.s1, remotePort: 'Gi1/0/2', sysName: 'SW-CORE', caps: { bridge: true }, mgmtIp: '10.15.0.2', source: 'lldp' }],
    arp: [],
  }
  return [s1, s2]
}

export function snmpChecks(check) {
  check('SNMP : index d\'OID et MAC', () => {
    assert.deepEqual(indexAfter(`${OID.dot1qTpFdbPort}.1.0.27.84.0.0.1`, OID.dot1qTpFdbPort), [1, 0, 27, 84, 0, 0, 1])
    assert.equal(indexAfter('1.3.6.1.2.1.99.1', OID.dot1qTpFdbPort), null)
    assert.equal(macFromParts([0, 27, 84, 0, 0, 1]), '00:1b:54:00:00:01')
    assert.equal(macFromParts([0, 27, 84, 0, 0, 999]), null)
    assert.equal(cleanSnmpText(Buffer.from('Gi1/0/1\u0000\u0007  x')), 'Gi1/0/1 x')
  })

  check('SNMP : table MAC (Q-BRIDGE, repli BRIDGE-MIB), port 0 ignoré, index invalide ignoré', () => {
    const q = [
      vb(`${OID.dot1qTpFdbPort}.10.${macParts(MACS.printer).join('.')}`, 3),
      vb(`${OID.dot1qTpFdbPort}.10.${macParts(MACS.s1).join('.')}`, 0), // l'équipement lui-même
      vb(`${OID.dot1qTpFdbPort}.10.1.2.3`, 4), // index tronqué
    ]
    assert.deepEqual(parseFdb(q, []), [{ mac: MACS.printer, bridgePort: 3, vlan: 10 }])
    const d = [vb(`${OID.dot1dTpFdbPort}.${macParts(MACS.camera).join('.')}`, 5)]
    assert.deepEqual(parseFdb([], d), [{ mac: MACS.camera, bridgePort: 5, vlan: null }])
  })

  check('SNMP : noms de ports et correspondance pont → interface', () => {
    const names = parseIfNames([vb(`${OID.ifName}.10101`, Buffer.from('Gi1/0/1'))], [vb(`${OID.ifDescr}.10101`, Buffer.from('GigabitEthernet1/0/1')), vb(`${OID.ifDescr}.10102`, Buffer.from('GigabitEthernet1/0/2'))])
    assert.equal(names.get(10101), 'Gi1/0/1') // ifName prioritaire
    assert.equal(names.get(10102), 'GigabitEthernet1/0/2')
    assert.deepEqual([...parseBasePorts([vb(`${OID.basePortIfIndex}.1`, 10101)]).entries()], [[1, 10101]])
  })

  check('SNMP : voisins LLDP (capacités, MAC, port distant, adresse de gestion)', () => {
    const base = OID.lldpRem
    const rem = [
      vb(`${base}.4.0.4.1`, 4), vb(`${base}.5.0.4.1`, macBuf(MACS.ap)), vb(`${base}.7.0.4.1`, Buffer.from('eth0')),
      vb(`${base}.9.0.4.1`, Buffer.from('AP-HALL')), vb(`${base}.12.0.4.1`, Buffer.from([0x30, 0x00])),
      vb(`${base}.4.0.2.7`, 7), vb(`${base}.5.0.2.7`, Buffer.from('SW-ETAGE')), vb(`${base}.9.0.2.7`, Buffer.from('SW-ETAGE')), vb(`${base}.12.0.2.7`, Buffer.from([0x20, 0x00])),
    ]
    const loc = [vb(`${OID.lldpLocPortDesc}.4`, Buffer.from('GigabitEthernet1/0/4'))]
    const man = [vb(`${OID.lldpRemManAddrIfSubtype}.0.4.1.1.4.10.15.0.50`, 2)]
    const n = parseLldp({ rem, locPortDesc: loc, manAddr: man })
    const ap = n.find((x) => x.sysName === 'AP-HALL')
    assert.deepEqual([ap.localPort, ap.mac, ap.remotePort, ap.mgmtIp, ap.caps.wlanAp, ap.caps.bridge], ['GigabitEthernet1/0/4', MACS.ap, 'eth0', '10.15.0.50', true, true])
    const sw = n.find((x) => x.sysName === 'SW-ETAGE')
    assert.deepEqual([sw.localPort, sw.mac, sw.caps.bridge, sw.caps.wlanAp], ['2', null, true, false]) // châssis non MAC : pas de MAC inventée
    assert.deepEqual(lldpCaps(Buffer.from([0x04])), { other: false, repeater: false, bridge: false, wlanAp: false, router: false, telephone: true, station: false })
  })

  check('SNMP : CDP, table ARP, VLAN Cisco', () => {
    const c = OID.cdpCache
    const cdp = parseCdp([vb(`${c}.4.10102.1`, Buffer.from([10, 15, 0, 3])), vb(`${c}.6.10102.1`, Buffer.from('SW-ETAGE')), vb(`${c}.7.10102.1`, Buffer.from('Gi0/1')), vb(`${c}.9.10102.1`, Buffer.from([0, 0, 0, 0x08]))], new Map([[10102, 'Gi1/0/2']]))
    assert.deepEqual([cdp[0].localPort, cdp[0].mgmtIp, cdp[0].sysName, cdp[0].remotePort, cdp[0].caps.bridge, cdp[0].ifIndex], ['Gi1/0/2', '10.15.0.3', 'SW-ETAGE', 'Gi0/1', true, 10102])
    const arp = parseArpTable([vb(`${OID.ipNetToMediaPhysAddress}.3.10.15.0.1`, macBuf(MACS.gw)), vb(`${OID.ipNetToMediaPhysAddress}.3.10.15.0.9`, Buffer.from([0, 0, 0, 0, 0, 0])), vb(`${OID.ipNetToMediaPhysAddress}.3.10.15.0`, macBuf(MACS.gw))])
    assert.deepEqual(arp, [{ ip: '10.15.0.1', mac: MACS.gw }])
    assert.deepEqual(parseVlans([vb(`${OID.vtpVlanState}.1.1`, 1), vb(`${OID.vtpVlanState}.1.20`, 1), vb(`${OID.vtpVlanState}.1.1002`, 1), vb(`${OID.vtpVlanState}.1.30`, 2)]), [1, 20])
  })

  check('SNMP : formes de noms de ports rapprochées (GigabitEthernet1/0/2 = Gi1/0/2 = port de pont 2)', () => {
    const a = portKeys({ name: 'Gi1/0/2', bridgePort: 2 })
    const b = portKeys({ name: 'GigabitEthernet1/0/2', bridgePort: 2 })
    assert.ok([...a].some((k) => b.has(k)))
    assert.ok(![...portKeys({ name: 'Gi1/0/3' })].some((k) => b.has(k) && k.startsWith('s:')))
  })

  check('topologie : chaque appareil sur son VRAI port (liaisons entre switchs écartées)', () => {
    const { links } = buildTopology(mixedNetwork())
    const to = (k) => links.filter((l) => l.toMac === MACS[k])
    const one = (k) => { const l = to(k); assert.equal(l.length, 1, `${k} : ${l.length} lien(s)`); return l[0] }
    assert.deepEqual([one('gw').fromIp, one('gw').fromPort, one('gw').status, one('gw').medium], ['10.15.0.2', 'Gi1/0/1', 'observed', 'ethernet'])
    assert.deepEqual([one('printer').fromPort, one('printer').status], ['Gi1/0/3', 'observed'])
    assert.deepEqual([one('camera').fromIp, one('camera').fromPort, one('camera').status], ['10.15.0.3', 'port 5', 'observed']) // pas sur le port de liaison de SW-CORE
    for (const pc of ['pc1', 'pc2', 'pc3']) assert.deepEqual([one(pc).fromPort, one(pc).status, one(pc).medium], ['Gi1/0/5', 'inferred', 'unknown'])
    assert.ok(one('pc1').evidence.includes('partagé par 3 appareils'))
  })

  check('topologie : point Wi-Fi relié par LLDP, téléphones rattachés en Wi-Fi à ce point d\'accès', () => {
    const { links, devices } = buildTopology(mixedNetwork())
    const ap = links.filter((l) => l.toMac === MACS.ap)
    assert.equal(ap.length, 1)
    assert.deepEqual([ap[0].source, ap[0].fromPort, ap[0].status], ['lldp', 'GigabitEthernet1/0/4', 'observed'])
    for (const ph of ['phone1', 'phone2']) {
      const l = links.filter((x) => x.toMac === MACS[ph])
      assert.equal(l.length, 1)
      assert.deepEqual([l[0].fromMac, l[0].medium, l[0].status], [MACS.ap, 'wifi', 'inferred'])
    }
    assert.equal(devices.find((d) => d.mac === MACS.ap).role, 'access_point')
    assert.equal(devices.find((d) => d.mac === MACS.s1).role, 'switch')
    assert.equal(devices.find((d) => d.mac === MACS.phone1).ip, '10.15.4.38') // IP lue dans la table ARP du cœur
  })

  check('topologie : liaison entre switchs une seule fois ; switchs jamais comptés comme extrémités', () => {
    const { links } = buildTopology(mixedNetwork())
    const sw = links.filter((l) => (l.toMac === MACS.s2 && l.fromMac === MACS.s1) || (l.toMac === MACS.s1 && l.fromMac === MACS.s2))
    assert.equal(sw.length, 1)
    assert.equal(sw[0].source, 'lldp')
    assert.equal(links.filter((l) => l.source === 'fdb' && (l.toMac === MACS.s1 || l.toMac === MACS.s2)).length, 0)
  })

  check('topologie : switch sans LLDP repéré par sa propre MAC dans la table du voisin', () => {
    const net = mixedNetwork().map((p) => ({ ...p, neighbors: [] }))
    const { links } = buildTopology(net)
    const cam = links.filter((l) => l.toMac === MACS.camera)
    assert.equal(cam.length, 1)
    assert.equal(cam[0].fromIp, '10.15.0.3')
  })

  check('topologie : aucune donnée → rien d\'inventé', () => {
    assert.deepEqual(buildTopology([]), { links: [], devices: [], arp: new Map(), hostLocations: [] })
  })

  check('topologie : localisations par hôte (une par switch ; liaisons entre switchs toujours écartées)', () => {
    const { hostLocations } = buildTopology(mixedNetwork())
    const of = (k) => hostLocations.find((h) => h.mac === MACS[k])
    assert.deepEqual(of('gw').locations, [{ switchIp: '10.15.0.2', port: 'Gi1/0/1' }]) // une seule : vu en extrémité sur S1 seulement
    assert.equal(of('s1'), undefined) // un switch interrogé n'est jamais un hôte (own.has)
    assert.equal(of('s2'), undefined)
    assert.deepEqual(of('camera').locations, [{ switchIp: '10.15.0.3', port: 'port 5' }])
  })

  check('topologie : une même adresse MAC apprise par DEUX switchs → doublon signalé (clonage ou usurpation)', () => {
    const net = mixedNetwork()
    // La caméra (normalement vue uniquement sur S2, port 5) apparaît AUSSI en extrémité sur S1, port 3
    // (remplace l'imprimante sur ce port, pour isoler le cas sans toucher au reste de la fixture).
    net[0].fdb = net[0].fdb.map((e) => (e.mac === MACS.printer ? { ...e, mac: MACS.camera } : e))
    const { hostLocations } = buildTopology(net)
    const dup = hostLocations.find((h) => h.mac === MACS.camera)
    assert.equal(dup.locations.length, 2)
    assert.ok(dup.locations.some((l) => l.switchIp === '10.15.0.2' && l.port === 'Gi1/0/3'))
    assert.ok(dup.locations.some((l) => l.switchIp === '10.15.0.3' && l.port === 'port 5'))
  })
}
