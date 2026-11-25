// Tests de l'identification et de l'inventaire : demandes DHCP, fabricant, classification, écriture en base.
import assert from 'node:assert/strict'
import { parseDhcpClientRequest, cleanText } from '../lib/parse-dhcp.mjs'
import { createOui, isRandomMac, shortVendor } from '../lib/oui.mjs'
import { classify } from '../lib/classify.mjs'
import { createInventory, cidrOf, inCidr, autoName, STALE_MS } from '../lib/inventory.mjs'
import { dhcpClientFrame, dhcpServerFrame } from './frames.mjs'

const TABLE = {
  '38C0EA': 'Fortinet, Inc.\n899 Kifer Road', D8B053: 'Xiaomi Communications Co Ltd\n#019', '4419B6': 'Hangzhou Hikvision Digital Technology Co.,Ltd.\nNo.555',
  '000048': 'Seiko Epson Corporation\n80 Harashinden', BC071D: 'TP-Link Systems Inc.\n10 Mauchly', '3C5282': 'Hewlett Packard\n11445 Compaq',
}

function fakeClient(tables = {}) {
  const db = { networks: [], devices: [], services: [], links: [], ...tables }
  let seq = 0
  const query = (rows, apply) => {
    const f = []
    let wantRows = false
    const q = {
      eq: (c, v) => { f.push((r) => r[c] === v); return q },
      in: (c, v) => { f.push((r) => v.includes(r[c])); return q },
      select: () => { wantRows = true; return q },
      then: (ok, ko) => Promise.resolve(apply(rows.filter((r) => f.every((x) => x(r))), wantRows)).then(ok, ko),
    }
    return q
  }
  return {
    db,
    from: (t) => ({
      select: () => query(db[t], (hit) => ({ data: hit.map((r) => ({ ...r })), error: null })),
      update: (patch) => query(db[t], (hit) => { hit.forEach((r) => Object.assign(r, patch)); return { error: null } }),
      delete: () => query(db[t], (hit) => { const gone = new Set(hit); db[t] = db[t].filter((r) => !gone.has(r)); return { error: null } }),
      insert: (rows) => {
        const list = [].concat(rows).map((r) => ({ id: `${t}${++seq}`, ...r }))
        db[t].push(...list)
        const out = { error: null, data: list.map((r) => ({ id: r.id })) }
        return { select: () => Promise.resolve(out), then: (ok, ko) => Promise.resolve(out).then(ok, ko) }
      },
    }),
  }
}

export function inventoryChecks(check, checkAsync) {
  check('DHCP appareil : nom, système, IP demandée, paramètres', () => {
    const d = parseDhcpClientRequest(dhcpClientFrame({ type: 3, mac: 'd8:b0:53:13:54:8d', hostname: 'Redmi-Note-12', vendorClass: 'android-dhcp-14', requestedIp: '10.15.4.64' }))
    assert.deepEqual(d, { messageType: 3, mac: 'd8:b0:53:13:54:8d', hostname: 'Redmi-Note-12', vendorClass: 'android-dhcp-14', params: '1,3,6,15', ip: '10.15.4.64' })
    const w = parseDhcpClientRequest(dhcpClientFrame({ type: 8, mac: '3c:52:82:aa:bb:cc', ciaddr: '10.15.2.20', vendorClass: 'MSFT 5.0' }))
    assert.deepEqual([w.ip, w.vendorClass, w.hostname], ['10.15.2.20', 'MSFT 5.0', null])
  })
  check('DHCP appareil : texte piégé nettoyé, trames hors sujet ou tronquées ignorées', () => {
    const d = parseDhcpClientRequest(dhcpClientFrame({ mac: 'aa:bb:cc:00:00:01', hostname: '<script>x\u0007"' + 'a'.repeat(100) }))
    assert.ok(!/[<>"\u0007]/.test(d.hostname) && d.hostname.length <= 63)
    assert.equal(cleanText(Buffer.from('\u0000\u0001')), null)
    assert.equal(parseDhcpClientRequest(dhcpServerFrame({ serverMac: 'aa:bb:cc:00:00:02', serverIp: '10.15.0.1' })), null) // réponse serveur
    const full = dhcpClientFrame({ mac: 'aa:bb:cc:00:00:01', hostname: 'pc' })
    for (const n of [0, 20, 100, 270, full.length - 3]) assert.doesNotThrow(() => parseDhcpClientRequest(full.subarray(0, n)))
    assert.equal(parseDhcpClientRequest(dhcpClientFrame({ type: 5, mac: 'aa:bb:cc:00:00:01' })), null) // pas une demande
    assert.equal(parseDhcpClientRequest(null), null)
  })

  check('fabricant : registre IEEE, MAC aléatoire jamais attribuée, nom court', () => {
    const o = createOui({ table: TABLE })
    assert.equal(o.vendorOf('38:C0:EA:0d:59:2a'), 'Fortinet')
    assert.equal(o.vendorOf('d8:b0:53:13:54:8d'), 'Xiaomi')
    assert.equal(o.vendorOf('44:19:b6:00:00:01'), 'Hangzhou Hikvision Digital')
    assert.equal(o.vendorOf('16:40:34:1c:d5:d9'), null) // aléatoire
    assert.equal(o.vendorOf('pas-une-mac'), null)
    assert.equal(o.vendorOf('00:11:22:33:44:55'), null) // inconnu : rien d'inventé
    assert.equal(isRandomMac('2a:25:f9:09:7b:e7'), true)
    assert.equal(isRandomMac('38:c0:ea:0d:59:2a'), false)
    assert.equal(shortVendor('Seiko Epson Corporation\nx'), 'Seiko Epson')
    assert.equal(shortVendor(''), null)
  })

  check('classification : chaque type avec sa preuve ; aucun indice → rien', () => {
    const t = (h) => { const r = classify(h); return [r.role, r.type, r.confidence] }
    assert.deepEqual(t({ vendor: 'Hangzhou Hikvision Digital', ports: [554] }), ['camera', 'Caméra', 'probable'])
    assert.deepEqual(t({ vendor: 'Seiko Epson' }), ['printer', 'Imprimante', 'probable'])
    assert.deepEqual(t({ vendor: 'Hewlett Packard', ports: [9100] }), ['printer', 'Imprimante', 'probable'])
    assert.deepEqual(t({ vendor: 'Xiaomi', vendorClass: 'android-dhcp-14' }), ['phone', 'Téléphone', 'probable'])
    assert.deepEqual(t({ randomMac: true, hostname: 'iPhone-de-Ali' }), ['phone', 'Téléphone', 'probable'])
    assert.deepEqual(t({ randomMac: true }), ['phone', 'Téléphone', 'à vérifier'])
    assert.deepEqual(t({ vendor: 'Apple', hostname: 'MacBook-Pro' }), ['workstation', 'Poste', 'probable'])
    assert.deepEqual(t({ vendor: 'Dell', vendorClass: 'MSFT 5.0', hostname: 'DESKTOP-AB12' }), ['workstation', 'Poste', 'probable'])
    assert.deepEqual(t({ vendor: 'TP-Link' }), ['other', 'Équipement réseau', 'à vérifier'])
    assert.deepEqual(t({ vendor: 'Fortinet', isGateway: true }), ['gateway', 'Accès Internet', 'certaine'])
    assert.deepEqual(t({ isSelf: true }), ['workstation', 'Poste', 'certaine'])
    assert.deepEqual(t({ vendor: 'VMware' }), ['server', 'Serveur', 'probable'])
    assert.deepEqual(t({ hostname: 'NPI8A1B2C' }), ['printer', 'Imprimante', 'probable'])
    assert.deepEqual(t({}), [null, null, null])
    // Fabricants réels vus sur un réseau d'entreprise, avec les noms COURTS produits par oui.mjs.
    const o = createOui({ table: { '3CEF8C': 'Hangzhou Huacheng Network Technology Co.,Ltd', '805EC0': 'YEALINK(XIAMEN) NETWORK TECHNOLOGY CO.,LTD.',
      F8A03D: 'Dinstar Technologies Co., Limited', '8C79F5': 'Samsung Electronics Co.,Ltd', ACCC8E: 'Axis Communications AB', '44650D': 'Amazon Technologies Inc.',
      '00A0B0': 'SHARP Corporation', '0007DF': 'Zebra Technologies Inc.', '00E0FC': 'HUAWEI TECHNOLOGIES CO.,LTD' } })
    const v = (mac) => o.vendorOf(mac)
    assert.deepEqual(t({ vendor: v('3c:ef:8c:00:00:01') }), ['camera', 'Caméra', 'probable']) // Huacheng = Dahua / Imou
    assert.deepEqual(t({ vendor: v('80:5e:c0:00:00:01') }), ['phone', 'Téléphone', 'probable']) // téléphone IP Yealink
    assert.deepEqual(t({ vendor: v('f8:a0:3d:00:00:01') }), ['other', 'Équipement réseau', 'à vérifier']) // passerelle VoIP
    assert.deepEqual(t({ vendor: v('8c:79:f5:00:00:01') }), ['phone', 'Téléphone', 'à vérifier']) // Samsung : téléphone ou TV
    assert.deepEqual(t({ vendor: v('ac:cc:8e:00:00:01') }), ['camera', 'Caméra', 'probable'])
    assert.deepEqual(t({ vendor: v('44:65:0d:00:00:01') }), ['iot', 'Objet connecté', 'à vérifier'])
    assert.deepEqual(t({ vendor: v('00:a0:b0:00:00:01') })[0], 'printer')
    assert.deepEqual(t({ vendor: v('00:07:df:00:00:01') })[0], 'printer')
    assert.deepEqual(t({ vendor: v('00:e0:fc:00:00:01') })[0], 'other') // Huawei réseau (≠ Huawei Device)
    assert.deepEqual(t({ vendor: 'TP-Link', hostname: 'TL-SG1428PE' }), ['switch', 'Équipement réseau', 'probable']) // switch nommé
    assert.deepEqual(t({ vendor: 'TP-Link', hostname: 'EAP225-Hall' }), ['access_point', 'Équipement réseau', 'probable'])
    assert.ok(classify({ vendor: 'Seiko Epson' }).evidence.includes('fabricant Seiko Epson'))
  })

  check('sous-réseau : calcul et appartenance', () => {
    assert.equal(cidrOf('10.15.5.117', '255.255.0.0'), '10.15.0.0/16')
    assert.equal(cidrOf('192.168.1.20', '255.255.255.0'), '192.168.1.0/24')
    assert.equal(cidrOf('192.168.1.20', '255.0.255.0'), null) // masque invalide
    assert.equal(inCidr('10.15.4.64', '10.15.0.0/16'), true)
    assert.equal(inCidr('192.168.1.5', '10.15.0.0/16'), false)
    assert.equal(autoName({ vendor: 'Xiaomi', ip: '10.15.4.64', mac: 'd8:b0:53:13:54:8d' }), 'Xiaomi (10.15.4.64)')
    assert.equal(autoName({ ip: '10.15.4.16', mac: '16:40:34:1c:d5:d9' }), 'Appareil d5:d9 (10.15.4.16)')
  })

  const NOW = new Date('2026-11-25T10:00:00Z')
  const mk = (tables) => {
    const client = fakeClient(tables)
    const inv = createInventory({ client, oui: createOui({ table: TABLE }), log: () => {}, now: () => NOW })
    inv.setSubnet('10.15.0.0/16')
    return { client, inv }
  }
  const CTX = { networkId: 'n1', gatewayIp: '10.15.0.1', gatewayMac: '38:c0:ea:0d:59:2a', sensorMac: '3c:52:82:aa:bb:cc' }

  checkAsync('inventaire : réseau créé une fois (MAC de passerelle confirmée), puis retrouvé', async () => {
    const { client, inv } = mk()
    const id1 = await inv.ensureNetwork({ gatewayMac: '38:c0:ea:0d:59:2a', gatewayIp: '10.15.0.1', name: 'Meridiana' })
    const id2 = await inv.ensureNetwork({ gatewayMac: '38:c0:ea:0d:59:2a', gatewayIp: '10.15.0.1', name: 'Meridiana' })
    assert.equal(id1, id2)
    assert.equal(client.db.networks.length, 1)
    assert.deepEqual([client.db.networks[0].name, client.db.networks[0].cidr], ['Meridiana', '10.15.0.0/16'])
    assert.equal(await inv.ensureNetwork({ gatewayMac: null }), null) // sans MAC confirmée : rien n'est créé
  })

  checkAsync('inventaire : appareils vus ajoutés, identifiés, avec preuve ; hors sous-réseau ignoré', async () => {
    const { client, inv } = mk()
    const t = NOW.getTime()
    inv.observe('38:c0:ea:0d:59:2a', '10.15.0.1', t)
    inv.observe('44:19:b6:00:00:01', '10.15.3.7', t)
    inv.observeDhcp({ mac: 'd8:b0:53:13:54:8d', ip: '10.15.4.64', hostname: 'Redmi-Note-12', vendorClass: 'android-dhcp-14' }, t)
    inv.observe('16:40:34:1c:d5:d9', '10.15.4.16', t)
    inv.observe('3c:52:82:aa:bb:cc', '10.15.5.117', t)
    inv.observe('aa:bb:cc:00:00:09', '192.168.1.9', t) // autre sous-réseau : MAC gardée, IP ignorée
    inv.observe('ff:ff:ff:ff:ff:ff', '10.15.0.255', t) // diffusion : ignorée
    inv.observe('01:00:5e:00:00:01', '10.15.0.9', t) // multicast : ignorée
    const r = await inv.sync(CTX)
    assert.equal(r.inserted, 6)
    const by = (mac) => client.db.devices.find((d) => d.mac === mac)
    assert.deepEqual([by('38:c0:ea:0d:59:2a').role, by('38:c0:ea:0d:59:2a').type, by('38:c0:ea:0d:59:2a').name], ['gateway', 'Accès Internet', 'Passerelle Fortinet (10.15.0.1)'])
    assert.deepEqual([by('44:19:b6:00:00:01').role, by('44:19:b6:00:00:01').type], ['camera', 'Caméra'])
    assert.deepEqual([by('d8:b0:53:13:54:8d').role, by('d8:b0:53:13:54:8d').name], ['phone', 'Redmi-Note-12'])
    assert.equal(by('16:40:34:1c:d5:d9').role_confidence, 'à vérifier')
    assert.equal(by('3c:52:82:aa:bb:cc').role_confidence, 'certaine') // PC du capteur
    assert.equal(by('aa:bb:cc:00:00:09').ip, null)
    assert.ok(client.db.devices.every((d) => d.network_id === 'n1' && d.discovery_source === 'sensor' && d.status === 'on'))
    assert.ok(by('44:19:b6:00:00:01').role_evidence.startsWith('Capteur : fabricant Hangzhou Hikvision'))
    assert.equal(client.db.devices.some((d) => d.mac === 'ff:ff:ff:ff:ff:ff' || d.mac === '01:00:5e:00:00:01'), false)
  })

  checkAsync('inventaire : nom, type et rôle choisis à la main JAMAIS écrasés ; IP suivie par la MAC', async () => {
    const { client, inv } = mk({ devices: [
      { id: 'd1', network_id: 'n1', name: 'Caméra parking', mac: '44:19:b6:00:00:01', ip: '10.15.3.7', type: 'Poste', role: 'workstation', role_evidence: 'choisi à la main', status: 'off', discovery_source: 'agent', last_seen: '2026-11-20T00:00:00Z' },
    ] })
    inv.observe('44:19:b6:00:00:01', '10.15.3.99', NOW.getTime())
    await inv.sync(CTX)
    const d = client.db.devices[0]
    assert.equal(client.db.devices.length, 1) // pas de doublon
    assert.deepEqual([d.name, d.type, d.role, d.role_evidence], ['Caméra parking', 'Poste', 'workstation', 'choisi à la main'])
    assert.deepEqual([d.ip, d.status, d.vendor], ['10.15.3.99', 'on', 'Hangzhou Hikvision Digital'])
  })

  checkAsync('inventaire : nom automatique remplacé par le vrai nom ; identification affinée', async () => {
    const { client, inv } = mk({ devices: [
      { id: 'd2', network_id: 'n1', name: 'Appareil d5:d9 (10.15.4.16)', mac: '16:40:34:1c:d5:d9', ip: '10.15.4.16', role: 'phone', type: 'Téléphone', role_confidence: 'à vérifier', role_evidence: 'Capteur : adresse MAC aléatoire', status: 'on', discovery_source: 'sensor', last_seen: NOW.toISOString() },
    ] })
    inv.observeDhcp({ mac: '16:40:34:1c:d5:d9', ip: '10.15.4.16', hostname: 'iPhone-de-Sara' }, NOW.getTime())
    await inv.sync(CTX)
    const d = client.db.devices[0]
    assert.deepEqual([d.name, d.role, d.role_confidence], ['iPhone-de-Sara', 'phone', 'probable'])
  })

  checkAsync('inventaire : absent depuis longtemps → hors ligne (seulement les appareils du capteur)', async () => {
    const old = new Date(NOW.getTime() - STALE_MS - 60000).toISOString()
    const { client, inv } = mk({ devices: [
      { id: 'a', network_id: 'n1', name: 'x', mac: 'aa:aa:aa:00:00:01', status: 'on', discovery_source: 'sensor', last_seen: old },
      { id: 'b', network_id: 'n1', name: 'y', mac: 'aa:aa:aa:00:00:02', status: 'on', discovery_source: 'agent', last_seen: old },
      { id: 'c', network_id: 'n1', name: 'z', mac: 'aa:aa:aa:00:00:03', status: 'on', discovery_source: 'sensor', last_seen: old },
    ] })
    inv.observe('aa:aa:aa:00:00:03', '10.15.9.9', NOW.getTime()) // revu à l'instant
    const r = await inv.sync(CTX)
    assert.equal(r.offline, 1)
    assert.deepEqual(client.db.devices.map((d) => d.status), ['off', 'on', 'on'])
  })

  checkAsync('écoute LLDP passive : switch entendu créé, PC du capteur créé, liaison directe enregistrée', async () => {
    const { client, inv } = mk()
    inv.observeUplink({ source: 'lldp', chassisId: '00:1b:54:aa:bb:cc', senderMac: '00:1b:54:aa:bb:cc', sysName: 'SW-CORE', sysDescr: 'Cisco C2960X', mgmtIp: '10.15.0.2', portId: 'Gi1/0/7', caps: { bridge: true } }, NOW.getTime())
    const r = await inv.syncUplinks({ networkId: 'n1', sensorMac: '3c:52:82:aa:bb:cc', sensorIp: '10.15.5.117' })
    assert.deepEqual([r.switches, r.links], [1, 1])
    const sw = client.db.devices.find((d) => d.mac === '00:1b:54:aa:bb:cc')
    assert.deepEqual([sw.role, sw.type, sw.hostname, sw.ip], ['switch', 'Équipement réseau', 'SW-CORE', '10.15.0.2'])
    const self = client.db.devices.find((d) => d.mac === '3c:52:82:aa:bb:cc')
    assert.deepEqual([self.role, self.role_confidence], ['workstation', 'certaine'])
    const link = client.db.links[0]
    assert.deepEqual([link.from_device_id, link.to_device_id, link.from_port, link.medium, link.source, link.status], [sw.id, self.id, 'Gi1/0/7', 'ethernet', 'lldp', 'observed'])
    // Relancé : pas de doublon (switch, PC ni liaison)
    await inv.syncUplinks({ networkId: 'n1', sensorMac: '3c:52:82:aa:bb:cc', sensorIp: '10.15.5.117' })
    assert.equal(client.db.devices.filter((d) => d.mac === '00:1b:54:aa:bb:cc').length, 1)
    assert.equal(client.db.links.length, 1)
  })

  checkAsync('écoute LLDP : point d\'accès (capacité Wi-Fi) ; sans réseau ou sans voisin, rien', async () => {
    const { client, inv } = mk()
    inv.observeUplink({ source: 'cdp', chassisId: '94:b4:0f:00:00:0a', senderMac: '94:b4:0f:00:00:0a', sysName: 'AP-HALL', caps: { wlanAp: true, bridge: true }, portId: 'eth0' }, NOW.getTime())
    await inv.syncUplinks({ networkId: 'n1', sensorMac: '3c:52:82:aa:bb:cc' })
    assert.equal(client.db.devices.find((d) => d.mac === '94:b4:0f:00:00:0a').role, 'access_point')
    assert.deepEqual(await inv.syncUplinks({ networkId: null, sensorMac: '3c:52:82:aa:bb:cc' }), { switches: 0, links: 0 })
    const empty = mk()
    assert.deepEqual(await empty.inv.syncUplinks({ networkId: 'n1', sensorMac: '3c:52:82:aa:bb:cc' }), { switches: 0, links: 0 })
  })

  checkAsync('écoute LLDP : avec SNMP actif (writeLinks=false), switch gardé mais aucune liaison passive', async () => {
    const { client, inv } = mk()
    inv.observeUplink({ source: 'lldp', chassisId: '00:1b:54:aa:bb:cc', senderMac: '00:1b:54:aa:bb:cc', sysName: 'SW-X', caps: { bridge: true }, portId: 'Gi1/0/1' }, NOW.getTime())
    const r = await inv.syncUplinks({ networkId: 'n1', sensorMac: '3c:52:82:aa:bb:cc', writeLinks: false })
    assert.deepEqual([r.switches, r.links], [1, 0])
    assert.ok(client.db.devices.some((d) => d.hostname === 'SW-X'))
    assert.equal(client.db.links.length, 0)
  })

  checkAsync('inventaire : sans réseau rien n\'est écrit ; ports relevés utilisés pour le type', async () => {
    const { client, inv } = mk({ devices: [
      { id: 'p', network_id: 'n1', name: 'HP (10.15.2.2)', mac: '3c:52:82:00:00:02', ip: '10.15.2.2', status: 'on', discovery_source: 'sensor', last_seen: NOW.toISOString() },
    ], services: [{ device_id: 'p', port: 9100 }] })
    inv.observe('3c:52:82:00:00:02', '10.15.2.2', NOW.getTime())
    assert.deepEqual(await inv.sync({ ...CTX, networkId: null }), { inserted: 0, updated: 0, offline: 0 })
    await inv.sync(CTX)
    assert.deepEqual([client.db.devices[0].role, client.db.devices[0].type], ['printer', 'Imprimante'])
  })
}
