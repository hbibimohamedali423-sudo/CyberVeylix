// Tests de l'intégration FortiGate (lecture seule) : analyse, client HTTP (fetch simulé), exploitation.
// Aucune connexion réelle. Adresses d'exemple : RFC 5737 / plages privées.
import assert from 'node:assert/strict'
import { parseInterfaces, parseDhcpLeases, parseArpTable, parseSessions, parseAddressObjects, parseAddressGroups, parsePolicies, normMac, isIpv4, maskToPrefix, toArray } from '../lib/fortigate-parse.mjs'
import { createFortigateClient } from '../lib/fortigate.mjs'
import { applyFortigate } from '../lib/fortigate-sync.mjs'
import { createBehaviorEngine } from '../lib/behavior.mjs'
import { createThreatList } from '../lib/threatlist.mjs'

export function fortigateChecks(check, checkAsync) {
  check('fortigate : aides (mac, ipv4, masque, results objet/tableau)', () => {
    assert.equal(normMac('AA-BB-CC-00-11-22'), 'aa:bb:cc:00:11:22')
    assert.equal(normMac('zzz'), null)
    assert.ok(isIpv4('192.168.1.10'))
    assert.equal(isIpv4('999.1.1.1'), false)
    assert.equal(maskToPrefix('255.255.255.0'), 24)
    assert.equal(maskToPrefix('255.0.255.0'), null) // masque non contigu
    assert.deepEqual(toArray({ results: { port1: { ip: '1' } } }).map((x) => x.name), ['port1'])
  })

  check('fortigate : interfaces et VLAN (ip « adresse masque »)', () => {
    const r = parseInterfaces({ results: [
      { name: 'port1', ip: '192.168.1.1 255.255.255.0' },
      { name: 'vlan20', vlanid: 20, interface: 'port1', ip: '192.168.20.1 255.255.255.0' },
      { name: 'down', ip: '0.0.0.0 0.0.0.0' },
    ] })
    assert.deepEqual(r[0], { name: 'port1', vlan: null, parent: null, ip: '192.168.1.1', cidr: '192.168.1.1/24' })
    assert.equal(r[1].vlan, 20)
    assert.equal(r[1].cidr, '192.168.20.1/24')
    assert.equal(r[2].ip, null) // 0.0.0.0 ignorée
  })

  check('fortigate : baux DHCP (noms de champs variables)', () => {
    const r = parseDhcpLeases({ results: [
      { ip: '192.168.1.50', mac: 'aa:bb:cc:dd:ee:01', hostname: 'poste-1', interface: 'port1' },
      { ipaddr: '192.168.20.80', macaddr: 'AABBCCDDEE02', host: 'cam-2' },
    ] })
    assert.equal(r.length, 2)
    assert.equal(r[0].hostname, 'poste-1')
    assert.equal(r[1].ip, '192.168.20.80')
    assert.equal(r[1].mac, 'aa:bb:cc:dd:ee:02')
  })

  check('fortigate : table ARP', () => {
    const r = parseArpTable({ results: [
      { ip: '192.168.1.1', mac: '00:11:22:33:44:55', interface: 'port1' },
      { ip: 'pas-ip', mac: '00:11:22:33:44:56' },
    ] })
    assert.deepEqual(r, [{ ip: '192.168.1.1', mac: '00:11:22:33:44:55', iface: 'port1' }])
  })

  check('fortigate : sessions (deux conventions de noms)', () => {
    const r = parseSessions({ results: [
      { source_address: '192.168.1.50', destination_address: '203.0.113.9', destination_port: 443, protocol: 'tcp' },
      { saddr: '192.168.1.60', daddr: '192.168.1.10', dport: 22, sport: 51000, proto: 6 },
      { src: 'invalide', dst: '192.168.1.1' },
    ] })
    assert.equal(r.length, 2)
    assert.deepEqual(r[0], { src: '192.168.1.50', dst: '203.0.113.9', srcPort: null, dstPort: 443, proto: 'tcp' })
    assert.equal(r[1].dstPort, 22)
  })

  check('fortigate : objets adresse (sous-réseau, plage, type non résolvable)', () => {
    const r = parseAddressObjects({ results: [
      { name: 'Net1', type: 'ipmask', subnet: '192.168.1.0 255.255.255.0' },
      { name: 'Range1', type: 'iprange', 'start-ip': '192.168.1.10', 'end-ip': '192.168.1.20' },
      { name: 'Ext1', type: 'fqdn' },
    ] })
    assert.deepEqual([r[0].cidr, r[0].resolved], ['192.168.1.0/24', true])
    assert.deepEqual([r[1].resolved, r[1].lo <= r[1].hi], [true, true])
    assert.deepEqual([r[2].resolved, r[2].reason !== null], [false, true])
  })

  check('fortigate : groupes d’adresses (membres en noms, forme objet ou chaîne)', () => {
    const r = parseAddressGroups({ results: [{ name: 'G1', member: [{ name: 'Net1' }, 'Range1'] }] })
    assert.deepEqual(r, [{ name: 'G1', members: ['Net1', 'Range1'] }])
  })

  check('fortigate : règles de pare-feu (champs variables, action/état normalisés)', () => {
    const r = parsePolicies({ results: [
      { policyid: 12, name: 'Autoriser-LAN', srcintf: [{ name: 'vlan10' }], dstintf: [{ name: 'vlan20' }], srcaddr: [{ name: 'Net1' }], dstaddr: ['all'], action: 'accept', status: 'enable' },
      { policyid: 13, action: 'deny' },
    ] })
    assert.deepEqual([r[0].id, r[0].srcintf, r[0].dstintf, r[0].srcaddr, r[0].action, r[0].enabled], ['12', ['vlan10'], ['vlan20'], ['Net1'], 'accept', true])
    assert.deepEqual([r[1].name, r[1].action, r[1].enabled], [null, 'deny', true])
  })

  checkAsync('fortigate : client en lecture seule (GET + jeton Bearer, erreurs isolées)', async () => {
    const calls = []
    const payloads = {
      'cmdb/system/interface': { results: [{ name: 'port1', ip: '192.168.1.1 255.255.255.0' }] },
      'monitor/system/dhcp': { results: [{ ip: '192.168.1.50', mac: 'aa:bb:cc:dd:ee:01' }] },
      'monitor/network/arp': { results: [{ ip: '192.168.1.1', mac: '00:11:22:33:44:55' }] },
      'cmdb/firewall/address': { results: [{ name: 'Net1', type: 'ipmask', subnet: '192.168.1.0 255.255.255.0' }] },
      'cmdb/firewall/addrgrp': { results: [{ name: 'G1', member: [{ name: 'Net1' }] }] },
      'cmdb/firewall/policy': { results: [{ policyid: 1, srcintf: ['any'], dstintf: ['any'], srcaddr: ['all'], dstaddr: ['all'], action: 'accept' }] },
      'monitor/firewall/session': 'boom', // simulera une erreur
    }
    const fetchImpl = async (url, opts) => {
      calls.push({ url, method: opts.method, auth: opts.headers.Authorization })
      const key = Object.keys(payloads).find((k) => url.includes(k))
      const body = payloads[key]
      if (body === 'boom') return { ok: false, status: 500, json: async () => ({}) }
      return { ok: true, status: 200, json: async () => body }
    }
    const client = createFortigateClient({ host: '192.168.1.254', token: 'SECRET', fetchImpl })
    const r = await client.poll()
    assert.ok(calls.every((c) => c.method === 'GET'), 'uniquement des GET')
    assert.ok(calls.every((c) => c.auth === 'Bearer SECRET'), 'jeton Bearer envoyé')
    assert.ok(calls.every((c) => c.url.startsWith('https://192.168.1.254:443/')))
    assert.equal(r.leases.length, 1)
    assert.equal(r.interfaces.length, 1)
    assert.equal(r.addresses.length, 1)
    assert.equal(r.addressGroups.length, 1)
    assert.equal(r.policies.length, 1)
    assert.ok(r.errors.sessions) // le point en échec est isolé, les autres réussissent
  })

  check('fortigate : hôte ou jeton manquant -> refus clair', () => {
    assert.throws(() => createFortigateClient({ token: 'x', fetchImpl: () => {} }))
    assert.throws(() => createFortigateClient({ host: 'h', fetchImpl: () => {} }))
  })

  check('fortigate : exploitation -> inventaire + détection de comportement', () => {
    const observed = []
    const inventory = { observe: (mac, ip) => observed.push({ mac, ip }) }
    const threatList = createThreatList(['203.0.113.9'])
    const behavior = createBehaviorEngine({ threatList, horizontalThreshold: 10, windowMs: 60000 })
    const poll = {
      interfaces: [{ name: 'vlan20', vlan: 20, cidr: '192.168.20.0/24' }, { name: 'vlan30', vlan: 30, cidr: '192.168.30.0/24' }, { name: 'port1', vlan: null }],
      leases: [{ ip: '192.168.1.50', mac: 'aa:bb:cc:dd:ee:01' }, { ip: '192.168.20.80', mac: 'aa:bb:cc:dd:ee:02' }],
      arp: [{ ip: '192.168.1.1', mac: '00:11:22:33:44:55' }],
      sessions: [
        { src: '192.168.1.66', dst: '203.0.113.9', dstPort: 443 }, // adresse malveillante connue
        ...Array.from({ length: 12 }, (_, i) => ({ src: '192.168.1.77', dst: `192.168.20.${i + 1}`, dstPort: 445 })), // balayage
      ],
      policies: [{ policyid: '1', name: null, srcintf: ['vlan30'], dstintf: ['vlan20'], srcaddr: ['all'], dstaddr: ['all'], service: [], action: 'accept', enabled: true }],
      addresses: [],
      addressGroups: [],
    }
    const r = applyFortigate(poll, { behavior, inventory, now: Date.parse('2026-11-26T12:00:00Z') })
    assert.equal(r.deviceCount, 3) // 2 baux + 1 ARP distincts
    assert.equal(r.vlanCount, 2) // vlan20 et vlan30 (port1 n'a pas de VLAN)
    assert.equal(observed.length, 3) // tous enregistrés dans l'inventaire
    assert.ok(r.events.some((e) => e.type === 'malware_c2'))
    assert.ok(r.events.some((e) => e.type === 'lateral_scan'))
    // Matrice d'atteignabilité calculée à partir des mêmes règles lues (voir reachability-test.mjs
    // pour le détail de cette logique ; ici on vérifie seulement que fortigate-sync la relie bien).
    assert.equal(r.reachability.zones.length, 2)
    assert.equal(r.reachability.matrix.find((m) => m.from === 'vlan30' && m.to === 'vlan20').allowed, true)
  })
}
