// Tests de l'analyse d'atteignabilité VLAN-à-VLAN (purs, sans réseau).
// Adresses d'exemple : plages privées et de documentation (RFC 5737), jamais de vraies.
import assert from 'node:assert/strict'
import { parseAddressObjects, parseAddressGroups, parsePolicies } from '../lib/fortigate-parse.mjs'
import { resolveAddressNames, zonesFromInterfaces, buildVlanReachability } from '../lib/reachability.mjs'

// -- Fixtures ----------------------------------------------------------------------------------
const IFACES = [
  { name: 'vlan10', vlan: 10, parent: 'internal', ip: '192.168.10.1', cidr: '192.168.10.0/24' }, // caméras
  { name: 'vlan20', vlan: 20, parent: 'internal', ip: '192.168.20.1', cidr: '192.168.20.0/24' }, // comptabilité
  { name: 'vlan30', vlan: 30, parent: 'internal', ip: '192.168.30.1', cidr: '192.168.30.0/24' }, // invités
  { name: 'wan1', vlan: null, parent: null, ip: '203.0.113.5', cidr: '203.0.113.5/29' },
  { name: 'vlan99', vlan: 99, parent: 'internal', ip: null, cidr: null }, // pas de sous-réseau connu
]

const ADDR_ROWS = [
  { name: 'Cameras_net', type: 'ipmask', subnet: '192.168.10.0 255.255.255.0' },
  { name: 'Accounting_net', type: 'ipmask', subnet: '192.168.20.0 255.255.255.0' },
  { name: 'Guest_net', type: 'ipmask', subnet: ['192.168.30.0', '255.255.255.0'] },
  { name: 'Accounting_server', type: 'ipmask', subnet: '192.168.20.50 255.255.255.255' },
  { name: 'Mystery_fqdn', type: 'fqdn' },
]
const ADDRESSES = parseAddressObjects({ results: ADDR_ROWS })

const GROUP_ROWS = [
  { name: 'Internal_nets', member: [{ name: 'Cameras_net' }, { name: 'Accounting_net' }] },
  { name: 'Wrapped_guest', member: ['Guest_net'] }, // groupe à un seul membre
  { name: 'Loopy', member: ['Loopy'] }, // boucle directe
  { name: 'LoopA', member: ['LoopB'] }, { name: 'LoopB', member: ['LoopA'] }, // boucle croisée
]
const GROUPS = parseAddressGroups({ results: GROUP_ROWS })

// policyid croissant = ordre d'évaluation (comme l'API FortiOS par défaut).
function policies(rows) {
  return parsePolicies({ results: rows.map((r, i) => ({ policyid: i + 1, status: 'enable', action: 'accept', ...r })) })
}

export function reachabilityChecks(check) {
  check('reachability : « all »/« any » résolu comme tout l’espace IPv4, insensible à la casse', () => {
    const r = resolveAddressNames(['ALL', 'Any'], { addresses: ADDRESSES, groups: GROUPS })
    assert.equal(r.unresolved.length, 0)
    assert.deepEqual(r.ranges, [{ lo: 0, hi: 0xffffffff }, { lo: 0, hi: 0xffffffff }])
  })

  check('reachability : adresse directe résolue (sous-réseau « ip masque »)', () => {
    const r = resolveAddressNames(['Cameras_net'], { addresses: ADDRESSES, groups: GROUPS })
    assert.equal(r.unresolved.length, 0)
    assert.equal(r.ranges.length, 1)
    assert.ok(r.ranges[0].lo <= r.ranges[0].hi)
  })

  check('reachability : type non résolvable (fqdn) → marqué, jamais deviné', () => {
    const r = resolveAddressNames(['Mystery_fqdn'], { addresses: ADDRESSES, groups: GROUPS })
    assert.equal(r.ranges.length, 0)
    assert.equal(r.unresolved.length, 1)
    assert.match(r.unresolved[0].reason, /non résolvable/)
  })

  check('reachability : nom inconnu (ni adresse ni groupe) → non résolu, pas une exception', () => {
    const r = resolveAddressNames(['N’existe_pas'], { addresses: ADDRESSES, groups: GROUPS })
    assert.equal(r.ranges.length, 0)
    assert.match(r.unresolved[0].reason, /inconnue/)
  })

  check('reachability : groupe résolu récursivement (plusieurs membres)', () => {
    const r = resolveAddressNames(['Internal_nets'], { addresses: ADDRESSES, groups: GROUPS })
    assert.equal(r.unresolved.length, 0)
    assert.equal(r.ranges.length, 2)
  })

  check('reachability : groupe d’un seul membre, groupe de groupe', () => {
    const direct = resolveAddressNames(['Guest_net'], { addresses: ADDRESSES, groups: GROUPS })
    const wrapped = resolveAddressNames(['Wrapped_guest'], { addresses: ADDRESSES, groups: GROUPS })
    assert.deepEqual(wrapped.ranges, direct.ranges)
  })

  check('reachability : boucle de groupe directe → signalée, pas de boucle infinie', () => {
    const r = resolveAddressNames(['Loopy'], { addresses: ADDRESSES, groups: GROUPS })
    assert.equal(r.ranges.length, 0)
    assert.match(r.unresolved[0].reason, /boucle/)
  })

  check('reachability : boucle de groupe croisée (A↔B) → signalée, pas de boucle infinie', () => {
    const r = resolveAddressNames(['LoopA'], { addresses: ADDRESSES, groups: GROUPS })
    assert.equal(r.ranges.length, 0)
    assert.match(r.unresolved[0].reason, /boucle/)
  })

  check('reachability : profondeur de groupes bornée (au-delà de 8 niveaux)', () => {
    const deep = Array.from({ length: 10 }, (_, i) => ({ name: `G${i}`, member: [i === 9 ? 'Cameras_net' : `G${i + 1}`] }))
    const groups = parseAddressGroups({ results: deep })
    const r = resolveAddressNames(['G0'], { addresses: ADDRESSES, groups })
    assert.equal(r.ranges.length, 0)
    assert.match(r.unresolved[0].reason, /profond/)
  })

  check('zones : une interface sans sous-réseau connu n’est jamais une zone', () => {
    const zones = zonesFromInterfaces(IFACES)
    assert.deepEqual(zones.map((z) => z.name).sort(), ['vlan10', 'vlan20', 'vlan30', 'wan1'])
  })

  check('matrice : aucune règle → refus par défaut partout, aucune paire d’une zone vers elle-même', () => {
    const { zones, matrix } = buildVlanReachability({ interfaces: IFACES, policies: [], addresses: ADDRESSES, addressGroups: GROUPS })
    assert.equal(matrix.length, zones.length * (zones.length - 1))
    assert.ok(matrix.every((m) => m.allowed === false && /refus par défaut/.test(m.reason)))
    assert.ok(!matrix.some((m) => m.from === m.to))
  })

  check('matrice : règle d’autorisation qui correspond → allowed:true, preuve = cette règle', () => {
    const pols = policies([{ srcintf: ['vlan10'], dstintf: ['vlan20'], srcaddr: ['Cameras_net'], dstaddr: ['Accounting_net'] }])
    const { matrix } = buildVlanReachability({ interfaces: IFACES, policies: pols, addresses: ADDRESSES, addressGroups: GROUPS })
    const m = matrix.find((x) => x.from === 'vlan10' && x.to === 'vlan20')
    assert.equal(m.allowed, true)
    assert.deepEqual(m.evidence, [{ id: '1', name: null }])
  })

  check('matrice : règle désactivée → ignorée, refus par défaut', () => {
    const pols = policies([{ srcintf: ['vlan10'], dstintf: ['vlan20'], srcaddr: ['Cameras_net'], dstaddr: ['Accounting_net'], status: 'disable' }])
    const { matrix } = buildVlanReachability({ interfaces: IFACES, policies: pols, addresses: ADDRESSES, addressGroups: GROUPS })
    assert.equal(matrix.find((x) => x.from === 'vlan10' && x.to === 'vlan20').allowed, false)
  })

  check('matrice : règle de blocage qui correspond → allowed:false, raison explicite (pas juste « refus par défaut »)', () => {
    const pols = policies([{ srcintf: ['vlan10'], dstintf: ['vlan20'], srcaddr: ['Cameras_net'], dstaddr: ['Accounting_net'], action: 'deny' }])
    const { matrix } = buildVlanReachability({ interfaces: IFACES, policies: pols, addresses: ADDRESSES, addressGroups: GROUPS })
    const m = matrix.find((x) => x.from === 'vlan10' && x.to === 'vlan20')
    assert.equal(m.allowed, false)
    assert.match(m.reason, /bloqué explicitement/)
  })

  check('matrice : L’ORDRE DÉCIDE — un refus placé AVANT une autorisation pour le même trafic l’emporte', () => {
    const pols = policies([
      { srcintf: ['vlan10'], dstintf: ['vlan20'], srcaddr: ['Cameras_net'], dstaddr: ['Accounting_net'], action: 'deny' },
      { srcintf: ['vlan10'], dstintf: ['vlan20'], srcaddr: ['Cameras_net'], dstaddr: ['Accounting_net'], action: 'accept' },
    ])
    const { matrix } = buildVlanReachability({ interfaces: IFACES, policies: pols, addresses: ADDRESSES, addressGroups: GROUPS })
    const m = matrix.find((x) => x.from === 'vlan10' && x.to === 'vlan20')
    assert.equal(m.allowed, false) // la première règle (refus) décide, la seconde n'est jamais atteinte
    assert.equal(m.evidence[0].id, '1')
  })

  check('matrice : même règles, ORDRE INVERSÉ — l’autorisation placée en premier l’emporte', () => {
    const pols = policies([
      { srcintf: ['vlan10'], dstintf: ['vlan20'], srcaddr: ['Cameras_net'], dstaddr: ['Accounting_net'], action: 'accept' },
      { srcintf: ['vlan10'], dstintf: ['vlan20'], srcaddr: ['Cameras_net'], dstaddr: ['Accounting_net'], action: 'deny' },
    ])
    const { matrix } = buildVlanReachability({ interfaces: IFACES, policies: pols, addresses: ADDRESSES, addressGroups: GROUPS })
    const m = matrix.find((x) => x.from === 'vlan10' && x.to === 'vlan20')
    assert.equal(m.allowed, true)
    assert.equal(m.evidence[0].id, '1')
  })

  check('matrice : une règle ANTÉRIEURE non résolue dégrade une autorisation CONFIRMÉE plus loin vers « incertain »', () => {
    const pols = policies([
      { srcintf: ['vlan10'], dstintf: ['vlan20'], srcaddr: ['Mystery_fqdn'], dstaddr: ['Accounting_net'] }, // destination confirmée, source non résolue
      { srcintf: ['vlan10'], dstintf: ['vlan20'], srcaddr: ['Cameras_net'], dstaddr: ['Accounting_net'] }, // ensuite, autorisation confirmée
    ])
    const { matrix } = buildVlanReachability({ interfaces: IFACES, policies: pols, addresses: ADDRESSES, addressGroups: GROUPS })
    const m = matrix.find((x) => x.from === 'vlan10' && x.to === 'vlan20')
    assert.equal(m.allowed, null)
    assert.equal(m.evidence.length, 2)
    assert.match(m.reason, /antérieure non résolue/)
  })

  check('matrice : règle dont les deux côtés sont non résolus, sans aucune autre règle → incertain (jamais « deviné sûr »)', () => {
    const pols = policies([{ srcintf: ['vlan10'], dstintf: ['vlan20'], srcaddr: ['Mystery_fqdn'], dstaddr: ['Mystery_fqdn'] }])
    const { matrix } = buildVlanReachability({ interfaces: IFACES, policies: pols, addresses: ADDRESSES, addressGroups: GROUPS })
    assert.equal(matrix.find((x) => x.from === 'vlan10' && x.to === 'vlan20').allowed, null)
  })

  check('matrice : règle qui ne concerne pas cette paire (autres interfaces) → sans effet', () => {
    const pols = policies([{ srcintf: ['vlan30'], dstintf: ['vlan20'], srcaddr: ['Guest_net'], dstaddr: ['Accounting_net'] }])
    const { matrix } = buildVlanReachability({ interfaces: IFACES, policies: pols, addresses: ADDRESSES, addressGroups: GROUPS })
    assert.equal(matrix.find((x) => x.from === 'vlan10' && x.to === 'vlan20').allowed, false)
    assert.equal(matrix.find((x) => x.from === 'vlan30' && x.to === 'vlan20').allowed, true)
  })

  check('matrice : règle entièrement résolue qui ne recouvre ni A ni B → ignorée (pas « incertaine »)', () => {
    const pols = policies([{ srcintf: ['vlan10'], dstintf: ['vlan20'], srcaddr: ['Guest_net'], dstaddr: ['Guest_net'] }])
    const { matrix } = buildVlanReachability({ interfaces: IFACES, policies: pols, addresses: ADDRESSES, addressGroups: GROUPS })
    const m = matrix.find((x) => x.from === 'vlan10' && x.to === 'vlan20')
    assert.equal(m.allowed, false)
    assert.match(m.reason, /refus par défaut/)
  })

  check('matrice : interface « any » s’applique à toute zone', () => {
    const pols = policies([{ srcintf: ['any'], dstintf: ['any'], srcaddr: ['all'], dstaddr: ['all'] }])
    const { zones, matrix } = buildVlanReachability({ interfaces: IFACES, policies: pols, addresses: ADDRESSES, addressGroups: GROUPS })
    assert.equal(matrix.length, zones.length * (zones.length - 1))
    assert.ok(matrix.every((m) => m.allowed === true)) // segmentation effectivement nulle : la vraie valeur de cette analyse
  })

  check('matrice : groupe utilisé comme source d’une règle', () => {
    const pols = policies([{ srcintf: ['vlan10'], dstintf: ['vlan20'], srcaddr: ['Internal_nets'], dstaddr: ['Accounting_net'] }])
    const { matrix } = buildVlanReachability({ interfaces: IFACES, policies: pols, addresses: ADDRESSES, addressGroups: GROUPS })
    assert.equal(matrix.find((x) => x.from === 'vlan10' && x.to === 'vlan20').allowed, true)
  })
}
