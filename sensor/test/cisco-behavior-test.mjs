// Tests du moteur de détection réseau-large Cisco/SNMP (pur, sans réseau).
import assert from 'node:assert/strict'
import { createCiscoBehavior } from '../lib/cisco-behavior.mjs'
import { IP_IDENTIFIES_OFFENDER, ALERT_SOURCE } from '../lib/push.mjs'

const GW = '38:c0:ea:0d:59:2a'
const DEV = '3c:52:82:00:00:11'
const T0 = Date.parse('2026-11-26T12:00:00Z')

export function ciscoBehaviorChecks(check) {
  check('cisco : une seule localisation → rien (cas normal, y compris s’il n’y en a aucune)', () => {
    const eng = createCiscoBehavior()
    assert.deepEqual(eng.observeSnapshot([{ mac: DEV, locations: [{ switchIp: '10.0.0.2', port: 'Gi1/0/5' }] }], { now: T0 }), [])
    assert.deepEqual(eng.observeSnapshot([], { now: T0 }), [])
    assert.deepEqual(eng.observeSnapshot([{ mac: DEV, locations: [] }], { now: T0 }), [])
  })

  check('cisco : adresse apprise par deux switchs à la fois → doublon, gravité haute', () => {
    const eng = createCiscoBehavior()
    const ev = eng.observeSnapshot([{ mac: DEV, locations: [{ switchIp: '10.0.0.2', port: 'Gi1/0/5' }, { switchIp: '10.0.0.3', port: 'port 2' }] }], { now: T0 })
    assert.equal(ev.length, 1)
    assert.equal(ev[0].type, 'mac_duplicate_location')
    assert.equal(ev[0].severity, 'h')
    assert.equal(ev[0].mac, DEV)
    assert.match(ev[0].detail, /10\.0\.0\.2.*Gi1\/0\/5/)
    assert.match(ev[0].detail, /10\.0\.0\.3.*port 2/)
  })

  check('cisco : la passerelle dupliquée → gravité critique, type dédié', () => {
    const eng = createCiscoBehavior()
    const ev = eng.observeSnapshot(
      [{ mac: GW, locations: [{ switchIp: '10.0.0.2', port: 'Gi1/0/1' }, { switchIp: '10.0.0.5', port: 'Gi0/3' }] }],
      { gatewayMac: GW, now: T0 },
    )
    assert.equal(ev[0].type, 'gateway_duplicate_location')
    assert.equal(ev[0].severity, 'c')
  })

  check('cisco : une seule localisation pour la passerelle (cas normal : routeur non géré en SNMP) → rien', () => {
    const eng = createCiscoBehavior()
    const ev = eng.observeSnapshot([{ mac: GW, locations: [{ switchIp: '10.0.0.2', port: 'Gi1/0/1' }] }], { gatewayMac: GW, now: T0 })
    assert.equal(ev.length, 0)
  })

  check('cisco : trois localisations ou plus comptent comme un seul doublon (pas un par paire)', () => {
    const eng = createCiscoBehavior()
    const ev = eng.observeSnapshot([{ mac: DEV, locations: [{ switchIp: 'a' }, { switchIp: 'b' }, { switchIp: 'c' }] }], { now: T0 })
    assert.equal(ev.length, 1)
  })

  check('cisco : anti-répétition tant que le doublon persiste, ré-alerte après la fenêtre', () => {
    const eng = createCiscoBehavior({ cooldownMs: 10 * 60000 })
    const loc = [{ mac: DEV, locations: [{ switchIp: 'a' }, { switchIp: 'b' }] }]
    assert.equal(eng.observeSnapshot(loc, { now: T0 }).length, 1)
    assert.equal(eng.observeSnapshot(loc, { now: T0 + 60000 }).length, 0) // même passage peu après : silence
    assert.equal(eng.observeSnapshot(loc, { now: T0 + 11 * 60000 }).length, 1) // fenêtre expirée : ré-alerte
  })

  check('cisco : plusieurs adresses dupliquées dans le même passage → une alerte chacune', () => {
    const eng = createCiscoBehavior()
    const ev = eng.observeSnapshot([
      { mac: DEV, locations: [{ switchIp: 'a' }, { switchIp: 'b' }] },
      { mac: GW, locations: [{ switchIp: 'a' }, { switchIp: 'c' }] },
    ], { gatewayMac: GW, now: T0 })
    assert.equal(ev.length, 2)
    assert.deepEqual(ev.map((e) => e.type).sort(), ['gateway_duplicate_location', 'mac_duplicate_location'])
  })

  check('cisco : les nouveaux types sont bien pris en compte par push.mjs (origine « sensor », fautif identifié par MAC)', () => {
    for (const type of ['mac_duplicate_location', 'gateway_duplicate_location']) {
      assert.equal(ALERT_SOURCE[type], 'sensor')
      assert.ok(!IP_IDENTIFIES_OFFENDER.has(type)) // pas d'IP fiable ici : seule la MAC désigne l'appareil
    }
  })
}
