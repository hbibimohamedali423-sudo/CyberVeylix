// Vérifications du rapprochement des appareils de l'agent (aucune dépendance) : node scripts/agent-check.mjs
import assert from 'node:assert/strict'
import {
  normalizeMac, createIndex, matchHost, devicePatch, newDeviceAlert, sensitivePortAlerts, planOffline,
} from '../agent/lib/reconcile.mjs'

let passed = 0
const failures = []
function check(name, fn) {
  try {
    fn()
    passed += 1
    console.log(`PASS  ${name}`)
  } catch (e) {
    failures.push(name)
    console.log(`FAIL  ${name}`)
    console.log(`      ${String(e.message).split('\n')[0]}`)
  }
}

const SENSITIVE = { 23: ['h', 'Telnet, non chiffré'], 3389: ['m', 'Bureau à distance RDP'] }
const inRange = (ip) => ip.startsWith('192.168.1.')
const MIN = 60 * 1000

// Mini base en mémoire qui rejoue exactement les étapes de agent/scan.mjs avec le module pur.
function simulateScan(db, hosts, { nowMs, baseline = false }) {
  const nowIso = new Date(nowMs).toISOString()
  const index = createIndex(db.devices)
  const touched = new Set()
  const alerts = []
  for (const h of hosts) {
    const m = matchHost(h, index, touched)
    let id
    let prev = []
    if (m.device) {
      id = m.device.id
      Object.assign(m.device, devicePatch(h, m.device, nowIso))
      prev = db.services[id] || []
    } else {
      id = `dev${++db.seq}`
      const row = { id, name: h.name || h.ip, ip: h.ip, mac: normalizeMac(h.mac), status: 'on', last_seen: nowIso }
      db.devices.push(row)
      index.add(row)
      if (!baseline) alerts.push({ ...newDeviceAlert(h, m.replaced), device_id: id })
    }
    touched.add(id)
    if (!baseline) alerts.push(...sensitivePortAlerts(h, prev, SENSITIVE).map((a) => ({ ...a, device_id: id })))
    db.services[id] = h.ports || []
  }
  const { off } = planOffline(db.devices, touched, inRange, nowMs, 90 * MIN)
  for (const d of db.devices) if (off.includes(d.id)) d.status = 'off'
  return alerts
}
const newDb = (devices = []) => ({ devices, services: {}, seq: 0 })
const T0 = Date.parse('2026-11-24T08:00:00Z')

check('MAC normalisée (tirets Windows, majuscules), invalide → null', () => {
  assert.equal(normalizeMac('AA-BB-CC-00-11-22'), 'aa:bb:cc:00:11:22')
  assert.equal(normalizeMac('zz'), null)
  assert.equal(normalizeMac(null), null)
})

check('Téléphone dont l\'IP change (DHCP) : même appareil suivi par sa MAC, aucune alerte', () => {
  const db = newDb()
  simulateScan(db, [{ ip: '192.168.1.20', mac: 'aa:00:00:00:00:20', name: 'phone', ports: [] }], { nowMs: T0, baseline: true })
  const alerts = simulateScan(db, [{ ip: '192.168.1.57', mac: 'aa:00:00:00:00:20', ports: [] }], { nowMs: T0 + 60 * MIN })
  assert.equal(db.devices.length, 1)
  assert.equal(db.devices[0].ip, '192.168.1.57')
  assert.deepEqual(alerts, [])
})

check('Nouvelle MAC sur une IP connue : NOUVEL appareil + alerte citant l\'ancien occupant', () => {
  const db = newDb()
  simulateScan(db, [{ ip: '192.168.1.30', mac: 'aa:00:00:00:00:30', name: 'pc-compta', ports: [] }], { nowMs: T0, baseline: true })
  const alerts = simulateScan(db, [{ ip: '192.168.1.30', mac: 'bc:00:00:00:00:99', ports: [] }], { nowMs: T0 + 60 * MIN })
  assert.equal(db.devices.length, 2)
  assert.equal(db.devices[0].mac, 'aa:00:00:00:00:30') // l'ancien n'est jamais écrasé
  assert.equal(alerts.length, 1)
  assert.match(alerts[0].detail, /pc-compta \(aa:00:00:00:00:30\)/)
  assert.match(alerts[0].detail, /usurpation/)
})

check('L\'appareil dont l\'IP a été reprise passe « Hors ligne » après le délai (plus jugé présent par IP)', () => {
  const db = newDb()
  simulateScan(db, [{ ip: '192.168.1.30', mac: 'aa:00:00:00:00:30', ports: [] }], { nowMs: T0, baseline: true })
  simulateScan(db, [{ ip: '192.168.1.30', mac: 'bc:00:00:00:00:99', ports: [] }], { nowMs: T0 + 30 * MIN })
  assert.equal(db.devices[0].status, 'on') // encore dans le délai de grâce
  simulateScan(db, [{ ip: '192.168.1.30', mac: 'bc:00:00:00:00:99', ports: [] }], { nowMs: T0 + 120 * MIN })
  assert.equal(db.devices[0].status, 'off')
  assert.equal(db.devices[1].status, 'on')
})

check('Appareil ajouté à la main (sans last_seen) : jamais déclaré « Hors ligne » par l\'agent', () => {
  const db = newDb([{ id: 'manual', name: 'Imprimante', ip: '192.168.1.200', mac: null, status: 'un', last_seen: null }])
  simulateScan(db, [], { nowMs: T0 + 500 * MIN })
  assert.equal(db.devices[0].status, 'un')
})

check('Appareil ajouté à la main puis vu par l\'agent : repris (MAC complétée), pas de doublon', () => {
  const db = newDb([{ id: 'manual', name: 'Imprimante', ip: '192.168.1.200', mac: null, status: 'un', last_seen: null }])
  const alerts = simulateScan(db, [{ ip: '192.168.1.200', mac: 'AA-00-00-00-02-00', ports: [] }], { nowMs: T0 })
  assert.equal(db.devices.length, 1)
  assert.equal(db.devices[0].mac, 'aa:00:00:00:02:00')
  assert.equal(db.devices[0].status, 'on')
  assert.deepEqual(alerts, [])
})

check('Même MAC sur deux IP dans un scan : pas d\'alternance d\'IP sur un seul enregistrement', () => {
  const db = newDb()
  simulateScan(db, [{ ip: '192.168.1.1', mac: 'aa:00:00:00:00:01', ports: [] }], { nowMs: T0, baseline: true })
  simulateScan(db, [
    { ip: '192.168.1.1', mac: 'aa:00:00:00:00:01', ports: [] },
    { ip: '192.168.1.254', mac: 'aa:00:00:00:00:01', ports: [] },
  ], { nowMs: T0 + 60 * MIN })
  assert.equal(db.devices.find((d) => d.ip === '192.168.1.1').mac, 'aa:00:00:00:00:01')
  assert.ok(db.devices.find((d) => d.ip === '192.168.1.254'))
})

check('MAC illisible (hôte hors table ARP) : rapprochement par IP comme avant', () => {
  const db = newDb()
  simulateScan(db, [{ ip: '192.168.1.40', mac: 'aa:00:00:00:00:40', ports: [] }], { nowMs: T0, baseline: true })
  simulateScan(db, [{ ip: '192.168.1.40', mac: null, ports: [] }], { nowMs: T0 + 60 * MIN })
  assert.equal(db.devices.length, 1)
  assert.equal(db.devices[0].mac, 'aa:00:00:00:00:40') // MAC connue conservée
})

check('Ports sensibles : alerte seulement quand le port s\'ouvre, pas à chaque scan', () => {
  const db = newDb()
  simulateScan(db, [{ ip: '192.168.1.50', mac: 'aa:00:00:00:00:50', ports: [80] }], { nowMs: T0, baseline: true })
  const opened = simulateScan(db, [{ ip: '192.168.1.50', mac: 'aa:00:00:00:00:50', ports: [80, 23] }], { nowMs: T0 + 60 * MIN })
  assert.deepEqual(opened.map((a) => a.title), ['Port 23 ouvert (Telnet, non chiffré)'])
  const again = simulateScan(db, [{ ip: '192.168.1.50', mac: 'aa:00:00:00:00:50', ports: [80, 23] }], { nowMs: T0 + 120 * MIN })
  assert.deepEqual(again, [])
})

check('Premier inventaire : aucune alerte', () => {
  const db = newDb()
  const alerts = simulateScan(db, [{ ip: '192.168.1.60', mac: 'aa:00:00:00:00:60', ports: [23] }], { nowMs: T0, baseline: true })
  assert.deepEqual(alerts, [])
})

check('Appareil hors de la plage scannée : jamais touché', () => {
  const db = newDb([{ id: 'x', ip: '10.0.0.5', mac: null, status: 'on', last_seen: new Date(T0).toISOString() }])
  simulateScan(db, [], { nowMs: T0 + 500 * MIN })
  assert.equal(db.devices[0].status, 'on')
})

console.log('')
if (failures.length) {
  console.log(`${failures.length} vérification(s) en échec : ${failures.join(', ')}`)
  process.exitCode = 1
} else {
  console.log(`${passed} vérifications réussies.`)
}
