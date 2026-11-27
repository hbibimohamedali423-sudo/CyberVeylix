// Vérifications des indicateurs du tableau de bord HUD (aucune dépendance) : node scripts/hud-check.mjs
import assert from 'node:assert/strict'
import { deviceAtRisk, securityLevel, gauges, levelOf, headlineAlert, openAlerts, pendingFixes, portMatrix, lastScanAt, inventory, radarPoint } from '../src/lib/hud.js'

let passed = 0
const failures = []
function check(name, fn) {
  try { fn(); passed += 1; console.log(`PASS  ${name}`) } catch (e) { failures.push(name); console.log(`FAIL  ${name}\n      ${String(e.message).split('\n')[0]}`) }
}

const NOW = Date.parse('2026-11-26T12:00:00Z')
const devices = [
  { id: 'd1', name: 'srv', ip: '192.168.1.10', status: 'on', last_seen: '2026-11-26T11:58:00Z' },
  { id: 'd2', name: 'pc', ip: '192.168.1.21', status: 'on', last_seen: '2026-11-26T11:00:00Z' },
  { id: 'd3', name: 'cam', ip: '192.168.1.54', status: 'off', last_seen: null },
  { id: 'd4', name: 'nas', ip: null, status: 'un' },
]
const vulns = [
  { id: 'v1', device_id: 'd1', severity: 'h', status: 'open' },
  { id: 'v2', device_id: 'd2', severity: 'c', status: 'resolved' },
  { id: 'v3', device_id: 'd4', severity: 'm' },
]
const alerts = [
  { id: 'a1', severity: 'm', status: 'open', source_ip: '192.168.1.54', created_at: '2026-11-26T10:00:00Z' },
  { id: 'a2', severity: 'c', status: 'ack', source_ip: '192.168.1.21', created_at: '2026-11-26T11:00:00Z' },
  { id: 'a3', severity: 'h', created_at: '2026-11-26T09:00:00Z' },
]

check('appareil à risque : vulnérabilité haute ouverte', () => assert.equal(deviceAtRisk(devices[0], vulns, alerts), true))
check('vulnérabilité résolue et alerte prise en compte : pas de risque', () => assert.equal(deviceAtRisk(devices[1], vulns, alerts), false))
check('alerte ouverte venant de son adresse : risque', () => assert.equal(deviceAtRisk(devices[2], vulns, alerts), true))
check('vulnérabilité moyenne : pas de risque', () => assert.equal(deviceAtRisk(devices[3], vulns, alerts), false))

check('niveau de sécurité = appareils sûrs / total', () => {
  assert.deepEqual(securityLevel(devices, vulns, alerts), { safe: 2, total: 4, pct: 50 })
})
check('niveau de sécurité sans appareil : null (pas de chiffre inventé)', () => {
  assert.deepEqual(securityLevel([], [], []), { safe: 0, total: 0, pct: null })
})

check('jauges calculées sur les lignes enregistrées', () => {
  const sensors = [{ last_heartbeat: '2026-11-26T11:59:00Z', started_at: '2026-11-26T08:00:00Z' }, { last_heartbeat: '2026-11-25T10:00:00Z' }]
  const g = Object.fromEntries(gauges({ devices, vulns, alerts, sensors }, NOW).map((x) => [x.key, x]))
  assert.equal(g.alertsTreated.pct, 33)
  assert.equal(g.vulnsFixed.pct, 33)
  assert.equal(g.devicesOnline.pct, 50)
  assert.equal(g.sensorsRunning.n, 1)
  assert.equal(gauges({}, NOW)[0].pct, null)
})

check('couleur des jauges : seuils 80 / 50', () => {
  assert.equal(levelOf(80), 'good'); assert.equal(levelOf(79), 'warn'); assert.equal(levelOf(49), 'bad'); assert.equal(levelOf(null), 'none')
})

check('alerte mise en avant : critique/haute ouverte la plus récente', () => {
  assert.equal(headlineAlert(alerts).id, 'a3')
  assert.equal(headlineAlert([alerts[0]]).id, 'a1')
  assert.equal(headlineAlert([alerts[1]]), null)
})

check('alertes ouvertes triées par date', () => assert.deepEqual(openAlerts(alerts).map((a) => a.id), ['a1', 'a3']))

check('correctifs en attente par gravité', () => assert.deepEqual(pendingFixes(vulns), { total: 2, c: 0, h: 1, m: 1, l: 0 }))

check('matrice des ports : ports sensibles en premier, appareils comptés une fois', () => {
  const m = portMatrix([{ device_id: 'd1', port: 80 }, { device_id: 'd2', port: 80 }, { device_id: 'd1', port: 445 }, { device_id: 'd1', port: 445 }, { device_id: 'd1', port: 'x' }])
  assert.deepEqual(m, [{ port: 445, devices: 1, risky: true }, { port: 80, devices: 2, risky: false }])
})

check('dernier scan : date la plus récente, null sans donnée', () => {
  assert.equal(lastScanAt([{ last_scan_at: '2026-11-26T09:30:00Z' }], devices), Date.parse('2026-11-26T11:58:00Z'))
  assert.equal(lastScanAt([], []), null)
})

check('inventaire : appareils à risque en premier', () => {
  assert.deepEqual(inventory(devices, vulns, alerts).map((d) => d.id), ['d1', 'd3', 'd2', 'd4'])
})

check('radar : position stable et dans le cercle', () => {
  const p = radarPoint(devices[0], NOW)
  assert.deepEqual(p, radarPoint(devices[0], NOW))
  assert.ok(Math.hypot(p.x, p.y) <= 0.95 + 1e-9)
  assert.ok(Math.hypot(radarPoint(devices[2], NOW).x, radarPoint(devices[2], NOW).y) > 0.9)
})

console.log(`\n${passed} vérifications réussies.`)
if (failures.length) { console.log(`${failures.length} échec(s).`); process.exit(1) }
