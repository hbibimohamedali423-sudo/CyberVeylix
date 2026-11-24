// Vérifications de la logique R3 (aucune dépendance) : node scripts/r3-check.mjs
import assert from 'node:assert/strict'
import { isCve, cveUrl, cvesOf, sourceOf, sensorState, SENSOR_STALE_MS, isMissingTableMessage, parseCommandResult, isActiveCommand, pickSensorFor, blockState } from '../src/lib/findings.js'

let passed = 0
const failures = []
function check(name, fn) {
  try { fn(); passed += 1; console.log(`PASS  ${name}`) } catch (e) {
    failures.push(name); console.log(`FAIL  ${name}`); console.log(`      ${String(e.message).split('\n')[0]}`)
  }
}

check('format CVE reconnu', () => {
  assert.equal(isCve('CVE-2024-6387'), true)
  assert.equal(isCve(' cve-2017-0144 '), true)
  assert.equal(isCve('CVE-24-1'), false)
  assert.equal(isCve('javascript:alert(1)'), false)
  assert.equal(isCve(null), false)
})

check('lien NVD uniquement pour une CVE valide', () => {
  assert.equal(cveUrl('CVE-2024-6387'), 'https://nvd.nist.gov/vuln/detail/CVE-2024-6387')
  assert.equal(cveUrl('http://exemple.test'), null)
})

check('cves : tableau stocké seulement', () => {
  assert.deepEqual(cvesOf({ cves: ['CVE-2024-6387', '', null] }), ['CVE-2024-6387'])
  assert.deepEqual(cvesOf({ cves: null }), [])
  assert.deepEqual(cvesOf({}), [])
})

check('source par défaut : manual', () => {
  assert.equal(sourceOf({}), 'manual')
  assert.equal(sourceOf({ source: null }), 'manual')
  assert.equal(sourceOf({ source: 'scan' }), 'scan')
})

check('état du capteur selon le dernier pouls', () => {
  const now = Date.parse('2026-11-24T12:00:00Z')
  assert.equal(sensorState({}, now).state, 'never')
  assert.equal(sensorState({ last_heartbeat: 'invalide' }, now).state, 'never')
  const fresh = sensorState({ last_heartbeat: new Date(now - 60000).toISOString(), started_at: '2026-11-24T08:00:00Z' }, now)
  assert.equal(fresh.state, 'running')
  assert.equal(fresh.since, '2026-11-24T08:00:00Z')
  const old = new Date(now - SENSOR_STALE_MS - 1).toISOString()
  assert.deepEqual(sensorState({ last_heartbeat: old }, now), { state: 'stopped', since: old })
})

check('table absente reconnue', () => {
  assert.equal(isMissingTableMessage("Could not find the table 'public.sensors' in the schema cache"), true)
  assert.equal(isMissingTableMessage('permission denied'), false)
})

check('résultat de commande : JSON, texte libre, vide', () => {
  assert.deepEqual(parseCommandResult('{"code":"scan_done","hosts":3}'), { code: 'scan_done', hosts: 3 })
  assert.deepEqual(parseCommandResult('terminé'), { code: 'raw', message: 'terminé' })
  assert.deepEqual(parseCommandResult('{"x":1}'), { code: 'raw', message: '{"x":1}' })
  assert.equal(parseCommandResult(null), null)
  assert.equal(parseCommandResult(''), null)
})

check('commande active : pending et running seulement', () => {
  assert.equal(isActiveCommand({ status: 'pending' }), true)
  assert.equal(isActiveCommand({ status: 'running' }), true)
  assert.equal(isActiveCommand({ status: 'done' }), false)
  assert.equal(isActiveCommand(undefined), false)
})

check('capteur choisi pour un blocage : en service, réseau de l\'alerte en priorité', () => {
  const now = Date.parse('2026-11-24T12:00:00Z')
  const hb = (min) => new Date(now - min * 60000).toISOString()
  const sensors = [
    { id: 'a', network_id: 'n1', last_heartbeat: hb(1) },
    { id: 'b', network_id: 'n2', last_heartbeat: hb(2) },
    { id: 'c', network_id: 'n2', last_heartbeat: hb(120) }, // arrêté
  ]
  assert.equal(pickSensorFor({ network_id: 'n2' }, sensors, now).id, 'b')
  assert.equal(pickSensorFor({ network_id: 'n9' }, sensors, now).id, 'a') // autre réseau : premier en service
  assert.equal(pickSensorFor({ network_id: 'n2' }, [sensors[2]], now), null) // aucun en service
  assert.equal(pickSensorFor({}, [], now), null)
})

check('état du blocage : actif, en attente, aucun', () => {
  const blocked = [{ ip: '10.0.0.5', status: 'active' }, { ip: '10.0.0.6', status: 'released' }]
  const cmds = [{ kind: 'block_ip', status: 'pending', params: { ip: '10.0.0.7' } }, { kind: 'block_ip', status: 'done', params: { ip: '10.0.0.8' } }]
  assert.equal(blockState('10.0.0.5', blocked, cmds), 'blocked')
  assert.equal(blockState('10.0.0.6', blocked, cmds), 'none') // libérée
  assert.equal(blockState('10.0.0.7', blocked, cmds), 'pending')
  assert.equal(blockState('10.0.0.8', blocked, cmds), 'none') // demande terminée
  assert.equal(blockState(null, blocked, cmds), 'none')
})

console.log('')
if (failures.length) { console.log(`${failures.length} vérification(s) en échec : ${failures.join(', ')}`); process.exitCode = 1 }
else console.log(`${passed} vérifications réussies.`)
