// Vérifications de la logique R3 (aucune dépendance) : node scripts/r3-check.mjs
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { buildPhysical, groupByType } from '../src/lib/physical.js'
import { fileURLToPath } from 'node:url'
import { isCve, cveUrl, cvesOf, sourceOf, sensorState, SENSOR_STALE_MS, isMissingTableMessage, parseCommandResult, isActiveCommand, pickSensorFor, blockState, localFixOf, fixSensorFor, hostKey, buildTimeline, parseIpList, hourlyCounts, searchAll } from '../src/lib/findings.js'

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

check('correction locale : clé « local:<pc>:<id> » → capteur du même PC', () => {
  assert.deepEqual(localFixOf({ finding_key: 'local:pc-accueil:smbv1' }), { host: 'pc-accueil', id: 'smbv1' })
  assert.equal(localFixOf({ finding_key: 'local:pc:rm_rf' }), null) // id hors liste blanche
  assert.equal(localFixOf({ finding_key: '192.168.1.10:445:smb1-enabled' }), null) // faiblesse réseau : pas de bouton
  assert.equal(localFixOf({ finding_key: null }), null)
  assert.equal(localFixOf(undefined), null)
  assert.equal(hostKey('PC-Accueil'), 'pc-accueil')
  const sensors = [{ id: 'a', name: 'SRV-1' }, { id: 'b', name: 'PC-Accueil' }]
  assert.equal(fixSensorFor({ finding_key: 'local:pc-accueil:telnet' }, sensors).id, 'b')
  assert.equal(fixSensorFor({ finding_key: 'local:autre:telnet' }, sensors), null)
})

check('journal SOC : événements enregistrés seulement, du plus récent au plus ancien', () => {
  const tl = buildTimeline({
    alerts: [{ id: 'a', created_at: '2026-11-24T10:00:00Z' }, { id: 'x', created_at: null }],
    vulns: [{ id: 'v', created_at: '2026-11-24T09:00:00Z', status: 'resolved', resolved_at: '2026-11-24T11:00:00Z' }, { id: 'w', created_at: '2026-11-24T08:00:00Z', status: 'open' }],
    commands: [{ id: 'c', created_at: '2026-11-24T10:30:00Z' }],
    blocked: [{ id: 'b', blocked_at: '2026-11-24T10:40:00Z', status: 'released', released_at: '2026-11-24T12:00:00Z' }, { id: 'f', blocked_at: '2026-11-24T10:45:00Z', status: 'failed' }],
  })
  assert.deepEqual(tl.map((i) => i.id), ['unblock:b', 'vuln_resolved:v', 'block:b', 'command:c', 'alert:a', 'vuln_new:v', 'vuln_new:w'])
  assert.equal(buildTimeline({ alerts: Array.from({ length: 5 }, (_, i) => ({ id: i, created_at: `2026-11-2${i}T00:00:00Z` })) }, 3).length, 3)
  assert.deepEqual(buildTimeline(), [])
})

check('liste de confiance : IPv4 valides, doublons retirés, erreurs signalées', () => {
  assert.deepEqual(parseIpList('192.168.1.5, 192.168.1.6\n192.168.1.5;abc 300.1.1.1'), { ips: ['192.168.1.5', '192.168.1.6'], invalid: ['abc', '300.1.1.1'], tooMany: false })
  assert.deepEqual(parseIpList(''), { ips: [], invalid: [], tooMany: false })
  assert.equal(parseIpList(Array.from({ length: 101 }, (_, i) => `10.0.${Math.floor(i / 250)}.${i % 250}`).join(' ')).tooMany, true)
})

// Régression : le tableau de bord lit chaque table triée par created_at (src/useRows.js). Une table lue
// sans cette colonne renvoie une erreur 400 (« Erreur de synchronisation ») : vérifié sur les scripts SQL.
check('chaque table lue par le tableau de bord a une colonne created_at (scripts supabase/)', () => {
  const root = fileURLToPath(new URL('..', import.meta.url))
  const files = (dir) => readdirSync(dir).flatMap((n) => { const f = join(dir, n); return statSync(f).isDirectory() ? files(f) : [f] })
  const tables = new Set()
  for (const f of files(join(root, 'src')).filter((f) => /\.(js|jsx)$/.test(f))) {
    for (const m of readFileSync(f, 'utf8').matchAll(/useRows\('([a-z_]+)'/g)) tables.add(m[1])
  }
  assert.ok(tables.size >= 9, `seulement ${tables.size} table(s) trouvée(s)`)
  const sql = readdirSync(join(root, 'supabase')).filter((n) => n.endsWith('.sql')).map((n) => readFileSync(join(root, 'supabase', n), 'utf8')).join('\n')
  for (const t of tables) {
    const created = new RegExp(`create table if not exists public\\.${t} \\(([\\s\\S]*?)\\n\\);`).exec(sql)
    const inCreate = created && /\bcreated_at\b/.test(created[1])
    const added = new RegExp(`alter table public\\.${t} add column if not exists created_at\\b`).test(sql)
    assert.ok(inCreate || added, `table ${t} : colonne created_at absente des scripts SQL`)
  }
})

check('branchements réels : arbre passerelle → switchs → ports → appareils, Wi-Fi sous son point d\'accès', () => {
  const d = (id, role, name, type = null) => ({ id, role, name, type })
  const devices = [d('gw', 'gateway', 'Fortinet'), d('s1', 'switch', 'SW-CORE'), d('s2', 'switch', 'SW-ETAGE'), d('ap', 'access_point', 'AP-HALL'),
    d('pr', 'printer', 'Imprimante', 'Imprimante'), d('cam', 'camera', 'Caméra', 'Caméra'), d('ph', 'phone', 'iPhone', 'Téléphone'), d('pc1', 'workstation', 'PC-1', 'Poste'),
    d('pc10', 'workstation', 'PC-10', 'Poste'), d('lost', 'phone', 'Hors carte', 'Téléphone')]
  const L = (from, to, fromPort, medium = 'ethernet', source = 'fdb', toPort = null) => ({ from_device_id: from, to_device_id: to, from_port: fromPort, to_port: toPort, medium, source, status: 'observed' })
  const links = [L('s1', 'gw', 'Gi1/0/1'), L('s1', 's2', 'Gi1/0/2', 'ethernet', 'lldp', 'port 1'), L('s1', 'ap', 'Gi1/0/4', 'ethernet', 'lldp', 'eth0'),
    L('s1', 'pr', 'Gi1/0/3'), L('s2', 'cam', 'port 5'), L('ap', 'ph', null, 'wifi'), L('s1', 'pc10', 'Gi1/0/10'), L('s1', 'pc1', 'Gi1/0/9'),
    L('s1', 'inconnu', 'Gi1/0/7')] // lien vers un appareil supprimé : ignoré
  const r = buildPhysical(devices, links)
  assert.equal(r.roots.length, 1)
  const root = r.roots[0]
  assert.equal(root.device.id, 'gw') // la passerelle en tête
  const s1 = root.children[0]
  assert.deepEqual([s1.device.id, s1.via.parentPort, s1.via.port], ['s1', null, 'Gi1/0/1'])
  assert.deepEqual(s1.children.map((c) => c.device.id), ['s2', 'ap'])
  assert.deepEqual(s1.ports.map((p) => p.port), ['Gi1/0/3', 'Gi1/0/9', 'Gi1/0/10']) // ordre naturel des ports
  const ap = s1.children.find((c) => c.device.id === 'ap')
  assert.deepEqual([ap.ports[0].wifi, ap.ports[0].entries[0].device.id], [true, 'ph'])
  assert.deepEqual(r.stats, { cable: 4, wifi: 1, unknown: 0 })
  assert.deepEqual(r.unplaced.map((x) => x.id), ['lost'])
  assert.equal(buildPhysical(devices, []).hasLinks, false)
  assert.deepEqual(groupByType(devices).map((g) => [g.type, g.devices.length]).slice(0, 2), [['', 4], ['Poste', 2]])
})

check('activité : alertes enregistrées comptées par heure (24 h), hors fenêtre ignorées', () => {
  const now = Date.parse('2026-11-25T12:30:00Z')
  const b = hourlyCounts([{ created_at: '2026-11-25T12:05:00Z' }, { created_at: '2026-11-25T12:59:00Z' }, { created_at: '2026-11-25T11:00:00Z' },
    { created_at: '2026-11-24T12:59:00Z' }, { created_at: '2026-11-24T13:00:00Z' }, { created_at: null }, {}], now)
  assert.equal(b.length, 24)
  assert.equal(b[23].n, 2) // heure en cours
  assert.equal(b[22].n, 1)
  assert.equal(b[0].n, 1) // 24-11 13:00 : première heure de la fenêtre ; 12:59 la veille : hors fenêtre
  assert.equal(b.reduce((n, x) => n + x.n, 0), 4)
})

check('recherche : appareils, alertes, vulnérabilités ; 2 caractères minimum ; limite', () => {
  const data = { devices: [{ id: 1, name: 'Caméra parking', ip: '10.15.3.7', vendor: 'Hikvision' }], alerts: [{ id: 2, title: 'Balayage', source_ip: '10.15.3.70' }], vulns: [{ id: 3, title: 'SMBv1', cves: ['CVE-2017-0144'] }] }
  assert.deepEqual(searchAll(data, '10.15.3.7').map((r) => r.kind), ['device', 'alert'])
  assert.deepEqual(searchAll(data, 'hikv').map((r) => r.id), [1])
  assert.deepEqual(searchAll(data, 'cve-2017').map((r) => r.kind), ['vuln'])
  assert.deepEqual(searchAll(data, 'a'), [])
  assert.equal(searchAll({ devices: Array.from({ length: 20 }, (_, i) => ({ id: i, name: `PC-${i}` })) }, 'pc').length, 8)
})

console.log('')
if (failures.length) { console.log(`${failures.length} vérification(s) en échec : ${failures.join(', ')}`); process.exitCode = 1 }
else console.log(`${passed} vérifications réussies.`)
