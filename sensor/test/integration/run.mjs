// Test d'intégration du capteur : le VRAI listener.mjs, avec une carte réseau simulée (stubmods/cap, à la place
// de Npcap) et une fausse base Supabase locale (mock-supabase.mjs). Vérifie le pouls, l'interface servie,
// config.js et l'exécution des demandes de la page. Lancement : npm run test:integration (après npm run build).
import { spawn } from 'node:child_process'
import { writeFileSync, mkdirSync, rmSync, cpSync, existsSync, mkdtempSync } from 'node:fs'
import { hostname, tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { startMock } from './mock-supabase.mjs'
import { arpFrame, dhcpClientFrame } from '../frames.mjs'
const HERE = fileURLToPath(new URL('.', import.meta.url))
const REPO = fileURLToPath(new URL('../../../', import.meta.url))
const SP = mkdtempSync(join(tmpdir(), 'cv-it-'))
mkdirSync(`${SP}/it`, { recursive: true })
if (!existsSync(`${REPO}/dist/index.html`)) { console.error('Lancez d\'abord npm run build (dossier dist absent).'); process.exit(1) }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const mock = await startMock(54399)
writeFileSync(`${SP}/it/test.env`, 'SUPABASE_URL=http://127.0.0.1:54399\nSUPABASE_ANON_KEY=anon-test\nCV_EMAIL=capteur@test\nCV_PASSWORD=MOT-DE-PASSE-TEST\n')
rmSync(`${SP}/it/data`, { recursive: true, force: true }); mkdirSync(`${SP}/it/data`, { recursive: true })
// Trames « reçues » par la carte simulée : passerelle Fortinet, caméra Hikvision, téléphone Xiaomi (DHCP avec nom).
const GW_MAC = '38:c0:ea:0d:59:2a'
writeFileSync(`${SP}/it/frames.json`, JSON.stringify([
  arpFrame({ op: 2, senderMac: GW_MAC, senderIp: '192.168.50.1' }),
  arpFrame({ op: 1, senderMac: '44:19:b6:00:00:01', senderIp: '192.168.50.20' }),
  dhcpClientFrame({ type: 3, mac: 'd8:b0:53:13:54:8d', hostname: 'Redmi-Note-12', vendorClass: 'android-dhcp-14', requestedIp: '192.168.50.64' }),
].map((b) => b.toString('hex'))))
const uiDir = `${REPO}/sensor/ui`; const hadUi = existsSync(uiDir)
if (!hadUi) cpSync(`${REPO}/dist`, uiDir, { recursive: true })
const proc = spawn(process.execPath, [`--env-file=${SP}/it/test.env`, `${REPO}/sensor/listener.mjs`, '--yes', '--push', '--ui', '--ui-port=8799', `--data-dir=${SP}/it/data`, '--learn-minutes=0', '--gateway=192.168.50.1', `--gateway-mac=${GW_MAC}`], { env: { ...process.env, NODE_PATH: join(HERE, 'stubmods'), CV_STUB_FRAMES: `${SP}/it/frames.json`, CV_TEST_INVENTORY_DELAY_MS: '1500' } })
let log = ''; proc.stdout.on('data', (d) => { log += d }); proc.stderr.on('data', (d) => { log += d })
const results = []; const ok = (name, cond, extra = '') => { results.push([cond ? 'PASS' : 'FAIL', name, extra]) }
try {
  for (let i = 0; i < 40 && !mock.db.sensors.length; i++) await sleep(250)
  const s = mock.db.sensors[0]
  ok('pouls : capteur enregistré dans sensors', !!s && s.name === hostname() && s.version && s.last_heartbeat, JSON.stringify(s || {}).slice(0, 120))
  let home = null
  for (let i = 0; i < 40 && !home; i++) { try { home = await fetch('http://127.0.0.1:8799/') } catch { await sleep(250) } }
  const cfg = await (await fetch('http://127.0.0.1:8799/config.js')).text()
  ok('interface servie par le capteur', !!home && home.status === 200 && (await home.text()).includes('<div id="root">'))
  ok('config.js : URL + clé anon, jamais le mot de passe', cfg.includes('anon-test') && !cfg.includes('MOT-DE-PASSE') && !cfg.includes('capteur@test'), cfg.trim())
  const add = (row) => fetch('http://127.0.0.1:54399/__db', { method: 'POST', body: JSON.stringify({ table: 'sensor_commands', row: { sensor_id: s.id, status: 'pending', params: {}, ...row } }) })
  await add({ kind: 'scan_now' })
  await add({ kind: 'block_ip', params: { ip: '192.168.50.99' } })
  await add({ kind: 'block_ip', params: { ip: '192.168.50.1' } })
  await add({ kind: 'fix', params: { id: 'smbv1' } })
  await add({ kind: 'unblock_ip', params: { ip: '192.168.50.99' } })
  for (let i = 0; i < 60 && mock.db.sensor_commands.some((c) => c.status === 'pending' || c.status === 'running'); i++) await sleep(250)
  const by = (k, ip) => mock.db.sensor_commands.find((c) => c.kind === k && (!ip || c.params.ip === ip))
  const res = (c) => (c && c.result ? JSON.parse(c.result) : {})
  // Les 2 appareils appris par ARP (passerelle et caméra simulées) sont analysés ; le PC du capteur, jamais.
  ok('scan_now exécuté sur les appareils appris par ARP', by('scan_now').status === 'done' && res(by('scan_now')).code === 'scan_done' && res(by('scan_now')).hosts === 2, by('scan_now').status + ' ' + by('scan_now').result)
  ok('block_ip passerelle → refusé (gateway)', by('block_ip', '192.168.50.1').status === 'rejected' && res(by('block_ip', '192.168.50.1')).reason === 'gateway', by('block_ip', '192.168.50.1').result)
  ok('block_ip sous Linux → refusé proprement (unsupported_os)', by('block_ip', '192.168.50.99').status === 'rejected' && res(by('block_ip', '192.168.50.99')).reason === 'unsupported_os', by('block_ip', '192.168.50.99').result)
  ok('fix sous Linux → refusé (unsupported_os)', by('fix').status === 'rejected' && res(by('fix')).reason === 'unsupported_os', by('fix').result)
  ok('unblock_ip sous Linux → refusé (unsupported_os)', by('unblock_ip').status === 'rejected', by('unblock_ip').result)
  ok('toutes les demandes ont started_at / finished_at', mock.db.sensor_commands.every((c) => c.started_at && c.finished_at))
  ok('aucune adresse bloquée inventée', mock.db.blocked_ips.length === 0)
  for (let i = 0; i < 40 && mock.db.devices.length < 3; i++) await sleep(250)
  const net = mock.db.networks[0]
  ok('inventaire : réseau enregistré pour la passerelle confirmée', mock.db.networks.length === 1 && net.gateway_mac === GW_MAC && net.cidr === '192.168.50.0/24', JSON.stringify(mock.db.networks))
  const dev = (mac) => mock.db.devices.find((d) => d.mac === mac) || {}
  ok('inventaire : passerelle identifiée (Fortinet)', dev(GW_MAC).role === 'gateway' && dev(GW_MAC).vendor === 'Fortinet', JSON.stringify(dev(GW_MAC)))
  ok('inventaire : caméra identifiée par son fabricant', dev('44:19:b6:00:00:01').role === 'camera' && dev('44:19:b6:00:00:01').type === 'Caméra', JSON.stringify(dev('44:19:b6:00:00:01')))
  ok('inventaire : téléphone nommé par sa demande DHCP', dev('d8:b0:53:13:54:8d').name === 'Redmi-Note-12' && dev('d8:b0:53:13:54:8d').role === 'phone' && dev('d8:b0:53:13:54:8d').ip === '192.168.50.64', JSON.stringify(dev('d8:b0:53:13:54:8d')))
  ok('inventaire : appareils rattachés au réseau, preuve enregistrée', mock.db.devices.every((d) => d.network_id === net.id && String(d.role_evidence).startsWith('Capteur : ')))
  ok('aucune erreur fatale dans le journal', !/✖|TypeError|ReferenceError|Unhandled/.test(log))
} catch (e) {
  results.push(['FAIL', 'exception du test', String(e && e.message)])
} finally {
  proc.kill('SIGTERM'); await sleep(500); mock.close()
  if (!hadUi) rmSync(uiDir, { recursive: true, force: true })
  rmSync(SP, { recursive: true, force: true })
}
for (const [st, n, e] of results) console.log(`${st}  ${n}${st === 'FAIL' ? '  → ' + e : ''}`)
console.log('\n--- journal du capteur ---\n' + log.split('\n').slice(0, 25).join('\n'))
process.exitCode = results.some((r) => r[0] === 'FAIL') ? 1 : 0
