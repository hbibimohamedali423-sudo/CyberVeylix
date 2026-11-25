// Tests du capteur CyberVeylix (aucune dépendance, aucun réseau) : node sensor/test/run.mjs
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { stripPowerShell, checkPowerShellFile, checkCmdFile } from './ps-check.mjs'
import { stripTelnet, createLineReader, parseFtpCommand, parseLoginForm, sanitizeUsername } from '../lib/honeypot-proto.mjs'
import { createHoneypotMonitor } from '../lib/honeypot-monitor.mjs'
import { startHoneypots, isPortServed, DEFAULT_PORTS } from '../lib/honeypot-servers.mjs'
import net from 'node:net'
import { vulnUnitChecks } from './vuln-unit.mjs'
import { vulnIntegrationChecks } from './vuln-integration.mjs'
import { vulnReportChecks } from './vuln-report.mjs'
import { pushChecks } from './push-test.mjs'
import { webChecks } from './web-test.mjs'
import { commandsChecks } from './commands-test.mjs'
import { actionsChecks } from './actions-test.mjs'
import { fixesChecks } from './fixes-test.mjs'
import { inventoryChecks } from './inventory-test.mjs'
import { snmpChecks } from './snmp-test.mjs'
import { snmpLiveChecks } from './snmp-live-test.mjs'
import { topoSyncChecks } from './topo-sync-test.mjs'
import { notifyChecks } from './notify-test.mjs'
import { parseArp, ARP_REQUEST, ARP_REPLY } from '../lib/parse-arp.mjs'
import { parseDhcpServerReply, DHCP_OFFER } from '../lib/parse-dhcp.mjs'
import { createDetectors } from '../lib/detectors.mjs'
import { parseConfigText, resolveOptions, effectiveLearnMinutes } from '../lib/options.mjs'
import { arpFrame, dhcpServerFrame } from './frames.mjs'

let passed = 0
const failures = []
function check(name, fn) {
  try { fn(); passed += 1; console.log(`PASS  ${name}`) }
  catch (e) { failures.push(name); console.log(`FAIL  ${name}`); console.log(`      ${String(e.message).split('\n')[0]}`) }
}

// --- Analyse ARP -----------------------------------------------------------
check('ARP : réponse valide décodée', () => {
  const r = parseArp(arpFrame({ op: ARP_REPLY, senderMac: 'aa:bb:cc:00:11:22', senderIp: '192.168.1.5' }))
  assert.equal(r.op, ARP_REPLY)
  assert.equal(r.senderMac, 'aa:bb:cc:00:11:22')
  assert.equal(r.senderIp, '192.168.1.5')
})
check('ARP : requête valide décodée', () => {
  const r = parseArp(arpFrame({ op: ARP_REQUEST, senderMac: 'de:ad:be:ef:00:01', senderIp: '10.0.0.2' }))
  assert.equal(r.op, ARP_REQUEST)
})
check('ARP : trame tronquée → null (pas d\'accès hors limites)', () => {
  assert.equal(parseArp(arpFrame({ senderMac: 'aa:bb:cc:dd:ee:ff', senderIp: '1.2.3.4' }).subarray(0, 20)), null)
})
check('ARP : mauvais ethertype → null', () => {
  const f = arpFrame({ senderMac: 'aa:bb:cc:dd:ee:ff', senderIp: '1.2.3.4' })
  f[12] = 0x08; f[13] = 0x00
  assert.equal(parseArp(f), null)
})
check('ARP : entrée non-Buffer → null', () => {
  assert.equal(parseArp('xxxx'), null)
  assert.equal(parseArp(null), null)
})

// --- Analyse DHCP ----------------------------------------------------------
check('DHCP : OFFER serveur décodé', () => {
  const r = parseDhcpServerReply(dhcpServerFrame({ type: DHCP_OFFER, serverMac: '11:22:33:44:55:66', serverIp: '192.168.1.1' }))
  assert.equal(r.messageType, DHCP_OFFER)
  assert.equal(r.serverId, '192.168.1.1')
  assert.equal(r.serverMac, '11:22:33:44:55:66')
})
check('DHCP : repli sur IP source si option 54 absente', () => {
  const r = parseDhcpServerReply(dhcpServerFrame({ serverMac: '11:22:33:44:55:66', serverIp: '192.168.1.9', serverIdOption: false }))
  assert.equal(r.serverId, '192.168.1.9')
})
check('DHCP : cookie magique invalide → null', () => {
  const g =dhcpServerFrame({ serverMac: '11:22:33:44:55:66', serverIp: '192.168.1.1' })
  g.writeUInt32BE(0, 14 + 20 + 8 + 236)
  assert.equal(parseDhcpServerReply(g), null)
})

// --- Détection : nouvel appareil ------------------------------------------
check('Détecteur : nouvel appareil signalé une seule fois', () => {
  const d = createDetectors()
  const f = arpFrame({ senderMac: 'aa:aa:aa:aa:aa:aa', senderIp: '192.168.1.20' })
  const first = d.onArp(parseArp(f), 1000)
  assert.equal(first.length, 1)
  assert.equal(first[0].type, 'new_device')
  const again = d.onArp(parseArp(f), 2000)
  assert.equal(again.length, 0) // anti-répétition
})

// --- Détection : usurpation de la passerelle -------------------------------
check('Détecteur : usurpation passerelle = critique', () => {
  const d = createDetectors({ gatewayIp: '192.168.1.1', gatewayMac: '00:11:22:33:44:55' })
  d.onArp(parseArp(arpFrame({ senderMac: '00:11:22:33:44:55', senderIp: '192.168.1.1' })), 1000)
  const ev = d.onArp(parseArp(arpFrame({ op: ARP_REPLY, senderMac: 'ba:d0:00:00:00:01', senderIp: '192.168.1.1' })), 2000)
  assert.equal(ev.some((e) => e.type === 'gateway_spoof' && e.severity === 'c'), true)
})

check('Détecteur : la MAC de l\'usurpateur n\'est jamais apprise pour la passerelle', () => {
  const d = createDetectors({ gatewayIp: '192.168.1.1', gatewayMac: '00:11:22:33:44:55' })
  d.onArp(parseArp(arpFrame({ senderMac: '00:11:22:33:44:55', senderIp: '192.168.1.1' })), 1000)
  d.onArp(parseArp(arpFrame({ senderMac: 'ba:d0:00:00:00:01', senderIp: '192.168.1.1' })), 2000)
  const gw = d.snapshot().bindings.find((b) => b.ip === '192.168.1.1')
  assert.equal(gw.mac, '00:11:22:33:44:55') // la référence reste la vraie passerelle
  // La vraie passerelle qui se réannonce ne déclenche aucune fausse alerte.
  const legit = d.onArp(parseArp(arpFrame({ senderMac: '00:11:22:33:44:55', senderIp: '192.168.1.1' })), 3000)
  assert.equal(legit.length, 0)
  // L'attaquant reste inconnu : s'il apparaît sous sa propre IP, il est signalé comme nouveau.
  const own = d.onArp(parseArp(arpFrame({ senderMac: 'ba:d0:00:00:00:01', senderIp: '192.168.1.66' })), 4000)
  assert.equal(own.some((e) => e.type === 'new_device'), true)
})

// --- Détection : changement de MAC sur IP connue ---------------------------
check('Détecteur : IP connue qui change de MAC = haute', () => {
  const d = createDetectors()
  d.onArp(parseArp(arpFrame({ senderMac: 'aa:00:00:00:00:01', senderIp: '192.168.1.30' })), 1000)
  // 'bc' : octet pair → MAC unicast (une MAC à octet impair comme 'bb' serait multicast).
  const ev = d.onArp(parseArp(arpFrame({ senderMac: 'bc:00:00:00:00:02', senderIp: '192.168.1.30' })), 2000)
  assert.equal(ev.some((e) => e.type === 'mac_changed' && e.severity === 'h'), true)
})

check('Détecteur : MAC multicast ignorée (pas un vrai appareil)', () => {
  const d = createDetectors()
  const ev = d.onArp(parseArp(arpFrame({ senderMac: '01:00:5e:00:00:01', senderIp: '192.168.1.31' })), 1000)
  assert.equal(ev.length, 0)
  assert.equal(d.snapshot().deviceCount, 0)
})

// --- Détection : balayage d'IP par une même MAC ----------------------------
check('Détecteur : une MAC revendiquant ≥ 5 IP = usurpation ARP', () => {
  const d = createDetectors({ spoofIpThreshold: 5 })
  let ev = []
  for (let i = 1; i <= 5; i++) {
    ev = d.onArp(parseArp(arpFrame({ op: ARP_REPLY, senderMac: 'ca:fe:00:00:00:01', senderIp: `192.168.1.${100 + i}` })), 1000 + i)
  }
  assert.equal(ev.some((e) => e.type === 'arp_spoof_sweep'), true)
})

// --- Détection : serveur DHCP pirate ---------------------------------------
check('Détecteur : DHCP de référence appris puis pirate détecté', () => {
  const learn = createDetectors({ alert: false })
  learn.onDhcp(parseDhcpServerReply(dhcpServerFrame({ serverMac: '00:11:22:33:44:55', serverIp: '192.168.1.1' })), 1000)
  const trusted = learn.snapshot().trustedDhcpServers
  assert.deepEqual(trusted, ['192.168.1.1'])

  const live = createDetectors({ trustedDhcpServers: trusted })
  const ok = live.onDhcp(parseDhcpServerReply(dhcpServerFrame({ serverMac: '00:11:22:33:44:55', serverIp: '192.168.1.1' })), 2000)
  assert.equal(ok.length, 0) // serveur légitime
  const rogue = live.onDhcp(parseDhcpServerReply(dhcpServerFrame({ serverMac: 'ba:d0:00:00:00:02', serverIp: '192.168.1.66' })), 3000)
  assert.equal(rogue.some((e) => e.type === 'rogue_dhcp' && e.severity === 'c'), true)
})

// --- Mode apprentissage : aucun événement ----------------------------------
check('Détecteur : mode apprentissage n\'émet aucun événement', () => {
  const d = createDetectors({ alert: false })
  const ev = d.onArp(parseArp(arpFrame({ senderMac: 'aa:bb:cc:dd:ee:00', senderIp: '192.168.1.40' })), 1000)
  assert.equal(ev.length, 0)
  assert.equal(d.snapshot().deviceCount, 1) // mais l'état est bien appris
})

// --- Référence sauvegardée et passage en mode alerte -----------------------
check('Détecteur : référence restaurée → appareil connu non signalé, changement détecté', () => {
  const d = createDetectors({ bindings: [{ ip: '192.168.1.60', mac: 'AA:00:00:00:00:60' }] })
  const same = d.onArp(parseArp(arpFrame({ senderMac: 'aa:00:00:00:00:60', senderIp: '192.168.1.60' })), 1000)
  assert.equal(same.length, 0)
  const changed = d.onArp(parseArp(arpFrame({ senderMac: 'ac:00:00:00:00:61', senderIp: '192.168.1.60' })), 2000)
  assert.equal(changed.some((e) => e.type === 'mac_changed'), true)
})

check('Détecteur : apprentissage puis setAlerting(true) garde l\'état appris', () => {
  const d = createDetectors({ alert: false })
  d.onArp(parseArp(arpFrame({ senderMac: 'aa:00:00:00:00:70', senderIp: '192.168.1.70' })), 1000)
  d.setAlerting(true)
  const known = d.onArp(parseArp(arpFrame({ senderMac: 'aa:00:00:00:00:70', senderIp: '192.168.1.70' })), 2000)
  assert.equal(known.length, 0) // appris pendant la référence → pas « nouveau »
  const fresh = d.onArp(parseArp(arpFrame({ senderMac: 'aa:00:00:00:00:71', senderIp: '192.168.1.71' })), 3000)
  assert.equal(fresh.some((e) => e.type === 'new_device'), true)
})

// --- Faux positifs et inondation ---------------------------------------------
check('Détecteur : bail DHCP qui change sur des jours ≠ usurpation', () => {
  const d = createDetectors({ spoofIpThreshold: 5 })
  const DAY = 24 * 60 * 60 * 1000
  let all = []
  for (let i = 0; i < 8; i++) {
    all = all.concat(d.onArp(parseArp(arpFrame({ op: ARP_REPLY, senderMac: 'a4:00:00:00:00:01', senderIp: `192.168.1.${10 + i}` })), i * DAY))
  }
  assert.equal(all.some((e) => e.type === 'arp_spoof_sweep'), false)
})

check('Détecteur : inondation de MAC aléatoires → une seule alerte groupée', () => {
  const d = createDetectors({ floodPerMinute: 20 })
  let all = []
  for (let i = 0; i < 500; i++) {
    const mac = `02:00:00:00:${String((i >> 8) & 255).padStart(2, '0').slice(-2)}:${(i & 255).toString(16).padStart(2, '0')}`
    all = all.concat(d.onArp(parseArp(arpFrame({ senderMac: mac, senderIp: `10.0.${(i >> 8) & 255}.${(i & 255) || 1}` })), 1000 + i))
  }
  assert.equal(all.filter((e) => e.type === 'mac_flood').length, 1)
  assert.equal(all.filter((e) => e.type === 'new_device').length, 20) // au plus le seuil, puis regroupement
})

check('Détecteur : plafond mémoire des appareils respecté', () => {
  const d = createDetectors({ maxDevices: 50, floodPerMinute: 1e9 })
  for (let i = 0; i < 300; i++) {
    const mac = `02:00:00:00:${((i >> 8) & 255).toString(16).padStart(2, '0')}:${(i & 255).toString(16).padStart(2, '0')}`
    d.onArp(parseArp(arpFrame({ senderMac: mac, senderIp: `10.1.${(i >> 8) & 255}.${(i & 255) || 1}` })), i)
  }
  assert.equal(d.snapshot().deviceCount, 50)
})

// --- Options et fichier de configuration (install.ps1) ---------------------
check('Options : config.json avec BOM (Windows PowerShell 5.1) accepté', () => {
  const r = parseConfigText('﻿{"interface":"192.168.1.10","authorized":true}')
  assert.equal(r.error, undefined)
  assert.equal(r.config.interface, '192.168.1.10')
})
check('Options : JSON invalide ou non-objet → erreur lisible, sans exception', () => {
  assert.match(parseConfigText('{pas du json').error, /illisible/)
  assert.match(parseConfigText('[1,2]').error, /objet JSON/)
})
check('Options : autorisation via config, MAC normalisée (tirets Windows)', () => {
  const { options } = resolveOptions([], { authorized: true, gatewayMac: '00-11-22-AA-BB-CC', gateway: '192.168.1.1' })
  assert.equal(options.authorized, true)
  assert.equal(options.gatewayMac, '00:11:22:aa:bb:cc')
})
check('Options : la ligne de commande prime sur le fichier', () => {
  const { options } = resolveOptions(['--interface=10.0.0.5', '--learn-minutes=0'], { interface: '192.168.1.10', learnMinutes: 10 })
  assert.equal(options.interface, '10.0.0.5')
  assert.equal(options.learnMinutes, 0)
})
check('Options : sans --yes ni autorisation enregistrée → non autorisé', () => {
  assert.equal(resolveOptions([], {}).options.authorized, false)
  assert.equal(resolveOptions([], { authorized: 'true' }).options.authorized, false) // chaîne ≠ booléen
})
check('Options : apprentissage initial seulement au premier lancement (pas après redémarrage)', () => {
  const { options } = resolveOptions([], { initialLearnMinutes: 10 })
  assert.equal(effectiveLearnMinutes(options, false), 10) // premier lancement
  assert.equal(effectiveLearnMinutes(options, true), 0) // référence existante : surveillance immédiate
  const forced = resolveOptions(['--learn-minutes=5'], { initialLearnMinutes: 10 }).options
  assert.equal(effectiveLearnMinutes(forced, true), 5) // valeur imposée à la main
  assert.equal(effectiveLearnMinutes(resolveOptions([], {}).options, false), 10) // défaut
})

check('Options : leurres (désactivés par défaut, config, --no-honeypot, ports, sources autorisées)', () => {
  assert.equal(resolveOptions([], {}).options.honeypot, false)
  const cfg = { honeypot: true, honeypotPorts: [23, 23, 8080], honeypotAllow: ['192.168.1.50'] }
  const o = resolveOptions([], cfg).options
  assert.equal(o.honeypot, true)
  assert.deepEqual(o.honeypotPorts, [23, 8080]) // doublons retirés
  assert.deepEqual(o.honeypotAllow, ['192.168.1.50'])
  assert.equal(resolveOptions(['--no-honeypot'], cfg).options.honeypot, false)
  assert.deepEqual(resolveOptions(['--honeypot', '--honeypot-ports=21, 2323'], {}).options.honeypotPorts, [21, 2323])
  // Tableau d'un seul élément « déballé » par ConvertTo-Json (PowerShell 5.1).
  assert.deepEqual(resolveOptions([], { honeypotAllow: '192.168.1.60', honeypotPorts: 23 }).options.honeypotAllow, ['192.168.1.60'])
  assert.deepEqual(resolveOptions([], { honeypotPorts: 23 }).options.honeypotPorts, [23])
  assert.match(resolveOptions(['--honeypot-ports=0,23'], {}).error, /honeypot-ports/)
  assert.match(resolveOptions(['--honeypot-allow=pas-une-ip'], {}).error, /honeypot-allow/)
})

check('Options : valeurs invalides refusées', () => {
  assert.match(resolveOptions(['--gateway-mac=zz'], {}).error, /gateway-mac/)
  assert.match(resolveOptions(['--gateway=999.1.1.1'], {}).error, /Passerelle/)
  assert.match(resolveOptions(['--learn-minutes=-3'], {}).error, /learn-minutes/)
})

// --- Robustesse : trames aléatoires et corrompues --------------------------
check('Robustesse : 20 000 trames aléatoires/corrompues sans exception', () => {
  let seed = 12345
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed }
  const d = createDetectors()
  const base = [
    arpFrame({ senderMac: 'aa:bb:cc:dd:ee:01', senderIp: '192.168.1.2' }),
    dhcpServerFrame({ serverMac: '00:11:22:33:44:55', serverIp: '192.168.1.1' }),
  ]
  for (let n = 0; n < 20000; n++) {
    let f
    if (n % 3 === 0) {
      f = Buffer.alloc(rnd() % 400)
      for (let i = 0; i < f.length; i++) f[i] = rnd() & 255
    } else {
      f = Buffer.from(base[n % 2])
      for (let k = 0; k < 4; k++) f[rnd() % f.length] = rnd() & 255 // octets corrompus
      if (n % 5 === 0) f = f.subarray(0, rnd() % f.length) // trame tronquée
    }
    d.onArp(parseArp(f), n)
    d.onDhcp(parseDhcpServerReply(f), n)
  }
})

// --- Leurres : analyse des échanges --------------------------------------------
check('Leurre : négociation Telnet (IAC) retirée, texte conservé', () => {
  const raw = Buffer.from([0xff, 0xfb, 0x01, 0xff, 0xfd, 0x03, 0x61, 0x64, 0xff, 0xff, 0x6d,
    0xff, 0xfa, 0x18, 0x00, 0x41, 0xff, 0xf0, 0x69, 0x6e])
  assert.equal(stripTelnet(raw).toString('latin1'), 'ad\xffmin')
  assert.equal(stripTelnet(Buffer.from([0x61, 0xff])).toString(), 'a') // IAC tronqué en fin de bloc
})
check('Leurre : lecteur de lignes (CRLF, CR NUL, découpage, bornes)', () => {
  const r = createLineReader(3)
  assert.deepEqual(r.push('adm'), [])
  assert.deepEqual(r.push('in\r\nsecret\r\0'), ['admin', 'secret'])
  const big = createLineReader(2)
  big.push('x'.repeat(10000))
  assert.equal(big.push('\n')[0].length, 256) // ligne bornée, pas d'accumulation sans fin
})
check('Leurre : commandes FTP', () => {
  assert.deepEqual(parseFtpCommand('user admin'), { cmd: 'USER', arg: 'admin' })
  assert.deepEqual(parseFtpCommand('PASS'), { cmd: 'PASS', arg: '' })
  assert.deepEqual(parseFtpCommand('###'), { cmd: '', arg: '' })
})
check('Leurre : formulaire web → identifiant gardé, mot de passe JAMAIS conservé', () => {
  const secret = 'MonVraiMotDePasse!2026'
  const r = parseLoginForm(`username=admin&password=${encodeURIComponent(secret)}`, 'application/x-www-form-urlencoded')
  assert.deepEqual(r, { username: 'admin', hasPassword: true })
  assert.equal(JSON.stringify(r).includes(secret), false)
  const j = parseLoginForm(JSON.stringify({ User: 'root', PWD: secret }), 'application/json')
  assert.deepEqual(j, { username: 'root', hasPassword: true })
  assert.deepEqual(parseLoginForm('{cassé', 'application/json'), { username: '', hasPassword: false })
})
check('Leurre : identifiant nettoyé (contrôles retirés, 64 caractères max)', () => {
  assert.equal(sanitizeUsername('ad\x1b[31mmin\n'), 'ad[31mmin')
  assert.equal(sanitizeUsername('a'.repeat(500)).length, 64)
})

// --- Leurres : interprétation ---------------------------------------------------
const hp = (over = {}) => ({ srcIp: '192.168.1.23', port: 23, service: 'telnet', kind: 'touch', ...over })
check('Leurre : premier contact = alerte haute, puis anti-répétition', () => {
  const m = createHoneypotMonitor()
  const e = m.onActivity(hp(), 1000)
  assert.equal(e.length, 1)
  assert.equal(e[0].type, 'honeypot_touch')
  assert.equal(e[0].severity, 'h')
  assert.equal(m.onActivity(hp(), 2000).length, 0)
})
check('Leurre : 3 services sondés en une minute = balayage critique (une seule alerte)', () => {
  const m = createHoneypotMonitor()
  const all = [21, 23, 3389, 5900, 8080].flatMap((port, i) => m.onActivity(hp({ port }), 1000 + i))
  const scans = all.filter((e) => e.type === 'honeypot_scan')
  assert.equal(scans.length, 1)
  assert.equal(scans[0].severity, 'c')
  assert.equal(all.filter((e) => e.type === 'honeypot_touch').length, 2) // les 2 premiers, puis regroupement
})
check('Leurre : contacts espacés de plus d\'une minute ≠ balayage', () => {
  const m = createHoneypotMonitor()
  const all = [21, 23, 3389].flatMap((port, i) => m.onActivity(hp({ port }), i * 120000))
  assert.equal(all.some((e) => e.type === 'honeypot_scan'), false)
})
check('Leurre : tentative d\'identification = critique, identifiant cité, MAC ajoutée', () => {
  const m = createHoneypotMonitor({ macOf: (ip) => (ip === '192.168.1.23' ? 'aa:bb:cc:00:00:23' : null) })
  const [e] = m.onActivity(hp({ kind: 'login', username: 'admin', hasPassword: true }), 1000)
  assert.equal(e.type, 'honeypot_login')
  assert.equal(e.severity, 'c')
  assert.match(e.detail, /« admin »/)
  assert.match(e.detail, /aa:bb:cc:00:00:23/)
  assert.match(e.detail, /non conservé/)
})
check('Leurre : capteur lui-même et scanners autorisés ignorés ; IPv6 mappée normalisée', () => {
  const m = createHoneypotMonitor({ ignoreIps: ['192.168.1.10'], allowIps: ['192.168.1.50'] })
  assert.equal(m.onActivity(hp({ srcIp: '192.168.1.10' }), 1).length, 0)
  assert.equal(m.onActivity(hp({ srcIp: '::ffff:192.168.1.50' }), 2).length, 0)
  assert.equal(m.onActivity(hp({ srcIp: '::ffff:192.168.1.99' }), 3)[0].ip, '192.168.1.99')
})
check('Leurre : mémoire bornée face à des milliers de sources', () => {
  const m = createHoneypotMonitor({ maxSources: 100 })
  for (let i = 0; i < 5000; i++) m.onActivity(hp({ srcIp: `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}` }), i)
  // Pas d'exception ni de croissance sans fin : une nouvelle source est encore signalée.
  assert.equal(m.onActivity(hp({ srcIp: '10.200.0.1' }), 6000).length, 1)
})

// --- Vulnérabilités : moteur pur ------------------------------------------------
vulnUnitChecks(check)

// --- Leurres : vrais sockets (127.0.0.1, ports éphémères) ---------------------
const asyncChecks = []
const checkAsync = (name, fn) => asyncChecks.push([name, fn])

// Client minimal : envoie des étapes [attendre /regex/, puis écrire 'texte'] et rend tout le texte reçu.
function converse(port, steps, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: '127.0.0.1', port })
    let got = ''
    let i = 0
    const timer = setTimeout(() => { s.destroy(); reject(new Error(`délai dépassé, reçu : ${JSON.stringify(got)}`)) }, timeoutMs)
    const next = () => {
      while (i < steps.length && steps[i][0].test(got)) { s.write(steps[i][1]); i++ }
    }
    s.on('data', (d) => { got += d.toString('latin1'); next() })
    s.on('close', () => { clearTimeout(timer); resolve(got) })
    s.on('error', () => {})
  })
}

checkAsync('Leurres réels : Telnet, FTP, web, SSH — identifiants remontés, mots de passe jamais', async () => {
  const activity = []
  const hp = await startHoneypots({
    host: '127.0.0.1',
    services: [{ port: 0, service: 'telnet' }, { port: 0, service: 'ftp' }, { port: 0, service: 'http' }, { port: 0, service: 'ssh' }],
    onActivity: (a) => activity.push(a),
  })
  try {
    const port = (svc) => hp.listening.find((l) => l.service === svc).port
    const telnet = await converse(port('telnet'), [[/login: $/, 'admin\r\n'], [/Password: $/, 'S3cret-telnet\r\n']])
    assert.match(telnet, /Login incorrect/)
    const ftp = await converse(port('ftp'), [[/^220 /, 'USER root\r\n'], [/331 /, 'PASS S3cret-ftp\r\n']])
    assert.match(ftp, /530 Login incorrect/)
    const page = await fetch(`http://127.0.0.1:${port('http')}/`)
    assert.equal(page.status, 200)
    assert.match(await page.text(), /name="password"/)
    const post = await fetch(`http://127.0.0.1:${port('http')}/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'username=webadmin&password=S3cret-web',
    })
    assert.equal(post.status, 401)
    await post.text()
    const ssh = await new Promise((resolve) => {
      const s = net.connect({ host: '127.0.0.1', port: port('ssh') }, () => {})
      s.once('data', (d) => { resolve(d.toString()); s.destroy() })
    })
    assert.match(ssh, /^SSH-2\.0-/)

    await new Promise((r) => setTimeout(r, 100))
    const logins = activity.filter((a) => a.kind === 'login')
    assert.deepEqual(logins.map((a) => [a.service, a.username, a.hasPassword]).sort(), [
      ['ftp', 'root', true], ['http', 'webadmin', true], ['telnet', 'admin', true],
    ])
    assert.equal(activity.filter((a) => a.kind === 'touch').length >= 4, true)
    assert.equal(JSON.stringify(activity).includes('S3cret'), false) // aucun mot de passe nulle part
  } finally {
    await hp.close()
  }
})

checkAsync('Leurres réels : flot de 200 Ko borné, port occupé signalé sans planter', async () => {
  const hp = await startHoneypots({ host: '127.0.0.1', services: [{ port: 0, service: 'generic' }], onActivity: () => {} })
  try {
    const port = hp.listening[0].port
    const closed = await new Promise((resolve) => {
      const s = net.connect({ host: '127.0.0.1', port }, () => s.write(Buffer.alloc(200 * 1024, 0x41)))
      s.on('error', () => {})
      s.on('close', () => resolve(true))
      setTimeout(() => resolve(false), 3000)
    })
    assert.equal(closed, true) // le leurre ferme au-delà de 4 Ko au lieu de tout lire
    // Port déjà pris (ici par le premier leurre) : refusé proprement, sans planter.
    const again = await startHoneypots({ host: '127.0.0.1', services: [{ port, service: 'telnet' }], onActivity: () => {} })
    assert.deepEqual(again.listening, [])
    assert.equal(['SERVICE_PRESENT', 'EADDRINUSE'].includes(again.failed[0].code), true)
  } finally {
    await hp.close()
  }
})

checkAsync('Leurres réels : un vrai service du PC (toutes adresses) n\'est jamais détourné', async () => {
  // Simule le Bureau à distance du client qui écoute sur 0.0.0.0.
  const real = net.createServer((s) => { s.on('error', () => {}); s.end('VRAI SERVICE') })
  await new Promise((r) => real.listen({ host: '0.0.0.0', port: 0 }, r))
  const port = real.address().port
  try {
    assert.equal(await isPortServed('127.0.0.1', port), true)
    const hp = await startHoneypots({ host: '127.0.0.1', services: [{ port, service: 'rdp' }], onActivity: () => {} })
    assert.deepEqual(hp.listening, [])
    assert.equal(hp.failed[0].code, 'SERVICE_PRESENT')
    await hp.close()
    // Le vrai service répond toujours normalement.
    const got = await converse(port, [])
    assert.equal(got, 'VRAI SERVICE')
  } finally {
    await new Promise((r) => real.close(r))
  }
  assert.equal(await isPortServed('127.0.0.1', port), false)
})

checkAsync('Leurres réels + interprétation : balayage et tentative de connexion = alertes critiques', async () => {
  const events = []
  const monitor = createHoneypotMonitor()
  const hp = await startHoneypots({
    host: '127.0.0.1',
    services: [{ port: 0, service: 'telnet' }, { port: 0, service: 'vnc' }, { port: 0, service: 'mysql' }],
    onActivity: (a) => events.push(...monitor.onActivity(a, Date.now())),
  })
  try {
    for (const l of hp.listening) {
      await new Promise((resolve) => {
        const s = net.connect({ host: '127.0.0.1', port: l.port }, () => s.destroy())
        s.on('close', resolve)
        s.on('error', resolve)
      })
    }
    await converse(hp.listening[0].port, [[/login: $/, 'root\r\n'], [/Password: $/, 'x\r\n']])
    await new Promise((r) => setTimeout(r, 100))
    assert.deepEqual(events.filter((e) => e.severity === 'c').map((e) => e.type).sort(), ['honeypot_login', 'honeypot_scan'])
  } finally {
    await hp.close()
  }
})

// --- Vulnérabilités : sondes réelles contre des services factices -------------
vulnIntegrationChecks(checkAsync, check)
vulnReportChecks(check, checkAsync)
pushChecks(check, checkAsync)
webChecks(check, checkAsync)
commandsChecks(check, checkAsync)
actionsChecks(check, checkAsync)
fixesChecks(check, checkAsync)
inventoryChecks(check, checkAsync)
snmpChecks(check, checkAsync)
snmpLiveChecks(check, checkAsync)
topoSyncChecks(check, checkAsync)
notifyChecks(check, checkAsync)

// --- Scripts Windows (installateur / désinstallateur) ------------------------
const sensorFile = (name) => fileURLToPath(new URL(`../${name}`, import.meta.url))

check('Contrôle PS : le vérificateur détecte bien les erreurs visées', () => {
  // Garde-fou du garde-fou : chaque règle doit réellement attraper son cas.
  assert.match(stripPowerShell("$a = 'x ?? y' # $b ?? c"), /^\$a = ''\s*$/)
  assert.equal(stripPowerShell('"a ""b"" `" c" + $x').trim(), "'' + $x")
})

for (const name of ['install.ps1', 'uninstall.ps1']) {
  check(`${name} : compatible Windows PowerShell 5.1 (BOM, syntaxe, guillemets, parenthèses)`, () => {
    assert.deepEqual(checkPowerShellFile(sensorFile(name)), [])
  })
}

for (const name of ['install.cmd', 'uninstall.cmd', 'vulnscan.cmd', 'run-sensor.bat']) {
  check(`${name} : ASCII et fins de ligne CRLF`, () => {
    assert.deepEqual(checkCmdFile(sensorFile(name)), [])
  })
}

check('install.ps1 : tous les fichiers obligatoires qu\'il copie existent', () => {
  const src = readFileSync(sensorFile('install.ps1'), 'utf8')
  const list = /\$items = @\(([\s\S]*?)\)/.exec(src)[1].match(/'([^']+)'/g).map((s) => s.slice(1, -1))
  const optional = new Set(['node_modules', 'node.exe', 'node-LICENSE.txt', 'ui']) // fournis par le paquet construit
  const missing = list.filter((f) => !optional.has(f) && !existsSync(sensorFile(f)))
  assert.deepEqual(missing, [])
})

for (const [name, fn] of asyncChecks) {
  try { await fn(); passed += 1; console.log(`PASS  ${name}`) }
  catch (e) { failures.push(name); console.log(`FAIL  ${name}`); console.log(`      ${String(e.message).split('\n')[0]}`) }
}

check('install.ps1 : ports des leurres identiques à ceux du capteur (règle de pare-feu cohérente)', () => {
  const src = readFileSync(sensorFile('install.ps1'), 'utf8')
  const ports = /\$DefaultHoneypotPorts = @\(([^)]*)\)/.exec(src)[1].split(',').map((s) => Number(s.trim()))
  assert.deepEqual(ports, DEFAULT_PORTS)
})

console.log(`\n${passed} vérification(s) réussie(s)${failures.length ? `, ${failures.length} échec(s)` : ''}.`)
if (failures.length) process.exit(1)
