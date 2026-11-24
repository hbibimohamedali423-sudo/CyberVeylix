// Tests d'intégration des sondes : vrais sockets contre des services factices sur 127.0.0.1.
// Un jeu « vulnérable » doit tout déclencher, un jeu « durci » ne doit rien déclencher.
import assert from 'node:assert/strict'
import net from 'node:net'
import http from 'node:http'
import tls from 'node:tls'
import { readFileSync } from 'node:fs'
import { scanHost, expandTargets, isPrivateIpv4 } from '../lib/vuln/scan.mjs'

const fixture = (name) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url))

function listen(server) {
  return new Promise((resolve) => server.listen({ host: '127.0.0.1', port: 0 }, () => resolve(server.address().port)))
}
// Serveur TCP : onConnect(socket) écrit la bannière, onData(socket, chunk) répond.
function tcpService({ onConnect, onData }) {
  return net.createServer((s) => {
    s.on('error', () => {})
    if (onConnect) onConnect(s)
    if (onData) s.on('data', (d) => onData(s, d))
  })
}
function httpService(handler) {
  const srv = http.createServer(handler)
  srv.on('clientError', (_e, s) => s.destroy())
  return srv
}

const smb1Accept = () => {
  const b = Buffer.alloc(39)
  b.writeUInt32BE(35, 0)
  Buffer.from([0xff, 0x53, 0x4d, 0x42]).copy(b, 4)
  b[8] = 0x72
  b[36] = 17
  return b
}
const rdpReply = (type, value) => {
  const b = Buffer.from([0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0, type, 0, 8, 0, 0, 0, 0, 0])
  b.writeUInt32LE(value, 15)
  return b
}
const mysqlGreeting = (version) => {
  const payload = Buffer.concat([Buffer.from([10]), Buffer.from(version + '\0', 'latin1'), Buffer.alloc(20)])
  const hdr = Buffer.alloc(4)
  hdr.writeUIntLE(payload.length, 0, 3)
  return Buffer.concat([hdr, payload])
}

function vulnerableServices() {
  return {
    ssh: tcpService({ onConnect: (s) => s.write('SSH-2.0-OpenSSH_9.6p1\r\n') }),
    ftp: tcpService({
      onConnect: (s) => s.write('220 (vsFTPd 2.3.4)\r\n'),
      onData: (s, d) => { if (/FEAT/i.test(d)) s.write('211-Features:\r\n PASV\r\n211 End\r\n') },
    }),
    telnet: tcpService({ onConnect: (s) => s.write('login: ') }),
    http: httpService((_q, r) => { r.writeHead(200, { Server: 'Apache/2.4.49 (Unix)' }); r.end('<form><input type="password"></form>') }),
    smb: tcpService({ onData: (s) => s.end(smb1Accept()) }),
    rdp: tcpService({ onData: (s) => s.end(rdpReply(0x02, 1)) }),
    vnc: tcpService({ onConnect: (s) => s.write('RFB 003.008\n'), onData: (s) => s.write(Buffer.from([1, 1])) }),
    redis: tcpService({ onData: (s) => s.write('+PONG\r\n') }),
    docker: httpService((q, r) => { r.writeHead(200, { 'Content-Type': 'application/json' }); r.end(q.url === '/version' ? '{"Version":"24.0.7","ApiVersion":"1.43"}' : '{}') }),
    elasticsearch: httpService((_q, r) => r.end('{"cluster_name":"prod","tagline":"You Know, for Search"}')),
    mysql: tcpService({ onConnect: (s) => s.write(mysqlGreeting('5.7.44')) }),
    // TLS 1.0 accepté + certificat auto-signé.
    tls: tls.createServer({ key: fixture('test-only-key.pem'), cert: fixture('test-only-cert.pem'), minVersion: 'TLSv1', ciphers: 'DEFAULT@SECLEVEL=0' }, (s) => { s.on('error', () => {}); s.end() }),
  }
}

export function hardenedServices() {
  return {
    ssh: tcpService({ onConnect: (s) => s.write('SSH-2.0-OpenSSH_9.9p1\r\n') }),
    ftp: tcpService({
      onConnect: (s) => s.write('220 (vsFTPd 3.0.5)\r\n'),
      onData: (s, d) => { if (/FEAT/i.test(d)) s.write('211-Features:\r\n AUTH TLS\r\n211 End\r\n') },
    }),
    http: httpService((_q, r) => { r.writeHead(200, { Server: 'nginx/1.26.2' }); r.end('<p>ok</p>') }),
    smb: tcpService({ onData: (s) => s.end() }), // SMBv1 refusé : connexion coupée
    rdp: tcpService({ onData: (s) => s.end(rdpReply(0x03, 5)) }), // NLA exigée
    vnc: tcpService({ onConnect: (s) => s.write('RFB 003.008\n'), onData: (s) => s.write(Buffer.from([1, 2])) }),
    redis: tcpService({ onData: (s) => s.write('-NOAUTH Authentication required.\r\n') }),
    mysql: tcpService({ onConnect: (s) => s.write(Buffer.from([9, 0, 0, 0, 0xff, 0x6a, 0x04, 0x48, 0x6f, 0x73, 0x74, 0x20, 0x21])) }),
    tls: tls.createServer({ key: fixture('test-only-key.pem'), cert: fixture('test-only-cert.pem') }, (s) => { s.on('error', () => {}); s.end() }),
  }
}

export async function scanFakes(services) {
  const ports = []
  for (const [service, server] of Object.entries(services)) ports.push({ port: await listen(server), service })
  try {
    return await scanHost('127.0.0.1', { ports })
  } finally {
    await Promise.all(Object.values(services).map((s) => new Promise((r) => s.close(() => r()))))
  }
}

export function vulnIntegrationChecks(checkAsync, check) {
  check('Cibles : réseaux privés seulement, /22 au plus, CIDR développé', () => {
    assert.equal(expandTargets('192.168.1.0/24').targets.length, 254)
    assert.deepEqual(expandTargets('10.0.0.5, 10.0.0.5,172.16.3.4').targets, ['10.0.0.5', '172.16.3.4'])
    assert.match(expandTargets('8.8.8.8').error, /privée/)
    assert.match(expandTargets('172.32.0.1').error, /privée/)
    assert.match(expandTargets('10.0.0.0/16').error, /Préfixe/)
    assert.match(expandTargets('127.0.0.1').error, /privée/)
    assert.deepEqual(expandTargets('127.0.0.1', { allowLoopback: true }).targets, ['127.0.0.1'])
    assert.match(expandTargets('pas-une-ip').error, /invalide/)
    assert.equal(isPrivateIpv4('192.168.300.1'), false)
  })

  checkAsync('Sondes réelles : services vulnérables → chaque faiblesse détectée', async () => {
    const host = await scanFakes(vulnerableServices())
    assert.equal(host.alive, true)
    const found = host.findings.map((f) => f.rule).sort()
    assert.deepEqual(found, [
      'db-exposed', 'docker-api-open', 'elasticsearch-open', 'ftp-cleartext', 'ftp-vsftpd-backdoor',
      'http-apache-traversal', 'http-login-cleartext', 'rdp-no-nla', 'redis-noauth', 'smb1-enabled',
      'ssh-regresshion', 'telnet-open', 'tls-legacy', 'tls-selfsigned', 'vnc-noauth',
    ])
    const mysql = host.observations.find((o) => o.service === 'mysql')
    assert.equal(mysql.mysql.version, '5.7.44')
  })

  checkAsync('Sondes réelles : services durcis → aucune fausse alerte', async () => {
    const host = await scanFakes(hardenedServices())
    // Seul résultat attendu : le certificat de test est réellement auto-signé (gravité basse, exact).
    assert.deepEqual(host.findings.map((f) => f.rule), ['tls-selfsigned'])
    const obs = Object.fromEntries(host.observations.map((o) => [o.service, o]))
    assert.equal(obs.smb.smb1, false)
    assert.equal(obs.rdp.rdp, 'nla-required')
    assert.deepEqual(obs.vnc.vnc.types, [2])
    assert.equal(obs.redis.redis, 'auth')
    assert.equal(obs.ftp.ftp.tls, true)
    assert.equal(obs.tls.tls.legacy, false)
  })

  checkAsync('Sondes réelles : hôte sans service → joignable mais rien d\'ouvert ; port muet → pas de blocage', async () => {
    const mute = net.createServer((s) => s.on('error', () => {})) // accepte puis ne dit rien
    const port = await listen(mute)
    try {
      const t0 = Date.now()
      const host = await scanHost('127.0.0.1', { ports: [{ port, service: 'ssh' }, { port: 1, service: 'telnet' }] })
      assert.ok(Date.now() - t0 < 8000, 'délai borné')
      assert.equal(host.alive, true)
      assert.deepEqual(host.findings, [])
    } finally {
      await new Promise((r) => mute.close(r))
    }
  })
}
