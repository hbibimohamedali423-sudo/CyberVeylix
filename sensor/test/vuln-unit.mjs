// Tests unitaires du moteur de vulnérabilités (aucun réseau). Appelé par sensor/test/run.mjs.
import assert from 'node:assert/strict'
import {
  parseVersion, compareVersions, parseSshBanner, parseFtpBanner, parseServerHeader,
  smb1NegotiateRequest, parseSmb1NegotiateResponse, rdpNegotiationRequest, parseRdpNegotiationResponse,
  parseRfbVersion, parseVncSecurityTypes, parseMysqlGreeting, analyzeCertificate, hasPasswordField,
} from '../lib/vuln/parsers.mjs'
import { evaluate, diffFindings, bySeverity } from '../lib/vuln/rules.mjs'

const smbResponse = ({ proto = 0xff, status = 0, dialect = 0 } = {}) => {
  const b = Buffer.alloc(39)
  b.writeUInt32BE(35, 0)
  Buffer.from([proto, 0x53, 0x4d, 0x42]).copy(b, 4)
  b[8] = 0x72
  b.writeUInt32LE(status, 9)
  b[36] = 17
  b.writeUInt16LE(dialect, 37)
  return b
}
const rdpResponse = (type, value) => {
  const b = Buffer.from([0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0, type, 0, 8, 0, 0, 0, 0, 0])
  b.writeUInt32LE(value, 15)
  return b
}
const obs = (over) => ({ ip: '192.168.1.20', port: 22, service: 'ssh', open: true, ...over })
const rules = (o) => evaluate(o).map((f) => f.rule)

export function vulnUnitChecks(check) {
  check('Vuln : versions comparées champ par champ (y compris « p1 »)', () => {
    assert.deepEqual(parseVersion('9.6p1'), [9, 6, 1])
    assert.equal(compareVersions('9.6p1', '9.8p1'), -1)
    assert.equal(compareVersions('8.5p1', '8.5p1'), 0)
    assert.equal(compareVersions('2.4.51', '2.4.9'), 1)
    assert.equal(compareVersions('abc', '1.0'), null)
  })

  check('Vuln : bannières SSH, FTP et en-tête Server', () => {
    assert.deepEqual(parseSshBanner('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n'),
      { protocol: '2.0', software: 'OpenSSH_9.6p1', product: 'OpenSSH', version: '9.6p1', comment: 'Ubuntu-3ubuntu13' })
    assert.equal(parseSshBanner('SSH-2.0-dropbear_2015.71').version, '2015.71')
    assert.equal(parseSshBanner('HTTP/1.1 400'), null)
    assert.deepEqual(parseFtpBanner('220 (vsFTPd 2.3.4)\r\n'), { product: 'vsftpd', version: '2.3.4' })
    assert.deepEqual(parseFtpBanner('220 ProFTPD 1.3.5a Server (Debian)'), { product: 'ProFTPD', version: '1.3.5a' })
    assert.equal(parseFtpBanner('500 nope'), null)
    assert.deepEqual(parseServerHeader('Apache/2.4.49 (Unix)'), { product: 'Apache', version: '2.4.49' })
    assert.deepEqual(parseServerHeader('Microsoft-IIS/6.0'), { product: 'Microsoft-IIS', version: '6.0' })
    assert.equal(parseServerHeader('cloudflare'), null)
  })

  check('Vuln : SMBv1 — requête valide et réponses interprétées', () => {
    const req = smb1NegotiateRequest()
    assert.equal(req.readUInt32BE(0), req.length - 4)
    assert.equal(req.subarray(4, 8).toString('latin1'), '\xffSMB')
    assert.equal(req[8], 0x72)
    assert.ok(req.includes(Buffer.from('NT LM 0.12\0', 'latin1')))
    assert.equal(parseSmb1NegotiateResponse(smbResponse()), true)
    assert.equal(parseSmb1NegotiateResponse(smbResponse({ dialect: 0xffff })), false)
    assert.equal(parseSmb1NegotiateResponse(smbResponse({ status: 0xc0000022 })), false)
    assert.equal(parseSmb1NegotiateResponse(smbResponse({ proto: 0xfe })), false)
    assert.equal(parseSmb1NegotiateResponse(Buffer.from('garbage!')), null)
    assert.equal(parseSmb1NegotiateResponse(Buffer.alloc(3)), null)
  })

  check('Vuln : RDP — NLA exigée ou non', () => {
    const req = rdpNegotiationRequest()
    assert.equal(req.length, 19)
    assert.equal(req[3], 19)
    assert.equal(req[11], 0x01)
    assert.equal(req.readUInt32LE(15), 1) // TLS seul proposé
    assert.equal(parseRdpNegotiationResponse(rdpResponse(0x02, 1)), 'no-nla')
    assert.equal(parseRdpNegotiationResponse(rdpResponse(0x03, 5)), 'nla-required')
    assert.equal(parseRdpNegotiationResponse(rdpResponse(0x03, 2)), 'no-nla')
    assert.equal(parseRdpNegotiationResponse(rdpResponse(0x02, 1).subarray(0, 11)), 'no-nla') // ancien serveur
    assert.equal(parseRdpNegotiationResponse(Buffer.from('HTTP/1.1 200')), null)
  })

  check('Vuln : VNC — version et types de sécurité (3.3 et 3.8)', () => {
    assert.deepEqual(parseRfbVersion('RFB 003.008\n'), { major: 3, minor: 8 })
    assert.equal(parseRfbVersion('SSH-2.0'), null)
    assert.deepEqual(parseVncSecurityTypes(Buffer.from([2, 1, 2]), 8), [1, 2])
    assert.deepEqual(parseVncSecurityTypes(Buffer.from([0, 0, 0, 2]), 3), [2])
    assert.deepEqual(parseVncSecurityTypes(Buffer.from([0]), 8), [])
    assert.equal(parseVncSecurityTypes(Buffer.from([0, 0]), 3), null)
  })

  check('Vuln : MySQL — version annoncée, hôte refusé, paquet invalide', () => {
    const payload = Buffer.concat([Buffer.from([10]), Buffer.from('8.0.36\0', 'latin1'), Buffer.alloc(20)])
    const hdr = Buffer.alloc(4)
    hdr.writeUIntLE(payload.length, 0, 3)
    assert.deepEqual(parseMysqlGreeting(Buffer.concat([hdr, payload])), { version: '8.0.36' })
    const err = Buffer.from([5, 0, 0, 0, 0xff, 0x6a, 0x04, 0x48, 0x6f])
    assert.deepEqual(parseMysqlGreeting(err), { blocked: true })
    assert.equal(parseMysqlGreeting(Buffer.from([1, 0])), null)
  })

  check('Vuln : certificat expiré / auto-signé', () => {
    const now = Date.parse('2026-11-24T00:00:00Z')
    const self = { subject: { CN: 'nas.local' }, issuer: { CN: 'nas.local' }, valid_to: 'Jan  1 00:00:00 2025 GMT' }
    assert.deepEqual(analyzeCertificate(self, now).expired, true)
    assert.equal(analyzeCertificate(self, now).selfSigned, true)
    const ok = { subject: { CN: 'a' }, issuer: { CN: 'CA' }, valid_to: 'Jan  1 00:00:00 2030 GMT' }
    assert.equal(analyzeCertificate(ok, now).expired, false)
    assert.equal(analyzeCertificate(ok, now).selfSigned, false)
    assert.equal(analyzeCertificate({}, now), null)
    assert.equal(hasPasswordField('<form><input name=p TYPE="password"></form>'), true)
    assert.equal(hasPasswordField('<input type="text">'), false)
  })

  check('Règle regreSSHion : bornes exactes 8.5p1 ≤ v < 9.8p1, confiance selon la distribution', () => {
    const ssh = (version, comment = '') => obs({ ssh: { protocol: '2.0', product: 'OpenSSH', version, software: `OpenSSH_${version}`, comment } })
    assert.deepEqual(rules(ssh('9.6p1')), ['ssh-regresshion'])
    assert.deepEqual(rules(ssh('8.5p1')), ['ssh-regresshion'])
    assert.deepEqual(rules(ssh('8.4p1')), [])
    assert.deepEqual(rules(ssh('9.8p1')), [])
    assert.deepEqual(rules(ssh('4.3p2')), ['ssh-regresshion'])
    assert.equal(evaluate(ssh('9.6p1'))[0].confidence, 'probable')
    assert.equal(evaluate(ssh('8.9p1', 'Ubuntu-3ubuntu0.10'))[0].confidence, 'à vérifier')
    assert.deepEqual(evaluate(ssh('9.6p1'))[0].cves, ['CVE-2024-6387'])
  })

  check('Règles SSH v1 et Dropbear ancien', () => {
    assert.deepEqual(rules(obs({ ssh: { protocol: '1.5', software: 'x', product: null, version: null, comment: '' } })), ['ssh-v1'])
    assert.deepEqual(rules(obs({ ssh: { protocol: '1.99', software: 'x', product: null, version: null, comment: '' } })), [])
    assert.deepEqual(rules(obs({ ssh: { protocol: '2.0', product: 'Dropbear', version: '2015.71', software: 'dropbear_2015.71', comment: '' } })), ['ssh-dropbear-old'])
    assert.deepEqual(rules(obs({ ssh: { protocol: '2.0', product: 'Dropbear', version: '2022.83', software: 'dropbear_2022.83', comment: '' } })), [])
  })

  check('Règles FTP : porte dérobée vsftpd, ProFTPD 1.3.5 (pas 1.3.5a), FTP en clair', () => {
    const ftp = (product, version, tls = false) => obs({ port: 21, service: 'ftp', ftp: { product, version, tls } })
    assert.deepEqual(rules(ftp('vsftpd', '2.3.4')).sort(), ['ftp-cleartext', 'ftp-vsftpd-backdoor'])
    assert.deepEqual(rules(ftp('vsftpd', '3.0.5', true)), [])
    assert.deepEqual(rules(ftp('ProFTPD', '1.3.5', true)), ['ftp-proftpd-modcopy'])
    assert.deepEqual(rules(ftp('ProFTPD', '1.3.5a', true)), [])
  })

  check('Règles web : Apache 2.4.49/2.4.50, IIS 6.0, connexion en HTTP', () => {
    const http = (server, extra = {}) => {
      const p = parseServerHeader(server) || {}
      return obs({ port: 80, service: 'http', http: { server, product: p.product, version: p.version, secure: false, loginForm: false, ...extra } })
    }
    assert.deepEqual(evaluate(http('Apache/2.4.49 (Unix)'))[0].cves, ['CVE-2021-41773'])
    assert.deepEqual(evaluate(http('Apache/2.4.50'))[0].cves, ['CVE-2021-42013'])
    assert.deepEqual(rules(http('Apache/2.4.51')), [])
    assert.deepEqual(rules(http('Microsoft-IIS/6.0')), ['http-iis6'])
    assert.deepEqual(rules(http('Microsoft-IIS/10.0')), [])
    assert.deepEqual(rules(http('lighttpd', { loginForm: true })), ['http-login-cleartext'])
    assert.deepEqual(rules(http('lighttpd', { loginForm: true, secure: true })), [])
  })

  check('Règles configuration : Telnet, SMBv1, RDP sans NLA, VNC, Redis, Docker, Elasticsearch, bases, TLS', () => {
    assert.deepEqual(rules(obs({ port: 23, service: 'telnet' })), ['telnet-open'])
    assert.deepEqual(rules(obs({ port: 445, service: 'smb', smb1: true })), ['smb1-enabled'])
    assert.deepEqual(rules(obs({ port: 445, service: 'smb', smb1: false })), [])
    assert.deepEqual(rules(obs({ port: 445, service: 'smb', smb1: null })), [])
    assert.deepEqual(rules(obs({ port: 3389, service: 'rdp', rdp: 'no-nla' })), ['rdp-no-nla'])
    assert.deepEqual(rules(obs({ port: 3389, service: 'rdp', rdp: 'nla-required' })), [])
    assert.deepEqual(rules(obs({ port: 5900, service: 'vnc', vnc: { types: [1] } })), ['vnc-noauth'])
    assert.deepEqual(rules(obs({ port: 5900, service: 'vnc', vnc: { types: [2] } })), [])
    assert.deepEqual(rules(obs({ port: 6379, service: 'redis', redis: 'open' })), ['redis-noauth'])
    assert.deepEqual(rules(obs({ port: 6379, service: 'redis', redis: 'auth' })), [])
    assert.deepEqual(rules(obs({ port: 2375, service: 'docker', docker: { version: '24.0' } })), ['docker-api-open'])
    assert.deepEqual(rules(obs({ port: 9200, service: 'elasticsearch', es: { cluster: 'prod' } })), ['elasticsearch-open'])
    assert.deepEqual(rules(obs({ port: 3306, service: 'mysql', mysql: { version: '8.0.36' } })), ['db-exposed'])
    assert.deepEqual(rules(obs({ port: 3306, service: 'mysql', mysql: { blocked: true } })), []) // hôte refusé
    const tls = (cert, legacy = false) => obs({ port: 443, service: 'https', tls: { cert, legacy } })
    assert.deepEqual(rules(tls({ expired: true, selfSigned: true, subject: 'x', validTo: 'x' })), ['tls-expired'])
    assert.deepEqual(rules(tls({ expired: false, selfSigned: true, subject: 'x', validTo: 'x' }, true)).sort(), ['tls-legacy', 'tls-selfsigned'])
  })

  check('Vuln : chaque résultat a clé stable, titre, gravité, preuve et correction', () => {
    const f = evaluate(obs({ port: 445, service: 'smb', smb1: true }))[0]
    assert.equal(f.key, '192.168.1.20:445:smb1-enabled')
    for (const k of ['title', 'severity', 'evidence', 'remediation', 'confidence']) assert.ok(f[k], k)
  })

  check('Vuln : comparaison d\'analyses — nouvelles, corrigées, appareil absent ≠ corrigé', () => {
    const a = { key: '1.1.1.1:23:telnet-open', ip: '192.168.1.5' }
    const b = { key: '192.168.1.6:445:smb1-enabled', ip: '192.168.1.6' }
    const c = { key: '192.168.1.7:5900:vnc-noauth', ip: '192.168.1.7' }
    const d = diffFindings([a, b], [b, c], ['192.168.1.6', '192.168.1.7']) // .5 non analysé cette fois
    assert.deepEqual(d.added.map((f) => f.key), [c.key])
    assert.deepEqual(d.fixed, [])
    const d2 = diffFindings([a, b], [b], ['192.168.1.5', '192.168.1.6'])
    assert.deepEqual(d2.fixed.map((f) => f.key), [a.key])
  })

  check('Vuln : tri critique → basse puis IP numérique', () => {
    const list = [
      { severity: 'm', ip: '192.168.1.10', port: 1 }, { severity: 'c', ip: '192.168.1.9', port: 1 },
      { severity: 'c', ip: '192.168.1.10', port: 1 }, { severity: 'l', ip: '192.168.1.2', port: 1 },
    ].sort(bySeverity)
    assert.deepEqual(list.map((f) => `${f.severity}${f.ip.split('.')[3]}`), ['c9', 'c10', 'm10', 'l2'])
  })

  check('Vuln : observations corrompues → aucune exception', () => {
    for (const o of [{}, { ssh: {} }, { http: { version: 5 } }, { tls: {} }, { vnc: {} }, { ip: null }]) evaluate(o)
  })
}
