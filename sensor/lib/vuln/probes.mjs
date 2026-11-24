// CyberVeylix — sondes réseau des vulnérabilités.
// Elles ne font que LIRE ce qu'un service annonce ou négocier son protocole, exactement comme un
// client normal : aucune exploitation, aucun essai de mot de passe, aucune écriture.
// Chaque sonde rend une observation partielle ; une sonde qui échoue rend {} (jamais d'exception).
import net from 'node:net'
import tls from 'node:tls'
import http from 'node:http'
import https from 'node:https'
import {
  parseSshBanner, parseFtpBanner, parseServerHeader, smb1NegotiateRequest, parseSmb1NegotiateResponse,
  rdpNegotiationRequest, parseRdpNegotiationResponse, parseRfbVersion, parseVncSecurityTypes,
  parseMysqlGreeting, analyzeCertificate, hasPasswordField,
} from './parsers.mjs'

const MAX_BYTES = 16 * 1024
const DEFAULT_TIMEOUT = 4000

// Dialogue TCP borné. step(data, write) renvoie true quand l'échange est terminé.
// Résultat : { connected, refused, data }.
export function talk(ip, port, step, timeoutMs = DEFAULT_TIMEOUT) {
  return new Promise((resolve) => {
    const s = net.connect({ host: ip, port })
    let data = Buffer.alloc(0)
    let connected = false
    let done = false
    const finish = (extra = {}) => {
      if (done) return
      done = true
      s.destroy()
      resolve({ connected, refused: false, data, ...extra })
    }
    const write = (b) => { if (!s.destroyed) s.write(b) }
    s.setTimeout(timeoutMs, () => finish())
    s.on('connect', () => {
      connected = true
      try { if (step(data, write, 'connect')) finish() } catch { finish() }
    })
    s.on('data', (chunk) => {
      data = Buffer.concat([data, chunk]).subarray(0, MAX_BYTES)
      try { if (step(data, write, 'data') || data.length >= MAX_BYTES) finish() } catch { finish() }
    })
    s.on('error', (e) => finish({ refused: e.code === 'ECONNREFUSED' }))
    s.on('close', () => finish())
  })
}

// Port ouvert ? (et « refusé » : l'hôte est joignable mais le port fermé)
export async function probeOpen(ip, port, timeoutMs = 1500) {
  const r = await talk(ip, port, (_d, _w, ev) => ev === 'connect', timeoutMs)
  return { open: r.connected, refused: r.refused }
}

const firstLine = (buf) => buf.toString('latin1').split(/\r?\n/)[0]

async function probeSsh(ip, port) {
  const r = await talk(ip, port, (d) => d.includes(0x0a))
  const ssh = r.data.length ? parseSshBanner(r.data.toString('latin1')) : null
  return ssh ? { ssh } : {}
}

async function probeFtp(ip, port) {
  let sent = false
  const r = await talk(ip, port, (d, write) => {
    const text = d.toString('latin1')
    if (!sent && /^220 /m.test(text)) { write('FEAT\r\n'); sent = true; return false }
    // Fin de la liste des fonctions (« 211 End ») ou refus de FEAT (5xx) : 211 n'apparaît qu'après FEAT.
    return sent && (/^211 /m.test(text) || /^5\d\d /m.test(text))
  })
  const text = r.data.toString('latin1')
  const banner = parseFtpBanner(text)
  if (!banner) return {}
  return { ftp: { ...banner, tls: /AUTH\s+TLS|AUTH\s+SSL/i.test(text) } }
}

function httpGet(ip, port, path, secure, timeoutMs = DEFAULT_TIMEOUT) {
  return new Promise((resolve) => {
    const lib = secure ? https : http
    const req = lib.request({
      host: ip, port, path, method: 'GET', timeout: timeoutMs,
      headers: { 'User-Agent': 'CyberVeylix-Audit', Accept: '*/*', Connection: 'close' },
      rejectUnauthorized: false, // on veut justement analyser les certificats invalides
    }, (res) => {
      let body = ''
      res.setEncoding('latin1')
      res.on('data', (c) => { if (body.length < 64 * 1024) body += c })
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }))
      res.on('error', () => resolve(null))
    })
    req.on('timeout', () => req.destroy())
    req.on('error', () => resolve(null))
    req.end()
  })
}

async function probeHttp(ip, port, secure) {
  const res = await httpGet(ip, port, '/', secure)
  if (!res) return {}
  const server = String(res.headers.server || '').slice(0, 120)
  const parsed = parseServerHeader(server) || {}
  return {
    http: {
      status: res.status, server, product: parsed.product || null, version: parsed.version || null,
      secure, loginForm: hasPasswordField(res.body),
    },
  }
}

function tlsHandshake(ip, port, options, timeoutMs = DEFAULT_TIMEOUT) {
  return new Promise((resolve) => {
    let done = false
    const finish = (v) => { if (!done) { done = true; s.destroy(); resolve(v) } }
    const s = tls.connect({ host: ip, port, rejectUnauthorized: false, servername: undefined, ...options })
    s.setTimeout(timeoutMs, () => finish(null))
    s.once('secureConnect', () => finish({ cert: s.getPeerCertificate(), protocol: s.getProtocol() }))
    s.on('error', () => finish(null))
  })
}

async function probeTls(ip, port, now) {
  const modern = await tlsHandshake(ip, port, {})
  if (!modern) return {}
  // TLS 1.0 encore accepté ? (OpenSSL 3 l'interdit par défaut côté client : niveau de sécurité 0 requis)
  const legacy = await tlsHandshake(ip, port, { minVersion: 'TLSv1', maxVersion: 'TLSv1', ciphers: 'DEFAULT@SECLEVEL=0' })
  return { tls: { cert: analyzeCertificate(modern.cert, now), legacy: Boolean(legacy), protocol: modern.protocol } }
}

async function probeSmb(ip, port) {
  const r = await talk(ip, port, (d, write, ev) => {
    if (ev === 'connect') { write(smb1NegotiateRequest()); return false }
    return d.length >= 4 && d.length >= 4 + d.readUIntBE(1, 3)
  })
  if (!r.connected) return {}
  // Connexion fermée sans réponse : Windows/NAS sans SMBv1 coupe simplement la négociation.
  return { smb1: r.data.length ? parseSmb1NegotiateResponse(r.data) : false }
}

async function probeRdp(ip, port) {
  const r = await talk(ip, port, (d, write, ev) => {
    if (ev === 'connect') { write(rdpNegotiationRequest()); return false }
    return d.length >= 4 && d.length >= d.readUInt16BE(2)
  })
  return r.data.length ? { rdp: parseRdpNegotiationResponse(r.data) } : {}
}

async function probeVnc(ip, port) {
  let version = null
  const r = await talk(ip, port, (d, write) => {
    if (!version) {
      if (d.length < 12) return false
      version = parseRfbVersion(d.subarray(0, 12).toString('latin1'))
      if (!version) return true
      const minor = Math.min(version.minor >= 7 ? 8 : 3, 8)
      write(`RFB 003.00${minor}\n`)
      return false
    }
    const rest = d.subarray(12)
    if (version.minor < 7) return rest.length >= 4
    return rest.length >= 1 && rest.length >= 1 + rest[0]
  })
  if (!version) return {}
  const types = parseVncSecurityTypes(r.data.subarray(12), version.minor >= 7 ? 8 : 3)
  return types ? { vnc: { version: `${version.major}.${version.minor}`, types } } : {}
}

async function probeRedis(ip, port) {
  const r = await talk(ip, port, (d, write, ev) => {
    if (ev === 'connect') { write('PING\r\n'); return false }
    return d.includes(0x0a)
  })
  const line = firstLine(r.data)
  if (line.startsWith('+PONG')) return { redis: 'open' }
  if (/^-(NOAUTH|ERR|DENIED)/.test(line)) return { redis: 'auth' }
  return {}
}

async function probeMysql(ip, port) {
  const r = await talk(ip, port, (d) => d.length >= 4 && d.length >= 4 + d.readUIntLE(0, 3))
  const g = parseMysqlGreeting(r.data)
  return g ? { mysql: g } : {}
}

async function probeDocker(ip, port) {
  const res = await httpGet(ip, port, '/version', false)
  if (!res || res.status !== 200) return {}
  try {
    const j = JSON.parse(res.body)
    return j && j.ApiVersion ? { docker: { version: String(j.Version || j.ApiVersion).slice(0, 40) } } : {}
  } catch { return {} }
}

async function probeElasticsearch(ip, port) {
  const res = await httpGet(ip, port, '/', false)
  if (!res || res.status !== 200) return {}
  try {
    const j = JSON.parse(res.body)
    return j && (j.cluster_name || j.tagline) ? { es: { cluster: String(j.cluster_name || '').slice(0, 80) } } : {}
  } catch { return {} }
}

// Service supposé par port (surcharge possible : { port, service }).
export const PORT_SERVICES = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 80: 'http', 443: 'https', 445: 'smb', 993: 'tls', 995: 'tls',
  1433: 'mssql', 2375: 'docker', 3306: 'mysql', 3389: 'rdp', 5432: 'postgres', 5900: 'vnc',
  6379: 'redis', 8000: 'http', 8080: 'http', 8443: 'https', 9200: 'elasticsearch',
}

// Sondes par service (après confirmation que le port est ouvert).
export const SERVICE_PROBES = {
  ssh: probeSsh,
  ftp: probeFtp,
  http: (ip, port) => probeHttp(ip, port, false),
  https: async (ip, port, now) => ({ ...(await probeHttp(ip, port, true)), ...(await probeTls(ip, port, now)) }),
  tls: (ip, port, now) => probeTls(ip, port, now),
  smb: probeSmb,
  rdp: probeRdp,
  vnc: probeVnc,
  redis: probeRedis,
  mysql: probeMysql,
  docker: probeDocker,
  elasticsearch: probeElasticsearch,
}
