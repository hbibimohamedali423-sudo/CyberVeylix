// CyberVeylix Sensor — services leurres à faible interaction.
// Ils imitent juste assez un vrai service pour qu'un attaquant ou un malware s'y essaie,
// n'exécutent jamais rien, et ferment vite la connexion. Toute activité est remontée via onActivity.
import net from 'node:net'
import http from 'node:http'
import { stripTelnet, createLineReader, parseFtpCommand, parseLoginForm, sanitizeUsername } from './honeypot-proto.mjs'
import { normalizeIp } from './honeypot-monitor.mjs'

// Ports par défaut : services souvent visés par les attaquants internes et les botnets.
// 445 (SMB) et 135/139 sont exclus : Windows les utilise lui-même.
export const DEFAULT_PORTS = [21, 22, 23, 80, 1433, 2323, 3306, 3389, 5900, 8080]
const SERVICE_BY_PORT = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 2323: 'telnet', 80: 'http', 8080: 'http', 8000: 'http',
  1433: 'mssql', 3306: 'mysql', 3389: 'rdp', 5900: 'vnc',
}
export const serviceForPort = (port) => SERVICE_BY_PORT[port] || 'generic'

const LIMITS = {
  socketTimeoutMs: 15 * 1000, // connexion inactive fermée
  maxBytes: 4096, // au-delà, on ignore ce qui est envoyé
  maxConnections: 64, // par leurre
  maxBodyBytes: 8192, // corps HTTP
}

const LOGIN_PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>Administration</title>
<style>body{font-family:sans-serif;background:#eef1f5;display:grid;place-items:center;height:100vh;margin:0}
form{background:#fff;padding:28px;border-radius:8px;box-shadow:0 1px 4px #0002;width:280px}
input{width:100%;box-sizing:border-box;margin:6px 0 12px;padding:8px}button{width:100%;padding:9px}</style></head>
<body><form method="post" action="/login"><h3>Administration</h3>
<label>Utilisateur<input name="username" autocomplete="username"></label>
<label>Mot de passe<input name="password" type="password" autocomplete="current-password"></label>
<button>Connexion</button></form></body></html>`

// Lecture bornée d'un socket brut : chaque bloc passe par onData tant que la limite n'est pas atteinte.
function guard(socket, onData) {
  let received = 0
  socket.setTimeout(LIMITS.socketTimeoutMs, () => socket.destroy())
  socket.on('error', () => {})
  socket.on('data', (chunk) => {
    if (received >= LIMITS.maxBytes) return
    received += chunk.length
    onData(chunk.subarray(0, Math.max(0, chunk.length - Math.max(0, received - LIMITS.maxBytes))))
    if (received >= LIMITS.maxBytes) socket.end()
  })
}

const write = (socket, text) => { if (!socket.destroyed && socket.writable) socket.write(text) }
const closeSoon = (socket) => setTimeout(() => socket.end(), 300).unref()

function telnetHandler(socket, report) {
  const lines = createLineReader(4)
  let username = null
  write(socket, '\r\nlogin: ')
  guard(socket, (chunk) => {
    for (const line of lines.push(stripTelnet(chunk).toString('latin1'))) {
      if (username === null) {
        username = sanitizeUsername(line)
        write(socket, 'Password: ')
      } else {
        report({ kind: 'login', username, hasPassword: line.length > 0 }) // le mot de passe n'est pas transmis
        write(socket, '\r\nLogin incorrect\r\n')
        closeSoon(socket)
        return
      }
    }
  })
}

function ftpHandler(socket, report) {
  const lines = createLineReader(6)
  let username = ''
  write(socket, '220 FTP server ready.\r\n')
  guard(socket, (chunk) => {
    for (const line of lines.push(chunk.toString('latin1'))) {
      const { cmd, arg } = parseFtpCommand(line)
      if (cmd === 'USER') { username = sanitizeUsername(arg); write(socket, '331 Please specify the password.\r\n') }
      else if (cmd === 'PASS') {
        report({ kind: 'login', username, hasPassword: arg.length > 0 })
        write(socket, '530 Login incorrect.\r\n')
        closeSoon(socket)
        return
      } else if (cmd === 'QUIT') { write(socket, '221 Goodbye.\r\n'); closeSoon(socket); return }
      else write(socket, '530 Please login with USER and PASS.\r\n')
    }
    if (lines.exhausted) socket.end()
  })
}

function bannerHandler(banner) {
  return (socket) => {
    if (banner) write(socket, banner)
    guard(socket, () => {}) // on lit (borné) puis on laisse expirer
  }
}

const RAW_HANDLERS = {
  telnet: telnetHandler,
  ftp: ftpHandler,
  ssh: bannerHandler('SSH-2.0-OpenSSH_8.9p1\r\n'),
  vnc: bannerHandler('RFB 003.008\n'),
  mssql: bannerHandler(null), mysql: bannerHandler(null), rdp: bannerHandler(null), generic: bannerHandler(null),
}

function createHttpLure(report) {
  const server = http.createServer({ maxHeaderSize: 8192 }, (req, res) => {
    const reply = (status, body) => {
      res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', Connection: 'close' })
      res.end(body)
    }
    if (req.method !== 'POST') return reply(200, LOGIN_PAGE)
    const chunks = []
    let size = 0
    req.on('data', (c) => {
      size += c.length
      if (size > LIMITS.maxBodyBytes) { req.destroy(); return }
      chunks.push(c)
    })
    req.on('end', () => {
      const form = parseLoginForm(Buffer.concat(chunks).toString('utf8'), req.headers['content-type'] || '')
      if (form.username || form.hasPassword) report(req.socket, { kind: 'login', ...form })
      reply(401, LOGIN_PAGE.replace('<h3>Administration</h3>', '<h3>Administration</h3><p style="color:#b3261e">Identifiants incorrects.</p>'))
    })
    req.on('error', () => {})
  })
  server.headersTimeout = 10 * 1000
  server.requestTimeout = LIMITS.socketTimeoutMs
  server.on('clientError', (_err, socket) => socket.destroy())
  return server
}

// Un vrai service répond-il déjà sur ce port (ex. Bureau à distance, IIS, serveur SSH du client) ?
// Sous Windows, un leurre pourrait parfois s'attacher à l'IP du réseau alors qu'un service écoute sur
// « toutes les adresses », et détourner ses connexions légitimes. On vérifie donc AVANT d'écouter.
export function isPortServed(host, port, timeoutMs = 400) {
  const probe = (h) => new Promise((resolve) => {
    const s = net.connect({ host: h, port })
    let settled = false
    const done = (served) => { if (!settled) { settled = true; s.destroy(); resolve(served) } }
    s.setTimeout(timeoutMs, () => done(false))
    s.once('connect', () => done(true))
    s.on('error', () => done(false)) // « on » et non « once » : une 2e erreur ne doit jamais faire planter le capteur
  })
  const hosts = [...new Set(['127.0.0.1', host])]
  return Promise.all(hosts.map(probe)).then((r) => r.some(Boolean))
}

// services : [{ port, service? }]. host : IPv4 d'écoute. onActivity(activity) reçoit
// { srcIp, port, service, kind: 'touch' | 'login', username?, hasPassword? }.
export async function startHoneypots({ host, services, onActivity }) {
  const sockets = new Set()
  const servers = []
  const listening = []
  const failed = []

  for (const spec of services) {
    const service = spec.service || serviceForPort(spec.port)
    let server
    let boundPort = spec.port
    // Activité rapportée avec le port réellement écouté (utile quand port = 0 dans les tests).
    const reportFrom = (socket, extra) => onActivity({
      srcIp: normalizeIp(socket.remoteAddress), port: boundPort, service, ...extra,
    })

    if (service === 'http') {
      server = createHttpLure(reportFrom)
    } else {
      const handler = RAW_HANDLERS[service] || RAW_HANDLERS.generic
      server = net.createServer((socket) => handler(socket, (extra) => reportFrom(socket, extra)))
    }
    server.maxConnections = LIMITS.maxConnections
    server.on('connection', (socket) => {
      sockets.add(socket)
      socket.on('close', () => sockets.delete(socket))
      reportFrom(socket, { kind: 'touch' })
    })

    if (spec.port !== 0 && await isPortServed(host, spec.port)) {
      failed.push({ port: spec.port, service, code: 'SERVICE_PRESENT' })
      continue
    }

    try {
      await new Promise((resolve, reject) => {
        server.once('error', reject)
        server.listen({ host, port: spec.port, exclusive: true }, () => { server.off('error', reject); resolve() })
      })
      boundPort = server.address().port
      server.on('error', () => {})
      servers.push(server)
      listening.push({ port: boundPort, service })
    } catch (e) {
      failed.push({ port: spec.port, service, code: e.code || e.message })
    }
  }

  async function close() {
    for (const s of sockets) s.destroy()
    await Promise.all(servers.map((s) => new Promise((r) => s.close(() => r()))))
  }

  return { listening, failed, close }
}
