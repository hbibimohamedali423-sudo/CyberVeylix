// CyberVeylix Sensor — serveur web local de l'interface (tableau de bord).
// Sert uniquement les fichiers statiques du dossier « ui » (build de l'application React) et /config.js.
// - config.js ne contient QUE l'URL du projet Supabase et la clé publique « anon » (jamais le mot de passe
//   du compte ni une clé service_role) : la liste blanche est explicite.
// - Lecture seule (GET/HEAD), aucun listage de dossier, aucune sortie du dossier « ui ».
import http from 'node:http'
import { readFile } from 'node:fs/promises'
import { extname, join, resolve, sep } from 'node:path'

export const DEFAULT_UI_PORT = 8710

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
}

// Origine (schéma + hôte) d'une URL, ou null si elle n'est pas une URL http(s) valide.
export function originOf(value) {
  try {
    const u = new URL(String(value))
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.origin : null
  } catch { return null }
}

// Script exécuté par la page avant l'application : window.__CV_CONFIG__ = { url, anonKey }.
export function runtimeConfigScript(env) {
  const url = originOf(env.SUPABASE_URL)
  const anonKey = typeof env.SUPABASE_ANON_KEY === 'string' ? env.SUPABASE_ANON_KEY.trim() : ''
  const cfg = url && anonKey ? { url, anonKey } : {}
  // « < » échappé : impossible de refermer la balise <script> depuis une valeur.
  return `window.__CV_CONFIG__ = ${JSON.stringify(cfg).replaceAll('<', '\\u003c')}\n`
}

// Politique de contenu : l'application ne parle qu'à elle-même et à Supabase.
export function contentSecurityPolicy(env) {
  const supa = originOf(env.SUPABASE_URL)
  const connect = ["'self'"]
  if (supa) connect.push(supa, supa.replace(/^http/, 'ws'))
  return [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    `connect-src ${connect.join(' ')}`,
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ')
}

// Chemin demandé → fichier à l'intérieur de root, ou null (traversée, caractère NUL, encodage invalide).
export function resolveRequestPath(root, urlPath) {
  let decoded
  try { decoded = decodeURIComponent(urlPath.split('?')[0].split('#')[0]) } catch { return null }
  if (decoded.includes('\0') || decoded.includes('\\')) return null
  const base = resolve(root)
  const file = resolve(join(base, decoded))
  return file === base || file.startsWith(base + sep) ? file : null
}

export function createWebServer({ root, env = process.env, log = () => {} }) {
  const csp = contentSecurityPolicy(env)
  const baseHeaders = {
    'Content-Security-Policy': csp,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
  }
  const send = (res, status, headers, body, head) => {
    res.writeHead(status, { ...baseHeaders, ...headers })
    res.end(head ? undefined : body)
  }

  return http.createServer(async (req, res) => {
    const head = req.method === 'HEAD'
    if (req.method !== 'GET' && !head) { send(res, 405, { Allow: 'GET, HEAD', 'Content-Type': 'text/plain' }, 'Method Not Allowed'); return }
    const path = (req.url || '/').split('?')[0]
    try {
      if (path === '/config.js') {
        send(res, 200, { 'Content-Type': TYPES['.js'], 'Cache-Control': 'no-store' }, runtimeConfigScript(env), head)
        return
      }
      let file = resolveRequestPath(root, path === '/' ? '/index.html' : path)
      if (!file) { send(res, 400, { 'Content-Type': 'text/plain' }, 'Bad Request', head); return }
      let ext = extname(file).toLowerCase()
      let body
      try { body = await readFile(file) } catch {
        // Chemin sans extension (ex. /vulns) : page d'accueil de l'application. Fichier absent : 404.
        if (ext) { send(res, 404, { 'Content-Type': 'text/plain' }, 'Not Found', head); return }
        file = join(resolve(root), 'index.html')
        ext = '.html'
        body = await readFile(file)
      }
      const type = TYPES[ext]
      if (!type) { send(res, 404, { 'Content-Type': 'text/plain' }, 'Not Found', head); return }
      // Fichiers du build : nom empreinté → cache long ; page d'accueil : toujours revalidée.
      const cache = file.includes(`${sep}assets${sep}`) ? 'public, max-age=31536000, immutable' : 'no-cache'
      send(res, 200, { 'Content-Type': type, 'Cache-Control': cache, 'Content-Length': body.length }, body, head)
    } catch (e) {
      log('⚠ Interface : ' + e.message)
      send(res, 500, { 'Content-Type': 'text/plain' }, 'Internal Server Error', head)
    }
  })
}

// host : 0.0.0.0 (réseau local, protégé par le pare-feu) ou 127.0.0.1 (ce PC seulement).
export function startWebServer({ root, env = process.env, port = DEFAULT_UI_PORT, host = '0.0.0.0', log = console.log }) {
  const server = createWebServer({ root, env, log })
  return new Promise((resolveStart, reject) => {
    server.once('error', reject)
    server.listen(port, host, () => {
      server.off('error', reject)
      server.on('error', (e) => log('⚠ Interface : ' + e.message))
      resolveStart({ port: server.address().port, close: () => new Promise((r) => server.close(() => r())) })
    })
  })
}
