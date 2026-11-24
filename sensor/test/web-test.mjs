// Tests du serveur web de l'interface (lib/web-server.mjs) : fichiers statiques, config.js, sécurité des chemins.
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import http from 'node:http'
import { runtimeConfigScript, resolveRequestPath, startWebServer, contentSecurityPolicy } from '../lib/web-server.mjs'
import { resolveOptions } from '../lib/options.mjs'

const ENV = {
  SUPABASE_URL: 'https://abc.supabase.co/rest/v1/',
  SUPABASE_ANON_KEY: 'anon-public-key',
  CV_EMAIL: 'secret@exemple.test',
  CV_PASSWORD: 'MOT-DE-PASSE-SECRET',
}

export function webChecks(check, checkAsync) {
  check('config.js : seulement URL (origine) et clé anon, jamais le mot de passe ni l\'e-mail', () => {
    const js = runtimeConfigScript(ENV)
    assert.ok(js.startsWith('window.__CV_CONFIG__ = '))
    assert.ok(js.includes('https://abc.supabase.co') && !js.includes('/rest/v1'))
    assert.ok(js.includes('anon-public-key'))
    assert.ok(!js.includes('MOT-DE-PASSE') && !js.includes('secret@'))
  })
  check('config.js : sans Supabase → objet vide ; valeur piégée sans fermeture de balise', () => {
    assert.equal(runtimeConfigScript({}), 'window.__CV_CONFIG__ = {}\n')
    assert.equal(runtimeConfigScript({ SUPABASE_URL: 'javascript:alert(1)', SUPABASE_ANON_KEY: 'k' }), 'window.__CV_CONFIG__ = {}\n')
    const js = runtimeConfigScript({ SUPABASE_URL: 'https://a.co', SUPABASE_ANON_KEY: '</script><b>' })
    assert.ok(!js.includes('</script>'))
  })
  check('CSP : connexions limitées à l\'application et à Supabase', () => {
    const csp = contentSecurityPolicy(ENV)
    assert.ok(csp.includes("connect-src 'self' https://abc.supabase.co wss://abc.supabase.co"))
    assert.ok(csp.includes("script-src 'self'") && csp.includes("frame-ancestors 'none'"))
  })
  check('chemins : traversée de dossier et caractères interdits refusés', () => {
    const root = join(tmpdir(), 'cv-ui-root')
    assert.equal(resolveRequestPath(root, '/../secret.txt'), null)
    assert.equal(resolveRequestPath(root, '/%2e%2e/secret.txt'), null)
    assert.equal(resolveRequestPath(root, '/a%00.js'), null)
    assert.equal(resolveRequestPath(root, '/a\\b.js'), null)
    assert.equal(resolveRequestPath(root, '/%E0%A4%A'), null)
    assert.equal(resolveRequestPath(root, '/assets/app.js'), join(root, 'assets', 'app.js'))
  })
  check('options : --ui, --ui-port, --ui-local et config.json', () => {
    const base = resolveOptions(['--yes'], {}).options
    assert.equal(base.ui, false)
    assert.equal(base.uiPort, 8710)
    assert.equal(base.uiLan, true)
    const cfg = resolveOptions(['--yes'], { ui: true, uiPort: 9000, uiLan: false }).options
    assert.deepEqual([cfg.ui, cfg.uiPort, cfg.uiLan], [true, 9000, false])
    assert.equal(resolveOptions(['--yes', '--ui', '--ui-local'], {}).options.uiLan, false)
    assert.equal(resolveOptions(['--yes', '--ui-port=80'], {}).error?.includes('--ui-port'), true)
    assert.equal(resolveOptions(['--yes', '--ui-port=9000.5'], {}).error?.includes('--ui-port'), true)
    assert.equal(resolveOptions(['--yes', '--ui', '--no-ui'], { ui: true }).options.ui, true) // --no-ui n'annule que le config
  })

  checkAsync('serveur web : page, fichiers, config.js, 404, méthodes, en-têtes de sécurité', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cv-ui-'))
    mkdirSync(join(dir, 'assets'))
    writeFileSync(join(dir, 'index.html'), '<!doctype html><title>CV</title>')
    writeFileSync(join(dir, 'assets', 'app-123.js'), 'console.log(1)')
    writeFileSync(join(dir, 'config.js'), '/* fichier statique : doit être masqué par la route dynamique */')
    writeFileSync(join(dir, 'secret.exe'), 'x')
    const web = await startWebServer({ root: dir, env: ENV, port: 0, host: '127.0.0.1', log: () => {} })
    const get = (path, init) => fetch(`http://127.0.0.1:${web.port}${path}`, init)
    try {
      const home = await get('/')
      assert.equal(home.status, 200)
      assert.ok((await home.text()).includes('<title>CV</title>'))
      assert.equal(home.headers.get('x-content-type-options'), 'nosniff')
      assert.equal(home.headers.get('x-frame-options'), 'DENY')
      assert.ok(home.headers.get('content-security-policy').includes("default-src 'self'"))
      assert.equal(home.headers.get('cache-control'), 'no-cache')

      const js = await get('/assets/app-123.js')
      assert.equal(js.status, 200)
      assert.ok(js.headers.get('content-type').startsWith('text/javascript'))
      assert.ok(js.headers.get('cache-control').includes('immutable'))

      const cfg = await get('/config.js')
      const cfgText = await cfg.text()
      assert.ok(cfgText.includes('anon-public-key') && !cfgText.includes('fichier statique'))
      assert.ok(!cfgText.includes('MOT-DE-PASSE'))
      assert.equal(cfg.headers.get('cache-control'), 'no-store')

      const spa = await get('/vulns') // route de l'application → page d'accueil
      assert.equal(spa.status, 200)
      assert.ok((await spa.text()).includes('<title>CV</title>'))
      assert.equal((await get('/inexistant.js')).status, 404)
      assert.equal((await get('/secret.exe')).status, 404) // type non servi
      assert.equal((await get('/', { method: 'POST', body: 'x' })).status, 405)
      assert.equal((await get('/', { method: 'DELETE' })).status, 405)
      assert.equal((await get('/', { method: 'HEAD' })).status, 200)
      // fetch() normalise les « .. » : requêtes brutes pour atteindre réellement le serveur.
      const raw = (path) => new Promise((ok, ko) => http.get({ host: '127.0.0.1', port: web.port, path }, (r) => { r.resume(); ok(r.statusCode) }).on('error', ko))
      assert.equal(await raw('/%2e%2e/%2e%2e/etc/passwd'), 400)
      assert.equal(await raw('/../../etc/passwd'), 400)
      assert.equal(await raw('/..%5c..%5csecret'), 400)
    } finally {
      await web.close()
      rmSync(dir, { recursive: true, force: true })
    }
  })

  checkAsync('serveur web : port déjà pris → erreur claire (le capteur continue)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cv-ui-'))
    writeFileSync(join(dir, 'index.html'), 'x')
    const first = await startWebServer({ root: dir, env: {}, port: 0, host: '127.0.0.1', log: () => {} })
    try {
      await assert.rejects(startWebServer({ root: dir, env: {}, port: first.port, host: '127.0.0.1', log: () => {} }), /EADDRINUSE/)
    } finally {
      await first.close()
      rmSync(dir, { recursive: true, force: true })
    }
  })
}
