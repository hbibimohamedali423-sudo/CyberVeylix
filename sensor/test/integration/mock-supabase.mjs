// Mini PostgREST + Auth en mémoire (test d'intégration du capteur). Expose aussi /__db pour lire/écrire l'état.
import http from 'node:http'
export function startMock(port) {
  const db = { networks: [], devices: [], alerts: [], vulnerabilities: [], services: [], sensors: [], sensor_commands: [], blocked_ips: [] }
  let seq = 0
  const id = () => `00000000-0000-4000-8000-${String(++seq).padStart(12, '0')}`
  const parseVal = (v) => (v === 'null' ? null : v === 'true' ? true : v === 'false' ? false : v)
  const filtersOf = (sp) => {
    const out = []
    for (const [k, raw] of sp) {
      if (['select', 'order', 'on_conflict', 'limit', 'columns'].includes(k)) continue
      const [op, ...rest] = raw.split('.'); const v = rest.join('.')
      if (op === 'eq') out.push((r) => String(r[k]) === v)
      else if (op === 'neq') out.push((r) => String(r[k]) !== v)
      else if (op === 'lt') out.push((r) => r[k] < v)
      else if (op === 'in') { const list = v.replace(/^\(|\)$/g, '').split(',').map((x) => x.replace(/^"|"$/g, '')); out.push((r) => list.includes(String(r[k]))) }
      else if (op === 'is') out.push((r) => r[k] === parseVal(v))
    }
    return out
  }
  const server = http.createServer((req, res) => {
    let body = ''
    req.on('data', (c) => { body += c })
    req.on('end', () => {
      const u = new URL(req.url, 'http://x')
      const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(obj === undefined ? '' : JSON.stringify(obj)) }
      if (u.pathname === '/auth/v1/token') {
        return send(200, { access_token: 'tok', token_type: 'bearer', expires_in: 3600, expires_at: Math.floor(Date.now() / 1000) + 3600, refresh_token: 'r', user: { id: 'u1', aud: 'authenticated', role: 'authenticated', email: 'capteur@test' } })
      }
      if (u.pathname === '/__db') { if (req.method === 'POST') { const { table, row } = JSON.parse(body); db[table].push({ id: id(), created_at: new Date().toISOString(), ...row }) } return send(200, db) }
      const m = u.pathname.match(/^\/rest\/v1\/(\w+)$/)
      if (!m || !db[m[1]]) return send(404, { code: 'PGRST205', message: `Could not find the table 'public.${m && m[1]}' in the schema cache` })
      const rows = db[m[1]]
      const hit = () => { const f = filtersOf(u.searchParams); return rows.filter((r) => f.every((x) => x(r))) }
      const prefer = req.headers.prefer || ''
      if (req.method === 'GET') {
        let out = hit()
        const order = u.searchParams.get('order')
        if (order) { const [c] = order.split('.'); out = out.slice().sort((a, b) => String(a[c]).localeCompare(String(b[c]))) }
        return send(200, out)
      }
      if (req.method === 'POST') {
        const list = [].concat(JSON.parse(body || '[]'))
        const conflict = u.searchParams.get('on_conflict')
        const out = []
        for (const r of list) {
          const keys = conflict ? conflict.split(',').filter((k) => k !== 'user_id') : []
          const ex = keys.length && prefer.includes('merge-duplicates') ? rows.find((x) => keys.every((k) => x[k] === r[k])) : null
          if (ex) { Object.assign(ex, r); out.push(ex) } else { const n = { id: id(), user_id: 'u1', created_at: new Date().toISOString(), status: m[1] === 'sensor_commands' ? 'pending' : (m[1] === 'blocked_ips' ? 'active' : 'open'), ...r }; rows.push(n); out.push(n) }
        }
        return prefer.includes('return=representation') ? send(201, out) : send(201)
      }
      if (req.method === 'PATCH') {
        const patch = JSON.parse(body || '{}'); const out = hit()
        for (const r of out) Object.assign(r, patch)
        return prefer.includes('return=representation') ? send(200, out) : send(204)
      }
      return send(405, {})
    })
  })
  return new Promise((ok) => server.listen(port, '127.0.0.1', () => ok({ db, close: () => server.close() })))
}
