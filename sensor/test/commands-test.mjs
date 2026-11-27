// Tests de lib/commands.mjs avec un faux client Supabase en mémoire (table sensors + sensor_commands).
import assert from 'node:assert/strict'
import { createCommandRunner, encodeResult, EXPIRE_MS } from '../lib/commands.mjs'

function fakeClient({ sensors = [{ id: 's1', name: 'PC-TEST' }], commands = [], claimRace = false } = {}) {
  const tables = { sensors, sensor_commands: commands }
  const log = []
  const result = (v) => ({ then: (ok, ko) => Promise.resolve(v).then(ok, ko) })
  function from(name) {
    const rows = tables[name]
    const query = (apply) => {
      const filters = []
      let order = null
      let wantRows = false
      const q = {
        eq: (c, v) => { filters.push((r) => r[c] === v); return q },
        lt: (c, v) => { filters.push((r) => r[c] < v); return q },
        order: (c) => { order = c; return q },
        select: () => { wantRows = true; return q },
        then: (ok, ko) => {
          let hit = rows.filter((r) => filters.every((f) => f(r)))
          if (order) hit = hit.slice().sort((a, b) => String(a[order]).localeCompare(String(b[order])))
          const out = apply(hit, wantRows)
          return Promise.resolve(out).then(ok, ko)
        },
      }
      return q
    }
    return {
      select: () => query((hit) => ({ data: hit.map((r) => ({ ...r })), error: null })),
      update: (patch) => query((hit, wantRows) => {
        if (claimRace && patch.status === 'running') return { data: [], error: null } // un autre capteur a déjà réclamé
        for (const r of hit) { Object.assign(r, patch); log.push([name, r.id, patch.status]) }
        return { data: wantRows ? hit.map((r) => ({ id: r.id })) : null, error: null }
      }),
    }
  }
  return { from, tables, log }
}

const NOW = new Date('2026-11-24T12:00:00Z')
const cmd = (over) => ({ id: 'c1', sensor_id: 's1', kind: 'scan_now', params: {}, status: 'pending', result: null, created_at: '2026-11-24T11:59:00Z', ...over })
const runner = (client, handlers, extra = {}) => createCommandRunner({ client, sensorName: 'PC-TEST', handlers, log: () => {}, now: () => NOW, ...extra })
const resultOf = (client, id) => JSON.parse(client.tables.sensor_commands.find((c) => c.id === id).result)
const statusOf = (client, id) => client.tables.sensor_commands.find((c) => c.id === id).status

export function commandsChecks(check, checkAsync) {
  check('résultat : JSON borné', () => {
    assert.equal(encodeResult({ code: 'x' }), '{"code":"x"}')
    const big = JSON.parse(encodeResult({ code: 'x', message: 'a'.repeat(5000) }))
    assert.deepEqual(big, { code: 'x', truncated: true })
  })

  checkAsync('commandes : « scan_now » exécutée une fois, résultat écrit, statut done', async () => {
    const client = fakeClient({ commands: [cmd()] })
    let calls = 0
    const r = runner(client, { scan_now: async () => { calls += 1; return { code: 'scan_done', hosts: 3, findings: 2, c: 1, h: 1, m: 0, l: 0 } } })
    assert.equal(await r.tick(), 1)
    assert.equal(await r.tick(), 0) // déjà traitée
    assert.equal(calls, 1)
    assert.equal(statusOf(client, 'c1'), 'done')
    assert.deepEqual(resultOf(client, 'c1'), { code: 'scan_done', hosts: 3, findings: 2, c: 1, h: 1, m: 0, l: 0 })
    const row = client.tables.sensor_commands[0]
    assert.ok(row.started_at && row.finished_at)
  })

  checkAsync('commandes : type sans gestionnaire (block_ip, fix…) refusé, jamais exécuté', async () => {
    const client = fakeClient({ commands: [cmd({ id: 'b', kind: 'block_ip', params: { ip: '192.168.1.50' } }), cmd({ id: 'f', kind: 'fix', params: { id: 'x' } })] })
    const r = runner(client, { scan_now: async () => ({ code: 'scan_done' }) })
    await r.tick()
    for (const id of ['b', 'f']) {
      assert.equal(statusOf(client, id), 'rejected')
      assert.equal(resultOf(client, id).code, 'unsupported')
    }
  })

  checkAsync('commandes : « __proto__ » ou « constructor » ne sont pas des gestionnaires', async () => {
    const client = fakeClient({ commands: [cmd({ id: 'p', kind: 'constructor' })] })
    await runner(client, {}).tick()
    assert.equal(statusOf(client, 'p'), 'rejected')
  })

  checkAsync('commandes : exception du gestionnaire → failed, le capteur continue', async () => {
    const client = fakeClient({ commands: [cmd({ id: 'a' }), cmd({ id: 'b', created_at: '2026-11-24T11:59:30Z' })] })
    let n = 0
    const r = runner(client, { scan_now: async () => { n += 1; if (n === 1) throw new Error('réseau coupé'); return { code: 'scan_done' } } })
    assert.equal(await r.tick(), 2)
    assert.equal(statusOf(client, 'a'), 'failed')
    assert.deepEqual(resultOf(client, 'a'), { code: 'error', message: 'réseau coupé' })
    assert.equal(statusOf(client, 'b'), 'done')
  })

  checkAsync('commandes : résultat « failed » / « rejected » du gestionnaire respecté', async () => {
    const client = fakeClient({ commands: [cmd({ id: 'a' })] })
    await runner(client, { scan_now: async () => ({ code: 'error', failed: true, message: 'x' }) }).tick()
    assert.equal(statusOf(client, 'a'), 'failed')
    const c2 = fakeClient({ commands: [cmd({ id: 'b' })] })
    await runner(c2, { scan_now: async () => ({ code: 'rejected', reason: 'gateway' }) }).tick()
    assert.equal(statusOf(c2, 'b'), 'rejected')
  })

  checkAsync('commandes : demande trop ancienne expirée sans exécution', async () => {
    const old = new Date(NOW.getTime() - EXPIRE_MS - 60000).toISOString()
    const client = fakeClient({ commands: [cmd({ id: 'old', created_at: old })] })
    let calls = 0
    await runner(client, { scan_now: async () => { calls += 1; return { code: 'scan_done' } } }).tick()
    assert.equal(calls, 0)
    assert.equal(statusOf(client, 'old'), 'rejected')
    assert.equal(resultOf(client, 'old').code, 'expired')
  })

  checkAsync('commandes : « en cours » avant redémarrage → failed (restarted), au premier passage seulement', async () => {
    const client = fakeClient({ commands: [cmd({ id: 'r', status: 'running' })] })
    const r = runner(client, { scan_now: async () => ({ code: 'scan_done' }) })
    await r.tick()
    assert.equal(statusOf(client, 'r'), 'failed')
    assert.equal(resultOf(client, 'r').code, 'restarted')
  })

  checkAsync('commandes : demande d\'un autre capteur ignorée ; capteur inconnu = rien', async () => {
    const client = fakeClient({ commands: [cmd({ id: 'x', sensor_id: 'autre' })] })
    let calls = 0
    const r = runner(client, { scan_now: async () => { calls += 1; return { code: 'scan_done' } } })
    assert.equal(await r.tick(), 0)
    assert.equal(calls, 0)
    assert.equal(statusOf(client, 'x'), 'pending')
    const none = fakeClient({ sensors: [], commands: [cmd()] })
    assert.equal(await runner(none, { scan_now: async () => ({}) }).tick(), 0)
    assert.equal(statusOf(none, 'c1'), 'pending')
  })

  checkAsync('commandes : réclamation perdue (course) → non exécutée', async () => {
    const client = fakeClient({ commands: [cmd()], claimRace: true })
    let calls = 0
    assert.equal(await runner(client, { scan_now: async () => { calls += 1; return {} } }).tick(), 0)
    assert.equal(calls, 0)
  })
}
