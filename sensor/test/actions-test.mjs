// Tests de lib/blocker.mjs et lib/actions.mjs : pare-feu simulé (aucune commande réelle) et faux client Supabase.
import assert from 'node:assert/strict'
import { createBlocker, protectedReason, ruleName, isValidIpv4 } from '../lib/blocker.mjs'
import { createActions, AUTO_BLOCK_MAX_PER_HOUR } from '../lib/actions.mjs'

// Pare-feu simulé : mémorise les règles posées par « netsh advfirewall firewall … ».
function fakeFirewall({ failAdd = null, noDelete = false } = {}) {
  const rules = new Set()
  const calls = []
  const exec = async (file, args) => {
    calls.push([file, ...args])
    assert.equal(file, 'netsh')
    assert.deepEqual(args.slice(0, 2), ['advfirewall', 'firewall'])
    const verb = args[2]
    const name = args.find((a) => a.startsWith('name='))?.slice(5)
    if (verb === 'show') { if (!rules.has(name)) throw Object.assign(new Error('Aucune règle'), { code: 1 }); return 'ok' }
    if (verb === 'add') {
      if (failAdd && args.includes(`dir=${failAdd}`)) throw new Error('Accès refusé')
      rules.add(name); return 'ok'
    }
    if (verb === 'delete') { if (!noDelete) rules.delete(name); if (!rules.has(name) && !noDelete) return 'ok'; return 'ok' }
    throw new Error('verbe inconnu ' + verb)
  }
  return { exec, rules, calls }
}

function fakeClient({ sensorRow = { id: 's1', auto_block: false, trusted_ips: null }, blocked = [] } = {}) {
  const tables = { sensors: [sensorRow], blocked_ips: blocked }
  let seq = 0
  const query = (rows, apply) => {
    const filters = []
    const q = {
      eq: (c, v) => { filters.push((r) => r[c] === v); return q },
      then: (ok, ko) => Promise.resolve(apply(rows.filter((r) => filters.every((f) => f(r))))).then(ok, ko),
    }
    return q
  }
  return {
    tables,
    from: (name) => ({
      select: () => query(tables[name], (hit) => ({ data: hit.map((r) => ({ ...r })), error: null })),
      update: (patch) => query(tables[name], (hit) => { hit.forEach((r) => Object.assign(r, patch)); return { error: null } }),
      insert: (row) => { tables[name].push({ id: `b${++seq}`, ...row }); return Promise.resolve({ error: null }) },
    }),
  }
}

const CTX = () => ({ gatewayIp: '192.168.1.1', sensorIp: '192.168.1.10', dhcp: ['192.168.1.2'] })
const make = ({ fw = fakeFirewall(), client = fakeClient(), platform = 'win32', serviceIps = async () => [] } = {}) => {
  const blocker = createBlocker({ platform, exec: fw.exec })
  const logs = []
  const actions = createActions({ client, getSensorId: async () => 's1', blocker, context: CTX, serviceIps, log: (m) => logs.push(m) })
  return { fw, client, actions, logs }
}

export function actionsChecks(check, checkAsync) {
  check('adresses : protégées ou invalides jamais bloquables', () => {
    const ctx = { gatewayIp: '192.168.1.1', sensorIp: '192.168.1.10', trusted: ['192.168.1.77'], dhcp: ['192.168.1.2'], serviceIps: ['104.18.1.1'] }
    assert.equal(protectedReason('192.168.1.1', ctx), 'gateway')
    assert.equal(protectedReason('192.168.1.10', ctx), 'self')
    assert.equal(protectedReason('192.168.1.77', ctx), 'trusted')
    assert.equal(protectedReason('192.168.1.2', ctx), 'dhcp')
    assert.equal(protectedReason('104.18.1.1', ctx), 'dns_service')
    for (const bad of ['127.0.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '300.1.1.1', '1.2.3', '10.0.0.1; calc', '', undefined, 5]) {
      assert.equal(protectedReason(bad, ctx), 'invalid_ip', String(bad))
    }
    assert.equal(protectedReason('192.168.1.50', ctx), null)
    assert.equal(isValidIpv4('192.168.1.50'), true)
  })

  checkAsync('pare-feu : règles entrante et sortante posées, vérifiées, sans shell', async () => {
    const fw = fakeFirewall()
    const b = createBlocker({ platform: 'win32', exec: fw.exec })
    assert.deepEqual(await b.block('192.168.1.50'), { ok: true })
    assert.ok(fw.rules.has(ruleName('192.168.1.50')))
    const adds = fw.calls.filter((c) => c[3] === 'add')
    assert.equal(adds.length, 2)
    assert.ok(adds.some((c) => c.includes('dir=in')) && adds.some((c) => c.includes('dir=out')))
    assert.ok(adds.every((c) => c.includes('action=block') && c.includes('remoteip=192.168.1.50')))
    assert.deepEqual(await b.block('192.168.1.50'), { ok: true, already: true }) // idempotent
    assert.equal(fw.calls.filter((c) => c[3] === 'add').length, 2)
    assert.deepEqual(await b.unblock('192.168.1.50'), { ok: true })
    assert.equal(fw.rules.size, 0)
    assert.deepEqual(await b.unblock('192.168.1.50'), { ok: true }) // déjà absente : pas une erreur
  })

  checkAsync('pare-feu : adresse piégée refusée avant tout appel ; système non Windows non supporté', async () => {
    const fw = fakeFirewall()
    const b = createBlocker({ platform: 'win32', exec: fw.exec })
    assert.equal((await b.block('10.0.0.1 & calc')).code, 'invalid_ip')
    assert.equal((await b.block('127.0.0.1')).code, 'invalid_ip')
    assert.equal(fw.calls.length, 0)
    const linux = createBlocker({ platform: 'linux', exec: fw.exec })
    assert.equal((await linux.block('192.168.1.50')).code, 'unsupported_os')
    assert.equal(fw.calls.length, 0)
  })

  checkAsync('pare-feu : échec de la règle sortante → rien ne reste posé', async () => {
    const fw = fakeFirewall({ failAdd: 'out' })
    const b = createBlocker({ platform: 'win32', exec: fw.exec })
    const r = await b.block('192.168.1.50')
    assert.equal(r.ok, false)
    assert.equal(r.code, 'firewall_error')
    assert.equal(fw.rules.size, 0)
  })

  checkAsync('blocage : passerelle, PC du capteur, DHCP, adresses du service → refusé, pare-feu intact', async () => {
    const t = make({ serviceIps: async () => ['104.18.1.1'] })
    for (const [ip, reason] of [['192.168.1.1', 'gateway'], ['192.168.1.10', 'self'], ['192.168.1.2', 'dhcp'], ['104.18.1.1', 'dns_service'], ['127.0.0.1', 'invalid_ip']]) {
      const r = await t.actions.handlers.block_ip({ ip })
      assert.deepEqual([r.code, r.reason], ['rejected', reason], ip)
    }
    assert.equal(t.fw.calls.length, 0)
    assert.equal(t.client.tables.blocked_ips.length, 0)
  })

  checkAsync('blocage : liste « ne jamais bloquer » du capteur respectée', async () => {
    const t = make({ client: fakeClient({ sensorRow: { id: 's1', auto_block: false, trusted_ips: ['192.168.1.77', 'pas-une-ip'] } }) })
    assert.equal((await t.actions.handlers.block_ip({ ip: '192.168.1.77' })).reason, 'trusted')
  })

  checkAsync('blocage manuel : règle posée, ligne blocked_ips active (raison, alerte, auteur)', async () => {
    const t = make()
    const alertId = '123e4567-e89b-12d3-a456-426614174000'
    const r = await t.actions.handlers.block_ip({ ip: '192.168.1.50', reason: 'Balayage', alert_id: alertId, by: 'manual' })
    assert.deepEqual(r, { code: 'blocked', ip: '192.168.1.50', already: false, recorded: true })
    assert.ok(t.fw.rules.has(ruleName('192.168.1.50')))
    const row = t.client.tables.blocked_ips[0]
    assert.deepEqual([row.ip, row.status, row.blocked_by, row.reason, row.alert_id, row.sensor_id], ['192.168.1.50', 'active', 'manual', 'Balayage', alertId, 's1'])
    // second blocage : pas de doublon
    await t.actions.handlers.block_ip({ ip: '192.168.1.50', reason: 'Autre' })
    assert.equal(t.client.tables.blocked_ips.length, 1)
  })

  checkAsync('blocage : alert_id invalide ignoré ; auteur inconnu = manual', async () => {
    const t = make()
    await t.actions.handlers.block_ip({ ip: '192.168.1.51', alert_id: "x'; drop table alerts;--", by: 'root' })
    const row = t.client.tables.blocked_ips[0]
    assert.equal(row.alert_id, null)
    assert.equal(row.blocked_by, 'manual')
  })

  checkAsync('blocage : échec du pare-feu → résultat « failed », ligne « failed » enregistrée', async () => {
    const t = make({ fw: fakeFirewall({ failAdd: 'in' }) })
    const r = await t.actions.handlers.block_ip({ ip: '192.168.1.50' })
    assert.equal(r.code, 'error')
    assert.equal(r.failed, true)
    assert.equal(t.client.tables.blocked_ips[0].status, 'failed')
  })

  checkAsync('déblocage : règle retirée, ligne passée à « released »', async () => {
    const t = make()
    await t.actions.handlers.block_ip({ ip: '192.168.1.50' })
    const r = await t.actions.handlers.unblock_ip({ ip: '192.168.1.50' })
    assert.deepEqual([r.code, r.recorded], ['unblocked', true])
    assert.equal(t.fw.rules.size, 0)
    assert.equal(t.client.tables.blocked_ips[0].status, 'released')
    assert.ok(t.client.tables.blocked_ips[0].released_at)
    assert.equal((await t.actions.handlers.unblock_ip({ ip: 'abc' })).reason, 'invalid_ip')
  })

  checkAsync('blocage sous Linux : refusé proprement, rien enregistré', async () => {
    const t = make({ platform: 'linux' })
    const r = await t.actions.handlers.block_ip({ ip: '192.168.1.50' })
    assert.deepEqual([r.code, r.reason], ['rejected', 'unsupported_os'])
    assert.equal(t.client.tables.blocked_ips.length, 0)
  })

  checkAsync('blocage automatique : désactivé par défaut ; seulement leurre (scan/login) ; marqué « auto »', async () => {
    const off = make()
    assert.equal(await off.actions.maybeAutoBlock({ type: 'honeypot_scan', ip: '192.168.1.50', title: 't' }), null)
    assert.equal(off.fw.rules.size, 0)

    const on = make({ client: fakeClient({ sensorRow: { id: 's1', auto_block: true, trusted_ips: null } }) })
    assert.equal(await on.actions.maybeAutoBlock({ type: 'honeypot_touch', ip: '192.168.1.50' }), null) // simple contact : trop ambigu
    assert.equal(await on.actions.maybeAutoBlock({ type: 'gateway_spoof', ip: '192.168.1.1' }), null)
    assert.equal(await on.actions.maybeAutoBlock({ type: 'mac_flood', ip: '192.168.1.60' }), null)
    const r = await on.actions.maybeAutoBlock({ type: 'honeypot_login', ip: '192.168.1.50', title: 'Tentative d\'intrusion' })
    assert.equal(r.code, 'blocked')
    assert.equal(on.client.tables.blocked_ips[0].blocked_by, 'auto')
    // même en automatique : jamais la passerelle ni le PC du capteur
    assert.equal((await on.actions.maybeAutoBlock({ type: 'honeypot_scan', ip: '192.168.1.1' })).reason, 'gateway')
  })

  checkAsync('blocage automatique : limite horaire', async () => {
    const t = make({ client: fakeClient({ sensorRow: { id: 's1', auto_block: true, trusted_ips: null } }) })
    let last
    for (let i = 0; i <= AUTO_BLOCK_MAX_PER_HOUR; i++) last = await t.actions.maybeAutoBlock({ type: 'honeypot_scan', ip: `192.168.2.${i + 1}` })
    assert.deepEqual([last.code, last.reason], ['rejected', 'rate_limit'])
    assert.equal(t.client.tables.blocked_ips.length, AUTO_BLOCK_MAX_PER_HOUR)
  })
}
