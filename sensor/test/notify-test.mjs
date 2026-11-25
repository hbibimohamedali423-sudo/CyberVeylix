// Tests des alertes Telegram : configuration, message, regroupement, limite, jeton jamais journalisé.
import assert from 'node:assert/strict'
import { parseNotifyConfig, formatMessage, createNotifier } from '../lib/notify.mjs'

const TOKEN = '123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw1'
const CFG = { telegram: { token: TOKEN, chatId: '987654321' }, minSeverity: 'h' }

function fakeFetch({ ok = true, throwMsg = null } = {}) {
  const calls = []
  const fn = async (url, init) => {
    calls.push({ url, body: JSON.parse(init.body) })
    if (throwMsg) throw new Error(throwMsg)
    return { ok, status: ok ? 200 : 401, json: async () => (ok ? { ok: true } : { ok: false, description: 'Unauthorized' }) }
  }
  return { fn, calls }
}
const ev = (severity, title, ip = null) => ({ severity, title, detail: `détail ${title}`, ip })

export function notifyChecks(check, checkAsync) {
  check('notify.json : jeton et conversation validés ; gravité minimale par défaut « haute »', () => {
    const ok = parseNotifyConfig(JSON.stringify({ telegram: { token: TOKEN, chatId: 987654321 } }))
    assert.deepEqual(ok.config, { telegram: { token: TOKEN, chatId: '987654321' }, minSeverity: 'h' })
    assert.equal(parseNotifyConfig(JSON.stringify({ telegram: { token: TOKEN, chatId: '-1001234567' }, minSeverity: 'c' })).config.minSeverity, 'c')
    assert.ok(parseNotifyConfig(JSON.stringify({ telegram: { token: 'abc', chatId: '1' } })).error)
    assert.ok(parseNotifyConfig(JSON.stringify({ telegram: { token: TOKEN, chatId: 'x y' } })).error)
    assert.ok(parseNotifyConfig('{').error)
    const err = parseNotifyConfig(JSON.stringify({ telegram: { token: TOKEN + '!', chatId: '1' } })).error
    assert.ok(err && !err.includes(TOKEN))
  })

  check('message : client, appareil, gravité ; borné', () => {
    const m = formatMessage([ev('c', 'Usurpation de la passerelle', '10.15.0.1')], { client: 'Meridiana', host: 'PC-1' })
    assert.ok(m.includes('Meridiana') && m.includes('CRITIQUE') && m.includes('10.15.0.1'))
    const many = formatMessage(Array.from({ length: 15 }, (_, i) => ev('h', `A${i}`)))
    assert.ok(many.includes('et 5 autre(s)'))
    assert.ok(formatMessage([ev('c', 'x'.repeat(10000))]).length <= 3500)
  })

  checkAsync('envoi : alertes importantes regroupées en un message ; moyennes et basses ignorées', async () => {
    const f = fakeFetch()
    const n = createNotifier({ config: CFG, client: 'Meridiana', fetchImpl: f.fn, log: () => {}, batchMs: 5 })
    n.notify([ev('m', 'Nouvel appareil'), ev('l', 'info')])
    n.notify([ev('c', 'Balayage de ports', '10.15.4.9'), ev('h', 'Tentative de connexion')])
    await new Promise((r) => setTimeout(r, 30))
    assert.equal(f.calls.length, 1)
    assert.ok(f.calls[0].url.endsWith(`/bot${TOKEN}/sendMessage`))
    assert.equal(f.calls[0].body.chat_id, '987654321')
    assert.ok(f.calls[0].body.text.includes('Balayage de ports') && f.calls[0].body.text.includes('Tentative de connexion'))
    assert.ok(!f.calls[0].body.text.includes('Nouvel appareil'))
  })

  checkAsync('envoi : limite par heure respectée', async () => {
    const f = fakeFetch()
    let t = 0
    const n = createNotifier({ config: CFG, fetchImpl: f.fn, log: () => {}, now: () => t, maxPerHour: 3 })
    for (let i = 0; i < 5; i++) await n.sendText(`m${i}`)
    assert.equal(f.calls.length, 3)
    t = 3600001
    await n.sendText('après une heure')
    assert.equal(f.calls.length, 4)
  })

  checkAsync('envoi : erreurs journalisées SANS le jeton du bot', async () => {
    const logs = []
    const a = createNotifier({ config: CFG, fetchImpl: fakeFetch({ throwMsg: `connect ECONNREFUSED api.telegram.org/bot${TOKEN}` }).fn, log: (m) => logs.push(m) })
    assert.equal(await a.sendText('x'), false)
    const b = createNotifier({ config: CFG, fetchImpl: fakeFetch({ ok: false }).fn, log: (m) => logs.push(m) })
    assert.equal(await b.sendText('x'), false)
    assert.equal(logs.length, 2)
    assert.ok(logs.every((l) => !l.includes(TOKEN)))
  })
}
