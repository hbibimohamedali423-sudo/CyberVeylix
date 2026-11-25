// CyberVeylix Sensor — alertes instantanées sur Telegram (fichier local notify.json du dossier de données).
// - Seules les alertes importantes (gravité ≥ minSeverity, « haute » par défaut) sont envoyées.
// - Regroupées (une fenêtre de 10 s = un message) et limitées (30 messages par heure au plus) : jamais d'inondation.
// - Le jeton du bot ne quitte pas ce PC : ni base, ni page, ni journal (il est masqué dans tout message d'erreur).

export const TOKEN_RE = /^\d{5,15}:[A-Za-z0-9_-]{30,64}$/
const CHAT_RE = /^(-?\d{1,20}|@[A-Za-z0-9_]{5,64})$/
const RANK = { c: 4, h: 3, m: 2, l: 1 }
const ICON = { c: '🔴', h: '🟠', m: '🟡', l: '⚪' }
const LABEL = { c: 'CRITIQUE', h: 'HAUTE', m: 'MOYENNE', l: 'BASSE' }

export function parseNotifyConfig(text) {
  let raw
  try { raw = JSON.parse(String(text).replace(/^﻿/, '')) } catch { return { error: 'notify.json illisible (JSON invalide).' } }
  const tg = raw && raw.telegram
  if (!tg || typeof tg !== 'object') return { error: 'notify.json : section « telegram » attendue.' }
  if (typeof tg.token !== 'string' || !TOKEN_RE.test(tg.token)) return { error: 'notify.json : jeton du bot Telegram invalide.' }
  const chatId = String(tg.chatId ?? '').trim()
  if (!CHAT_RE.test(chatId)) return { error: 'notify.json : identifiant de conversation (chatId) invalide.' }
  const minSeverity = Object.hasOwn(RANK, raw.minSeverity) ? raw.minSeverity : 'h'
  return { config: { telegram: { token: tg.token, chatId }, minSeverity } }
}

// Texte du message (texte brut, sans mise en forme interprétée), borné à 3500 caractères.
export function formatMessage(events, { client = '', host = '' } = {}) {
  const head = `🛡 CyberVeylix${client ? ` — ${client}` : ''}${host ? ` (${host})` : ''}`
  const lines = events.slice(0, 10).map((e) => {
    const who = e.ip ? `\n   Appareil : ${e.ip}${e.mac ? ` (${e.mac})` : ''}` : (e.mac ? `\n   Appareil : ${e.mac}` : '')
    return `${ICON[e.severity] || '•'} ${LABEL[e.severity] || ''} — ${String(e.title || '').slice(0, 150)}${who}\n   ${String(e.detail || '').slice(0, 300)}`
  })
  const more = events.length > 10 ? `\n… et ${events.length - 10} autre(s) alerte(s) : voir le tableau de bord.` : ''
  return `${head}\n\n${lines.join('\n\n')}${more}`.slice(0, 3500)
}

export function createNotifier({ config, client = '', host = '', fetchImpl = globalThis.fetch, log = console.log, now = () => Date.now(), batchMs = 10000, maxPerHour = 30 }) {
  const { token, chatId } = config.telegram
  const hide = (s) => String(s || '').split(token).join('***')
  let queue = []
  let timer = null
  let sentAt = []
  let dropped = 0

  async function send(text) {
    const t = now()
    sentAt = sentAt.filter((x) => t - x < 3600000)
    if (sentAt.length >= maxPerHour) { dropped += 1; return false }
    sentAt.push(t)
    try {
      const res = await fetchImpl(`https://api.telegram.org/bot${token}/sendMessage`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, text, disable_web_page_preview: true }),
        signal: AbortSignal.timeout ? AbortSignal.timeout(15000) : undefined,
      })
      const body = await res.json().catch(() => ({}))
      if (!res.ok || !body.ok) { log(`⚠ Telegram : envoi refusé (${res.status}${body.description ? ` : ${hide(body.description)}` : ''}).`); return false }
      return true
    } catch (e) {
      log('⚠ Telegram : envoi impossible (' + hide(e && e.message) + ').')
      return false
    }
  }

  async function flush() {
    timer = null
    const batch = queue
    queue = []
    if (!batch.length) return
    let text = formatMessage(batch, { client, host })
    if (dropped) { text += `\n\n(${dropped} message(s) non envoyé(s) : limite de ${maxPerHour} par heure atteinte)`; dropped = 0 }
    await send(text)
  }

  function notify(events = []) {
    const min = RANK[config.minSeverity] || RANK.h
    const keep = events.filter((e) => (RANK[e.severity] || 0) >= min)
    if (!keep.length) return
    queue.push(...keep)
    if (!timer) { timer = setTimeout(flush, batchMs); timer.unref?.() }
  }

  return { notify, flush, send, sendText: (text) => send(String(text).slice(0, 3500)) }
}
