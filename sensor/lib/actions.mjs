// CyberVeylix Sensor — actions déclenchées par la page web (blocage / déblocage) et blocage automatique.
// Le résultat de chaque action est un objet { code, ... } traduit par la page. La table blocked_ips
// est écrite ICI, par le capteur, qui connaît le vrai résultat du pare-feu (la page n'y écrit jamais).
import { protectedReason, isValidIpv4 } from './blocker.mjs'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const SETTINGS_TTL_MS = 30 * 1000
// Seuls ces événements désignent sans ambiguïté l'appareil fautif (connexion TCP réelle vers un leurre).
export const AUTO_BLOCK_TYPES = ['honeypot_scan', 'honeypot_login']
export const AUTO_BLOCK_MAX_PER_HOUR = 20

// context() → { gatewayIp, sensorIp, dhcp: [ip] } ; serviceIps() → Promise<[ip]> (adresses à ne jamais couper).
export function createActions({ client, getSensorId, blocker, context, serviceIps = async () => [], log = console.log, now = () => new Date() }) {
  let settings = { autoBlock: false, trusted: [] }
  let settingsAt = 0
  let autoCount = 0
  let autoHour = 0

  async function loadSettings(force = false) {
    if (!force && now().getTime() - settingsAt < SETTINGS_TTL_MS) return settings
    const id = await getSensorId()
    if (!id) return settings
    const { data, error } = await client.from('sensors').select('auto_block,trusted_ips').eq('id', id)
    if (!error && data && data.length) {
      settings = {
        autoBlock: data[0].auto_block === true,
        trusted: (data[0].trusted_ips || []).filter(isValidIpv4),
      }
      settingsAt = now().getTime()
    }
    return settings
  }

  async function record(sensorId, ip, fields) {
    try {
      const found = await client.from('blocked_ips').select('id').eq('sensor_id', sensorId).eq('ip', ip).eq('status', 'active')
      if (found.data && found.data.length && fields.status === 'active') {
        const r = await client.from('blocked_ips').update({ reason: fields.reason, blocked_by: fields.blocked_by }).eq('id', found.data[0].id)
        return !r.error
      }
      if (fields.status === 'released') {
        const r = await client.from('blocked_ips').update({ status: 'released', released_at: now().toISOString() })
          .eq('sensor_id', sensorId).eq('ip', ip).eq('status', 'active')
        return !r.error
      }
      const r = await client.from('blocked_ips').insert({ sensor_id: sensorId, ip, ...fields })
      return !r.error
    } catch (e) {
      log('⚠ Liste des adresses bloquées non mise à jour : ' + (e && e.message))
      return false
    }
  }

  async function blockIp(params = {}, by = null) {
    const ip = String(params.ip || '')
    const s = await loadSettings()
    const ctx = context()
    const why = protectedReason(ip, { ...ctx, trusted: s.trusted, serviceIps: await serviceIps() })
    if (why) { log(`Blocage refusé (${why}) : ${ip}`); return { code: 'rejected', reason: why, ip } }

    const res = await blocker.block(ip)
    const sensorId = await getSensorId()
    const reason = typeof params.reason === 'string' ? params.reason.slice(0, 500) : null
    const blocked_by = (by || params.by) === 'auto' ? 'auto' : 'manual'
    const alert_id = typeof params.alert_id === 'string' && UUID_RE.test(params.alert_id) ? params.alert_id : null

    if (!res.ok) {
      if (res.code === 'unsupported_os') return { code: 'rejected', reason: 'unsupported_os', ip }
      if (sensorId) await record(sensorId, ip, { reason, alert_id, blocked_by, status: 'failed', error: String(res.message || res.code).slice(0, 1000) })
      log(`⚠ Blocage de ${ip} impossible : ${res.message || res.code}`)
      return { code: 'error', failed: true, message: res.message || res.code, ip }
    }
    const recorded = sensorId ? await record(sensorId, ip, { reason, alert_id, blocked_by, status: 'active' }) : false
    log(`✔ Adresse bloquée dans le pare-feu de ce PC : ${ip}${res.already ? ' (déjà bloquée)' : ''}`)
    return { code: 'blocked', ip, already: Boolean(res.already), recorded }
  }

  async function unblockIp(params = {}) {
    const ip = String(params.ip || '')
    if (!isValidIpv4(ip)) return { code: 'rejected', reason: 'invalid_ip', ip }
    const res = await blocker.unblock(ip)
    if (!res.ok) {
      if (res.code === 'unsupported_os') return { code: 'rejected', reason: 'unsupported_os', ip }
      return { code: 'error', failed: true, message: res.message || res.code, ip }
    }
    const sensorId = await getSensorId()
    const recorded = sensorId ? await record(sensorId, ip, { status: 'released' }) : false
    log(`✔ Adresse débloquée : ${ip}`)
    return { code: 'unblocked', ip, recorded }
  }

  // Blocage automatique (réglage auto_block du capteur, désactivé par défaut) : seulement les événements
  // de leurre, au plus AUTO_BLOCK_MAX_PER_HOUR par heure, avec les mêmes garde-fous que le blocage manuel.
  async function maybeAutoBlock(event) {
    if (!event || !AUTO_BLOCK_TYPES.includes(event.type) || !event.ip) return null
    const s = await loadSettings()
    if (!s.autoBlock) return null
    const hour = Math.floor(now().getTime() / 3600000)
    if (hour !== autoHour) { autoHour = hour; autoCount = 0 }
    if (autoCount >= AUTO_BLOCK_MAX_PER_HOUR) { log('Blocage automatique : limite horaire atteinte.'); return { code: 'rejected', reason: 'rate_limit', ip: event.ip } }
    autoCount += 1
    return blockIp({ ip: event.ip, reason: String(event.title || 'Blocage automatique').slice(0, 200) }, 'auto')
  }

  return { handlers: { block_ip: (p) => blockIp(p), unblock_ip: (p) => unblockIp(p) }, blockIp, unblockIp, maybeAutoBlock, loadSettings }
}
