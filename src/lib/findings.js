// Logique pure de R3 (aucun JSX, aucun DOM) : testable via scripts/r3-check.mjs.

// Identifiant CVE valide (ex. CVE-2024-6387) : seul format transformé en lien.
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/
export const isCve = (v) => typeof v === 'string' && CVE_RE.test(v.trim().toUpperCase())
export const cveUrl = (v) => (isCve(v) ? `https://nvd.nist.gov/vuln/detail/${v.trim().toUpperCase()}` : null)

// Liste des CVE d'une ligne : colonne cves (tableau) ; rien d'autre n'est déduit.
export const cvesOf = (row) => (Array.isArray(row?.cves) ? row.cves.filter((c) => typeof c === 'string' && c.trim()) : [])

// Origine d'une ligne : la colonne vaut « manual » par défaut, null reste « manual ».
export const sourceOf = (row) => row?.source || 'manual'

// Le capteur envoie son pouls toutes les 5 minutes : au-delà de 15 minutes sans pouls, il est arrêté.
export const SENSOR_STALE_MS = 15 * 60 * 1000
export function sensorState(sensor, now = Date.now()) {
  const t = sensor?.last_heartbeat ? new Date(sensor.last_heartbeat).getTime() : NaN
  if (!Number.isFinite(t)) return { state: 'never', since: null }
  if (now - t <= SENSOR_STALE_MS) return { state: 'running', since: sensor.started_at || null }
  return { state: 'stopped', since: sensor.last_heartbeat }
}

// Table absente (schema_r1_results.sql pas encore exécuté) : message PostgREST correspondant.
export const isMissingTableMessage = (msg) => /could not find the table|relation .* does not exist|schema cache/i.test(msg || '')

// Résultat d'une commande du capteur : JSON { code, ... } écrit par sensor/lib/commands.mjs.
// Texte non JSON (ancienne version, saisie à la main) : code « raw », affiché tel quel.
export function parseCommandResult(text) {
  if (text === null || text === undefined || text === '') return null
  try {
    const v = JSON.parse(text)
    if (v && typeof v === 'object' && !Array.isArray(v) && typeof v.code === 'string') return v
  } catch { /* texte libre */ }
  return { code: 'raw', message: String(text).slice(0, 300) }
}

// Une demande est « active » tant que le capteur ne l'a pas terminée.
export const isActiveCommand = (c) => c?.status === 'pending' || c?.status === 'running'

// Capteur qui exécutera un blocage pour cette alerte : en service, de préférence sur le réseau de l'alerte.
export function pickSensorFor(alert, sensors, now = Date.now()) {
  const running = (sensors || []).filter((s) => sensorState(s, now).state === 'running')
  return running.find((s) => alert?.network_id && s.network_id === alert.network_id) || running[0] || null
}

// État du blocage d'une adresse : « blocked » (règle active), « pending » (demande en attente du capteur), « none ».
export function blockState(ip, blocked = [], commands = []) {
  if (!ip) return 'none'
  if (blocked.some((b) => b.ip === ip && b.status === 'active')) return 'blocked'
  if (commands.some((c) => (c.kind === 'block_ip' || c.kind === 'unblock_ip') && isActiveCommand(c) && c.params?.ip === ip)) return 'pending'
  return 'none'
}

// Correction possible pour une faiblesse de CE PC (audit local du capteur, clé « local:<pc>:<id> »).
// Même nettoyage du nom de PC que sensor/lib/fixes.mjs (hostKey).
export const hostKey = (name) => String(name || 'pc').toLowerCase().replace(/[^a-z0-9._-]/g, '-').slice(0, 63)
export const FIX_IDS = ['smbv1', 'rdp_nla', 'telnet']
export function localFixOf(vuln) {
  const m = /^local:([a-z0-9._-]+):([a-z0-9_]+)$/.exec(vuln?.finding_key || '')
  return m && FIX_IDS.includes(m[2]) ? { host: m[1], id: m[2] } : null
}
// Capteur qui a détecté la faiblesse (c'est lui, et lui seul, qui peut la corriger).
export const fixSensorFor = (vuln, sensors = []) => {
  const fix = localFixOf(vuln)
  return fix ? sensors.find((s) => hostKey(s.name) === fix.host) || null : null
}

// Journal de la page « Surveillance (SOC) » : uniquement des événements ENREGISTRÉS (alertes, faiblesses,
// demandes au capteur, blocages), du plus récent au plus ancien. Rien n'est déduit ni inventé.
const tsOf = (v) => { const n = v ? new Date(v).getTime() : NaN; return Number.isFinite(n) ? n : null }
export const TIMELINE_GROUPS = { alert: 'alerts', vuln_new: 'vulns', vuln_resolved: 'vulns', command: 'actions', block: 'actions', unblock: 'actions' }
export function buildTimeline({ alerts = [], vulns = [], commands = [], blocked = [] } = {}, limit = 200) {
  const items = []
  const push = (type, at, row) => { const ts = tsOf(at); if (ts !== null) items.push({ id: `${type}:${row.id}`, type, at, ts, row }) }
  for (const a of alerts) push('alert', a.created_at, a)
  for (const v of vulns) {
    push('vuln_new', v.created_at, v)
    if ((v.status || 'open') === 'resolved' && v.resolved_at) push('vuln_resolved', v.resolved_at, v)
  }
  for (const c of commands) push('command', c.created_at, c)
  for (const b of blocked) {
    if (b.status !== 'failed') push('block', b.blocked_at, b)
    if (b.status === 'released' && b.released_at) push('unblock', b.released_at, b)
  }
  return items.sort((x, y) => y.ts - x.ts).slice(0, limit)
}

// Liste « ne jamais bloquer » saisie dans « Paramètres » : IPv4 valides, sans doublon, 100 au plus.
const IPV4 = /^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$/
export function parseIpList(text) {
  const parts = String(text || '').split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean)
  const invalid = parts.filter((p) => !IPV4.test(p))
  const ips = [...new Set(parts.filter((p) => IPV4.test(p)))]
  return { ips, invalid, tooMany: ips.length > 100 }
}

// Événements enregistrés par heure sur les `hours` dernières heures (le plus ancien d'abord), pour « Activité ».
export function hourlyCounts(rows = [], now = Date.now(), hours = 24) {
  const HOUR = 3600000
  const end = Math.floor(now / HOUR) * HOUR + HOUR // fin de l'heure en cours
  const start = end - hours * HOUR
  const buckets = Array.from({ length: hours }, (_, i) => ({ at: start + i * HOUR, n: 0 }))
  for (const r of rows) {
    const ts = r && r.created_at ? Date.parse(r.created_at) : NaN
    if (!Number.isFinite(ts) || ts < start || ts >= end) continue
    buckets[Math.floor((ts - start) / HOUR)].n += 1
  }
  return buckets
}

// Recherche globale (barre du haut) : appareils, alertes, vulnérabilités ; 8 résultats au plus.
export function searchAll({ devices = [], alerts = [], vulns = [] } = {}, query = '', limit = 8) {
  const q = String(query).trim().toLowerCase()
  if (q.length < 2) return []
  const has = (...vals) => vals.some((v) => v !== null && v !== undefined && String(v).toLowerCase().includes(q))
  const out = []
  for (const d of devices) if (has(d.name, d.ip, d.mac, d.vendor, d.hostname)) out.push({ kind: 'device', id: d.id, label: d.name, sub: d.ip || d.mac || '' })
  for (const a of alerts) if (has(a.title, a.source_ip, a.source_mac, a.detail)) out.push({ kind: 'alert', id: a.id, label: a.title, sub: a.source_ip || '' })
  for (const v of vulns) if (has(v.title, ...(Array.isArray(v.cves) ? v.cves : []))) out.push({ kind: 'vuln', id: v.id, label: v.title, sub: (v.cves || [])[0] || '' })
  return out.slice(0, limit)
}
