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
