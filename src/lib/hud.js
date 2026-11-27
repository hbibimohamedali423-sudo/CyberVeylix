// Indicateurs du tableau de bord « HUD » : calculés uniquement à partir des lignes enregistrées.
// Aucune valeur inventée : sans donnée, la fonction renvoie null (affiché « — »).
import { SENSITIVE_PORTS } from '../constants.js'
import { sensorState } from './findings.js'

const isOpenAlert = (a) => !a?.status || a.status === 'open'
const isOpenVuln = (v) => (v?.status || 'open') !== 'resolved'
const isSevere = (sev) => sev === 'c' || sev === 'h'
const ratio = (n, total) => (total > 0 ? Math.round((n / total) * 100) : null)

// Appareil « protégé » : aucune vulnérabilité critique/haute non corrigée sur lui,
// et aucune alerte ouverte dont l'adresse source est la sienne.
export function deviceAtRisk(device, vulns = [], alerts = []) {
  if (!device) return false
  const vulnRisk = vulns.some((v) => v.device_id === device.id && isOpenVuln(v) && isSevere(v.severity))
  const alertRisk = Boolean(device.ip) && alerts.some((a) => isOpenAlert(a) && a.source_ip === device.ip)
  return vulnRisk || alertRisk
}

export function securityLevel(devices = [], vulns = [], alerts = []) {
  const total = devices.length
  const safe = devices.filter((d) => !deviceAtRisk(d, vulns, alerts)).length
  return { safe, total, pct: ratio(safe, total) }
}

// Les quatre jauges en pourcentage.
export function gauges({ devices = [], vulns = [], alerts = [], sensors = [] } = {}, now = Date.now()) {
  const treated = alerts.filter((a) => a.status === 'ack' || a.status === 'resolved').length
  const fixed = vulns.filter((v) => v.status === 'resolved').length
  const online = devices.filter((d) => d.status === 'on').length
  const running = sensors.filter((s) => sensorState(s, now).state === 'running').length
  return [
    { key: 'alertsTreated', n: treated, total: alerts.length, pct: ratio(treated, alerts.length) },
    { key: 'vulnsFixed', n: fixed, total: vulns.length, pct: ratio(fixed, vulns.length) },
    { key: 'devicesOnline', n: online, total: devices.length, pct: ratio(online, devices.length) },
    { key: 'sensorsRunning', n: running, total: sensors.length, pct: ratio(running, sensors.length) },
  ]
}

// Couleur d'état d'une jauge : vert ≥ 80 %, orange ≥ 50 %, rouge en dessous.
export const levelOf = (pct) => (pct === null || pct === undefined ? 'none' : pct >= 80 ? 'good' : pct >= 50 ? 'warn' : 'bad')

// Alerte à mettre en avant : la plus récente parmi les ouvertes, les critiques/hautes d'abord.
export function headlineAlert(alerts = []) {
  const open = alerts.filter(isOpenAlert)
  const time = (a) => new Date(a.created_at || 0).getTime()
  const pick = (list) => list.reduce((best, a) => (!best || time(a) > time(best) ? a : best), null)
  return pick(open.filter((a) => isSevere(a.severity))) || pick(open)
}

export const openAlerts = (alerts = [], limit = 5) =>
  alerts.filter(isOpenAlert).sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0)).slice(0, limit)

export function pendingFixes(vulns = []) {
  const open = vulns.filter(isOpenVuln)
  return { total: open.length, c: open.filter((v) => v.severity === 'c').length, h: open.filter((v) => v.severity === 'h').length, m: open.filter((v) => v.severity === 'm').length, l: open.filter((v) => v.severity === 'l').length }
}

// Ports ouverts : nombre d'appareils par port, ports sensibles signalés.
const RISKY = new Set([...SENSITIVE_PORTS, 445, 139, 135, 161, 1883])
export function portMatrix(services = [], limit = 18) {
  const byPort = new Map()
  for (const s of services) {
    if (!Number.isInteger(s?.port)) continue
    const set = byPort.get(s.port) || new Set()
    set.add(s.device_id)
    byPort.set(s.port, set)
  }
  return [...byPort.entries()]
    .map(([port, set]) => ({ port, devices: set.size, risky: RISKY.has(port) }))
    .sort((a, b) => Number(b.risky) - Number(a.risky) || b.devices - a.devices || a.port - b.port)
    .slice(0, limit)
}

export function lastScanAt(sensors = [], devices = []) {
  const times = [...sensors.map((s) => s.last_scan_at), ...devices.map((d) => d.last_seen)]
    .map((v) => (v ? new Date(v).getTime() : NaN)).filter(Number.isFinite)
  return times.length ? Math.max(...times) : null
}

// Inventaire résumé : appareils à risque d'abord, puis les plus récemment vus.
export function inventory(devices = [], vulns = [], alerts = [], limit = 6) {
  const seen = (d) => (d.last_seen ? new Date(d.last_seen).getTime() : 0)
  return devices
    .map((d) => ({ ...d, atRisk: deviceAtRisk(d, vulns, alerts) }))
    .sort((a, b) => Number(b.atRisk) - Number(a.atRisk) || seen(b) - seen(a))
    .slice(0, limit)
}

// Position stable d'un appareil sur le radar : angle tiré de son identifiant,
// distance au centre selon l'ancienneté de son dernier passage (récent = proche).
export function radarPoint(device, now = Date.now()) {
  const id = String(device?.id || device?.ip || device?.name || '')
  let h = 0
  for (const ch of id) h = (h * 31 + ch.charCodeAt(0)) >>> 0
  // Mélange des bits : des identifiants proches (« d1 », « d2 ») donnent des angles bien séparés.
  h = Math.imul(h ^ (h >>> 16), 0x45d9f3b) >>> 0
  h = Math.imul(h ^ (h >>> 16), 0x45d9f3b) >>> 0
  const angle = (h % 360) * (Math.PI / 180)
  const age = device?.last_seen ? Math.max(0, now - new Date(device.last_seen).getTime()) : Infinity
  // Un léger écart tiré de l'identifiant évite que les appareils vus à la même minute se superposent.
  const spread = ((h >>> 9) % 100) / 100
  const r = age === Infinity ? 0.95 : Math.min(0.92, 0.3 + spread * 0.35 + Math.min(1, age / (24 * 3600 * 1000)) * 0.27)
  return { x: Math.cos(angle) * r, y: Math.sin(angle) * r }
}
