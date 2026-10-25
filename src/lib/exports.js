// Définition des jeux de données exportables en CSV.
// Pur (aucun JSX, aucun DOM) pour rester testable via scripts/csv-check.mjs.
import { ALERT_STATUS, CATS, REPORTS_KINDS, SEV, STATUS } from '../constants.js'
import { csvFile, isoDate } from './csv.js'

const labelOf = (list, k) => list.find((x) => x.k === k)?.label
const kindLabel = (kind) => REPORTS_KINDS.find((x) => x.k === kind)?.label || kind

const time = (v) => {
  if (!v) return null
  const t = new Date(v).getTime()
  return Number.isFinite(t) ? t : null
}
// Tri décroissant par created_at, dates absentes/invalides en fin de liste.
const newestFirst = (a, b) => {
  const ta = time(a.created_at)
  const tb = time(b.created_at)
  if (ta === null && tb === null) return 0
  if (ta === null) return 1
  if (tb === null) return -1
  return tb - ta
}
const byNameThenIp = (a, b) => (a.name || '').localeCompare(b.name || '', 'fr') || (a.ip || '').localeCompare(b.ip || '', 'fr')

const servicesOf = (device, services) => services.filter((s) => s.device_id === device.id)
const joined = (list, value) => list.map(value).filter((v) => v !== null && v !== undefined && v !== '').join(', ') || '—'

export const DATASETS = [
  {
    kind: 'devices',
    label: kindLabel('devices'),
    prefix: 'cyberveylix-appareils',
    headers: ['Nom', 'Adresse IP', 'Adresse MAC', 'Type', 'Statut', 'Ports ouverts', 'Services', 'Dernier vu'],
    rows: (rows, { services = [] } = {}) => rows.slice().sort(byNameThenIp).map((d) => {
      const svc = servicesOf(d, services)
      return [
        d.name,
        d.ip,
        d.mac,
        // Le type stocké est déjà le libellé français (clé de TYPES).
        d.type,
        labelOf(STATUS, d.status) || d.status,
        joined(svc, (s) => s.port),
        joined(svc, (s) => s.service),
        isoDate(d.last_seen),
      ]
    }),
  },
  {
    kind: 'alerts',
    label: kindLabel('alerts'),
    prefix: 'cyberveylix-alertes',
    headers: ['Titre', 'Gravité', 'Statut', 'Détail', 'Créée le', 'Prise en compte', 'Résolue'],
    rows: (rows) => rows.slice().sort(newestFirst).map((a) => [
      a.title,
      labelOf(SEV, a.severity) || a.severity,
      labelOf(ALERT_STATUS, a.status || 'open') || a.status || 'open',
      a.detail,
      isoDate(a.created_at),
      isoDate(a.acknowledged_at),
      isoDate(a.resolved_at),
    ]),
  },
  {
    kind: 'vulnerabilities',
    label: kindLabel('vulnerabilities'),
    prefix: 'cyberveylix-vulnerabilites',
    headers: ['Titre', 'Gravité'],
    rows: (rows) => rows.slice().sort(newestFirst).map((v) => [
      v.title,
      labelOf(SEV, v.severity) || v.severity,
    ]),
  },
  {
    kind: 'threats',
    label: kindLabel('threats'),
    prefix: 'cyberveylix-menaces',
    headers: ['Catégorie', 'Bloquée', 'Date'],
    rows: (rows) => rows.slice().sort(newestFirst).map((t) => [
      labelOf(CATS, t.category) || t.category,
      t.blocked ? 'Oui' : 'Non',
      isoDate(t.created_at),
    ]),
  },
]

// Fichier complet pour un jeu de données : nom daté (UTC) et contenu avec BOM.
export function datasetCsv(kind, rows, extra = {}, now = new Date()) {
  const dataset = DATASETS.find((d) => d.kind === kind)
  if (!dataset) throw new Error(`Jeu de données inconnu : ${kind}`)
  const filename = `${dataset.prefix}-${now.toISOString().slice(0, 10)}.csv`
  return { filename, text: csvFile(dataset.headers, dataset.rows(rows, extra)), rowCount: rows.length }
}
