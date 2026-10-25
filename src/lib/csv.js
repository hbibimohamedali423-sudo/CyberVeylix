// Construction CSV côté client : séparateur « ; », BOM UTF-8, échappement strict
// et neutralisation des formules (injection CSV). Aucun accès DOM ici sauf downloadCsv.

// Un tableur interprète ces préfixes comme une formule : on les neutralise par une apostrophe.
const RISKY_FIRST = ['=', '+', '-', '@', '\t', '\r']

export function neutralizeCell(value) {
  const s = value === null || value === undefined ? '' : String(value)
  return s !== '' && RISKY_FIRST.includes(s[0]) ? `'${s}` : s
}

export function escapeCell(value) {
  const s = neutralizeCell(value)
  return /[;"\r\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s
}

// Retourne le CSV sans BOM, lignes terminées par CRLF, sans CRLF final.
export function buildCsv(headers, rows) {
  return [headers, ...rows].map((row) => row.map(escapeCell).join(';')).join('\r\n')
}

// Fichier complet prêt à télécharger : BOM UTF-8 puis contenu.
export function csvFile(headers, rows) {
  return `\uFEFF${buildCsv(headers, rows)}`
}

// Date ISO 8601 UTC pour tous les exports ; cellule vide si absente ou invalide.
export function isoDate(value) {
  const t = value ? new Date(value).getTime() : NaN
  return Number.isFinite(t) ? new Date(t).toISOString() : ''
}

export function downloadCsv(filename, text) {
  const blob = new Blob([text], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
  return filename
}
