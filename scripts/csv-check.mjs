// Vérifications du générateur CSV (aucune dépendance) : node scripts/csv-check.mjs
import assert from 'node:assert/strict'
import { buildCsv, csvFile, escapeCell, isoDate, neutralizeCell } from '../src/lib/csv.js'
import { DATASETS, datasetCsv } from '../src/lib/exports.js'

let passed = 0
const failures = []

function check(name, fn) {
  try {
    fn()
    passed += 1
    console.log(`PASS  ${name}`)
  } catch (e) {
    failures.push(name)
    console.log(`FAIL  ${name}`)
    console.log(`      ${String(e.message).split('\n')[0]}`)
  }
}

// --- Échappement de base ---------------------------------------------------
check('accents conservés', () => {
  assert.equal(escapeCell('Réseau vérifié'), 'Réseau vérifié')
})

check('séparateur « ; » → cellule entre guillemets', () => {
  assert.equal(escapeCell('a;b'), '"a;b"')
})

check('virgule simple non citée (séparateur = ;)', () => {
  assert.equal(escapeCell('a,b'), 'a,b')
})

check('guillemet doublé et cellule citée', () => {
  assert.equal(escapeCell('a"b'), '"a""b"')
})

check('saut de ligne LF préservé et cité', () => {
  assert.equal(escapeCell('a\nb'), '"a\nb"')
})

check('saut de ligne CRLF préservé et cité', () => {
  assert.equal(escapeCell('a\r\nb'), '"a\r\nb"')
})

check('null et undefined → cellule vide', () => {
  assert.equal(escapeCell(null), '')
  assert.equal(escapeCell(undefined), '')
})

check('zéro réel exporté comme « 0 » (pas vide)', () => {
  assert.equal(escapeCell(0), '0')
})

check('espaces de début/fin préservés', () => {
  assert.equal(escapeCell('  x  '), '  x  ')
})

// --- Injection CSV ---------------------------------------------------------
for (const prefix of ['=', '+', '-', '@', '\t', '\r']) {
  check(`injection « ${JSON.stringify(prefix)} » neutralisée par apostrophe`, () => {
    assert.equal(neutralizeCell(`${prefix}cmd`), `'${prefix}cmd`)
  })
}

check('injection combinée à « ; » : apostrophe puis guillemets', () => {
  assert.equal(escapeCell('=1+1;x'), '"\'=1+1;x"')
})

check('cellule vide non préfixée', () => {
  assert.equal(neutralizeCell(''), '')
})

// --- Document complet -----------------------------------------------------
check('BOM UTF-8 présent exactement une fois', () => {
  const text = csvFile(['A'], [['1']])
  assert.equal(text[0], '\uFEFF')
  assert.equal([...text].filter((c) => c === '\uFEFF').length, 1)
})

check('csvFile = BOM + buildCsv', () => {
  const headers = ['A', 'B']
  const rows = [['1', '2']]
  assert.equal(csvFile(headers, rows), `\uFEFF${buildCsv(headers, rows)}`)
})

check('lignes terminées par CRLF, sans CRLF final', () => {
  assert.equal(buildCsv(['A', 'B'], [['1', '2'], ['3', '4']]), 'A;B\r\n1;2\r\n3;4')
})

check('en-tête contenant « ; » correctement cité', () => {
  assert.equal(buildCsv(['Libellé;'], []), '"Libellé;"')
})

// --- Dates -----------------------------------------------------------------
check('date ISO 8601 UTC', () => {
  assert.equal(isoDate('2026-03-04T05:06:07.000Z'), '2026-03-04T05:06:07.000Z')
})

check('date absente ou invalide → cellule vide', () => {
  assert.equal(isoDate(null), '')
  assert.equal(isoDate(''), '')
  assert.equal(isoDate('n/a'), '')
})

// --- Jeux de données -------------------------------------------------------
const devices = [
  { id: 2, name: 'Zeta', ip: '192.168.1.20', mac: 'aa:bb:cc:dd:ee:ff', type: 'Poste', status: 'on', last_seen: '2026-03-04T05:06:07.000Z' },
  { id: 1, name: 'Alpha', ip: '192.168.1.10', mac: null, type: 'Serveur', status: 'off', last_seen: null },
  { id: 3, name: 'Alpha', ip: '192.168.1.2', type: 'Serveur', status: 'un' },
]
const services = [
  { device_id: 1, port: 22, service: 'ssh' },
  { device_id: 1, port: 443, service: 'https' },
  { device_id: 99, port: 80, service: 'http' },
]
const alerts = [
  { id: 1, title: 'Ancienne', severity: 'h', status: null, detail: null, created_at: '2026-01-01T10:00:00.000Z' },
  { id: 2, title: 'Récente', severity: 'c', status: 'resolved', created_at: '2026-03-01T10:00:00.000Z', acknowledged_at: '2026-03-01T11:00:00.000Z', resolved_at: '2026-03-01T12:00:00.000Z' },
  { id: 3, title: 'Invalide', severity: 'l', status: 'ack', created_at: 'n/a' },
  { id: 4, title: 'Sans date', severity: 'm' },
]
const vulnerabilities = [
  { id: 1, title: 'CVE-2024-0001', severity: 'c', created_at: '2026-01-01T00:00:00.000Z' },
  { id: 2, title: 'CVE-2024-0002', severity: 'l', created_at: '2026-02-01T00:00:00.000Z' },
]
const threats = [
  { id: 1, category: 'scan', blocked: true, created_at: '2026-01-01T00:00:00.000Z' },
  { id: 2, category: 'inconnue', blocked: false, created_at: '2026-02-01T00:00:00.000Z' },
]

const byKind = (kind) => DATASETS.find((d) => d.kind === kind)

check('en-têtes français par jeu de données', () => {
  assert.deepEqual(byKind('devices').headers, ['Nom', 'Adresse IP', 'Adresse MAC', 'Type', 'Statut', 'Ports ouverts', 'Services', 'Dernier vu'])
  assert.deepEqual(byKind('alerts').headers, ['Titre', 'Gravité', 'Statut', 'Détail', 'Créée le', 'Prise en compte', 'Résolue'])
  assert.deepEqual(byKind('vulnerabilities').headers, ['Titre', 'Gravité'])
  assert.deepEqual(byKind('threats').headers, ['Catégorie', 'Bloquée', 'Date'])
})

check('appareils : nom puis IP, ports et services joints, orphelins ignorés', () => {
  const rows = byKind('devices').rows(devices, { services })
  assert.deepEqual(rows.map((r) => [r[0], r[1]]), [['Alpha', '192.168.1.10'], ['Alpha', '192.168.1.2'], ['Zeta', '192.168.1.20']])
  assert.deepEqual(rows[0].slice(3), ['Serveur', 'Hors ligne', '22, 443', 'ssh, https', ''])
  assert.equal(rows[1][5], '—')
  assert.equal(rows[1][6], '—')
  assert.equal(rows[2][3], 'Poste')
  assert.equal(rows[2][7], '2026-03-04T05:06:07.000Z')
})

check('appareils : ports multiples exportés sans casser le séparateur', () => {
  const text = csvFile(byKind('devices').headers, byKind('devices').rows(devices, { services }))
  assert.ok(text.includes('Alpha;192.168.1.10;;Serveur;Hors ligne;22, 443;ssh, https;'))
})

check('alertes : plus récent d’abord, dates invalides/absentes en fin', () => {
  const rows = byKind('alerts').rows(alerts)
  assert.deepEqual(rows.map((r) => r[0]), ['Récente', 'Ancienne', 'Invalide', 'Sans date'])
})

check('alertes : statut absent → « Ouverte », dates ISO ou vides', () => {
  const text = csvFile(byKind('alerts').headers, byKind('alerts').rows(alerts))
  const lines = text.slice(1).split('\r\n')
  assert.equal(lines[1], 'Récente;Critique;Résolue;;2026-03-01T10:00:00.000Z;2026-03-01T11:00:00.000Z;2026-03-01T12:00:00.000Z')
  assert.equal(lines[2], 'Ancienne;Haute;Ouverte;;2026-01-01T10:00:00.000Z;;')
  assert.equal(lines[3], 'Invalide;Basse;Prise en compte;;;;')
  assert.equal(lines[4], 'Sans date;Moyenne;Ouverte;;;;')
})

check('vulnérabilités : gravité traduite, plus récent d’abord', () => {
  const rows = byKind('vulnerabilities').rows(vulnerabilities)
  assert.deepEqual(rows[0], ['CVE-2024-0002', 'Basse'])
  assert.deepEqual(rows[1], ['CVE-2024-0001', 'Critique'])
})

check('menaces : catégorie traduite, bloquée Oui/Non, plus récent d’abord', () => {
  const rows = byKind('threats').rows(threats)
  assert.deepEqual(rows[0], ['inconnue', 'Non', '2026-02-01T00:00:00.000Z'])
  assert.deepEqual(rows[1], ['Scan de ports', 'Oui', '2026-01-01T00:00:00.000Z'])
})

check('injection depuis une donnée réseau neutralisée dans le fichier', () => {
  const rows = byKind('devices').rows([{ id: 5, name: '=HYPERLINK("http://x")', ip: '192.168.1.50', type: 'Poste', status: 'on' }])
  const text = csvFile(byKind('devices').headers, rows)
  assert.ok(text.includes(`'=HYPERLINK`))
})

check('datasetCsv : nom de fichier daté, BOM et nombre de lignes', () => {
  const { filename, text, rowCount } = datasetCsv('devices', devices, { services }, new Date('2026-03-04T05:06:07.000Z'))
  assert.equal(filename, 'cyberveylix-appareils-2026-03-04.csv')
  assert.equal(rowCount, 3)
  assert.equal(text[0], '\uFEFF')
  assert.equal(text.split('\r\n').length, 4)
})

check('datasetCsv : kind inconnu refusé', () => {
  assert.throws(() => datasetCsv('inconnu', []), /Jeu de données inconnu/)
})

console.log('')
if (failures.length) {
  console.log(`${failures.length} vérification(s) en échec : ${failures.join(', ')}`)
  process.exitCode = 1
} else {
  console.log(`${passed} vérifications réussies.`)
}
