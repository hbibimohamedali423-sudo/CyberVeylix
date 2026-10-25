// Vérifications du catalogue i18n (aucune dépendance) : node scripts/i18n-check.mjs
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { LANGS, MESSAGES, DEFAULT_LANG, STORAGE_KEY, translate, dirOf, localeOf, isSupported } from '../src/i18n/messages.js'

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

const flatten = (obj, prefix = '') => Object.entries(obj).flatMap(([k, v]) => {
  const key = prefix ? `${prefix}.${k}` : k
  return v && typeof v === 'object' ? flatten(v, key) : [[key, v]]
})
const keysOf = (lang) => flatten(MESSAGES[lang]).map(([k]) => k).sort()
const dict = Object.fromEntries(LANGS.map((l) => [l.code, Object.fromEntries(flatten(MESSAGES[l.code]))]))
const varsOf = (s) => [...String(s).matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]).sort().join(',')

check('langues attendues : fr, en, de, ar, it', () => {
  assert.deepEqual(LANGS.map((l) => l.code).sort(), ['ar', 'de', 'en', 'fr', 'it'])
})

check('français par défaut', () => {
  assert.equal(DEFAULT_LANG, 'fr')
  assert.equal(STORAGE_KEY, 'cyberveylix.lang')
})

check('arabe en RTL, autres langues en LTR', () => {
  assert.equal(dirOf('ar'), 'rtl')
  for (const code of ['fr', 'en', 'de', 'it']) assert.equal(dirOf(code), 'ltr')
})

check('locale de date définie pour chaque langue', () => {
  for (const l of LANGS) {
    assert.ok(l.locale && l.locale.length >= 2, l.code)
    assert.equal(localeOf(l.code), l.locale)
  }
})

check('mêmes clés dans toutes les langues que le français', () => {
  const ref = keysOf('fr')
  for (const l of LANGS) assert.deepEqual(keysOf(l.code), ref, l.code)
})

check('aucune traduction vide', () => {
  for (const [key, value] of Object.entries(dict.fr)) {
    for (const l of LANGS) {
      assert.equal(typeof dict[l.code][key], 'string', `${l.code}:${key}`)
      assert.ok(dict[l.code][key].trim().length > 0, `${l.code}:${key}`)
    }
  }
})

check('mêmes variables {{…}} que le français pour chaque clé', () => {
  for (const [key, value] of Object.entries(dict.fr)) {
    const expected = varsOf(value)
    for (const l of LANGS) assert.equal(varsOf(dict[l.code][key]), expected, `${l.code}:${key}`)
  }
})

check('interpolation des variables', () => {
  assert.equal(translate('fr', 'topbar.lastScan', { date: '04/03/2026' }), 'Dernier scan : 04/03/2026')
  assert.equal(translate('en', 'topbar.lastScan', { date: '2026' }), 'Last scan: 2026')
  assert.equal(translate('ar', 'modal.devices'), 'الأجهزة')
})

check('variable absente remplacée par une chaîne vide', () => {
  assert.equal(translate('en', 'topbar.lastScan', {}), 'Last scan: ')
})

check('clé inconnue renvoyée telle quelle', () => {
  assert.equal(translate('fr', 'execution.inexistante'), 'execution.inexistante')
})

check('langue inconnue : repli sur le français', () => {
  assert.equal(translate('xx', 'banner.title'), translate('fr', 'banner.title'))
})

check('codes stockés (statuts, gravités, catégories) traduits dans les 5 langues', () => {
  for (const key of ['status.on', 'status.off', 'status.un', 'sev.c', 'sev.h', 'sev.m', 'sev.l', 'alertStatus.open', 'alertStatus.ack', 'alertStatus.resolved', 'cats.intrusion', 'cats.malware', 'cats.scan', 'cats.c2', 'cats.autre']) {
    for (const l of LANGS) assert.notEqual(translate(l.code, key), key, `${l.code}:${key}`)
  }
})

check('clés de type d’appareil (valeurs stockées françaises) traduites', () => {
  for (const key of ['Serveur', 'Poste', 'Caméra', 'Équipement réseau', 'Accès Internet']) {
    for (const l of LANGS) assert.notEqual(translate(l.code, `type.${key}`), `type.${key}`, `${l.code}:type.${key}`)
  }
})

check('isSupported : vrais codes uniquement', () => {
  for (const l of LANGS) assert.equal(isSupported(l.code), true)
  assert.equal(isSupported('es'), false)
  assert.equal(isSupported(null), false)
})

// --- Clés utilisées dans le code source -----------------------------------
const sourceFiles = (dir) => readdirSync(dir).flatMap((name) => {
  const path = join(dir, name)
  if (statSync(path).isDirectory()) return sourceFiles(path)
  return /\.(js|jsx)$/.test(name) ? [path] : []
})

check('chaque clé littérale utilisée dans le code existe', () => {
  const ref = new Set(keysOf('fr'))
  const used = new Set()
  for (const file of sourceFiles(fileURLToPath(new URL('../src', import.meta.url)))) {
    const text = readFileSync(file, 'utf8')
    for (const m of text.matchAll(/\bt\(\s*'([^']+)'/g)) used.add(m[1])
  }
  assert.ok(used.size > 100, `seulement ${used.size} clé(s) trouvée(s)`)
  for (const key of used) assert.ok(ref.has(key), `clé absente du catalogue : ${key}`)
})

console.log('')
if (failures.length) {
  console.log(`${failures.length} vérification(s) en échec : ${failures.join(', ')}`)
  process.exitCode = 1
} else {
  console.log(`${passed} vérifications réussies.`)
}
