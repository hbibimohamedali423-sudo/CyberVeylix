// Tests de lib/fixes.mjs : PC Windows simulé (aucune commande PowerShell réelle).
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createLocalFixes, parseAudit, stateOf, buildFindings, hostKey, localKey, AUDIT_SCRIPT, FIX_SCRIPTS, FIX_IDS } from '../lib/fixes.mjs'

// PC simulé : l'audit renvoie son état ; chaque script de correction le modifie. failApply : correction qui échoue ;
// noEffect : la commande réussit mais l'état ne change pas (la vérification doit le détecter).
function fakePc(state = {}, { failApply = null, noEffect = false, brokenAudit = false } = {}) {
  const pc = { smb1: true, rdp: true, nla: false, telnet: true, ...state }
  const calls = []
  const exec = async (file, args) => {
    assert.equal(file, 'powershell.exe')
    assert.deepEqual(args.slice(0, 5), ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command'])
    const script = args[5]
    calls.push(script)
    if (script === AUDIT_SCRIPT) {
      if (brokenAudit) return 'pas du json'
      return JSON.stringify(pc)
    }
    const id = Object.keys(FIX_SCRIPTS).find((k) => FIX_SCRIPTS[k] === script)
    assert.ok(id, 'script inattendu : ' + script)
    if (failApply === id) throw new Error('Accès refusé')
    if (noEffect) return ''
    if (id === 'smbv1') pc.smb1 = false
    if (id === 'rdp_nla') pc.nla = true
    if (id === 'telnet') pc.telnet = false
    return ''
  }
  return { exec, pc, calls }
}
const make = (opts = {}, pcOpts = {}, dataDir = null) => {
  const t = fakePc(opts, pcOpts)
  const logs = []
  const fixes = createLocalFixes({ platform: 'win32', exec: t.exec, hostname: 'PC-Accueil', ip: '192.168.1.10', dataDir, log: (m) => logs.push(m) })
  return { ...t, fixes, logs }
}

export function fixesChecks(check, checkAsync) {
  check('audit : sortie PowerShell lue strictement', () => {
    assert.deepEqual(parseAudit('{"smb1":true,"rdp":false,"nla":null,"telnet":true}\r\n'), { smb1: true, rdp: false, nla: null, telnet: true })
    assert.deepEqual(parseAudit('{"smb1":"True"}'), { smb1: null, rdp: null, nla: null, telnet: false }) // pas un vrai booléen : inconnu
    assert.equal(parseAudit('erreur'), null)
    assert.equal(parseAudit('[1]'), null)
    assert.equal(parseAudit(''), null)
  })

  check('état : vulnérable, corrigé ou inconnu (jamais « corrigé » par défaut)', () => {
    assert.equal(stateOf('smbv1', { smb1: true }), 'vulnerable')
    assert.equal(stateOf('smbv1', { smb1: false }), 'fixed')
    assert.equal(stateOf('smbv1', { smb1: null }), 'unknown')
    assert.equal(stateOf('rdp_nla', { rdp: true, nla: false }), 'vulnerable')
    assert.equal(stateOf('rdp_nla', { rdp: true, nla: true }), 'fixed')
    assert.equal(stateOf('rdp_nla', { rdp: false, nla: false }), 'fixed') // Bureau à distance désactivé
    assert.equal(stateOf('rdp_nla', { rdp: true, nla: null }), 'unknown')
    assert.equal(stateOf('telnet', { telnet: true }), 'vulnerable')
    assert.equal(stateOf('telnet', { telnet: false }), 'fixed')
    assert.equal(stateOf('inconnu', { smb1: true }), 'unknown')
    assert.equal(stateOf('smbv1', null), 'unknown')
  })

  check('faiblesses locales : clé stable « local:<pc>:<id> », confiance certaine, format du scanner', () => {
    const f = buildFindings({ smb1: true, rdp: true, nla: false, telnet: true }, { host: hostKey('PC-Accueil'), hostname: 'PC-Accueil', ip: '192.168.1.10' })
    assert.deepEqual(f.map((x) => x.key), ['local:pc-accueil:smbv1', 'local:pc-accueil:rdp_nla', 'local:pc-accueil:telnet'])
    for (const x of f) {
      assert.equal(x.confidence, 'certaine')
      assert.equal(x.ip, '192.168.1.10')
      assert.ok(x.title.includes('(PC-Accueil)') && x.remediation && x.evidence && x.severity === 'h')
    }
    assert.deepEqual(f[0].cves, ['CVE-2017-0144'])
    assert.equal(hostKey('Mon PC/évil'), 'mon-pc--vil')
    assert.match(localKey(hostKey('X'), 'smbv1'), /^local:[a-z0-9._-]+:[a-z0-9_]+$/)
    assert.deepEqual(buildFindings({ smb1: false, rdp: false, nla: false, telnet: false }, { host: 'h', hostname: 'H', ip: null }), [])
  })

  check('scripts : constants, sans variable JS ni texte venant de l\'extérieur', () => {
    assert.deepEqual(FIX_IDS, Object.keys(FIX_SCRIPTS))
    for (const s of Object.values(FIX_SCRIPTS)) assert.ok(!/[`]|\$\{/.test(s), s) // aucune interpolation résiduelle
    assert.ok(!/Set-|Stop-|Remove-|New-/.test(AUDIT_SCRIPT)) // l'audit ne modifie rien
  })

  checkAsync('audit local : faiblesses trouvées, état mémorisé', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cv-fix-'))
    try {
      const t = make({}, {}, dir)
      const r = await t.fixes.audit()
      assert.equal(r.ran, true)
      assert.equal(r.findings.length, 3)
      assert.deepEqual(r.fixed, [])
      assert.equal(t.calls.every((s) => s === AUDIT_SCRIPT), true) // lecture seule
      assert.equal(JSON.parse(readFileSync(join(dir, 'local-audit.json'), 'utf8')).keys.length, 3)
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  checkAsync('audit local : correction faite hors outil → « corrigée » au prochain audit ; état illisible ≠ corrigé', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cv-fix-'))
    try {
      const t = make({}, {}, dir)
      await t.fixes.audit()
      t.pc.smb1 = false
      t.pc.nla = null // illisible
      const r = await t.fixes.audit()
      assert.deepEqual(r.fixed, [{ key: 'local:pc-accueil:smbv1' }])
      assert.deepEqual(r.findings.map((f) => f.key), ['local:pc-accueil:telnet'])
      t.pc.nla = false
      const r2 = await t.fixes.audit()
      assert.deepEqual(r2.fixed, []) // smbv1 déjà annoncée corrigée
      assert.equal(r2.findings.length, 2)
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  checkAsync('audit local : non Windows ou sortie cassée → rien (aucune faiblesse inventée, aucun fichier)', async () => {
    const lin = createLocalFixes({ platform: 'linux', exec: async () => { throw new Error('ne doit pas être appelé') }, hostname: 'x' })
    assert.deepEqual(await lin.audit(), { ran: false, findings: [], fixed: [] })
    const dir = mkdtempSync(join(tmpdir(), 'cv-fix-'))
    try {
      const t = make({}, { brokenAudit: true }, dir)
      assert.deepEqual(await t.fixes.audit(), { ran: false, findings: [], fixed: [] })
      assert.equal(existsSync(join(dir, 'local-audit.json')), false)
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })

  for (const id of ['smbv1', 'rdp_nla', 'telnet']) {
    checkAsync(`correction « ${id} » : appliquée puis vérifiée`, async () => {
      const t = make()
      assert.deepEqual(await t.fixes.applyFix(id), { code: 'fix_done', id })
      assert.equal(stateOf(id, t.pc), 'fixed')
      assert.equal(t.calls.filter((s) => s === FIX_SCRIPTS[id]).length, 1)
      assert.deepEqual(await t.fixes.applyFix(id), { code: 'fix_already', id }) // seconde fois : rien à faire
      assert.equal(t.calls.filter((s) => s === FIX_SCRIPTS[id]).length, 1)
    })
  }

  checkAsync('correction : identifiant inconnu ou piégé refusé, aucun script lancé', async () => {
    const t = make()
    for (const bad of ['rm_rf', 'smbv1; calc', '__proto__', 'constructor', '', undefined, 42]) {
      const r = await t.fixes.applyFix(bad)
      assert.deepEqual([r.code, r.reason], ['rejected', 'unknown_fix'], String(bad))
    }
    assert.equal(t.calls.length, 0)
  })

  checkAsync('correction : échec de PowerShell → failed ; « réussie » sans effet → failed (vérification)', async () => {
    const a = make({}, { failApply: 'telnet' })
    const r = await a.fixes.applyFix('telnet')
    assert.deepEqual([r.code, r.failed], ['error', true])
    const b = make({}, { noEffect: true })
    const r2 = await b.fixes.applyFix('smbv1')
    assert.deepEqual([r2.code, r2.failed], ['error', true])
    assert.ok(r2.message.includes('toujours présente'))
    assert.equal(stateOf('smbv1', b.pc), 'vulnerable')
  })

  checkAsync('correction : état illisible → refus d\'agir à l\'aveugle ; non Windows refusé', async () => {
    const t = make({}, { brokenAudit: true })
    const r = await t.fixes.applyFix('smbv1')
    assert.equal(r.failed, true)
    assert.equal(t.calls.some((s) => s === FIX_SCRIPTS.smbv1), false)
    const lin = createLocalFixes({ platform: 'linux', exec: async () => { throw new Error('non') }, hostname: 'x' })
    assert.deepEqual([(await lin.applyFix('smbv1')).reason], ['unsupported_os'])
  })
}
