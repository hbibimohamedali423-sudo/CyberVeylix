// CyberVeylix Sensor — audit LOCAL du PC qui héberge le capteur et corrections de la liste blanche.
// - Audit en lecture seule (aucun changement) : SMBv1, Bureau à distance sans NLA, service Telnet.
//   Le PC du capteur n'est jamais analysé par le réseau (ses leurres ouverts fausseraient le résultat) :
//   on lit directement son état, ce qui est plus fiable (confiance « certaine »).
// - Trois corrections seulement, scripts FIXES et sans paramètre : aucun texte venant de la page n'est exécuté.
//   Le capteur vérifie l'état après chaque correction et ne répond « corrigé » que si c'est réellement le cas.
// - Uniquement ce PC. Les autres appareils (caméras, imprimantes…) gardent leurs instructions de correction.
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'

const run = promisify(execFile)

export const FIX_IDS = ['smbv1', 'rdp_nla', 'telnet']
const STATE_FILE = 'local-audit.json'
const TS = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"

// Lecture seule. Une valeur illisible reste null (jamais interprétée comme « corrigé » ni « vulnérable »).
export const AUDIT_SCRIPT = [
  '$o = [ordered]@{ smb1 = $null; rdp = $null; nla = $null; telnet = $false }',
  'try { $o.smb1 = [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { }',
  `try { $o.rdp = ((Get-ItemProperty '${TS}' -ErrorAction Stop).fDenyTSConnections -eq 0) } catch { }`,
  `try { $o.nla = ((Get-ItemProperty '${TS}\\WinStations\\RDP-Tcp' -ErrorAction Stop).UserAuthentication -eq 1) } catch { }`,
  "try { $o.telnet = ((Get-Service -Name TlntSvr -ErrorAction Stop).Status -eq 'Running') } catch { }",
  '$o | ConvertTo-Json -Compress',
].join('; ')

// Corrections : textes constants, sans variable ni entrée externe.
export const FIX_SCRIPTS = {
  smbv1: 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false -ErrorAction Stop',
  rdp_nla: `Set-ItemProperty -Path '${TS}\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1 -ErrorAction Stop`,
  telnet: "Stop-Service -Name TlntSvr -Force -ErrorAction Stop; Set-Service -Name TlntSvr -StartupType Disabled -ErrorAction Stop",
}

const defaultExec = async (file, args) => {
  const { stdout } = await run(file, args, { timeout: 60000, windowsHide: true })
  return String(stdout || '')
}
const ps = (exec, script) => exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script])

// Sortie JSON de l'audit → { smb1, rdp, nla, telnet } (booléens ou null), ou null si illisible.
export function parseAudit(stdout) {
  let v
  try { v = JSON.parse(String(stdout).trim()) } catch { return null }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null
  const bool = (x) => (x === true || x === false ? x : null)
  return { smb1: bool(v.smb1), rdp: bool(v.rdp), nla: bool(v.nla), telnet: v.telnet === true }
}

// 'vulnerable' | 'fixed' | 'unknown' pour une correction donnée.
export function stateOf(id, audit) {
  if (!audit) return 'unknown'
  if (id === 'smbv1') return audit.smb1 === null ? 'unknown' : (audit.smb1 ? 'vulnerable' : 'fixed')
  if (id === 'rdp_nla') {
    if (audit.rdp === false) return 'fixed' // Bureau à distance désactivé : rien d'exposé
    if (audit.rdp === null || audit.nla === null) return 'unknown'
    return audit.nla ? 'fixed' : 'vulnerable'
  }
  if (id === 'telnet') return audit.telnet ? 'vulnerable' : 'fixed'
  return 'unknown'
}

export const localKey = (host, id) => `local:${host}:${id}`
export const hostKey = (name) => String(name || 'pc').toLowerCase().replace(/[^a-z0-9._-]/g, '-').slice(0, 63)

const META = {
  smbv1: {
    severity: 'h', cves: ['CVE-2017-0144'], port: 445, service: 'smb',
    title: 'SMBv1 activé (vecteur de WannaCry / EternalBlue)',
    evidence: 'Get-SmbServerConfiguration : EnableSMB1Protocol = True',
    remediation: 'Bouton « Corriger » (désactive SMBv1 sur ce PC), ou en administrateur : Set-SmbServerConfiguration -EnableSMB1Protocol $false. '
      + 'Les très anciens appareils (Windows XP, vieux NAS / scanners) ne pourront plus accéder aux partages.',
  },
  rdp_nla: {
    severity: 'h', cves: ['CVE-2019-0708'], port: 3389, service: 'rdp',
    title: 'Bureau à distance sans authentification réseau (NLA)',
    evidence: 'Registre : UserAuthentication = 0 alors que le Bureau à distance est activé.',
    remediation: 'Bouton « Corriger » (exige NLA), ou Propriétés système > Utilisation à distance : n\'autoriser que les connexions avec NLA. '
      + 'Ne jamais exposer RDP sur Internet.',
  },
  telnet: {
    severity: 'h', cves: [], port: 23, service: 'telnet',
    title: 'Service Telnet actif : mots de passe en clair',
    evidence: 'Le service Windows TlntSvr (Telnet) est en cours d\'exécution.',
    remediation: 'Bouton « Corriger » (arrête et désactive le service Telnet), puis utiliser SSH ou le Bureau à distance avec NLA.',
  },
}

// Faiblesses actuelles de CE PC, au format des faiblesses de l'analyse réseau (voir push.mjs).
export function buildFindings(audit, { host, hostname, ip }) {
  return FIX_IDS.filter((id) => stateOf(id, audit) === 'vulnerable').map((id) => ({
    key: localKey(host, id), rule: `local-${id}`, ip: ip || null, confidence: 'certaine', ...META[id],
    title: `${META[id].title} (${hostname})`,
  }))
}

export function createLocalFixes({ platform = process.platform, exec = defaultExec, hostname = 'pc', ip = null, dataDir = null, log = console.log } = {}) {
  const host = hostKey(hostname)
  const supported = platform === 'win32'

  async function readAudit() { return parseAudit(await ps(exec, AUDIT_SCRIPT)) }

  const stateFile = () => (dataDir ? join(dataDir, STATE_FILE) : null)
  function loadKeys() {
    try { const f = stateFile(); return f && existsSync(f) ? JSON.parse(readFileSync(f, 'utf8')).keys || [] : [] } catch { return [] }
  }
  function saveKeys(keys) {
    try { const f = stateFile(); if (f) { mkdirSync(dataDir, { recursive: true }); writeFileSync(f, JSON.stringify({ keys }, null, 2)) } } catch { /* non bloquant */ }
  }

  // Audit lecture seule. fixed : faiblesses d'un audit précédent dont l'état est maintenant explicitement « corrigé »
  // (un état illisible n'est jamais compté comme corrigé).
  async function audit() {
    if (!supported) return { ran: false, findings: [], fixed: [] }
    let a
    try { a = await readAudit() } catch (e) { log('⚠ Audit local impossible : ' + (e && e.message)); return { ran: false, findings: [], fixed: [], error: String(e && e.message) } }
    if (!a) { log('⚠ Audit local : sortie illisible.'); return { ran: false, findings: [], fixed: [] } }
    const findings = buildFindings(a, { host, hostname, ip })
    const prev = loadKeys()
    const fixed = FIX_IDS.filter((id) => prev.includes(localKey(host, id)) && stateOf(id, a) === 'fixed').map((id) => ({ key: localKey(host, id) }))
    const keep = prev.filter((k) => !fixed.some((f) => f.key === k) && !k.startsWith(`local:${host}:`))
    saveKeys([...keep, ...findings.map((f) => f.key), ...FIX_IDS.filter((id) => prev.includes(localKey(host, id)) && stateOf(id, a) === 'unknown').map((id) => localKey(host, id))])
    return { ran: true, findings, fixed }
  }

  async function applyFix(id) {
    if (!supported) return { code: 'rejected', reason: 'unsupported_os', id }
    if (typeof id !== 'string' || !Object.hasOwn(FIX_SCRIPTS, id)) return { code: 'rejected', reason: 'unknown_fix', id: String(id).slice(0, 40) }
    let a
    try { a = await readAudit() } catch (e) { return { code: 'error', failed: true, message: String(e && e.message).slice(0, 300), id } }
    const before = stateOf(id, a)
    if (before === 'unknown') return { code: 'error', failed: true, message: 'état du PC illisible', id }
    if (before === 'fixed') return { code: 'fix_already', id }
    try { await ps(exec, FIX_SCRIPTS[id]) } catch (e) {
      log(`⚠ Correction ${id} en échec : ${e && e.message}`)
      return { code: 'error', failed: true, message: String(e && e.message).slice(0, 300), id }
    }
    let after
    try { after = stateOf(id, await readAudit()) } catch { after = 'unknown' }
    if (after !== 'fixed') return { code: 'error', failed: true, message: 'vérification : la faiblesse est toujours présente', id }
    log(`✔ Correction appliquée et vérifiée : ${id}`)
    return { code: 'fix_done', id }
  }

  return { audit, applyFix, host, supported }
}
