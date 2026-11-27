// Texte lisible d'une demande au capteur et de son résultat (pages « Analyse & Scan » et « Surveillance »).
import { parseCommandResult } from './findings.js'

export const COMMAND_KINDS = ['scan_now', 'block_ip', 'unblock_ip', 'fix']
const FIX_IDS = ['smbv1', 'rdp_nla', 'telnet']
const BLOCK_REASONS = ['invalid_ip', 'gateway', 'self', 'trusted', 'dhcp', 'dns_service', 'unsupported_os', 'rate_limit']
const RESULT_CODES = ['scan_done', 'no_devices', 'busy', 'error', 'unsupported', 'expired', 'restarted', 'rejected']

export const commandKindText = (t, kind) => (COMMAND_KINDS.includes(kind) ? t(`scan.kind.${kind}`) : String(kind || '—'))
const fixName = (t, id) => (FIX_IDS.includes(id) ? t(`fixes.${id}.name`) : String(id || ''))

// Cible de la demande : adresse (blocage) ou nom de la correction.
export function commandTarget(t, c) {
  if (!c || !c.params) return ''
  if (c.kind === 'block_ip' || c.kind === 'unblock_ip') return String(c.params.ip || '')
  if (c.kind === 'fix') return fixName(t, c.params.id)
  return ''
}

export function commandResultText(t, resultText) {
  const r = parseCommandResult(resultText)
  if (!r) return '—'
  if (r.code === 'raw') return r.message
  if (r.code === 'fix_done' || r.code === 'fix_already') return t(`fixes.result.${r.code}`, { name: fixName(t, r.id) })
  if (r.code === 'blocked' || r.code === 'unblocked') return t(`blocks.result.${r.code}`, { ip: r.ip || '' })
  if (r.code === 'rejected' && r.reason) {
    const why = r.reason === 'unknown_fix' ? t('fixes.reason.unknown_fix')
      : BLOCK_REASONS.includes(r.reason) ? t(`blocks.reason.${r.reason}`) : r.reason
    return t('blocks.result.rejectedWhy', { why })
  }
  if (!RESULT_CODES.includes(r.code)) return r.code
  return t(`scan.result.${r.code}`, { ...r, message: r.message || '' })
}
