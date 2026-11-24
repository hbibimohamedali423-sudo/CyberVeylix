import { useState } from 'react'
import { SEV } from '../constants'
import { useI18n } from '../i18n/context.js'
import { isActiveCommand, parseCommandResult, sensorState } from '../lib/findings.js'
import useRows from '../useRows'
import './ScanPage.css'

const KINDS = ['scan_now', 'block_ip', 'unblock_ip', 'fix']
const BLOCK_REASONS = ['invalid_ip', 'gateway', 'self', 'trusted', 'dhcp', 'dns_service', 'unsupported_os', 'rate_limit']
const RESULT_CODES = ['scan_done', 'no_devices', 'busy', 'error', 'unsupported', 'expired', 'restarted', 'rejected']

// Analyse à la demande : la page dépose une demande dans sensor_commands ; le capteur installé sur le PC
// permanent l'exécute lui-même et écrit le résultat. Rien n'est exécuté par le navigateur.
export default function ScanPage({ user, sensors = [], vulns = [], sensorsMissing, onOpenVulns }) {
  const { t, locale } = useI18n()
  const cmd = useRows('sensor_commands', user, 4000)
  const [picked, setPicked] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const when = (v) => (v ? new Date(v).toLocaleString(locale) : '—')

  const running = sensors.filter((s) => sensorState(s).state === 'running')
  const sensor = sensors.find((s) => s.id === picked) || running[0] || sensors[0] || null
  const state = sensor ? sensorState(sensor).state : 'never'
  const mine = sensor ? cmd.rows.filter((c) => c.sensor_id === sensor.id) : []
  const active = mine.some((c) => isActiveCommand(c) && c.kind === 'scan_now')
  const recent = cmd.rows.slice().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).slice(0, 15)

  const open = vulns.filter((v) => v.source === 'scan' && (v.status || 'open') !== 'resolved')
  const bySev = SEV.map((s) => [s, open.filter((v) => v.severity === s.k).length])

  const launch = async () => {
    if (!sensor) return
    setErr('')
    setBusy(true)
    try {
      const msg = await cmd.add({ sensor_id: sensor.id, kind: 'scan_now', params: {} })
      if (msg) setErr(msg)
    } catch {
      setErr(t('common.updateError'))
    } finally {
      setBusy(false)
    }
  }

  const resultText = (c) => {
    const r = parseCommandResult(c.result)
    if (!r) return '—'
    if (r.code === 'raw') return r.message
    if (r.code === 'blocked' || r.code === 'unblocked') return t(`blocks.result.${r.code}`, { ip: r.ip || '' })
    if (r.code === 'rejected' && r.reason) return t('blocks.result.rejectedWhy', { why: BLOCK_REASONS.includes(r.reason) ? t(`blocks.reason.${r.reason}`) : r.reason })
    if (!RESULT_CODES.includes(r.code)) return r.code
    return t(`scan.result.${r.code}`, { ...r, message: r.message || '' })
  }

  const blocked = !sensor || state !== 'running' || active || busy
  const hint = sensorsMissing ? t('sensors.missing')
    : !sensor ? t('scan.noSensor')
    : state !== 'running' ? t('scan.sensorStopped')
    : active ? t('scan.alreadyRunning')
    : ''

  return (
    <div className="card scan-page">
      <h3>{t('scan.title')}</h3>
      <p className="m">{t('scan.intro')}</p>

      <div className="scan-bar">
        {sensors.length > 1 && (
          <label>{t('scan.sensor')}
            <select value={sensor ? sensor.id : ''} onChange={(e) => setPicked(e.target.value)}>
              {sensors.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
          </label>
        )}
        <button type="button" onClick={launch} disabled={blocked}>
          {active ? t('scan.running') : t('scan.launch')}
        </button>
        {sensor && <span className="m">{t('sensors.lastScan', { date: when(sensor.last_scan_at) })}</span>}
      </div>
      {hint && <p className="scan-hint" role="status">{hint}</p>}
      {(err || cmd.error) && <div className="scan-err" role="alert">{err || cmd.error}</div>}

      <section>
        <h4>{t('scan.lastFindings')}</h4>
        <ul className="scan-sev">
          {bySev.map(([s, n]) => (
            <li key={s.k} style={{ color: s.color }}><b>{n}</b> <span>{t(`sev.${s.k}`)}</span></li>
          ))}
        </ul>
        <button type="button" className="ghost" onClick={onOpenVulns}>{t('scan.openVulns')}</button>
      </section>

      <section>
        <h4>{t('scan.history')}</h4>
        {!recent.length ? <p className="m">{t('scan.noHistory')}</p> : (
          <div className="scan-tw">
            <table className="scan-dt">
              <thead><tr><th>{t('alertsPage.colCreated')}</th><th>{t('scan.colKind')}</th><th>{t('alertsPage.colStatus')}</th><th>{t('scan.colResult')}</th></tr></thead>
              <tbody>
                {recent.map((c) => (
                  <tr key={c.id}>
                    <td>{when(c.created_at)}</td>
                    <td>{KINDS.includes(c.kind) ? t(`scan.kind.${c.kind}`) : c.kind}</td>
                    <td className={`st-${c.status}`}>{t(`scan.status.${c.status}`)}</td>
                    <td>{resultText(c)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
