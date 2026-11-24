import { useState } from 'react'
import { ALERT_SOURCES, ALERT_STATUS, NETWORK_FILTER_NONE, SEV } from '../constants'
import { blockState, pickSensorFor, sensorState, sourceOf } from '../lib/findings.js'
import { useI18n } from '../i18n/context.js'
import './AlertsPage.css'

// Statut réel d’une alerte : repli sur le défaut de la colonne (open) si null.
const stateOf = (a) => a.status || 'open'
const when = (v, locale) => (v ? new Date(v).toLocaleString(locale) : '—')
const time = (v) => {
  if (!v) return null
  const t = new Date(v).getTime()
  return Number.isFinite(t) ? t : null
}
// Tri décroissant par created_at, dates invalides ou absentes en fin de liste.
const newestFirst = (a, b) => {
  const ta = time(a.created_at)
  const tb = time(b.created_at)
  if (ta === null && tb === null) return 0
  if (ta === null) return 1
  if (tb === null) return -1
  return tb - ta
}
const find = (list, k) => list.find((x) => x.k === k)

const sortByDate = (field) => (a, b) => String(b[field] || '').localeCompare(String(a[field] || ''))

// Le blocage se fait par une demande au capteur (table sensor_commands) : c'est lui qui agit sur le pare-feu Windows.
export default function AlertsPage({ alerts, networks = [], onUpdate, sensors = [], blocked = [], commands = [], onCommand }) {
  const { t, locale } = useI18n()
  const [sev, setSev] = useState('')
  const [status, setStatus] = useState('')
  const [networkFilter, setNetworkFilter] = useState('')
  const [src, setSrc] = useState('')
  const [err, setErr] = useState('')
  const [busyId, setBusyId] = useState(null)

  const networkName = (id) => {
    if (!id) return t('networks.noNetwork')
    const network = networks.find((n) => n.id === id)
    return network ? (network.name || network.cidr) : t('networks.unknown')
  }

  const list = alerts
    .filter((a) => (!sev || a.severity === sev)
      && (!status || stateOf(a) === status)
      && (!src || sourceOf(a) === src)
      && (!networkFilter
        || (networkFilter === NETWORK_FILTER_NONE ? !a.network_id : a.network_id === networkFilter)))
    .sort(newestFirst)

  const run = async (a, patch) => {
    setErr('')
    setBusyId(a.id)
    try {
      const msg = await onUpdate(a.id, patch)
      if (msg) setErr(msg)
    } catch {
      setErr(t('alertsPage.errUpdate'))
    } finally {
      setBusyId(null)
    }
  }

  const sendCommand = async (sensor, kind, params) => {
    setErr('')
    setBusyId(params.ip)
    try {
      const msg = await onCommand(sensor.id, kind, params)
      if (msg) setErr(msg)
    } catch {
      setErr(t('alertsPage.errUpdate'))
    } finally {
      setBusyId(null)
    }
  }
  const blockIp = (a) => {
    const sensor = pickSensorFor(a, sensors)
    if (!sensor) return
    if (!window.confirm(t('blocks.confirmBlock', { ip: a.source_ip, sensor: sensor.name }))) return
    sendCommand(sensor, 'block_ip', { ip: a.source_ip, reason: String(a.title || '').slice(0, 200), alert_id: a.id, by: 'manual' })
  }
  const unblockIp = (ip, sensorId) => {
    const sensor = sensors.find((x) => x.id === sensorId)
    if (!sensor || !window.confirm(t('blocks.confirmUnblock', { ip }))) return
    sendCommand(sensor, 'unblock_ip', { ip })
  }

  const acknowledge = (a) => run(a, { status: 'ack', acknowledged_at: new Date().toISOString() })
  const resolve = (a) => {
    if (window.confirm(t('alertsPage.confirmResolve', { title: a.title }))) {
      run(a, { status: 'resolved', resolved_at: new Date().toISOString() })
    }
  }

  return (
    <div className="card alerts-page">
      <h3>
        {t('alertsPage.title')}
        <span className="m" style={{ fontWeight: 400 }}> · {t('alertsPage.section')} · {list.length} / {alerts.length}</span>
      </h3>
      <div className="alerts-bar">
        <label>{t('alertsPage.sevFilter')}
          <select value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="">{t('alertsPage.allSev')}</option>
            {SEV.map((s) => <option key={s.k} value={s.k}>{t(`sev.${s.k}`)}</option>)}
          </select>
        </label>
        <label>{t('alertsPage.statusFilter')}
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">{t('alertsPage.allStatuses')}</option>
            {ALERT_STATUS.map((s) => <option key={s.k} value={s.k}>{t(`alertStatus.${s.k}`)}</option>)}
          </select>
        </label>
        <label>{t('alertsPage.networkFilter')}
          <select value={networkFilter} onChange={(e) => setNetworkFilter(e.target.value)}>
            <option value="">{t('networks.all')}</option>
            {networks.map((n) => <option key={n.id} value={n.id}>{n.name || n.cidr}</option>)}
            <option value={NETWORK_FILTER_NONE}>{t('networks.noNetwork')}</option>
          </select>
        </label>
        <label>{t('sources.filter')}
          <select value={src} onChange={(e) => setSrc(e.target.value)}>
            <option value="">{t('sources.all')}</option>
            {ALERT_SOURCES.map((k) => <option key={k} value={k}>{t(`sources.${k}`)}</option>)}
          </select>
        </label>
      </div>
      {err && <div className="alerts-err" role="alert">{err}</div>}
      <div className="alerts-tw">
        <table className="alerts-dt">
          <thead>
            <tr>
              <th>{t('alertsPage.colTitle')}</th><th>{t('alertsPage.colNetwork')}</th><th>{t('sources.col')}</th><th>{t('blocks.colSource')}</th><th>{t('alertsPage.colSev')}</th><th>{t('alertsPage.colStatus')}</th><th>{t('alertsPage.colDetail')}</th>
              <th>{t('alertsPage.colCreated')}</th><th>{t('alertsPage.colAck')}</th><th>{t('alertsPage.colResolved')}</th><th>{t('alertsPage.colActions')}</th>
            </tr>
          </thead>
          <tbody>
            {list.map((a) => {
              const s = find(SEV, a.severity)
              const st = find(ALERT_STATUS, stateOf(a))
              const busy = busyId === a.id
              return (
                <tr key={a.id}>
                  <td>{a.title}</td>
                  <td>{networkName(a.network_id)}</td>
                  <td>{ALERT_SOURCES.includes(sourceOf(a)) ? t(`sources.${sourceOf(a)}`) : sourceOf(a)}</td>
                  <td className="src">
                    {a.source_ip && <div dir="ltr">{a.source_ip}</div>}
                    {a.source_mac && <div className="m" dir="ltr" title={a.source_ip ? undefined : t('blocks.macHint')}>{a.source_mac}</div>}
                    {!a.source_ip && !a.source_mac && '—'}
                  </td>
                  <td><span style={{ color: s?.color || 'var(--m)' }}>● {s ? t(`sev.${a.severity}`) : (a.severity || '—')}</span></td>
                  <td><span style={{ color: st?.color || 'var(--m)' }}>● {st ? t(`alertStatus.${stateOf(a)}`) : stateOf(a)}</span></td>
                  <td className="detail">{a.detail || '—'}</td>
                  <td>{when(a.created_at, locale)}</td>
                  <td>{when(a.acknowledged_at, locale)}</td>
                  <td>{when(a.resolved_at, locale)}</td>
                  <td className="acts">
                    {a.source_ip && stateOf(a) !== 'resolved' && onCommand && (() => {
                      const bs = blockState(a.source_ip, blocked, commands)
                      const sensor = pickSensorFor(a, sensors)
                      if (bs === 'blocked') {
                        const row = blocked.find((b) => b.ip === a.source_ip && b.status === 'active')
                        return (
                          <>
                            <span className="blocked-badge">{t('blocks.blockedBadge')}</span>
                            <button type="button" className="ghost" disabled={busyId === a.source_ip || !sensors.some((x) => x.id === row.sensor_id && sensorState(x).state === 'running')}
                              aria-label={t('blocks.ariaUnblock', { ip: a.source_ip })} onClick={() => unblockIp(a.source_ip, row.sensor_id)}>{t('blocks.unblock')}</button>
                          </>
                        )
                      }
                      return (
                        <button type="button" className="del" disabled={bs === 'pending' || busyId === a.source_ip || !sensor}
                          title={sensor ? undefined : t('blocks.noSensor')}
                          aria-label={t('blocks.ariaBlock', { ip: a.source_ip })} onClick={() => blockIp(a)}>
                          {bs === 'pending' ? t('blocks.pending') : t('blocks.block')}
                        </button>
                      )
                    })()}
                    {stateOf(a) === 'open' && (
                      <button type="button" className="ack" disabled={busy}
                        aria-label={t('alertsPage.ariaAck', { title: a.title })} onClick={() => acknowledge(a)}>
                        {t('alertsPage.ack')}
                      </button>
                    )}
                    {(stateOf(a) === 'open' || stateOf(a) === 'ack') && (
                      <button type="button" className="solve" disabled={busy}
                        aria-label={t('alertsPage.ariaResolve', { title: a.title })} onClick={() => resolve(a)}>
                        {t('alertsPage.resolve')}
                      </button>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {!alerts.length && <p className="alerts-empty">{t('alertsPage.empty')}</p>}
      {!!alerts.length && !list.length && <p className="alerts-empty">{t('alertsPage.noResult')}</p>}

      {onCommand && (
        <section className="blocks-panel">
          <h4>{t('blocks.title')}</h4>
          <p className="m">{t('blocks.scope')}</p>
          {!blocked.length ? <p className="m">{t('blocks.empty')}</p> : (
            <div className="alerts-tw">
              <table className="alerts-dt">
                <thead>
                  <tr><th>{t('blocks.colIp')}</th><th>{t('blocks.colSensor')}</th><th>{t('blocks.colBy')}</th><th>{t('blocks.colReason')}</th><th>{t('alertsPage.colCreated')}</th><th>{t('alertsPage.colStatus')}</th><th>{t('alertsPage.colActions')}</th></tr>
                </thead>
                <tbody>
                  {blocked.slice().sort(sortByDate('blocked_at')).slice(0, 30).map((b) => {
                    const sensor = sensors.find((x) => x.id === b.sensor_id)
                    const pending = blockState(b.ip, [], commands) === 'pending'
                    return (
                      <tr key={b.id}>
                        <td dir="ltr">{b.ip}</td>
                        <td>{sensor ? sensor.name : '—'}</td>
                        <td>{t(`blocks.by.${b.blocked_by}`)}</td>
                        <td className="detail">{b.status === 'failed' ? (b.error || b.reason || '—') : (b.reason || '—')}</td>
                        <td>{when(b.blocked_at, locale)}</td>
                        <td className={`bst-${b.status}`}>{t(`blocks.status.${b.status}`)}</td>
                        <td className="acts">
                          {b.status === 'active' && (
                            <button type="button" className="ghost" disabled={pending || busyId === b.ip || !sensor || sensorState(sensor).state !== 'running'}
                              aria-label={t('blocks.ariaUnblock', { ip: b.ip })} onClick={() => unblockIp(b.ip, b.sensor_id)}>
                              {pending ? t('blocks.pending') : t('blocks.unblock')}
                            </button>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  )
}
