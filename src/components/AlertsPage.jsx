import { useState } from 'react'
import { ALERT_SOURCES, ALERT_STATUS, NETWORK_FILTER_NONE, SEV } from '../constants'
import { sourceOf } from '../lib/findings.js'
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

export default function AlertsPage({ alerts, networks = [], onUpdate }) {
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
              <th>{t('alertsPage.colTitle')}</th><th>{t('alertsPage.colNetwork')}</th><th>{t('sources.col')}</th><th>{t('alertsPage.colSev')}</th><th>{t('alertsPage.colStatus')}</th><th>{t('alertsPage.colDetail')}</th>
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
                  <td><span style={{ color: s?.color || 'var(--m)' }}>● {s ? t(`sev.${a.severity}`) : (a.severity || '—')}</span></td>
                  <td><span style={{ color: st?.color || 'var(--m)' }}>● {st ? t(`alertStatus.${stateOf(a)}`) : stateOf(a)}</span></td>
                  <td className="detail">{a.detail || '—'}</td>
                  <td>{when(a.created_at, locale)}</td>
                  <td>{when(a.acknowledged_at, locale)}</td>
                  <td>{when(a.resolved_at, locale)}</td>
                  <td className="acts">
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
    </div>
  )
}
