import { hourlyCounts } from '../lib/findings.js'
import Donut from './Donut'
import { KPIS, STATUS, SEV } from '../constants'
import { useI18n } from '../i18n/context.js'

export function Banner() {
  const { t } = useI18n()
  return (
    <section className="banner">
      <div><small>{t('banner.brand')}</small><h1>{t('banner.title')}</h1><div style={{ fontSize: 15 }}>{t('banner.subtitle')}</div></div>
      <div className="slogan">{t('banner.slogan1')}<br />{t('banner.slogan2')}</div>
    </section>
  )
}

export function Kpis({ counts }) {
  const { t } = useI18n()
  return (
    <section className="kpis">
      {KPIS.map((k, i) => {
        const n = counts[i]
        const known = typeof n === 'number'
        return (
          <div key={k.key} className={`card kpi ${k.cls}`}>
            <div className="ic" />
            <div>
              <div>{t(`kpi.${k.key}`)}</div>
              <b>{known ? n : '—'}</b><br />
              <small>{!known ? t('kpi.pending') : n ? t('kpi.stored') : t('kpi.noData')}</small>
            </div>
          </div>
        )
      })}
    </section>
  )
}

// Activité : alertes ENREGISTRÉES par heure sur 24 h (une seule série : la couleur du thème, pas de légende),
// avec infobulle par barre et tableau équivalent pour les lecteurs d'écran.
const barPath = (x, y, w, h, r) => {
  const rr = Math.min(r, w / 2, h)
  return `M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`
}
export function Activity({ alerts = [], devices = [] }) {
  const { t, locale } = useI18n()
  const buckets = hourlyCounts(alerts)
  const total = buckets.reduce((n, b) => n + b.n, 0)
  const max = Math.max(1, ...buckets.map((b) => b.n))
  const [x0, x1, y0, y1] = [34, 252, 12, 140]
  const step = (x1 - x0) / buckets.length
  const hour = (ms) => new Date(ms).toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' })
  const online = devices.filter((d) => d.status === 'on').length
  return (
    <div className="card activity-card">
      <h3>{t('activity.title')}</h3>
      <div className="m" style={{ margin: '4px 0 8px' }}>{t('activityLive.subtitle')}</div>
      <svg viewBox="0 0 260 170" style={{ width: '100%' }} role="img" aria-label={t('activityLive.aria', { n: total })}>
        <g style={{ stroke: 'var(--map-grid)' }} strokeWidth="1"><path d={`M${x0} ${y1}H${x1}M${x0} ${y0}H${x1}`} /></g>
        <text x={x0 - 6} y={y1 + 3} textAnchor="end" fontSize="9" style={{ fill: 'var(--m)' }}>0</text>
        <text x={x0 - 6} y={y0 + 3} textAnchor="end" fontSize="9" style={{ fill: 'var(--m)' }}>{max}</text>
        {buckets.map((b, i) => {
          const h = (b.n / max) * (y1 - y0)
          const x = x0 + i * step + 1
          return (
            <g key={b.at} className="act-bar">
              <rect x={x0 + i * step} y={y0} width={step} height={y1 - y0} fill="transparent" />
              {b.n > 0 && <path d={barPath(x, y1 - h, step - 2, h, 4)} style={{ fill: 'var(--chart)' }} />}
              <title>{t('activityLive.barTitle', { hour: hour(b.at), n: b.n })}</title>
            </g>
          )
        })}
        {buckets.map((b, i) => (i % 6 === 0 ? <text key={`l${b.at}`} x={x0 + i * step} y={y1 + 14} fontSize="9" style={{ fill: 'var(--m)' }}>{hour(b.at)}</text> : null))}
        {total === 0 && <text x={(x0 + x1) / 2} y={(y0 + y1) / 2} textAnchor="middle" fontSize="10" style={{ fill: 'var(--m)' }}>{t('activityLive.empty')}</text>}
      </svg>
      <table className="sr-only">
        <caption>{t('activityLive.subtitle')}</caption>
        <thead><tr><th>{t('activityLive.hourCol')}</th><th>{t('activityLive.countCol')}</th></tr></thead>
        <tbody>{buckets.map((b) => <tr key={b.at}><td>{hour(b.at)}</td><td>{b.n}</td></tr>)}</tbody>
      </table>
      <div className="bw"><small>{t('activityLive.alerts24')}</small><br /><b>{total}</b></div>
      <div className="bw"><small>{t('activityLive.online')}</small><br /><b>{online}</b></div>
    </div>
  )
}

function Legend({ items }) {
  const total = items.reduce((a, i) => a + i.n, 0)
  return (
    <table><tbody>
      {items.map((i) => <tr key={i.label}><td style={{ color: i.color }}>● {i.label}</td><td>{total ? `${i.n} · ${Math.round((i.n / total) * 100)}%` : '—'}</td></tr>)}
    </tbody></table>
  )
}

export function DevicesCard({ devices }) {
  const { t } = useI18n()
  const items = STATUS.map((s) => ({ ...s, label: t(`status.${s.k}`), n: devices.filter((d) => d.status === s.k).length }))
  return <div className="card"><h3>{t('cards.devicesTitle')}</h3><div className="don"><Donut items={items} /><Legend items={items} /></div></div>
}

export function VulnCard({ vulns, onAdd }) {
  const { t } = useI18n()
  const unresolved = vulns.filter((v) => (v.status || 'open') !== 'resolved')
  const items = SEV.map((s) => ({ ...s, label: t(`sev.${s.k}`), n: unresolved.filter((v) => v.severity === s.k).length }))
  return (
    <div className="card">
      <h3>{t('cards.vulnTitle')} <span className="m" style={{ fontWeight: 400 }}>· {t('cards.vulnUnresolved')}</span> <span className="sel" style={{ cursor: 'pointer' }} title={t('cards.addVuln')} onClick={onAdd}>+</span></h3>
      <div className="don"><Donut items={items} /><Legend items={items} /></div>
    </div>
  )
}

export function ThreatsCard({ threats }) {
  const { t, locale } = useI18n()
  const days = Array.from({ length: 7 }, (_, i) => {
    const d = new Date()
    d.setHours(0, 0, 0, 0)
    d.setDate(d.getDate() - (6 - i))
    return d
  })
  const key = (d) => new Date(d).toDateString()
  const counts = days.map((d) => threats.filter((th) => key(th.created_at) === key(d)).length)
  const top = Math.max(10, Math.ceil(Math.max(...counts) / 10) * 10)
  const empty = !counts.some(Boolean)
  return (
    <div className="card">
      <h3>{t('cards.threatsTitle')} <span className="sel">{t('cards.threatsRange')} ⌄</span></h3>
      <svg viewBox="0 0 300 150" style={{ width: '100%', marginTop: 8 }}>
        <g style={{ stroke: 'var(--map-grid)' }}><path d="M30 116h260M30 66h260M30 16h260" /></g>
        <g style={{ fill: 'var(--m)' }} fontSize="9"><text x="2" y="19">{top}</text><text x="2" y="69">{top / 2}</text><text x="6" y="119">0</text></g>
        {counts.map((n, i) => {
          const h = (n / top) * 100
          return <rect key={i} x={36 + i * 37} y={116 - h} width="28" height={h} style={{ fill: 'var(--chart)' }} />
        })}
        {days.map((d, i) => (
          <text key={i} x={36 + i * 37 + 14} y="132" textAnchor="middle" style={{ fill: 'var(--m)' }} fontSize="8">
            {d.toLocaleDateString(locale, { day: '2-digit', month: 'short' })}
          </text>
        ))}
        {empty && <text x="160" y="70" textAnchor="middle" style={{ fill: 'var(--m)' }} fontSize="10">{t('cards.noData')}</text>}
      </svg>
    </div>
  )
}
