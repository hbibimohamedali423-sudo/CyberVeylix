import Donut from './Donut'
import { KPIS, TYPES, STATUS, SEV, SLOTS } from '../constants'
import { useI18n } from '../i18n/context.js'

export function Banner() {
  const { t } = useI18n()
  return (
    <section className="banner">
      <div><small>CYBERVEYLIX</small><h1>{t('banner.title')}</h1><div style={{ fontSize: 15 }}>{t('banner.subtitle')}</div></div>
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

export function NetworkMap({ devices, onAdd }) {
  const { t } = useI18n()
  return (
    <div className="card map">
      <h3>{t('map.title')} <span className="live" style={{ color: 'var(--m)' }}>● {t('map.offline')}</span></h3>
      <div className="legend">
        {Object.entries(TYPES).map(([ty, c]) => <div key={ty}><i style={{ background: c }} />{t(`type.${ty}`)}</div>)}
        <div><i style={{ background: 'var(--r)' }} />{t('map.threat')}</div>
      </div>
      <svg className="mapsvg" viewBox="0 0 600 340" preserveAspectRatio="xMidYMid slice">
        <g fill="#0b1f3d" stroke="#14406b" opacity=".6"><path d="M150 200l120-70 150 70-120 80z" /><path d="M270 130l120-60 140 60-110 70z" /><path d="M220 270l110-60 120 60-110 55z" /></g>
        {!devices.length && <text x="300" y="200" textAnchor="middle" fill="#8fa6c0" fontSize="14">{t('map.noDevices')}</text>}
        {devices.map((d, i) => {
          const [x, y] = SLOTS[i % SLOTS.length]
          const st = STATUS.find((s) => s.k === d.status)
          return (
            <g key={i}>
              <title>{d.name} — {d.ip || '—'}</title>
              <circle cx={x} cy={y} r="9" fill={TYPES[d.type]} stroke={st?.color} strokeWidth="2" />
              <text x={x} y={y + 22} textAnchor="middle" fill="#8fa6c0" fontSize="9">{d.name}</text>
            </g>
          )
        })}
      </svg>
      <div className="ctrl"><span style={{ cursor: 'pointer' }} title={t('map.addDevice')} onClick={onAdd}>+</span><span>◎</span><span>↻</span><span style={{ fontSize: 11 }}>3D</span></div>
      <div className="site">📍 {t('map.site')}<br />—</div>
    </div>
  )
}

export function Activity() {
  const { t } = useI18n()
  return (
    <div className="card">
      <h3>{t('activity.title')} <span className="live" style={{ float: 'inline-end', color: 'var(--m)' }}>● —</span></h3>
      <div className="m" style={{ textAlign: 'end', margin: '8px 0' }}>● {t('activity.inbound')} &nbsp;<span style={{ color: 'var(--pu)' }}>● {t('activity.outbound')}</span></div>
      <svg viewBox="0 0 260 170" style={{ width: '100%' }}>
        <g stroke="#14304f"><path d="M40 10h210M40 45h210M40 80h210M40 115h210M40 150h210" /></g>
        <text x="145" y="85" textAnchor="middle" fill="#8fa6c0" fontSize="10">{t('activity.waiting')}</text>
      </svg>
      <div className="bw"><small>{t('activity.bandwidth')}</small><br /><b>—</b></div>
      <div className="bw"><small>{t('activity.packets')}</small><br /><b>—</b></div>
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
        <g stroke="#14304f"><path d="M30 116h260M30 66h260M30 16h260" /></g>
        <g fill="#8fa6c0" fontSize="9"><text x="2" y="19">{top}</text><text x="2" y="69">{top / 2}</text><text x="6" y="119">0</text></g>
        {counts.map((n, i) => {
          const h = (n / top) * 100
          return <rect key={i} x={36 + i * 37} y={116 - h} width="28" height={h} fill="#2f6df0" />
        })}
        {days.map((d, i) => (
          <text key={i} x={36 + i * 37 + 14} y="132" textAnchor="middle" fill="#8fa6c0" fontSize="8">
            {d.toLocaleDateString(locale, { day: '2-digit', month: 'short' })}
          </text>
        ))}
        {empty && <text x="160" y="70" textAnchor="middle" fill="#8fa6c0" fontSize="10">{t('cards.noData')}</text>}
      </svg>
    </div>
  )
}
