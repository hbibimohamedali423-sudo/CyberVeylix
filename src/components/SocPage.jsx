import { useState } from 'react'
import { ALERT_SOURCES, SEV } from '../constants'
import { useI18n } from '../i18n/context.js'
import { buildTimeline, isActiveCommand, sourceOf, TIMELINE_GROUPS } from '../lib/findings.js'
import { commandKindText, commandResultText, commandTarget } from '../lib/commandText.js'
import SensorCard from './SensorCard'
import './SocPage.css'

const FILTERS = ['all', 'alerts', 'vulns', 'actions']

// Surveillance : journal en direct de tout ce que la base a enregistré (rafraîchi par le tableau de bord).
export default function SocPage({ alerts = [], vulns = [], commands = [], blocked = [], sensors = [], sensorsLoaded, sensorsMissing }) {
  const { t, locale } = useI18n()
  const [filter, setFilter] = useState('all')
  const when = (v) => (v ? new Date(v).toLocaleString(locale) : '—')
  const sev = (k) => SEV.find((s) => s.k === k)
  const sensorName = (id) => sensors.find((s) => s.id === id)?.name || '—'

  const timeline = buildTimeline({ alerts, vulns, commands, blocked })
  const shown = timeline.filter((i) => filter === 'all' || TIMELINE_GROUPS[i.type] === filter)

  const kpis = [
    ['openAlerts', alerts.filter((a) => (a.status || 'open') === 'open').length],
    ['openVulns', vulns.filter((v) => (v.status || 'open') !== 'resolved').length],
    ['activeBlocks', blocked.filter((b) => b.status === 'active').length],
    ['pending', commands.filter(isActiveCommand).length],
  ]

  const describe = (i) => {
    const r = i.row
    switch (i.type) {
      case 'alert': {
        const src = sourceOf(r)
        return { title: r.title, meta: [ALERT_SOURCES.includes(src) ? t(`sources.${src}`) : src, r.source_ip || r.source_mac].filter(Boolean).join(' · '), sev: r.severity }
      }
      case 'vuln_new': return { title: r.title, meta: t('soc.vulnNew'), sev: r.severity }
      case 'vuln_resolved': return { title: r.title, meta: t('soc.vulnResolved') }
      case 'command': {
        const target = commandTarget(t, r)
        const status = t(`scan.status.${r.status}`)
        const result = r.result ? commandResultText(t, r.result) : ''
        return { title: `${commandKindText(t, r.kind)}${target ? ` — ${target}` : ''}`, meta: [status, result, sensorName(r.sensor_id)].filter(Boolean).join(' · ') }
      }
      case 'block': return { title: t('soc.blocked', { ip: r.ip }), meta: [t(`blocks.by.${r.blocked_by}`), r.reason, sensorName(r.sensor_id)].filter(Boolean).join(' · ') }
      case 'unblock': return { title: t('soc.unblocked', { ip: r.ip }), meta: sensorName(r.sensor_id) }
      default: return { title: i.type, meta: '' }
    }
  }

  return (
    <>
      <SensorCard sensors={sensors} loaded={sensorsLoaded} missing={sensorsMissing} />
      <div className="card soc-page">
        <h3>{t('soc.title')}</h3>
        <p className="m">{t('soc.intro')}</p>
        <ul className="soc-kpis">
          {kpis.map(([k, n]) => <li key={k}><b>{n}</b><span>{t(`soc.kpi.${k}`)}</span></li>)}
        </ul>
        <div className="soc-filters" role="group" aria-label={t('soc.filterAria')}>
          {FILTERS.map((f) => (
            <button key={f} type="button" className={filter === f ? 'on' : ''} aria-pressed={filter === f} onClick={() => setFilter(f)}>
              {t(`soc.filter.${f}`)}
            </button>
          ))}
        </div>
        {!shown.length ? <p className="m soc-empty">{t('soc.empty')}</p> : (
          <ol className="soc-list">
            {shown.map((i) => {
              const d = describe(i)
              const s = d.sev ? sev(d.sev) : null
              return (
                <li key={i.id} className={`soc-${i.type}`}>
                  <span className="soc-dot" style={s ? { background: s.color } : undefined} aria-hidden="true" />
                  <time dateTime={i.at}>{when(i.at)}</time>
                  <span className="soc-type">{t(`soc.type.${i.type}`)}</span>
                  <div className="soc-body">
                    <div className="soc-title">{s && <span className="sr-only">{t(`sev.${d.sev}`)} : </span>}{d.title}</div>
                    {d.meta && <div className="m" dir="auto">{d.meta}</div>}
                  </div>
                </li>
              )
            })}
          </ol>
        )}
      </div>
    </>
  )
}
