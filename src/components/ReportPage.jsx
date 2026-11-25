import { ALERT_SOURCES, ALERT_STATUS, CONFIDENCE, SEV, STATUS, TYPES, VULN_SOURCES } from '../constants'
import { useI18n } from '../i18n/context.js'
import { sensorState, sourceOf } from '../lib/findings.js'
import { CveLinks } from './FindingBits.jsx'
import { datasetCsv } from '../lib/exports.js'
import './ReportPage.css'

// Rapport imprimable (Imprimer → « Enregistrer au format PDF ») construit uniquement
// à partir des lignes lues dans Supabase : aucune valeur calculée n'est inventée.
const sevRank = (k) => { const i = SEV.findIndex((s) => s.k === k); return i < 0 ? SEV.length : i }
const time = (v) => { const n = v ? new Date(v).getTime() : NaN; return Number.isFinite(n) ? n : 0 }
const MAX_ALERTS = 50

// Fichier téléchargé par le navigateur (aucun envoi ailleurs).
const download = (filename, text) => {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/csv;charset=utf-8' }))
  const a = document.createElement('a')
  a.href = url; a.download = filename
  document.body.appendChild(a); a.click(); a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export default function ReportPage({ email, devices = [], services = [], vulns = [], alerts = [], threats = [], sensors = [], sensorsMissing, onRecord }) {
  const { t, locale } = useI18n()
  const when = (v) => (v ? new Date(v).toLocaleString(locale) : '—')
  const label = (list, prefix, k) => (list.some((x) => (x.k ?? x) === k) ? t(`${prefix}.${k}`) : (k || '—'))
  const deviceName = (id) => (id == null ? '—' : devices.find((d) => d.id === id)?.name || t('vulnsPage.deviceDeleted'))

  const openVulns = vulns.filter((v) => (v.status || 'open') !== 'resolved')
    .sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || time(b.created_at) - time(a.created_at))
  const openAlerts = alerts.filter((a) => (a.status || 'open') !== 'resolved')
  const recentAlerts = alerts.slice().sort((a, b) => time(b.created_at) - time(a.created_at)).slice(0, MAX_ALERTS)
  const online = devices.filter((d) => d.status === 'on').length
  const bySev = SEV.map((s) => [s, openVulns.filter((v) => v.severity === s.k).length])
  const servicesOf = (d) => services.filter((s) => s.device_id === d.id).sort((a, b) => (a.port || 0) - (b.port || 0))

  return (
    <div className="card report-print">
      <div className="report-head">
        <div>
          <h2>{t('report.title')}</h2>
          <p className="m">{t('report.generated', { date: when(new Date().toISOString()) })}{email ? ` · ${email}` : ''}</p>
          <p className="m">{t('report.sourceNote')}</p>
        </div>
        <button type="button" className="no-print" onClick={() => { onRecord?.({ kind: 'security', row_count: devices.length }); window.print() }}>{t('report.print')}</button>
      </div>
      <div className="report-exports no-print" role="group" aria-label={t('reportExtra.exportsAria')}>
        {[['devices', devices], ['alerts', alerts], ['vulnerabilities', vulns], ['threats', threats]].map(([kind, rows]) => (
          <button key={kind} type="button" onClick={() => {
            const f = datasetCsv(kind, rows, { services })
            download(f.filename, f.text)
            onRecord?.({ kind, row_count: f.rowCount })
          }}>{t('reportExtra.exportCsv', { what: t(`reportKind.${kind}`) })}</button>
        ))}
      </div>

      <section>
        <h3>{t('report.summary')}</h3>
        <ul className="report-kpis">
          <li><b>{devices.length}</b><span>{t('report.devices')}</span></li>
          <li><b>{online}</b><span>{t('report.online')}</span></li>
          <li><b>{openVulns.length}</b><span>{t('report.openVulns')}</span></li>
          <li><b>{openAlerts.length}</b><span>{t('report.openAlerts')}</span></li>
          <li><b>{services.length}</b><span>{t('report.services')}</span></li>
        </ul>
        <p className="m">{bySev.map(([s, n]) => `${t(`sev.${s.k}`)} : ${n}`).join(' · ')}</p>
      </section>

      <section>
        <h3>{t('report.sensors')}</h3>
        {sensorsMissing ? <p className="m">{t('sensors.missing')}</p> : !sensors.length ? <p className="m">{t('sensors.empty')}</p> : (
          <table><thead><tr><th>{t('report.colName')}</th><th>IP</th><th>{t('report.colState')}</th><th>{t('report.colHeartbeat')}</th><th>{t('report.colScan')}</th></tr></thead>
            <tbody>{sensors.map((s) => {
              const st = sensorState(s)
              return <tr key={s.id}><td>{s.name}</td><td dir="ltr">{s.ip || '—'}</td><td>{t(`sensors.state_${st.state}`)}</td><td>{when(s.last_heartbeat)}</td><td>{when(s.last_scan_at)}</td></tr>
            })}</tbody></table>
        )}
      </section>

      <section>
        <h3>{t('report.vulnsTitle')} ({openVulns.length})</h3>
        {!openVulns.length ? <p className="m">{t('vulnsPage.empty')}</p> : (
          <table><thead><tr><th>{t('alertsPage.colTitle')}</th><th>{t('vulnsPage.colDevice')}</th><th>{t('alertsPage.colSev')}</th><th>{t('vulnDetail.colCve')}</th><th>{t('vulnDetail.colConfidence')}</th><th>{t('sources.col')}</th><th>{t('vulnDetail.remediation')}</th></tr></thead>
            <tbody>{openVulns.map((v) => (
              <tr key={v.id}>
                <td>{v.title}{v.evidence && <div className="m pre">{v.evidence}</div>}</td>
                <td>{deviceName(v.device_id)}</td>
                <td>{label(SEV, 'sev', v.severity)}</td>
                <td><CveLinks row={v} /></td>
                <td>{v.confidence ? label(CONFIDENCE, 'confidence', v.confidence) : '—'}</td>
                <td>{label(VULN_SOURCES, 'sources', sourceOf(v))}</td>
                <td className="pre">{v.remediation || '—'}</td>
              </tr>
            ))}</tbody></table>
        )}
      </section>

      <section>
        <h3>{t('report.devicesTitle')} ({devices.length})</h3>
        {!devices.length ? <p className="m">{t('devicesPage.empty')}</p> : (
          <table><thead><tr><th>{t('devicesPage.colName')}</th><th>{t('devicesPage.colIp')}</th><th>{t('devicesPage.colType')}</th><th>{t('devicesPage.colStatus')}</th><th>{t('deviceDetail.services')}</th><th>{t('devicesPage.colSeen')}</th></tr></thead>
            <tbody>{devices.map((d) => (
              <tr key={d.id}>
                <td>{d.name}</td><td dir="ltr">{d.ip || '—'}</td>
                <td>{d.type && Object.hasOwn(TYPES, d.type) ? t(`type.${d.type}`) : (d.type || t('type.unknown'))}</td>
                <td>{label(STATUS, 'status', d.status)}</td>
                <td dir="ltr">{servicesOf(d).map((s) => [s.port, s.service, s.version].filter(Boolean).join(' ')).join(', ') || '—'}</td>
                <td>{when(d.last_seen)}</td>
              </tr>
            ))}</tbody></table>
        )}
      </section>

      <section>
        <h3>{t('report.alertsTitle', { n: MAX_ALERTS })} ({recentAlerts.length} / {alerts.length})</h3>
        {!recentAlerts.length ? <p className="m">{t('alertsPage.empty')}</p> : (
          <table><thead><tr><th>{t('alertsPage.colCreated')}</th><th>{t('alertsPage.colTitle')}</th><th>{t('sources.col')}</th><th>{t('alertsPage.colSev')}</th><th>{t('alertsPage.colStatus')}</th></tr></thead>
            <tbody>{recentAlerts.map((a) => (
              <tr key={a.id}>
                <td>{when(a.created_at)}</td>
                <td>{a.title}{a.detail && <div className="m pre">{a.detail}</div>}</td>
                <td>{label(ALERT_SOURCES, 'sources', sourceOf(a))}</td>
                <td>{label(SEV, 'sev', a.severity)}</td>
                <td>{label(ALERT_STATUS, 'alertStatus', a.status || 'open')}</td>
              </tr>
            ))}</tbody></table>
        )}
      </section>
    </div>
  )
}
