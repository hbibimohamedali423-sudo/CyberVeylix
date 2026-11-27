import { useI18n } from '../i18n/context.js'
import { sensorState } from '../lib/findings.js'
import './SensorCard.css'

// État des capteurs tel qu'enregistré dans la table sensors (pouls last_heartbeat), rien d'autre.
export default function SensorCard({ sensors = [], loaded, missing }) {
  const { t, locale } = useI18n()
  const when = (v) => (v ? new Date(v).toLocaleString(locale) : '—')
  return (
    <div className="card sensor-card">
      <h3>{t('sensors.title')}</h3>
      {missing ? <p className="m">{t('sensors.missing')}</p>
        : !loaded ? <p className="m">{t('common.loading')}</p>
        : !sensors.length ? <p className="m">{t('sensors.empty')}</p>
        : (
          <ul>
            {sensors.map((s) => {
              const st = sensorState(s)
              return (
                <li key={s.id} className={`sensor-${st.state}`}>
                  <span className="sensor-dot" aria-hidden="true" />
                  <div>
                    <b>{s.name}</b>{s.ip && <span className="m" dir="ltr"> · {s.ip}</span>}{s.version && <span className="m"> · v{s.version}</span>}
                    <div className="sensor-state">
                      {st.state === 'running' && (st.since ? t('sensors.runningSince', { date: when(st.since) }) : t('sensors.running'))}
                      {st.state === 'stopped' && t('sensors.stoppedSince', { date: when(st.since) })}
                      {st.state === 'never' && t('sensors.never')}
                    </div>
                    <div className="m">
                      {t('sensors.lastHeartbeat', { date: when(s.last_heartbeat) })}
                      {' · '}{t('sensors.lastScan', { date: when(s.last_scan_at) })}
                      {' · '}{t('sensors.honeypot')} : {s.honeypot ? t('common.yes') : t('common.no')}
                      {' · '}{t('sensors.vulnScan')} : {s.vuln_scan ? t('common.yes') : t('common.no')}
                    </div>
                  </div>
                </li>
              )
            })}
          </ul>
        )}
    </div>
  )
}
