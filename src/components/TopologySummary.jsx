import { useI18n } from '../i18n/context.js'
import './TopologySummary.css'

export default function TopologySummary({ devices = [], networks = [], loaded = true, lastScan = null, onOpen }) {
  const { t, locale } = useI18n()
  let online = 0

  for (const device of devices) {
    if (device.status === 'on') online += 1
  }

  const hasScan = Number.isFinite(lastScan) && lastScan > 0
  const scanLabel = hasScan ? new Date(lastScan).toLocaleString(locale) : t('topologySummary.never')

  return (
    <section className="card topology-summary" aria-labelledby="topology-summary-title">
      <div className="ts-head">
        <div>
          <h3 id="topology-summary-title">{t('topologySummary.title')}</h3>
          <p className="m">{t('topologySummary.subtitle')}</p>
        </div>
        <button type="button" className="ts-open" onClick={onOpen}>
          {t('topologySummary.open')}<span aria-hidden="true">→</span>
        </button>
      </div>
      {!loaded ? (
        <p className="ts-state" role="status">{t('topologySummary.loading')}</p>
      ) : (
        <>
          <dl className="ts-stats">
            <div><dt>{t('topologySummary.devices')}</dt><dd>{devices.length}</dd></div>
            <div><dt>{t('topologySummary.networks')}</dt><dd>{networks.length}</dd></div>
            <div><dt>{t('topologySummary.online')}</dt><dd>{online}</dd></div>
            <div><dt>{t('topologySummary.lastScan')}</dt><dd className="ts-date">{scanLabel}</dd></div>
          </dl>
          {!devices.length && <p className="m ts-empty">{t('topologySummary.empty')}</p>}
        </>
      )}
    </section>
  )
}
