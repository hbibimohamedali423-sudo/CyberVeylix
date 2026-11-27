import { useState } from 'react'
import { useI18n } from '../i18n/context.js'
import { parseIpList, sensorState } from '../lib/findings.js'
import './SettingsPage.css'

// Réglages de chaque capteur, enregistrés dans la table sensors et relus par le capteur (≤ 30 s).
export default function SettingsPage({ sensors = [], sensorsMissing, onUpdateSensor }) {
  const { t } = useI18n()
  return (
    <div className="card settings-page">
      <h3>{t('settings.title')}</h3>
      <p className="m">{t('settings.intro')}</p>
      {sensorsMissing ? <p className="m">{t('sensors.missing')}</p>
        : !sensors.length ? <p className="m">{t('sensors.empty')}</p>
        : sensors.map((s) => <SensorSettings key={s.id} sensor={s} onUpdate={onUpdateSensor} />)}
    </div>
  )
}

function SensorSettings({ sensor, onUpdate }) {
  const { t, locale } = useI18n()
  const [draft, setDraft] = useState(() => (sensor.trusted_ips || []).join('\n'))
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const st = sensorState(sensor)
  const when = (v) => (v ? new Date(v).toLocaleString(locale) : '—')

  const save = async (patch, message) => {
    setBusy(true); setErr(''); setOk('')
    try {
      const msg = await onUpdate(sensor.id, patch)
      if (msg) setErr(msg)
      else setOk(message)
    } catch {
      setErr(t('common.updateError'))
    } finally {
      setBusy(false)
    }
  }

  const toggleAuto = () => {
    const next = !sensor.auto_block
    if (next && !window.confirm(t('settings.confirmAuto', { name: sensor.name }))) return
    save({ auto_block: next }, next ? t('settings.autoOn') : t('settings.autoOff'))
  }

  const saveTrusted = () => {
    const { ips, invalid, tooMany } = parseIpList(draft)
    if (invalid.length) { setErr(t('settings.invalidIps', { list: invalid.slice(0, 5).join(', ') })); setOk(''); return }
    if (tooMany) { setErr(t('settings.tooMany')); setOk(''); return }
    save({ trusted_ips: ips.length ? ips : null }, t('settings.trustedSaved', { n: ips.length }))
  }

  return (
    <section className="sensor-settings" aria-labelledby={`ss-${sensor.id}`}>
      <h4 id={`ss-${sensor.id}`}>
        {sensor.name}
        <span className={`ss-state ss-${st.state}`}> · {t(`sensors.state_${st.state}`)}</span>
      </h4>
      <p className="m" dir="auto">
        {[sensor.ip, sensor.version ? `v${sensor.version}` : null, t('sensors.lastHeartbeat', { date: when(sensor.last_heartbeat) })].filter(Boolean).join(' · ')}
      </p>

      <label className="ss-switch">
        <input type="checkbox" checked={sensor.auto_block === true} disabled={busy} onChange={toggleAuto} />
        <span><b>{t('settings.autoTitle')}</b><br /><span className="m">{t('settings.autoHelp')}</span></span>
      </label>

      <label className="ss-trusted">
        <b>{t('settings.trustedTitle')}</b>
        <span className="m">{t('settings.trustedHelp')}</span>
        <textarea dir="ltr" value={draft} disabled={busy} placeholder="192.168.1.50" onChange={(e) => setDraft(e.target.value)} />
      </label>
      <button type="button" disabled={busy} onClick={saveTrusted}>{t('common.save')}</button>
      {err && <div className="ss-err" role="alert">{err}</div>}
      {ok && <div className="ss-ok" role="status">{ok}</div>}
    </section>
  )
}
