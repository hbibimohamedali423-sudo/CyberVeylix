import { useI18n } from '../i18n/context.js'

export default function Topbar({ email, onLogout, connected = true, lastScan = null }) {
  const { t, locale } = useI18n()
  return (
    <header className="top">
      <div className="logo">CyberVeylix<small>NETWORK INTELLIGENCE &amp; CYBERSECURITY</small></div>
      <div className="search"><span>{t('topbar.search')}</span><small>{t('topbar.shortcut')}</small></div>
      <div className="right">
        <div>
          <span className="dot" style={connected ? undefined : { background: 'var(--r)' }} />
          {connected ? t('topbar.connected') : t('topbar.syncError')}
          <br /><small>{t('topbar.lastScan', { date: lastScan === null ? '—' : new Date(lastScan).toLocaleString(locale) })}</small>
        </div>
        <span>🔔</span><span>⚙</span>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div className="av" />
          <div>{email}<br /><small style={{ cursor: 'pointer' }} onClick={onLogout}>{t('topbar.logout')}</small></div>
        </div>
      </div>
    </header>
  )
}
