export default function Topbar({ email, onLogout, connected = true, lastScan = null }) {
  return (
    <header className="top">
      <div className="logo">CyberVeylix<small>NETWORK INTELLIGENCE &amp; CYBERSECURITY</small></div>
      <div className="search"><span>Rechercher un appareil, une IP, un domaine…</span><small>Ctrl + K</small></div>
      <div className="right">
        <div>
          <span className="dot" style={connected ? undefined : { background: 'var(--r)' }} />
          {connected ? 'Base de données connectée' : 'Erreur de synchronisation'}
          <br /><small>Dernier scan : {lastScan === null ? '—' : new Date(lastScan).toLocaleString('fr-FR')}</small>
        </div>
        <span>🔔</span><span>⚙</span>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div className="av" />
          <div>{email}<br /><small style={{ cursor: 'pointer' }} onClick={onLogout}>Déconnexion</small></div>
        </div>
      </div>
    </header>
  )
}
