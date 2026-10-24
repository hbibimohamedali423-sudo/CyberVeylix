export default function Topbar() {
  return (
    <header className="top">
      <div className="logo">CyberVeylix<small>NETWORK INTELLIGENCE &amp; CYBERSECURITY</small></div>
      <div className="search"><span>Rechercher un appareil, une IP, un domaine…</span><small>Ctrl + K</small></div>
      <div className="right">
        <div><span className="dot" style={{ background: '#5d7390' }} />En attente de connexion<br /><small>Dernière mise à jour : —</small></div>
        <span>🔔</span><span>⚙</span>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}><div className="av" /><div>Admin<br /><small>CyberVeylix</small></div></div>
      </div>
    </header>
  )
}
