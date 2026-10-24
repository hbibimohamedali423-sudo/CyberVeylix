import { useState } from 'react'
import { NAV } from '../constants'

export default function Sidebar() {
  const [active, setActive] = useState(0)
  return (
    <div>
      <nav>{NAV.map((n, i) => <a key={n} className={i === active ? 'on' : ''} onClick={() => setActive(i)}><i />{n}</a>)}</nav>
      <div className="promo"><div className="shield" /><b>Une vision complète<br />de votre sécurité réseau</b><span>Détecter • Analyser • Protéger</span></div>
      <div className="tg"><span>◐ Mode Sombre</span><div className="sw" /></div>
      <div className="tg" style={{ marginTop: 14 }}><span>🌐 FR</span><span>⌄</span></div>
    </div>
  )
}
