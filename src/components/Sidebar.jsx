import { NAV } from '../constants'

export default function Sidebar({ active, onChange }) {
  return (
    <div>
      <nav>{NAV.map((n, i) => <a key={n} className={i === active ? 'on' : ''} onClick={() => onChange(i)}><i />{n}</a>)}</nav>
      <div className="promo"><div className="shield" /><b>Une vision complète<br />de votre sécurité réseau</b><span>Détecter • Analyser • Protéger</span></div>
      <div className="tg"><span>◐ Mode Sombre</span><div className="sw" /></div>
      <div className="tg" style={{ marginTop: 14 }}><span>🌐 FR</span><span>⌄</span></div>
    </div>
  )
}
