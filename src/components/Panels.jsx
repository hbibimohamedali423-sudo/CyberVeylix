import Donut from './Donut'
import { KPIS, TYPES, STATUS, SEV, SLOTS } from '../constants'

export const Banner = () => (
  <section className="banner">
    <div><small>CYBERVEYLIX</small><h1>Tableau de bord</h1><div style={{ fontSize: 15 }}>Vue d’ensemble de votre infrastructure et de votre sécurité</div></div>
    <div className="slogan">Plus qu’un outil…<br />une intelligence réseau.</div>
  </section>
)

export function Kpis({ counts }) {
  return (
    <section className="kpis">
      {KPIS.map((k, i) => (
        <div key={k.label} className={`card kpi ${k.cls}`}>
          <div className="ic" />
          <div><div>{k.label}</div><b>{counts[i] || '—'}</b><br /><small>{counts[i] ? 'Saisi manuellement' : 'Aucune donnée'}</small></div>
        </div>
      ))}
    </section>
  )
}

export function NetworkMap({ devices, onAdd }) {
  return (
    <div className="card map">
      <h3>Carte réseau en temps réel <span className="live" style={{ color: 'var(--m)' }}>● Hors ligne</span></h3>
      <div className="legend">
        {Object.entries(TYPES).map(([t, c]) => <div key={t}><i style={{ background: c }} />{t}</div>)}
        <div><i style={{ background: 'var(--r)' }} />Menace détectée</div>
      </div>
      <svg className="mapsvg" viewBox="0 0 600 340" preserveAspectRatio="xMidYMid slice">
        <g fill="#0b1f3d" stroke="#14406b" opacity=".6"><path d="M150 200l120-70 150 70-120 80z" /><path d="M270 130l120-60 140 60-110 70z" /><path d="M220 270l110-60 120 60-110 55z" /></g>
        {!devices.length && <text x="300" y="200" textAnchor="middle" fill="#8fa6c0" fontSize="14">Aucun appareil détecté</text>}
        {devices.map((d, i) => {
          const [x, y] = SLOTS[i % SLOTS.length]
          const st = STATUS.find((s) => s.k === d.status)
          return (
            <g key={i}>
              <title>{d.name} — {d.ip || '—'}</title>
              <circle cx={x} cy={y} r="9" fill={TYPES[d.type]} stroke={st.color} strokeWidth="2" />
              <text x={x} y={y + 22} textAnchor="middle" fill="#8fa6c0" fontSize="9">{d.name}</text>
            </g>
          )
        })}
      </svg>
      <div className="ctrl"><span style={{ cursor: 'pointer' }} title="Ajouter un appareil" onClick={onAdd}>+</span><span>◎</span><span>↻</span><span style={{ fontSize: 11 }}>3D</span></div>
      <div className="site">📍 Site principal<br />—</div>
    </div>
  )
}

export const Activity = () => (
  <div className="card">
    <h3>Activité réseau <span className="live" style={{ float: 'right', color: 'var(--m)' }}>● —</span></h3>
    <div className="m" style={{ textAlign: 'right', margin: '8px 0' }}>● Entrant &nbsp;<span style={{ color: 'var(--pu)' }}>● Sortant</span></div>
    <svg viewBox="0 0 260 170" style={{ width: '100%' }}>
      <g stroke="#14304f"><path d="M40 10h210M40 45h210M40 80h210M40 115h210M40 150h210" /></g>
      <text x="145" y="85" textAnchor="middle" fill="#8fa6c0" fontSize="10">En attente de données</text>
    </svg>
    <div className="bw"><small>Bande passante actuelle</small><br /><b>—</b></div>
    <div className="bw"><small>Paquets analysés</small><br /><b>—</b></div>
  </div>
)

function Legend({ items }) {
  const t = items.reduce((a, i) => a + i.n, 0)
  return (
    <table><tbody>
      {items.map((i) => <tr key={i.label}><td style={{ color: i.color }}>● {i.label}</td><td>{t ? `${i.n} · ${Math.round((i.n / t) * 100)}%` : '—'}</td></tr>)}
    </tbody></table>
  )
}

export function DevicesCard({ devices }) {
  const items = STATUS.map((s) => ({ ...s, n: devices.filter((d) => d.status === s.k).length }))
  return <div className="card"><h3>État des appareils</h3><div className="don"><Donut items={items} /><Legend items={items} /></div></div>
}

export function VulnCard({ vulns, onAdd }) {
  const items = SEV.map((s) => ({ ...s, n: vulns.filter((v) => v.sev === s.k).length }))
  return (
    <div className="card">
      <h3>Vulnérabilités par sévérité <span className="sel" style={{ cursor: 'pointer' }} title="Ajouter une vulnérabilité" onClick={onAdd}>+</span></h3>
      <div className="don"><Donut items={items} /><Legend items={items} /></div>
    </div>
  )
}

export const ThreatsCard = () => (
  <div className="card">
    <h3>Évolution des menaces <span className="sel">7 jours ⌄</span></h3>
    <svg viewBox="0 0 300 150" style={{ width: '100%', marginTop: 8 }}>
      <g stroke="#14304f"><path d="M30 116h260M30 90h260M30 64h260M30 38h260M30 12h260" /></g>
      <text x="160" y="70" textAnchor="middle" fill="#8fa6c0" fontSize="10">Aucune donnée</text>
    </svg>
  </div>
)
