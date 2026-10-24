import { CATS, SEV } from '../constants'

const hm = (d) => new Date(d).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })

function Card({ title, onAdd, children }) {
  return (
    <div className="card">
      <h3>{title}{onAdd && <span className="sel" style={{ cursor: 'pointer' }} onClick={onAdd}>+</span>}</h3>
      {children}
    </div>
  )
}

const Empty = ({ text }) => <p className="m" style={{ padding: '22px 0', textAlign: 'center' }}>{text}</p>

export default function RightColumn({ alerts, threats, onAddAlert, onAddThreat }) {
  const recent = [...alerts].reverse().slice(0, 4)
  const counts = CATS.map((c) => ({ ...c, n: threats.filter((t) => t.category === c.k).length }))
    .filter((c) => c.n).sort((a, b) => b.n - a.n)
  const max = counts[0]?.n || 1

  return (
    <aside>
      <Card title="Alertes & Notifications" onAdd={onAddAlert}>
        {recent.length ? recent.map((a) => (
          <div className="row" key={a.id}>
            <div className="ic" style={{ borderColor: SEV.find((s) => s.k === a.severity).color, width: 34, height: 34 }} />
            <div><b>{a.title}</b><small>{a.detail}</small></div>
            <small>{hm(a.created_at)}</small>
          </div>
        )) : <Empty text="Aucune alerte" />}
      </Card>
      <Card title="Top menaces récentes" onAdd={onAddThreat}>
        {counts.length ? counts.slice(0, 5).map((c) => (
          <div className="row" key={c.k}>
            <div><b>{c.label}</b><div className="bar"><i style={{ width: `${(c.n / max) * 100}%`, background: c.color }} /></div></div>
            {c.n}
          </div>
        )) : <Empty text="Aucune menace enregistrée" />}
      </Card>
      <Card title="Derniers rapports"><Empty text="Aucun rapport" /></Card>
    </aside>
  )
}
