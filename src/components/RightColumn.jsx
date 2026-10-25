import { CATS, SEV } from '../constants'
import './RightColumn.css'

const hm = (d) => new Date(d).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })

// Statut réel d’une alerte : repli sur le défaut de la colonne (open) si null.
const stateOf = (a) => a.status || 'open'
const time = (v) => {
  if (!v) return null
  const t = new Date(v).getTime()
  return Number.isFinite(t) ? t : null
}
// Tri décroissant par created_at, dates invalides ou absentes en fin de liste.
const newestFirst = (a, b) => {
  const ta = time(a.created_at)
  const tb = time(b.created_at)
  if (ta === null && tb === null) return 0
  if (ta === null) return 1
  if (tb === null) return -1
  return tb - ta
}

function Card({ title, onAdd, badge = 0, cls = '', children }) {
  return (
    <div className={`card ${cls}`.trim()}>
      <h3>
        {title}
        {badge > 0 && <span className="alert-badge">{badge}</span>}
        {onAdd && <span className="sel" style={{ cursor: 'pointer' }} onClick={onAdd}>+</span>}
      </h3>
      {children}
    </div>
  )
}

const Empty = ({ text }) => <p className="m" style={{ padding: '22px 0', textAlign: 'center' }}>{text}</p>

export default function RightColumn({ alerts, threats, onAddAlert, onAddThreat }) {
  const visible = alerts.filter((a) => stateOf(a) !== 'resolved').sort(newestFirst).slice(0, 4)
  const openCount = alerts.filter((a) => stateOf(a) === 'open').length
  const counts = CATS.map((c) => ({ ...c, n: threats.filter((t) => t.category === c.k).length }))
    .filter((c) => c.n).sort((a, b) => b.n - a.n)
  const max = counts[0]?.n || 1

  return (
    <aside>
      <Card title="Alertes & Notifications" cls="alerts-card" badge={openCount} onAdd={onAddAlert}>
        {visible.length ? visible.map((a) => (
          <div className="row" key={a.id}>
            <div className="ic" style={{ borderColor: SEV.find((s) => s.k === a.severity).color, width: 34, height: 34 }} />
            <div>
              <b>{a.title}</b>
              <small>{a.detail}</small>
              {stateOf(a) === 'ack' && <small style={{ display: 'block', color: 'var(--o)' }}>Prise en compte</small>}
            </div>
            <small>{hm(a.created_at)}</small>
          </div>
        )) : <Empty text={alerts.length ? 'Aucune alerte ouverte' : 'Aucune alerte'} />}
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
