const Empty = ({ title, text }) => (
  <div className="card"><h3>{title}<span className="vt">Voir tout ›</span></h3><p className="m" style={{ padding: '22px 0', textAlign: 'center' }}>{text}</p></div>
)

export default function RightColumn() {
  return (
    <aside>
      <Empty title="Alertes & Notifications" text="Aucune alerte" />
      <Empty title="Top menaces récentes" text="Aucune menace enregistrée" />
      <Empty title="Derniers rapports" text="Aucun rapport" />
    </aside>
  )
}
