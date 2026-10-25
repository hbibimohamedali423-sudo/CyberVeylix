import { useState } from 'react'
import { ALERT_STATUS, SEV } from '../constants'
import './AlertsPage.css'

// Statut réel d’une alerte : repli sur le défaut de la colonne (open) si null.
const stateOf = (a) => a.status || 'open'
const when = (v) => (v ? new Date(v).toLocaleString('fr-FR') : '—')
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
const find = (list, k) => list.find((x) => x.k === k)

export default function AlertsPage({ alerts, onUpdate }) {
  const [sev, setSev] = useState('')
  const [status, setStatus] = useState('')
  const [err, setErr] = useState('')
  const [busyId, setBusyId] = useState(null)

  const list = alerts
    .filter((a) => (!sev || a.severity === sev) && (!status || stateOf(a) === status))
    .sort(newestFirst)

  const run = async (a, patch) => {
    setErr('')
    setBusyId(a.id)
    try {
      const msg = await onUpdate(a.id, patch)
      if (msg) setErr(msg)
    } catch {
      setErr('Échec de la mise à jour. Vérifiez votre connexion puis réessayez.')
    } finally {
      setBusyId(null)
    }
  }

  const acknowledge = (a) => run(a, { status: 'ack', acknowledged_at: new Date().toISOString() })
  const resolve = (a) => {
    if (window.confirm(`Résoudre l’alerte « ${a.title} » ?`)) {
      run(a, { status: 'resolved', resolved_at: new Date().toISOString() })
    }
  }

  return (
    <div className="card alerts-page">
      <h3>
        Menaces &amp; Incidents
        <span className="m" style={{ fontWeight: 400 }}> · Alertes · {list.length} / {alerts.length}</span>
      </h3>
      <div className="alerts-bar">
        <label>Gravité
          <select value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="">Toutes les gravités</option>
            {SEV.map((s) => <option key={s.k} value={s.k}>{s.label}</option>)}
          </select>
        </label>
        <label>Statut
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">Tous les statuts</option>
            {ALERT_STATUS.map((s) => <option key={s.k} value={s.k}>{s.label}</option>)}
          </select>
        </label>
      </div>
      {err && <div className="alerts-err" role="alert">{err}</div>}
      <div className="alerts-tw">
        <table className="alerts-dt">
          <thead>
            <tr>
              <th>Titre</th><th>Gravité</th><th>Statut</th><th>Détail</th>
              <th>Créée le</th><th>Prise en compte</th><th>Résolue</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {list.map((a) => {
              const s = find(SEV, a.severity)
              const st = find(ALERT_STATUS, stateOf(a))
              const busy = busyId === a.id
              return (
                <tr key={a.id}>
                  <td>{a.title}</td>
                  <td><span style={{ color: s?.color || 'var(--m)' }}>● {s?.label || a.severity || '—'}</span></td>
                  <td><span style={{ color: st?.color || 'var(--m)' }}>● {st?.label || stateOf(a)}</span></td>
                  <td className="detail">{a.detail || '—'}</td>
                  <td>{when(a.created_at)}</td>
                  <td>{when(a.acknowledged_at)}</td>
                  <td>{when(a.resolved_at)}</td>
                  <td className="acts">
                    {stateOf(a) === 'open' && (
                      <button type="button" className="ack" disabled={busy}
                        aria-label={`Prendre en compte « ${a.title} »`} onClick={() => acknowledge(a)}>
                        Prendre en compte
                      </button>
                    )}
                    {(stateOf(a) === 'open' || stateOf(a) === 'ack') && (
                      <button type="button" className="solve" disabled={busy}
                        aria-label={`Résoudre « ${a.title} »`} onClick={() => resolve(a)}>
                        Résoudre
                      </button>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {!alerts.length && <p className="alerts-empty">Aucune alerte</p>}
      {!!alerts.length && !list.length && <p className="alerts-empty">Aucun résultat</p>}
    </div>
  )
}
