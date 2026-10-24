import { useState } from 'react'
import { TYPES, STATUS } from '../constants'
import './DevicesPage.css'

const validIp = (v) => !v || (/^(\d{1,3}\.){3}\d{1,3}$/.test(v) && v.split('.').every((n) => Number(n) <= 255))

export default function DevicesPage({ devices, services = [], onAddClick, onUpdate, onRemove }) {
  const [q, setQ] = useState('')
  const [st, setSt] = useState('')
  const [editId, setEditId] = useState(null)
  const [draft, setDraft] = useState({})
  const [err, setErr] = useState('')

  const list = devices.filter((d) => {
    const hay = `${d.name} ${d.ip || ''} ${d.type}`.toLowerCase()
    return hay.includes(q.trim().toLowerCase()) && (!st || d.status === st)
  })

  const ports = (d) => services.filter((s) => s.device_id === d.id).map((s) => s.port).join(', ') || '—'
  const seen = (d) => (d.last_seen ? new Date(d.last_seen).toLocaleString('fr-FR') : '—')

  const startEdit = (d) => {
    setEditId(d.id)
    setDraft({ name: d.name, ip: d.ip || '', type: d.type, status: d.status })
    setErr('')
  }
  const set = (k) => (e) => setDraft({ ...draft, [k]: e.target.value })
  const save = async () => {
    const name = draft.name.trim()
    const ip = draft.ip.trim()
    if (!name) return setErr('Le nom est obligatoire.')
    if (!validIp(ip)) return setErr('Adresse IPv4 invalide (ex. 192.168.1.10).')
    await onUpdate(editId, { name, ip: ip || null, type: draft.type, status: draft.status })
    setEditId(null)
    setErr('')
  }
  const del = (d) => {
    if (window.confirm(`Supprimer « ${d.name} » ?`)) onRemove(devices.indexOf(d))
  }

  return (
    <div className="card">
      <h3>Réseau &amp; Appareils <span className="m" style={{ fontWeight: 400 }}>· {list.length} / {devices.length} appareil(s)</span></h3>
      <div className="tb">
        <input placeholder="Rechercher par nom, IP ou type…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={st} onChange={(e) => setSt(e.target.value)}>
          <option value="">Tous les statuts</option>
          {STATUS.map((s) => <option key={s.k} value={s.k}>{s.label}</option>)}
        </select>
        <button onClick={onAddClick}>+ Ajouter</button>
      </div>
      {err && <div className="err">{err}</div>}
      <div className="tw">
        <table className="dt">
          <thead><tr><th>Nom</th><th>Adresse IP</th><th>Type</th><th>Statut</th><th>Ports ouverts</th><th>Dernier vu</th><th>Actions</th></tr></thead>
          <tbody>
            {list.map((d) => {
              const s = STATUS.find((x) => x.k === d.status)
              return editId === d.id ? (
                <tr key={d.id}>
                  <td><input value={draft.name} onChange={set('name')} /></td>
                  <td><input value={draft.ip} onChange={set('ip')} placeholder="192.168.1.10" /></td>
                  <td><select value={draft.type} onChange={set('type')}>{Object.keys(TYPES).map((t) => <option key={t}>{t}</option>)}</select></td>
                  <td><select value={draft.status} onChange={set('status')}>{STATUS.map((x) => <option key={x.k} value={x.k}>{x.label}</option>)}</select></td>
                  <td>{ports(d)}</td><td>{seen(d)}</td>
                  <td><button onClick={save}>Enregistrer</button><button className="x" onClick={() => { setEditId(null); setErr('') }}>Annuler</button></td>
                </tr>
              ) : (
                <tr key={d.id}>
                  <td>{d.name}</td>
                  <td>{d.ip || '—'}{d.mac && <div className="m">{d.mac}</div>}</td>
                  <td>{d.type}</td>
                  <td style={{ color: s.color }}>● {s.label}</td>
                  <td>{ports(d)}</td><td>{seen(d)}</td>
                  <td><button className="x" onClick={() => startEdit(d)}>Modifier</button><button className="del" onClick={() => del(d)}>Supprimer</button></td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {!devices.length && <p className="m" style={{ padding: '22px 0', textAlign: 'center' }}>Aucun appareil. Utilisez « + Ajouter » pour en saisir un.</p>}
      {!!devices.length && !list.length && <p className="m" style={{ padding: '22px 0', textAlign: 'center' }}>Aucun résultat.</p>}
    </div>
  )
}
