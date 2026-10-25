import { useState } from 'react'
import { ALERT_STATUS, SEV } from '../constants'
import './VulnsPage.css'

// Statut réel d’une vulnérabilité : repli sur le défaut de la colonne (open) si null.
const stateOf = (v) => v.status || 'open'
const when = (d) => (d ? new Date(d).toLocaleString('fr-FR') : '—')
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
const blank = { title: '', severity: SEV[0].k, device: '', note: '' }

export default function VulnsPage({ vulns = [], devices = [], onAdd, onUpdate, onRemove }) {
  const [sev, setSev] = useState('')
  const [status, setStatus] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')
  const [editId, setEditId] = useState(null)
  const [draft, setDraft] = useState(() => ({ ...blank }))
  const [form, setForm] = useState(() => ({ ...blank }))

  const list = vulns
    .filter((v) => (!sev || v.severity === sev) && (!status || stateOf(v) === status))
    .sort(newestFirst)

  // On repasse toujours l’identifiant réel de l’appareil (type inchangé, uuid ou entier).
  const deviceOf = (id) => devices.find((d) => String(d.id) === String(id))
  const deviceIdOf = (value) => (value === '' ? null : deviceOf(value)?.id ?? null)
  const deviceLabel = (id) => {
    if (id === null || id === undefined || id === '') return '—'
    return deviceOf(id)?.name || 'Appareil supprimé'
  }

  const act = async (key, call) => {
    setErr('')
    setBusy(key)
    try {
      const msg = await call()
      if (msg) { setErr(msg); return false }
      return true
    } catch {
      setErr('Échec de l’opération. Vérifiez votre connexion puis réessayez.')
      return false
    } finally {
      setBusy('')
    }
  }

  const acknowledge = (v) => act(`ack:${v.id}`, () => onUpdate(v.id, { status: 'ack', acknowledged_at: new Date().toISOString() }))

  const resolveVuln = (v) => {
    if (!window.confirm(`Résoudre la vulnérabilité « ${v.title} » ?`)) return
    act(`resolve:${v.id}`, () => onUpdate(v.id, { status: 'resolved', resolved_at: new Date().toISOString() }))
  }

  const removeVuln = (v) => {
    if (!window.confirm(`Supprimer la vulnérabilité « ${v.title} » ?`)) return
    act(`del:${v.id}`, () => onRemove(vulns.indexOf(v)))
  }

  const startEdit = (v) => {
    setEditId(v.id)
    setDraft({
      title: v.title || '',
      severity: v.severity || SEV[0].k,
      device: v.device_id === null || v.device_id === undefined ? '' : String(v.device_id),
      note: v.note || '',
    })
    setErr('')
  }

  const save = async () => {
    const title = draft.title.trim()
    if (!title) { setErr('Le titre est obligatoire.'); return }
    const ok = await act(`save:${editId}`, () => onUpdate(editId, {
      title, severity: draft.severity, device_id: deviceIdOf(draft.device), note: draft.note.trim() || null,
    }))
    if (ok) { setEditId(null); setDraft({ ...blank }) }
  }

  const add = async (e) => {
    e.preventDefault()
    const title = form.title.trim()
    if (!title) { setErr('Le titre est obligatoire.'); return }
    const ok = await act('add', () => onAdd({
      title, severity: form.severity, device_id: deviceIdOf(form.device), note: form.note.trim() || null,
    }))
    if (ok) setForm({ ...blank })
  }

  return (
    <div className="card vulns-page">
      <h3>
        Vulnérabilités
        <span className="m" style={{ fontWeight: 400 }}> · {list.length} / {vulns.length}</span>
      </h3>

      <form className="vulns-form" onSubmit={add}>
        <label>Titre
          <input value={form.title} placeholder="Titre ou CVE (ex. CVE-2024-6387)"
            onChange={(e) => setForm({ ...form, title: e.target.value })} />
        </label>
        <label>Gravité
          <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
            {SEV.map((s) => <option key={s.k} value={s.k}>{s.label}</option>)}
          </select>
        </label>
        <label>Appareil (facultatif)
          <select value={form.device} onChange={(e) => setForm({ ...form, device: e.target.value })}>
            <option value="">Aucun</option>
            {devices.map((d) => <option key={d.id} value={d.id}>{d.name} — {d.ip || '—'}</option>)}
          </select>
        </label>
        <label className="note">Note (facultatif)
          <textarea value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} />
        </label>
        <button type="submit" disabled={busy === 'add'}>Ajouter</button>
      </form>

      <div className="vulns-bar">
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

      {err && <div className="vulns-err" role="alert">{err}</div>}

      <div className="vulns-tw">
        <table className="vulns-dt">
          <thead>
            <tr>
              <th>Titre</th><th>Gravité</th><th>Statut</th><th>Appareil</th><th>Note</th>
              <th>Créée le</th><th>Prise en compte</th><th>Résolue</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {list.map((v) => {
              const s = find(SEV, v.severity)
              const st = find(ALERT_STATUS, stateOf(v))
              const rowBusy = busy.endsWith(`:${v.id}`)
              return editId === v.id ? (
                <tr key={v.id}>
                  <td>
                    <input aria-label={`Titre de « ${v.title} »`} value={draft.title}
                      onChange={(e) => setDraft({ ...draft, title: e.target.value })} />
                  </td>
                  <td>
                    <select aria-label={`Gravité de « ${v.title} »`} value={draft.severity}
                      onChange={(e) => setDraft({ ...draft, severity: e.target.value })}>
                      {SEV.map((x) => <option key={x.k} value={x.k}>{x.label}</option>)}
                    </select>
                  </td>
                  <td><span style={{ color: st?.color || 'var(--m)' }}>● {st?.label || stateOf(v)}</span></td>
                  <td>
                    <select aria-label={`Appareil lié à « ${v.title} »`} value={draft.device}
                      onChange={(e) => setDraft({ ...draft, device: e.target.value })}>
                      <option value="">Aucun</option>
                      {devices.map((d) => <option key={d.id} value={d.id}>{d.name} — {d.ip || '—'}</option>)}
                    </select>
                  </td>
                  <td>
                    <textarea aria-label={`Note de « ${v.title} »`} value={draft.note}
                      onChange={(e) => setDraft({ ...draft, note: e.target.value })} />
                  </td>
                  <td>{when(v.created_at)}</td>
                  <td>{when(v.acknowledged_at)}</td>
                  <td>{when(v.resolved_at)}</td>
                  <td className="acts">
                    <button type="button" className="ack" disabled={rowBusy}
                      aria-label={`Enregistrer « ${v.title} »`} onClick={save}>Enregistrer</button>
                    <button type="button" className="ghost" disabled={rowBusy}
                      aria-label={`Annuler la modification de « ${v.title} »`}
                      onClick={() => { setEditId(null); setErr(''); setDraft({ ...blank }) }}>Annuler</button>
                  </td>
                </tr>
              ) : (
                <tr key={v.id}>
                  <td>{v.title}</td>
                  <td><span style={{ color: s?.color || 'var(--m)' }}>● {s?.label || v.severity || '—'}</span></td>
                  <td><span style={{ color: st?.color || 'var(--m)' }}>● {st?.label || stateOf(v)}</span></td>
                  <td>{deviceLabel(v.device_id)}</td>
                  <td className="note">{v.note || '—'}</td>
                  <td>{when(v.created_at)}</td>
                  <td>{when(v.acknowledged_at)}</td>
                  <td>{when(v.resolved_at)}</td>
                  <td className="acts">
                    {stateOf(v) === 'open' && (
                      <button type="button" className="ack" disabled={rowBusy}
                        aria-label={`Prendre en compte « ${v.title} »`} onClick={() => acknowledge(v)}>
                        Prendre en compte
                      </button>
                    )}
                    {(stateOf(v) === 'open' || stateOf(v) === 'ack') && (
                      <button type="button" className="solve" disabled={rowBusy}
                        aria-label={`Résoudre « ${v.title} »`} onClick={() => resolveVuln(v)}>
                        Résoudre
                      </button>
                    )}
                    <button type="button" className="ghost" disabled={rowBusy}
                      aria-label={`Modifier « ${v.title} »`} onClick={() => startEdit(v)}>Modifier</button>
                    <button type="button" className="del" disabled={rowBusy}
                      aria-label={`Supprimer « ${v.title} »`} onClick={() => removeVuln(v)}>Supprimer</button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {!vulns.length && <p className="vulns-empty">Aucune vulnérabilité</p>}
      {!!vulns.length && !list.length && <p className="vulns-empty">Aucun résultat</p>}
    </div>
  )
}
