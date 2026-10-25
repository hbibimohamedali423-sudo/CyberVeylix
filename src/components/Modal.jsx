import { useState } from 'react'
import { useI18n } from '../i18n/context.js'

export default function Modal({ title, fields, rows, onAdd, onRemove, onClose }) {
  const { t } = useI18n()
  const empty = Object.fromEntries(fields.map((x) => [x.k, x.opts ? x.opts[0][0] : '']))
  const [f, setF] = useState(empty)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })

  const submit = async () => {
    if (!f[fields[0].k].trim() || busy) return
    setBusy(true)
    setErr('')
    try {
      const msg = await onAdd(f)
      if (msg) {
        setErr(msg)
        console.error('Modal add failed:', msg)
      } else {
        setF(empty)
      }
    } catch (e) {
      const msg = e?.message ?? t('common.updateError')
      setErr(msg)
      console.error('Modal add threw:', e)
    } finally {
      setBusy(false)
    }
  }

  const remove = async (id) => {
    if (busy) return
    setErr('')
    setBusy(true)
    try {
      const msg = await onRemove(id)
      if (msg) {
        setErr(msg)
        console.error('Modal remove failed:', msg)
      }
    } catch (e) {
      const msg = e?.message ?? t('common.updateError')
      setErr(msg)
      console.error('Modal remove threw:', e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="ov" onClick={onClose}>
      <div className="dlg" onClick={(e) => e.stopPropagation()}>
        <h3>{title}</h3>
        {err && <div style={{ color: 'var(--danger-ink)', margin: '6px 0', fontSize: 12 }} role="alert">{err}</div>}
        {fields.map((x) => x.opts
          ? <select key={x.k} value={f[x.k]} onChange={set(x.k)} disabled={busy}>{x.opts.map((o) => <option key={o[0]} value={o[0]}>{o[1]}</option>)}</select>
          : <input key={x.k} placeholder={x.ph} value={f[x.k]} onChange={set(x.k)} disabled={busy} />)}
        <button onClick={submit} disabled={busy}>{t('modal.add')}</button>
        <button className="x wide" onClick={onClose}>{t('modal.close')}</button>
        <div className="dl">
          {rows.map((r) => <div key={r.id}><span>{r.label}</span><button className="x" onClick={() => remove(r.id)} disabled={busy}>✕</button></div>)}
        </div>
      </div>
    </div>
  )
}
