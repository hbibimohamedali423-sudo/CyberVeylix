import { useState } from 'react'

export default function Modal({ title, fields, rows, onAdd, onRemove, onClose }) {
  const empty = Object.fromEntries(fields.map((x) => [x.k, x.opts ? x.opts[0][0] : '']))
  const [f, setF] = useState(empty)
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })
  const submit = () => {
    if (!f[fields[0].k].trim()) return
    onAdd(f)
    setF(empty)
  }
  return (
    <div className="ov" onClick={onClose}>
      <div className="dlg" onClick={(e) => e.stopPropagation()}>
        <h3>{title}</h3>
        {fields.map((x) => x.opts
          ? <select key={x.k} value={f[x.k]} onChange={set(x.k)}>{x.opts.map((o) => <option key={o[0]} value={o[0]}>{o[1]}</option>)}</select>
          : <input key={x.k} placeholder={x.ph} value={f[x.k]} onChange={set(x.k)} />)}
        <button onClick={submit}>Ajouter</button>
        <button className="x wide" onClick={onClose}>Fermer</button>
        <div className="dl">
          {rows.map((r, i) => <div key={i}><span>{r}</span><button className="x" onClick={() => onRemove(i)}>✕</button></div>)}
        </div>
      </div>
    </div>
  )
}
