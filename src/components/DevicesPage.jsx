import { useState } from 'react'
import { TYPES, STATUS } from '../constants'
import { useI18n } from '../i18n/context.js'
import './DevicesPage.css'

const validIp = (v) => !v || (/^(\d{1,3}\.){3}\d{1,3}$/.test(v) && v.split('.').every((n) => Number(n) <= 255))

export default function DevicesPage({ devices, services = [], onAddClick, onUpdate, onRemove }) {
  const { t, locale } = useI18n()
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
  const seen = (d) => (d.last_seen ? new Date(d.last_seen).toLocaleString(locale) : '—')

  const startEdit = (d) => {
    setEditId(d.id)
    setDraft({ name: d.name, ip: d.ip || '', type: d.type, status: d.status })
    setErr('')
  }
  const set = (k) => (e) => setDraft({ ...draft, [k]: e.target.value })
  const save = async () => {
    const name = draft.name.trim()
    const ip = draft.ip.trim()
    if (!name) return setErr(t('devicesPage.errName'))
    if (!validIp(ip)) return setErr(t('devicesPage.errIp'))
    try {
      const msg = await onUpdate(editId, { name, ip: ip || null, type: draft.type, status: draft.status })
      if (msg) { setErr(msg); return }
      setEditId(null)
      setErr('')
    } catch {
      setErr(t('common.updateError'))
    }
  }
  const del = (d) => {
    if (window.confirm(t('devicesPage.confirmDelete', { name: d.name }))) onRemove(devices.indexOf(d))
  }

  return (
    <div className="card">
      <h3>{t('devicesPage.title')} <span className="m" style={{ fontWeight: 400 }}>· {t('devicesPage.count', { shown: list.length, total: devices.length })}</span></h3>
      <div className="tb">
        <input placeholder={t('devicesPage.search')} value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={st} onChange={(e) => setSt(e.target.value)}>
          <option value="">{t('devicesPage.allStatuses')}</option>
          {STATUS.map((s) => <option key={s.k} value={s.k}>{t(`status.${s.k}`)}</option>)}
        </select>
        <button onClick={onAddClick}>{t('devicesPage.add')}</button>
      </div>
      {err && <div className="err">{err}</div>}
      <div className="tw">
        <table className="dt">
          <thead><tr><th>{t('devicesPage.colName')}</th><th>{t('devicesPage.colIp')}</th><th>{t('devicesPage.colType')}</th><th>{t('devicesPage.colStatus')}</th><th>{t('devicesPage.colPorts')}</th><th>{t('devicesPage.colSeen')}</th><th>{t('devicesPage.colActions')}</th></tr></thead>
          <tbody>
            {list.map((d) => {
              const s = STATUS.find((x) => x.k === d.status)
              return editId === d.id ? (
                <tr key={d.id}>
                  <td><input value={draft.name} onChange={set('name')} /></td>
                  <td><input value={draft.ip} onChange={set('ip')} placeholder={t('devicesPage.ipPlaceholder')} /></td>
                  <td><select value={draft.type} onChange={set('type')}>{Object.keys(TYPES).map((ty) => <option key={ty} value={ty}>{t(`type.${ty}`)}</option>)}</select></td>
                  <td><select value={draft.status} onChange={set('status')}>{STATUS.map((x) => <option key={x.k} value={x.k}>{t(`status.${x.k}`)}</option>)}</select></td>
                  <td>{ports(d)}</td><td>{seen(d)}</td>
                  <td><button onClick={save}>{t('devicesPage.save')}</button><button className="x" onClick={() => { setEditId(null); setErr('') }}>{t('devicesPage.cancel')}</button></td>
                </tr>
              ) : (
                <tr key={d.id}>
                  <td>{d.name}</td>
                  <td>{d.ip || '—'}{d.mac && <div className="m">{d.mac}</div>}</td>
                  <td>{d.type ? t(`type.${d.type}`) : '—'}</td>
                  <td style={{ color: s?.color }}>● {s ? t(`status.${d.status}`) : (d.status || '—')}</td>
                  <td>{ports(d)}</td><td>{seen(d)}</td>
                  <td><button className="x" onClick={() => startEdit(d)}>{t('devicesPage.edit')}</button><button className="del" onClick={() => del(d)}>{t('devicesPage.delete')}</button></td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {!devices.length && <p className="m" style={{ padding: '22px 0', textAlign: 'center' }}>{t('devicesPage.empty')}</p>}
      {!!devices.length && !list.length && <p className="m" style={{ padding: '22px 0', textAlign: 'center' }}>{t('devicesPage.noResult')}</p>}
    </div>
  )
}
