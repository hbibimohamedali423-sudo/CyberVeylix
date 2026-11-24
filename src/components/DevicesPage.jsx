import { Fragment, useState } from 'react'
import { ALERT_STATUS, NETWORK_FILTER_NONE, SEV, STATUS, TYPES } from '../constants'
import { CveLinks } from './FindingBits.jsx'
import { useI18n } from '../i18n/context.js'
import './DevicesPage.css'

const validIp = (v) => !v || (/^(\d{1,3}\.){3}\d{1,3}$/.test(v) && v.split('.').every((n) => Number(n) <= 255))
const typeLabelOf = (t, type) => {
  if (type === null || type === undefined || type === '') return t('type.unknown')
  if (Object.hasOwn(TYPES, type)) return t(`type.${type}`)
  return String(type)
}

export default function DevicesPage({
  devices,
  services = [],
  vulns = [],
  networks = [],
  onAddClick,
  onUpdate,
  onRemove,
  onNetworkUpdate,
  onNetworkRemove,
}) {
  const { t, locale } = useI18n()
  const [q, setQ] = useState('')
  const [st, setSt] = useState('')
  const [networkFilter, setNetworkFilter] = useState('')
  const [editId, setEditId] = useState(null)
  const [openId, setOpenId] = useState(null)
  const [draft, setDraft] = useState({})
  const [err, setErr] = useState('')

  const networkById = new Map(networks.map((n) => [n.id, n]))
  const networkLabel = (id) => {
    if (!id) return t('networks.unassigned')
    const n = networkById.get(id)
    return n ? (n.name || n.cidr) : t('networks.unknown')
  }

  const list = devices.filter((d) => {
    const hay = `${d.name} ${d.ip || ''} ${typeLabelOf(t, d.type)} ${networkLabel(d.network_id)}`.toLowerCase()
    const sameNetwork = !networkFilter
      || (networkFilter === NETWORK_FILTER_NONE ? !d.network_id : d.network_id === networkFilter)
    return hay.includes(q.trim().toLowerCase()) && (!st || d.status === st) && sameNetwork
  })
  const unassigned = devices.filter((d) => !d.network_id)

  const ports = (d) => services.filter((s) => s.device_id === d.id).map((s) => s.port).join(', ') || '—'
  const seen = (d) => (d.last_seen ? new Date(d.last_seen).toLocaleString(locale) : '—')

  const startEdit = (d) => {
    setEditId(d.id)
    setDraft({ name: d.name, ip: d.ip || '', type: d.type || '', status: d.status, network_id: d.network_id || '' })
    setErr('')
  }
  const set = (k) => (e) => setDraft({ ...draft, [k]: e.target.value })
  const save = async () => {
    const name = draft.name.trim()
    const ip = draft.ip.trim()
    if (!name) return setErr(t('devicesPage.errName'))
    if (!validIp(ip)) return setErr(t('devicesPage.errIp'))
    if (draft.network_id && !networkById.has(draft.network_id)) return setErr(t('networks.invalid'))
    try {
      const msg = await onUpdate(editId, {
        name,
        ip: ip || null,
        type: draft.type || null,
        status: draft.status,
        network_id: draft.network_id || null,
      })
      if (msg) { setErr(msg); return }
      setEditId(null)
      setErr('')
    } catch {
      setErr(t('common.updateError'))
    }
  }
  const del = async (d) => {
    if (!window.confirm(t('devicesPage.confirmDelete', { name: d.name }))) return
    setErr('')
    try {
      const msg = await onRemove(d.id)
      if (msg) {
        setErr(msg)
        console.error('Device delete failed:', msg)
      }
    } catch (e) {
      setErr(t('common.updateError'))
      console.error('Device delete threw:', e)
    }
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
        <label className="tb-network">
          <span>{t('networks.filter')}</span>
          <select value={networkFilter} onChange={(e) => setNetworkFilter(e.target.value)}>
            <option value="">{t('networks.all')}</option>
            {networks.map((n) => <option key={n.id} value={n.id}>{n.name || n.cidr}</option>)}
            <option value={NETWORK_FILTER_NONE}>{t('networks.unassigned')}</option>
          </select>
        </label>
        <button onClick={onAddClick}>{t('devicesPage.add')}</button>
      </div>
      {err && <div className="err">{err}</div>}
      <div className="tw">
        <table className="dt">
          <thead><tr><th>{t('devicesPage.colName')}</th><th>{t('devicesPage.colIp')}</th><th>{t('devicesPage.colNetwork')}</th><th>{t('devicesPage.colType')}</th><th>{t('devicesPage.colStatus')}</th><th>{t('devicesPage.colPorts')}</th><th>{t('devicesPage.colSeen')}</th><th>{t('devicesPage.colActions')}</th></tr></thead>
          <tbody>
            {list.map((d) => {
              const s = STATUS.find((x) => x.k === d.status)
              return editId === d.id ? (
                <tr key={d.id}>
                  <td><input value={draft.name} onChange={set('name')} /></td>
                  <td><input value={draft.ip} onChange={set('ip')} placeholder={t('devicesPage.ipPlaceholder')} /></td>
                  <td>
                    <select value={draft.network_id} onChange={set('network_id')} aria-label={t('networks.filter')}>
                      <option value="">{t('networks.unassigned')}</option>
                      {networks.map((n) => <option key={n.id} value={n.id}>{n.name || n.cidr}</option>)}
                    </select>
                  </td>
                  <td>
                    <select value={draft.type} onChange={set('type')}>
                      <option value="">{t('type.unknown')}</option>
                      {Object.keys(TYPES).map((ty) => <option key={ty} value={ty}>{t(`type.${ty}`)}</option>)}
                    </select>
                  </td>
                  <td><select value={draft.status} onChange={set('status')}>{STATUS.map((x) => <option key={x.k} value={x.k}>{t(`status.${x.k}`)}</option>)}</select></td>
                  <td>{ports(d)}</td><td>{seen(d)}</td>
                  <td><button onClick={save}>{t('devicesPage.save')}</button><button className="x" onClick={() => { setEditId(null); setErr('') }}>{t('devicesPage.cancel')}</button></td>
                </tr>
              ) : (
                <Fragment key={d.id}>
                <tr>
                  <td>{d.name}</td>
                  <td>{d.ip || '—'}{d.mac && <div className="m">{d.mac}</div>}</td>
                  <td>{networkLabel(d.network_id)}</td>
                  <td>{typeLabelOf(t, d.type)}</td>
                  <td style={{ color: s?.color }}>● {s ? t(`status.${d.status}`) : (d.status || '—')}</td>
                  <td>{ports(d)}</td><td>{seen(d)}</td>
                  <td>
                    <button className="x" aria-expanded={openId === d.id} aria-label={t('deviceDetail.ariaToggle', { name: d.name })}
                      onClick={() => setOpenId(openId === d.id ? null : d.id)}>{openId === d.id ? t('deviceDetail.hide') : t('deviceDetail.show')}</button>
                    <button className="x" onClick={() => startEdit(d)}>{t('devicesPage.edit')}</button><button className="del" onClick={() => del(d)}>{t('devicesPage.delete')}</button>
                  </td>
                </tr>
                {openId === d.id && (
                  <tr className="dev-detail"><td colSpan={8}>
                    <DeviceDetail services={services.filter((x) => x.device_id === d.id)} vulns={vulns.filter((v) => v.device_id === d.id)} />
                  </td></tr>
                )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
      {!devices.length && <p className="m" style={{ padding: '22px 0', textAlign: 'center' }}>{t('devicesPage.empty')}</p>}
      {!!devices.length && !list.length && <p className="m" style={{ padding: '22px 0', textAlign: 'center' }}>{t('devicesPage.noResult')}</p>}

      {!!unassigned.length && (
        <UnassignedPanel devices={unassigned} networks={networks} onUpdate={onUpdate} />
      )}
      <NetworkManager networks={networks} devices={devices} onUpdate={onNetworkUpdate} onRemove={onNetworkRemove} />
    </div>
  )
}

const byPort = (a, b) => (Number(a.port) || 0) - (Number(b.port) || 0)

// Services enregistrés (port, version annoncée) et vulnérabilités liées à l'appareil.
function DeviceDetail({ services, vulns }) {
  const { t, locale } = useI18n()
  const when = (v) => (v ? new Date(v).toLocaleString(locale) : '—')
  const sevOf = (k) => SEV.find((x) => x.k === k)
  const stOf = (k) => ALERT_STATUS.find((x) => x.k === k)
  return (
    <div className="dev-detail-grid">
      <section>
        <h4>{t('deviceDetail.services')} ({services.length})</h4>
        {!services.length ? <p className="m">{t('deviceDetail.noServices')}</p> : (
          <table className="dev-sub">
            <thead><tr><th>{t('deviceDetail.port')}</th><th>{t('deviceDetail.protocol')}</th><th>{t('deviceDetail.service')}</th><th>{t('deviceDetail.version')}</th><th>{t('deviceDetail.lastSeen')}</th></tr></thead>
            <tbody>{services.slice().sort(byPort).map((x) => (
              <tr key={x.id}><td dir="ltr">{x.port ?? '—'}</td><td>{x.protocol || '—'}</td><td>{x.service || '—'}</td><td dir="ltr">{x.version || '—'}</td><td>{when(x.last_seen)}</td></tr>
            ))}</tbody>
          </table>
        )}
      </section>
      <section>
        <h4>{t('deviceDetail.vulns')} ({vulns.length})</h4>
        {!vulns.length ? <p className="m">{t('deviceDetail.noVulns')}</p> : (
          <table className="dev-sub">
            <thead><tr><th>{t('alertsPage.colTitle')}</th><th>{t('alertsPage.colSev')}</th><th>{t('alertsPage.colStatus')}</th><th>{t('vulnDetail.colCve')}</th></tr></thead>
            <tbody>{vulns.map((v) => {
              const s = sevOf(v.severity)
              const st = stOf(v.status || 'open')
              return (
                <tr key={v.id}>
                  <td>{v.title}</td>
                  <td style={{ color: s?.color }}>● {s ? t(`sev.${v.severity}`) : (v.severity || '—')}</td>
                  <td style={{ color: st?.color }}>● {st ? t(`alertStatus.${v.status || 'open'}`) : v.status}</td>
                  <td><CveLinks row={v} /></td>
                </tr>
              )
            })}</tbody>
          </table>
        )}
      </section>
    </div>
  )
}

function UnassignedPanel({ devices, networks, onUpdate }) {
  const { t } = useI18n()
  const [selected, setSelected] = useState([])
  const [target, setTarget] = useState('')
  const [rowTarget, setRowTarget] = useState({})
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')

  const networkName = (id) => {
    const n = networks.find((x) => x.id === id)
    return n ? (n.name || n.cidr) : ''
  }
  const toggle = (id) => setSelected((current) => (
    current.includes(id) ? current.filter((x) => x !== id) : [...current, id]
  ))
  const allSelected = devices.length > 0 && selected.length === devices.length
  const toggleAll = () => setSelected(allSelected ? [] : devices.map((d) => d.id))

  const assign = async (ids, networkId) => {
    if (!networkId || !networks.some((n) => n.id === networkId)) {
      setErr(t('networks.invalid'))
      return
    }
    const targets = ids.filter((id) => devices.some((d) => d.id === id))
    if (!targets.length) return
    setBusy(true)
    setErr('')
    setOk('')
    try {
      for (const id of targets) {
        const msg = await onUpdate(id, { network_id: networkId })
        if (msg) { setErr(msg); return }
      }
      setOk(targets.length === 1
        ? t('networks.assigned', { name: networkName(networkId) })
        : t('networks.assignedMany', { n: targets.length, name: networkName(networkId) }))
      setSelected([])
    } catch {
      setErr(t('common.updateError'))
    } finally {
      setBusy(false)
    }
  }

  const bulk = () => {
    const name = networkName(target)
    if (!name) { setErr(t('networks.invalid')); return }
    if (!selected.length) return
    if (!window.confirm(t('networks.confirmBulk', { n: selected.length, name }))) return
    assign(selected, target)
  }

  return (
    <section className="net-unassigned" aria-labelledby="net-unassigned-title">
      <div className="net-panel-head">
        <div>
          <h4 id="net-unassigned-title">{t('networks.unassignedTitle')}</h4>
          <p className="m">{t('networks.unassignedCount', { n: devices.length })}</p>
        </div>
      </div>
      {err && <div className="err" role="alert">{err}</div>}
      {ok && <p className="net-ok" role="status">{ok}</p>}
      {!networks.length ? (
        <p className="m">{t('networks.empty')}</p>
      ) : (
        <>
          <div className="net-bulk">
            <label className="net-check">
              <input type="checkbox" checked={allSelected} onChange={toggleAll} disabled={busy} />
              <span>{t('networks.selectAll')}</span>
            </label>
            <select value={target} onChange={(e) => setTarget(e.target.value)} disabled={busy} aria-label={t('networks.filter')}>
              <option value="">{t('networks.choose')}</option>
              {networks.map((n) => <option key={n.id} value={n.id}>{n.name || n.cidr}</option>)}
            </select>
            <button type="button" onClick={bulk} disabled={busy || !selected.length || !target}>{t('networks.assignSelected')}</button>
          </div>
          <div className="net-unassigned-list">
            {devices.map((d) => (
              <div className="net-unassigned-row" key={d.id}>
                <input
                  type="checkbox"
                  checked={selected.includes(d.id)}
                  onChange={() => toggle(d.id)}
                  disabled={busy}
                  aria-label={t('networks.selectAria', { name: d.name })}
                />
                <div className="net-unassigned-name">
                  <b>{d.name}</b>
                  <small>{d.ip || '—'}</small>
                </div>
                <select
                  value={rowTarget[d.id] || ''}
                  onChange={(e) => setRowTarget({ ...rowTarget, [d.id]: e.target.value })}
                  disabled={busy}
                  aria-label={t('networks.assignAria', { name: d.name })}
                >
                  <option value="">{t('networks.choose')}</option>
                  {networks.map((n) => <option key={n.id} value={n.id}>{n.name || n.cidr}</option>)}
                </select>
                <button type="button" onClick={() => assign([d.id], rowTarget[d.id])} disabled={busy || !rowTarget[d.id]}>
                  {t('networks.assign')}
                </button>
              </div>
            ))}
          </div>
        </>
      )}
    </section>
  )
}

function NetworkManager({ networks, devices, onUpdate, onRemove }) {
  const { t, locale } = useI18n()
  const [editId, setEditId] = useState(null)
  const [nameDraft, setNameDraft] = useState('')
  const [busyId, setBusyId] = useState(null)
  const [err, setErr] = useState('')

  const deviceCount = (id) => devices.filter((d) => d.network_id === id).length
  const when = (v) => (v ? new Date(v).toLocaleString(locale) : t('common.dash'))

  const startRename = (n) => {
    setEditId(n.id)
    setNameDraft(n.name || '')
    setErr('')
  }
  const saveName = async (n) => {
    const name = nameDraft.trim()
    if (!name) { setErr(t('networks.errName')); return }
    setBusyId(n.id)
    setErr('')
    try {
      const msg = await onUpdate(n.id, { name })
      if (msg) { setErr(msg); return }
      setEditId(null)
    } catch {
      setErr(t('common.updateError'))
    } finally {
      setBusyId(null)
    }
  }
  const toggleScan = async (n) => {
    setBusyId(n.id)
    setErr('')
    try {
      const msg = await onUpdate(n.id, { scan_allowed: !n.scan_allowed })
      if (msg) setErr(msg)
    } catch {
      setErr(t('common.updateError'))
    } finally {
      setBusyId(null)
    }
  }
  const del = async (n) => {
    const name = n.name || n.cidr
    if (!window.confirm(t('networks.confirmDelete', { name }))) return
    setBusyId(n.id)
    setErr('')
    try {
      const msg = await onRemove(n.id)
      if (msg) setErr(msg)
    } catch {
      setErr(t('common.updateError'))
    } finally {
      setBusyId(null)
    }
  }

  return (
    <section className="net-manager" aria-labelledby="net-manager-title">
      <div className="net-panel-head">
        <div>
          <h4 id="net-manager-title">{t('networks.title')}</h4>
          <p className="m">{t('networks.subtitle')}</p>
        </div>
      </div>
      {err && <div className="err" role="alert">{err}</div>}
      {!networks.length ? (
        <p className="m net-empty">{t('networks.empty')}</p>
      ) : (
        <div className="net-tw">
          <table className="net-table">
            <thead>
              <tr>
                <th>{t('networks.colName')}</th>
                <th>{t('networks.colCidr')}</th>
                <th>{t('networks.colGateway')}</th>
                <th>{t('networks.colSsid')}</th>
                <th>{t('networks.colLastSeen')}</th>
                <th>{t('networks.colDevices')}</th>
                <th>{t('networks.colScan')}</th>
                <th>{t('networks.colActions')}</th>
              </tr>
            </thead>
            <tbody>
              {networks.map((n) => {
                const busy = busyId === n.id
                return (
                  <tr key={n.id}>
                    <td>
                      {editId === n.id ? (
                        <input
                          value={nameDraft}
                          onChange={(e) => setNameDraft(e.target.value)}
                          aria-label={t('networks.renameAria', { name: n.name || n.cidr })}
                          disabled={busy}
                        />
                      ) : (n.name || n.cidr)}
                    </td>
                    <td>{n.cidr || t('common.dash')}</td>
                    <td>{n.gateway_ip || t('common.dash')}</td>
                    <td>{n.ssid || t('common.dash')}</td>
                    <td>{when(n.last_seen)}</td>
                    <td>{deviceCount(n.id)}</td>
                    <td>
                      <label className="net-check">
                        <input
                          type="checkbox"
                          checked={Boolean(n.scan_allowed)}
                          onChange={() => toggleScan(n)}
                          disabled={busy}
                          aria-label={t('networks.scanAllowedAria', { name: n.name || n.cidr })}
                        />
                        <span>{n.scan_allowed ? t('networks.scanAllowed') : t('networks.scanBlocked')}</span>
                      </label>
                    </td>
                    <td className="net-actions">
                      {editId === n.id ? (
                        <>
                          <button type="button" onClick={() => saveName(n)} disabled={busy}>{t('common.save')}</button>
                          <button type="button" className="x" onClick={() => { setEditId(null); setErr('') }} disabled={busy}>{t('common.cancel')}</button>
                        </>
                      ) : (
                        <>
                          <button type="button" className="x" onClick={() => startRename(n)} disabled={busy} aria-label={t('networks.renameAria', { name: n.name || n.cidr })}>{t('networks.rename')}</button>
                          <button type="button" className="del" onClick={() => del(n)} disabled={busy} aria-label={t('networks.deleteAria', { name: n.name || n.cidr })}>{t('common.delete')}</button>
                        </>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
