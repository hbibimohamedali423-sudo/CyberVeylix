import { Fragment, useState } from 'react'
import { ALERT_STATUS, SEV, VULN_SOURCES } from '../constants'
import { fixSensorFor, isActiveCommand, localFixOf, sensorState, sourceOf } from '../lib/findings.js'
import { CveLinks, ConfidenceLabel } from './FindingBits.jsx'
import { useI18n } from '../i18n/context.js'
import './VulnsPage.css'

// Statut réel d’une vulnérabilité : repli sur le défaut de la colonne (open) si null.
const stateOf = (v) => v.status || 'open'
const when = (d, locale) => (d ? new Date(d).toLocaleString(locale) : '—')
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

export default function VulnsPage({ vulns = [], devices = [], onAdd, onUpdate, onRemove, sensors = [], commands = [], onCommand }) {
  const { t, locale } = useI18n()
  const [sev, setSev] = useState('')
  const [status, setStatus] = useState('')
  const [src, setSrc] = useState('')
  const [openId, setOpenId] = useState(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')
  const [editId, setEditId] = useState(null)
  const [draft, setDraft] = useState(() => ({ ...blank }))
  const [form, setForm] = useState(() => ({ ...blank }))

  const list = vulns
    .filter((v) => (!sev || v.severity === sev) && (!status || stateOf(v) === status) && (!src || sourceOf(v) === src))
    .sort(newestFirst)

  // On repasse toujours l’identifiant réel de l’appareil (type inchangé, uuid ou entier).
  const deviceOf = (id) => devices.find((d) => String(d.id) === String(id))
  const deviceIdOf = (value) => (value === '' ? null : deviceOf(value)?.id ?? null)
  const deviceLabel = (id) => {
    if (id === null || id === undefined || id === '') return '—'
    return deviceOf(id)?.name || t('vulnsPage.deviceDeleted')
  }

  const act = async (key, call) => {
    setErr('')
    setBusy(key)
    try {
      const msg = await call()
      if (msg) { setErr(msg); return false }
      return true
    } catch (e) {
      setErr(t('common.updateError'))
      console.error('VulnsPage operation failed:', e)
      return false
    } finally {
      setBusy('')
    }
  }

  const acknowledge = (v) => act(`ack:${v.id}`, () => onUpdate(v.id, { status: 'ack', acknowledged_at: new Date().toISOString() }))

  const resolveVuln = (v) => {
    if (!window.confirm(t('vulnsPage.confirmResolve', { title: v.title }))) return
    act(`resolve:${v.id}`, () => onUpdate(v.id, { status: 'resolved', resolved_at: new Date().toISOString() }))
  }

  const removeVuln = (v) => {
    if (!window.confirm(t('vulnsPage.confirmDelete', { title: v.title }))) return
    act(`del:${v.id}`, () => onRemove(v.id))
  }

  // Correction sur CE PC (liste blanche du capteur) : demande au capteur, qui exécute puis vérifie.
  const fixOf = (v) => {
    const fix = localFixOf(v)
    if (!fix || !onCommand) return null
    const sensor = fixSensorFor(v, sensors)
    const pending = !!sensor && commands.some((c) => c.kind === 'fix' && isActiveCommand(c) && c.sensor_id === sensor.id && c.params?.id === fix.id)
    return { ...fix, sensor, pending, ready: !!sensor && sensorState(sensor).state === 'running' }
  }
  const applyFix = (v) => {
    const fix = fixOf(v)
    if (!fix || !fix.ready) return
    if (!window.confirm(t('fixes.confirm', { name: t(`fixes.${fix.id}.name`), sensor: fix.sensor.name, what: t(`fixes.${fix.id}.what`) }))) return
    act(`fix:${v.id}`, () => onCommand(fix.sensor.id, 'fix', { id: fix.id }))
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
    if (!title) { setErr(t('vulnsPage.errTitle')); return }
    const ok = await act(`save:${editId}`, () => onUpdate(editId, {
      title, severity: draft.severity, device_id: deviceIdOf(draft.device), note: draft.note.trim() || null,
    }))
    if (ok) { setEditId(null); setDraft({ ...blank }) }
  }

  const add = async (e) => {
    e.preventDefault()
    const title = form.title.trim()
    if (!title) { setErr(t('vulnsPage.errTitle')); return }
    const ok = await act('add', () => onAdd({
      title, severity: form.severity, device_id: deviceIdOf(form.device), note: form.note.trim() || null,
    }))
    if (ok) setForm({ ...blank })
  }

  return (
    <div className="card vulns-page">
      <h3>
        {t('vulnsPage.title')}
        <span className="m" style={{ fontWeight: 400 }}> · {list.length} / {vulns.length}</span>
      </h3>

      <form className="vulns-form" onSubmit={add}>
        <label>{t('vulnsPage.formTitle')}
          <input value={form.title} placeholder={t('vulnsPage.formTitlePh')}
            onChange={(e) => setForm({ ...form, title: e.target.value })} />
        </label>
        <label>{t('vulnsPage.severity')}
          <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
            {SEV.map((s) => <option key={s.k} value={s.k}>{t(`sev.${s.k}`)}</option>)}
          </select>
        </label>
        <label>{t('vulnsPage.device')}
          <select value={form.device} onChange={(e) => setForm({ ...form, device: e.target.value })}>
            <option value="">{t('vulnsPage.deviceNone')}</option>
            {devices.map((d) => <option key={d.id} value={d.id}>{d.name} — {d.ip || '—'}</option>)}
          </select>
        </label>
        <label className="note">{t('vulnsPage.note')}
          <textarea value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} />
        </label>
        <button type="submit" disabled={busy === 'add'}>{t('vulnsPage.add')}</button>
      </form>

      <div className="vulns-bar">
        <label>{t('vulnsPage.severity')}
          <select value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="">{t('alertsPage.allSev')}</option>
            {SEV.map((s) => <option key={s.k} value={s.k}>{t(`sev.${s.k}`)}</option>)}
          </select>
        </label>
        <label>{t('alertsPage.statusFilter')}
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">{t('alertsPage.allStatuses')}</option>
            {ALERT_STATUS.map((s) => <option key={s.k} value={s.k}>{t(`alertStatus.${s.k}`)}</option>)}
          </select>
        </label>
        <label>{t('sources.filter')}
          <select value={src} onChange={(e) => setSrc(e.target.value)}>
            <option value="">{t('sources.all')}</option>
            {VULN_SOURCES.map((k) => <option key={k} value={k}>{t(`sources.${k}`)}</option>)}
          </select>
        </label>
      </div>

      {err && <div className="vulns-err" role="alert">{err}</div>}

      <div className="vulns-tw">
        <table className="vulns-dt">
          <thead>
            <tr>
              <th>{t('alertsPage.colTitle')}</th><th>{t('alertsPage.colSev')}</th><th>{t('alertsPage.colStatus')}</th><th>{t('vulnsPage.colDevice')}</th><th>{t('sources.col')}</th><th>{t('vulnDetail.colCve')}</th><th>{t('vulnDetail.colConfidence')}</th><th>{t('vulnsPage.colNote')}</th>
              <th>{t('alertsPage.colCreated')}</th><th>{t('alertsPage.colAck')}</th><th>{t('alertsPage.colResolved')}</th><th>{t('alertsPage.colActions')}</th>
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
                    <input aria-label={t('vulnsPage.ariaTitle', { title: v.title })} value={draft.title}
                      onChange={(e) => setDraft({ ...draft, title: e.target.value })} />
                  </td>
                  <td>
                    <select aria-label={t('vulnsPage.ariaSeverity', { title: v.title })} value={draft.severity}
                      onChange={(e) => setDraft({ ...draft, severity: e.target.value })}>
                      {SEV.map((x) => <option key={x.k} value={x.k}>{t(`sev.${x.k}`)}</option>)}
                    </select>
                  </td>
                  <td><span style={{ color: st?.color || 'var(--m)' }}>● {st ? t(`alertStatus.${stateOf(v)}`) : stateOf(v)}</span></td>
                  <td>
                    <select aria-label={t('vulnsPage.ariaDevice', { title: v.title })} value={draft.device}
                      onChange={(e) => setDraft({ ...draft, device: e.target.value })}>
                      <option value="">{t('vulnsPage.deviceNone')}</option>
                      {devices.map((d) => <option key={d.id} value={d.id}>{d.name} — {d.ip || '—'}</option>)}
                    </select>
                  </td>
                  <td>{t(`sources.${sourceOf(v)}`)}</td>
                  <td><CveLinks row={v} /></td>
                  <td><ConfidenceLabel value={v.confidence} /></td>
                  <td>
                    <textarea aria-label={t('vulnsPage.ariaNote', { title: v.title })} value={draft.note}
                      onChange={(e) => setDraft({ ...draft, note: e.target.value })} />
                  </td>
                  <td>{when(v.created_at, locale)}</td>
                  <td>{when(v.acknowledged_at, locale)}</td>
                  <td>{when(v.resolved_at, locale)}</td>
                  <td className="acts">
                    <button type="button" className="ack" disabled={rowBusy}
                      aria-label={t('vulnsPage.ariaSave', { title: v.title })} onClick={save}>{t('common.save')}</button>
                    <button type="button" className="ghost" disabled={rowBusy}
                      aria-label={t('vulnsPage.ariaCancel', { title: v.title })}
                      onClick={() => { setEditId(null); setErr(''); setDraft({ ...blank }) }}>{t('common.cancel')}</button>
                  </td>
                </tr>
              ) : (
                <Fragment key={v.id}>
                <tr>
                  <td>{v.title}</td>
                  <td><span style={{ color: s?.color || 'var(--m)' }}>● {s ? t(`sev.${v.severity}`) : (v.severity || '—')}</span></td>
                  <td><span style={{ color: st?.color || 'var(--m)' }}>● {st ? t(`alertStatus.${stateOf(v)}`) : stateOf(v)}</span></td>
                  <td>{deviceLabel(v.device_id)}</td>
                  <td>{VULN_SOURCES.includes(sourceOf(v)) ? t(`sources.${sourceOf(v)}`) : sourceOf(v)}</td>
                  <td><CveLinks row={v} /></td>
                  <td><ConfidenceLabel value={v.confidence} /></td>
                  <td className="note">{v.note || '—'}</td>
                  <td>{when(v.created_at, locale)}</td>
                  <td>{when(v.acknowledged_at, locale)}</td>
                  <td>{when(v.resolved_at, locale)}</td>
                  <td className="acts">
                    <button type="button" className="ghost" aria-expanded={openId === v.id}
                      aria-label={t('vulnDetail.ariaToggle', { title: v.title })}
                      onClick={() => setOpenId(openId === v.id ? null : v.id)}>
                      {openId === v.id ? t('vulnDetail.hide') : t('vulnDetail.show')}
                    </button>
                    {stateOf(v) !== 'resolved' && fixOf(v) && (() => {
                      const fx = fixOf(v)
                      return (
                        <button type="button" className="fix" disabled={rowBusy || fx.pending || !fx.ready}
                          title={fx.ready ? t(`fixes.${fx.id}.name`) : t('fixes.unavailable')}
                          aria-label={t('fixes.ariaFix', { title: v.title })} onClick={() => applyFix(v)}>
                          {fx.pending ? t('fixes.pending') : t('fixes.button')}
                        </button>
                      )
                    })()}
                    {stateOf(v) === 'open' && (
                      <button type="button" className="ack" disabled={rowBusy}
                        aria-label={t('alertsPage.ariaAck', { title: v.title })} onClick={() => acknowledge(v)}>
                        {t('alertsPage.ack')}
                      </button>
                    )}
                    {(stateOf(v) === 'open' || stateOf(v) === 'ack') && (
                      <button type="button" className="solve" disabled={rowBusy}
                        aria-label={t('alertsPage.ariaResolve', { title: v.title })} onClick={() => resolveVuln(v)}>
                        {t('alertsPage.resolve')}
                      </button>
                    )}
                    <button type="button" className="ghost" disabled={rowBusy}
                      aria-label={t('vulnsPage.ariaEdit', { title: v.title })} onClick={() => startEdit(v)}>{t('common.edit')}</button>
                    <button type="button" className="del" disabled={rowBusy}
                      aria-label={t('vulnsPage.ariaDelete', { title: v.title })} onClick={() => removeVuln(v)}>{t('common.delete')}</button>
                  </td>
                </tr>
                {openId === v.id && (
                  <tr className="vulns-detail">
                    <td colSpan={12}>
                      <dl>
                        <dt>{t('vulnDetail.evidence')}</dt><dd className="pre">{v.evidence || t('vulnDetail.none')}</dd>
                        <dt>{t('vulnDetail.remediation')}</dt><dd className="pre">{v.remediation || t('vulnDetail.none')}</dd>
                        <dt>{t('vulnDetail.service')}</dt>
                        <dd><bdi dir="ltr">{v.port ? `${v.port}${v.service ? ` · ${v.service}` : ''}` : (v.service || '—')}</bdi></dd>
                        <dt>{t('vulnDetail.lastSeen')}</dt><dd>{when(v.last_seen, locale)}</dd>
                      </dl>
                    </td>
                  </tr>
                )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
      {!vulns.length && <p className="vulns-empty">{t('vulnsPage.empty')}</p>}
      {!!vulns.length && !list.length && <p className="vulns-empty">{t('vulnsPage.noResult')}</p>}
    </div>
  )
}
