import { useState } from 'react'
import { TYPES } from '../constants'
import { useI18n } from '../i18n/context.js'
import { buildPhysical, groupByType } from '../lib/physical.js'
import './PhysicalTopology.css'

const ROLES = ['gateway', 'switch', 'access_point', 'server', 'workstation', 'printer', 'camera', 'iot', 'phone', 'other']
const UNKNOWN = '__unknown'

const Dot = ({ d }) => <span className="ph-dot" style={{ background: (d.type && TYPES[d.type]) || 'var(--m)' }} aria-hidden="true" />

// Défini hors du composant principal : l'état ouvert / fermé des branches survit aux rafraîchissements.
function Node({ node, depth, ctx }) {
  const { t, match, filtering, typeLabel, roleLabel } = ctx
  const status = (s) => (s === 'observed' ? t('physical.observed') : s === 'inferred' ? t('physical.inferred') : '')
  const medium = (m) => (m === 'wifi' ? t('physical.wifi') : m === 'ethernet' ? t('physical.cable') : t('physical.unknownMedium'))
  const d = node.device
  const ports = node.ports.map((p) => ({ ...p, entries: p.entries.filter((e) => match(e.device)) })).filter((p) => !filtering || p.entries.length)
  return (
    <li className={`ph-node ph-${d.role || 'other'}`}>
      <details open={depth < 3}>
        <summary>
          <Dot d={d} />
          <b><bdi>{d.name}</bdi></b>
          {d.ip && <span className="m"> · <bdi dir="ltr">{d.ip}</bdi></span>}
          <span className="ph-role"> · {roleLabel(d.role) || typeLabel(d.type)}</span>
          {node.via && (
            <span className="ph-via" dir="auto">
              {' '}— {node.via.parentPort ? t('physical.viaBoth', { parentPort: node.via.parentPort, port: node.via.port || '?' }) : t('physical.via', { port: node.via.port || '?' })}
            </span>
          )}
          {d.model && <div className="m ph-model">{d.model}</div>}
        </summary>
        {ports.map((p) => (
          <div key={p.port} className={`ph-port${p.wifi ? ' ph-port-wifi' : ''}`}>
            <div className="ph-port-name">
              {p.wifi ? t('physical.wifiClients') : p.port === '__unknown' ? t('physical.unknownPort') : /^port\b/i.test(p.port) ? p.port : t('physical.port', { port: p.port })}
              {!p.wifi && p.entries.length > 1 && <span className="m"> · {t('physical.shared', { n: p.entries.length })}</span>}
            </div>
            <ul>
              {p.entries.map((e) => (
                <li key={e.device.id} title={e.evidence || undefined}>
                  <Dot d={e.device} />
                  <bdi>{e.device.name}</bdi>
                  {e.device.ip && <span className="m"> · <bdi dir="ltr">{e.device.ip}</bdi></span>}
                  <span className="m"> · {typeLabel(e.device.type)}</span>
                  <span className={`ph-badge ph-${e.medium}`}>{medium(e.medium)}</span>
                  <span className="ph-status">{status(e.status)}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
        {node.children.length > 0 && <ul className="ph-tree">{node.children.map((c) => <Node key={c.device.id} node={c} depth={depth + 1} ctx={ctx} />)}</ul>}
      </details>
    </li>
  )
}

// Branchements réels : passerelle → switchs → ports → appareils (câble / Wi-Fi), d'après les liens enregistrés
// par la lecture des switchs (capteur). Inventaire par type en dessous, à partir des appareils enregistrés.
export default function PhysicalTopology({ devices = [], links = [] }) {
  const { t } = useI18n()
  const [q, setQ] = useState('')
  const [type, setType] = useState('')
  const typeLabel = (ty) => (ty && Object.hasOwn(TYPES, ty) ? t(`type.${ty}`) : t('type.unknown'))
  const roleLabel = (r) => (r && ROLES.includes(r) ? t(`ident.roles.${r}`) : '')
  const match = (d) => {
    if (!d) return false
    if (type && (type === UNKNOWN ? Boolean(d.type) : d.type !== type)) return false
    const hay = `${d.name || ''} ${d.ip || ''} ${d.mac || ''} ${d.vendor || ''} ${d.hostname || ''}`.toLowerCase()
    return hay.includes(q.trim().toLowerCase())
  }
  const filtering = Boolean(q.trim() || type)

  const { roots, unplaced, stats, hasLinks } = buildPhysical(devices, links)
  const groups = groupByType(devices.filter(match))
  const lost = unplaced.filter(match)

  const ctx = { t, match, filtering, typeLabel, roleLabel }

  return (
    <div className="card physical-topology">
      <h3>{t('physical.title')}</h3>
      <p className="m">{t('physical.intro')}</p>
      <div className="ph-bar">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('physical.search')} aria-label={t('physical.search')} />
        <label>{t('physical.typeFilter')}
          <select value={type} onChange={(e) => setType(e.target.value)}>
            <option value="">{t('physical.allTypes')}</option>
            {Object.keys(TYPES).map((ty) => <option key={ty} value={ty}>{t(`type.${ty}`)}</option>)}
            <option value={UNKNOWN}>{t('type.unknown')}</option>
          </select>
        </label>
        <ul className="ph-stats" aria-label={t('physical.title')}>
          <li><b>{stats.cable}</b> {t('physical.cable')}</li>
          <li><b>{stats.wifi}</b> {t('physical.wifi')}</li>
          <li><b>{stats.unknown}</b> {t('physical.unknownMedium')}</li>
          <li><b>{unplaced.length}</b> {t('physical.unplaced')}</li>
        </ul>
      </div>

      {!hasLinks ? (
        <div className="ph-notice" role="status">
          <b>{t('physical.noLinks')}</b>
          <p>{t('physical.noLinksHow')}</p>
          <p className="m">{t('physical.noLinksPassive')}</p>
          <code dir="ltr">install.cmd -Reconfigure</code>
        </div>
      ) : (
        <ul className="ph-tree ph-root">{roots.map((n) => <Node key={n.device.id} node={n} depth={0} ctx={ctx} />)}</ul>
      )}

      {hasLinks && lost.length > 0 && (
        <section className="ph-section">
          <h4>{t('physical.unplaced')} ({lost.length})</h4>
          <p className="m">{t('physical.unplacedHint')}</p>
          <ul className="ph-flat">{lost.map((d) => <li key={d.id}><Dot d={d} /><bdi>{d.name}</bdi>{d.ip && <span className="m"> · <bdi dir="ltr">{d.ip}</bdi></span>}<span className="m"> · {typeLabel(d.type)}</span></li>)}</ul>
        </section>
      )}

      <section className="ph-section">
        <h4>{t('physical.byType')}</h4>
        {!groups.length ? <p className="m">{t('physical.empty')}</p> : groups.map((g) => (
          <details key={g.type || UNKNOWN} className="ph-group">
            <summary><Dot d={{ type: g.type }} /><b>{typeLabel(g.type)}</b> <span className="m">· {t('physical.countDevices', { n: g.devices.length })}</span></summary>
            <ul className="ph-flat">
              {g.devices.map((d) => (
                <li key={d.id}>
                  <bdi>{d.name}</bdi>
                  {d.ip && <span className="m"> · <bdi dir="ltr">{d.ip}</bdi></span>}
                  {d.vendor && <span className="m"> · {d.vendor}</span>}
                  <span className={`ph-st ph-st-${d.status || 'un'}`}> · {t(`status.${['on', 'off', 'un'].includes(d.status) ? d.status : 'un'}`)}</span>
                </li>
              ))}
            </ul>
          </details>
        ))}
      </section>
    </div>
  )
}
