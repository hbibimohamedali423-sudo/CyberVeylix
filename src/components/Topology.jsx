import { useState, useMemo } from 'react'
import { useI18n } from '../i18n/context.js'
import { TYPES, STATUS } from '../constants.js'
import './Topology.css'

const subnetOf = (ip) => (ip ? ip.split('.').slice(0, 2).join('.') : null)

const TYPE_ICONS = {
  Serveur: '\u{1F5A5}',
  Poste: '\u{1F4BB}',
  Caméra: '\u{1F4F7}',
  'Équipement réseau': '\u{1F310}',
  'Accès Internet': '\u{2601}',
}

export default function Topology({ devices, services }) {
  const { t } = useI18n()
  const [selected, setSelected] = useState(null)
  const [hovered, setHovered] = useState(null)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [zoom, setZoom] = useState(1)

  const registered = devices.filter((d) => !d.source || d.source === 'manual')
  const discovered = devices.filter((d) => d.source === 'discovered')
  const sel = selected == null ? null : devices.find((d) => d.id === selected)

  // Filter devices by search / type
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return devices.filter((d) => {
      if (q && !d.name.toLowerCase().includes(q) && !(d.ip || '').toLowerCase().includes(q)) return false
      if (typeFilter && d.type !== typeFilter) return false
      return true
    })
  }, [devices, search, typeFilter])

  // Subnet groups for inferred links (first 2 octets = /16)
  const subnetGroups = useMemo(() => {
    const map = {}
    filtered.forEach((d, i) => {
      const sn = subnetOf(d.ip)
      if (!sn) return
      if (!map[sn]) map[sn] = []
      map[sn].push(i)
    })
    return map
  }, [filtered])

  // Connection link pairs — ALL are dashed (inferred, not verified)
  const links = useMemo(() => {
    const result = []
    const seen = new Set()
    for (const indices of Object.values(subnetGroups)) {
      for (let a = 0; a < indices.length; a++) {
        for (let b = a + 1; b < indices.length; b++) {
          const key = `${Math.min(indices[a], indices[b])}-${Math.max(indices[a], indices[b])}`
          if (!seen.has(key)) { seen.add(key); result.push([indices[a], indices[b]]) }
        }
      }
    }
    return result
  }, [subnetGroups])

  const hasData = filtered.length > 0
  const deviceTypes = Object.keys(TYPES)

  // Grid layout for device nodes
  const CELL_W = 170, CELL_H = 108, GAP = 22, PAD = 28
  const cols = hasData ? Math.max(1, Math.min(4, Math.ceil(Math.sqrt(filtered.length * 1.4)))) : 0
  const rows = cols ? Math.ceil(filtered.length / cols) : 0
  const canvasW = cols ? cols * CELL_W + (cols - 1) * GAP + PAD * 2 : 400
  const canvasH = rows ? rows * CELL_H + (rows - 1) * GAP + PAD * 2 + 10 : 200

  const pos = (i) => ({
    x: PAD + (i % cols) * (CELL_W + GAP),
    y: PAD + Math.floor(i / cols) * (CELL_H + GAP),
  })

  const portList = (d) =>
    services.filter((s) => s.device_id === d.id).map((s) => s.port).sort((a, b) => a - b).slice(0, 4)

  return (
    <section className="topology">
      {/* ── Header ── */}
      <div className="topo-head">
        <div>
          <h2 className="topo-title">{t('topology.title')}</h2>
          <p className="topo-sub">{t('topology.subtitle')}</p>
        </div>
        <div className="topo-head-badge">
          <span className="topo-count">{filtered.length} / {devices.length}</span>
          <span className="topo-label">{t('topology.devicesL')}</span>
        </div>
      </div>

      {/* ── Toolbar ── */}
      <div className="topo-toolbar">
        <div className="topo-toolbar-left">
          <span className="topo-search-ic">{'\u{1F50D}'}</span>
          <input className="topo-search" type="text" placeholder={t('topology.search')}
            value={search} onChange={(e) => setSearch(e.target.value)} />
          <select className="topo-filter" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
            <option value="">{t('topology.allTypes')}</option>
            {deviceTypes.map((ty) => <option key={ty} value={ty}>{t(`type.${ty}`)}</option>)}
          </select>
        </div>
        <div className="topo-toolbar-right">
          <div className="topo-legend">
            {deviceTypes.map((ty) => (
              <span key={ty} className="topo-legend-item">
                <i className="topo-legend-d" style={{ background: TYPES[ty] }} />
                {t(`type.${ty}`)}
              </span>
            ))}
          </div>
          <span className="topo-sep" />
          <button className="topo-btn" title={t('topology.zoomIn')}
            onClick={() => setZoom((z) => Math.min(z + 0.2, 2.5))}>+</button>
          <button className="topo-btn" title={t('topology.zoomOut')}
            onClick={() => setZoom((z) => Math.max(z - 0.2, 0.3))}>{'\u2212'}</button>
          <button className="topo-btn" title={t('topology.fit')}
            onClick={() => setZoom(1)}>{'\u{26F6}'}</button>
          {sel && <button className="topo-btn topo-btn-pri" onClick={() => setSelected(null)}>
            {t('topology.clearSel')}</button>}
        </div>
      </div>

      {/* ── Content row: canvas + inspector ── */}
      <div className="topo-content">
        {/* ── Canvas ── */}
        <div className="topo-canvas-area">
          {!hasData ? (
            <div className="topo-empty">
              <div className="topo-empty-ic">{'\u{1F4E1}'}</div>
              <p className="topo-empty-t">{t('topology.emptyDevices')}</p>
              <p className="topo-empty-s">{t('topology.sensorPending')}</p>
            </div>
          ) : (
            <svg className="topo-svg" viewBox={`0 0 ${canvasW} ${canvasH}`}
              style={{ transform: `scale(${zoom})`, transformOrigin: '0 0' }}
              role="img" aria-label={t('topology.title')}>
              <defs>
                <filter id="topo-ns"><feDropShadow dx="0" dy="1" stdDeviation="2" floodOpacity="0.1" /></filter>
              </defs>

              {/* Inferred connection links — dashed bezier curves */}
              {links.map(([a, b], k) => {
                const pa = pos(a), pb = pos(b)
                const ax = pa.x + CELL_W / 2, ay = pa.y + CELL_H / 2
                const bx = pb.x + CELL_W / 2, by = pb.y + CELL_H / 2
                const mx = (ax + bx) / 2, my = (ay + by) / 2 - 16
                const hi = hovered != null && (hovered === a || hovered === b)
                const hiSel = selected != null && (selected === filtered[a].id || selected === filtered[b].id)
                return (
                  <path key={k} d={`M${ax},${ay} Q${mx},${my} ${bx},${by}`}
                    className={`topo-link${hi || hiSel ? ' on' : ''}`} />
                )
              })}

              {/* Device nodes */}
              {filtered.map((d, i) => {
                const p = pos(i)
                const st = STATUS.find((s) => s.k === d.status)
                const tc = TYPES[d.type] || 'var(--m)'
                const isH = hovered === i, isS = selected === d.id
                const ports = portList(d)
                const sub = subnetOf(d.ip)

                return (
                  <g key={d.id} className={`topo-node${isH ? ' hov' : ''}${isS ? ' sel' : ''}`}
                    onMouseEnter={() => setHovered(i)}
                    onMouseLeave={() => setHovered(null)}
                    onClick={() => setSelected(d.id)} style={{ cursor: 'pointer' }}>
                    {/* Card body */}
                    <rect x={p.x} y={p.y} rx="9" width={CELL_W} height={CELL_H} className="topo-n-bg" filter="url(#topo-ns)" />
                    {/* Type accent bar */}
                    <rect x={p.x + 1} y={p.y + 7} rx="2" width="3" height={CELL_H - 14} fill={tc} />
                    {/* Type icon */}
                    <text x={p.x + 16} y={p.y + 22} fontSize="15">{TYPE_ICONS[d.type] || '\u{1F4F1}'}</text>
                    {/* Status dot */}
                    <circle cx={p.x + CELL_W - 14} cy={p.y + 14} r="4.5" fill={st?.color || 'var(--status-un)'} />
                    {/* Name */}
                    <text x={p.x + 16} y={p.y + 38} className="topo-n-name">{d.name}</text>
                    {/* IP */}
                    <text x={p.x + 16} y={p.y + 52} className="topo-n-ip">{d.ip || '\u2014'}</text>
                    {/* Type label */}
                    <text x={p.x + 16} y={p.y + 66} className="topo-n-type">{d.type ? t(`type.${d.type}`) : '\u2014'}</text>
                    {/* Status text */}
                    <text x={p.x + 16} y={p.y + 80} className="topo-n-st" fill={st?.color || 'var(--status-un)'}>
                      {'\u25CF'} {st ? t(`status.${d.status}`) : '\u2014'}
                    </text>
                    {/* Port pills */}
                    {ports.length > 0 && (
                      <rect x={p.x + 16} y={p.y + 86} rx="4" width={Math.min(ports.length * 28 + 8, 120)} height="14" className="topo-n-pt-bg" />
                    )}
                    {ports.length > 0 && ports.map((pt, pi) => (
                      <text key={pi} x={p.x + 20 + pi * 28} y={p.y + 96} className="topo-n-pt-t">{pt}</text>
                    ))}
                    {ports.length === 0 && (
                      <text x={p.x + 16} y={p.y + 96} className="topo-n-pt-t dim">{t('topology.noPorts')}</text>
                    )}
                    {/* Subnet badge */}
                    {sub && (
                      <text x={p.x + CELL_W - 10} y={p.y + CELL_H - 8}
                        className="topo-n-sub" textAnchor="end">{sub}.0/16</text>
                    )}
                  </g>
                )
              })}
            </svg>
          )}
        </div>

        {/* ── Inspector (right side) ── */}
        {sel ? (
          <aside className="topo-inspector">
            <div className="topo-insp-h">{t('topology.inspectorTitle')}</div>
            <div className="topo-insp-body">
              <div className="topo-insp-row">
                <span className="topo-insp-l">{t('topology.detailName')}</span>
                <span className="topo-insp-v">{sel.name}</span>
              </div>
              <div className="topo-insp-row">
                <span className="topo-insp-l">{t('topology.detailIp')}</span>
                <span className="topo-insp-v">{sel.ip || '\u2014'}</span>
              </div>
              <div className="topo-insp-row">
                <span className="topo-insp-l">{t('topology.detailType')}</span>
                <span className="topo-insp-v">{sel.type ? t(`type.${sel.type}`) : '\u2014'}</span>
              </div>
              <div className="topo-insp-row">
                <span className="topo-insp-l">{t('topology.detailStatus')}</span>
                <span className="topo-insp-v">
                  <span className="topo-insp-dot" style={{
                    background: STATUS.find((s) => s.k === sel.status)?.color || 'var(--status-un)'
                  }} />
                  {sel.status ? t(`status.${sel.status}`) : '\u2014'}
                </span>
              </div>
              <div className="topo-insp-row">
                <span className="topo-insp-l">{t('topology.detailPorts')}</span>
                <span className="topo-insp-v">
                  {portList(sel).length > 0 ? portList(sel).join('\u00B7 ') : t('topology.noPorts')}
                </span>
              </div>
              <div className="topo-insp-row">
                <span className="topo-insp-l">{t('topology.detailSubnet')}</span>
                <span className="topo-insp-v">{subnetOf(sel.ip) ? `${subnetOf(sel.ip)}.0/16` : '\u2014'}</span>
              </div>
              <div className="topo-insp-row">
                <span className="topo-insp-l">{t('topology.detailSeen')}</span>
                <span className="topo-insp-v">{sel.last_seen ? new Date(sel.last_seen).toLocaleString() : '\u2014'}</span>
              </div>
            </div>
            <button className="topo-btn topo-btn-pri topo-insp-close" onClick={() => setSelected(null)}>
              {t('topology.clearSel')}
            </button>
          </aside>
        ) : null}
      </div>

      {/* ── Footer stats ── */}
      <div className="topo-foot">
        <span className="topo-stat">{'\u2713'} {t('topology.registered')} {registered.length}</span>
        <span className="topo-stat muted">{'\u25CB'} {t('topology.discovered')} {discovered.length}</span>
        <span className="topo-stat muted">{'\u2302'} {Object.keys(subnetGroups).length} {t('topology.subnetsL')}</span>
        <span className="topo-stat muted">{'\u27D0'} {services.length} {t('topology.servicesL')}</span>
        <span className="topo-stat muted">{t('topology.sensorStatus')}: {t('topology.sensorOffline')}</span>
      </div>
    </section>
  )
}