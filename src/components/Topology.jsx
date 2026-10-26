import { useEffect, useMemo, useRef, useState } from 'react'
import { useI18n } from '../i18n/context.js'
import { TYPES, SENSITIVE_PORTS } from '../constants.js'
import './Topology.css'

/* ── Geometry (graph units) ─────────────────────────────────────────────── */
const LEAF_W = 148
const LEAF_H = 76
const GAP_X = 14
const GAP_Y = 12
const PER_ROW = 5
const GUTTER = 26
const COL_GAP = 56
const MARGIN = 28
const HEAD_H = 22
const HEAD_GAP = 8
const CLUSTER_GAP = 26
const PILL_H = 48
const INTERNET_W = 160
const LAN_W = 176
const UNKNOWN_W = 200
const INTERNET_Y = MARGIN
const LAN_Y = INTERNET_Y + PILL_H + 76
const CLUSTER_TOP = LAN_Y + PILL_H + 52
const MIN_GRAPH_W = 360

const TYPE_KEYS = Object.keys(TYPES)

/* ── Hand-drawn type glyphs (no icon dependency) ────────────────────────── */
const ICONS = {
  Serveur: (
    <>
      <rect x="3" y="4" width="18" height="7" rx="2" />
      <rect x="3" y="13" width="18" height="7" rx="2" />
      <path d="M7 7.5h.01M7 16.5h.01" />
    </>
  ),
  Poste: (
    <>
      <rect x="2.5" y="4" width="19" height="12" rx="2" />
      <path d="M8 20h8M12 16v4" />
    </>
  ),
  Caméra: (
    <>
      <rect x="2.5" y="6" width="12" height="12" rx="2" />
      <path d="m14.5 10 5-3v10l-5-3z" />
      <circle cx="8.5" cy="12" r="2" />
    </>
  ),
  'Équipement réseau': (
    <>
      <rect x="2.5" y="8" width="19" height="8" rx="2" />
      <path d="M6 12h.01M9.5 12h.01M13 12h.01M16.5 12h.01" />
    </>
  ),
  'Accès Internet': (
    <path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z" />
  ),
  __lan: (
    <>
      <rect x="2.5" y="8" width="19" height="8" rx="2" />
      <path d="M6 12h.01M9.5 12h.01M13 12h.01M16.5 12h.01" />
    </>
  ),
  __question: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M9.5 9.5a2.5 2.5 0 1 1 4 2c-.9.7-1.5 1.2-1.5 2.5M12 17h.01" />
    </>
  ),
  __other: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 8v4M12 16h.01" />
    </>
  ),
}

function Glyph({ type, x = 0, y = 0, size = 16 }) {
  return (
    <svg
      x={x} y={y} width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"
      aria-hidden="true"
    >
      {ICONS[type] || ICONS.__other}
    </svg>
  )
}

/* ── Data helpers (stored values only, no inference beyond the IP prefix) ── */
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

function prefixOf(ip) {
  if (typeof ip !== 'string') return null
  const m = IPV4.exec(ip.trim())
  if (!m) return null
  const octets = m.slice(1, 5).map(Number)
  if (octets.some((n) => n > 255)) return null
  return `${octets[0]}.${octets[1]}.${octets[2]}`
}

const truncate = (value, max) => {
  const str = String(value ?? '')
  return str.length > max ? `${str.slice(0, max - 1)}…` : str
}

const isRecent = (value) => {
  if (!value) return false
  const ms = new Date(value).getTime()
  if (!Number.isFinite(ms)) return false
  const age = Date.now() - ms
  return age >= 0 && age < 86_400_000
}

const statusTone = (status) => {
  if (status === 'on') return 'var(--status-on)'
  if (status === 'off') return 'var(--m)'
  return 'var(--o)'
}

const zoomed = (view, factor, fit) => {
  const minW = fit.w * 0.2
  const maxW = fit.w * 2.4
  const w = Math.min(maxW, Math.max(minW, view.w * factor))
  const h = view.h * (w / view.w)
  return { x: view.x + (view.w - w) / 2, y: view.y + (view.h - h) / 2, w, h }
}

/* ── Component ─────────────────────────────────────────────────────────── */
export default function Topology({ devices = [], services = [], loaded = true }) {
  const { t } = useI18n()
  const [selected, setSelected] = useState(null)
  const [dragging, setDragging] = useState(false)
  // `null` means "use the computed fit" so the graph follows the inventory
  // until the user pans or zooms.
  const [view, setView] = useState(null)
  const mapRef = useRef(null)
  const drag = useRef(null)

  const portsByDevice = useMemo(() => {
    const map = new Map()
    for (const s of services) {
      if (!s || s.device_id == null) continue
      const list = map.get(s.device_id)
      if (list) list.push(s)
      else map.set(s.device_id, [s])
    }
    return map
  }, [services])

  /* One valid /24 per distinct first-three-octets prefix. Devices without a
     valid IPv4 go to a standalone "unknown address" group (no LAN claim). */
  const layout = useMemo(() => {
    const byPrefix = new Map()
    const unknown = []
    for (const d of devices) {
      const prefix = prefixOf(d?.ip)
      if (!prefix) {
        unknown.push(d)
        continue
      }
      const list = byPrefix.get(prefix)
      if (list) list.push(d)
      else byPrefix.set(prefix, [d])
    }

    const nets = [...byPrefix.entries()]
      .sort((a, b) => a[0].localeCompare(b[0], 'en', { numeric: true }))
      .map(([prefix, list]) => ({ key: prefix, prefix, kind: 'net', devices: list }))

    // Zero valid IPv4: keep one LAN node, labelled without a prefix.
    if (!nets.length) nets.push({ key: '__lan', prefix: null, kind: 'net', devices: [] })
    if (unknown.length) nets.push({ key: '__unknown', prefix: null, kind: 'unknown', devices: unknown })

    for (const net of nets) {
      const byType = new Map()
      for (const d of net.devices) {
        const key = Object.hasOwn(TYPES, d.type) ? d.type : '__other'
        const list = byType.get(key)
        if (list) list.push(d)
        else byType.set(key, [d])
      }
      const clusters = [...TYPE_KEYS, '__other']
        .map((key) => ({
          type: key,
          devices: (byType.get(key) || []).slice()
            .sort((a, b) => String(a.name || '').localeCompare(String(b.name || ''))),
        }))
        .filter((cluster) => cluster.devices.length)

      const widest = Math.max(1, ...clusters.map((c) => Math.min(PER_ROW, c.devices.length)))
      const gridW = widest * LEAF_W + (widest - 1) * GAP_X
      net.clusters = clusters
      net.gridW = gridW
      net.width = Math.max(gridW + GUTTER + 8, LAN_W + 40)
    }

    let cursor = MARGIN
    let deepest = CLUSTER_TOP
    for (const net of nets) {
      net.left = cursor
      net.center = cursor + net.width / 2
      net.gridLeft = cursor + GUTTER
      let y = CLUSTER_TOP
      for (const cluster of net.clusters) {
        cluster.headY = y
        cluster.gridTop = y + HEAD_H + HEAD_GAP
        const rows = Math.ceil(cluster.devices.length / PER_ROW)
        cluster.gridH = rows * LEAF_H + Math.max(0, rows - 1) * GAP_Y
        cluster.cards = cluster.devices.map((device, i) => ({
          device,
          x: net.gridLeft + (i % PER_ROW) * (LEAF_W + GAP_X),
          y: cluster.gridTop + Math.floor(i / PER_ROW) * (LEAF_H + GAP_Y),
        }))
        y = cluster.gridTop + cluster.gridH + CLUSTER_GAP
      }
      net.bottom = y - CLUSTER_GAP
      deepest = Math.max(deepest, net.bottom)
      cursor += net.width + COL_GAP
    }

    const totalW = Math.max(MIN_GRAPH_W, cursor - COL_GAP + MARGIN)
    const totalH = Math.max(260, deepest + MARGIN)
    return { nets, totalW, totalH }
  }, [devices])

  const fitView = useMemo(
    () => ({ x: -26, y: -20, w: layout.totalW + 52, h: layout.totalH + 40 }),
    [layout.totalW, layout.totalH],
  )
  const current = view ?? fitView

  /* Ctrl/Cmd + wheel zooms, plain wheel keeps the page scroll. */
  useEffect(() => {
    const el = mapRef.current
    if (!el) return undefined
    const onWheel = (event) => {
      if (!event.ctrlKey && !event.metaKey) return
      event.preventDefault()
      setView((previous) => zoomed(previous ?? fitView, event.deltaY > 0 ? 1.16 : 0.86, fitView))
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [fitView])

  const zoomBy = (factor) => setView((previous) => zoomed(previous ?? fitView, factor, fitView))
  const nudge = (dx, dy) => setView((previous) => {
    const base = previous ?? fitView
    const step = base.w * 0.08
    return { ...base, x: base.x + dx * step, y: base.y + dy * step }
  })

  const onKeyDown = (event) => {
    if (event.altKey || event.ctrlKey || event.metaKey) return
    const key = event.key
    if (key === 'ArrowLeft') { event.preventDefault(); nudge(-1, 0) }
    else if (key === 'ArrowRight') { event.preventDefault(); nudge(1, 0) }
    else if (key === 'ArrowUp') { event.preventDefault(); nudge(0, -1) }
    else if (key === 'ArrowDown') { event.preventDefault(); nudge(0, 1) }
    else if (key === '+' || key === '=') { event.preventDefault(); zoomBy(0.86) }
    else if (key === '-' || key === '_') { event.preventDefault(); zoomBy(1.16) }
    else if (key === '0' || key === 'Home') { event.preventDefault(); setView(fitView) }
  }

  const onPointerDown = (event) => {
    if (event.button !== 0) return
    const el = mapRef.current
    if (!el) return
    const rect = el.getBoundingClientRect()
    drag.current = {
      id: event.pointerId,
      x: event.clientX,
      y: event.clientY,
      view: current,
      scale: Math.max(current.w / rect.width, current.h / rect.height),
      moved: false,
    }
    el.setPointerCapture?.(event.pointerId)
    setDragging(true)
  }

  const onPointerMove = (event) => {
    const info = drag.current
    if (!info || info.id !== event.pointerId) return
    const dx = event.clientX - info.x
    const dy = event.clientY - info.y
    if (Math.abs(dx) + Math.abs(dy) > 3) info.moved = true
    setView({ ...info.view, x: info.view.x - dx * info.scale, y: info.view.y - dy * info.scale })
  }

  const onPointerUp = (event) => {
    const info = drag.current
    if (!info) return
    drag.current = null
    setDragging(false)
    mapRef.current?.releasePointerCapture?.(event.pointerId)
    if (!info.moved) setSelected(null)
  }

  const typeLabel = (type) => {
    if (type === '__other' || !Object.hasOwn(TYPES, type)) return t('topology.otherType')
    const key = `type.${type}`
    const label = t(key)
    return label === key ? t('topology.otherType') : label
  }
  const statusLabel = (status) => {
    const key = `status.${status}`
    const label = t(key)
    return label === key ? '—' : label
  }
  const portWord = (n) => (n === 1 ? t('topology.portOne') : t('topology.portMany'))
  const deviceWord = (n) => (n === 1 ? t('topology.deviceOne') : t('topology.deviceMany'))

  const visibleNets = layout.nets.filter((net) => net.kind === 'net')
  const internetCx = layout.totalW / 2

  return (
    <section className="topology">
      <div className="topo-head">
        <div className="topo-head-text">
          <h2 className="topo-title">{t('topology.title')}</h2>
          <p className="topo-sub">{t('topology.subtitle')}</p>
        </div>
        <span className="topo-count">
          <b>{devices.length}</b>
          {deviceWord(devices.length)}
        </span>
      </div>

      {!loaded ? (
        <p className="topo-state" role="status">{t('topology.loading')}</p>
      ) : devices.length === 0 ? (
        <div className="topo-empty">
          <div className="topo-empty-icon" aria-hidden="true">
            <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="4" width="18" height="7" rx="2" />
              <rect x="3" y="13" width="18" height="7" rx="2" />
              <path d="M7 7.5h.01M7 16.5h.01" />
            </svg>
          </div>
          <h3 className="topo-empty-title">{t('topology.emptyTitle')}</h3>
          <p className="topo-empty-text">{t('topology.emptyText')}</p>
          <div className="topo-empty-cmd">
            <span className="topo-empty-cmd-label">{t('topology.emptyCmd')}</span>
            <code>node --env-file=agent/.env agent/scan.mjs --yes --cidr=192.168.1.0/24</code>
          </div>
          <p className="topo-empty-warning">{t('topology.emptyWarning')}</p>
        </div>
      ) : (
        <>
          <p className="topo-note">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <circle cx="12" cy="12" r="9" />
              <path d="M12 11v5M12 8h.01" />
            </svg>
            <span>{t('topology.legend')}</span>
          </p>

          <div
            className={`topo-map${dragging ? ' is-drag' : ''}`}
            ref={mapRef}
            tabIndex={0}
            role="region"
            aria-label={t('topology.mapLabel')}
            aria-describedby="topo-canvas-hint"
            onKeyDown={onKeyDown}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerCancel={onPointerUp}
          >
            <span id="topo-canvas-hint" className="sr-only">{t('topology.canvasHint')}</span>

            <div className="topo-rail" onPointerDown={(event) => event.stopPropagation()}>
              <button type="button" aria-label={t('topology.zoomIn')} title={t('topology.zoomIn')} onClick={() => zoomBy(0.86)}>
                <span aria-hidden="true">+</span>
              </button>
              <button type="button" aria-label={t('topology.zoomOut')} title={t('topology.zoomOut')} onClick={() => zoomBy(1.16)}>
                <span aria-hidden="true">−</span>
              </button>
              <button type="button" aria-label={t('topology.fit')} title={t('topology.fit')} onClick={() => setView(fitView)}>
                <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                  strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M4 9V5.5A1.5 1.5 0 0 1 5.5 4H9M15 4h3.5A1.5 1.5 0 0 1 20 5.5V9M20 15v3.5a1.5 1.5 0 0 1-1.5 1.5H15M9 20H5.5A1.5 1.5 0 0 1 4 18.5V15" />
                </svg>
              </button>
            </div>

            <svg className="topo-svg" viewBox={`${current.x} ${current.y} ${current.w} ${current.h}`} preserveAspectRatio="xMidYMid meet">
              {/* Membership edges only: Internet → LAN, LAN → type cluster. */}
              {visibleNets.map((net) => (
                <path
                  key={`edge-net-${net.key}`}
                  className="topo-edge"
                  d={`M ${internetCx} ${INTERNET_Y + PILL_H} C ${internetCx} ${LAN_Y - 42}, ${net.center} ${LAN_Y - 42}, ${net.center} ${LAN_Y}`}
                />
              ))}
              {layout.nets.map((net) => (
                net.kind === 'net'
                  ? net.clusters.map((cluster) => (
                    <path
                      key={`edge-cluster-${net.key}-${cluster.type}`}
                      className="topo-edge"
                      d={`M ${net.center} ${LAN_Y + PILL_H} C ${net.center} ${LAN_Y + PILL_H + 46}, ${net.left + 8} ${cluster.headY - 34}, ${net.left + 8} ${cluster.headY + 10}`}
                    />
                  ))
                  : null
              ))}

              {/* Conceptual Internet node */}
              <g className="topo-pill is-internet">
                <rect x={internetCx - INTERNET_W / 2} y={INTERNET_Y} width={INTERNET_W} height={PILL_H} rx="16" className="topo-pill-bg" />
                <Glyph type="Accès Internet" x={internetCx - INTERNET_W / 2 + 18} y={INTERNET_Y + 15} size={18} />
                <text x={internetCx - INTERNET_W / 2 + 44} y={INTERNET_Y + 22} className="topo-pill-title">{t('topology.internet')}</text>
                <text x={internetCx - INTERNET_W / 2 + 44} y={INTERNET_Y + 35} className="topo-pill-meta">{t('topology.internetHint')}</text>
              </g>

              {visibleNets.length > 1 && (
                <g className="topo-netlabel-group">
                  <rect x={internetCx - 78} y={LAN_Y - 36} width="156" height="24" rx="12" className="topo-netlabel-bg" />
                  <text x={internetCx} y={LAN_Y - 20} textAnchor="middle" className="topo-netlabel">{t('topology.networksSeen')}</text>
                </g>
              )}

              {/* LAN nodes */}
              {layout.nets.filter((net) => net.kind === 'net').map((net) => (
                <g key={`lan-${net.key}`} className="topo-pill is-lan">
                  <rect x={net.center - LAN_W / 2} y={LAN_Y} width={LAN_W} height={PILL_H} rx="16" className="topo-pill-bg" />
                  <Glyph type="__lan" x={net.center - LAN_W / 2 + 16} y={LAN_Y + 15} size={18} />
                  <text x={net.center - LAN_W / 2 + 42} y={LAN_Y + 22} className="topo-pill-title">
                    {net.prefix ? `${net.prefix}.0/24` : t('topology.lan')}
                  </text>
                  <text x={net.center - LAN_W / 2 + 42} y={LAN_Y + 35} className="topo-pill-meta">
                    {net.devices.length} {deviceWord(net.devices.length)}
                  </text>
                </g>
              ))}

              {/* Devices without a valid IPv4: standalone group, no LAN claim */}
              {layout.nets.filter((net) => net.kind === 'unknown').map((net) => (
                <g key={`unknown-${net.key}`} className="topo-pill is-unknown">
                  <rect x={net.center - UNKNOWN_W / 2} y={LAN_Y} width={UNKNOWN_W} height={PILL_H} rx="16" className="topo-pill-bg" />
                  <Glyph type="__question" x={net.center - UNKNOWN_W / 2 + 16} y={LAN_Y + 15} size={18} />
                  <text x={net.center - UNKNOWN_W / 2 + 42} y={LAN_Y + 22} className="topo-pill-title">{t('topology.lanUnknown')}</text>
                  <text x={net.center - UNKNOWN_W / 2 + 42} y={LAN_Y + 35} className="topo-pill-meta">
                    {net.devices.length} {deviceWord(net.devices.length)}
                  </text>
                </g>
              ))}

              {/* Cluster headings + device cards */}
              {layout.nets.map((net) => net.clusters.map((cluster) => (
                <g key={`cluster-${net.key}-${cluster.type}`}>
                  <rect
                    x={net.left + 6} y={cluster.headY + 4} width="3" height="12" rx="1.5"
                    fill={TYPES[cluster.type] || 'var(--m)'}
                  />
                  <text x={net.left + 16} y={cluster.headY + 13} className="topo-cluster">
                    {typeLabel(cluster.type)}
                    <tspan className="topo-cluster-count"> · {cluster.devices.length}</tspan>
                  </text>

                  {cluster.cards.map(({ device: d, x, y }) => {
                    const rawName = String(d.name ?? '').trim()
                    const ip = String(d.ip ?? '').trim()
                    const sameAsIp = ip && rawName === ip
                    const title = rawName || ip || '—'
                    const subtitle = sameAsIp ? typeLabel(d.type) : (ip || '—')
                    const ports = portsByDevice.get(d.id) || []
                    const portCount = ports.length
                    const sensitiveCount = ports.filter((s) => SENSITIVE_PORTS.includes(Number(s.port))).length
                    const recent = isRecent(d.created_at)
                    const label = statusLabel(d.status)
                    const isSelected = selected === d.id
                    const offline = d.status === 'off'

                    const chips = []
                    let chipX = x + 9
                    if (portCount > 0) {
                      const width = 22 + String(portCount).length * 5
                      chips.push({ key: 'ports', kind: 'ports', text: String(portCount), width, x: chipX })
                      chipX += width + 4
                    }
                    if (sensitiveCount > 0) {
                      const width = 22 + String(sensitiveCount).length * 5
                      chips.push({ key: 'sens', kind: 'sens', text: String(sensitiveCount), width, x: chipX })
                      chipX += width + 4
                    }
                    if (recent) {
                      const text = t('topology.newBadge')
                      const width = 12 + text.length * 4.6
                      chips.push({ key: 'new', kind: 'new', text, width: Math.round(width), x: chipX })
                    }

                    return (
                      <g
                        key={d.id}
                        className={`topo-leaf${offline ? ' is-off' : ''}${isSelected ? ' is-sel' : ''}`}
                        role="button"
                        tabIndex={0}
                        aria-pressed={isSelected}
                        aria-label={`${title}, ${ip || '—'}, ${typeLabel(d.type)}, ${label}, ${portCount} ${portWord(portCount)}`}
                        style={{ '--tc': TYPES[d.type] || 'var(--m)' }}
                        onPointerDown={(event) => event.stopPropagation()}
                        onClick={(event) => {
                          event.stopPropagation()
                          setSelected((previous) => (previous === d.id ? null : d.id))
                        }}
                        onKeyDown={(event) => {
                          if (event.key !== 'Enter' && event.key !== ' ') return
                          event.preventDefault()
                          event.stopPropagation()
                          setSelected((previous) => (previous === d.id ? null : d.id))
                        }}
                      >
                        <title>{`${title} — ${ip || '—'}`}</title>
                        <rect x={x - 2} y={y - 2} width={LEAF_W + 4} height={LEAF_H + 4} rx="14" className="topo-leaf-halo" />
                        <rect x={x} y={y} width={LEAF_W} height={LEAF_H} rx="12" className="topo-leaf-bg" />
                        <rect x={x + 9} y={y + 9} width="26" height="26" rx="8" className="topo-leaf-icon-bg" />
                        <Glyph type={Object.hasOwn(TYPES, d.type) ? d.type : '__other'} x={x + 14} y={y + 14} size={16} />
                        <text x={x + 42} y={y + 21} className="topo-leaf-name">{truncate(title, 10)}</text>
                        <circle cx={x + LEAF_W - 13} cy={y + 13} r="3.4" fill={statusTone(d.status)} />
                        <text x={x + LEAF_W - 9} y={y + 27} textAnchor="end" className="topo-leaf-status">{label}</text>
                        <text x={x + 42} y={y + 37} className="topo-leaf-ip">{truncate(subtitle, 16)}</text>

                        {chips.map((chip) => (
                          <g key={chip.key} className={`topo-chip is-${chip.kind}`} transform={`translate(${chip.x},${y + 52})`}>
                            <title>
                              {chip.kind === 'sens'
                                ? t('topology.sensitivePorts', { n: sensitiveCount })
                                : chip.kind === 'ports'
                                  ? t('topology.openPorts', { n: portCount })
                                  : t('topology.newBadge')}
                            </title>
                            <rect width={chip.width} height="13" rx="6.5" />
                            {chip.kind === 'ports' && (
                              <svg x="5" y="2.5" width="8" height="8" viewBox="0 0 12 12" fill="none"
                                stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" aria-hidden="true">
                                <rect x="1.5" y="3" width="9" height="6" rx="1" />
                                <path d="M4 6h.01M6 6h.01M8 6h.01" />
                              </svg>
                            )}
                            {chip.kind === 'sens' && (
                              <svg x="5" y="2.5" width="8" height="8" viewBox="0 0 12 12" fill="none"
                                stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                <path d="M6 1.5 11 10.5H1z" />
                                <path d="M6 5v2.5M6 9h.01" />
                              </svg>
                            )}
                            <text
                              x={chip.kind === 'new' ? chip.width / 2 : 16}
                              y="9.4"
                              textAnchor={chip.kind === 'new' ? 'middle' : 'start'}
                            >
                              {chip.text}
                            </text>
                          </g>
                        ))}
                      </g>
                    )
                  })}
                </g>
              )))}
            </svg>
          </div>

          <div className="topo-foot">
            <span>{t('topology.typeEstimated')}</span>
            <span>{t('topology.statusSource')}</span>
          </div>
        </>
      )}
    </section>
  )
}
