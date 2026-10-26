import { useEffect, useMemo, useRef, useState } from 'react'
import { useI18n } from '../i18n/context.js'
import { TYPES, SENSITIVE_PORTS } from '../constants.js'
import './Topology.css'

/* ── Geometry (graph units) ─────────────────────────────────────────────── */
const LEAF_W = 196
const LEAF_H = 96
const GAP_X = 14
const GAP_Y = 14
const GUTTER = 28
const COL_GAP = 48
const MARGIN = 24
const HEAD_H = 24
const HEAD_GAP = 8
const CLUSTER_GAP = 16
const CLUSTER_COL_GAP = 20
const PILL_H = 52
const INTERNET_W = 176
const LAN_W = 200
const UNKNOWN_W = 220
const INTERNET_Y = MARGIN
const LAN_Y = INTERNET_Y + PILL_H + 40
const CLUSTER_TOP = LAN_Y + PILL_H + 24
const MIN_GRAPH_W = 360
const FIT_PAD_X = 14
const FIT_PAD_Y = 12
const MAX_FIT_SCALE = 1.4
// Both grids are tried and the best fit for the measured canvas is kept:
// cards per row inside a type cluster, and type clusters side by side.
const PER_ROW_OPTIONS = [1, 2, 3, 4, 5, 6]
const CLUSTER_COL_OPTIONS = [1, 2, 3, 4]

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

/* Approximate text metrics so long names wrap inside the card instead of
   being cut, including wide (CJK/emoji) characters. */
const charWidth = (ch, size) => {
  const code = ch.codePointAt(0)
  if (ch === ' ') return size * 0.32
  const wide = code > 0xffff
    || (code >= 0x1100 && code <= 0x115f)
    || (code >= 0x2e80 && code <= 0x9fff)
    || (code >= 0xac00 && code <= 0xd7a3)
    || (code >= 0xf900 && code <= 0xfaff)
    || (code >= 0xfe30 && code <= 0xfe4f)
    || (code >= 0xff00 && code <= 0xff60)
  return wide ? size : size * 0.55
}

const estimateTextWidth = (value, size) => {
  let width = 0
  for (const ch of String(value ?? '')) width += charWidth(ch, size)
  return width
}

function wrapText(value, maxWidth, size = 13.5, maxLines = 2) {
  const text = String(value ?? '').replace(/\s+/g, ' ').trim()
  if (!text) return { lines: ['—'], truncated: false }
  const lines = []
  let rest = text
  while (rest && lines.length < maxLines) {
    if (estimateTextWidth(rest, size) <= maxWidth) {
      lines.push(rest)
      rest = ''
      break
    }
    const chars = Array.from(rest)
    let width = 0
    let fit = 0
    let lastSpace = -1
    for (let i = 0; i < chars.length; i += 1) {
      const w = charWidth(chars[i], size)
      if (width + w > maxWidth) break
      width += w
      fit = i + 1
      if (chars[i] === ' ') lastSpace = i
    }
    if (fit === 0) fit = 1
    const cut = lastSpace > 0 ? lastSpace : fit
    lines.push(chars.slice(0, cut).join('').trimEnd())
    rest = chars.slice(cut).join('').trimStart()
  }
  const truncated = Boolean(rest)
  if (rest) {
    const last = lines[lines.length - 1] || ''
    const budget = maxWidth - estimateTextWidth('…', size)
    let width = 0
    let out = ''
    for (const ch of last) {
      const w = charWidth(ch, size)
      if (width + w > budget) break
      width += w
      out += ch
    }
    lines[lines.length - 1] = `${out.trimEnd()}…`
  }
  return { lines: lines.length ? lines : ['—'], truncated }
}

const zoomed = (view, factor, fit) => {
  const minW = fit.w * 0.2
  const maxW = fit.w * 2.4
  const w = Math.min(maxW, Math.max(minW, view.w * factor))
  const h = view.h * (w / view.w)
  return { x: view.x + (view.w - w) / 2, y: view.y + (view.h - h) / 2, w, h }
}

/* ── Graph construction ─────────────────────────────────────────────────── */
function buildBaseNets(devices) {
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
    net.clusters = [...TYPE_KEYS, '__other']
      .map((key) => ({
        type: key,
        devices: (byType.get(key) || []).slice()
          .sort((a, b) => String(a.name || '').localeCompare(String(b.name || ''))),
      }))
      .filter((cluster) => cluster.devices.length)
  }
  return nets
}

function placeNets(baseNets, perRow, clusterCols) {
  const nets = baseNets.map((base) => ({
    ...base,
    rows: [],
    clusters: base.clusters.map((cluster) => ({
      type: cluster.type,
      devices: cluster.devices,
      cards: [],
    })),
  }))

  let cursor = MARGIN
  let deepest = CLUSTER_TOP
  for (const net of nets) {
    net.left = cursor

    // Measure every type block, then pack the blocks into cluster rows.
    for (const cluster of net.clusters) {
      const count = cluster.devices.length
      const usedCols = Math.min(perRow, count)
      const rows = Math.ceil(count / perRow)
      cluster.gridW = usedCols * LEAF_W + Math.max(0, usedCols - 1) * GAP_X
      cluster.gridH = rows * LEAF_H + Math.max(0, rows - 1) * GAP_Y
      cluster.blockW = GUTTER + cluster.gridW + 8
      cluster.blockH = HEAD_H + HEAD_GAP + cluster.gridH
    }

    const cols = net.clusters.length ? Math.min(clusterCols, net.clusters.length) : 1
    const chunks = []
    for (let i = 0; i < net.clusters.length; i += cols) chunks.push(net.clusters.slice(i, i + cols))
    const rowWidths = chunks.map((chunk) => chunk.reduce((sum, cluster) => sum + cluster.blockW, 0)
      + Math.max(0, chunk.length - 1) * CLUSTER_COL_GAP)
    net.width = Math.max(LAN_W + 40, ...rowWidths)
    net.center = net.left + net.width / 2
    net.spineX = net.left + 8

    let rowTop = CLUSTER_TOP
    for (let r = 0; r < chunks.length; r += 1) {
      const chunk = chunks[r]
      const rowH = Math.max(...chunk.map((cluster) => cluster.blockH))
      let x = net.left + (net.width - rowWidths[r]) / 2
      for (const cluster of chunk) {
        cluster.left = x
        cluster.headY = rowTop
        cluster.gridTop = rowTop + HEAD_H + HEAD_GAP
        cluster.gridLeft = x + GUTTER
        cluster.cards = cluster.devices.map((device, i) => ({
          device,
          x: cluster.gridLeft + (i % perRow) * (LEAF_W + GAP_X),
          y: cluster.gridTop + Math.floor(i / perRow) * (LEAF_H + GAP_Y),
        }))
        x += cluster.blockW + CLUSTER_COL_GAP
      }
      net.rows.push({ busY: rowTop - 8, clusters: chunk })
      rowTop += rowH + CLUSTER_GAP
    }

    net.bottom = net.clusters.length ? rowTop - CLUSTER_GAP : CLUSTER_TOP
    deepest = Math.max(deepest, net.bottom)
    cursor += net.width + COL_GAP
  }

  return {
    nets,
    perRow,
    clusterCols,
    totalW: Math.max(MIN_GRAPH_W, cursor - COL_GAP + MARGIN),
    totalH: Math.max(260, deepest + MARGIN),
  }
}

/* ── Component ─────────────────────────────────────────────────────────── */
export default function Topology({ devices = [], services = [], loaded = true }) {
  const { t } = useI18n()
  const [selected, setSelected] = useState(null)
  const [dragging, setDragging] = useState(false)
  // `null` means "use the computed fit" so the graph follows the inventory
  // until the user pans or zooms.
  const [view, setView] = useState(null)
  const [mapBox, setMapBox] = useState({ w: 0, h: 0 })
  const mapRef = useRef(null)
  const drag = useRef(null)
  const hasMap = loaded && devices.length > 0

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

  useEffect(() => {
    if (!hasMap) return undefined
    const el = mapRef.current
    if (!el || typeof ResizeObserver === 'undefined') return undefined
    const measure = () => {
      const rect = el.getBoundingClientRect()
      const w = Math.round(rect.width)
      const h = Math.round(rect.height)
      setMapBox((previous) => (previous.w === w && previous.h === h ? previous : { w, h }))
    }
    const observer = new ResizeObserver(measure)
    observer.observe(el)
    return () => observer.disconnect()
  }, [hasMap])

  /* One valid /24 per distinct first-three-octets prefix. Devices without a
     valid IPv4 go to a standalone "unknown address" group (no LAN claim).
     The per-row count is picked so the fit zooms in as much as the canvas
     allows instead of scaling readable text down to nothing. */
  const layout = useMemo(() => {
    const base = buildBaseNets(devices)
    const candidates = []
    for (const perRow of PER_ROW_OPTIONS) {
      for (const clusterCols of CLUSTER_COL_OPTIONS) {
        candidates.push(placeNets(base, perRow, clusterCols))
      }
    }
    if (!mapBox.w || !mapBox.h) {
      return candidates.find((candidate) => candidate.perRow === 3 && candidate.clusterCols === 2) ?? candidates[0]
    }
    let best = candidates[0]
    let bestScale = -Infinity
    for (const candidate of candidates) {
      const scale = Math.min(
        mapBox.w / (candidate.totalW + FIT_PAD_X * 2),
        mapBox.h / (candidate.totalH + FIT_PAD_Y * 2),
      )
      if (scale > bestScale + 0.0001) {
        best = candidate
        bestScale = scale
      }
    }
    return best
  }, [devices, mapBox.w, mapBox.h])

  const fitView = useMemo(() => {
    const w0 = layout.totalW + FIT_PAD_X * 2
    const h0 = layout.totalH + FIT_PAD_Y * 2
    const base = { x: -FIT_PAD_X, y: -FIT_PAD_Y, w: w0, h: h0 }
    if (!mapBox.w || !mapBox.h) return base
    const scale = Math.min(mapBox.w / w0, mapBox.h / h0)
    if (scale <= MAX_FIT_SCALE) return base
    const k = scale / MAX_FIT_SCALE
    const w = w0 * k
    const h = h0 * k
    return { x: layout.totalW / 2 - w / 2, y: layout.totalH / 2 - h / 2, w, h }
  }, [layout.totalW, layout.totalH, mapBox.w, mapBox.h])
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
              {/* Membership edges only: Internet → LAN, LAN → cluster rows → cards. */}
              {visibleNets.map((net) => (
                <path
                  key={`edge-net-${net.key}`}
                  className="topo-edge"
                  d={`M ${internetCx} ${INTERNET_Y + PILL_H} C ${internetCx} ${LAN_Y - 42}, ${net.center} ${LAN_Y - 42}, ${net.center} ${LAN_Y}`}
                />
              ))}
              {layout.nets.map((net) => {
                if (net.kind !== 'net' || !net.rows.length) return null
                const spineX = net.spineX
                const topY = LAN_Y + PILL_H
                const endY = net.rows[net.rows.length - 1].busY
                return (
                  <g key={`net-tree-${net.key}`} className="topo-links" aria-hidden="true">
                    <path
                      className="topo-edge"
                      d={`M ${net.center} ${topY} C ${net.center} ${topY + 22}, ${spineX} ${topY + 12}, ${spineX} ${topY + 34} L ${spineX} ${endY}`}
                    />
                    {net.rows.map((row, index) => {
                      const last = row.clusters[row.clusters.length - 1]
                      const busEndX = last.left + 8
                      return (
                        <g key={`net-row-${index}`}>
                          {busEndX > spineX + 1 && (
                            <path
                              className="topo-edge"
                              d={`M ${spineX} ${row.busY} C ${spineX + 12} ${row.busY}, ${busEndX - 12} ${row.busY}, ${busEndX} ${row.busY}`}
                            />
                          )}
                          {row.clusters.map((cluster) => (
                            <path
                              key={`net-drop-${cluster.type}`}
                              className="topo-edge"
                              d={`M ${cluster.left + 8} ${row.busY} L ${cluster.left + 8} ${cluster.headY + 4}`}
                            />
                          ))}
                        </g>
                      )
                    })}
                  </g>
                )
              })}

              {/* Conceptual Internet node */}
              <g className="topo-pill is-internet">
                <rect x={internetCx - INTERNET_W / 2} y={INTERNET_Y} width={INTERNET_W} height={PILL_H} rx="16" className="topo-pill-bg" />
                <Glyph type="Accès Internet" x={internetCx - INTERNET_W / 2 + 18} y={INTERNET_Y + 17} size={20} />
                <text x={internetCx - INTERNET_W / 2 + 46} y={INTERNET_Y + 26} className="topo-pill-title">{t('topology.internet')}</text>
                <text x={internetCx - INTERNET_W / 2 + 46} y={INTERNET_Y + 41} className="topo-pill-meta">{t('topology.internetHint')}</text>
              </g>

              {visibleNets.length > 1 && (
                <g className="topo-netlabel-group">
                  <rect x={internetCx - 84} y={LAN_Y - 30} width="168" height="24" rx="12" className="topo-netlabel-bg" />
                  <text x={internetCx} y={LAN_Y - 14} textAnchor="middle" className="topo-netlabel">{t('topology.networksSeen')}</text>
                </g>
              )}

              {/* LAN nodes */}
              {layout.nets.filter((net) => net.kind === 'net').map((net) => (
                <g key={`lan-${net.key}`} className="topo-pill is-lan">
                  <rect x={net.center - LAN_W / 2} y={LAN_Y} width={LAN_W} height={PILL_H} rx="16" className="topo-pill-bg" />
                  <Glyph type="__lan" x={net.center - LAN_W / 2 + 18} y={LAN_Y + 17} size={20} />
                  <text x={net.center - LAN_W / 2 + 46} y={LAN_Y + 26} className="topo-pill-title">
                    {net.prefix ? `${net.prefix}.0/24` : t('topology.lan')}
                  </text>
                  <text x={net.center - LAN_W / 2 + 46} y={LAN_Y + 41} className="topo-pill-meta">
                    {net.devices.length} {deviceWord(net.devices.length)}
                  </text>
                </g>
              ))}

              {/* Devices without a valid IPv4: standalone group, no LAN claim */}
              {layout.nets.filter((net) => net.kind === 'unknown').map((net) => (
                <g key={`unknown-${net.key}`} className="topo-pill is-unknown">
                  <rect x={net.center - UNKNOWN_W / 2} y={LAN_Y} width={UNKNOWN_W} height={PILL_H} rx="16" className="topo-pill-bg" />
                  <Glyph type="__question" x={net.center - UNKNOWN_W / 2 + 18} y={LAN_Y + 17} size={20} />
                  <text x={net.center - UNKNOWN_W / 2 + 46} y={LAN_Y + 26} className="topo-pill-title">{t('topology.lanUnknown')}</text>
                  <text x={net.center - UNKNOWN_W / 2 + 46} y={LAN_Y + 41} className="topo-pill-meta">
                    {net.devices.length} {deviceWord(net.devices.length)}
                  </text>
                </g>
              ))}

              {/* Cluster headings, cluster→card membership lines, device cards */}
              {layout.nets.map((net) => net.clusters.map((cluster) => {
                const spineX = cluster.left + 8
                const rows = []
                for (const card of cluster.cards) {
                  const index = Math.round((card.y - cluster.gridTop) / (LEAF_H + GAP_Y))
                  if (!rows[index]) rows[index] = []
                  rows[index].push(card)
                }
                const lastRow = rows[rows.length - 1]
                const spineStart = cluster.headY + 10
                const spineEnd = lastRow[0].y - 7
                const spineStep = (spineEnd - spineStart) / 3

                return (
                  <g key={`cluster-${net.key}-${cluster.type}`}>
                    <rect
                      x={cluster.left + 6} y={cluster.headY + 4} width="3" height="14" rx="1.5"
                      fill={TYPES[cluster.type] || 'var(--m)'}
                    />
                    <text x={cluster.left + 16} y={cluster.headY + 14} className="topo-cluster">
                      {typeLabel(cluster.type)}
                      <tspan className="topo-cluster-count"> · {cluster.devices.length}</tspan>
                    </text>

                    {cluster.cards.length > 0 && (
                      <g className="topo-links" aria-hidden="true">
                        {/* Cluster spine, then a bus above each row and a drop into each card. */}
                        <path
                          className="topo-edge"
                          d={`M ${spineX} ${spineStart} C ${spineX} ${spineStart + spineStep}, ${spineX} ${spineEnd - spineStep}, ${spineX} ${spineEnd}`}
                        />
                        {rows.map((row, rowIndex) => {
                          const busY = row[0].y - 7
                          const firstCx = row[0].x + LEAF_W / 2
                          const lastCx = row[row.length - 1].x + LEAF_W / 2
                          return (
                            <g key={`row-${rowIndex}`}>
                              <path
                                className="topo-edge"
                                d={`M ${spineX} ${busY} C ${spineX + 12} ${busY}, ${firstCx - 12} ${busY}, ${firstCx} ${busY}`}
                              />
                              {row.length > 1 && (
                                <path
                                  className="topo-edge"
                                  d={`M ${firstCx} ${busY} C ${firstCx + 12} ${busY}, ${lastCx - 12} ${busY}, ${lastCx} ${busY}`}
                                />
                              )}
                              {row.map(({ device, x, y }) => {
                                const cx = x + LEAF_W / 2
                                return (
                                  <path
                                    key={`drop-${device.id}`}
                                    className="topo-edge"
                                    d={`M ${cx} ${busY} C ${cx} ${busY + 3}, ${cx} ${y - 3}, ${cx} ${y}`}
                                  />
                                )
                              })}
                            </g>
                          )
                        })}
                      </g>
                    )}

                    {cluster.cards.map(({ device: d, x, y }) => {
                      const rawName = String(d.name ?? '').trim()
                      const ip = String(d.ip ?? '').trim()
                      const ipMatchesName = Boolean(ip) && rawName === ip
                      const displayName = rawName || ip || '—'
                      let secondary = ip || '—'
                      if (!ip || ipMatchesName) secondary = typeLabel(d.type)
                      const nameWidth = LEAF_W - 58
                      let nameFit = wrapText(displayName, nameWidth, 13.5, 2)
                      let nameSize = 13.5
                      if (nameFit.truncated) {
                        for (const size of [12.5, 11.5, 11, 10.5]) {
                          const next = wrapText(displayName, nameWidth, size, 2)
                          if (!next.truncated) {
                            nameFit = next
                            nameSize = size
                            break
                          }
                        }
                      }
                      const nameTop = nameFit.lines.length > 1 ? y + 24 : y + 33
                      const nameStep = nameSize < 13 ? 16 : 17
                      const ports = portsByDevice.get(d.id) || []
                      const portCount = ports.length
                      const sensitiveCount = ports.filter((s) => SENSITIVE_PORTS.includes(Number(s.port))).length
                      const recent = isRecent(d.created_at)
                      const label = statusLabel(d.status)
                      const isSelected = selected === d.id
                      const offline = d.status === 'off'

                      const chipItems = []
                      if (portCount > 0) {
                        chipItems.push({ key: 'ports', kind: 'ports', text: String(portCount), width: 24 + String(portCount).length * 5.5 })
                      }
                      if (sensitiveCount > 0) {
                        chipItems.push({ key: 'sens', kind: 'sens', text: String(sensitiveCount), width: 24 + String(sensitiveCount).length * 5.5 })
                      }
                      if (recent) {
                        const text = t('topology.newBadge')
                        chipItems.push({ key: 'new', kind: 'new', text, width: 14 + text.length * 5.4 })
                      }
                      // Keep the status text readable: if the bottom row is too
                      // tight, drop the least important chip (the real count is
                      // still in the accessible label and in the table).
                      const chipGap = 4
                      const totalWidth = (list) => list.reduce((sum, chip) => sum + chip.width, 0)
                        + Math.max(0, list.length - 1) * chipGap
                      const statusEnd = x + 21 + estimateTextWidth(label, 10.5)
                      const chipBudget = x + LEAF_W - 10 - (statusEnd + 6)
                      while (chipItems.length > 1 && totalWidth(chipItems) > chipBudget) {
                        const index = chipItems.findIndex((chip) => chip.kind === 'ports')
                        if (index < 0) break
                        chipItems.splice(index, 1)
                      }
                      let chipX = x + LEAF_W - 10 - totalWidth(chipItems)
                      const chips = chipItems.map((chip) => {
                        const positioned = { ...chip, x: chipX }
                        chipX += chip.width + chipGap
                        return positioned
                      })

                      return (
                        <g
                          key={d.id}
                          className={`topo-leaf${offline ? ' is-off' : ''}${isSelected ? ' is-sel' : ''}`}
                          role="button"
                          tabIndex={0}
                          aria-pressed={isSelected}
                          aria-label={`${displayName}, ${ip || '—'}, ${typeLabel(d.type)}, ${label}, ${portCount} ${portWord(portCount)}`}
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
                          <title>{`${rawName || ip || '—'} — ${ip || '—'}`}</title>
                          <rect x={x - 2} y={y - 2} width={LEAF_W + 4} height={LEAF_H + 4} rx="16" className="topo-leaf-halo" />
                          <rect x={x} y={y} width={LEAF_W} height={LEAF_H} rx="14" className="topo-leaf-bg" />
                          <rect x={x + 10} y={y + 10} width="28" height="28" rx="9" className="topo-leaf-icon-bg" />
                          <Glyph type={Object.hasOwn(TYPES, d.type) ? d.type : '__other'} x={x + 15.5} y={y + 15.5} size={17} />
                          <text x={x + 46} y={nameTop} className="topo-leaf-name" style={{ fontSize: nameSize }}>
                            {nameFit.lines.map((line, index) => (
                              <tspan key={index} x={x + 46} y={nameTop + index * nameStep}>{line}</tspan>
                            ))}
                          </text>
                          <text x={x + 10} y={y + 63} className="topo-leaf-ip">{secondary}</text>
                          <circle cx={x + 13} cy={y + 80} r="3.6" fill={statusTone(d.status)} />
                          <text x={x + 21} y={y + 84} className="topo-leaf-status">{label}</text>

                          {chips.map((chip) => (
                            <g key={chip.key} className={`topo-chip is-${chip.kind}`} transform={`translate(${chip.x},${y + 74})`}>
                              <title>
                                {chip.kind === 'sens'
                                  ? t('topology.sensitivePorts', { n: sensitiveCount })
                                  : chip.kind === 'ports'
                                    ? t('topology.openPorts', { n: portCount })
                                    : t('topology.newBadge')}
                              </title>
                              <rect width={chip.width} height="15" rx="7.5" />
                              {chip.kind === 'ports' && (
                                <svg x="5" y="3" width="9" height="9" viewBox="0 0 12 12" fill="none"
                                  stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" aria-hidden="true">
                                  <rect x="1.5" y="3" width="9" height="6" rx="1" />
                                  <path d="M4 6h.01M6 6h.01M8 6h.01" />
                                </svg>
                              )}
                              {chip.kind === 'sens' && (
                                <svg x="5" y="3" width="9" height="9" viewBox="0 0 12 12" fill="none"
                                  stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                                  <path d="M6 1.5 11 10.5H1z" />
                                  <path d="M6 5v2.5M6 9h.01" />
                                </svg>
                              )}
                              <text
                                x={chip.kind === 'new' ? chip.width / 2 : 17}
                                y="10.7"
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
                )
              }))}
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
