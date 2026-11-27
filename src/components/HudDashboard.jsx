import { useEffect, useState } from 'react'
import { hourlyCounts, sensorState } from '../lib/findings.js'
import { securityLevel, gauges, levelOf, headlineAlert, openAlerts, pendingFixes, portMatrix, lastScanAt, inventory, deviceAtRisk, radarPoint } from '../lib/hud.js'
import { useI18n } from '../i18n/context.js'
import './HudDashboard.css'

// Tableau de bord « HUD » : chaque chiffre vient des tables enregistrées (appareils, alertes,
// vulnérabilités, menaces, services, réseaux, capteurs, adresses bloquées). Sans donnée : « — ».

const LEVEL_COLOR = { good: '#3BE58A', warn: '#F2A23A', bad: '#FF4D5E', none: '#2A5560' }
const SEV_COLOR = { c: '#FF4D5E', h: '#F2A23A', m: '#E8C547', l: '#8FB4BB' }
// Heure courante rafraîchie chaque minute (« il y a 3 min » reste juste).
function useNow(ms = 60000) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), ms)
    return () => clearInterval(id)
  }, [ms])
  return now
}

const dash = (v) => (v === null || v === undefined ? '—' : v)

function Ph({ title, tag, end }) {
  return (
    <div className={`hud-ph${end ? ' is-end' : ''}`}>
      <h3>{title}</h3>
      <span className="hud-hatch" aria-hidden="true" />
      {tag && <b>[ {tag} ]</b>}
    </div>
  )
}

const arc = (cx, cy, r, from, to) => {
  const p = (a) => [cx + r * Math.cos((a * Math.PI) / 180), cy + r * Math.sin((a * Math.PI) / 180)]
  const [x0, y0] = p(from)
  const [x1, y1] = p(to)
  return `M${x0} ${y0}A${r} ${r} 0 ${to - from > 180 ? 1 : 0} 1 ${x1} ${y1}`
}

function Ring({ pct, size = 104, label, sub }) {
  const c = size / 2
  const r = c - 12
  const color = LEVEL_COLOR[levelOf(pct)]
  return (
    <svg className="hud-ring" viewBox={`0 0 ${size} ${size}`} width={size} height={size} role="img" aria-label={`${label} : ${pct === null ? '—' : `${pct} %`}`}>
      <circle cx={c} cy={c} r={c - 3} fill="none" stroke="#2A5560" />
      <circle cx={c} cy={c} r={r} fill="rgba(10,30,36,.6)" stroke="#132B32" strokeWidth="7" />
      {pct > 0 && <path d={arc(c, c, r, -90, -90 + Math.min(359.9, pct * 3.6))} stroke={color} strokeWidth="4" fill="none" style={{ filter: `drop-shadow(0 0 4px ${color})` }} />}
      <path d={arc(c, c, c - 3, -120, -60)} stroke="#D6E4E7" strokeWidth="2" fill="none" />
      <text x={c} y={c + 2} textAnchor="middle" className="hud-ring-v">{pct === null ? '—' : `${pct}%`}</text>
      <text x={c} y={c + 16} textAnchor="middle" className="hud-ring-l">{label}</text>
      {sub && <text x={c} y={c + 26} textAnchor="middle" className="hud-ring-s">{sub}</text>}
    </svg>
  )
}

// Activité : alertes (au-dessus) et menaces (en dessous) par heure sur 24 h.
function Traffic({ alerts, threats }) {
  const { t, locale } = useI18n()
  const up = hourlyCounts(alerts)
  const down = hourlyCounts(threats)
  const max = Math.max(1, ...up.map((b) => b.n), ...down.map((b) => b.n))
  const total = up.reduce((n, b) => n + b.n, 0)
  const W = 320
  const step = W / up.length
  const hour = (ms) => new Date(ms).toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit' })
  return (
    <section className="hud-panel">
      <Ph title={t('hud.activity')} tag="24 H" />
      <div className="hud-big"><span>{total}</span><small>{t('hud.alerts24')}</small></div>
      <svg viewBox={`0 0 ${W} 170`} className="hud-traffic" role="img" aria-label={t('hud.activityAria', { n: total })}>
        <line x1="0" y1="90" x2={W} y2="90" stroke="#2A5560" />
        {up.map((b, i) => {
          const h = (b.n / max) * 80
          const d = (down[i].n / max) * 70
          return (
            <g key={b.at}>
              {h > 0 && <rect x={i * step + 2} y={90 - h} width={step - 4} height={h} fill="#33E6F5" opacity=".85"><title>{`${hour(b.at)} · ${b.n}`}</title></rect>}
              {d > 0 && <rect x={i * step + 2} y={90} width={step - 4} height={d} fill="#8FB4BB" opacity=".5"><title>{`${hour(b.at)} · ${down[i].n}`}</title></rect>}
              {h === 0 && <rect x={i * step + 2} y={88} width={step - 4} height={2} fill="#2A5560" />}
            </g>
          )
        })}
        {up.map((b, i) => (i % 6 === 0 ? <text key={`l${b.at}`} x={i * step + 2} y="168" className="hud-axis">{hour(b.at)}</text> : null))}
      </svg>
      <div className="hud-legend"><span><i style={{ background: '#33E6F5' }} />{t('hud.legendAlerts')}</span><span><i style={{ background: '#8FB4BB' }} />{t('hud.legendThreats')}</span></div>
    </section>
  )
}

function SensorPanel({ devices, vulns, alerts, sensors, sensorsMissing }) {
  const { t, locale } = useI18n()
  const online = devices.filter((d) => d.status === 'on').length
  const running = sensors.filter((s) => sensorState(s).state === 'running')
  const last = lastScanAt(sensors, [])
  const beat = sensors.map((s) => s.last_heartbeat).filter(Boolean).sort().pop()
  const when = (v) => (v ? new Date(v).toLocaleString(locale) : '—')
  return (
    <section className="hud-panel">
      <Ph title={t('hud.sensor')} tag="SCAN.LAN" />
      <div className="hud-sensor">
        <div>
          <div className="hud-k">{t('hud.devicesSeen')}</div>
          <div className="hud-huge">{devices.length}</div>
          <div className="hud-mono hud-cyan">{t('hud.onlineN', { n: online })}<br />{t('hud.offlineN', { n: devices.length - online })}</div>
        </div>
        <svg viewBox="-110 -110 220 220" className="hud-radar" role="img" aria-label={t('hud.radarAria', { n: devices.length })}>
          <circle r="104" fill="none" stroke="#33E6F5" strokeOpacity=".8" />
          <circle r="70" fill="none" stroke="#2A5560" /><circle r="36" fill="none" stroke="#2A5560" />
          <path d="M-104 0H104M0 -104V104" stroke="#2A5560" />
          {Array.from({ length: 72 }, (_, i) => {
            const a = (i * 5 * Math.PI) / 180
            const r2 = i % 6 ? 99 : 94
            return <line key={i} x1={100 * Math.cos(a)} y1={100 * Math.sin(a)} x2={r2 * Math.cos(a)} y2={r2 * Math.sin(a)} stroke="#33E6F5" strokeOpacity={i % 6 ? 0.35 : 0.8} />
          })}
          <g className="hud-sweep"><path d="M0 0 L80 0 A80 80 0 0 1 56.6 56.6 Z" fill="url(#hudSweep)" /></g>
          <defs><linearGradient id="hudSweep" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stopColor="#33E6F5" stopOpacity=".05" /><stop offset="1" stopColor="#7BF5E0" stopOpacity=".7" /></linearGradient></defs>
          <rect x="-8" y="-8" width="16" height="16" fill="#0F242B" stroke="#D6E4E7" transform="rotate(45)" />
          {devices.map((d) => {
            const p = radarPoint(d)
            const risk = deviceAtRisk(d, vulns, alerts)
            const color = risk ? '#FF4D5E' : d.status === 'on' ? '#33E6F5' : d.status === 'off' ? '#F2A23A' : '#8FB4BB'
            return <circle key={d.id} cx={p.x * 100} cy={p.y * 100} r="3.4" fill={color}><title>{`${d.name}${d.ip ? ` · ${d.ip}` : ''}`}</title></circle>
          })}
        </svg>
      </div>
      <div className="hud-sensor-foot hud-mono">
        {sensorsMissing ? <span>{t('hud.sensorMissing')}</span> : (
          <>
            <span className={running.length ? 'hud-ok' : 'hud-warn'}>■ {sensors.length ? t('hud.sensorsRunning', { n: running.length, total: sensors.length }) : t('hud.noSensor')}</span>
            <span>{t('hud.lastSignal')} : {when(beat)}</span>
            <span>{t('hud.lastScan')} : {when(last)}</span>
          </>
        )}
      </div>
    </section>
  )
}

function Emblem({ level }) {
  const { t } = useI18n()
  const segs = 36
  const on = level.pct === null ? 0 : Math.round((level.pct / 100) * segs)
  const color = LEVEL_COLOR[levelOf(level.pct)]
  return (
    <div className="hud-emblem">
      <svg viewBox="0 0 720 330" role="img" aria-label={`${t('hud.securityLevel')} : ${level.pct === null ? '—' : `${level.pct} %`}`}>
        <defs>
          <radialGradient id="hudGlow"><stop offset="0" stopColor="#33E6F5" stopOpacity=".45" /><stop offset=".55" stopColor="#33E6F5" stopOpacity=".08" /><stop offset="1" stopColor="#33E6F5" stopOpacity="0" /></radialGradient>
          <radialGradient id="hudIris" cx=".5" cy=".5" r=".5"><stop offset=".5" stopColor="#0B3A44" /><stop offset=".68" stopColor="#25D8EA" /><stop offset=".78" stopColor="#D9FDFF" /><stop offset=".88" stopColor="#25D8EA" /><stop offset="1" stopColor="#0B3A44" /></radialGradient>
        </defs>
        {/* cadre en circuit */}
        {[-1, 1].map((s) => {
          const x = (v) => 360 + s * v
          return (
            <g key={s} fill="none">
              <path d={`M${x(190)} 150 V40 L${x(172)} 26 H${x(140)}`} stroke="#33E6F5" strokeWidth="2" />
              <rect x={s > 0 ? x(145) : x(195)} y="18" width="50" height="8" fill="#2D5C66" />
              <path d={`M${x(190)} 120 L${x(225)} 150 H${x(330)}`} stroke="#33E6F5" strokeWidth="1.4" opacity=".8" />
              <path d={`M${x(110)} 190 L${x(165)} 190 L${x(210)} 236 V252 L${x(165)} 208 H${x(110)} Z`} fill="#13303A" stroke="#2D5C66" />
              <path d={`M${x(170)} 188 L${x(222)} 236 V262 L${x(204)} 280`} stroke="#33E6F5" strokeWidth="2.2" />
            </g>
          )
        })}
        <circle cx="360" cy="105" r="150" fill="url(#hudGlow)" />
        <path d="M240 105 Q360 10 480 105 Q360 200 240 105 Z" fill="#06222A" stroke="#33E6F5" strokeWidth="3" />
        <path d="M226 105 Q360 -6 494 105 Q360 216 226 105 Z" fill="none" stroke="#33E6F5" strokeOpacity=".45" />
        <g className="hud-iris">
          <circle cx="360" cy="105" r="52" fill="url(#hudIris)" />
          {Array.from({ length: 40 }, (_, i) => {
            const a = (i * 9 * Math.PI) / 180
            return <line key={i} x1={360 + 56 * Math.cos(a)} y1={105 + 56 * Math.sin(a)} x2={360 + 61 * Math.cos(a)} y2={105 + 61 * Math.sin(a)} stroke="#33E6F5" strokeOpacity=".7" />
          })}
        </g>
        <circle cx="360" cy="105" r="25" fill="#020A0D" stroke="#A8F4FF" strokeWidth="2" />
        <circle cx="351" cy="96" r="6" fill="#fff" />
        <text x="360" y="232" textAnchor="middle" className="hud-brand">CyberVeylix</text>
        <circle cx="360" cy="254" r="4" fill="#E9F7F9" />
      </svg>
      <div className="hud-level">
        <div className="hud-level-v" style={{ color: level.pct === null ? undefined : '#E9F7F9' }}>{level.pct === null ? '—' : `${level.pct}%`}</div>
        <div className="hud-level-row">
          <span className="hud-k">{t('hud.securityLevel')}</span>
          <span className="hud-mono hud-dim">{level.total ? `${level.safe}/${level.total}` : '—'}</span>
        </div>
        <div className="hud-segs" aria-hidden="true">{Array.from({ length: segs }, (_, i) => <i key={i} style={i < on ? { background: color, boxShadow: `0 0 6px ${color}` } : undefined} />)}</div>
        <div className="hud-mono hud-dim hud-rule">{t('hud.securityRule')}</div>
      </div>
    </div>
  )
}

function Notification({ alert, onView, onAck }) {
  const { t, locale } = useI18n()
  return (
    <div className="hud-notif">
      <span className="hud-notif-tag">{t('hud.notification')}</span>
      {alert ? (
        <>
          <div className="hud-notif-title"><span style={{ color: SEV_COLOR[alert.severity] }}>{t(`sev.${alert.severity}`)}</span> · {alert.title}</div>
          <div className="hud-mono hud-dim">
            {new Date(alert.created_at).toLocaleString(locale)}
            {alert.source_ip && <> · {t('hud.source')} <bdi dir="ltr">{alert.source_ip}</bdi></>}
            {alert.detail && <> · {alert.detail}</>}
          </div>
          <div className="hud-notif-actions">
            <button type="button" onClick={onView}>{t('hud.view')}</button>
            {onAck && <button type="button" className="hud-amber" onClick={() => onAck(alert)}>{t('hud.ack')}</button>}
          </div>
        </>
      ) : <div className="hud-mono hud-dim">{t('hud.noOpenAlert')}</div>}
    </div>
  )
}

function Bottom({ devices, vulns, alerts, services, networks, sensors, onOpen, now }) {
  const { t, locale } = useI18n()
  const fixes = pendingFixes(vulns)
  const scan = lastScanAt(sensors, devices)
  const online = devices.filter((d) => d.status === 'on').length
  const ports = portMatrix(services)
  const rows = inventory(devices, vulns, alerts)
  const seen = (v) => {
    if (!v) return t('hud.never')
    const min = Math.round((now - new Date(v).getTime()) / 60000)
    return min < 60 ? t('hud.minAgo', { n: Math.max(0, min) }) : min < 1440 ? t('hud.hAgo', { n: Math.round(min / 60) }) : new Date(v).toLocaleDateString(locale)
  }
  const pctOn = devices.length ? (online / devices.length) * 100 : 0
  return (
    <div className="hud-bottom">
      <div className="hud-stats">
        <div>
          <div className="hud-title">{t('hud.lastScan')}</div>
          <div className="hud-mono hud-cyan">{scan ? new Date(scan).toLocaleString(locale) : '—'}</div>
          <div className="hud-mono hud-dim hud-lines">{t('hud.devices')} {devices.length}<br />{t('hud.services')} {services.length}<br />{t('hud.networks')} {networks.length}</div>
        </div>
        <div>
          <div className="hud-title">{t('hud.fixes')}</div>
          <div className="hud-mono hud-amberText">{t('hud.pending', { n: fixes.total })}</div>
          <div className="hud-mono hud-dim hud-lines">{['c', 'h', 'm', 'l'].map((k) => <span key={k}><i style={{ background: SEV_COLOR[k] }} />{t(`sev.${k}`)} {fixes[k]}<br /></span>)}</div>
        </div>
        <svg viewBox="0 0 150 130" className="hud-donut" role="img" aria-label={t('hud.availabilityAria', { n: online, total: devices.length })}>
          <circle cx="75" cy="58" r="42" fill="none" stroke="#2A5560" strokeWidth="11" strokeDasharray="2 1.4" />
          {pctOn > 0 && <path d={arc(75, 58, 42, -90, -90 + Math.min(359.9, pctOn * 3.6))} stroke="#33E6F5" strokeWidth="11" fill="none" />}
          <text x="75" y="62" textAnchor="middle" className="hud-ring-v">{devices.length ? online : '—'}</text>
          <text x="75" y="75" textAnchor="middle" className="hud-ring-s">/ {dash(devices.length || null)}</text>
          <text x="75" y="122" textAnchor="middle" className="hud-ring-l">{t('hud.availability')}</text>
        </svg>
      </div>
      <div className="hud-inv">
        <div className="hud-inv-h"><span className="hud-title">{t('hud.inventory')}</span><span className="hud-count">{devices.length}</span><span className="hud-hatch" aria-hidden="true" /><button type="button" onClick={() => onOpen('devices')}>{t('hud.seeAll')}</button></div>
        {rows.length ? (
          <table className="hud-table">
            <thead><tr><th aria-label={t('hud.state')} /><th>{t('hud.name')}</th><th>{t('hud.ip')}</th><th>{t('hud.seen')}</th><th>{t('hud.state')}</th></tr></thead>
            <tbody>{rows.map((d) => {
              const state = d.atRisk ? 'risk' : d.status === 'off' ? 'off' : d.status === 'on' ? 'ok' : 'un'
              return (
                <tr key={d.id} className={`is-${state}`}>
                  <td><i /></td><td><bdi>{d.name}</bdi></td><td dir="ltr">{d.ip || '—'}</td><td>{seen(d.last_seen)}</td><td>{t(`hud.state_${state}`)}</td>
                </tr>
              )
            })}</tbody>
          </table>
        ) : <p className="hud-mono hud-dim">{t('hud.noDevice')}</p>}
      </div>
      <div className="hud-ports">
        <div className="hud-k">{t('hud.ports')}</div>
        {ports.length ? <div className="hud-port-grid">{ports.map((p) => <span key={p.port} className={p.risky ? 'is-risky' : ''} title={t('hud.portTitle', { port: p.port, n: p.devices })}>{p.port}<small>×{p.devices}</small></span>)}</div>
          : <p className="hud-mono hud-dim">{t('hud.noPorts')}</p>}
      </div>
      <div className="hud-nets">
        {networks.slice(0, 3).map((n) => (
          <div key={n.id}><b><bdi>{n.name}</bdi></b><span dir="ltr">{n.cidr || n.gateway_ip || '—'}</span><span>{t('hud.hosts', { n: devices.filter((d) => d.network_id === n.id).length })}</span></div>
        ))}
        {!networks.length && <div className="hud-dim">{t('hud.noNetwork')}</div>}
      </div>
    </div>
  )
}

function AlertsPanel({ alerts, blocked, sensors, onOpen, onAddAlert, onAddThreat }) {
  const { t, locale } = useI18n()
  const list = openAlerts(alerts)
  const open = alerts.filter((a) => !a.status || a.status === 'open')
  const crit = open.filter((a) => a.severity === 'c' || a.severity === 'h').length
  const running = sensors.some((s) => sensorState(s).state === 'running')
  return (
    <section className="hud-panel">
      <div className="hud-alert-head">
        <svg width="36" height="40" viewBox="0 0 34 38" aria-hidden="true"><path d="M17 1l15 8.5v19L17 37 2 28.5v-19z" fill={open.length ? '#5A1E26' : '#2B5560'} /><path d="M17 10v12M17 26v2" stroke="#E9F3F5" strokeWidth="3" strokeLinecap="round" /></svg>
        <div>
          <div className="hud-alert-title">{t('hud.openAlerts', { n: open.length })}<span className="hud-stripes" aria-hidden="true" /></div>
          <div className="hud-mono hud-dim">{t('hud.severeAlerts', { n: crit })} ›››</div>
        </div>
      </div>
      {list.length ? (
        <ul className="hud-alerts">
          {list.map((a) => (
            <li key={a.id}>
              <i style={{ background: SEV_COLOR[a.severity] }} />
              <span dir="ltr">{a.source_ip || '—'}</span>
              <span className="hud-dim">{new Date(a.created_at).toLocaleString(locale, { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })}</span>
              <bdi style={{ color: SEV_COLOR[a.severity] }}>{a.kind || a.title}</bdi>
            </li>
          ))}
        </ul>
      ) : <p className="hud-mono hud-dim">{t('hud.noOpenAlert')}</p>}
      <div className="hud-states">
        <div><svg width="34" height="34" aria-hidden="true"><circle cx="17" cy="17" r="15" fill="none" stroke="#D6E4E7" /><circle cx="17" cy="17" r="8" fill="none" stroke="#D6E4E7" /><circle cx="17" cy="17" r="3" fill={running ? '#3BE58A' : '#F2A23A'} /></svg>
          <div><div className="hud-k">{t('hud.sensor')}</div><b>{sensors.length ? (running ? t('hud.active') : t('hud.stopped')) : '—'}</b></div></div>
        <div><svg width="34" height="34" aria-hidden="true"><circle cx="17" cy="17" r="15" fill="none" stroke="#D6E4E7" /><circle cx="17" cy="17" r="8" fill="none" stroke="#D6E4E7" /><circle cx="17" cy="17" r="3" fill="#D6E4E7" /></svg>
          <div><div className="hud-k">{t('hud.blocked')}</div><b>{blocked.length}</b></div></div>
      </div>
      <div className="hud-actions">
        <button type="button" onClick={() => onOpen('threats')}>{t('hud.seeAll')}</button>
        <button type="button" className="x" onClick={onAddAlert}>+ {t('hud.addAlert')}</button>
        <button type="button" className="x" onClick={onAddThreat}>+ {t('hud.addThreat')}</button>
      </div>
    </section>
  )
}

function GaugesPanel({ devices, vulns, alerts, sensors, level }) {
  const { t } = useI18n()
  const g = gauges({ devices, vulns, alerts, sensors })
  return (
    <section className="hud-panel">
      <Ph title={t('hud.network')} tag={t('hud.percent')} end />
      <div className="hud-gauges">
        <div className="hud-rings">{g.map((x) => <Ring key={x.key} pct={x.pct} label={t(`hud.g_${x.key}`)} sub={x.total ? `${x.n}/${x.total}` : ''} />)}</div>
        <div className="hud-score">
          <div className="hud-k">{t('hud.securityLevel')}</div>
          <div className="hud-score-v">{level.pct === null ? '—' : level.pct}</div>
          <div className="hud-mono hud-dim">% · {level.total ? `${level.safe}/${level.total}` : '—'}</div>
        </div>
      </div>
      <div className="hud-mono hud-dim hud-src">{t('hud.sourceNote')}</div>
    </section>
  )
}

export default function HudDashboard({ devices, vulns, alerts, threats, services, networks, sensors, blocked, sensorsMissing, onOpen, onAckAlert, onAddAlert, onAddThreat }) {
  const now = useNow()
  const level = securityLevel(devices, vulns, alerts)
  const head = headlineAlert(alerts)
  return (
    <div className="hud">
      <div className="hud-col">
        <Traffic alerts={alerts} threats={threats} />
        <SensorPanel devices={devices} vulns={vulns} alerts={alerts} sensors={sensors} sensorsMissing={sensorsMissing} />
      </div>
      <div className="hud-col hud-center">
        <Notification alert={head} onView={() => onOpen('threats')} onAck={onAckAlert} />
        <Emblem level={level} />
        <Bottom devices={devices} vulns={vulns} alerts={alerts} services={services} networks={networks} sensors={sensors} onOpen={onOpen} now={now} />
      </div>
      <div className="hud-col">
        <AlertsPanel alerts={alerts} blocked={blocked} sensors={sensors} onOpen={onOpen} onAddAlert={onAddAlert} onAddThreat={onAddThreat} />
        <GaugesPanel devices={devices} vulns={vulns} alerts={alerts} sensors={sensors} level={level} />
      </div>
    </div>
  )
}
