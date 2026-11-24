// CyberVeylix Sensor — interprétation des contacts avec les leurres (pur, déterministe, testable).
// Aucun appareil légitime n'a de raison de se connecter à un leurre : tout contact est suspect.
//   - contact simple             → 'h'  (honeypot_touch)
//   - ≥ 3 leurres en une minute  → 'c'  (honeypot_scan : reconnaissance, propagation de malware)
//   - tentative d'identification → 'c'  (honeypot_login : attaque de mots de passe, botnet type Mirai)

export const SERVICE_LABELS = {
  telnet: 'Telnet', ftp: 'FTP', ssh: 'SSH', http: 'portail d\'administration web', vnc: 'VNC',
  rdp: 'Bureau à distance (RDP)', mssql: 'SQL Server', mysql: 'MySQL', generic: 'TCP',
}

const DEFAULTS = {
  windowMs: 60 * 1000, // fenêtre de détection d'un balayage
  scanThreshold: 3, // leurres distincts touchés dans la fenêtre
  cooldownMs: 10 * 60 * 1000, // anti-répétition par événement
  maxSources: 5000, // plafond mémoire (sources suivies)
}

// « ::ffff:192.168.1.5 » (socket double pile) → « 192.168.1.5 ».
export function normalizeIp(ip) {
  return String(ip || '').replace(/^::ffff:/i, '')
}

export function createHoneypotMonitor(config = {}) {
  const cfg = { ...DEFAULTS, ...config }
  const ignored = new Set((cfg.ignoreIps || []).map(normalizeIp)) // le capteur lui-même
  const allowed = new Set((cfg.allowIps || []).map(normalizeIp)) // scanners légitimes du client
  const macOf = typeof cfg.macOf === 'function' ? cfg.macOf : () => null
  const sources = new Map() // ip -> Map(port -> dernier instant)
  const lastEmit = new Map()

  function emit(now, key, event) {
    const prev = lastEmit.get(key)
    if (prev !== undefined && now - prev < cfg.cooldownMs) return null
    if (lastEmit.size > 5000) for (const [k, t] of lastEmit) if (now - t >= cfg.cooldownMs) lastEmit.delete(k)
    lastEmit.set(key, now)
    return event
  }
  const recentlyEmitted = (key, now) => {
    const t = lastEmit.get(key)
    return t !== undefined && now - t < cfg.cooldownMs
  }

  // Ports distincts touchés par une source dans la fenêtre (les anciens sont oubliés au passage).
  function touch(ip, port, now) {
    if (!sources.has(ip)) {
      if (sources.size >= cfg.maxSources) {
        for (const [k, ports] of sources) {
          for (const [p, t] of ports) if (now - t > cfg.windowMs) ports.delete(p)
          if (!ports.size) sources.delete(k)
        }
        if (sources.size >= cfg.maxSources) return 1 // mémoire pleine : on continue d'alerter sans suivre
      }
      sources.set(ip, new Map())
    }
    const ports = sources.get(ip)
    ports.set(port, now)
    for (const [p, t] of ports) if (now - t > cfg.windowMs) ports.delete(p)
    return ports.size
  }

  // activity : { srcIp, port, service, kind: 'touch' | 'login', username?, hasPassword? }
  function onActivity(activity, now) {
    const ip = normalizeIp(activity.srcIp)
    if (!ip || ignored.has(ip) || allowed.has(ip)) return []
    const port = Number(activity.port)
    const label = SERVICE_LABELS[activity.service] || SERVICE_LABELS.generic
    const mac = macOf(ip)
    const who = mac ? `${ip} (${mac})` : ip
    const events = []

    if (activity.kind === 'login') {
      const user = activity.username ? `l'identifiant « ${activity.username} »` : 'un identifiant vide'
      const pwd = activity.hasPassword ? ' et un mot de passe (non conservé)' : ''
      const e = emit(now, `hp-login:${ip}:${port}`, {
        type: 'honeypot_login', severity: 'c', ip, mac, port, service: activity.service,
        username: activity.username || '',
        title: 'Tentative d\'intrusion sur un leurre',
        detail: `${who} a tenté de se connecter au leurre ${label} (port ${port}) avec ${user}${pwd}. `
          + 'Aucun usage légitime : appareil compromis, logiciel malveillant ou attaquant sur le réseau.',
      })
      if (e) events.push(e)
      return events
    }

    const distinct = touch(ip, port, now)
    if (distinct >= cfg.scanThreshold) {
      const list = [...(sources.get(ip)?.keys() || [])].sort((a, b) => a - b).join(', ')
      const e = emit(now, `hp-scan:${ip}`, {
        type: 'honeypot_scan', severity: 'c', ip, mac, port, service: activity.service,
        title: 'Balayage de ports interne détecté',
        detail: `${who} a sondé ${distinct} services leurres en moins d'une minute (ports ${list}). `
          + 'Reconnaissance typique d\'un attaquant ou d\'un logiciel malveillant qui se propage.',
      })
      if (e) { events.push(e); return events }
    }
    // Pendant un balayage déjà signalé, chaque port touché n'est pas réannoncé séparément.
    if (recentlyEmitted(`hp-scan:${ip}`, now)) return events
    const e = emit(now, `hp-touch:${ip}:${port}`, {
      type: 'honeypot_touch', severity: 'h', ip, mac, port, service: activity.service,
      title: 'Connexion à un service leurre',
      detail: `${who} s'est connecté au leurre ${label} (port ${port}). Aucun appareil légitime ne devrait l'utiliser.`,
    })
    if (e) events.push(e)
    return events
  }

  return { onActivity }
}
