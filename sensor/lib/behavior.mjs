// CyberVeylix Sensor — moteur de détection de comportement (pur, déterministe, testable sans réseau).
//
// Reçoit un flux d'« observations de connexion » déjà analysées, quelle qu'en soit la source
// (demandes ARP du réseau local, journaux de sessions du pare-feu, port miroir…) :
//   observe({ src, dst, dstPort?, name?, internal?, ts }, now)
//   - src   : adresse IP de l'appareil émetteur (l'« auteur » du comportement)
//   - dst   : adresse IP contactée ; name : domaine contacté (facultatif)
//   - dstPort : port contacté (facultatif) ; internal : dst est-il sur le réseau local (facultatif)
//
// Renvoie une liste d'événements de sécurité au même format que detectors.mjs
//   { type, severity:'c'|'h'|'m'|'l', ip, dst, title, detail }
// afin que push.mjs les enregistre comme alertes. Ne lit aucun contenu, seulement « qui parle à qui ».
//
// Détections (règles claires, pas d'IA) :
//   1. Destination connue malveillante (liste de menaces) -> possible logiciel malveillant / C2.
//   2. Balayage horizontal : un appareil contacte beaucoup d'autres appareils en peu de temps.
//   3. Balayage vertical : un appareil contacte beaucoup de ports d'une même cible.
//   4. Expansion anormale : un appareil parle soudain à bien plus de pairs que sa normale apprise.

const DEFAULTS = {
  windowMs: 60 * 1000, // fenêtre d'observation du balayage
  horizontalThreshold: 15, // destinations distinctes dans la fenêtre -> balayage horizontal
  verticalThreshold: 10, // ports distincts sur UNE cible dans la fenêtre -> balayage vertical
  fanoutFactor: 4, // pairs actuels > fanoutFactor × normale apprise -> expansion anormale
  fanoutMin: 10, // …et au moins ce nombre de pairs, pour éviter le bruit sur les petits réseaux
  baselineWeight: 0.1, // inertie de la normale apprise (moyenne mobile, 0..1)
  cooldownMs: 10 * 60 * 1000, // anti-répétition d'un même événement
  maxSources: 20000, // plafond mémoire
}

export function createBehaviorEngine(config = {}) {
  const cfg = { ...DEFAULTS, ...config }
  const threatList = config.threatList || null
  let alerting = config.alert !== false // false = apprentissage (met à jour la normale sans alerter)

  const sources = new Map() // src -> { events:[{dst,port,name,ts}], peers:Map(dst->ts), baseline:number|null }
  const lastEmit = new Map()

  function emit(now, key, event) {
    const prev = lastEmit.get(key)
    if (prev !== undefined && now - prev < cfg.cooldownMs) return null
    if (lastEmit.size > 5000) for (const [k, t] of lastEmit) if (now - t >= cfg.cooldownMs) lastEmit.delete(k)
    lastEmit.set(key, now)
    return event
  }

  function stateFor(src) {
    let s = sources.get(src)
    if (!s) {
      if (sources.size >= cfg.maxSources) return null
      s = { events: [], baseline: null, windowEnd: null, windowPeak: 0 }
      sources.set(src, s)
    }
    return s
  }

  function observe(flow, now = Date.now()) {
    if (!flow || !flow.src) return []
    const { src, dst = null, dstPort = null, name = null } = flow
    const ts = Number.isFinite(flow.ts) ? flow.ts : now
    const events = []

    // 1) Destination connue malveillante : signal fort, indépendant de la fenêtre.
    if (threatList) {
      const hit = threatList.match({ ip: dst, name })
      if (hit && alerting) {
        const target = name || dst
        const e = emit(now, `threat:${src}:${hit.value}`, {
          type: 'malware_c2', severity: 'c', ip: src, dst: target,
          title: 'Communication avec une adresse malveillante connue',
          detail: `${src} a contacté ${target}${hit.label ? ` (${hit.label})` : ''}, présent dans la liste de menaces. Appareil possiblement infecté.`,
        })
        if (e) events.push(e)
      }
    }

    if (!dst && !dstPort) return events
    const s = stateFor(src)
    if (!s) return events

    // Fenêtre glissante des connexions récentes de cet appareil.
    s.events.push({ dst, port: dstPort, name, ts })
    const cutoff = ts - cfg.windowMs
    if (s.events.length > 4096 || (s.events.length && s.events[0].ts < cutoff)) {
      s.events = s.events.filter((x) => x.ts >= cutoff)
    }

    const dsts = new Set()
    const portsByDst = new Map()
    for (const x of s.events) {
      if (x.dst) {
        dsts.add(x.dst)
        if (x.port != null) {
          const set = portsByDst.get(x.dst) || new Set()
          set.add(x.port)
          portsByDst.set(x.dst, set)
        }
      }
    }

    // Normale apprise = pic de pairs par fenêtre, mise à jour seulement à la FIN d'une fenêtre,
    // pour qu'un balayage en cours (une seule fenêtre) ne gonfle pas lui-même la normale.
    if (s.windowEnd === null) { s.windowEnd = ts + cfg.windowMs; s.windowPeak = 0 }
    else if (ts >= s.windowEnd) {
      s.baseline = s.baseline === null ? s.windowPeak : s.baseline + (s.windowPeak - s.baseline) * cfg.baselineWeight
      s.windowEnd = ts + cfg.windowMs
      s.windowPeak = 0
    }
    s.windowPeak = Math.max(s.windowPeak, dsts.size)

    if (alerting) {
      // 2) Balayage horizontal : beaucoup de cibles distinctes en peu de temps.
      if (dsts.size >= cfg.horizontalThreshold) {
        const e = emit(now, `hscan:${src}`, {
          type: 'lateral_scan', severity: 'h', ip: src, dst,
          title: 'Balayage du réseau par un appareil',
          detail: `${src} a contacté ${dsts.size} appareils en moins de ${Math.round(cfg.windowMs / 1000)} s. Comportement de ver ou de reconnaissance (déplacement latéral).`,
        })
        if (e) events.push(e)
      }
      // 3) Balayage vertical : beaucoup de ports sur une même cible.
      if (dst) {
        const ports = portsByDst.get(dst)
        if (ports && ports.size >= cfg.verticalThreshold) {
          const e = emit(now, `vscan:${src}:${dst}`, {
            type: 'port_scan', severity: 'm', ip: src, dst,
            title: 'Balayage de ports d’un appareil',
            detail: `${src} a sondé ${ports.size} ports de ${dst} en moins de ${Math.round(cfg.windowMs / 1000)} s.`,
          })
          if (e) events.push(e)
        }
      }
      // 4) Expansion anormale : bien plus de pairs que la normale apprise pour cet appareil.
      if (s.baseline !== null && s.baseline >= 1 && dsts.size >= cfg.fanoutMin && dsts.size > s.baseline * cfg.fanoutFactor) {
        const e = emit(now, `fanout:${src}`, {
          type: 'anomaly_fanout', severity: 'm', ip: src, dst,
          title: 'Appareil au comportement inhabituel',
          detail: `${src} parle à ${dsts.size} appareils, contre ${Math.round(s.baseline)} en temps normal. Changement soudain à surveiller.`,
        })
        if (e) events.push(e)
      }
    }

    return events
  }

  const setAlerting = (on) => { alerting = on }
  const snapshot = () => ({ sources: sources.size, alerting })

  return { observe, setAlerting, snapshot }
}
