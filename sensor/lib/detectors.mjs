// CyberVeylix Sensor — moteur de détection (pur, déterministe, testable sans réseau).
// Reçoit des messages ARP/DHCP déjà analysés et un horodatage `now` (ms),
// tient à jour l'état du réseau et renvoie une liste d'événements de sécurité.
//
// Gravités alignées sur l'application : 'c' critique, 'h' haute, 'm' moyenne, 'l' basse.
import { isBroadcastOrMulticast } from './format.mjs'
import { ARP_REPLY } from './parse-arp.mjs'

const DEFAULTS = {
  // Fenêtre anti-répétition : un même événement n'est pas réémis avant ce délai.
  cooldownMs: 10 * 60 * 1000,
  // Nombre d'IP distinctes revendiquées par une même MAC, DANS la fenêtre ci-dessous,
  // au-delà duquel on suspecte une usurpation. Une usurpation revendique vite beaucoup d'IP ;
  // un téléphone dont le bail DHCP change le fait sur des jours : il n'est donc pas compté.
  spoofIpThreshold: 5,
  spoofWindowMs: 5 * 60 * 1000,
  // Au-delà de ce nombre de nouveaux appareils par minute : inondation (MAC flooding), une seule alerte.
  floodPerMinute: 20,
  // Plafond mémoire : au-delà, les nouvelles MAC ne sont plus mémorisées (protection contre l'inondation).
  maxDevices: 10000,
}

export function createDetectors(config = {}) {
  const cfg = { ...DEFAULTS, ...config }
  let alert = config.alert !== false // false = mode apprentissage (référence), aucun événement émis

  const ipToMac = new Map() // ip -> mac observée la plus récente
  const macToIps = new Map() // mac -> Map(ip -> dernier instant vu) : IP revendiquées récemment par une MAC
  const knownMacs = new Set()
  // Référence sauvegardée (baseline.json) : évite de tout réapprendre après un redémarrage.
  // Instant 0 : ces revendications sont anciennes et ne comptent pas comme balayage récent.
  for (const b of config.bindings || []) {
    if (b && b.ip && b.mac) {
      const mac = String(b.mac).toLowerCase()
      ipToMac.set(b.ip, mac)
      if (!macToIps.has(mac)) macToIps.set(mac, new Map())
      macToIps.get(mac).set(b.ip, 0)
      knownMacs.add(mac)
    }
  }
  const dhcpServers = new Set(config.trustedDhcpServers || []) // identités de serveurs DHCP légitimes
  const lastEmit = new Map() // clé d'événement -> dernier instant d'émission (ms)

  let gatewayMac = config.gatewayMac ? config.gatewayMac.toLowerCase() : null
  const gatewayIp = config.gatewayIp || null

  const recentNew = [] // instants des derniers « nouvel appareil » (fenêtre glissante d'une minute)

  function bind(mac, ip, now) {
    if (!knownMacs.has(mac) && knownMacs.size >= cfg.maxDevices) return false // plafond mémoire atteint
    // L'IP quitte l'ancienne MAC quand une autre la reprend.
    const previous = ipToMac.get(ip)
    if (previous && previous !== mac) macToIps.get(previous)?.delete(ip)
    ipToMac.set(ip, mac)
    if (!macToIps.has(mac)) macToIps.set(mac, new Map())
    macToIps.get(mac).set(ip, now)
    knownMacs.add(mac)
    return true
  }

  // IP revendiquées par cette MAC dans la fenêtre récente (les anciennes sont oubliées au passage).
  function recentIpCount(mac, now) {
    const ips = macToIps.get(mac)
    if (!ips) return 0
    let count = 0
    for (const [ip, t] of ips) {
      if (now - t <= cfg.spoofWindowMs) count++
      else if (ipToMac.get(ip) !== mac) ips.delete(ip) // ni récente ni actuelle : on libère la mémoire
    }
    return count
  }

  // Respecte l'anti-répétition : renvoie l'événement ou null s'il a déjà été signalé récemment.
  function emit(now, key, event) {
    const prev = lastEmit.get(key)
    if (prev !== undefined && now - prev < cfg.cooldownMs) return null
    // Mémoire bornée : on oublie les clés dont l'anti-répétition a expiré (inondation lente).
    if (lastEmit.size > 5000) {
      for (const [k, t] of lastEmit) if (now - t >= cfg.cooldownMs) lastEmit.delete(k)
    }
    lastEmit.set(key, now)
    return event
  }

  function onArp(arp, now) {
    if (!arp) return []
    const mac = arp.senderMac.toLowerCase()
    const ip = arp.senderIp
    const events = []

    // 0.0.0.0 (sonde ARP) ou adresse non unicast : on ignore comme source d'appareil.
    if (ip === '0.0.0.0' || isBroadcastOrMulticast(mac)) return events

    // Verrouillage de la passerelle : la première MAC vue pour l'IP passerelle devient la référence,
    // quel que soit le mode. D'où l'intérêt de la phase d'apprentissage (ou de --gateway-mac).
    if (gatewayIp && ip === gatewayIp && !gatewayMac) gatewayMac = mac

    // 1) Usurpation de la passerelle = signal fort d'attaque « homme du milieu ».
    // Cette trame n'est JAMAIS apprise : sinon la MAC de l'attaquant deviendrait la « référence »
    // de la passerelle (fausse alerte sur la vraie passerelle et attaquant considéré comme connu).
    if (gatewayIp && ip === gatewayIp && gatewayMac && mac !== gatewayMac) {
      if (alert) {
        const e = emit(now, `gw-spoof:${ip}`, {
          type: 'gateway_spoof', severity: 'c', ip, mac,
          title: 'Usurpation de la passerelle',
          detail: `La passerelle ${ip} est maintenant annoncée par ${mac} (attendu ${gatewayMac}). Possible attaque homme du milieu.`,
        })
        if (e) events.push(e)
      }
      return events
    }

    if (alert) {
      if (ipToMac.has(ip) && ipToMac.get(ip) !== mac) {
        // 2) Une IP connue change de MAC : conflit d'adresse ou usurpation ciblée.
        const e = emit(now, `mac-change:${ip}`, {
          type: 'mac_changed', severity: 'h', ip, mac,
          title: 'Changement de MAC sur une adresse connue',
          detail: `${ip} passe de ${ipToMac.get(ip)} à ${mac}. Conflit d'adresse IP ou usurpation ARP.`,
        })
        if (e) events.push(e)
      } else if (!knownMacs.has(mac)) {
        // 3) Nouvel appareil (MAC jamais vue), sauf en cas d'inondation : une seule alerte groupée.
        while (recentNew.length && now - recentNew[0] > 60 * 1000) recentNew.shift()
        recentNew.push(now)
        if (recentNew.length > cfg.floodPerMinute) {
          const e = emit(now, 'mac-flood', {
            type: 'mac_flood', severity: 'h', ip, mac,
            title: 'Inondation d\'adresses MAC',
            detail: `Plus de ${cfg.floodPerMinute} nouveaux appareils en une minute. Attaque par inondation (MAC flooding) ou outil de balayage sur le réseau.`,
          })
          if (e) events.push(e)
        } else {
          const e = emit(now, `new:${mac}`, {
            type: 'new_device', severity: 'm', ip, mac,
            title: 'Nouvel appareil détecté',
            detail: `${mac} (${ip}) est apparu sur le réseau.`,
          })
          if (e) events.push(e)
        }
      }
    }

    if (!bind(mac, ip, now)) return events

    // 4) Une même MAC revendiquant vite de nombreuses IP (via des réponses ARP) : usurpation.
    if (alert && arp.op === ARP_REPLY) {
      const count = recentIpCount(mac, now)
      if (count >= cfg.spoofIpThreshold) {
        const e = emit(now, `many-ip:${mac}`, {
          type: 'arp_spoof_sweep', severity: 'h', ip, mac,
          title: 'Usurpation ARP probable',
          detail: `${mac} revendique ${count} adresses IP. Comportement typique d'un empoisonnement ARP.`,
        })
        if (e) events.push(e)
      }
    }

    return events
  }

  function onDhcp(dhcp, now) {
    if (!dhcp) return []
    const id = dhcp.serverId
    // En apprentissage, le(s) premier(s) serveur(s) vus deviennent la référence.
    if (!alert) { dhcpServers.add(id); return [] }
    if (dhcpServers.has(id)) return []
    // Serveur DHCP inconnu qui distribue des adresses = serveur pirate probable.
    const e = emit(now, `rogue-dhcp:${id}`, {
      type: 'rogue_dhcp', severity: 'c', ip: id, mac: dhcp.serverMac,
      title: 'Serveur DHCP non autorisé',
      detail: `${id} (${dhcp.serverMac}) distribue des adresses (propose ${dhcp.offeredIp}). Serveur DHCP pirate probable.`,
    })
    return e ? [e] : []
  }

  // État courant pour diagnostic / passage du mode apprentissage au mode alerte.
  function snapshot() {
    return {
      deviceCount: knownMacs.size,
      gatewayMac,
      trustedDhcpServers: [...dhcpServers],
      bindings: [...ipToMac.entries()].map(([ip, mac]) => ({ ip, mac })),
    }
  }

  // Fin de la période d'apprentissage : on passe en mode alerte sans perdre l'état appris.
  function setAlerting(value) { alert = Boolean(value) }

  // MAC connue pour une IP (enrichit les alertes des leurres : quel appareil exactement).
  const macOf = (ip) => ipToMac.get(ip) || null

  return { onArp, onDhcp, snapshot, setAlerting, macOf }
}
