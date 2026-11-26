// CyberVeylix Sensor — détection réseau-large sur les switchs Cisco (et compatibles) lus en SNMP,
// pure et testable sans réseau.
//
// Contrairement à behavior.mjs (qui a besoin de vraies sessions réseau, « qui parle à qui »), ce
// module ne reçoit QUE ce que les tables MAC standard des switchs (BRIDGE-MIB / Q-BRIDGE-MIB)
// fournissent réellement : quel port de quel switch a appris quelle adresse MAC. Il n'invente
// AUCUNE donnée de trafic : un switch ne sait pas qui parle à qui, seulement où chaque adresse
// se trouve. C'est topology.mjs (déjà en place) qui calcule, pour un passage de lecture donné,
// `hostLocations` : pour chaque adresse MAC vue comme appareil final (les liaisons entre switchs
// sont déjà écartées par topology.mjs), la liste des switchs où elle a été apprise.
//
// Une seule règle, à forte confiance : une adresse MAC apprise par PLUSIEURS switchs DANS LE MÊME
// passage n'est jamais normale pour un appareil final (un appareil n'est physiquement branché qu'à
// un seul endroit à la fois). Gravité critique si l'adresse dupliquée est celle de la passerelle
// (quelqu'un se fait passer pour le routeur ailleurs sur le réseau, signal de la même famille que
// l'usurpation ARP de la passerelle détectée localement, mais vue sur tout le parc Cisco) ; haute
// dans les autres cas (conflit matériel, clonage de MAC, ou usurpation d'un appareil quelconque).
//
// Limite assumée : peut aussi se produire lors d'une reconvergence réseau transitoire (bascule de
// lien, redémarrage d'un switch) ou d'un transfert d'adresse MAC virtuelle (cluster, VRRP/HSRP non
// reconnu comme tel) : à vérifier avant de considérer l'alerte comme certaine, d'où un cycle de
// répétition long et une seule alerte par adresse tant qu'elle reste dupliquée.

const DEFAULTS = {
  cooldownMs: 10 * 60 * 1000, // anti-répétition : une même adresse dupliquée ne réalerte pas en continu
}

export function createCiscoBehavior(config = {}) {
  const cfg = { ...DEFAULTS, ...config }
  const lastEmit = new Map()

  function emit(now, key, event) {
    const prev = lastEmit.get(key)
    if (prev !== undefined && now - prev < cfg.cooldownMs) return null
    if (lastEmit.size > 5000) for (const [k, t] of lastEmit) if (now - t >= cfg.cooldownMs) lastEmit.delete(k)
    lastEmit.set(key, now)
    return event
  }

  // hostLocations : [{ mac, locations: [{ switchIp, port }] }], tel que renvoyé par buildTopology().
  // gatewayMac : MAC de la passerelle déjà verrouillée par le capteur (detectors.mjs), ou null si inconnue.
  function observeSnapshot(hostLocations = [], { gatewayMac = null, now = Date.now() } = {}) {
    const events = []
    for (const h of hostLocations) {
      if (!h || !h.mac || !Array.isArray(h.locations) || h.locations.length < 2) continue
      const where = h.locations.map((l) => `${l.switchIp} (${l.port})`).join(', ')
      const isGateway = gatewayMac && h.mac === gatewayMac
      const e = emit(now, `${isGateway ? 'gw' : 'dup'}:${h.mac}`, isGateway ? {
        type: 'gateway_duplicate_location', severity: 'c', mac: h.mac,
        title: 'Adresse de la passerelle vue à plusieurs endroits du réseau',
        detail: `La MAC de la passerelle (${h.mac}) est apprise au même moment par ${h.locations.length} switchs : ${where}. Usurpation probable de la passerelle ailleurs sur le réseau (ou bascule réseau en cours : à vérifier).`,
      } : {
        type: 'mac_duplicate_location', severity: 'h', mac: h.mac,
        title: 'Une adresse réseau vue à plusieurs endroits à la fois',
        detail: `${h.mac} est apprise au même moment par ${h.locations.length} switchs : ${where}. Clonage ou usurpation d'adresse MAC probable (ou reconvergence réseau transitoire : à vérifier).`,
      })
      if (e) events.push(e)
    }
    return events
  }

  return { observeSnapshot }
}
