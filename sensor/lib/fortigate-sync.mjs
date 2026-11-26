// CyberVeylix Sensor — exploite une interrogation FortiGate (lecture seule) :
//   - enregistre dans l'inventaire tout appareil vu par le pare-feu (baux DHCP + table ARP),
//     y compris ceux des autres VLAN que le capteur ne voit pas en écoute directe ;
//   - alimente le moteur de comportement avec les sessions (« qui parle à qui ») pour détecter
//     le balayage, les ports sondés et la communication avec une adresse malveillante connue.
// Rien n'est modifié sur le pare-feu. Pur et testable : inventory et behavior sont injectés.

export function applyFortigate(poll, { behavior, inventory, now = Date.now() } = {}) {
  const events = []
  const devices = new Map() // ip|mac -> { ip, mac } (dédoublonnage DHCP + ARP)

  const addDevice = (ip, mac) => {
    if (!mac && !ip) return
    const key = `${ip || ''}|${mac || ''}`
    if (!devices.has(key)) devices.set(key, { ip: ip || null, mac: mac || null })
  }
  for (const l of poll.leases || []) addDevice(l.ip, l.mac)
  for (const a of poll.arp || []) addDevice(a.ip, a.mac)

  if (inventory) {
    for (const d of devices.values()) {
      if (d.mac && d.ip) inventory.observe(d.mac, d.ip, now)
    }
  }

  if (behavior) {
    const seen = new Set() // une même session active n'est comptée qu'une fois par interrogation
    for (const s of poll.sessions || []) {
      const key = `${s.src}>${s.dst}:${s.dstPort ?? ''}`
      if (seen.has(key)) continue
      seen.add(key)
      events.push(...behavior.observe({ src: s.src, dst: s.dst, dstPort: s.dstPort, ts: now }, now))
    }
  }

  const vlans = new Set((poll.interfaces || []).map((i) => i.vlan).filter((v) => v != null))
  return { events, deviceCount: devices.size, vlanCount: vlans.size, sessionCount: (poll.sessions || []).length }
}
