// CyberVeylix Sensor — petits utilitaires de formatage (purs, sans dépendance).

// Formate 6 octets en adresse MAC « aa:bb:cc:dd:ee:ff ».
export function macToString(buf, offset = 0) {
  const parts = []
  for (let i = 0; i < 6; i++) parts.push(buf[offset + i].toString(16).padStart(2, '0'))
  return parts.join(':')
}

// Formate 4 octets en adresse IPv4 « 192.168.1.1 ».
export function ipToString(buf, offset = 0) {
  return `${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}`
}

// MAC de diffusion ou multicast : ne désigne pas un vrai appareil source.
export function isBroadcastOrMulticast(mac) {
  if (mac === 'ff:ff:ff:ff:ff:ff' || mac === '00:00:00:00:00:00') return true
  // Bit de poids faible du premier octet = 1 → multicast (ex. 01:00:5e..., 33:33...).
  const first = parseInt(mac.slice(0, 2), 16)
  return Number.isFinite(first) && (first & 1) === 1
}
