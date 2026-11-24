// CyberVeylix Sensor — analyseur ARP (pur, testable sans réseau).
// Entrée : une trame Ethernet complète (Buffer). Sortie : objet ARP ou null.
// Toutes les lectures sont bornées : une trame malformée ou tronquée renvoie null,
// jamais d'accès hors limites (les paquets viennent du réseau et ne sont pas de confiance).
import { macToString, ipToString } from './format.mjs'

const ETH_HEADER_LEN = 14
const ETHERTYPE_ARP = 0x0806
const ARP_LEN = 28 // htype(2)+ptype(2)+hlen(1)+plen(1)+oper(2)+sha(6)+spa(4)+tha(6)+tpa(4)
const HTYPE_ETHERNET = 1
const PTYPE_IPV4 = 0x0800

export const ARP_REQUEST = 1
export const ARP_REPLY = 2

export function parseArp(frame) {
  if (!Buffer.isBuffer(frame) || frame.length < ETH_HEADER_LEN + ARP_LEN) return null
  if (frame.readUInt16BE(12) !== ETHERTYPE_ARP) return null

  const a = ETH_HEADER_LEN
  if (frame.readUInt16BE(a) !== HTYPE_ETHERNET) return null
  if (frame.readUInt16BE(a + 2) !== PTYPE_IPV4) return null
  if (frame[a + 4] !== 6 || frame[a + 5] !== 4) return null

  const op = frame.readUInt16BE(a + 6)
  if (op !== ARP_REQUEST && op !== ARP_REPLY) return null

  return {
    op,
    senderMac: macToString(frame, a + 8),
    senderIp: ipToString(frame, a + 14),
    targetMac: macToString(frame, a + 18),
    targetIp: ipToString(frame, a + 24),
    // L'émetteur réel de la trame (en-tête Ethernet), comparé à senderMac pour détecter l'usurpation.
    ethSrcMac: macToString(frame, 6),
  }
}
