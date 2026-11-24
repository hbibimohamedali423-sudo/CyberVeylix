// CyberVeylix Sensor — analyseur DHCP (pur, testable sans réseau).
// Entrée : une trame Ethernet complète (Buffer). Sortie : message DHCP serveur ou null.
// On ne s'intéresse qu'aux réponses serveur (OFFER/ACK) : elles révèlent QUI distribue
// des adresses sur le réseau, donc un éventuel serveur DHCP pirate.
// Lectures bornées : toute trame tronquée ou malformée renvoie null.
import { macToString, ipToString } from './format.mjs'

const ETH_HEADER_LEN = 14
const ETHERTYPE_IPV4 = 0x0800
const PROTO_UDP = 17
const DHCP_SERVER_PORT = 67
const DHCP_MAGIC = 0x63825363
const BOOTREPLY = 2

export const DHCP_OFFER = 2
export const DHCP_ACK = 5

export function parseDhcpServerReply(frame) {
  if (!Buffer.isBuffer(frame) || frame.length < ETH_HEADER_LEN + 20) return null
  if (frame.readUInt16BE(12) !== ETHERTYPE_IPV4) return null

  const ip = ETH_HEADER_LEN
  if ((frame[ip] >> 4) !== 4) return null
  const ihl = (frame[ip] & 0x0f) * 4
  if (ihl < 20 || frame.length < ip + ihl + 8) return null
  if (frame[ip + 9] !== PROTO_UDP) return null

  const srcIp = ipToString(frame, ip + 12)

  const udp = ip + ihl
  const srcPort = frame.readUInt16BE(udp)
  if (srcPort !== DHCP_SERVER_PORT) return null // seules les trames émises par un serveur

  const dhcp = udp + 8
  if (frame.length < dhcp + 240) return null // en-tête DHCP fixe + cookie magique
  if (frame[dhcp] !== BOOTREPLY) return null
  if (frame.readUInt32BE(dhcp + 236) !== DHCP_MAGIC) return null

  const yiaddr = ipToString(frame, dhcp + 16) // adresse proposée au client

  // Parcours borné des options (option 53 = type, option 54 = identifiant serveur).
  let messageType = null
  let serverId = null
  let i = dhcp + 240
  while (i < frame.length) {
    const code = frame[i]
    if (code === 255) break // fin des options
    if (code === 0) { i++; continue } // remplissage
    if (i + 1 >= frame.length) break
    const len = frame[i + 1]
    const valueAt = i + 2
    if (valueAt + len > frame.length) break
    if (code === 53 && len === 1) messageType = frame[valueAt]
    else if (code === 54 && len === 4) serverId = ipToString(frame, valueAt)
    i = valueAt + len
  }

  if (messageType !== DHCP_OFFER && messageType !== DHCP_ACK) return null

  return {
    messageType,
    // Identité du serveur : l'option 54 fait foi, sinon l'IP source du paquet.
    serverId: serverId || srcIp,
    serverMac: macToString(frame, 6),
    offeredIp: yiaddr,
  }
}
