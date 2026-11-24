// Constructeurs de trames Ethernet pour les tests (aucun réseau requis).
const macBytes = (mac) => Buffer.from(mac.split(':').map((h) => parseInt(h, 16)))
const ipBytes = (ip) => Buffer.from(ip.split('.').map((n) => Number(n)))

// Trame ARP complète. op : 1 = requête, 2 = réponse.
export function arpFrame({ op = 2, senderMac, senderIp, targetMac = '00:00:00:00:00:00', targetIp = '0.0.0.0', ethSrc }) {
  const eth = Buffer.concat([
    macBytes('ff:ff:ff:ff:ff:ff'),
    macBytes(ethSrc || senderMac),
    Buffer.from([0x08, 0x06]),
  ])
  const arp = Buffer.concat([
    Buffer.from([0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, op]),
    macBytes(senderMac), ipBytes(senderIp),
    macBytes(targetMac), ipBytes(targetIp),
  ])
  return Buffer.concat([eth, arp])
}

// Trame DHCP émise par un serveur (OFFER=2 / ACK=5).
export function dhcpServerFrame({ type = 2, serverMac, serverIp, offeredIp = '192.168.1.50', serverIdOption = true }) {
  const eth = Buffer.concat([
    macBytes('ff:ff:ff:ff:ff:ff'),
    macBytes(serverMac),
    Buffer.from([0x08, 0x00]),
  ])
  const ipHdr = Buffer.alloc(20)
  ipHdr[0] = 0x45
  ipHdr[9] = 17 // UDP
  ipBytes(serverIp).copy(ipHdr, 12)
  ipBytes('255.255.255.255').copy(ipHdr, 16)

  const udp = Buffer.alloc(8)
  udp.writeUInt16BE(67, 0) // src port serveur
  udp.writeUInt16BE(68, 2) // dst port client

  const dhcp = Buffer.alloc(240)
  dhcp[0] = 2 // BOOTREPLY
  dhcp[1] = 1; dhcp[2] = 6
  ipBytes(offeredIp).copy(dhcp, 16) // yiaddr
  dhcp.writeUInt32BE(0x63825363, 236) // cookie magique

  const opts = [53, 1, type]
  if (serverIdOption) opts.push(54, 4, ...serverIp.split('.').map(Number))
  opts.push(255)

  return Buffer.concat([eth, ipHdr, udp, dhcp, Buffer.from(opts)])
}
