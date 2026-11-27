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

// Demande DHCP d'un appareil (DISCOVER par défaut), avec nom (12), classe (60), IP demandée (50), paramètres (55).
export function dhcpClientFrame({ type = 1, mac, hostname = null, vendorClass = null, requestedIp = null, ciaddr = '0.0.0.0', params = [1, 3, 6, 15], extra = [] }) {
  const eth = Buffer.concat([macBytes('ff:ff:ff:ff:ff:ff'), macBytes(mac), Buffer.from([0x08, 0x00])])
  const ipHdr = Buffer.alloc(20)
  ipHdr[0] = 0x45
  ipHdr[9] = 17
  ipBytes('0.0.0.0').copy(ipHdr, 12)
  ipBytes('255.255.255.255').copy(ipHdr, 16)
  const udp = Buffer.alloc(8)
  udp.writeUInt16BE(68, 0)
  udp.writeUInt16BE(67, 2)
  const dhcp = Buffer.alloc(240)
  dhcp[0] = 1; dhcp[1] = 1; dhcp[2] = 6 // BOOTREQUEST, Ethernet
  ipBytes(ciaddr).copy(dhcp, 12)
  macBytes(mac).copy(dhcp, 28)
  dhcp.writeUInt32BE(0x63825363, 236)
  const opts = [53, 1, type]
  const str = (code, s) => { const b = Buffer.from(s, 'utf8'); opts.push(code, b.length, ...b) }
  if (hostname !== null) str(12, hostname)
  if (vendorClass !== null) str(60, vendorClass)
  if (requestedIp) opts.push(50, 4, ...requestedIp.split('.').map(Number))
  if (params) opts.push(55, params.length, ...params)
  opts.push(...extra, 255)
  return Buffer.concat([eth, ipHdr, udp, dhcp, Buffer.from(opts)])
}

// Trame LLDP d'un switch (TLV châssis MAC, port, nom, description, capacités bridge, adresse de gestion IPv4).
export function lldpFrame({ src, chassisMac = null, chassisName = null, portId = 'Gi1/0/7', sysName = 'SW-CORE', sysDescr = 'Cisco IOS', mgmtIp = '10.15.0.2', bridge = true, wlanAp = false, dst = '0180c200000e' }) {
  const eth = Buffer.concat([Buffer.from(dst, 'hex'), macBytes(src), Buffer.from([0x88, 0xcc])])
  const tlv = (type, value) => { const b = Buffer.from(value); const h = Buffer.alloc(2); h.writeUInt16BE((type << 9) | b.length); return Buffer.concat([h, b]) }
  const parts = []
  parts.push(tlv(1, chassisMac ? Buffer.concat([Buffer.from([4]), macBytes(chassisMac)]) : Buffer.concat([Buffer.from([7]), Buffer.from(chassisName || 'chassis')])))
  parts.push(tlv(2, Buffer.concat([Buffer.from([7]), Buffer.from(portId)])))
  if (sysName) parts.push(tlv(5, Buffer.from(sysName)))
  if (sysDescr) parts.push(tlv(6, Buffer.from(sysDescr)))
  const caps = (bridge ? 0x04 : 0) | (wlanAp ? 0x08 : 0)
  parts.push(tlv(7, Buffer.from([0, caps, 0, caps])))
  if (mgmtIp) parts.push(tlv(8, Buffer.concat([Buffer.from([5, 1]), ipBytes(mgmtIp), Buffer.from([0x03, 0, 0, 0, 0])])))
  parts.push(Buffer.from([0, 0])) // fin
  return Buffer.concat([eth, ...parts])
}

// Trame CDP (Cisco) : en-tête SNAP puis TLV Device ID, Port ID, adresse IPv4, capacités.
export function cdpFrame({ src, sysName = 'SW-ETAGE', portId = 'GigabitEthernet0/1', sysDescr = 'cisco WS-C2960', mgmtIp = '10.15.0.3', bridge = true }) {
  const payload = []
  const tlv = (type, value) => { const b = Buffer.from(value); const h = Buffer.alloc(4); h.writeUInt16BE(type, 0); h.writeUInt16BE(b.length + 4, 2); return Buffer.concat([h, b]) }
  payload.push(tlv(0x0001, Buffer.from(sysName)))
  if (mgmtIp) payload.push(tlv(0x0002, Buffer.concat([Buffer.from([0, 0, 0, 1, 1, 0xcc, 0, 4]), ipBytes(mgmtIp)])))
  payload.push(tlv(0x0003, Buffer.from(portId)))
  payload.push(tlv(0x0004, Buffer.from([0, 0, 0, bridge ? 0x08 : 0x10])))
  payload.push(tlv(0x0005, Buffer.from(sysDescr)))
  const body = Buffer.concat([Buffer.from([0x02, 0xb4, 0x00, 0x00]), ...payload]) // version, ttl, checksum (0)
  const snap = Buffer.from('aaaa0300000c2000', 'hex')
  const llcLen = Buffer.alloc(2); llcLen.writeUInt16BE(snap.length + body.length)
  const eth = Buffer.concat([Buffer.from('01000ccccccc', 'hex'), macBytes(src), llcLen])
  return Buffer.concat([eth, snap, body])
}
