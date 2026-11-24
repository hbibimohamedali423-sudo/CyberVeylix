// Carte réseau simulée pour le test d'intégration (remplace Npcap) : aucun paquet capturé.
const { EventEmitter } = require('node:events')
const DEV = { name: 'stub0', description: 'interface simulée', addresses: [{ addr: '192.168.50.10' }] }
class Cap extends EventEmitter {
  static deviceList() { return [DEV] }
  static findDevice(ip) { return ip === '192.168.50.10' ? 'stub0' : undefined }
  open() { return 'ETHERNET' }
  setMinBytes() {}
  close() {}
}
module.exports = { Cap, decoders: {} }
