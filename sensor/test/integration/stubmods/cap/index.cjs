// Carte réseau simulée pour le test d'intégration (remplace Npcap).
// Si CV_STUB_FRAMES désigne un fichier JSON de trames (hexadécimal), elles sont « reçues » peu après l'ouverture,
// exactement comme des paquets réels : le capteur les lit dans le tampon fourni à open().
const { EventEmitter } = require('node:events')
const { readFileSync } = require('node:fs')
const DEV = { name: 'stub0', description: 'interface simulée', addresses: [{ addr: '192.168.50.10', netmask: '255.255.255.0' }] }
class Cap extends EventEmitter {
  static deviceList() { return [DEV] }
  static findDevice(ip) { return ip === '192.168.50.10' ? 'stub0' : undefined }
  open(_device, _filter, _size, buffer) {
    const file = process.env.CV_STUB_FRAMES
    if (file) {
      const frames = JSON.parse(readFileSync(file, 'utf8'))
      setTimeout(() => {
        for (const hex of frames) {
          const f = Buffer.from(hex, 'hex')
          f.copy(buffer)
          this.emit('packet', f.length, false)
        }
      }, 300)
    }
    return 'ETHERNET'
  }
  setMinBytes() {}
  close() {}
}
module.exports = { Cap, decoders: {} }
