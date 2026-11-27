// CyberVeylix Sensor — fabricant d'un appareil d'après son adresse MAC (registre IEEE, paquet oui-data).
// - Les 3 premiers octets (OUI) désignent le fabricant de la carte réseau.
// - Une MAC « administrée localement » (bit 0x02 du premier octet) est aléatoire : c'est la protection de la vie
//   privée des téléphones et portables récents. Aucun fabricant ne peut alors en être déduit (jamais inventé).
// Registre absent ou illisible : le fabricant reste inconnu, le capteur continue.
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)

export const isRandomMac = (mac) => /^[0-9a-f]{2}:/i.test(mac || '') && (parseInt(mac.slice(0, 2), 16) & 0x02) === 0x02

// Nom court et lisible : première ligne du registre, sans les formes juridiques.
export function shortVendor(raw) {
  const first = String(raw || '').split('\n')[0].trim()
  if (!first) return null
  return first
    .replace(/[,.]?\s+(inc|corp|corporation|co|ltd|limited|llc|gmbh|s\.?a\.?|ag|plc|bv|b\.v|oy|ab|srl|s\.r\.l|pte|pty|kg|sas|spa|s\.p\.a)\.?(\s|,|$).*$/i, '')
    .replace(/\s+(technologies?|technology|communications?|electronics?|systems?|international|holdings?|group)$/i, '')
    .trim()
    .slice(0, 60) || first.slice(0, 60)
}

// table : { '38C0EA': 'Fortinet, Inc.\n…' } (injectable pour les tests). Sans table : chargement paresseux d'oui-data.
export function createOui({ table = null } = {}) {
  let data = table
  let tried = Boolean(table)
  const cache = new Map()
  const load = () => {
    if (tried) return data
    tried = true
    try { data = require('oui-data') } catch { data = null } // « exports » du paquet : la racine est le JSON
    return data
  }
  function vendorOf(mac) {
    const m = String(mac || '').toLowerCase()
    if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(m) || isRandomMac(m)) return null
    const prefix = m.slice(0, 8).replaceAll(':', '').toUpperCase()
    if (cache.has(prefix)) return cache.get(prefix)
    const d = load()
    const v = d && Object.hasOwn(d, prefix) ? shortVendor(d[prefix]) : null
    cache.set(prefix, v)
    return v
  }
  return { vendorOf, available: () => Boolean(load()) }
}
