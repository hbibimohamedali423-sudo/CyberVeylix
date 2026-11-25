// CyberVeylix Sensor — accès SNMP aux équipements (fichier local snmp.json du dossier de données, lecture seule).
// Les identifiants ne quittent JAMAIS ce PC : ni base de données, ni page web, ni journal. Messages d'erreur sans secret.
// Format :
// { "credentials": [ { "version": "2c", "community": "…" },
//                    { "version": "3", "user": "…", "authProtocol": "sha256", "authKey": "…", "privProtocol": "aes", "privKey": "…" } ],
//   "targets": ["10.15.0.2"],   ← équipements à interroger en plus de la découverte automatique (facultatif)
//   "auto": true }              ← passerelle, équipements réseau identifiés et voisins LLDP/CDP

const IPV4 = /^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$/
const AUTH = ['md5', 'sha', 'sha224', 'sha256', 'sha384', 'sha512']
const PRIV = ['des', 'aes', 'aes256b', 'aes256r']

// Réseaux privés (et boucle locale pour les tests) uniquement : jamais d'adresse publique.
export function isAllowedTarget(ip) {
  if (!IPV4.test(ip || '')) return false
  const [a, b] = ip.split('.').map(Number)
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 127
}
export function parseTarget(t) {
  const m = /^([\d.]+)(?::(\d{1,5}))?$/.exec(String(t || '').trim())
  if (!m || !isAllowedTarget(m[1])) return null
  const port = m[2] ? Number(m[2]) : 161
  return port >= 1 && port <= 65535 ? { host: m[1], port } : null
}

export function parseSnmpConfig(text) {
  let raw
  try { raw = JSON.parse(String(text).replace(/^﻿/, '')) } catch { return { error: 'snmp.json illisible (JSON invalide).' } }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { error: 'snmp.json : un objet JSON est attendu.' }
  const list = Array.isArray(raw.credentials) ? raw.credentials : (raw.community ? [{ version: '2c', community: raw.community }] : [])
  if (!list.length || list.length > 5) return { error: 'snmp.json : de 1 à 5 identifiants (credentials) sont attendus.' }
  const credentials = []
  for (const [n, c] of list.entries()) {
    const where = `snmp.json, identifiant n° ${n + 1}`
    if (!c || typeof c !== 'object') return { error: `${where} : objet attendu.` }
    const version = String(c.version || '2c')
    if (version === '2c' || version === '2') {
      if (typeof c.community !== 'string' || !c.community || c.community.length > 64 || /\s/.test(c.community)) return { error: `${where} : community invalide.` }
      credentials.push({ version: '2c', community: c.community })
    } else if (version === '3') {
      if (typeof c.user !== 'string' || !c.user || c.user.length > 32) return { error: `${where} : utilisateur SNMPv3 invalide.` }
      const cred = { version: '3', user: c.user }
      if (c.authKey !== undefined) {
        if (typeof c.authKey !== 'string' || c.authKey.length < 8) return { error: `${where} : clé d'authentification trop courte (8 caractères au moins).` }
        const p = String(c.authProtocol || 'sha').toLowerCase()
        if (!AUTH.includes(p)) return { error: `${where} : authProtocol inconnu (${AUTH.join(', ')}).` }
        Object.assign(cred, { authProtocol: p, authKey: c.authKey })
      }
      if (c.privKey !== undefined) {
        if (!cred.authKey) return { error: `${where} : le chiffrement (privKey) exige aussi authKey.` }
        if (typeof c.privKey !== 'string' || c.privKey.length < 8) return { error: `${where} : clé de chiffrement trop courte (8 caractères au moins).` }
        const p = String(c.privProtocol || 'aes').toLowerCase()
        if (!PRIV.includes(p)) return { error: `${where} : privProtocol inconnu (${PRIV.join(', ')}).` }
        Object.assign(cred, { privProtocol: p, privKey: c.privKey })
      }
      credentials.push(cred)
    } else {
      return { error: `${where} : version « 2c » ou « 3 » attendue.` }
    }
  }
  const targets = []
  for (const t of Array.isArray(raw.targets) ? raw.targets.slice(0, 200) : []) {
    const p = parseTarget(t)
    if (!p) return { error: `snmp.json : équipement « ${String(t).slice(0, 40)} » refusé (adresse IPv4 privée attendue).` }
    targets.push(p)
  }
  return { config: { credentials, targets, auto: raw.auto !== false } }
}
