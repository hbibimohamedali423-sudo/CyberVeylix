// CyberVeylix Sensor — client FortiGate (FortiOS) en LECTURE SEULE.
//
// N'émet que des requêtes GET vers l'API de surveillance du pare-feu, avec une clé d'API en
// lecture seule fournie par l'administrateur réseau du client. Ne modifie JAMAIS la configuration.
// La couche HTTP est injectable (fetchImpl) pour les tests ; par défaut fetch de Node.
//
// Points lus (tous en lecture seule) :
//   - interfaces et VLAN           cmdb/system/interface
//   - baux DHCP (tous les VLAN)     monitor/system/dhcp
//   - table ARP (tous les VLAN)     monitor/network/arp
//   - sessions actives (qui→qui)    monitor/firewall/session
//   - objets/groupes adresse        cmdb/firewall/address, cmdb/firewall/addrgrp
//   - règles de pare-feu            cmdb/firewall/policy
// Les trois derniers servent uniquement à reachability.mjs (qui peut joindre qui entre VLAN).
import { parseInterfaces, parseDhcpLeases, parseArpTable, parseSessions, parseAddressObjects, parseAddressGroups, parsePolicies } from './fortigate-parse.mjs'

const ENDPOINTS = {
  interfaces: 'api/v2/cmdb/system/interface',
  leases: 'api/v2/monitor/system/dhcp',
  arp: 'api/v2/monitor/network/arp',
  sessions: 'api/v2/monitor/firewall/session',
  addresses: 'api/v2/cmdb/firewall/address',
  addressGroups: 'api/v2/cmdb/firewall/addrgrp',
  policies: 'api/v2/cmdb/firewall/policy',
}

export function createFortigateClient(config = {}) {
  const host = String(config.host || '').replace(/^https?:\/\//, '').replace(/\/+$/, '')
  const port = config.port || 443
  const token = config.token || ''
  const timeoutMs = config.timeoutMs || 15000
  const fetchImpl = config.fetchImpl || globalThis.fetch
  if (!host) throw new Error('FortiGate : hôte manquant.')
  if (!token) throw new Error('FortiGate : clé d’API manquante.')
  if (typeof fetchImpl !== 'function') throw new Error('FortiGate : fetch indisponible.')

  const base = `https://${host}:${port}/`

  async function get(path) {
    const url = base + path + (path.includes('?') ? '&' : '?') + 'format=json'
    const ctrl = typeof AbortController === 'function' ? new AbortController() : null
    const timer = ctrl ? setTimeout(() => ctrl.abort(), timeoutMs) : null
    try {
      const res = await fetchImpl(url, {
        method: 'GET', // LECTURE SEULE : jamais POST/PUT/DELETE
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
        signal: ctrl ? ctrl.signal : undefined,
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      return await res.json()
    } finally {
      if (timer) clearTimeout(timer)
    }
  }

  // Interroge tous les points ; un point en échec n'empêche pas les autres (erreurs collectées).
  async function poll() {
    const out = { interfaces: [], leases: [], arp: [], sessions: [], addresses: [], addressGroups: [], policies: [], errors: {} }
    const run = async (key, parse) => {
      try { out[key] = parse(await get(ENDPOINTS[key])) }
      catch (e) { out.errors[key] = (e && e.message) || String(e) }
    }
    await Promise.all([
      run('interfaces', parseInterfaces),
      run('leases', parseDhcpLeases),
      run('arp', parseArpTable),
      run('sessions', parseSessions),
      run('addresses', parseAddressObjects),
      run('addressGroups', parseAddressGroups),
      run('policies', parsePolicies),
    ])
    return out
  }

  return { poll, get, base }
}
