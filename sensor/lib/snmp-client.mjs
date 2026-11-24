// CyberVeylix Sensor — client SNMP en LECTURE SEULE (GET / GETBULK) au-dessus de net-snmp.
// Aucun SET n'est jamais envoyé. Délais courts, nombre de lignes borné. Les identifiants viennent de snmp.json.
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)

export const isUnder = (oid, base) => String(oid).startsWith(base + '.')
export function compareOids(a, b) {
  const x = String(a).split('.').map(Number)
  const y = String(b).split('.').map(Number)
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    if (x[i] === undefined) return -1
    if (y[i] === undefined) return 1
    if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1
  }
  return 0
}

export function createSnmpClient({ lib = null, timeoutMs = 2000, retries = 1, maxRows = 20000, walkMs = 60000 } = {}) {
  const snmp = lib || require('net-snmp')

  function open({ host, port = 161 }, cred, { context = null } = {}) {
    if (cred.version === '3') {
      const level = cred.privKey ? snmp.SecurityLevel.authPriv : cred.authKey ? snmp.SecurityLevel.authNoPriv : snmp.SecurityLevel.noAuthNoPriv
      const user = { name: cred.user, level }
      if (cred.authKey) Object.assign(user, { authProtocol: snmp.AuthProtocols[cred.authProtocol], authKey: cred.authKey })
      if (cred.privKey) Object.assign(user, { privProtocol: snmp.PrivProtocols[cred.privProtocol], privKey: cred.privKey })
      return snmp.createV3Session(host, user, { port, timeout: timeoutMs, retries, version: snmp.Version3, context: context || '' })
    }
    // SNMPv2c ; « community@vlan » : table MAC par VLAN des anciens Cisco.
    return snmp.createSession(host, context ? `${cred.community}@${context}` : cred.community, { port, timeout: timeoutMs, retries, version: snmp.Version2c })
  }

  const get = (session, oids) => new Promise((resolve) => {
    session.get(oids, (err, vbs) => {
      if (err) return resolve({ error: err, rows: [] })
      resolve({ rows: (vbs || []).filter((v) => !snmp.isVarbindError(v)).map((v) => ({ oid: v.oid, value: v.value })) })
    })
  })

  // Parcours défensif d'une table (GETBULK) : on s'arrête à la fin des données, à la sortie de la table, si l'OID
  // n'avance plus (équipement qui boucle), au-delà de maxRows lignes ou après walkMs. Jamais de boucle infinie.
  const walk = async (session, oid, limit = maxRows) => {
    const rows = []
    const started = Date.now()
    let current = oid
    for (;;) {
      if (rows.length >= limit) return { rows, error: null, truncated: true }
      if (Date.now() - started > walkMs) return { rows, error: new Error('délai de lecture dépassé'), truncated: true }
      const res = await new Promise((resolve) => session.getBulk([current], 0, 20, (err, vbs) => resolve({ err, vbs })))
      if (res.err) return { rows, error: rows.length ? null : res.err, truncated: false }
      const batch = Array.isArray(res.vbs && res.vbs[0]) ? res.vbs[0] : []
      if (!batch.length) return { rows, error: null, truncated: false }
      for (const v of batch) {
        if (snmp.isVarbindError(v) || !isUnder(v.oid, oid)) return { rows, error: null, truncated: false }
        if (compareOids(v.oid, current) <= 0) return { rows, error: null, truncated: false } // pas de progression
        rows.push({ oid: v.oid, value: v.value })
        current = v.oid
        if (rows.length >= limit) return { rows, error: null, truncated: true }
      }
    }
  }

  const close = (session) => { try { session.close() } catch { /* déjà fermée */ } }

  // Premier identifiant qui répond (lecture de sysName.0) ; null si l'équipement ne répond à aucun.
  async function probe(target, credentials, sysNameOid = '1.3.6.1.2.1.1.5.0') {
    for (const cred of credentials) {
      const session = open(target, cred)
      session.on?.('error', () => {})
      const r = await get(session, [sysNameOid])
      if (!r.error && r.rows.length) return { session, cred }
      close(session)
    }
    return null
  }

  return { open, get, walk, close, probe }
}
