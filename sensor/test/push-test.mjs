// Tests de l'envoi au tableau de bord (lib/push.mjs) avec un faux client Supabase en mémoire.
import assert from 'node:assert/strict'
import { createPusher, isMissingColumn } from '../lib/push.mjs'

// Faux client : tables en mémoire ; `missing` liste les colonnes « absentes » (base sans R1),
// `noSensors` simule l'absence de la table sensors.
function fakeSupabase({ tables = {}, missing = [], noSensors = false } = {}) {
  const db = { networks: [], devices: [], alerts: [], vulnerabilities: [], services: [], sensors: [], ...tables }
  let seq = 0
  const calls = []
  const colError = (rows) => {
    for (const r of rows) for (const k of Object.keys(r)) {
      if (missing.includes(k)) return { code: 'PGRST204', message: `Could not find the '${k}' column of 'x' in the schema cache` }
    }
    return null
  }
  const result = (value) => ({ then: (ok, ko) => Promise.resolve(value).then(ok, ko) })
  function from(table) {
    if (table === 'sensors' && noSensors) {
      const err = { error: { code: 'PGRST205', message: "Could not find the table 'public.sensors' in the schema cache" } }
      return { upsert: () => result(err), select: () => result(err) }
    }
    const rows = db[table]
    return {
      select: () => result({ data: rows.map((r) => ({ ...r })), error: null }),
      insert(list) {
        calls.push(['insert', table, list])
        const error = colError(list)
        if (!error) for (const r of list) rows.push({ id: `id${++seq}`, status: 'open', ...r })
        return result({ error })
      },
      upsert(list, { onConflict }) {
        calls.push(['upsert', table, list])
        const error = colError(list)
        if (error) return result({ error })
        const keys = onConflict.split(',').filter((k) => k !== 'user_id')
        for (const r of list) {
          const hit = rows.find((x) => keys.every((k) => x[k] === r[k]))
          if (hit) Object.assign(hit, r)
          else rows.push({ id: `id${++seq}`, status: 'open', ...r })
        }
        return result({ error: null })
      },
      update(patch) {
        const filters = []
        const q = {
          in: (c, v) => { filters.push((r) => v.includes(r[c])); return q },
          eq: (c, v) => { filters.push((r) => r[c] === v); return q },
          neq: (c, v) => { filters.push((r) => r[c] !== v); return q },
          then: (ok, ko) => {
            for (const r of rows) if (filters.every((f) => f(r))) Object.assign(r, patch)
            return Promise.resolve({ error: null }).then(ok, ko)
          },
        }
        return q
      },
    }
  }
  return { from, db, calls }
}

const GW = 'AA-BB-CC-00-00-01'
const base = () => ({
  networks: [{ id: 'net-other', gateway_mac: '11:22:33:44:55:66' }, { id: 'net-bureau', gateway_mac: 'aa:bb:cc:00:00:01' }],
  devices: [
    { id: 'dev-cafe', ip: '192.168.1.20', network_id: 'net-other' },
    { id: 'dev-nas', ip: '192.168.1.20', network_id: 'net-bureau' },
  ],
})
const finding = (over) => ({
  key: '192.168.1.20:445:smb1-enabled', rule: 'smb1-enabled', ip: '192.168.1.20', port: 445, service: 'smb',
  severity: 'h', cves: ['CVE-2017-0144'], confidence: 'certaine', title: 'SMBv1 activé',
  evidence: 'Négociation SMB1 acceptée.', remediation: 'Désactiver SMBv1.', ...over,
})
const quiet = () => {}
const now = () => new Date('2026-11-24T10:00:00Z')

export function pushChecks(check, checkAsync) {
  check('Envoi : erreurs « colonne absente » reconnues (PostgREST et PostgreSQL)', () => {
    assert.equal(isMissingColumn({ code: 'PGRST204', message: '' }), true)
    assert.equal(isMissingColumn({ code: '42703', message: '' }), true)
    assert.equal(isMissingColumn({ code: '42501', message: 'new row violates row-level security policy' }), false)
    assert.equal(isMissingColumn(null), false)
  })

  checkAsync('Envoi : faiblesse détaillée, rattachée au réseau de la passerelle et au bon appareil', async () => {
    const sb = fakeSupabase({ tables: base() })
    const p = createPusher(sb, { gatewayMac: GW, log: quiet, now })
    await p.syncVulnerabilities({ findings: [finding()] })
    const [v] = sb.db.vulnerabilities
    assert.equal(sb.db.vulnerabilities.length, 1)
    assert.equal(v.network_id, 'net-bureau')
    assert.equal(v.device_id, 'dev-nas') // même IP dans un autre réseau : ignorée
    assert.deepEqual(v.cves, ['CVE-2017-0144'])
    assert.equal(v.source, 'scan')
    assert.equal(v.confidence, 'certaine')
    assert.equal(v.last_seen, '2026-11-24T10:00:00.000Z')
  })

  checkAsync('Envoi : analyse suivante sans doublon, statut choisi par l\'utilisateur conservé', async () => {
    const sb = fakeSupabase({ tables: base() })
    const p = createPusher(sb, { gatewayMac: GW, log: quiet, now })
    await p.syncVulnerabilities({ findings: [finding()] })
    sb.db.vulnerabilities[0].status = 'ack'
    await p.syncVulnerabilities({ findings: [finding({ evidence: 'Toujours là.' })] })
    assert.equal(sb.db.vulnerabilities.length, 1)
    assert.equal(sb.db.vulnerabilities[0].status, 'ack')
    assert.equal(sb.db.vulnerabilities[0].evidence, 'Toujours là.')
  })

  checkAsync('Envoi : faiblesse disparue → « Résolue » ; réapparue → rouverte', async () => {
    const sb = fakeSupabase({ tables: base() })
    const p = createPusher(sb, { gatewayMac: GW, log: quiet, now })
    const f = finding()
    await p.syncVulnerabilities({ findings: [f] })
    await p.syncVulnerabilities({ findings: [], fixed: [f] })
    assert.equal(sb.db.vulnerabilities[0].status, 'resolved')
    assert.equal(sb.db.vulnerabilities[0].resolved_at, '2026-11-24T10:00:00.000Z')
    await p.syncVulnerabilities({ findings: [f] })
    assert.equal(sb.db.vulnerabilities[0].status, 'open')
    assert.equal(sb.db.vulnerabilities[0].resolved_at, null)
  })

  checkAsync('Envoi : base sans R1 → envoi réduit (titre, gravité, appareil), toujours sans doublon', async () => {
    const sb = fakeSupabase({ tables: base(), missing: ['source', 'finding_key', 'kind', 'version'] })
    const p = createPusher(sb, { gatewayMac: GW, log: quiet, now })
    await p.syncVulnerabilities({ findings: [finding()] })
    await p.syncVulnerabilities({ findings: [finding()] })
    assert.equal(sb.db.vulnerabilities.length, 1)
    assert.deepEqual(Object.keys(sb.db.vulnerabilities[0]).sort(), ['device_id', 'id', 'severity', 'status', 'title'])
    await p.pushAlerts([{ type: 'gateway_spoof', severity: 'c', title: 'Usurpation', detail: 'x' }])
    assert.equal(sb.db.alerts.length, 1)
    assert.equal(sb.db.alerts[0].source, undefined)
    assert.equal(p.r1, false)
  })

  checkAsync('Envoi : alertes avec origine (capteur / leurre / analyse) et type', async () => {
    const sb = fakeSupabase({ tables: base() })
    const p = createPusher(sb, { gatewayMac: GW, log: quiet, now })
    await p.pushAlerts([
      { type: 'rogue_dhcp', severity: 'c', ip: '192.168.1.20', title: 'DHCP pirate', detail: 'd' },
      { type: 'honeypot_scan', severity: 'c', ip: '192.168.1.99', title: 'Balayage', detail: 'd' },
      { type: 'vuln_fixed', severity: 'l', title: 'Corrigée', detail: 'd' },
    ])
    assert.deepEqual(sb.db.alerts.map((a) => a.source), ['sensor', 'honeypot', 'vuln_scan'])
    assert.equal(sb.db.alerts[0].kind, 'rogue_dhcp')
    assert.equal(sb.db.alerts[0].device_id, 'dev-nas')
    assert.equal(sb.db.alerts[1].device_id, null) // appareil inconnu : rien d'inventé
    assert.ok(sb.db.alerts.every((a) => a.network_id === 'net-bureau'))
  })

  checkAsync('Envoi : adresse source seulement quand elle désigne le fautif ; MAC toujours', async () => {
    const sb = fakeSupabase({ tables: base() })
    const p = createPusher(sb, { gatewayMac: GW, log: quiet, now })
    await p.pushAlerts([
      { type: 'honeypot_scan', severity: 'c', ip: '192.168.1.99', mac: 'aa:bb:cc:00:00:99', title: 'Balayage', detail: 'd' },
      { type: 'rogue_dhcp', severity: 'c', ip: '192.168.1.20', mac: 'aa:bb:cc:00:00:20', title: 'DHCP', detail: 'd' },
      // IP = celle de la passerelle imitée (la victime) : jamais proposée comme adresse à bloquer.
      { type: 'gateway_spoof', severity: 'c', ip: '192.168.1.1', mac: 'de:ad:be:ef:00:01', title: 'Usurpation', detail: 'd' },
      { type: 'arp_spoof_sweep', severity: 'h', ip: '192.168.1.5', mac: 'de:ad:be:ef:00:02', title: 'ARP', detail: 'd' },
      { type: 'vuln_new', severity: 'h', title: 'Nouvelle faiblesse', detail: 'd' },
    ])
    assert.deepEqual(sb.db.alerts.map((a) => a.source_ip), ['192.168.1.99', '192.168.1.20', null, null, null])
    assert.deepEqual(sb.db.alerts.map((a) => a.source_mac), ['aa:bb:cc:00:00:99', 'aa:bb:cc:00:00:20', 'de:ad:be:ef:00:01', 'de:ad:be:ef:00:02', null])
  })

  checkAsync('Envoi : base sans R4 → alertes envoyées sans adresse source, R1 conservé', async () => {
    const logs = []
    const sb = fakeSupabase({ tables: base(), missing: ['source_ip', 'source_mac'] })
    const p = createPusher(sb, { gatewayMac: GW, log: (m) => logs.push(m), now })
    await p.pushAlerts([{ type: 'honeypot_scan', severity: 'c', ip: '192.168.1.99', mac: 'aa:bb:cc:00:00:99', title: 'Balayage', detail: 'd' }])
    await p.pushAlerts([{ type: 'new_device', severity: 'm', ip: '192.168.1.98', title: 'Nouveau', detail: 'd' }])
    assert.equal(sb.db.alerts.length, 2)
    assert.equal(sb.db.alerts[0].source, 'honeypot') // colonnes R1 toujours envoyées
    assert.equal(sb.db.alerts[0].source_ip, undefined)
    assert.equal(p.r1, true)
    assert.equal(logs.filter((m) => m.includes('R4')).length, 1) // message une seule fois
  })

  checkAsync('Envoi : réseau inconnu → network_id vide (aucun réseau deviné)', async () => {
    const sb = fakeSupabase({ tables: base() })
    const p = createPusher(sb, { gatewayMac: '00:00:00:00:00:99', log: quiet, now })
    await p.pushAlerts([{ type: 'new_device', severity: 'm', title: 't', detail: 'd' }])
    assert.equal(sb.db.alerts[0].network_id, null)
  })

  checkAsync('Envoi : services d\'appareils inventoriés seulement, avec version', async () => {
    const sb = fakeSupabase({ tables: base() })
    const p = createPusher(sb, { gatewayMac: GW, log: quiet, now })
    await p.syncServices([
      { ip: '192.168.1.20', services: [{ port: 22, service: 'ssh', detail: 'OpenSSH_9.6p1' }] },
      { ip: '192.168.1.77', services: [{ port: 80, service: 'http', detail: '' }] },
    ])
    assert.equal(sb.db.services.length, 1)
    assert.equal(sb.db.services[0].device_id, 'dev-nas')
    assert.equal(sb.db.services[0].version, 'OpenSSH_9.6p1')
  })

  checkAsync('Envoi : pouls du capteur sans doublon ; table absente → message unique, pas d\'erreur', async () => {
    const sb = fakeSupabase({ tables: base() })
    const p = createPusher(sb, { gatewayMac: GW, log: quiet, now })
    await p.heartbeat({ name: 'PC-ACCUEIL', version: '0.5.0', honeypot: true, vulnScan: true })
    await p.heartbeat({ name: 'PC-ACCUEIL', version: '0.5.0', honeypot: true, vulnScan: true, lastScanAt: '2026-11-24T09:00:00Z' })
    assert.equal(sb.db.sensors.length, 1)
    assert.equal(sb.db.sensors[0].network_id, 'net-bureau')
    assert.equal(sb.db.sensors[0].last_scan_at, '2026-11-24T09:00:00Z')

    const logs = []
    const p2 = createPusher(fakeSupabase({ noSensors: true }), { log: (m) => logs.push(m), now })
    await p2.heartbeat({ name: 'PC' })
    await p2.heartbeat({ name: 'PC' })
    assert.equal(logs.length, 1)
  })

  checkAsync('Envoi : MAC de passerelle apprise après le démarrage (fonction)', async () => {
    const sb = fakeSupabase({ tables: base() })
    let mac = null
    const p = createPusher(sb, { gatewayMac: () => mac, log: quiet, now })
    await p.pushAlerts([{ type: 'new_device', severity: 'm', title: 'a', detail: 'd' }])
    mac = GW
    await p.pushAlerts([{ type: 'new_device', severity: 'm', title: 'b', detail: 'd' }])
    assert.deepEqual(sb.db.alerts.map((a) => a.network_id), [null, 'net-bureau'])
  })
}
