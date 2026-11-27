// CyberVeylix — envoi des résultats du capteur et de l'analyse vers Supabase (tableau de bord).
// Le client Supabase est injecté : le module est testable avec un faux client (sensor/test/push-test.mjs).
// Compatible avant ET après supabase/schema_r1_results.sql : si une colonne R1 manque, on renvoie
// le strict minimum (titre, gravité, appareil) au lieu d'échouer.
import { normalizeMac } from './options.mjs'

// Origine affichée dans l'application pour chaque type d'événement.
export const ALERT_SOURCE = {
  gateway_spoof: 'sensor', rogue_dhcp: 'sensor', mac_changed: 'sensor', arp_spoof_sweep: 'sensor',
  mac_flood: 'sensor', new_device: 'sensor',
  malware_c2: 'sensor', lateral_scan: 'sensor', port_scan: 'sensor', anomaly_fanout: 'sensor',
  mac_duplicate_location: 'sensor', gateway_duplicate_location: 'sensor',
  honeypot_touch: 'honeypot', honeypot_scan: 'honeypot', honeypot_login: 'honeypot',
  vuln_new: 'vuln_scan', vuln_fixed: 'vuln_scan', vuln_scan_summary: 'vuln_scan',
}

const R1_ALERT_COLUMNS = ['source', 'kind']
// Colonnes de supabase/schema_r4_actions.sql : origine réseau de l'événement (pour « bloquer cette adresse »).
const R4_ALERT_COLUMNS = ['source_ip', 'source_mac']
// L'adresse IP n'identifie le fautif que pour ces événements. Pour une usurpation de passerelle ou ARP,
// l'IP annoncée est celle de la VICTIME imitée : seule la MAC (source_mac) désigne l'appareil à chercher.
export const IP_IDENTIFIES_OFFENDER = new Set(['honeypot_touch', 'honeypot_scan', 'honeypot_login', 'rogue_dhcp', 'new_device',
  // Détection de comportement (behavior.mjs) : l'IP source EST l'appareil fautif.
  'malware_c2', 'lateral_scan', 'port_scan', 'anomaly_fanout'])
const R1_VULN_COLUMNS = ['source', 'finding_key', 'cves', 'evidence', 'remediation', 'confidence', 'port', 'service', 'network_id', 'last_seen']
const R1_SERVICE_COLUMNS = ['version', 'last_seen']

// Colonne ou table absente (R1 pas encore exécuté) : erreurs PostgREST / PostgreSQL correspondantes.
export const isMissingColumn = (err) => Boolean(err) && (err.code === 'PGRST204' || err.code === '42703'
  || /could not find the '.*' column|column .* does not exist/i.test(err.message || ''))
// Nom de la colonne citée par une erreur « colonne absente » (PostgREST ou PostgreSQL), ou null.
export const missingColumnName = (err) => {
  const m = /the '([^']+)' column|column "?([a-z_0-9]+)"? (?:of relation|does not exist)/i.exec((err && err.message) || '')
  return m ? (m[1] || m[2]) : null
}
export const isMissingTable = (err) => Boolean(err) && (err.code === 'PGRST205' || err.code === '42P01'
  || /could not find the table|relation .* does not exist/i.test(err.message || ''))

const strip = (rows, keys) => rows.map((r) => Object.fromEntries(Object.entries(r).filter(([k]) => !keys.includes(k))))
const chunks = (list, size) => Array.from({ length: Math.ceil(list.length / size) }, (_, i) => list.slice(i * size, (i + 1) * size))

// Connexion avec le compte de agent/.env (SUPABASE_URL, SUPABASE_ANON_KEY, CV_EMAIL, CV_PASSWORD).
export async function connectSupabase(env, log = console.log) {
  if (!env.SUPABASE_URL || !env.SUPABASE_ANON_KEY || !env.CV_EMAIL || !env.CV_PASSWORD) {
    log('⚠ Envoi au tableau de bord : variables manquantes (lancez avec --env-file=agent/.env).')
    return null
  }
  const { createClient } = await import('@supabase/supabase-js')
  const client = createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, { auth: { persistSession: false } })
  const { data, error } = await client.auth.signInWithPassword({ email: env.CV_EMAIL, password: env.CV_PASSWORD })
  if (error) { log('⚠ Envoi au tableau de bord : connexion refusée : ' + error.message); return null }
  const uid = data && data.user && data.user.id
  return uid ? scopeToUser(client, uid) : client
}

// Toutes les LECTURES du capteur sont limitées aux données de son propre compte (user_id) : même si d'autres
// comptes partagent leurs données avec ce compte (lecture partagée, R8), le capteur ne les voit ni ne les mélange.
// Écritures inchangées (les politiques « propriétaire » les limitent déjà au compte).
export function scopeToUser(client, uid) {
  return {
    auth: client.auth,
    from(table) {
      const builder = client.from(table)
      return new Proxy(builder, {
        get(target, prop) {
          if (prop === 'select') return (...args) => target.select(...args).eq('user_id', uid)
          const v = target[prop]
          return typeof v === 'function' ? v.bind(target) : v
        },
      })
    },
  }
}

// gatewayMac : MAC de la passerelle du réseau surveillé (valeur ou fonction, car le capteur peut
// ne l'apprendre qu'après le démarrage), pour rattacher les résultats au réseau enregistré par l'agent.
// Réseau introuvable : network_id reste vide, rien n'est créé ni deviné.
export function createPusher(client, { gatewayMac = null, log = console.log, now = () => new Date() } = {}) {
  let r4 = true // passe à false dès que les colonnes source_ip / source_mac manquent
  let r1 = true // passe à false dès qu'une colonne R1 manque : on n'insiste plus
  let network = null

  async function networkId() {
    if (network) return network
    const gwMac = normalizeMac(typeof gatewayMac === 'function' ? gatewayMac() : gatewayMac)
    if (!gwMac) return null
    const { data, error } = await client.from('networks').select('id,gateway_mac')
    if (!error) network = (data || []).find((n) => normalizeMac(n.gateway_mac) === gwMac)?.id ?? null
    return network
  }

  // ip → id d'appareil, de préférence dans le réseau surveillé.
  async function deviceIds() {
    const net = await networkId()
    const { data, error } = await client.from('devices').select('id,ip,network_id')
    const map = new Map()
    if (error) return map
    for (const d of data || []) {
      if (!d.ip) continue
      if (!map.has(d.ip) || (net && d.network_id === net)) map.set(d.ip, d.id)
    }
    return map
  }

  // Insertion tolérante : sans les colonnes R1 si elles n'existent pas encore.
  async function write(rows, r1Columns, op) {
    if (!rows.length) return { error: null }
    let res = await op(r1 ? rows : strip(rows, r1Columns))
    if (res.error && r1 && isMissingColumn(res.error) && !R4_ALERT_COLUMNS.includes(missingColumnName(res.error))) {
      r1 = false
      log('  (colonnes R1 absentes : envoi réduit ; exécutez supabase/schema_r1_results.sql pour le détail)')
      res = await op(strip(rows, r1Columns))
    }
    return res
  }

  async function pushAlerts(events) {
    if (!events.length) return
    const [net, ids] = [await networkId(), await deviceIds()]
    const rows = events.map((e) => ({
      title: String(e.title).slice(0, 300),
      detail: e.detail ? String(e.detail).slice(0, 2000) : null,
      severity: e.severity,
      source: ALERT_SOURCE[e.type] || 'sensor',
      kind: e.type || null,
      network_id: net,
      device_id: (e.ip && ids.get(e.ip)) || null,
      source_ip: e.ip && IP_IDENTIFIES_OFFENDER.has(e.type) ? e.ip : null,
      source_mac: e.mac || null,
    }))
    const op = (r) => client.from('alerts').insert(r)
    let { error } = await write(r4 ? rows : strip(rows, R4_ALERT_COLUMNS), R1_ALERT_COLUMNS, op)
    if (error && r4 && isMissingColumn(error) && R4_ALERT_COLUMNS.includes(missingColumnName(error))) {
      r4 = false
      log('  (colonnes R4 absentes : adresse source non envoyée ; exécutez supabase/schema_r4_actions.sql)')
      ;({ error } = await write(strip(rows, R4_ALERT_COLUMNS), R1_ALERT_COLUMNS, op))
    }
    if (error) log('⚠ Alertes non envoyées : ' + error.message)
  }

  // Synchronise les faiblesses d'une analyse : nouvelles insérées, connues mises à jour (sans toucher
  // au statut choisi par l'utilisateur), disparues → « Résolue », réapparues → rouvertes.
  async function syncVulnerabilities({ findings, fixed = [] }) {
    const [net, ids] = [await networkId(), await deviceIds()]
    const stamp = now().toISOString()
    const rows = findings.map((f) => ({
      title: `${f.title} — ${f.ip}:${f.port}`.slice(0, 300),
      severity: f.severity,
      device_id: ids.get(f.ip) ?? null,
      source: 'scan',
      finding_key: f.key,
      cves: f.cves && f.cves.length ? f.cves : null,
      evidence: f.evidence || null,
      remediation: f.remediation || null,
      confidence: f.confidence || null,
      port: f.port || null,
      service: f.service || null,
      network_id: net,
      last_seen: stamp,
    }))

    if (r1) {
      const res = rows.length
        ? await client.from('vulnerabilities').upsert(rows, { onConflict: 'user_id,finding_key' })
        : { error: null }
      if (res.error && isMissingColumn(res.error)) {
        r1 = false
        log('  (colonnes R1 absentes : envoi réduit ; exécutez supabase/schema_r1_results.sql pour le détail)')
      } else if (res.error) {
        log('⚠ Vulnérabilités non envoyées : ' + res.error.message)
        return
      } else {
        // Toujours présente alors qu'elle était marquée « Résolue » : on la rouvre.
        for (const part of chunks(findings.map((f) => f.key), 100)) {
          await client.from('vulnerabilities').update({ status: 'open', resolved_at: null })
            .in('finding_key', part).eq('status', 'resolved')
        }
        const gone = fixed.map((f) => f.key)
        for (const part of chunks(gone, 100)) {
          await client.from('vulnerabilities').update({ status: 'resolved', resolved_at: stamp })
            .in('finding_key', part).neq('status', 'resolved')
        }
        log(`  ${rows.length} vulnérabilité(s) synchronisée(s), ${gone.length} marquée(s) corrigée(s).`)
        return
      }
    }

    // Sans R1 : comportement d'origine — insertion des seules faiblesses absentes (titre + appareil).
    const existing = await client.from('vulnerabilities').select('title,device_id')
    if (existing.error) { log('⚠ Vulnérabilités non envoyées : ' + existing.error.message); return }
    const seen = new Set((existing.data || []).map((v) => `${v.title}|${v.device_id ?? ''}`))
    const fresh = strip(rows, R1_VULN_COLUMNS).filter((r) => {
      const key = `${r.title}|${r.device_id ?? ''}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
    if (!fresh.length) return
    const { error } = await client.from('vulnerabilities').insert(fresh)
    if (error) log('⚠ Vulnérabilités non envoyées : ' + error.message)
    else log(`  ${fresh.length} vulnérabilité(s) envoyée(s).`)
  }

  // Services observés (port + version annoncée) des appareils connus du tableau de bord.
  async function syncServices(hosts) {
    const ids = await deviceIds()
    const stamp = now().toISOString()
    const rows = []
    for (const h of hosts || []) {
      const deviceId = ids.get(h.ip)
      if (!deviceId) continue // appareil pas encore inventorié : rien d'inventé
      for (const s of h.services || []) {
        rows.push({ device_id: deviceId, port: s.port, protocol: 'tcp', service: s.service, version: s.detail || null, last_seen: stamp })
      }
    }
    const { error } = await write(rows, R1_SERVICE_COLUMNS,
      (r) => client.from('services').upsert(r, { onConflict: 'device_id,port,protocol' }))
    if (error) log('⚠ Services non envoyés : ' + error.message)
  }

  // Atteignabilité VLAN-à-VLAN (table vlan_reachability de R9, voir sensor/lib/reachability.mjs).
  // Remplace, pour ce réseau, l'état complet de la matrice calculée à cette interrogation (comme les
  // liens de topologie) : une paire disparue du calcul (VLAN retiré) ne reste jamais affichée comme
  // à jour. Table absente (R9 pas encore exécuté) : message unique, pas d'erreur.
  let reachabilityMissing = false
  async function syncReachability(reachability) {
    if (reachabilityMissing || !reachability || !reachability.matrix.length) return
    const net = await networkId()
    if (!net) return // réseau introuvable : rien n'est créé ni deviné
    const vlanOf = new Map(reachability.zones.map((z) => [z.name, z.vlan]))
    const stamp = now().toISOString()
    const rows = reachability.matrix.map((m) => ({
      network_id: net,
      from_zone: m.from,
      to_zone: m.to,
      from_vlan: vlanOf.get(m.from) ?? null,
      to_vlan: vlanOf.get(m.to) ?? null,
      status: m.allowed === true ? 'allowed' : m.allowed === false ? 'blocked' : 'uncertain',
      reason: m.reason || null,
      evidence: m.evidence && m.evidence.length ? m.evidence : null,
      source: 'fortigate',
      computed_at: stamp,
    }))
    const del = await client.from('vlan_reachability').delete().eq('network_id', net).eq('source', 'fortigate')
    if (del.error) {
      if (isMissingTable(del.error)) {
        reachabilityMissing = true
        log('  (table vlan_reachability absente : atteignabilité non enregistrée ; exécutez supabase/schema_r9_reachability.sql)')
      } else {
        log('⚠ Atteignabilité non enregistrée : ' + del.error.message)
      }
      return
    }
    for (let i = 0; i < rows.length; i += 200) {
      const r = await client.from('vlan_reachability').insert(rows.slice(i, i + 200))
      if (r.error) { log('⚠ Atteignabilité non enregistrée : ' + r.error.message); return }
    }
  }

  // Pouls du capteur (table sensors de R1). Sans R1 : ignoré silencieusement après un message.
  let sensorsMissing = false
  async function heartbeat(info) {
    if (sensorsMissing) return
    const row = {
      name: info.name, version: info.version || null, ip: info.ip || null,
      honeypot: Boolean(info.honeypot), vuln_scan: Boolean(info.vulnScan),
      started_at: info.startedAt || null, last_heartbeat: now().toISOString(),
      network_id: await networkId(),
    }
    if (info.lastScanAt) row.last_scan_at = info.lastScanAt
    const { error } = await client.from('sensors').upsert([row], { onConflict: 'user_id,name' })
    if (error && (isMissingTable(error) || isMissingColumn(error))) {
      sensorsMissing = true
      log('  (table sensors absente : état du capteur non publié ; exécutez supabase/schema_r1_results.sql)')
    } else if (error) {
      log('⚠ État du capteur non envoyé : ' + error.message)
    }
  }

  return { pushAlerts, syncVulnerabilities, syncServices, syncReachability, heartbeat, client, get r1() { return r1 } }
}
