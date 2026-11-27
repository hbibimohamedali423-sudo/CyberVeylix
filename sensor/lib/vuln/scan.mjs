// CyberVeylix — orchestration d'une analyse de vulnérabilités.
// Réseaux privés uniquement, charge limitée (peu d'hôtes et de ports en parallèle, délais courts).
import { probeOpen, PORT_SERVICES, SERVICE_PROBES } from './probes.mjs'
import { evaluate, bySeverity } from './rules.mjs'

export const VULN_PORTS = [21, 22, 23, 80, 443, 445, 993, 995, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200]
const MAX_TARGETS = 1024

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
export function isPrivateIpv4(ip) {
  const m = IPV4.exec(String(ip))
  if (!m || m.slice(1).some((o) => Number(o) > 255)) return false
  const [a, b] = [Number(m[1]), Number(m[2])]
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
}

const toInt = (ip) => ip.split('.').reduce((n, o) => n * 256 + Number(o), 0)
const toIp = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.')

// « 192.168.1.0/24,192.168.2.7 » → liste d'IP (privées uniquement, /22 au plus large).
export function expandTargets(spec, { allowLoopback = false } = {}) {
  const out = new Set()
  for (const part of String(spec || '').split(',').map((s) => s.trim()).filter(Boolean)) {
    const cidr = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(part)
    if (cidr) {
      const bits = Number(cidr[2])
      if (bits < 22 || bits > 32) return { error: `Préfixe refusé pour ${part} : /22 à /32 (1 024 adresses au plus).` }
      const size = 2 ** (32 - bits)
      const base = Math.floor(toInt(cidr[1]) / size) * size
      const first = size > 2 ? base + 1 : base
      const last = size > 2 ? base + size - 2 : base + size - 1
      for (let n = first; n <= last; n++) out.add(toIp(n))
    } else if (IPV4.test(part)) {
      out.add(part)
    } else {
      return { error: `Cible invalide : ${part}` }
    }
  }
  const list = [...out]
  const bad = list.find((ip) => !(isPrivateIpv4(ip) || (allowLoopback && ip.startsWith('127.'))))
  if (bad) return { error: `Refusé : ${bad} n'est pas une adresse privée (10/8, 172.16/12, 192.168/16).` }
  if (list.length > MAX_TARGETS) return { error: `Trop de cibles (${list.length}, maximum ${MAX_TARGETS}).` }
  return { targets: list }
}

async function pool(items, n, fn) {
  const out = new Array(items.length)
  let i = 0
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k]) }
  }))
  return out
}

// ports : [21, 22, …] ou [{ port, service }] (service imposé, ex. tests sur ports éphémères).
export async function scanHost(ip, { ports = VULN_PORTS, portConcurrency = 6, now = Date.now() } = {}) {
  const specs = ports.map((p) => (typeof p === 'number' ? { port: p, service: PORT_SERVICES[p] || 'tcp' } : p))
  let alive = false
  const observations = (await pool(specs, portConcurrency, async ({ port, service }) => {
    const { open, refused } = await probeOpen(ip, port)
    if (open || refused) alive = true
    if (!open) return null
    let details = {}
    const probe = SERVICE_PROBES[service]
    if (probe) {
      try { details = await probe(ip, port, now) } catch { details = {} }
    }
    return { ip, port, service, open: true, ...details }
  })).filter(Boolean)
  const findings = observations.flatMap(evaluate)
  return { ip, alive, observations, findings }
}

// Analyse plusieurs hôtes. Renvoie le rapport complet (trié par gravité).
export async function scanTargets(targets, { ports, concurrency = 4, portConcurrency = 6, onHost } = {}) {
  const startedAt = new Date().toISOString()
  const hosts = await pool(targets, concurrency, async (ip) => {
    const h = await scanHost(ip, { ports, portConcurrency })
    if (onHost) onHost(h)
    return h
  })
  return {
    startedAt,
    finishedAt: new Date().toISOString(),
    targets: targets.length,
    scannedIps: hosts.filter((h) => h.alive).map((h) => h.ip),
    hosts: hosts.filter((h) => h.alive).map(({ ip, observations }) => ({
      ip, services: observations.map((o) => ({ port: o.port, service: o.service, detail: describe(o) })),
    })),
    findings: hosts.flatMap((h) => h.findings).sort(bySeverity),
  }
}

// Résumé lisible d'un service observé (inventaire du rapport).
function describe(o) {
  if (o.ssh) return o.ssh.software
  if (o.ftp) return [o.ftp.product, o.ftp.version].filter(Boolean).join(' ') || 'FTP'
  if (o.http && o.http.server) return o.http.server
  if (o.mysql && o.mysql.version) return `MySQL ${o.mysql.version}`
  if (o.vnc) return `RFB ${o.vnc.version}`
  if (o.docker) return `Docker ${o.docker.version}`
  return ''
}
