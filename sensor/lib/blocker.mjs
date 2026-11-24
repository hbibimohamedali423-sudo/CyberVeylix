// CyberVeylix Sensor — blocage d'une adresse IP par le pare-feu Windows du PC qui héberge le capteur.
// - Règles « bloquer » entrantes ET sortantes pour l'adresse, nommées CyberVeylix-Block-<ip> (retirées par le débloquage).
// - Protège CE PC seulement : ce n'est pas un blocage au niveau du réseau ni du routeur.
// - Commandes lancées SANS shell (execFile) avec une adresse validée strictement : aucune injection possible.
// - Refuse les adresses qui couperaient le réseau ou le capteur lui-même (voir protectedReason).
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const run = promisify(execFile)

export const IPV4_RE = /^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$/
export const RULE_PREFIX = 'CyberVeylix-Block-'

export const isValidIpv4 = (ip) => typeof ip === 'string' && IPV4_RE.test(ip)
// 0.x, 127.x et 224.x–255.x (multicast, diffusion, réservé) : jamais bloquables (même règle que la base de données).
export const isReservedIpv4 = (ip) => /^(0\.|127\.|22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.)/.test(ip)
export const ruleName = (ip) => `${RULE_PREFIX}${ip}`

// Raison pour laquelle une adresse ne doit PAS être bloquée, ou null si elle peut l'être.
// ctx : { gatewayIp, sensorIp, trusted: [ip], dhcp: [ip], serviceIps: [ip] } (tout est facultatif).
export function protectedReason(ip, ctx = {}) {
  if (!isValidIpv4(ip) || isReservedIpv4(ip)) return 'invalid_ip'
  if (ctx.gatewayIp && ip === ctx.gatewayIp) return 'gateway'        // couper le routeur = couper tout le réseau
  if (ctx.sensorIp && ip === ctx.sensorIp) return 'self'              // ne jamais se bloquer soi-même
  if ((ctx.trusted || []).includes(ip)) return 'trusted'              // liste « ne jamais bloquer » du client
  if ((ctx.dhcp || []).includes(ip)) return 'dhcp'                    // serveur DHCP de confiance
  if ((ctx.serviceIps || []).includes(ip)) return 'dns_service'       // adresses du tableau de bord (Supabase)
  return null
}

const defaultExec = async (file, args) => {
  const { stdout } = await run(file, args, { timeout: 15000, windowsHide: true })
  return String(stdout || '')
}

export function createBlocker({ platform = process.platform, exec = defaultExec } = {}) {
  const netsh = (args) => exec('netsh', ['advfirewall', 'firewall', ...args])
  const supported = platform === 'win32'

  async function exists(ip) {
    try { await netsh(['show', 'rule', `name=${ruleName(ip)}`]); return true } catch { return false }
  }

  async function block(ip) {
    if (!supported) return { ok: false, code: 'unsupported_os' }
    if (!isValidIpv4(ip) || isReservedIpv4(ip)) return { ok: false, code: 'invalid_ip' }
    if (await exists(ip)) return { ok: true, already: true }
    const name = ruleName(ip)
    try {
      for (const dir of ['in', 'out']) {
        await netsh(['add', 'rule', `name=${name}`, `dir=${dir}`, 'action=block', `remoteip=${ip}`, 'enable=yes', 'profile=any'])
      }
    } catch (e) {
      await netsh(['delete', 'rule', `name=${name}`]).catch(() => {}) // pas de règle à moitié posée
      return { ok: false, code: 'firewall_error', message: String(e && e.message || e).slice(0, 300) }
    }
    return (await exists(ip)) ? { ok: true } : { ok: false, code: 'firewall_error', message: 'règle introuvable après création' }
  }

  async function unblock(ip) {
    if (!supported) return { ok: false, code: 'unsupported_os' }
    if (!isValidIpv4(ip)) return { ok: false, code: 'invalid_ip' }
    // Code de sortie ≠ 0 quand aucune règle ne correspond : ce n'est pas une erreur, on vérifie l'état final.
    await netsh(['delete', 'rule', `name=${ruleName(ip)}`]).catch(() => {})
    return (await exists(ip)) ? { ok: false, code: 'firewall_error', message: 'règle toujours présente' } : { ok: true }
  }

  return { block, unblock, exists, supported }
}
