// CyberVeylix Sensor — analyse d'atteignabilité entre VLAN (pure, testable sans réseau).
//
// Répond à UNE question, étroite et vérifiable : « la politique du pare-feu autorise-t-elle le
// VLAN A à joindre le VLAN B ? », avec la ou les règles exactes comme preuve. Elle ne simule PAS
// un chemin appareil-à-appareil arbitraire (routage, NAT, ACL de switch ne sont pas lus) : c'est
// volontaire, pour que chaque conclusion reste traçable à une donnée réellement lue, jamais à une
// supposition. Quand une règle référence une adresse non résolvable (FQDN, type inconnu…), la
// conclusion reste « incertaine », jamais déclarée sûre ou bloquée au hasard.
//
// L'ORDRE des règles compte : FortiGate évalue ses règles dans l'ordre et s'arrête à la première
// qui correspond (« first match wins »). On suppose ici que l'ordre renvoyé par l'API est celui de
// l'évaluation réelle (c'est le cas par défaut de cmdb/firewall/policy). Une règle antérieure, non
// résolue, qui pourrait concerner la même paire, fait basculer la conclusion vers « incertaine »
// plutôt que de risquer d'affirmer un accès qu'une règle plus haute bloquerait peut-être déjà.
//
// Limite assumée : la correspondance se fait sur le RECOUVREMENT avec le sous-réseau entier de
// chaque VLAN, pas sur une portion exacte. Une règle qui ne vise qu'UN SEUL appareil d'un VLAN
// peut donc faire conclure « bloqué » ou « autorisé » pour tout le VLAN, alors que seul cet
// appareil est concerné. C'est une matrice VLAN-à-VLAN, pas appareil-à-appareil.
//
// Entrées : les sorties déjà analysées de fortigate-parse.mjs — parseInterfaces (zones),
// parsePolicies (règles, DANS L'ORDRE renvoyé par l'API), parseAddressObjects + parseAddressGroups.

const ALL_NAMES = new Set(['all', 'any']) // objets intégrés de FortiOS : tout l'espace IPv4.
const FULL_RANGE = { lo: 0, hi: 0xffffffff }

const rangesOverlap = (a, b) => a.lo <= b.hi && b.lo <= a.hi

// Résout un nom d'adresse (objet direct, groupe, ou « all »/« any ») en plages IPv4, récursivement.
// `seen` protège contre les boucles de groupes ; une profondeur maximale protège dans tous les cas.
export function resolveAddressNames(nameList, { addresses = [], groups = [] } = {}, seen = new Set(), depth = 0) {
  const byName = new Map(addresses.map((a) => [a.name, a]))
  const groupByName = new Map(groups.map((g) => [g.name, g]))
  const ranges = []
  const unresolved = []

  for (const rawName of nameList || []) {
    const name = String(rawName)
    if (ALL_NAMES.has(name.toLowerCase())) { ranges.push(FULL_RANGE); continue }
    if (seen.has(name)) { unresolved.push({ name, reason: 'boucle de groupes détectée' }); continue }
    if (depth >= 8) { unresolved.push({ name, reason: 'groupes imbriqués trop profondément (plus de 8 niveaux)' }); continue }

    const addr = byName.get(name)
    if (addr) {
      if (addr.resolved) ranges.push({ lo: addr.lo, hi: addr.hi })
      else unresolved.push({ name, reason: addr.reason || 'adresse non résolvable' })
      continue
    }
    const grp = groupByName.get(name)
    if (grp) {
      const sub = resolveAddressNames(grp.members, { addresses, groups }, new Set(seen).add(name), depth + 1)
      ranges.push(...sub.ranges)
      unresolved.push(...sub.unresolved)
      continue
    }
    unresolved.push({ name, reason: 'adresse inconnue (absente des objets et groupes lus)' })
  }
  return { ranges, unresolved }
}

// Reconstruit lo/hi à partir d'un cidr déjà validé (évite une dépendance circulaire avec
// fortigate-parse.mjs, qui dépend déjà de threatlist.mjs) ; renvoie null si invalide.
function cidrRange(cidr) {
  const [addr, bitsText] = String(cidr).split('/')
  const bits = Number(bitsText)
  const parts = addr.split('.').map(Number)
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255) || !Number.isInteger(bits) || bits < 0 || bits > 32) return null
  const base = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
  if (bits === 0) return { lo: 0, hi: 0xffffffff }
  const mask = (0xffffffff << (32 - bits)) >>> 0
  const lo = (base & mask) >>> 0
  return { lo, hi: (lo + (~mask >>> 0)) >>> 0 }
}

// Une zone = une interface avec un sous-réseau IPv4 connu (VLAN ou non, ex. l'interface WAN).
// Une interface sans adresse IPv4 ne peut pas être une zone : on ne peut rien affirmer sans donnée.
export function zonesFromInterfaces(interfaces = []) {
  return interfaces
    .map((i) => ({ name: i.name, vlan: i.vlan, cidr: i.cidr, range: i.cidr ? cidrRange(i.cidr) : null }))
    .filter((z) => z.range)
}

const touchesInterface = (policy, ifaceName, field) =>
  (policy[field] || []).some((n) => String(n).toLowerCase() === 'any' || n === ifaceName)

// Évalue une paire ordonnée (a → b) en parcourant les règles DANS L'ORDRE, comme le ferait
// FortiGate : s'arrête à la première qui correspond avec certitude. Voir l'en-tête du fichier
// pour la logique d'incertitude (une règle antérieure non résolue dégrade la conclusion).
function evaluatePair(a, b, policies, addresses, addressGroups) {
  const pending = []
  for (const p of policies) {
    if (!p.enabled) continue
    if (!touchesInterface(p, a.name, 'srcintf') || !touchesInterface(p, b.name, 'dstintf')) continue

    const src = resolveAddressNames(p.srcaddr, { addresses, groups: addressGroups })
    const dst = resolveAddressNames(p.dstaddr, { addresses, groups: addressGroups })
    const srcMatches = src.ranges.some((r) => rangesOverlap(r, a.range))
    const dstMatches = dst.ranges.some((r) => rangesOverlap(r, b.range))

    if (srcMatches && dstMatches) {
      const evidence = { id: p.id, name: p.name }
      if (pending.length) {
        return { allowed: null, evidence: [...pending, evidence], reason: 'une règle antérieure non résolue pourrait s’appliquer en premier (ordre des règles)' }
      }
      return p.action === 'accept'
        ? { allowed: true, evidence: [evidence], reason: null }
        : { allowed: false, evidence: [evidence], reason: 'bloqué explicitement par cette règle' }
    }

    const possiblyRelevant = (!srcMatches && !dstMatches && (src.unresolved.length || dst.unresolved.length))
      || (srcMatches && dst.unresolved.length > 0) || (dstMatches && src.unresolved.length > 0)
    if (possiblyRelevant) {
      pending.push({ id: p.id, name: p.name, reason: [...src.unresolved, ...dst.unresolved].map((u) => u.reason).join('; ') })
    }
  }
  if (pending.length) return { allowed: null, evidence: pending, reason: 'une ou plusieurs règles non résolues pourraient s’appliquer' }
  return { allowed: false, evidence: [], reason: 'aucune règle active ne correspond (refus par défaut)' }
}

// Construit la matrice VLAN→VLAN pour toutes les paires ordonnées de zones distinctes.
//   allowed: true  -> la première règle (dans l'ordre) qui correspond avec certitude autorise.
//   allowed: false -> soit la première règle qui correspond bloque explicitement, soit aucune
//                     règle ne correspond (refus par défaut de FortiGate).
//   allowed: null  -> une règle potentiellement antérieure référence une adresse non résolvable :
//                     on ne peut pas savoir avec certitude ce qu'elle déciderait.
export function buildVlanReachability({ interfaces = [], policies = [], addresses = [], addressGroups = [] } = {}) {
  const zones = zonesFromInterfaces(interfaces)
  const matrix = []
  for (const a of zones) {
    for (const b of zones) {
      if (a.name === b.name) continue
      const r = evaluatePair(a, b, policies, addresses, addressGroups)
      matrix.push({ from: a.name, to: b.name, ...r })
    }
  }
  return { zones, matrix }
}
