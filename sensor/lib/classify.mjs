// CyberVeylix Sensor — identification du type d'un appareil (pur, testable).
// Combine des indices OBSERVÉS : fabricant (registre IEEE), demande DHCP (nom, système annoncé), ports ouverts,
// MAC aléatoire, rôle connu (passerelle, PC du capteur). Renvoie le rôle, le type affiché, la confiance et la preuve.
// Sans indice suffisant : rien n'est inventé (role null).

export const ROLE_TYPES = {
  gateway: 'Accès Internet', switch: 'Équipement réseau', access_point: 'Équipement réseau', server: 'Serveur',
  workstation: 'Poste', camera: 'Caméra', printer: 'Imprimante', phone: 'Téléphone', iot: 'Objet connecté', other: null,
}

// Fabricants par famille (noms courts du registre IEEE). « strong » : le fabricant suffit à une identification probable.
const VENDORS = [
  { role: 'camera', strong: true, re: /hikvision|dahua|axis communications|uniview|reolink|hanwha|samsung techwin|vivotek|ezviz|tiandy|imou|amcrest|foscam|provision-isr|milesight|geovision|mobotix|bosch security/i },
  { role: 'printer', strong: true, re: /seiko epson|epson|canon|brother|lexmark|ricoh|kyocera|xerox|konica minolta|sharp corporation|oki electric|oki data|zebra technologies|pantum|toshiba tec/i },
  { role: 'network', strong: false, re: /cisco|meraki|aruba|juniper|tp-link|d-link|ubiquiti|mikrotik|routerboard|fortinet|ruckus|zyxel|netgear|cambium|extreme networks|sophos|ruijie|tenda|mercusys|edimax|allied telesis|hpe|hewlett packard enterprise|grandstream networks|teltonika|draytek|sagemcom|zte/i },
  { role: 'phone', strong: false, re: /xiaomi|oppo|vivo mobile|oneplus|realme|motorola mobility|huawei device|honor device|transsion|tecno|infinix|itel|nothing technology|fairphone|hmd global|sony mobile|lg electronics \(mobile/i },
  { role: 'workstation', strong: false, re: /dell|lenovo|asustek|acer|micro-star|gigabyte|intel corporate|liteon|lite-on|azurewave|hon hai|foxconn|quanta|compal|wistron|chicony|microsoft|framework computer|clevo/i },
  { role: 'server', strong: true, re: /vmware|parallels|xensource|nutanix|supermicro|super micro/i },
  { role: 'iot', strong: false, re: /espressif|tuya|shelly|allterco|itead|raspberry pi|amazon technologies|sonos|roku|signify|philips lighting|google|nest labs|ring llc|ecobee|lifx|wiz connected|broadlink|hisense|tcl|vizio|chromecast/i },
]
const AMBIGUOUS = [
  { re: /^apple/i, roles: ['phone', 'workstation'] }, // iPhone / iPad / Mac
  { re: /samsung electronics/i, roles: ['phone', 'iot'] }, // téléphone, TV, électroménager
  { re: /huawei technologies/i, roles: ['network', 'phone'] },
  { re: /hewlett packard|hp inc/i, roles: ['printer', 'workstation'] },
]

const HOSTNAME = [
  { role: 'phone', re: /iphone|ipad|android|galaxy|redmi|xiaomi|poco|oppo|vivo|huawei|honor|pixel|oneplus|realme|tecno|infinix|nokia|moto[ ._-]?[a-z0-9]|sm-[a-z]\d/i },
  { role: 'workstation', re: /^(desktop|laptop|pc|poste|portable|macbook|imac|mac-?mini|thinkpad|latitude|elitebook|vivobook|ideapad)([._ -]|$)|macbook|imac/i },
  { role: 'server', re: /^(srv|server|serveur|dc\d*|ad\d*|nas|esxi|proxmox|pve|vm-)|[-_](srv|server|nas)\d*$/i },
  { role: 'printer', re: /printer|imprimante|epson|canon|brother|^hp[a-f0-9]{6}|^npi[a-f0-9]{6}|laserjet|officejet|deskjet|lexmark|ricoh|kyocera|xerox|mfp/i },
  { role: 'camera', re: /^(cam|ipc|nvr|dvr)|camera|cam[-_]?\d|hikvision|dahua|reolink|ezviz/i },
  { role: 'access_point', re: /^(ap|wap)[-_]|access.?point|unifi|^eap\d|aruba-?ap|^iap-|omada/i },
  { role: 'switch', re: /^(sw|switch)[-_ ]?\d|switch/i },
  { role: 'iot', re: /esp[-_]?[0-9a-f]{4,}|tasmota|shelly|tuya|smart[-_ ]?(plug|tv)|chromecast|firetv|roku|sonos|echo[-_]|google-home|nest/i },
]

const VENDOR_CLASS = [
  { role: 'phone', re: /^android-dhcp/i, label: 'Android' },
  { role: 'workstation', re: /^MSFT 5\.0/i, label: 'Windows' },
  { role: 'iot', re: /^udhcp/i, label: 'système embarqué (udhcp)' },
  { role: 'workstation', re: /^dhcpcd/i, label: 'Linux (dhcpcd)' },
]

const PORTS = [
  { role: 'printer', any: [9100, 515, 631], label: 'impression' },
  { role: 'camera', any: [554, 8554, 37777, 34567], label: 'vidéo (RTSP / caméra)' },
  { role: 'workstation', any: [3389, 5900], label: 'bureau à distance' },
  { role: 'server', any: [1433, 3306, 5432, 389, 636, 88, 53], label: 'service serveur' },
]

const order = ['gateway', 'camera', 'printer', 'server', 'access_point', 'switch', 'workstation', 'phone', 'iot', 'network', 'other']

// h : { vendor, randomMac, hostname, vendorClass, ports: [n], isGateway, isSelf }
export function classify(h = {}) {
  if (h.isGateway) return result('gateway', 'certaine', ['passerelle du réseau (route par défaut)'], h)
  if (h.isSelf) return result('workstation', 'certaine', ['ordinateur qui héberge le capteur'], h)

  const score = new Map()
  const evidence = new Map()
  const add = (role, pts, why) => {
    score.set(role, (score.get(role) || 0) + pts)
    if (!evidence.has(role)) evidence.set(role, [])
    evidence.get(role).push(why)
  }

  const vendor = h.vendor || ''
  if (vendor) {
    const fam = VENDORS.find((f) => f.re.test(vendor))
    if (fam) add(fam.role, fam.strong ? 3 : 2, `fabricant ${vendor}`)
    const amb = AMBIGUOUS.find((a) => a.re.test(vendor))
    if (amb) for (const r of amb.roles) add(r, 1, `fabricant ${vendor}`)
  }
  if (h.hostname) {
    for (const rule of HOSTNAME) if (rule.re.test(h.hostname)) { add(rule.role, 3, `nom annoncé « ${h.hostname} »`); break }
  }
  if (h.vendorClass) {
    const vc = VENDOR_CLASS.find((v) => v.re.test(h.vendorClass))
    if (vc) add(vc.role, 3, `système annoncé ${vc.label} (DHCP)`)
  }
  const ports = new Set(h.ports || [])
  for (const p of PORTS) {
    const hit = p.any.filter((n) => ports.has(n))
    if (hit.length) add(p.role, 3, `port ${hit.join(', ')} ouvert (${p.label})`)
  }
  if (h.randomMac) add('phone', 1, 'adresse MAC aléatoire (téléphone ou portable récent)')

  if (!score.size) return { role: null, type: null, confidence: null, evidence: null }
  // Rôle au meilleur score ; à égalité, ordre de spécificité ci-dessus.
  const best = [...score.entries()].sort((a, b) => b[1] - a[1] || order.indexOf(a[0]) - order.indexOf(b[0]))[0]
  const [role, pts] = best
  // Un indice net (fabricant spécialisé, nom, système annoncé, port) = probable ; indices faibles seuls = à vérifier.
  const confidence = pts >= 3 ? 'probable' : 'à vérifier'
  const ev = evidence.get(role)
  if (role === 'network') ev.push('équipement réseau (routeur, switch ou point Wi-Fi : précisé par la lecture des switchs)')
  return result(role === 'network' ? 'other' : role, confidence, ev, h, role === 'network')
}

function result(role, confidence, evidence, h, networkGear = false) {
  return {
    role,
    type: networkGear ? 'Équipement réseau' : (ROLE_TYPES[role] ?? null),
    confidence,
    evidence: [...new Set(evidence)].join(' ; ').slice(0, 500),
  }
}
