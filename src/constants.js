// Codes de navigation : les libellés sont traduits à l’affichage (i18n).
export const NAV = ['home', 'devices', 'scan', 'vulns', 'threats', 'soc', 'reports', 'map', 'team', 'settings']
export const KPIS = [
  { key: 'devices', cls: '' },
  { key: 'threats', cls: 'r' },
  { key: 'vulns', cls: 'r' },
  { key: 'services', cls: '' },
]
// Couleurs pilotées par le thème (valeurs sombres et claires définies dans index.css).
export const TYPES = { 'Serveur': 'var(--type-server)', 'Poste': 'var(--type-workstation)', 'Caméra': 'var(--type-camera)', 'Équipement réseau': 'var(--type-network)', 'Accès Internet': 'var(--type-internet)' }
// Ports jugés sensibles par l’agent de découverte (même liste que agent/scan.mjs, SENSITIVE).
export const SENSITIVE_PORTS = [21, 23, 3389, 5900, 1433, 3306, 5432]
export const STATUS = [
  { k: 'on', label: 'En ligne', color: 'var(--status-on)' },
  { k: 'off', label: 'Hors ligne', color: 'var(--status-off)' },
  { k: 'un', label: 'Inconnu', color: 'var(--status-un)' },
]
export const SEV = [
  { k: 'c', label: 'Critique', color: 'var(--sev-c)' },
  { k: 'h', label: 'Haute', color: 'var(--sev-h)' },
  { k: 'm', label: 'Moyenne', color: 'var(--sev-m)' },
  { k: 'l', label: 'Basse', color: 'var(--sev-l)' },
]
export const ALERT_STATUS = [
  { k: 'open', label: 'Ouverte', color: 'var(--alert-open)' },
  { k: 'ack', label: 'Prise en compte', color: 'var(--alert-ack)' },
  { k: 'resolved', label: 'Résolue', color: 'var(--alert-resolved)' },
]
export const REPORTS_KINDS = [
  { k: 'devices', label: 'Appareils' },
  { k: 'alerts', label: 'Alertes' },
  { k: 'vulnerabilities', label: 'Vulnérabilités' },
  { k: 'threats', label: 'Menaces' },
]
export const SLOTS = [[300,150],[380,190],[230,200],[340,240],[420,130],[190,250],[300,290],[450,200],[260,130],[390,260],[340,100],[480,250]]
export const CATS = [
  { k: 'intrusion', label: 'Tentatives d’intrusion', color: 'var(--cat-intrusion)' },
  { k: 'malware', label: 'Malware / Ransomware', color: 'var(--cat-malware)' },
  { k: 'scan', label: 'Scan de ports', color: 'var(--cat-scan)' },
  { k: 'c2', label: 'C2 / Command & Control', color: 'var(--cat-c2)' },
  { k: 'autre', label: 'Autres', color: 'var(--cat-other)' },
]
