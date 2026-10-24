export const NAV = ['Accueil', 'Réseau & Appareils', 'Analyse & Scan', 'Vulnérabilités', 'Menaces & Incidents', 'Surveillance (SOC)', 'Rapports', 'Cartographie', 'Équipe', 'Paramètres']
export const KPIS = [
  { label: 'Appareils détectés', cls: '' },
  { label: 'Menaces bloquées', cls: 'r' },
  { label: 'Vulnérabilités', cls: 'r' },
  { label: 'Services exposés', cls: '' },
]
export const TYPES = { 'Serveur': '#e0a040', 'Poste': '#17a6f5', 'Caméra': '#e0a040', 'Équipement réseau': '#17c8f5', 'Accès Internet': '#6a8cff' }
export const STATUS = [
  { k: 'on', label: 'En ligne', color: '#1ed98a' },
  { k: 'off', label: 'Hors ligne', color: '#ff3b4e' },
  { k: 'un', label: 'Inconnu', color: '#8fa6c0' },
]
export const SEV = [
  { k: 'c', label: 'Critique', color: '#ff3b4e' },
  { k: 'h', label: 'Haute', color: '#ff9a2e' },
  { k: 'm', label: 'Moyenne', color: '#f5c542' },
  { k: 'l', label: 'Basse', color: '#8fa6c0' },
]
export const SLOTS = [[300,150],[380,190],[230,200],[340,240],[420,130],[190,250],[300,290],[450,200],[260,130],[390,260],[340,100],[480,250]]
