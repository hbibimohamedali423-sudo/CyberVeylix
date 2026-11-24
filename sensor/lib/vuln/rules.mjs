// CyberVeylix — règles de vulnérabilités (pur, testable).
// Base volontairement courte et vérifiée : chaque règle repose sur une observation réelle
// (version annoncée ou comportement du protocole) et indique sa confiance :
//   'certaine' : le comportement observé EST la faiblesse (ex. VNC sans mot de passe) ;
//   'probable' : la version annoncée est connue comme vulnérable ;
//   'à vérifier' : version vulnérable en amont, mais la distribution corrige souvent sans changer le numéro.
// L'absence de résultat ne prouve PAS l'absence de vulnérabilité.
import { compareVersions } from './parsers.mjs'

const DISTRO_PATCHES = /ubuntu|debian|deb\d|el\d|centos|rhel|fedora|suse|freebsd|raspbian/i
const cmp = compareVersions
const inRange = (v, from, to) => cmp(v, from) >= 0 && cmp(v, to) < 0

function finding(obs, rule, extra) {
  return {
    key: `${obs.ip}:${obs.port}:${rule}`,
    rule,
    ip: obs.ip,
    port: obs.port,
    service: obs.service,
    cves: [],
    ...extra,
  }
}

const RULES = [
  // --- SSH -------------------------------------------------------------------------------
  (o) => {
    const s = o.ssh
    if (!s || s.product !== 'OpenSSH' || !s.version) return null
    if (!(inRange(s.version, '8.5p1', '9.8p1') || cmp(s.version, '4.4p1') < 0)) return null
    const backport = DISTRO_PATCHES.test(s.comment)
    return finding(o, 'ssh-regresshion', {
      severity: 'h', cves: ['CVE-2024-6387'], confidence: backport ? 'à vérifier' : 'probable',
      title: `OpenSSH ${s.version} vulnérable à « regreSSHion » (CVE-2024-6387)`,
      evidence: `Bannière : ${s.software}${s.comment ? ' ' + s.comment : ''}`,
      remediation: 'Mettre à jour OpenSSH en 9.8p1 ou plus récent (ou installer le paquet corrigé de la distribution). '
        + 'En attendant : restreindre l\'accès SSH aux seuls postes d\'administration.'
        + (backport ? ' Cette distribution corrige souvent sans changer le numéro de version : vérifiez que les mises à jour de sécurité sont installées.' : ''),
    })
  },
  (o) => {
    const s = o.ssh
    if (!s || !/^1\./.test(s.protocol) || s.protocol === '1.99') return null
    return finding(o, 'ssh-v1', {
      severity: 'h', confidence: 'certaine',
      title: 'Protocole SSH version 1 uniquement (obsolète et cassé)',
      evidence: `Bannière : SSH-${s.protocol}-${s.software}`,
      remediation: 'Mettre à jour le système ou le firmware et n\'autoriser que SSH version 2.',
    })
  },
  (o) => {
    const s = o.ssh
    if (!s || s.product !== 'Dropbear' || !s.version || cmp(s.version, '2016.74') >= 0) return null
    return finding(o, 'ssh-dropbear-old', {
      severity: 'h', cves: ['CVE-2016-7406', 'CVE-2016-7407'], confidence: 'probable',
      title: `Serveur SSH Dropbear ${s.version} obsolète (failles d'exécution de code)`,
      evidence: `Bannière : ${s.software}`,
      remediation: 'Mettre à jour le firmware de l\'appareil (routeur, caméra, NAS…). S\'il n\'est plus maintenu : désactiver SSH ou isoler l\'appareil.',
    })
  },

  // --- FTP / Telnet -------------------------------------------------------------------------
  (o) => {
    const f = o.ftp
    if (!f || f.product !== 'vsftpd' || f.version !== '2.3.4') return null
    return finding(o, 'ftp-vsftpd-backdoor', {
      severity: 'c', cves: ['CVE-2011-2523'], confidence: 'probable',
      title: 'vsftpd 2.3.4 : version contenant une porte dérobée',
      evidence: `Bannière : vsFTPd ${f.version}`,
      remediation: 'Arrêter ce service immédiatement, le remplacer par une version saine, et vérifier que la machine n\'a pas été compromise.',
    })
  },
  (o) => {
    const f = o.ftp
    if (!f || f.product !== 'ProFTPD' || f.version !== '1.3.5') return null
    return finding(o, 'ftp-proftpd-modcopy', {
      severity: 'c', cves: ['CVE-2015-3306'], confidence: 'à vérifier',
      title: 'ProFTPD 1.3.5 : copie de fichiers sans authentification (mod_copy)',
      evidence: 'Bannière : ProFTPD 1.3.5',
      remediation: 'Mettre à jour ProFTPD (1.3.5a ou plus récent) ou désactiver le module mod_copy.',
    })
  },
  (o) => {
    if (o.service !== 'ftp' || !o.ftp || o.ftp.tls) return null
    return finding(o, 'ftp-cleartext', {
      severity: 'm', confidence: 'certaine',
      title: 'FTP sans chiffrement : identifiants et fichiers circulent en clair',
      evidence: 'Le serveur ne propose pas « AUTH TLS ».',
      remediation: 'Remplacer FTP par SFTP ou activer FTPS (TLS obligatoire). Désactiver FTP s\'il n\'est pas utilisé.',
    })
  },
  (o) => {
    if (o.service !== 'telnet' || !o.open) return null
    return finding(o, 'telnet-open', {
      severity: 'h', confidence: 'certaine',
      title: 'Telnet actif : mots de passe en clair, cible des botnets (Mirai…)',
      evidence: `Port ${o.port} ouvert.`,
      remediation: 'Désactiver Telnet (menu d\'administration ou firmware) et utiliser SSH. Changer le mot de passe par défaut de l\'appareil.',
    })
  },

  // --- Web ----------------------------------------------------------------------------------
  (o) => {
    const h = o.http
    if (!h || h.product !== 'Apache' || !['2.4.49', '2.4.50'].includes(h.version)) return null
    const cve = h.version === '2.4.49' ? 'CVE-2021-41773' : 'CVE-2021-42013'
    return finding(o, 'http-apache-traversal', {
      severity: 'c', cves: [cve], confidence: 'probable',
      title: `Apache ${h.version} : lecture de fichiers et exécution de code à distance (${cve})`,
      evidence: `En-tête Server : ${h.server}`,
      remediation: 'Mettre à jour Apache HTTP Server en 2.4.51 ou plus récent sans attendre.',
    })
  },
  (o) => {
    const h = o.http
    if (!h || h.product !== 'Microsoft-IIS' || h.version !== '6.0') return null
    return finding(o, 'http-iis6', {
      severity: 'c', cves: ['CVE-2017-7269'], confidence: 'probable',
      title: 'IIS 6.0 (Windows Server 2003) : système obsolète, faille WebDAV exploitée',
      evidence: `En-tête Server : ${h.server}`,
      remediation: 'Migrer vers un Windows Server maintenu. En attendant : désactiver WebDAV et isoler le serveur.',
    })
  },
  (o) => {
    const h = o.http
    if (!h || h.secure || !h.loginForm) return null
    return finding(o, 'http-login-cleartext', {
      severity: 'm', confidence: 'certaine',
      title: 'Page de connexion non chiffrée (HTTP) : mot de passe lisible sur le réseau',
      evidence: `Formulaire avec mot de passe servi en HTTP sur le port ${o.port}.`,
      remediation: 'Activer HTTPS sur l\'interface d\'administration et désactiver l\'accès HTTP, ou la réserver au réseau d\'administration.',
    })
  },

  // --- TLS ----------------------------------------------------------------------------------
  (o) => {
    const c = o.tls && o.tls.cert
    if (!c || !c.expired) return null
    return finding(o, 'tls-expired', {
      severity: 'm', confidence: 'certaine',
      title: 'Certificat TLS expiré',
      evidence: `Certificat « ${c.subject || '?'} » expiré le ${c.validTo}.`,
      remediation: 'Renouveler le certificat. Un certificat expiré habitue les utilisateurs à ignorer les alertes de sécurité.',
    })
  },
  (o) => {
    const c = o.tls && o.tls.cert
    if (!c || c.expired || !c.selfSigned) return null
    return finding(o, 'tls-selfsigned', {
      severity: 'l', confidence: 'certaine',
      title: 'Certificat TLS auto-signé',
      evidence: `Certificat « ${c.subject || '?'} » émis par lui-même.`,
      remediation: 'Utiliser un certificat émis par une autorité reconnue (ou l\'autorité interne de l\'entreprise).',
    })
  },
  (o) => {
    if (!o.tls || !o.tls.legacy) return null
    return finding(o, 'tls-legacy', {
      severity: 'm', confidence: 'certaine',
      title: 'TLS 1.0 encore accepté (protocole obsolète)',
      evidence: 'Une connexion en TLS 1.0 a été acceptée.',
      remediation: 'N\'autoriser que TLS 1.2 et TLS 1.3 dans la configuration du serveur ou de l\'appareil.',
    })
  },

  // --- Windows ------------------------------------------------------------------------------
  (o) => {
    if (o.smb1 !== true) return null
    return finding(o, 'smb1-enabled', {
      severity: 'h', cves: ['CVE-2017-0144'], confidence: 'certaine',
      title: 'SMBv1 activé (vecteur de WannaCry / EternalBlue)',
      evidence: 'Le serveur accepte une négociation SMB version 1.',
      remediation: 'Windows : exécuter en administrateur « Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol » puis redémarrer. '
        + 'NAS / imprimante : régler la version SMB minimale sur SMB2. Vérifier aussi que le correctif MS17-010 est installé.',
    })
  },
  (o) => {
    if (o.rdp !== 'no-nla') return null
    return finding(o, 'rdp-no-nla', {
      severity: 'h', cves: ['CVE-2019-0708'], confidence: 'certaine',
      title: 'Bureau à distance sans authentification réseau (NLA)',
      evidence: 'Le serveur accepte une session sans NLA (CredSSP).',
      remediation: 'Propriétés système > Utilisation à distance : cocher « N\'autoriser que les connexions des ordinateurs exécutant le Bureau à distance avec authentification NLA ». '
        + 'Sur les anciens Windows (7 / 2008), installer le correctif BlueKeep. Ne jamais exposer RDP sur Internet.',
    })
  },

  // --- Services sans authentification ---------------------------------------------------------
  (o) => {
    if (!o.vnc || !o.vnc.types || !o.vnc.types.includes(1)) return null
    return finding(o, 'vnc-noauth', {
      severity: 'c', confidence: 'certaine',
      title: 'VNC sans mot de passe : prise de contrôle de l\'écran par n\'importe qui',
      evidence: 'Le serveur propose le type de sécurité « None ».',
      remediation: 'Définir un mot de passe VNC robuste ou désactiver VNC. Préférer un accès à distance chiffré et authentifié.',
    })
  },
  (o) => {
    if (o.redis !== 'open') return null
    return finding(o, 'redis-noauth', {
      severity: 'c', confidence: 'certaine',
      title: 'Redis accessible sans mot de passe',
      evidence: 'La commande PING a répondu sans authentification.',
      remediation: 'Activer « requirepass » (ou les ACL), laisser « protected-mode yes » et limiter « bind » aux adresses nécessaires.',
    })
  },
  (o) => {
    if (!o.docker) return null
    return finding(o, 'docker-api-open', {
      severity: 'c', confidence: 'certaine',
      title: 'API Docker exposée sans authentification (contrôle total de la machine)',
      evidence: `API Docker ${o.docker.version || ''} accessible sur le port ${o.port}.`.replace('  ', ' '),
      remediation: 'Ne plus exposer le démon Docker sur TCP (retirer tcp://0.0.0.0:2375) ou exiger TLS avec certificats clients.',
    })
  },
  (o) => {
    if (!o.es) return null
    return finding(o, 'elasticsearch-open', {
      severity: 'h', confidence: 'certaine',
      title: 'Elasticsearch accessible sans authentification (fuite de données)',
      evidence: `Cluster « ${o.es.cluster || '?'} » lisible sans identifiant.`,
      remediation: 'Activer la sécurité Elasticsearch (authentification et TLS) et limiter l\'accès réseau.',
    })
  },
  (o) => {
    const db = { mysql: 'MySQL / MariaDB', mssql: 'SQL Server', postgres: 'PostgreSQL' }[o.service]
    if (!db || !o.open || (o.mysql && o.mysql.blocked)) return null
    return finding(o, 'db-exposed', {
      severity: 'm', confidence: 'certaine',
      title: `Base de données ${db} accessible depuis tout le réseau`,
      evidence: `Port ${o.port} ouvert${o.mysql && o.mysql.version ? `, version ${o.mysql.version}` : ''}.`,
      remediation: 'Limiter l\'accès (pare-feu) aux seuls serveurs d\'application, utiliser des mots de passe robustes et chiffrer les connexions.',
    })
  },
]

// Observation d'un port → liste des faiblesses trouvées.
export function evaluate(obs) {
  const out = []
  for (const rule of RULES) {
    try {
      const f = rule(obs)
      if (f) out.push(f)
    } catch { /* une règle défaillante ne doit pas bloquer les autres */ }
  }
  return out
}

export const SEVERITY_ORDER = { c: 0, h: 1, m: 2, l: 3 }
export const bySeverity = (a, b) => (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
  || a.ip.localeCompare(b.ip, 'en', { numeric: true }) || a.port - b.port

// Comparaison de deux analyses : nouvelles faiblesses et faiblesses corrigées (même hôte encore joignable).
export function diffFindings(previous, current, scannedIps) {
  const prev = new Map((previous || []).map((f) => [f.key, f]))
  const cur = new Map((current || []).map((f) => [f.key, f]))
  const scanned = new Set(scannedIps || [])
  return {
    added: [...cur.values()].filter((f) => !prev.has(f.key)),
    // Corrigée seulement si l'hôte a bien été analysé cette fois (un appareil éteint n'est pas « corrigé »).
    fixed: [...prev.values()].filter((f) => !cur.has(f.key) && scanned.has(f.ip)),
  }
}
