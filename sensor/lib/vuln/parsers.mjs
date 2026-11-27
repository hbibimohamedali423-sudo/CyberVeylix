// CyberVeylix — analyse des réponses des services (pur, testable sans réseau).
// Les réponses viennent d'appareils potentiellement compromis : toute lecture est bornée,
// une réponse inattendue donne « inconnu » (null), jamais une exception.

// --- Versions ---------------------------------------------------------------------------
// « 9.6p1 » → [9, 6, 1] ; « 2016.74 » → [2016, 74]. Comparaison champ par champ (manquant = 0).
export function parseVersion(text) {
  const nums = String(text || '').match(/\d+/g)
  return nums ? nums.map(Number) : null
}

export function compareVersions(a, b) {
  const x = Array.isArray(a) ? a : parseVersion(a)
  const y = Array.isArray(b) ? b : parseVersion(b)
  if (!x || !y) return null
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] || 0) - (y[i] || 0)
    if (d !== 0) return d < 0 ? -1 : 1
  }
  return 0
}

// --- Bannières texte ----------------------------------------------------------------------
// « SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13 » → { protocol, product, version, comment }
export function parseSshBanner(banner) {
  const m = /^SSH-(\d+\.\d+)-([^\s\r\n]+)(?:[ \t]+([^\r\n]*))?/.exec(String(banner || ''))
  if (!m) return null
  const sw = m[2]
  const known = /^(OpenSSH)_([\w.]+)/i.exec(sw) || /^(dropbear)_([\w.]+)/i.exec(sw)
  return {
    protocol: m[1],
    software: sw.slice(0, 80),
    product: known ? (known[1].toLowerCase() === 'dropbear' ? 'Dropbear' : 'OpenSSH') : null,
    version: known ? known[2] : null,
    comment: (m[3] || '').slice(0, 80),
  }
}

// « 220 (vsFTPd 2.3.4) » / « 220 ProFTPD 1.3.5 Server (Debian) » → { product, version }
export function parseFtpBanner(banner) {
  const text = String(banner || '')
  if (!/^220[ -]/.test(text)) return null
  const vs = /vsFTPd\s+([\d.]+\w*)/i.exec(text)
  if (vs) return { product: 'vsftpd', version: vs[1] }
  const pro = /ProFTPD\s+([\d.]+[a-z]?\w*)/i.exec(text)
  if (pro) return { product: 'ProFTPD', version: pro[1] }
  return { product: null, version: null }
}

// En-tête HTTP Server : « Apache/2.4.49 (Unix) » → { product: 'Apache', version: '2.4.49' }
export function parseServerHeader(value) {
  const m = /^([A-Za-z][\w.-]*)\/([\d][\w.-]*)/.exec(String(value || '').trim())
  return m ? { product: m[1], version: m[2] } : null
}

// --- SMB : SMBv1 accepté ? ------------------------------------------------------------------
// Requête « Negotiate » SMB1 n'offrant QUE le dialecte « NT LM 0.12 » (SMBv1). Aucune authentification.
export function smb1NegotiateRequest() {
  const dialects = Buffer.from('\x02NT LM 0.12\x00', 'latin1')
  const header = Buffer.alloc(32)
  Buffer.from([0xff, 0x53, 0x4d, 0x42]).copy(header, 0) // « \xFFSMB »
  header[4] = 0x72 // SMB_COM_NEGOTIATE
  header[9] = 0x18 // flags
  header.writeUInt16LE(0xc001, 10) // flags2 : unicode, codes NT, noms longs
  const body = Buffer.alloc(3)
  body[0] = 0 // word count
  body.writeUInt16LE(dialects.length, 1)
  const smb = Buffer.concat([header, body, dialects])
  const nb = Buffer.alloc(4)
  nb.writeUInt32BE(smb.length, 0) // en-tête de session NetBIOS (type 0)
  return Buffer.concat([nb, smb])
}

// true = SMBv1 accepté, false = refusé (réponse SMB2 ou erreur), null = réponse illisible.
export function parseSmb1NegotiateResponse(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 8) return null
  const proto = buf.subarray(4, 8)
  if (proto.equals(Buffer.from([0xfe, 0x53, 0x4d, 0x42]))) return false
  if (!proto.equals(Buffer.from([0xff, 0x53, 0x4d, 0x42]))) return null
  if (buf.length < 39 || buf[8] !== 0x72) return null
  if (buf.readUInt32LE(9) !== 0) return false // statut d'erreur : dialecte refusé
  if (buf[36] < 1) return false
  return buf.readUInt16LE(37) !== 0xffff // 0xFFFF = aucun dialecte accepté
}

// --- RDP : authentification NLA exigée ? ----------------------------------------------------
// Demande de connexion X.224 proposant TLS seul (sans CredSSP/NLA). Un serveur qui exige NLA refuse.
export function rdpNegotiationRequest(requestedProtocols = 0x1) {
  const neg = Buffer.alloc(8)
  neg[0] = 0x01 // TYPE_RDP_NEG_REQ
  neg.writeUInt16LE(8, 2)
  neg.writeUInt32LE(requestedProtocols, 4)
  const x224 = Buffer.from([0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00]) // LI=14, Connection Request
  const tpkt = Buffer.from([0x03, 0x00, 0x00, 4 + x224.length + neg.length])
  return Buffer.concat([tpkt, x224, neg])
}

// 'nla-required' | 'no-nla' | null (inconnu)
export function parseRdpNegotiationResponse(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 11 || buf[0] !== 0x03) return null
  if (buf[5] !== 0xd0) return null // pas une « Connection Confirm »
  if (buf.length < 19) return 'no-nla' // serveur sans négociation : sécurité RDP standard (ancien)
  const type = buf[11]
  const value = buf.readUInt32LE(15)
  if (type === 0x02) return 'no-nla' // TLS seul (ou RDP standard) accepté : NLA non exigée
  if (type === 0x03) return value === 0x05 ? 'nla-required' : 'no-nla' // 5 = HYBRID_REQUIRED_BY_SERVER
  return null
}

// --- VNC : types de sécurité proposés -------------------------------------------------------
// « RFB 003.008\n » → { major: 3, minor: 8 }
export function parseRfbVersion(text) {
  const m = /^RFB (\d{3})\.(\d{3})\n/.exec(String(text || ''))
  return m ? { major: Number(m[1]), minor: Number(m[2]) } : null
}

// Après l'envoi de notre version : liste des types de sécurité. 1 = « None » (aucun mot de passe).
export function parseVncSecurityTypes(buf, minor) {
  if (!Buffer.isBuffer(buf) || buf.length < 1) return null
  if (minor < 7) { // RFB 3.3 : le serveur impose un type sur 4 octets
    if (buf.length < 4) return null
    const t = buf.readUInt32BE(0)
    return t === 0 ? [] : [t]
  }
  const count = buf[0]
  if (count === 0) return [] // échec annoncé (ex. trop de tentatives)
  return [...buf.subarray(1, 1 + count)]
}

// --- MySQL : paquet d'accueil ----------------------------------------------------------------
// → { version } ou { blocked: true } (hôte refusé par le serveur) ou null.
export function parseMysqlGreeting(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 6) return null
  const len = buf.readUIntLE(0, 3)
  const payload = buf.subarray(4, 4 + len)
  if (payload.length < 2) return null
  if (payload[0] === 0xff) return { blocked: true }
  if (payload[0] !== 10) return null
  const end = payload.indexOf(0, 1)
  if (end < 0) return null
  return { version: payload.subarray(1, Math.min(end, 61)).toString('latin1') }
}

// --- Certificat TLS ---------------------------------------------------------------------------
// cert : objet de tls.TLSSocket#getPeerCertificate().
export function analyzeCertificate(cert, now = Date.now()) {
  if (!cert || !cert.valid_to) return null
  const end = Date.parse(cert.valid_to)
  const subject = JSON.stringify(cert.subject || {})
  const issuer = JSON.stringify(cert.issuer || {})
  return {
    expired: Number.isFinite(end) && end < now,
    daysLeft: Number.isFinite(end) ? Math.floor((end - now) / 86400000) : null,
    selfSigned: subject === issuer,
    subject: String((cert.subject && cert.subject.CN) || '').slice(0, 120),
    validTo: cert.valid_to,
  }
}

// Page HTTP contenant un champ mot de passe.
export const hasPasswordField = (html) => /<input[^>]+type\s*=\s*["']?password/i.test(String(html || ''))
