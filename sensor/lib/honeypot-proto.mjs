// CyberVeylix Sensor — analyse des échanges reçus par les leurres (pur, testable sans réseau).
// Règle absolue : un mot de passe saisi sur un leurre n'est JAMAIS conservé ni transmis.
// Un employé peut taper son vrai mot de passe par erreur : on ne garde que « un mot de passe a été envoyé ».

const MAX_LINE = 256
const MAX_USERNAME = 64

// Identifiant affichable : caractères imprimables uniquement, longueur bornée.
export function sanitizeUsername(value) {
  if (value === undefined || value === null) return ''
  return String(value).replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, MAX_USERNAME)
}

// Retire les séquences de négociation Telnet (IAC) d'un bloc reçu.
export function stripTelnet(buf) {
  const out = []
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i]
    if (b !== 0xff) { out.push(b); continue }
    const cmd = buf[i + 1]
    if (cmd === undefined) break
    if (cmd === 0xff) { out.push(0xff); i += 1; continue } // 255 littéral
    if (cmd >= 251 && cmd <= 254) { i += 2; continue } // WILL / WONT / DO / DONT + option
    if (cmd === 250) { // sous-négociation : jusqu'à IAC SE
      let j = i + 2
      while (j < buf.length && !(buf[j] === 0xff && buf[j + 1] === 240)) j++
      i = j + 1
      continue
    }
    i += 1 // autre commande sur 2 octets
  }
  return Buffer.from(out)
}

// Accumule du texte et rend les lignes complètes (CR/LF/NUL retirés, longueur bornée).
export function createLineReader(maxLines = 8) {
  let pending = ''
  let count = 0
  return {
    push(text) {
      pending += text
      const lines = []
      let idx
      while ((idx = pending.search(/\r?\n|\r\0|\0/)) >= 0 && count < maxLines) {
        const line = pending.slice(0, idx)
        pending = pending.slice(idx).replace(/^(\r?\n|\r\0|\0)/, '')
        lines.push(line.slice(0, MAX_LINE))
        count++
      }
      if (pending.length > MAX_LINE) pending = pending.slice(0, MAX_LINE) // pas d'accumulation sans fin
      return lines
    },
    get exhausted() { return count >= maxLines },
  }
}

// Commande FTP : « USER bob » → { cmd: 'USER', arg: 'bob' }.
export function parseFtpCommand(line) {
  const m = /^\s*([A-Za-z]{3,4})(?:\s+(.*))?$/.exec(String(line))
  if (!m) return { cmd: '', arg: '' }
  return { cmd: m[1].toUpperCase(), arg: (m[2] || '').trim() }
}

const USER_FIELDS = ['username', 'user', 'login', 'name', 'email', 'usr', 'uname']
const PASS_FIELDS = ['password', 'pass', 'passwd', 'pwd', 'psw']

// Corps d'un formulaire de connexion envoyé au faux portail : { username, hasPassword } (jamais le mot de passe).
export function parseLoginForm(body, contentType = '') {
  let fields = {}
  const text = String(body || '')
  if (/json/i.test(contentType)) {
    try {
      const data = JSON.parse(text)
      if (data && typeof data === 'object' && !Array.isArray(data)) fields = data
    } catch { fields = {} }
  } else {
    try {
      for (const [k, v] of new URLSearchParams(text)) fields[k] = v
    } catch { fields = {} }
  }
  const lower = Object.fromEntries(Object.entries(fields).map(([k, v]) => [k.toLowerCase(), v]))
  const userKey = USER_FIELDS.find((k) => typeof lower[k] === 'string' && lower[k] !== '')
  const passKey = PASS_FIELDS.find((k) => typeof lower[k] === 'string' && lower[k] !== '')
  return { username: userKey ? sanitizeUsername(lower[userKey]) : '', hasPassword: Boolean(passKey) }
}
