// Contrôle statique des scripts Windows (sans PowerShell) : compatibilité Windows PowerShell 5.1.
// La vraie analyse syntaxique est faite par la CI sur Windows (.github/workflows/sensor-build.yml).
import { readFileSync } from 'node:fs'

// Retire commentaires et chaînes pour ne garder que le code (tokenisation simplifiée mais suffisante ici).
export function stripPowerShell(src) {
  let out = ''
  let i = 0
  const n = src.length
  const at = (s) => src.startsWith(s, i)
  while (i < n) {
    if (at('<#')) { const e = src.indexOf('#>', i + 2); i = e < 0 ? n : e + 2; continue }
    if (at("@'") && /^\s*\r?\n/.test(src.slice(i + 2, i + 4))) { const e = src.indexOf("\n'@", i); i = e < 0 ? n : e + 3; out += "''"; continue }
    if (at('@"') && /^\s*\r?\n/.test(src.slice(i + 2, i + 4))) { const e = src.indexOf('\n"@', i); i = e < 0 ? n : e + 3; out += "''"; continue }
    const c = src[i]
    if (c === '#') { const e = src.indexOf('\n', i); i = e < 0 ? n : e; continue }
    if (c === "'") {
      i++
      while (i < n) { if (src[i] === "'") { if (src[i + 1] === "'") { i += 2; continue } i++; break } i++ }
      out += "''"; continue
    }
    if (c === '"') {
      i++
      while (i < n) {
        if (src[i] === '`') { i += 2; continue }
        if (src[i] === '"') { if (src[i + 1] === '"') { i += 2; continue } i++; break }
        i++
      }
      out += "''"; continue
    }
    if (c === '`') { out += src.slice(i, i + 2); i += 2; continue } // échappement / continuation de ligne
    out += c; i++
  }
  return out
}

const PS7_ONLY = [
  [/\?\?/, 'opérateur ?? (PowerShell 7)'],
  [/\?\./, 'opérateur ?. (PowerShell 7)'],
  [/&&|\|\|/, 'chaînage && / || (PowerShell 7)'],
  [/\?/, '« ? » dans le code (ternaire PowerShell 7 ou alias ambigu de Where-Object)'],
  [/-Parallel\b/i, 'ForEach-Object -Parallel (PowerShell 7)'],
  [/-AsHashtable\b/i, 'ConvertFrom-Json -AsHashtable (PowerShell 6+)'],
  [/-Encoding\s+utf8NoBOM\b/i, 'encodage utf8NoBOM (PowerShell 6+)'],
  [/-TargetName\b/i, 'Test-Connection -TargetName (PowerShell 7)'],
  [/\$PSStyle\b/, '$PSStyle (PowerShell 7.2+)'],
]

// Renvoie la liste des problèmes trouvés (vide = conforme).
export function checkPowerShellFile(path) {
  const buf = readFileSync(path)
  const problems = []
  const hasBom = buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf
  const text = buf.toString('utf8').replace(/^﻿/, '')
  // Sans BOM, Windows PowerShell 5.1 lit le fichier en ANSI : les accents seraient corrompus.
  if (/[^\x00-\x7f]/.test(text) && !hasBom) problems.push('caractères non ASCII sans BOM UTF-8')
  // PowerShell traite ‘ ’ “ ” comme de vrais guillemets : une apostrophe typographique casse une chaîne.
  const curly = text.match(/[‘’‚‛“”„]/)
  if (curly) problems.push(`guillemet typographique « ${curly[0]} » (interprété comme guillemet par PowerShell)`)
  if (text.includes('/dev/null')) problems.push('redirection Unix /dev/null (utiliser nul ou $null sous Windows)')
  const code = stripPowerShell(text)
  for (const [re, label] of PS7_ONLY) if (re.test(code)) problems.push(label)
  for (const [open, close] of [['(', ')'], ['{', '}'], ['[', ']']]) {
    const a = code.split(open).length - 1
    const b = code.split(close).length - 1
    if (a !== b) problems.push(`parenthèses déséquilibrées ${open}${close} : ${a} / ${b}`)
  }
  return problems
}

// Fichier .cmd : ASCII pur (cmd.exe lit en page de code OEM) et fins de ligne CRLF.
export function checkCmdFile(path) {
  const buf = readFileSync(path)
  const problems = []
  if ([...buf].some((b) => b > 0x7f)) problems.push('caractères non ASCII')
  const text = buf.toString('latin1')
  if (/[^\r]\n/.test(text) || /^\n/.test(text)) problems.push('fins de ligne LF au lieu de CRLF')
  // Chemin Unix : sous Windows, une redirection vers /dev/null échoue ou crée un fichier parasite.
  if (text.includes('/dev/null')) problems.push('redirection Unix /dev/null (utiliser nul sous Windows)')
  return problems
}
