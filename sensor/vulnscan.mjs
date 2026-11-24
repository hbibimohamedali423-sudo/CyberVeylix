// CyberVeylix — analyse de vulnérabilités à la demande (non intrusive, réseaux privés uniquement).
//
//   node sensor/vulnscan.mjs --yes --targets=192.168.1.0/24 [--client="Société X"] [--out=dossier]
//   node sensor/vulnscan.mjs --config=C:\ProgramData\CyberVeylix\Sensor\config.json
//       (appareils connus du capteur, client et autorisation repris de l'installation)
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseConfigText } from './lib/options.mjs'
import { expandTargets, isPrivateIpv4 } from './lib/vuln/scan.mjs'
import { runVulnScan } from './lib/vuln/run.mjs'
import { countBySeverity } from './lib/vuln/report.mjs'

const argv = process.argv.slice(2)
const value = (name) => argv.find((a) => a.startsWith(`--${name}=`))?.slice(name.length + 3)
const die = (msg) => { console.error('✖ ' + msg); process.exit(1) }
const HERE = dirname(fileURLToPath(import.meta.url))

let config = {}
const configPath = value('config')
if (configPath) {
  if (!existsSync(configPath)) die(`Fichier de configuration introuvable : ${configPath}`)
  const parsed = parseConfigText(readFileSync(configPath, 'utf8'))
  if (parsed.error) die(parsed.error)
  config = parsed.config
}
if (!argv.includes('--yes') && config.authorized !== true) {
  die('Ajoutez --yes pour confirmer l\'autorisation écrite du propriétaire du réseau.')
}

const dataDir = value('out') || config.dataDir || join(HERE, 'data')
const client = value('client') || config.client || ''

let targets
const spec = value('targets')
if (spec) {
  const r = expandTargets(spec)
  if (r.error) die(r.error)
  targets = r.targets
} else {
  // Appareils connus du capteur (référence apprise), sauf le PC du capteur lui-même.
  const baselineFile = join(dataDir, 'baseline.json')
  if (!existsSync(baselineFile)) die('Aucune cible : précisez --targets=… ou lancez d\'abord le capteur pour apprendre le réseau.')
  let baseline
  try { baseline = JSON.parse(readFileSync(baselineFile, 'utf8')) } catch { die('baseline.json illisible.') }
  targets = [...new Set((baseline.bindings || []).map((b) => b.ip))]
    .filter((ip) => isPrivateIpv4(ip) && ip !== config.interface)
  if (!targets.length) die('Aucun appareil connu à analyser.')
}

console.log(`CyberVeylix — analyse de vulnérabilités de ${targets.length} adresse(s)${client ? ` (client : ${client})` : ''}`)
console.log('Analyse non intrusive : lecture des services et négociation des protocoles, aucun essai de mot de passe.')
let done = 0
const result = await runVulnScan({
  targets, dataDir, client,
  scanOptions: { onHost: () => { done++; if (done % 16 === 0 || done === targets.length) process.stdout.write(`\r  ${done}/${targets.length} adresse(s) traitée(s)`) } },
})
process.stdout.write('\n')

const { report } = result
const n = countBySeverity(report.findings)
console.log(`${report.hosts.length} appareil(s) joignable(s) — critiques ${n.c}, hautes ${n.h}, moyennes ${n.m}, basses ${n.l}`)
for (const f of report.findings) {
  const tag = { c: 'CRITIQUE', h: 'HAUTE', m: 'MOYENNE', l: 'BASSE' }[f.severity]
  const extra = f.cves.filter((c) => !f.title.includes(c)) // pas de doublon si le titre cite déjà la CVE
  console.log(`  ${tag.padEnd(8)} ${`${f.ip}:${f.port}`.padEnd(21)} ${f.title}${extra.length ? ` [${extra.join(', ')}]` : ''}`)
}
if (!result.firstScan) console.log(`Depuis la dernière analyse : ${result.added.length} nouvelle(s), ${result.fixed.length} corrigée(s).`)
console.log(`Rapport (à ouvrir dans un navigateur, imprimable en PDF) : ${result.htmlFile}`)
