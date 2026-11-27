// CyberVeylix — exécution complète d'une analyse : sondes, comparaison avec la précédente,
// rapport HTML daté, état « dernière analyse » et événements. Partagé par vulnscan.mjs et le capteur.
import { readFileSync, writeFileSync, readdirSync, rmSync, existsSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { scanTargets } from './scan.mjs'
import { diffFindings } from './rules.mjs'
import { renderReportHtml, vulnEvents } from './report.mjs'

const KEEP_REPORTS = 20
const pad = (n) => String(n).padStart(2, '0')
export const reportStamp = (d) => `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}`

export async function runVulnScan({ targets, dataDir, client = '', now = new Date(), scanOptions = {} }) {
  mkdirSync(dataDir, { recursive: true })
  const report = await scanTargets(targets, scanOptions)
  const latestFile = join(dataDir, 'vulns-latest.json')
  let previous = null
  if (existsSync(latestFile)) {
    try { previous = JSON.parse(readFileSync(latestFile, 'utf8')) } catch { previous = null }
  }
  const diff = diffFindings(previous && previous.findings, report.findings, report.scannedIps)

  // Les faiblesses des appareils absents cette fois sont conservées : à leur retour,
  // elles ne doivent pas être annoncées comme « nouvelles ».
  const scanned = new Set(report.scannedIps)
  const carried = ((previous && previous.findings) || []).filter((f) => !scanned.has(f.ip))
  writeFileSync(latestFile, JSON.stringify({ ...report, findings: [...report.findings, ...carried] }, null, 2))

  const htmlFile = join(dataDir, `rapport-vulnerabilites-${reportStamp(now)}.html`)
  writeFileSync(htmlFile, renderReportHtml(report, { client, generatedAt: now }))
  const old = readdirSync(dataDir).filter((f) => /^rapport-vulnerabilites-\d{8}-\d{4}\.html$/.test(f)).sort()
  for (const f of old.slice(0, Math.max(0, old.length - KEEP_REPORTS))) rmSync(join(dataDir, f), { force: true })

  const events = vulnEvents({ firstScan: !previous, added: diff.added, fixed: diff.fixed, findings: report.findings, reportFile: htmlFile })
  return { report, firstScan: !previous, added: diff.added, fixed: diff.fixed, htmlFile, events }
}
