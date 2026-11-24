// CyberVeylix — rapport de vulnérabilités (HTML imprimable en PDF) et événements d'alerte. Pur, testable.
// Les bannières viennent d'appareils potentiellement compromis : TOUT texte est échappé.

const LABEL = { c: 'Critique', h: 'Haute', m: 'Moyenne', l: 'Basse' }
const COLOR = { c: '#b3261e', h: '#a85a00', m: '#7a5a00', l: '#4a607c' }
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
}

const cveLinks = (cves) => (cves || []).filter((c) => CVE_RE.test(c))
  .map((c) => `<a href="https://nvd.nist.gov/vuln/detail/${c}">${c}</a>`).join(', ')

export function countBySeverity(findings) {
  const n = { c: 0, h: 0, m: 0, l: 0 }
  for (const f of findings || []) if (n[f.severity] !== undefined) n[f.severity]++
  return n
}

export function renderReportHtml(report, { client = '', generatedAt = new Date() } = {}) {
  const n = countBySeverity(report.findings)
  const date = generatedAt.toLocaleString('fr-FR', { dateStyle: 'long', timeStyle: 'short' })
  const rows = report.findings.map((f) => `
    <tr>
      <td><span class="sev" style="background:${COLOR[f.severity] || '#555'}">${escapeHtml(LABEL[f.severity] || f.severity)}</span></td>
      <td>${escapeHtml(f.ip)}<br><small>port ${escapeHtml(f.port)} · ${escapeHtml(f.service)}</small></td>
      <td><b>${escapeHtml(f.title)}</b><br><small>${cveLinks(f.cves)}${f.cves && f.cves.length ? ' · ' : ''}confiance : ${escapeHtml(f.confidence)}</small>
        <div class="ev">${escapeHtml(f.evidence)}</div></td>
      <td>${escapeHtml(f.remediation)}</td>
    </tr>`).join('')
  const inventory = (report.hosts || []).map((h) => `
    <tr><td>${escapeHtml(h.ip)}</td><td>${h.services.map((s) => `${escapeHtml(s.port)}/${escapeHtml(s.service)}${s.detail ? ` <small>(${escapeHtml(s.detail)})</small>` : ''}`).join('<br>') || '—'}</td></tr>`).join('')

  return `<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport de vulnérabilités${client ? ' — ' + escapeHtml(client) : ''}</title>
<style>
body{font:14px/1.5 system-ui,Segoe UI,Arial,sans-serif;color:#14263d;margin:24px auto;max-width:1100px;padding:0 16px}
h1{font-size:22px;margin:0}h2{font-size:16px;margin:28px 0 8px;border-bottom:2px solid #07718a;padding-bottom:4px}
.meta{color:#4a607c;margin:4px 0 16px}.kpis{display:flex;gap:10px;flex-wrap:wrap}
.kpi{border:1px solid #c3cfdf;border-radius:8px;padding:10px 14px;min-width:110px}.kpi b{display:block;font-size:24px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{border-bottom:1px solid #d7e0ea;padding:8px;text-align:left;vertical-align:top}
th{background:#eef2f7}thead th:nth-child(3){width:38%}.sev{color:#fff;border-radius:4px;padding:2px 8px;font-size:12px;white-space:nowrap}
.ev{color:#4a607c;font-size:12px;margin-top:4px;word-break:break-word}small{color:#4a607c}
.note{background:#eef2f7;border-radius:8px;padding:10px 14px;font-size:12px;color:#4a607c}
@media print{body{margin:0}a{color:inherit;text-decoration:none}tr{break-inside:avoid}}
</style></head><body>
<h1>Rapport de vulnérabilités réseau</h1>
<div class="meta">${client ? `Client : <b>${escapeHtml(client)}</b> · ` : ''}${escapeHtml(date)} ·
${escapeHtml(report.targets)} adresse(s) analysée(s), ${escapeHtml((report.hosts || []).length)} appareil(s) joignable(s)</div>
<div class="kpis">
  <div class="kpi" style="border-color:${COLOR.c}"><b style="color:${COLOR.c}">${n.c}</b>Critique(s)</div>
  <div class="kpi" style="border-color:${COLOR.h}"><b style="color:${COLOR.h}">${n.h}</b>Haute(s)</div>
  <div class="kpi"><b style="color:${COLOR.m}">${n.m}</b>Moyenne(s)</div>
  <div class="kpi"><b style="color:${COLOR.l}">${n.l}</b>Basse(s)</div>
</div>
<h2>Faiblesses détectées et corrections</h2>
${report.findings.length ? `<table><thead><tr><th>Gravité</th><th>Appareil</th><th>Faiblesse</th><th>Correction recommandée</th></tr></thead><tbody>${rows}</tbody></table>`
    : '<p>Aucune faiblesse détectée par les contrôles effectués.</p>'}
<h2>Services observés</h2>
${inventory ? `<table><thead><tr><th>Appareil</th><th>Ports ouverts</th></tr></thead><tbody>${inventory}</tbody></table>` : '<p>Aucun service observé.</p>'}
<h2>Méthode et limites</h2>
<div class="note">
Analyse non intrusive réalisée par le capteur CyberVeylix : lecture des informations annoncées par chaque service et négociation
normale des protocoles. Aucune exploitation, aucun essai de mot de passe. La base de règles est volontairement limitée à des faiblesses
connues et vérifiées : <b>l'absence de résultat ne prouve pas l'absence de vulnérabilité</b>. Une faiblesse « à vérifier » dépend d'une
version annoncée que l'éditeur ou la distribution a pu corriger sans changer le numéro. Les appareils éteints au moment de l'analyse
n'ont pas pu être contrôlés.
</div>
</body></html>
`
}

// Événements d'alerte à partir d'une comparaison d'analyses.
// firstScan : aucune analyse précédente → un résumé + les faiblesses critiques seulement (pas d'avalanche).
export function vulnEvents({ firstScan, added, fixed, findings, reportFile }) {
  const events = []
  const where = (f) => `${f.ip} port ${f.port}`
  if (firstScan) {
    const n = countBySeverity(findings)
    const worst = ['c', 'h', 'm', 'l'].find((s) => n[s] > 0) || 'l'
    events.push({
      type: 'vuln_scan_summary', severity: worst,
      title: `Première analyse de vulnérabilités : ${findings.length} faiblesse(s)`,
      detail: `Critiques ${n.c}, hautes ${n.h}, moyennes ${n.m}, basses ${n.l}.${reportFile ? ` Rapport : ${reportFile}` : ''}`,
    })
    for (const f of findings.filter((x) => x.severity === 'c')) {
      events.push({ type: 'vuln_new', severity: 'c', ip: f.ip, port: f.port, title: f.title, detail: `${where(f)} — ${f.evidence} Correction : ${f.remediation}` })
    }
    return events
  }
  for (const f of added) {
    events.push({ type: 'vuln_new', severity: f.severity, ip: f.ip, port: f.port, title: `Nouvelle vulnérabilité : ${f.title}`, detail: `${where(f)} — ${f.evidence} Correction : ${f.remediation}` })
  }
  for (const f of fixed) {
    events.push({ type: 'vuln_fixed', severity: 'l', ip: f.ip, port: f.port, title: `Vulnérabilité corrigée : ${f.title}`, detail: `${where(f)} : la faiblesse n'est plus détectée.` })
  }
  return events
}
