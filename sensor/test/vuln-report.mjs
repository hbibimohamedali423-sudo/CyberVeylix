// Tests du rapport, des événements et de l'exécution complète (analyses successives).
import assert from 'node:assert/strict'
import net from 'node:net'
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { renderReportHtml, vulnEvents, escapeHtml } from '../lib/vuln/report.mjs'
import { runVulnScan } from '../lib/vuln/run.mjs'
import { resolveOptions } from '../lib/options.mjs'

const f = (over) => ({
  key: '192.168.1.5:23:telnet-open', rule: 'telnet-open', ip: '192.168.1.5', port: 23, service: 'telnet',
  severity: 'h', cves: [], confidence: 'certaine', title: 'Telnet actif', evidence: 'Port 23 ouvert.', remediation: 'Désactiver.', ...over,
})

export function vulnReportChecks(check, checkAsync) {
  check('Rapport : contenu hostile échappé (bannière piégée), liens CVE stricts', () => {
    const evil = f({
      title: '<script>alert(1)</script>', evidence: '"><img src=x onerror=alert(2)>',
      cves: ['CVE-2024-6387', 'javascript:alert(3)', 'CVE-1"onmouseover="x'], service: '<b>x</b>',
    })
    const html = renderReportHtml({ targets: 1, hosts: [{ ip: '192.168.1.5', services: [{ port: 23, service: 'telnet', detail: '<svg onload=alert(4)>' }] }], findings: [evil] }, { client: '<i>Client</i>' })
    assert.equal(/<script>|<img |<svg |<b>x|<i>Client/.test(html), false)
    assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/)
    assert.match(html, /href="https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-2024-6387"/)
    assert.equal(html.includes('javascript:'), false)
    assert.equal(html.includes('onmouseover'), false)
    assert.equal(escapeHtml(`&<>"'`), '&amp;&lt;&gt;&quot;&#39;')
  })

  check('Rapport : limites de l\'analyse toujours affichées, cas « aucune faiblesse »', () => {
    const html = renderReportHtml({ targets: 3, hosts: [], findings: [] })
    assert.match(html, /l'absence de résultat ne prouve pas l'absence de vulnérabilité/)
    assert.match(html, /Aucune faiblesse détectée/)
  })

  check('Événements : première analyse = résumé + critiques seulement ; ensuite nouvelles et corrigées', () => {
    const crit = f({ key: 'k1', severity: 'c', title: 'VNC sans mot de passe' })
    const med = f({ key: 'k2', severity: 'm' })
    const first = vulnEvents({ firstScan: true, added: [crit, med], fixed: [], findings: [crit, med], reportFile: 'r.html' })
    assert.deepEqual(first.map((e) => [e.type, e.severity]), [['vuln_scan_summary', 'c'], ['vuln_new', 'c']])
    const next = vulnEvents({ firstScan: false, added: [med], fixed: [crit], findings: [med] })
    assert.deepEqual(next.map((e) => e.type), ['vuln_new', 'vuln_fixed'])
    assert.match(next[1].title, /corrigée/)
    assert.equal(vulnEvents({ firstScan: true, added: [], fixed: [], findings: [] })[0].severity, 'l')
  })

  check('Options : analyse des vulnérabilités (activation, fréquence bornée)', () => {
    assert.equal(resolveOptions([], {}).options.vulnScan, false)
    const o = resolveOptions([], { vulnScan: true, vulnScanHours: 12 }).options
    assert.equal(o.vulnScan, true)
    assert.equal(o.vulnScanHours, 12)
    assert.equal(o.vulnFirstDelayMinutes, 5)
    assert.equal(resolveOptions(['--no-vuln-scan'], { vulnScan: true }).options.vulnScan, false)
    assert.match(resolveOptions(['--vuln-scan-hours=0'], {}).error, /vuln-scan-hours/)
    assert.match(resolveOptions(['--vuln-first-delay=-1'], {}).error, /vuln-first-delay/)
  })

  checkAsync('Analyses successives : nouvelle → corrigée ; appareil éteint ≠ corrigé ; rapports datés', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cv-vuln-'))
    let vncTypes = [1] // d'abord sans mot de passe
    const telnet = net.createServer((s) => { s.on('error', () => {}); s.write('login: ') })
    const vnc = net.createServer((s) => {
      s.on('error', () => {})
      s.write('RFB 003.008\n')
      s.on('data', () => s.write(Buffer.from([vncTypes.length, ...vncTypes])))
    })
    const port = (srv) => new Promise((r) => srv.listen({ host: '127.0.0.1', port: 0 }, () => r(srv.address().port)))
    const ports = [{ port: await port(telnet), service: 'telnet' }, { port: await port(vnc), service: 'vnc' }]
    const at = (min) => new Date(Date.UTC(2026, 10, 24, 10, min))
    try {
      const r1 = await runVulnScan({ targets: ['127.0.0.1'], dataDir: dir, client: 'Test', now: at(0), scanOptions: { ports } })
      assert.equal(r1.firstScan, true)
      assert.deepEqual(r1.report.findings.map((x) => x.rule), ['vnc-noauth', 'telnet-open'])
      assert.equal(r1.events[0].type, 'vuln_scan_summary')

      vncTypes = [2] // le client a mis un mot de passe VNC
      const r2 = await runVulnScan({ targets: ['127.0.0.1'], dataDir: dir, now: at(1), scanOptions: { ports } })
      assert.equal(r2.firstScan, false)
      assert.deepEqual(r2.fixed.map((x) => x.rule), ['vnc-noauth'])
      assert.deepEqual(r2.added, [])
      assert.deepEqual(r2.events.map((e) => e.type), ['vuln_fixed'])

      // Appareil injoignable (adresse privée inutilisée) : rien de « corrigé », rien de « nouveau ».
      const r3 = await runVulnScan({ targets: ['10.255.255.1'], dataDir: dir, now: at(2), scanOptions: { ports: [9] } })
      assert.deepEqual(r3.fixed, [])
      const latest = JSON.parse(readFileSync(join(dir, 'vulns-latest.json'), 'utf8'))
      assert.deepEqual(latest.findings.map((x) => x.rule), ['telnet-open']) // conservée pendant l'absence

      // Retour de l'appareil : la faiblesse conservée n'est pas réannoncée comme « nouvelle ».
      const r4 = await runVulnScan({ targets: ['127.0.0.1'], dataDir: dir, now: at(3), scanOptions: { ports } })
      assert.deepEqual(r4.added, [])

      const reports = readdirSync(dir).filter((n) => n.startsWith('rapport-vulnerabilites-'))
      assert.equal(reports.length, 4)
      assert.match(readFileSync(join(dir, reports[0]), 'utf8'), /Client : <b>Test<\/b>/)
    } finally {
      telnet.close()
      vnc.close()
      rmSync(dir, { recursive: true, force: true })
    }
  })
}
