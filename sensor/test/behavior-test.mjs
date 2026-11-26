// Tests du moteur de comportement et de la liste de menaces (purs, sans réseau).
// Adresses « malveillantes » : plages de DOCUMENTATION (RFC 5737) et domaines example, jamais de vraies.
import assert from 'node:assert/strict'
import { createThreatList, parseThreatFeed, parseCidr, ipToInt } from '../lib/threatlist.mjs'
import { createBehaviorEngine } from '../lib/behavior.mjs'

export function threatlistChecks(check) {
  check('threatlist : ipToInt et parseCidr', () => {
    assert.equal(ipToInt('0.0.0.0'), 0)
    assert.equal(ipToInt('255.255.255.255'), 0xffffffff)
    assert.equal(ipToInt('256.0.0.1'), null)
    assert.equal(ipToInt('abc'), null)
    assert.deepEqual(parseCidr('203.0.113.0/24'), { lo: ipToInt('203.0.113.0'), hi: ipToInt('203.0.113.255') })
    assert.equal(parseCidr('203.0.113.0/33'), null)
  })

  check('threatlist : analyse du fichier (commentaires et étiquettes ignorés/retenus)', () => {
    const e = parseThreatFeed('# feed\n\n203.0.113.5\n198.51.100.0/24 , Botnet X\nbad.example , Malware\n  \n')
    assert.deepEqual(e.map((x) => x.value), ['203.0.113.5', '198.51.100.0/24', 'bad.example'])
    assert.equal(e[1].label, 'Botnet X')
  })

  check('threatlist : correspondance IP exacte et par plage', () => {
    const tl = createThreatList(['203.0.113.5', '198.51.100.0/24'])
    assert.ok(tl.matchIp('203.0.113.5'))
    assert.equal(tl.matchIp('203.0.113.6'), null)
    assert.ok(tl.matchIp('198.51.100.200'))
    assert.equal(tl.matchIp('8.8.8.8'), null)
  })

  check('threatlist : correspondance domaine (exacte et parent)', () => {
    const tl = createThreatList([{ value: 'bad.example', label: 'C2' }])
    assert.equal(tl.matchDomain('bad.example').label, 'C2')
    assert.ok(tl.matchDomain('sub.bad.example')) // sous-domaine d'un domaine listé
    assert.equal(tl.matchDomain('good.example'), null)
    assert.equal(tl.matchDomain('notbad.example'), null) // pas une correspondance de suffixe partiel
  })

  check('threatlist : taille comptée, entrées invalides ignorées', () => {
    const tl = createThreatList(['203.0.113.5', 'pas-une-adresse', '198.51.100.0/24'])
    assert.equal(tl.size(), 2)
  })
}

export function behaviorChecks(check) {
  const T0 = Date.parse('2026-11-26T12:00:00Z')
  const run = (engine, flows) => { const out = []; for (const f of flows) out.push(...engine.observe(f, f.ts)); return out }

  check('comportement : destination malveillante connue -> alerte critique', () => {
    const tl = createThreatList(['203.0.113.9'])
    const eng = createBehaviorEngine({ threatList: tl })
    const ev = eng.observe({ src: '192.168.1.10', dst: '203.0.113.9', ts: T0 }, T0)
    assert.equal(ev.length, 1)
    assert.equal(ev[0].type, 'malware_c2')
    assert.equal(ev[0].severity, 'c')
    assert.equal(ev[0].ip, '192.168.1.10') // l'auteur, pas la cible
  })

  check('comportement : domaine malveillant détecté par le nom', () => {
    const tl = createThreatList([{ value: 'c2.example', label: 'C2' }])
    const eng = createBehaviorEngine({ threatList: tl })
    const ev = eng.observe({ src: '192.168.1.10', dst: null, name: 'login.c2.example', ts: T0 }, T0)
    assert.equal(ev[0]?.type, 'malware_c2')
  })

  check('comportement : balayage horizontal (beaucoup de cibles)', () => {
    const eng = createBehaviorEngine({ horizontalThreshold: 15, windowMs: 60000 })
    const flows = Array.from({ length: 15 }, (_, i) => ({ src: '192.168.1.50', dst: `192.168.1.${100 + i}`, ts: T0 + i * 100 }))
    const ev = run(eng, flows)
    assert.ok(ev.some((e) => e.type === 'lateral_scan' && e.severity === 'h'))
  })

  check('comportement : sous le seuil, aucune alerte', () => {
    const eng = createBehaviorEngine({ horizontalThreshold: 15 })
    const flows = Array.from({ length: 5 }, (_, i) => ({ src: '192.168.1.50', dst: `192.168.1.${100 + i}`, ts: T0 + i * 100 }))
    assert.equal(run(eng, flows).filter((e) => e.type === 'lateral_scan').length, 0)
  })

  check('comportement : cibles anciennes hors fenêtre ne comptent pas', () => {
    const eng = createBehaviorEngine({ horizontalThreshold: 15, windowMs: 60000 })
    run(eng, Array.from({ length: 10 }, (_, i) => ({ src: '192.168.1.50', dst: `192.168.1.${100 + i}`, ts: T0 + i * 100 })))
    // 10 nouvelles cibles, mais 5 min plus tard : les premières sont hors fenêtre -> pas de balayage
    const later = T0 + 5 * 60000
    const ev = run(eng, Array.from({ length: 10 }, (_, i) => ({ src: '192.168.1.50', dst: `10.0.0.${i}`, ts: later + i * 100 })))
    assert.equal(ev.filter((e) => e.type === 'lateral_scan').length, 0)
  })

  check('comportement : balayage vertical (beaucoup de ports d’une cible)', () => {
    const eng = createBehaviorEngine({ verticalThreshold: 10, windowMs: 60000, horizontalThreshold: 999 })
    const flows = Array.from({ length: 10 }, (_, i) => ({ src: '192.168.1.50', dst: '192.168.1.10', dstPort: 20 + i, ts: T0 + i * 100 }))
    const ev = run(eng, flows)
    assert.ok(ev.some((e) => e.type === 'port_scan' && e.severity === 'm'))
  })

  check('comportement : anti-répétition (une seule alerte par fenêtre de refroidissement)', () => {
    const eng = createBehaviorEngine({ horizontalThreshold: 5, windowMs: 60000, cooldownMs: 10 * 60000 })
    const ev = run(eng, Array.from({ length: 30 }, (_, i) => ({ src: '192.168.1.50', dst: `192.168.1.${100 + i}`, ts: T0 + i * 100 })))
    assert.equal(ev.filter((e) => e.type === 'lateral_scan').length, 1)
  })

  check('comportement : mode apprentissage n’alerte pas mais apprend la normale', () => {
    const eng = createBehaviorEngine({ alert: false, horizontalThreshold: 5 })
    const ev = run(eng, Array.from({ length: 10 }, (_, i) => ({ src: '192.168.1.50', dst: `192.168.1.${100 + i}`, ts: T0 + i * 100 })))
    assert.equal(ev.length, 0)
    assert.ok(eng.snapshot().sources >= 1)
  })

  check('comportement : expansion anormale par rapport à la normale apprise', () => {
    const eng = createBehaviorEngine({ fanoutMin: 10, fanoutFactor: 4, horizontalThreshold: 999, windowMs: 60000 })
    // Normale basse apprise sur plusieurs fenêtres (2 pairs à chaque fois).
    for (let w = 0; w < 30; w++) {
      const base = T0 + w * 5 * 60000
      eng.observe({ src: '192.168.1.60', dst: '192.168.1.1', ts: base }, base)
      eng.observe({ src: '192.168.1.60', dst: '192.168.1.2', ts: base + 100 }, base + 100)
    }
    const burst = T0 + 160 * 60000 // après toute la phase d’apprentissage (30 fenêtres × 5 min)
    const ev = run(eng, Array.from({ length: 20 }, (_, i) => ({ src: '192.168.1.60', dst: `10.0.0.${i}`, ts: burst + i * 50 })))
    assert.ok(ev.some((e) => e.type === 'anomaly_fanout'))
  })
}
