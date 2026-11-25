// Tests de l'écoute passive LLDP / CDP : décodage, trames hors sujet ignorées, tronquées sans plantage.
import assert from 'node:assert/strict'
import { parseLldp, parseCdp } from '../lib/parse-lldp.mjs'
import { lldpFrame, cdpFrame, arpFrame } from './frames.mjs'

export function lldpChecks(check) {
  check('LLDP : switch décodé (nom, port, gestion, capacité bridge)', () => {
    const r = parseLldp(lldpFrame({ src: '00:1b:54:00:00:01', chassisMac: '00:1b:54:aa:bb:cc', portId: 'Gi1/0/7', sysName: 'SW-CORE', sysDescr: 'Cisco IOS C2960X', mgmtIp: '10.15.0.2' }))
    assert.equal(r.source, 'lldp')
    assert.equal(r.senderMac, '00:1b:54:00:00:01')
    assert.equal(r.chassisId, '00:1b:54:aa:bb:cc')
    assert.equal(r.portId, 'Gi1/0/7')
    assert.equal(r.sysName, 'SW-CORE')
    assert.equal(r.mgmtIp, '10.15.0.2')
    assert.deepEqual([r.caps.bridge, r.caps.wlanAp], [true, false])
  })

  check('LLDP : point d\'accès Wi-Fi (capacité wlanAp)', () => {
    const r = parseLldp(lldpFrame({ src: '94:b4:0f:00:00:0a', chassisMac: '94:b4:0f:00:00:0a', sysName: 'AP-HALL', sysDescr: 'Aruba AP-305', bridge: true, wlanAp: true, mgmtIp: '10.15.0.50' }))
    assert.deepEqual([r.sysName, r.caps.wlanAp, r.mgmtIp], ['AP-HALL', true, '10.15.0.50'])
  })

  check('CDP : switch Cisco décodé (nom, port, gestion)', () => {
    const r = parseCdp(cdpFrame({ src: '00:0c:29:00:00:02', sysName: 'SW-ETAGE', portId: 'GigabitEthernet0/1', mgmtIp: '10.15.0.3', sysDescr: 'cisco WS-C2960' }))
    assert.equal(r.source, 'cdp')
    assert.deepEqual([r.sysName, r.portId, r.mgmtIp, r.caps.bridge], ['SW-ETAGE', 'GigabitEthernet0/1', '10.15.0.3', true])
  })

  check('LLDP / CDP : trames hors sujet ignorées, tronquées → null sans plantage', () => {
    assert.equal(parseLldp(arpFrame({ op: 2, senderMac: 'aa:bb:cc:00:11:22', senderIp: '10.0.0.1' })), null)
    assert.equal(parseCdp(arpFrame({ op: 2, senderMac: 'aa:bb:cc:00:11:22', senderIp: '10.0.0.1' })), null)
    assert.equal(parseLldp(null), null)
    assert.equal(parseLldp(Buffer.alloc(4)), null)
    const full = lldpFrame({ src: '00:1b:54:00:00:01', chassisMac: '00:1b:54:aa:bb:cc', sysName: 'SW' })
    for (let n = 0; n <= full.length; n += 3) assert.doesNotThrow(() => parseLldp(full.subarray(0, n)))
    const cdp = cdpFrame({ src: '00:0c:29:00:00:02', sysName: 'SW' })
    for (let n = 0; n <= cdp.length; n += 3) assert.doesNotThrow(() => parseCdp(cdp.subarray(0, n)))
  })
}
