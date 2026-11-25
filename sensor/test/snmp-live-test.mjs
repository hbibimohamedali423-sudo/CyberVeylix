// Tests du client SNMP sur un VRAI échange UDP : un agent net-snmp local joue le rôle d'un switch.
// (Lecture seule : le client n'envoie que GET / GETBULK.)
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import dgram from 'node:dgram'
import { createSnmpClient, compareOids } from '../lib/snmp-client.mjs'
import { OID, parseIfNames } from '../lib/snmp-mibs.mjs'
import { parseSnmpConfig, parseTarget, isAllowedTarget } from '../lib/snmp-config.mjs'

const require = createRequire(import.meta.url)

const freePort = () => new Promise((resolve) => { const s = dgram.createSocket('udp4'); s.bind(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)) }) })

export async function startAgent({ community = 'cv-lecture', v3 = null } = {}) {
  const snmp = require('net-snmp')
  const port = await freePort()
  const agent = snmp.createAgent({ port, address: '127.0.0.1', disableAuthorization: false, accessControlModelType: snmp.AccessControlModelType.None }, () => {})
  const authorizer = agent.getAuthorizer()
  authorizer.addCommunity(community)
  if (v3) authorizer.addUser({ name: v3.user, level: snmp.SecurityLevel.authPriv, authProtocol: snmp.AuthProtocols.sha256, authKey: v3.authKey, privProtocol: snmp.PrivProtocols.aes, privKey: v3.privKey })
  const mib = agent.getMib()
  mib.registerProvider({ name: 'sysName', type: snmp.MibProviderType.Scalar, oid: '1.3.6.1.2.1.1.5', scalarType: snmp.ObjectType.OctetString, maxAccess: snmp.MaxAccess['read-only'] })
  mib.setScalarValue('sysName', 'SW-TEST')
  mib.registerProvider({
    name: 'ifXTable', type: snmp.MibProviderType.Table, oid: '1.3.6.1.2.1.31.1.1.1', maxAccess: snmp.MaxAccess['not-accessible'],
    tableColumns: [
      { number: 1, name: 'ifName', type: snmp.ObjectType.OctetString, maxAccess: snmp.MaxAccess['read-only'] },
      { number: 99, name: 'idx', type: snmp.ObjectType.Integer, maxAccess: snmp.MaxAccess['not-accessible'] },
    ],
    tableIndex: [{ columnName: 'idx' }],
  })
  for (const [i, n] of [[1, 'Gi1/0/1'], [2, 'Gi1/0/2'], [3, 'Gi1/0/3']]) mib.addTableRow('ifXTable', [n, i])
  return { port, close: () => agent.close() }
}

export function snmpLiveChecks(check, checkAsync) {
  check('snmp.json : identifiants validés, adresses publiques refusées, aucun secret dans les messages', () => {
    const ok = parseSnmpConfig('﻿{"credentials":[{"version":"2c","community":"lecture"},{"version":"3","user":"cv","authProtocol":"sha256","authKey":"abcdefgh","privProtocol":"aes","privKey":"12345678"}],"targets":["10.15.0.2","192.168.1.3:1161"]}')
    assert.equal(ok.config.credentials.length, 2)
    assert.deepEqual(ok.config.targets, [{ host: '10.15.0.2', port: 161 }, { host: '192.168.1.3', port: 1161 }])
    assert.equal(ok.config.auto, true)
    assert.deepEqual(parseSnmpConfig('{"community":"public2"}').config.credentials, [{ version: '2c', community: 'public2' }])
    const bad = parseSnmpConfig('{"credentials":[{"version":"3","user":"cv","authKey":"court-secret"}]}')
    assert.ok(!bad.error) // 12 caractères : accepté
    const tooShort = parseSnmpConfig('{"credentials":[{"version":"3","user":"cv","authKey":"Xy7"}]}')
    assert.ok(tooShort.error && !tooShort.error.includes('Xy7'))
    assert.ok(parseSnmpConfig('{"credentials":[{"version":"2c","community":"a"}],"targets":["8.8.8.8"]}').error.includes('refusé'))
    assert.ok(parseSnmpConfig('pas du json').error)
    assert.ok(parseSnmpConfig('{"credentials":[]}').error)
    assert.equal(parseTarget('10.0.0.1:99999'), null)
    assert.equal(isAllowedTarget('172.32.0.1'), false)
    assert.equal(isAllowedTarget('172.20.0.1'), true)
  })

  checkAsync('SNMP réel (UDP) : lecture d\'une valeur et parcours d\'une table en v2c', async () => {
    const a = await startAgent()
    const c = createSnmpClient({ timeoutMs: 1500, retries: 0 })
    try {
      const p = await c.probe({ host: '127.0.0.1', port: a.port }, [{ version: '2c', community: 'mauvaise' }, { version: '2c', community: 'cv-lecture' }])
      assert.ok(p, 'aucun identifiant accepté')
      assert.equal(p.cred.community, 'cv-lecture') // le premier, faux, a été écarté
      const names = parseIfNames((await c.walk(p.session, OID.ifName)).rows, [])
      assert.deepEqual([...names.entries()], [[1, 'Gi1/0/1'], [2, 'Gi1/0/2'], [3, 'Gi1/0/3']])
      const sys = await c.get(p.session, [OID.sysName])
      assert.equal(sys.rows[0].value.toString(), 'SW-TEST')
      c.close(p.session)
    } finally { a.close() }
  })

  checkAsync('SNMP réel (UDP) : SNMPv3 authentifié et chiffré (SHA-256 / AES)', async () => {
    const v3 = { user: 'cvreader', authKey: 'auth-secret-123', privKey: 'priv-secret-456' }
    const a = await startAgent({ v3 })
    const c = createSnmpClient({ timeoutMs: 1500, retries: 0 })
    try {
      const p = await c.probe({ host: '127.0.0.1', port: a.port }, [{ version: '3', user: 'cvreader', authProtocol: 'sha256', authKey: v3.authKey, privProtocol: 'aes', privKey: v3.privKey }])
      assert.ok(p)
      assert.equal((await c.walk(p.session, OID.ifName)).rows.length, 3)
      c.close(p.session)
      const wrong = await c.probe({ host: '127.0.0.1', port: a.port }, [{ version: '3', user: 'cvreader', authProtocol: 'sha256', authKey: 'mauvaise-cle-1', privProtocol: 'aes', privKey: v3.privKey }])
      assert.equal(wrong, null)
    } finally { a.close() }
  })

  checkAsync('SNMP : parcours toujours terminé (équipement qui boucle, fin de données, délai)', async () => {
    const vb = (oid) => ({ oid, value: 1 })
    const lib = (behaviour) => ({ isVarbindError: (v) => v.err === true, createSession: () => ({ getBulk: (oids, n, r, cb) => setImmediate(() => cb(null, [behaviour(oids[0])])), close() {} }), Version2c: 1 })
    const base = '1.3.6.1.4.1.9.9.23.1.2.1.1'
    // 1) l'équipement renvoie toujours la même ligne
    let c = createSnmpClient({ lib: lib(() => [vb(`${base}.6.1.1`)]) })
    assert.equal((await c.walk(c.open({ host: '10.0.0.1' }, { version: '2c', community: 'x' }), base)).rows.length, 1)
    // 2) fin de données signalée
    c = createSnmpClient({ lib: lib(() => [{ oid: base, err: true }]) })
    assert.equal((await c.walk(c.open({ host: '10.0.0.1' }, { version: '2c', community: 'x' }), base)).rows.length, 0)
    // 3) table infinie : bornée par maxRows
    let n = 0
    c = createSnmpClient({ maxRows: 50, lib: lib(() => Array.from({ length: 20 }, () => vb(`${base}.6.1.${++n}`))) })
    const r = await c.walk(c.open({ host: '10.0.0.1' }, { version: '2c', community: 'x' }), base)
    assert.deepEqual([r.rows.length, r.truncated], [50, true])
    assert.equal(compareOids('1.3.6.1.10', '1.3.6.1.9'), 1)
    assert.equal(compareOids('1.3.6', '1.3.6.1'), -1)
  })

  checkAsync('SNMP réel (UDP) : équipement muet → null rapidement (pas de blocage)', async () => {
    const port = await freePort()
    const c = createSnmpClient({ timeoutMs: 400, retries: 0 })
    const t0 = Date.now()
    assert.equal(await c.probe({ host: '127.0.0.1', port }, [{ version: '2c', community: 'x' }]), null)
    assert.ok(Date.now() - t0 < 3000)
  })
}
