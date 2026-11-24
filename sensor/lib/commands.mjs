// CyberVeylix Sensor — exécution des demandes écrites par la page web dans la table sensor_commands.
// La page n'exécute rien : elle dépose une demande ; ce module, dans le capteur installé sur le PC permanent,
// la réclame (une seule fois), l'exécute avec un gestionnaire de la LISTE BLANCHE, puis écrit le résultat.
// Le résultat est un petit JSON { code, ... } que la page traduit dans la langue de l'utilisateur.
// Client Supabase injecté : testable avec un faux client (sensor/test/commands-test.mjs).

export const POLL_MS = 5000
export const EXPIRE_MS = 15 * 60 * 1000 // une demande plus ancienne n'est plus exécutée (le capteur était éteint)
const RESULT_MAX = 3900

export const encodeResult = (obj) => {
  const text = JSON.stringify(obj)
  return text.length <= RESULT_MAX ? text : JSON.stringify({ code: obj.code, truncated: true })
}

// handlers : { kind: async (params, command) => objet résultat { code, ... } }. Un type absent est refusé.
export function createCommandRunner({ client, sensorName, handlers, log = console.log, now = () => new Date(), pollMs = POLL_MS }) {
  let sensorId = null
  let timer = null
  let busy = false

  async function findSensorId() {
    if (sensorId) return sensorId
    const { data, error } = await client.from('sensors').select('id').eq('name', sensorName)
    if (error || !data || !data.length) return null // pas encore enregistré (le pouls le crée) : on réessaie
    sensorId = data[0].id
    return sensorId
  }

  const finish = (id, status, result) => client.from('sensor_commands')
    .update({ status, result: encodeResult(result), finished_at: now().toISOString() })
    .eq('id', id)

  // Au démarrage : ce qui était « en cours » avant l'arrêt du capteur ne l'est plus.
  async function cleanup(id) {
    const stamp = now().toISOString()
    await client.from('sensor_commands')
      .update({ status: 'failed', result: encodeResult({ code: 'restarted' }), finished_at: stamp })
      .eq('sensor_id', id).eq('status', 'running')
  }

  async function expireOld(id) {
    const cutoff = new Date(now().getTime() - EXPIRE_MS).toISOString()
    await client.from('sensor_commands')
      .update({ status: 'rejected', result: encodeResult({ code: 'expired' }), finished_at: now().toISOString() })
      .eq('sensor_id', id).eq('status', 'pending').lt('created_at', cutoff)
  }

  let cleaned = false
  async function tick() {
    if (busy) return 0
    busy = true
    let handled = 0
    try {
      const id = await findSensorId()
      if (!id) return 0
      if (!cleaned) { await cleanup(id); cleaned = true }
      await expireOld(id)
      const { data, error } = await client.from('sensor_commands').select('*')
        .eq('sensor_id', id).eq('status', 'pending').order('created_at')
      if (error) { log('⚠ Commandes : ' + error.message); return 0 }
      for (const cmd of data || []) {
        // Réclamation atomique : seule la mise à jour « pending → running » réussie exécute la demande.
        const claim = await client.from('sensor_commands')
          .update({ status: 'running', started_at: now().toISOString() })
          .eq('id', cmd.id).eq('status', 'pending').select('id')
        if (claim.error || !claim.data || !claim.data.length) continue
        handled += 1
        const handler = Object.hasOwn(handlers, cmd.kind) ? handlers[cmd.kind] : null
        if (!handler) {
          await finish(cmd.id, 'rejected', { code: 'unsupported', kind: cmd.kind })
          log(`Commande refusée (type non pris en charge par cette version) : ${cmd.kind}`)
          continue
        }
        try {
          log(`Commande reçue : ${cmd.kind}`)
          const result = await handler(cmd.params || {}, cmd)
          const status = result && result.code === 'rejected' ? 'rejected' : (result && result.failed ? 'failed' : 'done')
          await finish(cmd.id, status, result || { code: 'done' })
        } catch (e) {
          await finish(cmd.id, 'failed', { code: 'error', message: String(e && e.message || e).slice(0, 300) })
          log(`⚠ Commande ${cmd.kind} en échec : ${e && e.message}`)
        }
      }
    } catch (e) {
      log('⚠ Commandes : ' + (e && e.message))
    } finally {
      busy = false
    }
    return handled
  }

  return {
    tick,
    start() { if (!timer) { tick(); timer = setInterval(tick, pollMs); timer.unref?.() } },
    stop() { if (timer) clearInterval(timer); timer = null },
  }
}
