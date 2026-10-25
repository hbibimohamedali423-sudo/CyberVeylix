import { useCallback, useEffect, useState } from 'react'
import { supabase } from './supabaseClient'

// Lit/écrit une table Supabase pour l’utilisateur connecté (RLS : user_id = auth.uid()).
export default function useRows(table, user) {
  const [rows, setRows] = useState([])
  const [error, setError] = useState('')

  const load = useCallback(async (isActive = () => true) => {
    const { data, error: e } = await supabase.from(table).select('*').order('created_at')
    if (!isActive()) return
    if (e) setError(e.message)
    else { setRows(data); setError('') }
  }, [table])

  useEffect(() => {
    if (!user) return
    let active = true
    const isActive = () => active
    const first = setTimeout(() => { load(isActive) }, 0)
    const t = setInterval(() => { load(isActive) }, 15000)
    return () => { active = false; clearTimeout(first); clearInterval(t) }
  }, [user, load])

  const add = async (row) => {
    const { error: e } = await supabase.from(table).insert(row)
    if (e) setError(e.message)
    else load()
  }

  const remove = async (i) => {
    const { error: e } = await supabase.from(table).delete().eq('id', rows[i].id)
    if (e) setError(e.message)
    else load()
  }

  // Renvoie null si la mise à jour réussit, sinon le message d’erreur Supabase.
  const update = async (id, patch) => {
    const { error: e } = await supabase.from(table).update(patch).eq('id', id)
    if (e) { setError(e.message); return e.message }
    load()
    return null
  }

  return { rows, error, add, remove, update }
}
