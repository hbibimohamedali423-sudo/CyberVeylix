import { useCallback, useEffect, useState } from 'react'
import { supabase } from './supabaseClient'

// Lit/écrit une table Supabase pour l’utilisateur connecté (RLS : user_id = auth.uid()).
export default function useRows(table, user) {
  const [rows, setRows] = useState([])
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    const { data, error: e } = await supabase.from(table).select('*').order('created_at')
    if (e) setError(e.message)
    else { setRows(data); setError('') }
  }, [table])

  useEffect(() => {
    if (user) load()
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

  const update = async (id, patch) => {
    const { error: e } = await supabase.from(table).update(patch).eq('id', id)
    if (e) setError(e.message)
    else load()
  }

  return { rows, error, add, remove, update }
}
