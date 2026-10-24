import { useState, useEffect } from 'react'

export default function useStored(key, init = []) {
  const [v, setV] = useState(() => {
    try { return JSON.parse(localStorage.getItem(key)) ?? init } catch { return init }
  })
  useEffect(() => {
    try { localStorage.setItem(key, JSON.stringify(v)) } catch { /* stockage indisponible */ }
  }, [key, v])
  return [v, setV]
}
