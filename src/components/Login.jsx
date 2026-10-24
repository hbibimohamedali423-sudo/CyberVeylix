import { useState } from 'react'
import { supabase } from '../supabaseClient'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [msg, setMsg] = useState('')

  const signIn = async () => {
    const { error } = await supabase.auth.signInWithPassword({ email, password })
    setMsg(error ? error.message : '')
  }
  const signUp = async () => {
    const { data, error } = await supabase.auth.signUp({ email, password })
    if (error) setMsg(error.message)
    else if (!data.session) setMsg('Compte créé. Vérifiez votre e-mail pour confirmer, puis connectez-vous.')
  }

  return (
    <div style={{ display: 'grid', placeItems: 'center', minHeight: '100vh', padding: 16 }}>
      <div className="card" style={{ width: 'min(380px, 100%)' }}>
        <div className="logo" style={{ marginBottom: 14 }}>CyberVeylix<small>NETWORK INTELLIGENCE &amp; CYBERSECURITY</small></div>
        <input type="email" placeholder="E-mail" value={email} onChange={(e) => setEmail(e.target.value)} />
        <input type="password" placeholder="Mot de passe (8 caractères min.)" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button onClick={signIn}>Se connecter</button>
        <button className="x wide" onClick={signUp}>Créer un compte</button>
        {msg && <p className="m" style={{ marginTop: 10 }}>{msg}</p>}
      </div>
    </div>
  )
}
