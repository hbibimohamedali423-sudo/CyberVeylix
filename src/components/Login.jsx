import { useState } from 'react'
import { supabase } from '../supabaseClient'
import { useI18n } from '../i18n/context.js'
import { LanguageSelect } from '../i18n/index.jsx'

export default function Login() {
  const { t } = useI18n()
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
    else if (!data.session) setMsg(t('login.confirmEmail'))
  }

  return (
    <div style={{ display: 'grid', placeItems: 'center', minHeight: '100vh', padding: 16 }}>
      <div className="card" style={{ width: 'min(380px, 100%)' }}>
        <div className="logo" style={{ marginBottom: 14 }}>CyberVeylix<small>NETWORK INTELLIGENCE &amp; CYBERSECURITY</small></div>
        <LanguageSelect />
        <input type="email" placeholder={t('login.email')} value={email} onChange={(e) => setEmail(e.target.value)} />
        <input type="password" placeholder={t('login.password')} value={password} onChange={(e) => setPassword(e.target.value)} />
        <button onClick={signIn}>{t('login.signIn')}</button>
        <button className="x wide" onClick={signUp}>{t('login.signUp')}</button>
        {msg && <p className="m" style={{ marginTop: 10 }}>{msg}</p>}
      </div>
    </div>
  )
}
