import { lazy, Suspense, useState } from 'react'
import { supabase } from '../supabaseClient'
import { useI18n } from '../i18n/context.js'
import { LanguageSelect } from '../i18n/index.jsx'
import './Login.css'

// Scène 3D chargée à part : la bibliothèque 3D n'alourdit pas le reste de l'application.
const LoginScene = lazy(() => import('./LoginScene.jsx'))

// Inscription masquée par défaut : CyberVeylix est réservé aux comptes créés par l'administrateur.
// ATTENTION : masquer le bouton ne suffit pas. Désactiver aussi les inscriptions côté serveur :
// Supabase > Authentication > Sign In / Providers > « Allow new users to sign up » : OFF.
const ALLOW_SIGNUP = import.meta.env.VITE_ALLOW_SIGNUP === 'true'

const SCENE_KEYS = ['camera', 'computer', 'phone', 'switch', 'wifi', 'router', 'intruder']

export default function Login() {
  const { t } = useI18n()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  const signIn = async (e) => {
    e?.preventDefault()
    setBusy(true)
    const { error } = await supabase.auth.signInWithPassword({ email, password })
    setMsg(error ? error.message : '')
    setBusy(false)
  }
  const signUp = async () => {
    const { data, error } = await supabase.auth.signUp({ email, password })
    if (error) setMsg(error.message)
    else if (!data.session) setMsg(t('login.confirmEmail'))
  }

  const labels = SCENE_KEYS.map((key) => ({ key, text: t(`login.scene.${key}`), danger: key === 'intruder' }))

  return (
    <div className="login-hud">
      <div className="login-hud__corners">
        <span>CYBERVEYLIX // {t('login.secureAccess')}</span>
        <LanguageSelect />
      </div>

      <header className="login-hud__head">
        <h1>{t('login.title')}</h1>
        <p>{t('login.subtitle')}</p>
      </header>

      <Suspense fallback={<div className="login-hud__scene" aria-hidden="true" />}>
        <LoginScene labels={labels} />
      </Suspense>

      <div className="login-hud__brand">CyberVeylix</div>

      <form className="login-hud__form" onSubmit={signIn}>
        <label className="login-hud__field">
          <span aria-hidden="true">ID</span>
          <input type="email" autoComplete="email" required placeholder={t('login.email')} aria-label={t('login.email')} value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label className="login-hud__field">
          <span aria-hidden="true">KEY</span>
          <input type="password" autoComplete="current-password" required placeholder={t('login.password')} aria-label={t('login.password')} value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <button type="submit" className="login-hud__btn" disabled={busy}>{t('login.signIn')}</button>
        {ALLOW_SIGNUP && <button type="button" className="login-hud__link" onClick={signUp}>{t('login.signUp')}</button>}
        {msg && <p className="login-hud__msg" role="alert">{msg}</p>}
      </form>

      <footer className="login-hud__foot">
        <span>{t('login.footHttps')}</span>
        <span>{t('login.footIsolated')}</span>
        <span>{t('login.footHashed')}</span>
      </footer>
    </div>
  )
}
