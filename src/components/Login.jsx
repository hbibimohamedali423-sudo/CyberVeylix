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

// Ornements « viseur » autour du titre (purement décoratifs).
function HeadDeco() {
  return (
    <svg className="login-hud__deco" viewBox="0 0 640 90" aria-hidden="true">
      <g fill="none" stroke="#33E6F5" strokeWidth="1.4">
        <path d="M150 58 H262 M378 58 H490" />
        <path d="M118 60 l-6 -4 m6 4 l-6 4 M110 60 l-6 -4 m6 4 l-6 4 M102 60 l-6 -4 m6 4 l-6 4" />
        <path d="M522 60 l6 -4 m-6 4 l6 4 M530 60 l6 -4 m-6 4 l6 4 M538 60 l6 -4 m-6 4 l6 4" />
        <path d="M150 70 V84 H200 M490 70 V84 H440" />
        <circle cx="150" cy="90" r="3" /><circle cx="490" cy="90" r="3" />
      </g>
      <rect x="112" y="80" width="30" height="6" fill="#2D5C66" /><rect x="498" y="80" width="30" height="6" fill="#2D5C66" />
    </svg>
  )
}

// Ailes en circuit de part et d'autre de l'œil, comme un cadre de visée.
function Wings() {
  const side = (s) => {
    const x = (v) => 500 + s * v
    return (
      <g key={s}>
        <path d={`M${x(215)} 175 V70 L${x(198)} 56 H${x(168)}`} stroke="#33E6F5" strokeWidth="2" fill="none" />
        <rect x={s > 0 ? x(170) : x(220)} y="48" width="50" height="8" fill="#2D5C66" />
        <rect x={s > 0 ? x(222) : x(228)} y="66" width="6" height="6" fill="#33E6F5" />
        <path d={`M${x(215)} 160 L${x(250)} 192 H${x(400)} L${x(422)} 176 H${x(470)}`} stroke="#33E6F5" strokeWidth="1.5" fill="none" opacity=".85" />
        <path d={`M${x(160)} 150 H${x(205)} L${x(245)} 186`} stroke="#2D5C66" strokeWidth="1.3" fill="none" strokeDasharray="6 4" />
        <path d={`M${x(250)} 220 H${x(330)} L${x(372)} 258 H${x(450)}`} stroke="#2D5C66" strokeWidth="1.3" fill="none" />
        <path d={`M${x(120)} 235 L${x(190)} 235 L${x(240)} 282 V300 L${x(190)} 254 H${x(120)} Z`} fill="#13303A" stroke="#2D5C66" />
        <path d={`M${x(196)} 233 L${x(252)} 282 V312 L${x(232)} 332`} stroke="#33E6F5" strokeWidth="2.2" fill="none" />
        <path d={`M${x(436)} 300 h12 m-6 -6 v12 M${x(300)} 330 h12 m-6 -6 v12`} stroke="#4F7880" strokeWidth="1" />
      </g>
    )
  }
  return (
    <svg className="login-hud__wings" viewBox="0 0 1000 520" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
      {side(-1)}{side(1)}
    </svg>
  )
}

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
        <HeadDeco />
        <h1>{t('login.title')}</h1>
        <p>{t('login.subtitle')}</p>
      </header>

      <div className="login-hud__stage">
        <Wings />
        <Suspense fallback={<div className="login-hud__scene" aria-hidden="true" />}>
          <LoginScene labels={labels} />
        </Suspense>
      </div>

      <div className="login-hud__brand">CyberVeylix</div>
      <div className="login-hud__wire" aria-hidden="true" />

      <form className="login-hud__form" onSubmit={signIn}>
        <div className="login-hud__fields">
        <label className="login-hud__field">
          <span aria-hidden="true">ID</span>
          <input type="email" autoComplete="email" required placeholder={t('login.email')} aria-label={t('login.email')} value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label className="login-hud__field">
          <span aria-hidden="true">KEY</span>
          <input type="password" autoComplete="current-password" required placeholder={t('login.password')} aria-label={t('login.password')} value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        </div>
        <div className="login-hud__btnwrap">
          <button type="submit" className="login-hud__btn" disabled={busy}>{t('login.signIn')}</button>
        </div>
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
