import { NAV } from '../constants'
import { useI18n } from '../i18n/context.js'
import { LanguageSelect } from '../i18n/index.jsx'
import { useTheme } from '../theme/context.js'

export default function Sidebar({ active, onChange }) {
  const { t } = useI18n()
  const { theme, toggleTheme } = useTheme()
  const dark = theme === 'dark'
  return (
    <div>
      <nav>{NAV.map((n, i) => <a key={n} className={i === active ? 'on' : ''} onClick={() => onChange(i)}><i />{t(`nav.${n}`)}</a>)}</nav>
      <div className="promo"><div className="shield" /><b>{t('sidebar.promoTitle')}</b><span>{t('sidebar.promoSub')}</span></div>
      <button type="button" className="tg-btn" role="switch" aria-checked={dark}
        aria-label={t('sidebar.toggleTheme')} onClick={toggleTheme}>
        <span>{dark ? '◐' : '☀'} {dark ? t('sidebar.darkMode') : t('sidebar.lightMode')}</span>
        <span className={`sw${dark ? '' : ' off'}`} aria-hidden="true" />
      </button>
      <div className="lang-row"><LanguageSelect /></div>
    </div>
  )
}
