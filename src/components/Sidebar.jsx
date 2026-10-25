import { NAV } from '../constants'
import { useI18n } from '../i18n/context.js'
import { LanguageSelect } from '../i18n/index.jsx'

export default function Sidebar({ active, onChange }) {
  const { t } = useI18n()
  return (
    <div>
      <nav>{NAV.map((n, i) => <a key={n} className={i === active ? 'on' : ''} onClick={() => onChange(i)}><i />{t(`nav.${n}`)}</a>)}</nav>
      <div className="promo"><div className="shield" /><b>{t('sidebar.promoTitle')}</b><span>{t('sidebar.promoSub')}</span></div>
      <div className="tg"><span>◐ {t('sidebar.darkMode')}</span><div className="sw" /></div>
      <div className="lang-row"><LanguageSelect /></div>
    </div>
  )
}
