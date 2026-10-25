import { useEffect, useState } from 'react'
import { LANGS, DEFAULT_LANG, STORAGE_KEY, translate, dirOf, localeOf, isSupported } from './messages'
import { I18nContext, useI18n } from './context'

export function I18nProvider({ children }) {
  const [lang, setLangState] = useState(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY)
      return isSupported(saved) ? saved : DEFAULT_LANG
    } catch {
      return DEFAULT_LANG
    }
  })
  const dir = dirOf(lang)
  const locale = localeOf(lang)

  useEffect(() => {
    document.documentElement.lang = lang
    document.documentElement.dir = dir
    try {
      localStorage.setItem(STORAGE_KEY, lang)
    } catch {
      // Stockage indisponible (mode privé) : la langue reste active pour la session.
    }
  }, [lang, dir])

  const setLang = (code) => {
    if (isSupported(code)) setLangState(code)
  }
  const t = (key, vars) => translate(lang, key, vars)

  return <I18nContext.Provider value={{ lang, dir, locale, setLang, t }}>{children}</I18nContext.Provider>
}

export function LanguageSelect({ className = 'lang-select' }) {
  const { lang, setLang, t } = useI18n()
  return (
    <label className="lang-picker">
      <span aria-hidden="true">🌐</span>
      <span className="sr-only">{t('sidebar.language')}</span>
      <select className={className} aria-label={t('sidebar.language')} value={lang} onChange={(e) => setLang(e.target.value)}>
        {LANGS.map((l) => <option key={l.code} value={l.code}>{l.label}</option>)}
      </select>
    </label>
  )
}
