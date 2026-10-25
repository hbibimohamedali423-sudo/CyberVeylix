import { useLayoutEffect, useState } from 'react'
import { ThemeContext, DEFAULT_THEME, THEME_STORAGE_KEY, isTheme } from './context'

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(() => {
    try {
      const saved = localStorage.getItem(THEME_STORAGE_KEY)
      return isTheme(saved) ? saved : DEFAULT_THEME
    } catch {
      return DEFAULT_THEME
    }
  })

  // useLayoutEffect : le thème est appliqué avant le premier repaint (pas de flash).
  useLayoutEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme)
    } catch {
      // Stockage indisponible (mode privé) : le thème reste actif pour la session.
    }
  }, [theme])

  const setTheme = (next) => {
    if (isTheme(next)) setThemeState(next)
  }
  const toggleTheme = () => setThemeState((prev) => (prev === 'dark' ? 'light' : 'dark'))

  return <ThemeContext.Provider value={{ theme, setTheme, toggleTheme }}>{children}</ThemeContext.Provider>
}
