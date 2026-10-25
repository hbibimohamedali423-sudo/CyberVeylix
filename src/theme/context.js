import { createContext, useContext } from 'react'

export const THEMES = ['dark', 'light']
export const DEFAULT_THEME = 'dark'
export const THEME_STORAGE_KEY = 'cyberveylix.theme'

export const isTheme = (value) => THEMES.includes(value)

export const ThemeContext = createContext(null)

export function useTheme() {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme doit être utilisé dans ThemeProvider')
  return ctx
}
