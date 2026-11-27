import { useEffect, useRef, useState } from 'react'
import { useI18n } from '../i18n/context.js'
import { searchAll } from '../lib/findings.js'

const PAGE_OF = { device: 'devices', alert: 'threats', vuln: 'vulns' }

// Recherche globale (Ctrl + K) dans les données enregistrées : appareils, alertes, vulnérabilités.
function SearchBox({ data, onNavigate }) {
  const { t } = useI18n()
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const ref = useRef(null)
  const results = searchAll(data, q)

  useEffect(() => {
    const onKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); ref.current?.focus(); setOpen(true) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const go = (r) => { onNavigate?.(PAGE_OF[r.kind]); setOpen(false); setQ('') }
  const onKeyDown = (e) => {
    if (e.key === 'Escape') { setOpen(false); e.currentTarget.blur() }
    else if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(a + 1, results.length - 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)) }
    else if (e.key === 'Enter' && results[active]) go(results[active])
  }

  return (
    <div className="search search-live">
      <input ref={ref} value={q} placeholder={t('topbar.search')} aria-label={t('topbar.search')}
        role="combobox" aria-expanded={open && q.trim().length >= 2} aria-controls="search-results" aria-autocomplete="list"
        onChange={(e) => { setQ(e.target.value); setOpen(true); setActive(0) }}
        onFocus={() => setOpen(true)} onBlur={() => setTimeout(() => setOpen(false), 150)} onKeyDown={onKeyDown} />
      <small>{t('topbar.shortcut')}</small>
      {open && q.trim().length >= 2 && (
        <ul id="search-results" role="listbox" className="search-results">
          {!results.length && <li className="m">{t('searchBox.noResult')}</li>}
          {results.map((r, i) => (
            <li key={`${r.kind}${r.id}`} role="option" aria-selected={i === active} className={i === active ? 'on' : ''}
              onMouseDown={(e) => { e.preventDefault(); go(r) }}>
              <span className="search-kind">{t(`searchBox.kind.${r.kind}`)}</span>
              <bdi>{r.label}</bdi>{r.sub && <span className="m"> · <bdi dir="ltr">{r.sub}</bdi></span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

export default function Topbar({ email, onLogout, connected = true, lastScan = null, searchData, onNavigate }) {
  const { t, locale } = useI18n()
  return (
    <header className="top">
      <div className="logo">CyberVeylix<small>NETWORK INTELLIGENCE &amp; CYBERSECURITY</small></div>
      <SearchBox data={searchData} onNavigate={onNavigate} />
      <div className="right">
        <div>
          <span className="dot" style={connected ? undefined : { background: 'var(--r)' }} />
          {connected ? t('topbar.connected') : t('topbar.syncError')}
          <br /><small>{t('topbar.lastScan', { date: lastScan === null ? '—' : new Date(lastScan).toLocaleString(locale) })}</small>
        </div>
        <span>🔔</span><span>⚙</span>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div className="av" />
          <div>{email}<br /><small style={{ cursor: 'pointer' }} onClick={onLogout}>{t('topbar.logout')}</small></div>
        </div>
      </div>
    </header>
  )
}
