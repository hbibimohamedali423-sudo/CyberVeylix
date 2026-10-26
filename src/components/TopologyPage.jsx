import { useEffect, useRef, useState } from 'react'
import Topology from './Topology'
import { useI18n } from '../i18n/context.js'

export default function TopologyPage({ devices = [], services = [], loaded = true }) {
  const { t } = useI18n()
  const pageRef = useRef(null)
  const [fullscreen, setFullscreen] = useState(false)
  const [error, setError] = useState(false)
  const supported = typeof document !== 'undefined' && Boolean(document.fullscreenEnabled)

  useEffect(() => {
    const sync = () => setFullscreen(document.fullscreenElement === pageRef.current)
    sync()
    document.addEventListener('fullscreenchange', sync)
    return () => document.removeEventListener('fullscreenchange', sync)
  }, [])

  const toggle = async () => {
    if (!supported || !pageRef.current) return
    setError(false)
    try {
      if (document.fullscreenElement) await document.exitFullscreen()
      else await pageRef.current.requestFullscreen()
    } catch {
      setError(true)
    }
  }

  const label = fullscreen ? t('topologyPage.exitFullscreen') : t('topologyPage.fullscreen')
  const title = supported ? label : t('topologyPage.fullscreenUnavailable')

  return (
    <main className="main wide topology-page" ref={pageRef}>
      <div className="topology-page-bar">
        <h1 className="sr-only">{t('nav.topology')}</h1>
        <button
          type="button"
          className="topology-fs-btn"
          onClick={toggle}
          disabled={!supported}
          aria-pressed={fullscreen}
          aria-describedby={!supported ? 'topology-fs-unavailable' : undefined}
          title={title}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
            strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            {fullscreen
              ? <path d="M8 3v3a2 2 0 0 1-2 2H3M16 3v3a2 2 0 0 0 2 2h3M8 21v-3a2 2 0 0 0-2-2H3M16 21v-3a2 2 0 0 1 2-2h3" />
              : <path d="M8 3H5a2 2 0 0 0-2 2v3M16 3h3a2 2 0 0 1 2 2v3M8 21H5a2 2 0 0 1-2-2v-3M16 21h3a2 2 0 0 0 2-2v-3" />}
          </svg>
          <span>{label}</span>
        </button>
      </div>
      {!supported && <p id="topology-fs-unavailable" className="topology-fs-note">{t('topologyPage.fullscreenUnavailable')}</p>}
      {error && <p className="topology-fs-error" role="alert">{t('topologyPage.fullscreenError')}</p>}
      <Topology devices={devices} services={services} loaded={loaded} />
    </main>
  )
}
