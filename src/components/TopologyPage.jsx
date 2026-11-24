import { useEffect, useRef, useState } from 'react'
import Topology from './Topology'
import { useI18n } from '../i18n/context.js'

export default function TopologyPage({ devices = [], services = [], networks = [], loaded = true, networksLoaded = true }) {
  const { t } = useI18n()
  const pageRef = useRef(null)
  const [fullscreen, setFullscreen] = useState(false)
  const [error, setError] = useState(false)
  const [networkId, setNetworkId] = useState('')
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
  const visibleNetworks = networkId ? networks.filter((n) => n.id === networkId) : networks
  const visibleDevices = networkId ? devices.filter((d) => d.network_id === networkId) : devices

  return (
    <main className="main wide topology-page" ref={pageRef}>
      <div className="topology-page-bar">
        <h1 className="sr-only">{t('nav.topology')}</h1>
        <div className="topology-page-tools">
          <label className="topology-net-select">
            <span>{t('topology.networkFilter')}</span>
            <select value={networkId} onChange={(e) => setNetworkId(e.target.value)}>
              <option value="">{t('networks.all')}</option>
              {networks.map((n) => <option key={n.id} value={n.id}>{n.name || n.cidr}</option>)}
            </select>
          </label>
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
      </div>
      {!supported && <p id="topology-fs-unavailable" className="topology-fs-note">{t('topologyPage.fullscreenUnavailable')}</p>}
      {error && <p className="topology-fs-error" role="alert">{t('topologyPage.fullscreenError')}</p>}
      <Topology devices={visibleDevices} services={services} networks={visibleNetworks} loaded={loaded && networksLoaded} />
    </main>
  )
}
