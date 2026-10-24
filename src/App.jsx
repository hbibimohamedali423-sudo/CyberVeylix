import { useState } from 'react'
import useStored from './useStored'
import Topbar from './components/Topbar'
import Sidebar from './components/Sidebar'
import RightColumn from './components/RightColumn'
import Modal from './components/Modal'
import { Banner, Kpis, NetworkMap, Activity, DevicesCard, VulnCard, ThreatsCard } from './components/Panels'
import { TYPES, STATUS, SEV } from './constants'

export default function App() {
  const [devices, setDevices] = useStored('cv_dev')
  const [vulns, setVulns] = useStored('cv_vul')
  const [modal, setModal] = useState(null)
  const close = () => setModal(null)
  const label = (list, k) => list.find((x) => x.k === k)?.label

  return (
    <>
      <Topbar />
      <div className="wrap">
        <Sidebar />
        <main className="main">
          <Banner />
          <Kpis counts={[devices.length, 0, vulns.length, 0]} />
          <section className="mid">
            <NetworkMap devices={devices} onAdd={() => setModal('dev')} />
            <Activity />
          </section>
          <section className="bot">
            <DevicesCard devices={devices} />
            <VulnCard vulns={vulns} onAdd={() => setModal('vul')} />
            <ThreatsCard />
          </section>
        </main>
        <RightColumn />
      </div>
      <footer>
        <span>CyberVeylix ✦ v1.0.0 &nbsp;&nbsp; Network Intelligence &amp; Cybersecurity</span>
        <span><span className="dot" style={{ background: '#5d7390' }} />Aucune source de données connectée</span>
      </footer>
      {modal === 'dev' && (
        <Modal title="Appareils" onClose={close}
          fields={[{ k: 'name', ph: 'Nom de l’appareil' }, { k: 'ip', ph: 'Adresse IP (ex. 192.168.1.10)' },
            { k: 'type', opts: Object.keys(TYPES).map((t) => [t, t]) }, { k: 'status', opts: STATUS.map((s) => [s.k, s.label]) }]}
          rows={devices.map((d) => `${d.name} · ${d.ip || '—'} · ${label(STATUS, d.status)}`)}
          onAdd={(f) => setDevices([...devices, f])} onRemove={(i) => setDevices(devices.filter((_, j) => j !== i))} />
      )}
      {modal === 'vul' && (
        <Modal title="Vulnérabilités" onClose={close}
          fields={[{ k: 'title', ph: 'Titre ou CVE (ex. CVE-2024-6387)' }, { k: 'sev', opts: SEV.map((s) => [s.k, s.label]) }]}
          rows={vulns.map((v) => `${label(SEV, v.sev)} · ${v.title}`)}
          onAdd={(f) => setVulns([...vulns, f])} onRemove={(i) => setVulns(vulns.filter((_, j) => j !== i))} />
      )}
    </>
  )
}
