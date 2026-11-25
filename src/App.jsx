import { useEffect, useState } from 'react'
import { supabase, configured } from './supabaseClient'
import useRows from './useRows'
import Topbar from './components/Topbar'
import Sidebar from './components/Sidebar'
import RightColumn from './components/RightColumn'
import Modal from './components/Modal'
import Login from './components/Login'
import { Kpis, Activity, DevicesCard, VulnCard, ThreatsCard } from './components/Panels'
import TopologyPage from './components/TopologyPage'
import TopologySummary from './components/TopologySummary'
import DevicesPage from './components/DevicesPage'
import AlertsPage from './components/AlertsPage'
import VulnsPage from './components/VulnsPage'
import InstallPage from './components/InstallPage'
import SensorCard from './components/SensorCard'
import ReportPage from './components/ReportPage'
import ScanPage from './components/ScanPage'
import SocPage from './components/SocPage'
import SettingsPage from './components/SettingsPage'
import { isMissingTableMessage } from './lib/findings.js'
import { TYPES, STATUS, SEV, CATS } from './constants'
import { useI18n } from './i18n/context.js'
import { LanguageSelect } from './i18n/index.jsx'

function Dashboard({ user }) {
  const { t, locale } = useI18n()
  const dev = useRows('devices', user)
  const vul = useRows('vulnerabilities', user)
  const alr = useRows('alerts', user)
  const thr = useRows('threats', user)
  const srv = useRows('services', user)
  const net = useRows('networks', user)
  const sen = useRows('sensors', user)
  const lnk = useRows('links', user)
  // Table sensors absente tant que schema_r1_results.sql n'est pas exécuté : pas une panne.
  const sensorsMissing = isMissingTableMessage(sen.error)
  // Demandes au capteur et adresses bloquées (supabase/schema_r4_actions.sql) : rafraîchies toutes les 5 s.
  const cmd = useRows('sensor_commands', user, 5000)
  const blk = useRows('blocked_ips', user, 5000)
  const r4Missing = isMissingTableMessage(cmd.error) || isMissingTableMessage(blk.error)
  const sendCommand = (sensorId, kind, params) => cmd.add({ sensor_id: sensorId, kind, params })
  const [modal, setModal] = useState(null)
  const [page, setPage] = useState('home')
  const close = () => setModal(null)
  const error = dev.error || vul.error || alr.error || thr.error || srv.error || net.error || lnk.error || (sensorsMissing ? '' : sen.error) || (r4Missing ? '' : (cmd.error || blk.error))
  const connected = !error
  // Détache explicitement les appareils avant de supprimer un réseau : la suppression reste
  // sans effet destructif même si la contrainte FK réelle n'est pas « on delete set null ».
  const removeNetwork = async (id) => {
    for (const d of dev.rows.filter((row) => row.network_id === id)) {
      const msg = await dev.update(d.id, { network_id: null })
      if (msg) return msg
    }
    return net.remove(id)
  }
  const lastScan = dev.rows.reduce((latest, d) => {
    const t = d.last_seen ? new Date(d.last_seen).getTime() : NaN
    return Number.isFinite(t) && (latest === null || t > latest) ? t : latest
  }, null)

  return (
    <>
      <Topbar email={user.email} onLogout={() => supabase.auth.signOut()} connected={connected} lastScan={lastScan} />
      <div className={`wrap${page === 'topology' ? ' page-wide' : ''}`}>
        <Sidebar active={page} onChange={setPage} />
        {page === 'home' ? (<>
        <main className="main">
          <Kpis counts={[dev.loaded ? dev.rows.length : null, thr.loaded ? thr.rows.filter((t) => t.blocked).length : null, vul.loaded ? vul.rows.filter((v) => (v.status || 'open') !== 'resolved').length : null, srv.loaded ? srv.rows.length : null]} />
          <SensorCard sensors={sen.rows} loaded={sen.loaded} missing={sensorsMissing} />
          <section className="mid">
            <TopologySummary devices={dev.rows} networks={net.rows} loaded={dev.loaded && net.loaded} lastScan={lastScan} onOpen={() => setPage('topology')} />
            <Activity />
          </section>
          <section className="bot">
            <DevicesCard devices={dev.rows} />
            <VulnCard vulns={vul.rows} onAdd={() => setPage('vulns')} />
            <ThreatsCard threats={thr.rows} />
          </section>
        </main>
        <RightColumn alerts={alr.rows} threats={thr.rows} onAddAlert={() => setModal('alr')} onAddThreat={() => setModal('thr')} />
        </>) : page === 'devices' ? (
          <main className="main wide">
            <DevicesPage
              devices={dev.rows}
              services={srv.rows}
              vulns={vul.rows}
              networks={net.rows}
              onAddClick={() => setModal('dev')}
              onUpdate={dev.update}
              onRemove={dev.remove}
              onNetworkUpdate={net.update}
              onNetworkRemove={removeNetwork}
            />
          </main>
        ) : page === 'topology' ? (
          <TopologyPage devices={dev.rows} services={srv.rows} networks={net.rows} links={lnk.rows} networksLoaded={net.loaded} loaded={dev.loaded} />
        ) : page === 'vulns' ? (
          <main className="main wide">
            <VulnsPage vulns={vul.rows} devices={dev.rows} onAdd={vul.add} onUpdate={vul.update} onRemove={vul.remove}
              sensors={sen.rows} commands={r4Missing ? [] : cmd.rows} onCommand={r4Missing ? undefined : sendCommand} />
          </main>
        ) : page === 'threats' ? (
          <main className="main wide">
            <AlertsPage alerts={alr.rows} networks={net.rows} onUpdate={alr.update}
              sensors={sen.rows} blocked={r4Missing ? [] : blk.rows} commands={r4Missing ? [] : cmd.rows} onCommand={r4Missing ? undefined : sendCommand} />
          </main>
        ) : page === 'install' ? (
          <main className="main wide">
            <SensorCard sensors={sen.rows} loaded={sen.loaded} missing={sensorsMissing} />
            <InstallPage />
          </main>
        ) : page === 'scan' ? (
          <main className="main wide">
            <ScanPage user={user} sensors={sen.rows} vulns={vul.rows} sensorsMissing={sensorsMissing} onOpenVulns={() => setPage('vulns')} />
          </main>
        ) : page === 'soc' ? (
          <main className="main wide">
            <SocPage alerts={alr.rows} vulns={vul.rows} commands={r4Missing ? [] : cmd.rows} blocked={r4Missing ? [] : blk.rows}
              sensors={sen.rows} sensorsLoaded={sen.loaded} sensorsMissing={sensorsMissing} />
          </main>
        ) : page === 'settings' ? (
          <main className="main wide">
            <SettingsPage sensors={sen.rows} sensorsMissing={sensorsMissing} onUpdateSensor={sen.update} />
          </main>
        ) : page === 'reports' ? (
          <main className="main wide">
            <ReportPage email={user.email} devices={dev.rows} services={srv.rows} vulns={vul.rows}
              alerts={alr.rows} sensors={sen.rows} sensorsMissing={sensorsMissing} />
          </main>
        ) : (
          <main className="main wide">
            <div className="card"><h3>{t(`nav.${page}`)}</h3><p className="m" style={{ padding: '22px 0' }}>{t('common.sectionSoon')}</p></div>
          </main>
        )}
      </div>
      <footer>
        <span>CyberVeylix ✦ v1.0.0 &nbsp;&nbsp; Network Intelligence &amp; Cybersecurity</span>
        <span><span className="dot" style={error ? { background: 'var(--r)' } : undefined} />{error}</span>
      </footer>
      {modal === 'dev' && (
        <Modal title={t('modal.devices')} onClose={close}
          fields={[{ k: 'name', ph: t('modal.name') }, { k: 'ip', ph: t('modal.ip') },
            { k: 'type', opts: [['', t('type.unknown')], ...Object.keys(TYPES).map((ty) => [ty, t(`type.${ty}`)])] }, { k: 'status', opts: STATUS.map((s) => [s.k, t(`status.${s.k}`)]) }]}
          rows={dev.rows.map((d) => ({ id: d.id, label: `${d.name} · ${d.ip || '—'} · ${d.status ? t(`status.${d.status}`) : '—'}` }))}
          onAdd={(f) => dev.add({ name: f.name.trim(), ip: f.ip.trim() || null, type: f.type || null, status: f.status })}
          onRemove={dev.remove} />
      )}
      {modal === 'alr' && (
        <Modal title={t('modal.alerts')} onClose={close}
          fields={[{ k: 'title', ph: t('modal.alertTitle') }, { k: 'detail', ph: t('modal.detail') }, { k: 'severity', opts: SEV.map((s) => [s.k, t(`sev.${s.k}`)]) }]}
          rows={alr.rows.map((a) => ({ id: a.id, label: `${SEV.find((s) => s.k === a.severity) ? t(`sev.${a.severity}`) : (a.severity || '—')} · ${a.title}` }))}
          onAdd={(f) => alr.add({ title: f.title.trim(), detail: f.detail.trim() || null, severity: f.severity })}
          onRemove={alr.remove} />
      )}
      {modal === 'thr' && (
        <Modal title={t('modal.threats')} onClose={close}
          fields={[{ k: 'category', opts: CATS.map((c) => [c.k, t(`cats.${c.k}`)]) }, { k: 'blocked', opts: [['1', t('modal.blockedYes')], ['0', t('modal.blockedNo')]] }]}
          rows={thr.rows.map((th) => ({ id: th.id, label: `${CATS.find((c) => c.k === th.category) ? t(`cats.${th.category}`) : (th.category || '—')} · ${th.blocked ? t('modal.blockedYes') : t('modal.blockedNo')} · ${new Date(th.created_at).toLocaleDateString(locale)}` }))}
          onAdd={(f) => thr.add({ category: f.category, blocked: f.blocked === '1' })}
          onRemove={thr.remove} />
      )}
    </>
  )
}

function Setup() {
  const { t } = useI18n()
  return (
    <div style={{ display: 'grid', placeItems: 'center', minHeight: '100vh', padding: 16 }}>
      <div className="card" style={{ width: 'min(480px, 100%)' }}>
        <h3>{t('setup.title')}</h3>
        <p className="m" style={{ marginTop: 10 }}>{t('setup.text')}</p>
        <LanguageSelect />
      </div>
    </div>
  )
}

export default function App() {
  const { t } = useI18n()
  const [session, setSession] = useState(null)
  const [ready, setReady] = useState(!configured)

  useEffect(() => {
    if (!configured) return
    supabase.auth.getSession().then(({ data }) => { setSession(data.session); setReady(true) })
    const { data: sub } = supabase.auth.onAuthStateChange((_e, s) => setSession(s))
    return () => sub.subscription.unsubscribe()
  }, [])

  if (!configured) return <Setup />
  if (!ready) return <p className="m" style={{ padding: 24 }}>{t('common.loading')}</p>
  if (!session) return <Login />
  return <Dashboard user={session.user} />
}
