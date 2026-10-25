import { useEffect, useState } from 'react'
import { supabase, configured } from './supabaseClient'
import useRows from './useRows'
import Topbar from './components/Topbar'
import Sidebar from './components/Sidebar'
import RightColumn from './components/RightColumn'
import Modal from './components/Modal'
import Login from './components/Login'
import { Banner, Kpis, NetworkMap, Activity, DevicesCard, VulnCard, ThreatsCard } from './components/Panels'
import DevicesPage from './components/DevicesPage'
import AlertsPage from './components/AlertsPage'
import VulnsPage from './components/VulnsPage'
import { TYPES, STATUS, SEV, CATS, NAV } from './constants'
import { useI18n } from './i18n/context.js'
import { LanguageSelect } from './i18n/index.jsx'

function Dashboard({ user }) {
  const { t, locale } = useI18n()
  const dev = useRows('devices', user)
  const vul = useRows('vulnerabilities', user)
  const alr = useRows('alerts', user)
  const thr = useRows('threats', user)
  const srv = useRows('services', user)
  const [modal, setModal] = useState(null)
  const [page, setPage] = useState(0)
  const close = () => setModal(null)
  const error = dev.error || vul.error || alr.error || thr.error || srv.error
  const connected = !error
  const lastScan = dev.rows.reduce((latest, d) => {
    const t = d.last_seen ? new Date(d.last_seen).getTime() : NaN
    return Number.isFinite(t) && (latest === null || t > latest) ? t : latest
  }, null)

  return (
    <>
      <Topbar email={user.email} onLogout={() => supabase.auth.signOut()} connected={connected} lastScan={lastScan} />
      <div className="wrap">
        <Sidebar active={page} onChange={setPage} />
        {page === 0 ? (<>
        <main className="main">
          <Banner />
          <Kpis counts={[dev.loaded ? dev.rows.length : null, thr.loaded ? thr.rows.filter((t) => t.blocked).length : null, vul.loaded ? vul.rows.filter((v) => (v.status || 'open') !== 'resolved').length : null, srv.loaded ? srv.rows.length : null]} />
          <section className="mid">
            <NetworkMap devices={dev.rows} onAdd={() => setModal('dev')} />
            <Activity />
          </section>
          <section className="bot">
            <DevicesCard devices={dev.rows} />
            <VulnCard vulns={vul.rows} onAdd={() => setPage(3)} />
            <ThreatsCard threats={thr.rows} />
          </section>
        </main>
        <RightColumn alerts={alr.rows} threats={thr.rows} onAddAlert={() => setModal('alr')} onAddThreat={() => setModal('thr')} />
        </>) : page === 1 ? (
          <main className="main wide">
            <DevicesPage devices={dev.rows} services={srv.rows} onAddClick={() => setModal('dev')} onUpdate={dev.update} onRemove={dev.remove} />
          </main>
        ) : page === 3 ? (
          <main className="main wide">
            <VulnsPage vulns={vul.rows} devices={dev.rows} onAdd={vul.add} onUpdate={vul.update} onRemove={vul.remove} />
          </main>
        ) : page === 4 ? (
          <main className="main wide">
            <AlertsPage alerts={alr.rows} onUpdate={alr.update} />
          </main>
        ) : (
          <main className="main wide">
            <div className="card"><h3>{t(`nav.${NAV[page]}`)}</h3><p className="m" style={{ padding: '22px 0' }}>{t('common.sectionSoon')}</p></div>
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
            { k: 'type', opts: Object.keys(TYPES).map((ty) => [ty, t(`type.${ty}`)]) }, { k: 'status', opts: STATUS.map((s) => [s.k, t(`status.${s.k}`)]) }]}
          rows={dev.rows.map((d) => ({ id: d.id, label: `${d.name} · ${d.ip || '—'} · ${d.status ? t(`status.${d.status}`) : '—'}` }))}
          onAdd={(f) => dev.add({ name: f.name.trim(), ip: f.ip.trim() || null, type: f.type, status: f.status })}
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
