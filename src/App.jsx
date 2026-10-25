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
import { TYPES, STATUS, SEV, CATS, NAV } from './constants'

function Dashboard({ user }) {
  const dev = useRows('devices', user)
  const vul = useRows('vulnerabilities', user)
  const alr = useRows('alerts', user)
  const thr = useRows('threats', user)
  const srv = useRows('services', user)
  const [modal, setModal] = useState(null)
  const [page, setPage] = useState(0)
  const close = () => setModal(null)
  const label = (list, k) => list.find((x) => x.k === k)?.label
  const vulns = vul.rows.map((v) => ({ ...v, sev: v.severity }))
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
          <Kpis counts={[dev.loaded ? dev.rows.length : null, thr.loaded ? thr.rows.filter((t) => t.blocked).length : null, vul.loaded ? vul.rows.length : null, srv.loaded ? srv.rows.length : null]} />
          <section className="mid">
            <NetworkMap devices={dev.rows} onAdd={() => setModal('dev')} />
            <Activity />
          </section>
          <section className="bot">
            <DevicesCard devices={dev.rows} />
            <VulnCard vulns={vulns} onAdd={() => setModal('vul')} />
            <ThreatsCard threats={thr.rows} />
          </section>
        </main>
        <RightColumn alerts={alr.rows} threats={thr.rows} onAddAlert={() => setModal('alr')} onAddThreat={() => setModal('thr')} />
        </>) : page === 1 ? (
          <main className="main wide">
            <DevicesPage devices={dev.rows} services={srv.rows} onAddClick={() => setModal('dev')} onUpdate={dev.update} onRemove={dev.remove} />
          </main>
        ) : (
          <main className="main wide">
            <div className="card"><h3>{NAV[page]}</h3><p className="m" style={{ padding: '22px 0' }}>Cette section est en cours de développement.</p></div>
          </main>
        )}
      </div>
      <footer>
        <span>CyberVeylix ✦ v1.0.0 &nbsp;&nbsp; Network Intelligence &amp; Cybersecurity</span>
        <span><span className="dot" style={error ? { background: 'var(--r)' } : undefined} />{error}</span>
      </footer>
      {modal === 'dev' && (
        <Modal title="Appareils" onClose={close}
          fields={[{ k: 'name', ph: 'Nom de l’appareil' }, { k: 'ip', ph: 'Adresse IP (ex. 192.168.1.10)' },
            { k: 'type', opts: Object.keys(TYPES).map((t) => [t, t]) }, { k: 'status', opts: STATUS.map((s) => [s.k, s.label]) }]}
          rows={dev.rows.map((d) => `${d.name} · ${d.ip || '—'} · ${label(STATUS, d.status)}`)}
          onAdd={(f) => dev.add({ name: f.name.trim(), ip: f.ip.trim() || null, type: f.type, status: f.status })}
          onRemove={dev.remove} />
      )}
      {modal === 'vul' && (
        <Modal title="Vulnérabilités" onClose={close}
          fields={[{ k: 'title', ph: 'Titre ou CVE (ex. CVE-2024-6387)' }, { k: 'sev', opts: SEV.map((s) => [s.k, s.label]) }]}
          rows={vulns.map((v) => `${label(SEV, v.sev)} · ${v.title}`)}
          onAdd={(f) => vul.add({ title: f.title.trim(), severity: f.sev })}
          onRemove={vul.remove} />
      )}
      {modal === 'alr' && (
        <Modal title="Alertes" onClose={close}
          fields={[{ k: 'title', ph: 'Titre de l’alerte' }, { k: 'detail', ph: 'Détail (facultatif)' }, { k: 'severity', opts: SEV.map((s) => [s.k, s.label]) }]}
          rows={alr.rows.map((a) => `${label(SEV, a.severity)} · ${a.title}`)}
          onAdd={(f) => alr.add({ title: f.title.trim(), detail: f.detail.trim() || null, severity: f.severity })}
          onRemove={alr.remove} />
      )}
      {modal === 'thr' && (
        <Modal title="Menaces" onClose={close}
          fields={[{ k: 'category', opts: CATS.map((c) => [c.k, c.label]) }, { k: 'blocked', opts: [['1', 'Bloquée'], ['0', 'Non bloquée']] }]}
          rows={thr.rows.map((t) => `${label(CATS, t.category)} · ${t.blocked ? 'Bloquée' : 'Non bloquée'} · ${new Date(t.created_at).toLocaleDateString('fr-FR')}`)}
          onAdd={(f) => thr.add({ category: f.category, blocked: f.blocked === '1' })}
          onRemove={thr.remove} />
      )}
    </>
  )
}

function Setup() {
  return (
    <div style={{ display: 'grid', placeItems: 'center', minHeight: '100vh', padding: 16 }}>
      <div className="card" style={{ width: 'min(480px, 100%)' }}>
        <h3>Configuration requise</h3>
        <p className="m" style={{ marginTop: 10 }}>
          Créez un fichier <b>.env</b> à la racine du projet (voir .env.example) avec VITE_SUPABASE_URL et
          VITE_SUPABASE_ANON_KEY, puis relancez <b>npm run dev</b>.
        </p>
      </div>
    </div>
  )
}

export default function App() {
  const [session, setSession] = useState(null)
  const [ready, setReady] = useState(!configured)

  useEffect(() => {
    if (!configured) return
    supabase.auth.getSession().then(({ data }) => { setSession(data.session); setReady(true) })
    const { data: sub } = supabase.auth.onAuthStateChange((_e, s) => setSession(s))
    return () => sub.subscription.unsubscribe()
  }, [])

  if (!configured) return <Setup />
  if (!ready) return <p className="m" style={{ padding: 24 }}>Chargement…</p>
  if (!session) return <Login />
  return <Dashboard user={session.user} />
}
