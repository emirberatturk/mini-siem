import { useEffect, useState } from 'react'
import { UNAUTHORIZED_EVENT, api, type HealthResponse, type Me } from './lib/api'
import type { AlertFilters, Go, HuntFilters, PageId } from './lib/nav'
import AlertsPage from './pages/AlertsPage'
import HuntPage from './pages/HuntPage'
import LoginPage from './pages/LoginPage'
import OverviewPage from './pages/OverviewPage'
import ReportPage from './pages/ReportPage'
import RulesPage from './pages/RulesPage'
import UploadPage from './pages/UploadPage'

type Status = { kind: 'loading' } | { kind: 'up'; data: HealthResponse } | { kind: 'down' }

interface NavState {
  page: PageId
  alertId?: number
  hunt?: HuntFilters
  alerts?: AlertFilters
  seq: number // aynı sayfaya yeni filtreyle gidildiğinde sayfayı sıfırdan kurmak için
}

const NAV: { id: PageId; label: string; icon: string; adminOnly?: boolean }[] = [
  { id: 'overview', label: 'Genel Bakış', icon: '▦' },
  { id: 'alerts', label: 'Alertler', icon: '⚑' },
  { id: 'hunt', label: 'Olay Arama', icon: '⌕' },
  { id: 'rules', label: 'Kurallar', icon: '≡' },
  { id: 'upload', label: 'Log Yükle', icon: '⇪', adminOnly: true },
]

// Adres çubuğundaki #sayfa (veya #alerts/12): yenilemede aynı yerde kalınır, bağlantı paylaşılabilir
const navFromHash = (): NavState => {
  const [id, alertId] = window.location.hash.slice(1).split('/')
  const page = NAV.some((n) => n.id === id) ? (id as PageId) : 'overview'
  const n = Number(alertId)
  return { page, seq: 0, ...(page === 'alerts' && Number.isInteger(n) && n > 0 ? { alertId: n } : {}) }
}

// #report/12: menüsüz, yazdırılabilir olay raporu (yeni sekmede açılır)
const reportIdFromHash = (): number | null => {
  const [id, alertId] = window.location.hash.slice(1).split('/')
  const n = Number(alertId)
  return id === 'report' && Number.isInteger(n) && n > 0 ? n : null
}

/** Giriş kapısı: oturum yoksa (veya düşerse) giriş ekranı. Yetki kontrolü asıl olarak
 *  sunucudadır; arayüz yalnızca kullanıcının yapamayacağı şeyleri göstermez. */
export default function App() {
  const reportId = reportIdFromHash()
  const [me, setMe] = useState<Me | null | undefined>(undefined)

  useEffect(() => {
    api.me().then(setMe).catch(() => setMe(null))
    const onUnauthorized = () => setMe(null)
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
  }, [])

  if (me === undefined) return <div className="login-wrap muted">Yükleniyor…</div>
  if (me === null) return <LoginPage onLogin={setMe} />
  if (reportId) return <ReportPage alertId={reportId} />
  return <Shell me={me} onLogout={() => api.logout().finally(() => setMe(null))} />
}

function Shell({ me, onLogout }: { me: Me; onLogout: () => void }) {
  const isAdmin = me.role === 'admin'
  const nav_items = NAV.filter((n) => isAdmin || !n.adminOnly)
  const [status, setStatus] = useState<Status>({ kind: 'loading' })
  const [nav, setNav] = useState<NavState>(() => {
    const n = navFromHash()
    return nav_items.some((i) => i.id === n.page) ? n : { page: 'overview', seq: 0 }
  })

  useEffect(() => {
    const check = () =>
      api
        .health()
        .then((data) => setStatus({ kind: 'up', data }))
        .catch(() => setStatus({ kind: 'down' }))
    check()
    const id = setInterval(check, 10_000)
    return () => clearInterval(id)
  }, [])

  const go: Go = (page, opts = {}) => {
    setNav((n) => ({ page, ...opts, seq: n.seq + 1 }))
    window.history.replaceState(null, '', opts.alertId ? `#${page}/${opts.alertId}` : `#${page}`)
    window.scrollTo({ top: 0 })
  }

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden>◉</span>
          MINI <span className="brand-dim">SIEM</span>
        </div>
        <div className="topbar-right">
          <div className={`live live-${status.kind}`}>
            <span className="live-dot" />
            {status.kind === 'up' ? 'Canlı' : status.kind === 'down' ? 'Bağlantı yok' : 'Bağlanıyor…'}
          </div>
          <span className="user-chip" title="Oturum 8 saat sonra kendiliğinden kapanır">
            {me.username} · <span className="dim">{me.role_label}</span>
          </span>
          <button className="btn btn-ghost btn-logout" onClick={onLogout}>Çıkış</button>
        </div>
      </header>

      <nav className="sidebar">
        {nav_items.map((item) => (
          <button
            key={item.id}
            className={`nav-item${nav.page === item.id ? ' active' : ''}`}
            onClick={() => go(item.id)}
          >
            <span className="nav-icon" aria-hidden>{item.icon}</span>
            {item.label}
          </button>
        ))}
        <div className="sidebar-foot muted">
          {status.kind === 'up' ? `v${status.data.version}` : ''} · yalnızca yerel ağ
        </div>
      </nav>

      <main className="content" key={nav.seq}>
        {status.kind === 'down' && (
          <div className="card card-danger">
            Backend'e ulaşılamıyor. <code>baslat.bat</code> ile başlattın mı?
          </div>
        )}
        {nav.page === 'overview' && <OverviewPage go={go} />}
        {nav.page === 'alerts' && (
          <AlertsPage go={go} initialFilters={nav.alerts} initialAlertId={nav.alertId} />
        )}
        {nav.page === 'hunt' && <HuntPage go={go} initialFilters={nav.hunt} />}
        {nav.page === 'rules' && <RulesPage go={go} canRun={isAdmin} />}
        {nav.page === 'upload' && isAdmin && <UploadPage go={go} />}
      </main>
    </div>
  )
}
