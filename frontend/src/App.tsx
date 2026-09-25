import { useEffect, useState } from 'react'
import { api, type HealthResponse } from './lib/api'
import type { AlertFilters, Go, HuntFilters, PageId } from './lib/nav'
import AlertsPage from './pages/AlertsPage'
import HuntPage from './pages/HuntPage'
import OverviewPage from './pages/OverviewPage'
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

const NAV: { id: PageId; label: string; icon: string }[] = [
  { id: 'overview', label: 'Genel Bakış', icon: '▦' },
  { id: 'alerts', label: 'Alertler', icon: '⚑' },
  { id: 'hunt', label: 'Olay Arama', icon: '⌕' },
  { id: 'rules', label: 'Kurallar', icon: '≡' },
  { id: 'upload', label: 'Log Yükle', icon: '⇪' },
]

// Adres çubuğundaki #sayfa (veya #alerts/12): yenilemede aynı yerde kalınır, bağlantı paylaşılabilir
const navFromHash = (): NavState => {
  const [id, alertId] = window.location.hash.slice(1).split('/')
  const page = NAV.some((n) => n.id === id) ? (id as PageId) : 'overview'
  const n = Number(alertId)
  return { page, seq: 0, ...(page === 'alerts' && Number.isInteger(n) && n > 0 ? { alertId: n } : {}) }
}

export default function App() {
  const [status, setStatus] = useState<Status>({ kind: 'loading' })
  const [nav, setNav] = useState<NavState>(navFromHash)

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
        <div className={`live live-${status.kind}`}>
          <span className="live-dot" />
          {status.kind === 'up' ? 'Canlı' : status.kind === 'down' ? 'Bağlantı yok' : 'Bağlanıyor…'}
        </div>
      </header>

      <nav className="sidebar">
        {NAV.map((item) => (
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
        {nav.page === 'rules' && <RulesPage go={go} />}
        {nav.page === 'upload' && <UploadPage go={go} />}
      </main>
    </div>
  )
}
