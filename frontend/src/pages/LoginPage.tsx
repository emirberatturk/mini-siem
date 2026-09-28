import { useEffect, useState, type FormEvent } from 'react'
import { api, type Me } from '../lib/api'

export default function LoginPage({ onLogin }: { onLogin: (me: Me) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [hasUsers, setHasUsers] = useState<boolean | null>(null)

  useEffect(() => {
    api.setup().then((s) => setHasUsers(s.has_users)).catch(() => setHasUsers(null))
  }, [])

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      onLogin(await api.login(username, password))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setPassword('') // hatalı şifre formda kalmasın
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <div className="brand login-brand">
          <span className="brand-mark" aria-hidden>◉</span>
          MINI <span className="brand-dim">SIEM</span>
        </div>
        <h1>Giriş</h1>

        {hasUsers === false ? (
          <div className="card card-warn">
            Henüz kullanıcı yok. Güvenlik gereği varsayılan hesap bulunmaz; ilk yöneticiyi
            terminalden oluştur (backend klasöründe):
            <pre>.venv\Scripts\python.exe -m app.tools.users ekle adin --rol yonetici</pre>
          </div>
        ) : (
          <>
            <label>
              <span>Kullanıcı adı</span>
              <input
                autoComplete="username"
                autoFocus
                maxLength={64}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </label>
            <label>
              <span>Şifre</span>
              <input
                type="password"
                autoComplete="current-password"
                maxLength={256}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
            {error && <div className="card card-danger" role="alert">{error}</div>}
            <button className="btn btn-primary" type="submit" disabled={busy || !username || !password}>
              {busy ? 'Kontrol ediliyor…' : 'Giriş yap'}
            </button>
            <p className="muted login-hint">
              15 dakikada 5 hatalı denemeden sonra hesap geçici olarak kilitlenir.
            </p>
          </>
        )}
      </form>
    </div>
  )
}
