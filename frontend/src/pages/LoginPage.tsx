import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { api, type Enrollment, type Me } from '../lib/api'

/**
 * İki adımlı giriş: önce kullanıcı adı + şifre, sonra telefondaki doğrulama kodu.
 * Telefonunu henüz tanıtmamış hesap önce QR kodu okutur; yedek kodlar yalnızca bir kez gösterilir.
 */
type Step = 'password' | 'mfa' | 'enroll' | 'codes'

const errorText = (err: unknown) => (err instanceof Error ? err.message : String(err))

export default function LoginPage({ onLogin }: { onLogin: (me: Me) => void }) {
  const [step, setStep] = useState<Step>('password')
  const [hasUsers, setHasUsers] = useState<boolean | null>(null)
  const [done, setDone] = useState<{ me: Me; codes: string[] } | null>(null)

  useEffect(() => {
    api.setup().then((s) => setHasUsers(s.has_users)).catch(() => setHasUsers(null))
  }, [])

  const restart = () => setStep('password')

  return (
    <div className="login-wrap">
      <div className="login-card">
        <div className="brand login-brand">
          <span className="brand-mark" aria-hidden>◉</span>
          MINI <span className="brand-dim">SIEM</span>
        </div>

        {hasUsers === false ? (
          <>
            <h1>Giriş</h1>
            <div className="card card-warn">
              Henüz kullanıcı yok. Güvenlik gereği varsayılan hesap bulunmaz; ilk yöneticiyi
              terminalden oluştur (backend klasöründe):
              <pre>.venv\Scripts\python.exe -m app.tools.users ekle adin --rol yonetici</pre>
            </div>
          </>
        ) : step === 'password' ? (
          <PasswordStep onNext={setStep} />
        ) : step === 'mfa' ? (
          <CodeStep onLogin={onLogin} onRestart={restart} />
        ) : step === 'enroll' ? (
          <EnrollStep
            onRestart={restart}
            onDone={(me, codes) => {
              setDone({ me, codes })
              setStep('codes')
            }}
          />
        ) : (
          done && <RecoveryCodes codes={done.codes} onContinue={() => onLogin(done.me)} />
        )}
      </div>
    </div>
  )
}

function Form({ onSubmit, children }: { onSubmit: () => Promise<void>; children: ReactNode }) {
  return (
    <form
      className="login-form"
      onSubmit={(e: FormEvent) => {
        e.preventDefault()
        void onSubmit()
      }}
    >
      {children}
    </form>
  )
}

function PasswordStep({ onNext }: { onNext: (step: 'mfa' | 'enroll') => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit() {
    setBusy(true)
    setError(null)
    try {
      const { stage } = await api.login(username, password)
      onNext(stage)
    } catch (err) {
      setError(errorText(err))
    } finally {
      setPassword('') // şifre formda kalmasın (başarıda da)
      setBusy(false)
    }
  }

  return (
    <Form onSubmit={submit}>
      <h1>Giriş</h1>
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
        {busy ? 'Kontrol ediliyor…' : 'Devam'}
      </button>
      <p className="muted login-hint">
        Şifreden sonra telefonundaki doğrulama kodu istenir. 15 dakikada 5 hatalı denemeden
        sonra hesap geçici olarak kilitlenir.
      </p>
    </Form>
  )
}

function CodeStep({ onLogin, onRestart }: { onLogin: (me: Me) => void; onRestart: () => void }) {
  const [code, setCode] = useState('')
  const [useRecovery, setUseRecovery] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit() {
    setBusy(true)
    setError(null)
    try {
      onLogin(await api.verifyCode(code))
    } catch (err) {
      setError(errorText(err))
      setCode('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Form onSubmit={submit}>
      <h1>Doğrulama kodu</h1>
      <p className="muted login-hint">
        {useRecovery
          ? 'Kurulumda kaydettiğin yedek kodlardan birini gir. Her kod yalnızca bir kez çalışır.'
          : 'Telefonundaki doğrulama uygulamasında (Google Authenticator vb.) Mini-SIEM için görünen 6 haneli kodu gir.'}
      </p>
      <label>
        <span>{useRecovery ? 'Yedek kod' : 'Kod'}</span>
        <input
          key={useRecovery ? 'recovery' : 'totp'}
          className="code-input"
          autoFocus
          autoComplete="one-time-code"
          inputMode={useRecovery ? 'text' : 'numeric'}
          placeholder={useRecovery ? 'xxxxx-xxxxx' : '123456'}
          maxLength={useRecovery ? 16 : 7}
          value={code}
          onChange={(e) => setCode(e.target.value)}
        />
      </label>
      {error && <div className="card card-danger" role="alert">{error}</div>}
      <button className="btn btn-primary" type="submit" disabled={busy || !code.trim()}>
        {busy ? 'Kontrol ediliyor…' : 'Giriş yap'}
      </button>
      <div className="login-links">
        <button
          type="button"
          className="btn btn-ghost"
          onClick={() => {
            setUseRecovery(!useRecovery)
            setCode('')
            setError(null)
          }}
        >
          {useRecovery ? 'Telefon kodunu kullan' : 'Telefonum yanımda değil'}
        </button>
        <button type="button" className="btn btn-ghost" onClick={onRestart}>
          Baştan başla
        </button>
      </div>
    </Form>
  )
}

function EnrollStep({
  onDone,
  onRestart,
}: {
  onDone: (me: Me, codes: string[]) => void
  onRestart: () => void
}) {
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null)
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.startEnrollment().then(setEnrollment).catch((err) => setError(errorText(err)))
  }, [])

  async function submit() {
    setBusy(true)
    setError(null)
    try {
      const r = await api.finishEnrollment(code)
      onDone(r.me, r.recovery_codes)
    } catch (err) {
      setError(errorText(err))
      setCode('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Form onSubmit={submit}>
      <h1>İki adımlı doğrulamayı kur</h1>
      <ol className="enroll-steps">
        <li>
          Telefonuna <b>Google Authenticator</b> (ya da Microsoft Authenticator) kur.
        </li>
        <li>Uygulamada “+” → “QR kodu tara” ile aşağıdaki kodu okut.</li>
        <li>Uygulamanın gösterdiği 6 haneli kodu yaz.</li>
      </ol>
      {enrollment ? (
        <>
          <img className="enroll-qr" src={enrollment.qr} alt="Doğrulama uygulaması için QR kod" />
          <details className="enroll-secret">
            <summary>QR okutamıyorum</summary>
            <p className="muted">Uygulamada “Kurulum anahtarı gir” seçip bunu yaz:</p>
            <code>{enrollment.secret.match(/.{1,4}/g)?.join(' ')}</code>
          </details>
          <label>
            <span>Uygulamadaki kod</span>
            <input
              className="code-input"
              autoFocus
              autoComplete="one-time-code"
              inputMode="numeric"
              placeholder="123456"
              maxLength={7}
              value={code}
              onChange={(e) => setCode(e.target.value)}
            />
          </label>
        </>
      ) : (
        !error && <p className="muted">Hazırlanıyor…</p>
      )}
      {error && <div className="card card-danger" role="alert">{error}</div>}
      <button
        className="btn btn-primary"
        type="submit"
        disabled={busy || !enrollment || !code.trim()}
      >
        {busy ? 'Kontrol ediliyor…' : 'Doğrula ve bitir'}
      </button>
      <div className="login-links">
        <button type="button" className="btn btn-ghost" onClick={onRestart}>
          Baştan başla
        </button>
      </div>
    </Form>
  )
}

function RecoveryCodes({ codes, onContinue }: { codes: string[]; onContinue: () => void }) {
  const [saved, setSaved] = useState(false)
  const [copied, setCopied] = useState(false)

  return (
    <div className="login-form">
      <h1>Yedek kodların</h1>
      <div className="card card-warn">
        Telefonun kaybolursa bu kodlarla girersin. Her biri <b>bir kez</b> çalışır.
        <b> Bu ekran bir daha gösterilmez</b>: kâğıda yaz ya da şifre yöneticine kaydet.
      </div>
      <ul className="recovery-codes">
        {codes.map((c) => (
          <li key={c}>
            <code>{c}</code>
          </li>
        ))}
      </ul>
      <button
        type="button"
        className="btn btn-ghost"
        onClick={() =>
          navigator.clipboard
            .writeText(codes.join('\n'))
            .then(() => setCopied(true))
            .catch(() => setCopied(false))
        }
      >
        {copied ? 'Kopyalandı' : 'Kodları kopyala'}
      </button>
      <label className="check">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
        <span>Kodları güvenli bir yere kaydettim</span>
      </label>
      <button className="btn btn-primary" type="button" disabled={!saved} onClick={onContinue}>
        SIEM'e geç
      </button>
    </div>
  )
}
