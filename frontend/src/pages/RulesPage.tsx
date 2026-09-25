import { useEffect, useState } from 'react'
import { api, type Rule } from '../lib/api'
import { MITRE, fmtNumber, mitreUrl } from '../lib/labels'
import type { Go } from '../lib/nav'

const CONFIG_LABEL: Record<string, string> = {
  window_minutes: 'Pencere (dk)',
  threshold: 'Eşik',
  high_threshold: 'Yüksek eşik',
  lookback_minutes: 'Geriye bakış (dk)',
  min_failures: 'En az başarısız',
  followup_minutes: 'Takip süresi (dk)',
  scan_unique_paths: 'Tarama: farklı yol',
}

export default function RulesPage({ go }: { go: Go }) {
  const [rules, setRules] = useState<Rule[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [msg, setMsg] = useState<string | null>(null)
  const [running, setRunning] = useState(false)

  const load = () => api.rules().then(setRules).catch((e: Error) => setError(e.message))
  useEffect(() => {
    load()
  }, [])

  async function rerun() {
    setRunning(true)
    try {
      const r = await api.rerunDetection()
      setMsg(`Kurallar tüm olaylar üzerinde çalıştı: ${r.created} yeni alert, ${r.updated} güncellenen alert.`)
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setRunning(false)
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Tespit Kuralları</h1>
          <p className="muted">
            Eşikler <code>config/rules.yaml</code> dosyasından okunur. Değiştirdikten sonra
            backend'i yeniden başlatıp kuralları tekrar çalıştır.
          </p>
        </div>
        <button className="btn btn-outline" disabled={running} onClick={rerun}>
          {running ? 'Çalışıyor…' : 'Kuralları yeniden çalıştır'}
        </button>
      </div>

      {msg && <div className="card card-ok">{msg}</div>}
      {error && <div className="card card-danger">{error}</div>}

      <div className="rule-grid">
        {rules?.map((r) => (
          <article key={r.id} className={`panel rule${r.enabled ? '' : ' disabled'}`}>
            <div className="rule-head">
              <span className="mono dim">{r.id}</span>
              <span className={`pill ${r.enabled ? 'pill-on' : 'pill-off'}`}>
                {r.enabled ? 'Etkin' : 'Kapalı'}
              </span>
            </div>
            <h2>{r.title}</h2>
            <p className="muted">{r.description}</p>
            {r.known_devices.length > 0 && (
              <div className="rule-devices">
                <span className="muted">Bilinen cihazlar:</span>
                {r.known_devices.map((d) => (
                  <span key={d} className="chip">{d}</span>
                ))}
              </div>
            )}
            {r.skips_proxies && (
              <p className="rule-note">Hacim tabanlı: aracı sunucu IP'lerinde çalışmaz.</p>
            )}
            {r.alert_on && (
              <p className="rule-note">
                {r.alert_on === 'all'
                  ? 'Her imza eşleşmesi alarm üretir.'
                  : 'Yalnızca sunucu başarılı (2xx) yanıt verdiyse alarm üretir; engellenen denemeler olaylarda görünür.'}
              </p>
            )}
            {r.signature_rules.length > 0 && (
              <details className="rule-sigma">
                <summary>{r.signature_rules.length} Sigma kuralı (SigmaHQ · DRL 1.1)</summary>
                <ul className="plain">
                  {r.signature_rules.map((s) => (
                    <li key={s.name}>
                      <span className={`sev-dot sev-${s.level}`} aria-hidden /> {s.title}
                      <span className="dim"> · {s.author}</span>
                    </li>
                  ))}
                </ul>
              </details>
            )}

            <dl className="config">
              {Object.entries(r.config).map(([k, v]) => (
                <div key={k}>
                  <dt>{CONFIG_LABEL[k] ?? k}</dt>
                  <dd className="mono">{v}</dd>
                </div>
              ))}
            </dl>

            <div className="rule-mitre">
              {r.mitre.length ? (
                r.mitre.map((t) => (
                  <a key={t} className="mitre" href={mitreUrl(t)} target="_blank" rel="noopener noreferrer">
                    <span className="mono">{t}</span>
                    <span>{MITRE[t]?.name}</span>
                    <span className="dim">{MITRE[t]?.tactic}</span>
                  </a>
                ))
              ) : (
                <span className="muted">
                  MITRE eşlemesi yok — kuralın anlamıyla birebir örtüşen bir teknik olmadığından
                  tahmini eşleme yapılmadı.
                </span>
              )}
            </div>

            <button className="rule-foot link-btn" onClick={() => go('alerts', { alerts: { rule_id: r.id, status: '' } })}>
              {fmtNumber(r.alert_count)} alert · {fmtNumber(r.open_alert_count)} açık →
            </button>
          </article>
        ))}
      </div>
    </>
  )
}
