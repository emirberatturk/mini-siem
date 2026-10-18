import { useEffect, useMemo, useState } from 'react'
import { api, type WeeklyReport, type WeeklyTotals } from '../lib/api'
import { RULE_LABEL, SEVERITY_LABEL, STATUS_LABEL, fmtNumber, fmtTime } from '../lib/labels'
import { maskDeep } from '../lib/mask'

/** "2026-09-23" yerel gününü kaydırmadan biçimlendirir (UTC gece yarısı olarak okunur). */
const fmtDay = (d: string, opts: Intl.DateTimeFormatOptions = { day: 'numeric', month: 'long' }) =>
  new Date(`${d}T00:00:00Z`).toLocaleDateString('tr-TR', { timeZone: 'UTC', ...opts })

function Delta({ now, before }: { now: number; before: number }) {
  if (before === 0) return <span className="report-muted">{now ? 'önceki hafta yok' : '—'}</span>
  const pct = Math.round(((now - before) / before) * 100)
  const cls = pct > 0 ? 'delta-up' : pct < 0 ? 'delta-down' : 'report-muted'
  return <span className={cls}>{pct > 0 ? '+' : ''}{pct}% · önceki: {fmtNumber(before)}</span>
}

type WeeklyAlert = WeeklyReport['alerts'][number]

/** Aynı kural, önem, kaynak ve aynı kararla kapatılan alarmlar tek satır olur: yöneticiye giden
 *  raporda 17 özdeş satır yerine "#72–88 · 17 alarm". Kararı olmayan alarmlar hep ayrı kalır. */
function groupAlerts(alerts: WeeklyAlert[]): { first: WeeklyAlert; ids: number[] }[] {
  const groups = new Map<string, { first: WeeklyAlert; ids: number[] }>()
  for (const a of alerts) {
    const key = a.decided_by
      ? JSON.stringify([a.rule_id, a.severity, a.status, a.source_ip, a.decided_by, a.decision_note])
      : `tek-${a.id}`
    const g = groups.get(key)
    if (g) g.ids.push(a.id)
    else groups.set(key, { first: a, ids: [a.id] })
  }
  return [...groups.values()]
}

const idLabel = (ids: number[]) => {
  if (ids.length === 1) return `${ids[0]}`
  const sorted = [...ids].sort((x, y) => x - y)
  const consecutive = sorted.every((id, i) => i === 0 || id === sorted[i - 1] + 1)
  return consecutive ? `${sorted[0]}–${sorted[sorted.length - 1]}` : sorted.join(', ')
}

const KPIS: { key: keyof WeeklyTotals; label: string }[] = [
  { key: 'events', label: 'Olay (istek)' },
  { key: 'suspicious', label: 'Saldırı imzası / anomali' },
  { key: 'client_errors', label: 'İstemci hatası (4xx)' },
  { key: 'auth_fail', label: 'Başarısız site girişi' },
  { key: 'alerts', label: 'Yeni alarm' },
]

/**
 * Haftalık özet rapor (yöneticiye / hocaya verilecek belge). Olay raporu gibi tarayıcıdan
 * "PDF olarak kaydet" ile PDF'e dönüşür; hiçbir veri dışarı gönderilmez. IP'ler varsayılan maskeli.
 */
export default function WeeklyReportPage({ initialEnd }: { initialEnd?: string }) {
  const [end, setEnd] = useState<string | undefined>(initialEnd)
  const [raw, setRaw] = useState<WeeklyReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [maskIps, setMaskIps] = useState(true)
  const generatedAt = useMemo(() => new Date().toISOString(), [])

  useEffect(() => {
    api.weekly(end).then(setRaw).catch((e: Error) => setError(e.message))
  }, [end])

  useEffect(() => {
    document.body.classList.add('report-body')
    return () => document.body.classList.remove('report-body')
  }, [])

  useEffect(() => {
    if (!raw) return
    document.title = `Haftalık Rapor ${raw.first_day} – ${raw.last_day} · Mini-SIEM`
  }, [raw])

  const goWeek = (day: string) => {
    window.history.replaceState(null, '', `#weekly/${day}`)
    setRaw(null)
    setEnd(day)
  }

  if (error) return <div className="report"><p>Rapor oluşturulamadı: {error}</p></div>
  if (!raw) return <div className="report"><p>Yükleniyor…</p></div>

  const r = maskIps ? maskDeep(raw) : raw
  const t = r.totals
  const maxEvents = Math.max(1, ...r.days.map((d) => d.events))
  const decided = r.alerts.filter((a) => a.status === 'false_positive' || a.status === 'resolved')
  const fp = r.alerts_by_status.false_positive ?? 0
  const blockedPct = t.suspicious ? Math.round((t.suspicious_blocked / t.suspicious) * 100) : null

  return (
    <div className="report">
      <div className="report-toolbar no-print">
        <div className="week-nav">
          <button className="btn btn-ghost" disabled={!r.prev_last_day}
                  onClick={() => r.prev_last_day && goWeek(r.prev_last_day)}>
            ← Önceki hafta
          </button>
          <button className="btn btn-ghost" disabled={!r.next_last_day}
                  onClick={() => r.next_last_day && goWeek(r.next_last_day)}>
            Sonraki hafta →
          </button>
        </div>
        <label>
          <input type="checkbox" checked={maskIps} onChange={(e) => setMaskIps(e.target.checked)} />
          IP adreslerini maskele
        </label>
        <button className="btn btn-primary" onClick={() => window.print()}>
          Yazdır / PDF olarak kaydet
        </button>
      </div>

      <header className="report-head">
        <div>
          <div className="report-kicker">Mini-SIEM · Haftalık Güvenlik Raporu</div>
          <h1>
            {fmtDay(r.first_day)} – {fmtDay(r.last_day, { day: 'numeric', month: 'long', year: 'numeric' })}
          </h1>
        </div>
        <div className="report-meta">
          <div>Oluşturma: {fmtTime(generatedAt)}</div>
          <div>IP adresleri: {maskIps ? 'maskeli' : 'açık'}</div>
        </div>
      </header>

      {r.missing_days.length > 0 && (
        <p className="report-warn">
          ⚠ Şu günlerde hiç kayıt yok: {r.missing_days.map((d) => fmtDay(d)).join(', ')}. O günlerin
          logu yüklenmemiş olabilir; rakamlar eksik olabilir.
        </p>
      )}

      <section>
        <h2>Özet</h2>
        <div className="kpi-grid">
          {KPIS.map((k) => (
            <div key={k.key} className="kpi">
              <div className="kpi-label">{k.label}</div>
              <div className="kpi-value">{fmtNumber(t[k.key])}</div>
              <div className="kpi-delta"><Delta now={t[k.key]} before={r.previous[k.key]} /></div>
            </div>
          ))}
        </div>
        <ul className="report-bullets">
          <li>
            {blockedPct === null
              ? 'Bu hafta saldırı imzası ya da anomali bulunan istek yok.'
              : <>Saldırı imzası/anomali bulunan {fmtNumber(t.suspicious)} isteğin <strong>%{blockedPct}</strong>'i
                sunucu tarafından reddedildi (başarılı yanıt almadı).</>}
          </li>
          <li>
            {fmtNumber(t.alerts)} yeni alarmın {fmtNumber(decided.length)} tanesi karara bağlandı
            {decided.length > 0 && <> ({fmtNumber(fp)} yanlış alarm)</>}. Tüm zamanlarda hâlâ açık
            alarm: <strong>{fmtNumber(r.open_alerts_total)}</strong>.
          </li>
          <li>Site girişleri: {fmtNumber(t.auth_ok)} başarılı, {fmtNumber(t.auth_fail)} başarısız.</li>
        </ul>
      </section>

      <section>
        <h2>Günlük dağılım</h2>
        <table className="report-table">
          <thead>
            <tr><th>Gün</th><th>Olay</th><th /><th>İmza/anomali</th><th>Başarısız giriş</th><th>Alarm</th></tr>
          </thead>
          <tbody>
            {r.days.map((d) => (
              <tr key={d.day} className={d.events === 0 ? 'report-muted' : ''}>
                <td className="nowrap">{fmtDay(d.day, { weekday: 'short', day: 'numeric', month: 'short' })}</td>
                <td className="mono">{d.events ? fmtNumber(d.events) : 'log yok'}</td>
                <td className="bar-cell">
                  <span className="bar" style={{ width: `${(d.events / maxEvents) * 100}%` }} />
                </td>
                <td className="mono">{fmtNumber(d.suspicious)}</td>
                <td className="mono">{fmtNumber(d.auth_failures)}</td>
                <td className="mono">{fmtNumber(d.alerts)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section>
        <h2>Alarmlar ve analist kararları</h2>
        {r.alerts.length === 0 ? (
          <p className="report-muted">Bu hafta alarm yok.</p>
        ) : (
          <table className="report-table">
            <thead>
              <tr><th>#</th><th>Önem</th><th>Kural</th><th>Kaynak</th><th>Durum</th><th>Karar</th></tr>
            </thead>
            <tbody>
              {groupAlerts(r.alerts).map(({ first: a, ids }) => (
                <tr key={a.id}>
                  <td className="mono">
                    {idLabel(ids)}
                    {ids.length > 1 && <div className="report-muted">{ids.length} alarm</div>}
                  </td>
                  <td>{SEVERITY_LABEL[a.severity]}</td>
                  <td>{a.rule_id} · {RULE_LABEL[a.rule_id] ?? a.title}</td>
                  <td className="mono">{a.source_ip}</td>
                  <td className="nowrap">{STATUS_LABEL[a.status]}</td>
                  <td className="break">
                    {a.decided_by ? <>{a.decided_by}{a.decision_note && <> — {a.decision_note}</>}</>
                      : <span className="report-muted">incelenmedi</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {(r.top_signatures.length > 0 || r.top_anomalies.length > 0) && (
        <section>
          <h2>Saldırı imzaları ve anomaliler</h2>
          <table className="report-table">
            <thead><tr><th>Bulgu</th><th>İstek</th><th>Reddedilen</th></tr></thead>
            <tbody>
              {[...r.top_signatures, ...r.top_anomalies].map((s) => (
                <tr key={s.key}>
                  <td>{s.label}</td>
                  <td className="mono">{fmtNumber(s.count)}</td>
                  <td className="mono">{fmtNumber(s.blocked)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {r.top_sources.length > 0 && (
        <section>
          <h2>En çok hata / şüpheli istek üreten adresler</h2>
          <table className="report-table">
            <thead><tr><th>Adres</th><th>İstek</th><th /></tr></thead>
            <tbody>
              {r.top_sources.map((s) => (
                <tr key={s.key}>
                  <td className="mono">{s.key}</td>
                  <td className="mono">{fmtNumber(s.count)}</td>
                  <td>{s.proxy && <span className="tag">aracı sunucu: arkasında farklı kişiler olabilir</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section>
        <h2>Veri saklama (KVKK)</h2>
        <p>
          Loglar <strong>{r.retention_days} gün</strong> saklanır; süresi dolan kayıtlar silinir,
          kapatılmış alarmlarda IP adresleri maskelenir.
          {r.oldest_event && r.next_purge_at && (
            <> En eski kayıt {fmtTime(r.oldest_event)} tarihli; {fmtTime(r.next_purge_at)} sonrasında
              silinecek.</>
          )}
        </p>
      </section>

      <footer className="report-foot">
        Bu rapor Mini-SIEM tarafından üretildi. Haftalar logdaki olay zamanına göre (Türkiye saati)
        hesaplanır. Telefon, e-posta ve TC Kimlik No gibi kişisel veriler kayıt sırasında
        maskelenmiştir; IP adresleri bu raporda {maskIps ? 'maskelenmiştir' : 'AÇIKTIR'}. KVKK
        kapsamında yalnızca yetkili kişilerle paylaşın.
      </footer>
    </div>
  )
}
