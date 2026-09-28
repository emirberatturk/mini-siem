import { useEffect, useMemo, useState } from 'react'
import { Evidence } from '../components/Evidence'
import { api, type AlertDetail } from '../lib/api'
import { MITRE, RULE_LABEL, SEVERITY_LABEL, STATUS_LABEL, fmtNumber, fmtTime } from '../lib/labels'
import { maskDeep } from '../lib/mask'

const MAX_EVENTS = 50

/**
 * Yazdırılabilir olay raporu (SOC'lerde yöneticiye/ekibe verilen belge).
 * Tarayıcının "PDF olarak kaydet" özelliğiyle PDF'e dönüşür; sunucuya yeni bir şey eklenmez.
 * Varsayılan olarak IP adresleri maskelidir: rapor paylaşılmak için üretilir.
 */
export default function ReportPage({ alertId }: { alertId: number }) {
  const [raw, setRaw] = useState<AlertDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [maskIps, setMaskIps] = useState(true)
  const generatedAt = useMemo(() => new Date().toISOString(), [])

  useEffect(() => {
    api.alert(alertId).then(setRaw).catch((e: Error) => setError(e.message))
  }, [alertId])

  useEffect(() => {
    document.title = `Olay Raporu #${alertId} · Mini-SIEM`
    document.body.classList.add('report-body') // koyu tema yerine beyaz "kâğıt"
    return () => document.body.classList.remove('report-body')
  }, [alertId])

  if (error) return <div className="report"><p>Rapor oluşturulamadı: {error}</p></div>
  if (!raw) return <div className="report"><p>Yükleniyor…</p></div>

  const alert = maskIps ? maskDeep(raw) : raw
  const decision = [...alert.history].reverse().find((h) => h.changed_by !== 'sistem')
  const events = alert.events.slice(0, MAX_EVENTS)

  return (
    <div className="report">
      <div className="report-toolbar no-print">
        <label>
          <input type="checkbox" checked={maskIps} onChange={(e) => setMaskIps(e.target.checked)} />
          IP adreslerini maskele (paylaşmak için önerilir)
        </label>
        <button className="btn btn-primary" onClick={() => window.print()}>
          Yazdır / PDF olarak kaydet
        </button>
      </div>

      <header className="report-head">
        <div>
          <div className="report-kicker">Mini-SIEM · Olay Raporu</div>
          <h1>#{alert.id} · {alert.title}</h1>
        </div>
        <div className="report-meta">
          <div>Oluşturma: {fmtTime(generatedAt)}</div>
          <div>IP adresleri: {maskIps ? 'maskeli' : 'açık'}</div>
        </div>
      </header>

      <section>
        <h2>Özet</h2>
        <table className="report-facts">
          <tbody>
            <tr><th>Kural</th><td>{alert.rule_id} · {RULE_LABEL[alert.rule_id] ?? ''}</td></tr>
            <tr><th>Önem</th><td>{SEVERITY_LABEL[alert.severity]}</td></tr>
            <tr><th>Durum</th><td>{STATUS_LABEL[alert.status]}</td></tr>
            <tr><th>Kaynak IP</th><td className="mono">{alert.source_ip}</td></tr>
            <tr><th>Zaman aralığı</th><td>{fmtTime(alert.first_seen)} → {fmtTime(alert.last_seen)}</td></tr>
            <tr><th>Olay sayısı</th><td>{fmtNumber(alert.event_count)}</td></tr>
            {alert.mitre.length > 0 && (
              <tr>
                <th>MITRE ATT&CK</th>
                <td>{alert.mitre.map((t) => `${t} ${MITRE[t]?.name ?? ''}`).join(' · ')}</td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      <section>
        <h2>Ne oldu?</h2>
        <p>{alert.reason}</p>
      </section>

      <section>
        <h2>Analist kararı</h2>
        {decision ? (
          <p>
            <strong>{STATUS_LABEL[decision.to_status]}</strong> · {decision.changed_by} ·{' '}
            {fmtTime(decision.changed_at)}
            {decision.note && <><br />{decision.note}</>}
          </p>
        ) : (
          <p className="report-muted">Henüz incelenmedi.</p>
        )}
      </section>

      <section>
        <h2>Kanıt</h2>
        <Evidence evidence={alert.evidence} />
      </section>

      <section>
        <h2>İlgili olaylar{alert.event_count > events.length && ` (ilk ${events.length} / ${fmtNumber(alert.event_count)})`}</h2>
        <table className="report-table">
          <thead>
            <tr><th>Zaman</th><th>IP</th><th>İstek</th><th>Kod</th><th>Bayt</th></tr>
          </thead>
          <tbody>
            {events.map((e, i) => (
              <tr key={e.id ?? i}>
                <td className="mono nowrap">{fmtTime(e.timestamp)}</td>
                <td className="mono">{e.source_ip}</td>
                <td className="mono break">
                  {e.http_method ?? '?'} {e.url_path}{e.url_query && `?${e.url_query}`}
                </td>
                <td className="mono">{e.status_code}</td>
                <td className="mono">{fmtNumber(e.bytes_sent)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section>
        <h2>Denetim kaydı</h2>
        <ol className="report-history">
          {alert.history.map((h, i) => (
            <li key={i}>
              {fmtTime(h.changed_at)} · <strong>{STATUS_LABEL[h.to_status]}</strong> · {h.changed_by}
              {h.note && <> — {h.note}</>}
            </li>
          ))}
        </ol>
      </section>

      <section>
        <h2>Önerilen adımlar</h2>
        <ol>
          {alert.recommended_steps.map((s) => <li key={s}>{s}</li>)}
        </ol>
      </section>

      <footer className="report-foot">
        Bu rapor Mini-SIEM tarafından üretildi. Telefon, e-posta ve TC Kimlik No gibi kişisel
        veriler kayıt sırasında maskelenmiştir; IP adresleri bu raporda{' '}
        {maskIps ? 'maskelenmiştir' : 'AÇIKTIR'}. KVKK kapsamında yalnızca yetkili kişilerle
        paylaşın.
      </footer>
    </div>
  )
}
