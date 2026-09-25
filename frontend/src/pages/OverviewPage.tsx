import { useCallback, useEffect, useState } from 'react'
import { SeverityBadge, StatusBadge } from '../components/Badges'
import { BarList } from '../components/BarList'
import { Timeline } from '../components/Timeline'
import { api, type Overview, type Severity } from '../lib/api'
import { EVENT_LABEL, RULE_LABEL, SEVERITIES, SEVERITY_LABEL, fmtNumber, fmtTime } from '../lib/labels'
import type { EventType } from '../lib/api'
import type { Go } from '../lib/nav'

export default function OverviewPage({ go }: { go: Go }) {
  const [data, setData] = useState<Overview | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    api.overview().then(setData).catch((e: Error) => setError(e.message))
  }, [])

  useEffect(() => {
    load()
    const id = setInterval(load, 15_000) // SOC ekranı: kendiliğinden tazelenir
    return () => clearInterval(id)
  }, [load])

  if (error) return <div className="card card-danger">Veriler alınamadı: {error}</div>
  if (!data) return <div className="muted">Yükleniyor…</div>

  if (data.total_events === 0) {
    return (
      <>
        <h1>Genel Bakış</h1>
        <div className="card empty-state">
          <h2>Henüz veri yok</h2>
          <p className="muted">
            Başlamak için bir Apache/cPanel log dosyası yükle. Olaylar ayrıştırılır, kişisel
            veriler maskelenir ve tespit kuralları otomatik çalışır.
          </p>
          <button className="btn btn-primary" onClick={() => go('upload')}>
            Log yükle
          </button>
        </div>
      </>
    )
  }

  const openTotal = SEVERITIES.reduce((s, k) => s + data.open_alerts_by_severity[k], 0)

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Genel Bakış</h1>
          {data.range_start && data.range_end && (
            <p className="muted">
              Veri aralığı: {fmtTime(data.range_start)} — {fmtTime(data.range_end)}
            </p>
          )}
        </div>
      </div>

      {data.proxy_event_share > 0 && (
        <div className="card card-warn notice">
          <strong>Aracı sunucu üzerinden gelen trafik: %{fmtNumber(data.proxy_event_share)}</strong>
          <span className="mono"> ({data.proxy_ips.join(', ')})</span>
          <p className="muted">
            Bu adres bir ziyaretçi değil, hosting firmasının önündeki sunucu: gerçek ziyaretçi IP'leri
            logda görünmüyor. Bu yüzden "çok istek / çok 404" kuralları bu adres için kapalı; giriş
            kuralları çalışıyor ama bir alert'in arkasında tek kişi olduğu varsayılamaz.
          </p>
        </div>
      )}

      <div className="kpi-grid">
        <div className="stat">
          <div className="card-label">Toplam olay</div>
          <div className="stat-value">{fmtNumber(data.total_events)}</div>
          <div className="muted">
            ort. {fmtNumber(data.events_per_minute)}/dk · tepe {fmtNumber(data.peak_events_per_minute)}/dk
          </div>
        </div>
        <button
          className="stat clickable"
          onClick={() => go('alerts', { alerts: { status: 'open' } })}
        >
          <div className="card-label">Açık alert</div>
          <div className="stat-value">{fmtNumber(openTotal)}</div>
          <div className="muted">
            toplam {fmtNumber(data.total_alerts)}
            {data.false_positives > 0 && ` · ${fmtNumber(data.false_positives)} yanlış alarm`}
          </div>
        </button>
        {SEVERITIES.map((s: Severity) => (
          <button
            key={s}
            className={`stat clickable stat-sev stat-sev-${s}`}
            onClick={() => go('alerts', { alerts: { severity: s, status: 'open' } })}
          >
            <div className="card-label">{SEVERITY_LABEL[s]}</div>
            <div className="stat-value">{fmtNumber(data.open_alerts_by_severity[s])}</div>
            <div className="muted">açık</div>
          </button>
        ))}
      </div>

      <section className="panel">
        <h2 className="panel-title">Olay ve saldırı zaman çizelgesi</h2>
        <Timeline buckets={data.timeline} bucketMinutes={data.bucket_minutes} />
      </section>

      <div className="panel-grid">
        <section className="panel">
          <h2 className="panel-title">En çok istek yapan IP'ler</h2>
          <BarList
            items={data.top_ips}
            mono
            onSelect={(ip) => go('hunt', { hunt: { ip } })}
          />
          <p className="panel-hint">Bir IP'ye tıkla → olaylarını incele</p>
        </section>

        <section className="panel">
          <h2 className="panel-title">En çok tetiklenen kurallar</h2>
          <BarList
            items={data.top_rules}
            label={(k) => (
              <>
                <span className="mono dim">{k}</span> {RULE_LABEL[k] ?? ''}
              </>
            )}
            onSelect={(rule_id) => go('alerts', { alerts: { rule_id } })}
            empty="Henüz alert yok"
          />
        </section>

        <section className="panel">
          <h2 className="panel-title">HTTP yanıt dağılımı</h2>
          <BarList
            items={data.status_classes}
            label={(k) => `${k} ${STATUS_CLASS[k] ?? ''}`}
            onSelect={(status) => go('hunt', { hunt: { status } })}
          />
          <h2 className="panel-title spaced">Olay türleri</h2>
          <BarList
            items={data.event_types}
            label={(k) => EVENT_LABEL[k as EventType] ?? k}
            onSelect={(event_type) => go('hunt', { hunt: { event_type } })}
          />
        </section>
      </div>

      <section className="panel">
        <div className="panel-head">
          <h2 className="panel-title">Son alertler</h2>
          <button className="btn btn-ghost" onClick={() => go('alerts')}>
            Tümü →
          </button>
        </div>
        {data.recent_alerts.length === 0 ? (
          <div className="muted empty">Bu aralıkta alert yok — kurallar tetiklenmedi.</div>
        ) : (
          <div className="table-wrap flat">
            <table className="table">
              <thead>
                <tr>
                  <th>Önem</th>
                  <th>Alert</th>
                  <th>Kaynak IP</th>
                  <th>Olay</th>
                  <th>Son görülme</th>
                  <th>Durum</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_alerts.map((a) => (
                  <tr key={a.id} className="clickable" onClick={() => go('alerts', { alertId: a.id })}>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td>
                      <div>{a.title}</div>
                      <div className="mono dim">{a.rule_id}</div>
                    </td>
                    <td className="mono">{a.source_ip}</td>
                    <td className="mono">{fmtNumber(a.event_count)}</td>
                    <td className="mono nowrap">{fmtTime(a.last_seen)}</td>
                    <td><StatusBadge status={a.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  )
}

const STATUS_CLASS: Record<string, string> = {
  '2xx': 'Başarılı',
  '3xx': 'Yönlendirme',
  '4xx': 'İstemci hatası',
  '5xx': 'Sunucu hatası',
}
