import { useRef, useState, type DragEvent } from 'react'
import { api, type EventType, type IngestSummary } from '../lib/api'
import { EVENT_LABEL, fmtNumber as n, fmtTime } from '../lib/labels'
import type { Go } from '../lib/nav'

type State =
  | { kind: 'idle' }
  | { kind: 'uploading'; name: string }
  | { kind: 'done'; summary: IngestSummary }
  | { kind: 'error'; message: string }


function formatBytes(n: number) {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

export default function UploadPage({ go }: { go: Go }) {
  const [state, setState] = useState<State>({ kind: 'idle' })
  const [dragging, setDragging] = useState(false)
  const input = useRef<HTMLInputElement>(null)

  async function send(file: File) {
    setState({ kind: 'uploading', name: file.name })
    try {
      setState({ kind: 'done', summary: await api.uploadLog(file) })
    } catch (e) {
      setState({ kind: 'error', message: e instanceof Error ? e.message : String(e) })
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) send(file)
  }

  return (
    <>
      <h1>Log Yükle</h1>
      <p className="muted">
        cPanel → Metrics → Raw Access'ten indirdiğin <code>.gz</code> dosyasını ya da Apache
        biçimindeki bir log dosyasını buraya bırak.
      </p>

      <div
        className={`dropzone${dragging ? ' dragging' : ''}`}
        onDragOver={(e) => {
          e.preventDefault()
          setDragging(true)
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => input.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && input.current?.click()}
      >
        <div className="dropzone-icon" aria-hidden>⇪</div>
        {state.kind === 'uploading' ? (
          <div>
            <strong>{state.name}</strong> işleniyor…
          </div>
        ) : (
          <div>
            Dosyayı sürükle bırak veya <span className="link">seç</span>
            <div className="muted">.log, .txt veya .gz · en fazla 50 MB</div>
          </div>
        )}
        <input
          ref={input}
          type="file"
          hidden
          onChange={(e) => {
            const file = e.target.files?.[0]
            if (file) send(file)
            e.target.value = '' // aynı dosya tekrar seçilebilsin
          }}
        />
      </div>

      {state.kind === 'error' && <div className="card card-danger">Yüklenemedi: {state.message}</div>}
      {state.kind === 'done' && <Result s={state.summary} go={go} />}
    </>
  )
}

function Result({ s, go }: { s: IngestSummary; go: Go }) {
  const alerts = s.alerts_created + s.alerts_updated
  return (
    <>
      <h2 className="section-title">{s.filename}</h2>
      <div className={`card ${alerts ? 'card-warn' : 'card-ok'} result-banner`}>
        {alerts ? (
          <>
            <span>
              Tespit kuralları çalıştı: <strong>{n(s.alerts_created)}</strong> yeni alert
              {s.alerts_updated > 0 && <>, {n(s.alerts_updated)} mevcut alert güncellendi</>}.
            </span>
            <button className="btn btn-primary" onClick={() => go('alerts')}>Alertleri incele →</button>
          </>
        ) : (
          <>
            <span>Tespit kuralları çalıştı: bu dosyada şüpheli davranış bulunmadı.</span>
            <button className="btn btn-ghost" onClick={() => go('overview')}>Genel bakışa git →</button>
          </>
        )}
      </div>
      <div className="stat-grid">
        <Stat
          label="Ayrıştırılan olay"
          value={n(s.events_parsed)}
          hint={`${n(s.lines_total)} satırdan · ${n(s.lines_failed)} bozuk`}
        />
        <Stat
          label="Veritabanına eklenen"
          value={n(s.events_inserted)}
          hint={s.duplicates ? `${n(s.duplicates)} olay zaten vardı (tekrar yükleme)` : 'hepsi yeni'}
        />
        <Stat
          label="KVKK maskeleme"
          value={n(s.redactions)}
          hint="kişisel veri / sorgu değeri gizlendi"
          accent="ok"
        />
        <Stat
          label="Boyut"
          value={formatBytes(s.size_bytes)}
          hint={s.compressed ? 'gzip' : 'sıkıştırılmamış'}
        />
      </div>

      <h2 className="section-title">Olay türleri</h2>
      <div className="chips">
        {Object.entries(s.event_types).map(([type, count]) => (
          <span key={type} className={`chip chip-${type}`}>
            {EVENT_LABEL[type as EventType] ?? type} <strong>{n(count ?? 0)}</strong>
          </span>
        ))}
      </div>

      <h2 className="section-title">Örnek olaylar (maskelenmiş hâliyle)</h2>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Zaman (TR)</th>
              <th>IP</th>
              <th>Tür</th>
              <th>İstek</th>
              <th>Kod</th>
            </tr>
          </thead>
          <tbody>
            {s.samples.map((e, i) => (
              <tr key={i}>
                <td className="mono nowrap">
                  {fmtTime(e.timestamp)}
                </td>
                <td className="mono">{e.source_ip}</td>
                <td>
                  <span className={`chip chip-${e.event_type}`}>{EVENT_LABEL[e.event_type]}</span>
                </td>
                <td className="mono break">
                  {/* Log verisi daima düz metin olarak basılır (React escape eder) */}
                  {e.http_method ?? '?'} {e.url_path}
                  {e.url_query && `?${e.url_query}`}
                </td>
                <td className={`mono status-${String(e.status_code)[0]}`}>{e.status_code}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

function Stat({
  label,
  value,
  hint,
  accent,
}: {
  label: string
  value: string
  hint?: string
  accent?: 'ok'
}) {
  return (
    <div className={`stat${accent ? ` stat-${accent}` : ''}`}>
      <div className="card-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="muted">{hint}</div>}
    </div>
  )
}
