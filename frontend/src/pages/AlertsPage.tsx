import { useCallback, useEffect, useState } from 'react'
import { SeverityBadge, StatusBadge } from '../components/Badges'
import { Pager } from '../components/Pager'
import { api, type Alert, type AlertDetail, type AlertStatus, type Page } from '../lib/api'
import {
  EVENT_LABEL,
  MITRE,
  NEXT_STATUS,
  NOTE_REQUIRED,
  RULE_LABEL,
  SEVERITIES,
  SEVERITY_LABEL,
  STATUSES,
  STATUS_LABEL,
  fmtNumber,
  fmtTime,
  mitreUrl,
} from '../lib/labels'
import type { AlertFilters, Go } from '../lib/nav'

const OPEN = ['new', 'investigating', 'confirmed']
const PAGE_SIZE = 25

export default function AlertsPage({
  go,
  initialFilters,
  initialAlertId,
}: {
  go: Go
  initialFilters?: AlertFilters
  initialAlertId?: number
}) {
  const [filters, setFilters] = useState<AlertFilters>(initialFilters ?? { status: 'open' })
  const [page, setPage] = useState(0)
  const [data, setData] = useState<Page<Alert> | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<number | null>(initialAlertId ?? null)

  const load = useCallback(() => {
    const status = filters.status === 'open' ? OPEN : filters.status
    api
      .alerts({ ...filters, status, limit: PAGE_SIZE, offset: page * PAGE_SIZE })
      .then((d) => {
        setData(d)
        setError(null)
      })
      .catch((e: Error) => setError(e.message))
  }, [filters, page])

  useEffect(load, [load])

  const set = (patch: Partial<AlertFilters>) => {
    setPage(0)
    setFilters((f) => ({ ...f, ...patch }))
  }

  return (
    <>
      <div className="page-head">
        <h1>Alertler</h1>
      </div>

      <div className="filters">
        <select value={filters.status ?? ''} onChange={(e) => set({ status: e.target.value || undefined })}>
          <option value="open">Açık alertler</option>
          <option value="">Tüm durumlar</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>{STATUS_LABEL[s]}</option>
          ))}
        </select>
        <select value={filters.severity ?? ''} onChange={(e) => set({ severity: e.target.value || undefined })}>
          <option value="">Tüm önem seviyeleri</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>
          ))}
        </select>
        <select value={filters.rule_id ?? ''} onChange={(e) => set({ rule_id: e.target.value || undefined })}>
          <option value="">Tüm kurallar</option>
          {Object.entries(RULE_LABEL).map(([id, name]) => (
            <option key={id} value={id}>{id} · {name}</option>
          ))}
        </select>
        <input
          placeholder="Kaynak IP"
          value={filters.ip ?? ''}
          onChange={(e) => set({ ip: e.target.value.trim() || undefined })}
          className="mono"
        />
        {Object.values(filters).some(Boolean) && (
          <button className="btn btn-ghost" onClick={() => { setPage(0); setFilters({}) }}>
            Filtreleri temizle
          </button>
        )}
      </div>

      {error && <div className="card card-danger">{error}</div>}

      {data && (
        <section className="panel flush">
          {data.items.length === 0 ? (
            <div className="muted empty">Bu filtrelerle alert yok.</div>
          ) : (
            <div className="table-wrap flat">
              <table className="table">
                <thead>
                  <tr>
                    <th>Önem</th>
                    <th>Alert</th>
                    <th>Kaynak IP</th>
                    <th>Olay</th>
                    <th>İlk / son görülme</th>
                    <th>Durum</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((a) => (
                    <tr
                      key={a.id}
                      className={`clickable${selected === a.id ? ' selected' : ''}`}
                      onClick={() => setSelected(a.id)}
                    >
                      <td><SeverityBadge severity={a.severity} /></td>
                      <td>
                        <div>{a.title}</div>
                        <div className="mono dim">#{a.id} · {a.rule_id}</div>
                      </td>
                      <td className="mono">{a.source_ip}</td>
                      <td className="mono">{fmtNumber(a.event_count)}</td>
                      <td className="mono nowrap dim">
                        {fmtTime(a.first_seen)}
                        <br />
                        {fmtTime(a.last_seen)}
                      </td>
                      <td><StatusBadge status={a.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <Pager page={page} total={data.total} size={PAGE_SIZE} onPage={setPage} />
        </section>
      )}

      {selected !== null && (
        <AlertDrawer
          key={selected}
          id={selected}
          go={go}
          onClose={() => setSelected(null)}
          onChanged={load}
        />
      )}
    </>
  )
}

function AlertDrawer({
  id,
  go,
  onClose,
  onChanged,
}: {
  id: number
  go: Go
  onClose: () => void
  onChanged: () => void
}) {
  const [alert, setAlert] = useState<AlertDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [target, setTarget] = useState<AlertStatus | null>(null)
  const [note, setNote] = useState('')
  const [saving, setSaving] = useState(false)

  // Başka bir alert seçilince bileşen key={id} ile yeniden kurulur; state kendiliğinden sıfırlanır
  useEffect(() => {
    api.alert(id).then(setAlert).catch((e: Error) => setError(e.message))
  }, [id])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  async function save() {
    if (!alert || !target) return
    setSaving(true)
    try {
      setAlert(await api.setAlertStatus(alert.id, target, note))
      setTarget(null)
      setNote('')
      setError(null)
      onChanged()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setSaving(false)
    }
  }

  const needsNote = alert && target ? NOTE_REQUIRED(alert.status, target) : false

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="Alert detayı">
        <button className="drawer-close" onClick={onClose} aria-label="Kapat">×</button>
        {!alert && !error && <div className="muted">Yükleniyor…</div>}
        {error && <div className="card card-danger">{error}</div>}
        {alert && (
          <>
            <div className="drawer-head">
              <div className="badges">
                <SeverityBadge severity={alert.severity} />
                <StatusBadge status={alert.status} />
                <span className="mono dim">#{alert.id} · {alert.rule_id}</span>
              </div>
              <h2>{alert.title}</h2>
              <p>{alert.reason}</p>
            </div>

            <dl className="facts">
              <dt>Kaynak IP</dt>
              <dd className="mono">
                {alert.source_ip}{' '}
                <button className="link-btn" onClick={() => go('hunt', { hunt: { ip: alert.source_ip } })}>
                  tüm olayları →
                </button>
              </dd>
              <dt>Olay sayısı</dt>
              <dd className="mono">{fmtNumber(alert.event_count)}</dd>
              <dt>İlk görülme</dt>
              <dd className="mono">{fmtTime(alert.first_seen)}</dd>
              <dt>Son görülme</dt>
              <dd className="mono">{fmtTime(alert.last_seen)}</dd>
              {alert.mitre.length > 0 && (
                <>
                  <dt>MITRE ATT&CK</dt>
                  <dd>
                    {alert.mitre.map((t) => (
                      <a key={t} className="mitre" href={mitreUrl(t)} target="_blank" rel="noopener noreferrer">
                        <span className="mono">{t}</span> {MITRE[t]?.name}
                      </a>
                    ))}
                  </dd>
                </>
              )}
            </dl>

            <section className="drawer-section">
              <h3>Durumu değiştir</h3>
              <div className="actions">
                {NEXT_STATUS[alert.status].map((s) => (
                  <button
                    key={s}
                    className={`btn ${target === s ? 'btn-primary' : 'btn-outline'}`}
                    onClick={() => setTarget(target === s ? null : s)}
                  >
                    {STATUS_LABEL[s]}
                  </button>
                ))}
              </div>
              {target && (
                <div className="note-box">
                  <textarea
                    value={note}
                    maxLength={2000}
                    onChange={(e) => setNote(e.target.value)}
                    placeholder={needsNote ? 'Gerekçe (zorunlu): ne buldun, neden bu karar?' : 'Not (isteğe bağlı)'}
                  />
                  <button
                    className="btn btn-primary"
                    disabled={saving || (needsNote && !note.trim())}
                    onClick={save}
                  >
                    {STATUS_LABEL[target]} olarak kaydet
                  </button>
                </div>
              )}
            </section>

            <section className="drawer-section">
              <h3>Önerilen inceleme adımları</h3>
              <ol className="steps">
                {alert.recommended_steps.map((s) => (
                  <li key={s}>{s}</li>
                ))}
              </ol>
            </section>

            <section className="drawer-section">
              <h3>Kanıt</h3>
              <Evidence evidence={alert.evidence} />
            </section>

            <section className="drawer-section">
              <h3>İlgili olaylar {alert.events.length < alert.event_count && <span className="muted">(ilk {alert.events.length})</span>}</h3>
              <div className="table-wrap">
                <table className="table compact">
                  <thead>
                    <tr>
                      <th>Zaman</th>
                      <th>Tür</th>
                      <th>İstek</th>
                      <th>Kod</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alert.events.map((e) => (
                      <tr key={e.id}>
                        <td className="mono nowrap">{fmtTime(e.timestamp)}</td>
                        <td className="nowrap">{EVENT_LABEL[e.event_type]}</td>
                        <td className="mono break">
                          {e.http_method ?? '?'} {e.url_path}
                          {e.url_query && `?${e.url_query}`}
                        </td>
                        <td className={`mono status-${String(e.status_code)[0]}`}>{e.status_code}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="drawer-section">
              <h3>Geçmiş (denetim kaydı)</h3>
              <ul className="history">
                {alert.history.map((h, i) => (
                  <li key={i}>
                    <div>
                      <strong>{STATUS_LABEL[h.to_status]}</strong>
                      <span className="muted"> · {h.changed_by} · {fmtTime(h.changed_at)}</span>
                    </div>
                    {h.note && <div className="history-note">{h.note}</div>}
                  </li>
                ))}
              </ul>
            </section>
          </>
        )}
      </aside>
    </>
  )
}

const EVIDENCE_LABEL: Record<string, string> = {
  failed_logins: 'Başarısız giriş',
  lockouts: 'Hesap kilidi',
  failed_before: 'Önceki başarısız deneme',
  success_at: 'Başarılı giriş zamanı',
  unique_paths: 'Farklı yol sayısı',
  peak_per_window: 'Pencere başına tepe',
  total: 'Toplam istek',
  status_codes: 'Yanıt kodları',
  methods: 'HTTP metotları',
  user_agents: 'User-agent',
  top_paths: 'En çok istenen yollar',
  path: 'Yol',
  user_agent: 'Tarayıcı / cihaz',
  known_devices: 'Bilinen cihazlar',
  days_active: 'Süre (gün)',
  post_login: 'Girişten sonraki admin istekleri',
}

/** Kanıt, kuraldan kurala değişen bir JSON: tanıdık alanları okunaklı biçimde göster. */
function Evidence({ evidence }: { evidence: Record<string, unknown> }) {
  return (
    <dl className="facts evidence">
      {Object.entries(evidence).map(([k, v]) => (
        <div key={k} className="fact-row">
          <dt>{EVIDENCE_LABEL[k] ?? k}</dt>
          <dd>{renderValue(k, v)}</dd>
        </div>
      ))}
    </dl>
  )
}

function renderValue(key: string, v: unknown) {
  if (key === 'success_at' && typeof v === 'string') return <span className="mono">{fmtTime(v)}</span>
  if (Array.isArray(v)) {
    if (v.length === 0) return <span className="muted">—</span>
    return (
      <ul className="plain">
        {v.map((item, i) => (
          <li key={i} className="mono break">
            {typeof item === 'object' && item !== null
              ? Object.values(item as Record<string, unknown>).join('  ·  ')
              : String(item)}
          </li>
        ))}
      </ul>
    )
  }
  if (typeof v === 'object' && v !== null) {
    return (
      <span className="mono">
        {Object.entries(v as Record<string, unknown>).map(([a, b]) => `${a}: ${b}`).join(' · ')}
      </span>
    )
  }
  return <span className="mono">{String(v)}</span>
}
