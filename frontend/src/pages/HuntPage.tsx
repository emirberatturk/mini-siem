import { Fragment, useCallback, useEffect, useState, type FormEvent } from 'react'
import { Pager } from '../components/Pager'
import { api, type EventType, type NormalizedEvent, type Page } from '../lib/api'
import { EVENT_LABEL, fmtTime } from '../lib/labels'
import type { Go, HuntFilters } from '../lib/nav'

const PAGE_SIZE = 50

/** <input type="datetime-local"> değeri (TR saati) → UTC ISO; tersine de çevirir. */
const TR_OFFSET = '+03:00'
const toIso = (local?: string) => (local ? new Date(`${local}:00${TR_OFFSET}`).toISOString() : undefined)
const toLocal = (iso?: string) =>
  iso
    ? new Date(new Date(iso).getTime() + 3 * 3600_000).toISOString().slice(0, 16)
    : ''

export default function HuntPage({ go, initialFilters }: { go: Go; initialFilters?: HuntFilters }) {
  const [draft, setDraft] = useState<HuntFilters>(initialFilters ?? {})
  const [filters, setFilters] = useState<HuntFilters>(initialFilters ?? {})
  const [page, setPage] = useState(0)
  const [data, setData] = useState<Page<NormalizedEvent> | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState<number | null>(null)

  const load = useCallback(() => {
    api
      .events({ ...filters, limit: PAGE_SIZE, offset: page * PAGE_SIZE })
      .then((d) => {
        setData(d)
        setError(null)
      })
      .catch((e: Error) => setError(e.message))
  }, [filters, page])

  useEffect(load, [load])

  const apply = (next: HuntFilters) => {
    setPage(0)
    setDraft(next)
    setFilters(next)
  }

  function submit(e: FormEvent) {
    e.preventDefault()
    const clean = Object.fromEntries(
      Object.entries(draft).filter(([, v]) => v !== undefined && String(v).trim() !== ''),
    ) as HuntFilters
    apply(clean)
  }

  const field = (k: keyof HuntFilters) => ({
    value: draft[k] ?? '',
    onChange: (e: { target: { value: string } }) => setDraft((d) => ({ ...d, [k]: e.target.value })),
  })

  const active = Object.entries(filters).filter(([, v]) => v)

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Olay Arama</h1>
          <p className="muted">
            Threat hunting: alert beklemeden olaylar arasında şüpheli iz ara. IP'ye tıklayarak o
            adrese odaklan.
          </p>
        </div>
      </div>

      <form className="filters hunt-form" onSubmit={submit}>
        <label>
          <span>IP</span>
          <input className="mono" placeholder="203.0.113.10" {...field('ip')} />
        </label>
        <label>
          <span>Yol içerir</span>
          <input className="mono" placeholder="/wp-admin" maxLength={200} {...field('path')} />
        </label>
        <label>
          <span>Olay türü</span>
          <select {...field('event_type')}>
            <option value="">Tümü</option>
            {Object.entries(EVENT_LABEL).map(([k, v]) => (
              <option key={k} value={k}>{v}</option>
            ))}
          </select>
        </label>
        <label>
          <span>HTTP kodu</span>
          <input className="mono short" placeholder="404 / 4xx" {...field('status')} />
        </label>
        <label>
          <span>Başlangıç (TR)</span>
          <input
            type="datetime-local"
            value={toLocal(draft.since)}
            onChange={(e) => setDraft((d) => ({ ...d, since: toIso(e.target.value) }))}
          />
        </label>
        <label>
          <span>Bitiş (TR)</span>
          <input
            type="datetime-local"
            value={toLocal(draft.until)}
            onChange={(e) => setDraft((d) => ({ ...d, until: toIso(e.target.value) }))}
          />
        </label>
        <div className="form-actions">
          <button className="btn btn-primary" type="submit">Ara</button>
          {active.length > 0 && (
            <button className="btn btn-ghost" type="button" onClick={() => apply({})}>
              Temizle
            </button>
          )}
        </div>
      </form>

      {filters.ip && (
        <div className="pivot-bar">
          <span>
            Odak: <strong className="mono">{filters.ip}</strong>
          </span>
          <button className="link-btn" onClick={() => go('alerts', { alerts: { ip: filters.ip } })}>
            Bu IP'nin alertleri →
          </button>
          <button
            className="link-btn"
            onClick={() => apply({ ...filters, event_type: 'authentication_failure' })}
          >
            Sadece başarısız girişler
          </button>
          <button className="link-btn" onClick={() => apply({ ...filters, status: '4xx' })}>
            Sadece 4xx yanıtlar
          </button>
        </div>
      )}

      {error && <div className="card card-danger">{error}</div>}

      {data && (
        <section className="panel flush">
          {data.items.length === 0 ? (
            <div className="muted empty">Eşleşen olay yok.</div>
          ) : (
            <div className="table-wrap flat">
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
                  {data.items.map((e) => (
                    <Fragment key={e.id}>
                      <tr className="clickable" onClick={() => setOpen(open === e.id ? null : e.id!)}>
                        <td className="mono nowrap">{fmtTime(e.timestamp)}</td>
                        <td className="mono">
                          <button
                            className="link-btn mono"
                            onClick={(ev) => {
                              ev.stopPropagation()
                              apply({ ip: e.source_ip })
                            }}
                          >
                            {e.source_ip}
                          </button>
                        </td>
                        <td>
                          <span className={`chip chip-${e.event_type}`}>
                            {EVENT_LABEL[e.event_type as EventType]}
                          </span>
                        </td>
                        <td className="mono break">
                          {e.http_method ?? '?'} {e.url_path}
                          {e.url_query && <span className="dim">?{e.url_query}</span>}
                        </td>
                        <td className={`mono status-${String(e.status_code)[0]}`}>{e.status_code}</td>
                      </tr>
                      {open === e.id && (
                        <tr className="row-detail">
                          <td colSpan={5}>
                            <dl className="facts">
                              <dt>User-agent</dt>
                              <dd className="mono break">{e.user_agent}</dd>
                              <dt>Referrer</dt>
                              <dd className="mono break">{e.referrer || '—'}</dd>
                              <dt>Gönderilen</dt>
                              <dd className="mono">{e.bytes_sent.toLocaleString('tr-TR')} bayt</dd>
                              <dt>Maskelenen değer</dt>
                              <dd className="mono">{e.redactions}</dd>
                            </dl>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <Pager page={page} total={data.total} size={PAGE_SIZE} onPage={setPage} />
        </section>
      )}
    </>
  )
}
