export interface HealthResponse {
  status: 'ok'
  app: string
  version: string
  time: string
}

export type EventType =
  | 'http_request'
  | 'authentication_success'
  | 'authentication_failure'
  | 'authentication_lockout'
  | 'admin_access'

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type AlertStatus = 'new' | 'investigating' | 'confirmed' | 'false_positive' | 'resolved'

export interface NormalizedEvent {
  id?: number
  timestamp: string
  source_ip: string
  http_method: string | null
  url_path: string
  url_query: string
  status_code: number
  bytes_sent: number
  referrer: string
  user_agent: string
  event_category: 'web' | 'authentication'
  event_type: EventType
  event_outcome: 'success' | 'failure' | 'unknown'
  redactions: number
}

export interface IngestSummary {
  filename: string
  size_bytes: number
  compressed: boolean
  lines_total: number
  lines_empty: number
  lines_truncated: number
  format_hint: string
  batch_id: number
  events_parsed: number
  events_inserted: number
  duplicates: number
  alerts_created: number
  alerts_updated: number
  lines_failed: number
  redactions: number
  event_types: Partial<Record<EventType, number>>
  samples: NormalizedEvent[]
}

export interface Alert {
  id: number
  rule_id: string
  title: string
  severity: Severity
  status: AlertStatus
  source_ip: string
  first_seen: string
  last_seen: string
  event_count: number
  reason: string
  evidence: Record<string, unknown>
  recommended_steps: string[]
  mitre: string[]
  created_at: string
  updated_at: string
}

export interface AlertHistory {
  from_status: AlertStatus | null
  to_status: AlertStatus
  note: string
  changed_by: string
  changed_at: string
}

export interface AlertDetail extends Alert {
  history: AlertHistory[]
  events: NormalizedEvent[]
}

export interface Page<T> {
  total: number
  items: T[]
}

export interface Rule {
  id: string
  title: string
  description: string
  enabled: boolean
  config: Record<string, number>
  mitre: string[]
  alert_count: number
  open_alert_count: number
  skips_proxies: boolean
  known_devices: string[]
}

export interface Count {
  key: string
  count: number
  proxy?: boolean
}

export interface TimelineBucket {
  start: string
  events: number
  auth_failures: number
  alerts: number
}

export interface Overview {
  range_start: string | null
  range_end: string | null
  bucket_minutes: number
  total_events: number
  total_alerts: number
  false_positives: number
  proxy_ips: string[]
  proxy_event_share: number
  open_alerts_by_severity: Record<Severity, number>
  events_per_minute: number
  peak_events_per_minute: number
  top_ips: Count[]
  top_rules: Count[]
  status_classes: Count[]
  event_types: Count[]
  timeline: TimelineBucket[]
  recent_alerts: Alert[]
}

export type Query = Record<string, string | number | string[] | undefined | null>

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    // FastAPI hataları {"detail": "..."} şeklinde döner
    const body = await res.json().catch(() => null)
    const detail = body?.detail
    throw new Error(typeof detail === 'string' ? detail : `HTTP ${res.status}`)
  }
  return res.json() as Promise<T>
}

function qs(params: Query = {}) {
  const sp = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue
    for (const item of Array.isArray(v) ? v : [v]) sp.append(k, String(item))
  }
  const s = sp.toString()
  return s ? `?${s}` : ''
}

const get = <T>(path: string, params?: Query) =>
  fetch(`/api/v1${path}${qs(params)}`).then((r) => handle<T>(r))

export const api = {
  health: () => get<HealthResponse>('/health'),
  overview: () => get<Overview>('/stats/overview'),
  alerts: (params: Query) => get<Page<Alert>>('/alerts', params),
  alert: (id: number) => get<AlertDetail>(`/alerts/${id}`),
  events: (params: Query) => get<Page<NormalizedEvent>>('/events', params),
  rules: () => get<Rule[]>('/rules'),

  setAlertStatus: (id: number, status: AlertStatus, note: string) =>
    fetch(`/api/v1/alerts/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, note }),
    }).then((r) => handle<AlertDetail>(r)),

  rerunDetection: () =>
    fetch('/api/v1/detection/run', { method: 'POST' }).then((r) =>
      handle<{ created: number; updated: number }>(r),
    ),

  uploadLog: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return fetch('/api/v1/ingest/upload', { method: 'POST', body: form }).then((r) =>
      handle<IngestSummary>(r),
    )
  },
}
