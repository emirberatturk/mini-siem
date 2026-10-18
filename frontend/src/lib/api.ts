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
  /** Eşleşen imza (Sigma) kuralları: olay aramada liste, yükleme özetinde virgüllü metin */
  signatures?: string[] | string
  /** Anomali bulguları "parametre:tür" (aynı biçim kuralı) */
  anomalies?: string[] | string
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
  alert_on?: string | null
  signature_rules: SignatureRule[]
  anomaly_profile?: AnomalyProfile | null
}

export interface AnomalyProfile {
  paths: number
  usable_paths: number
  params: number
  requests: number
}

export interface SignatureRule {
  name: string
  title: string
  level: Severity
  mitre: string[]
  author: string
}

export interface Count {
  key: string
  count: number
  proxy?: boolean
}

export interface SignatureCount {
  key: string
  label: string
  count: number
  blocked: number
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
  top_signatures: SignatureCount[]
  top_anomalies: SignatureCount[]
  status_classes: Count[]
  event_types: Count[]
  timeline: TimelineBucket[]
  recent_alerts: Alert[]
}

export type Query = Record<string, string | number | string[] | undefined | null>

/** Oturum düştüğünde (401) uygulamaya haber verilir: giriş ekranına dönülür. */
export const UNAUTHORIZED_EVENT = 'siem:unauthorized'

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    if (res.status === 401) window.dispatchEvent(new Event(UNAUTHORIZED_EVENT))
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

/**
 * Tüm istekler buradan geçer. Oturum çerezi (HttpOnly) tarayıcı tarafından otomatik gönderilir;
 * JavaScript onu göremez. Durum değiştiren isteklerde sunucu bu başlığı ister (CSRF koruması).
 */
function send<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('X-Requested-With', 'mini-siem')
  return fetch(`/api/v1${path}`, { ...init, headers, credentials: 'same-origin' }).then((r) =>
    handle<T>(r),
  )
}

const get = <T>(path: string, params?: Query) => send<T>(`${path}${qs(params)}`)

const sendJson = <T>(method: string, path: string, body: unknown) =>
  send<T>(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

export interface Me {
  username: string
  role: 'admin' | 'analyst'
  role_label: string
}

export interface WeeklyTotals {
  events: number
  unique_ips: number
  client_errors: number
  suspicious: number
  suspicious_blocked: number
  auth_ok: number
  auth_fail: number
  alerts: number
}

export interface WeeklyReport {
  start: string
  end: string
  first_day: string // YYYY-MM-DD (yerel gün)
  last_day: string
  prev_last_day: string | null
  next_last_day: string | null
  days: { day: string; events: number; suspicious: number; auth_failures: number; alerts: number }[]
  missing_days: string[]
  totals: WeeklyTotals
  previous: WeeklyTotals
  alerts: {
    id: number
    rule_id: string
    title: string
    severity: Severity
    status: AlertStatus
    source_ip: string
    first_seen: string
    decided_by: string | null
    decision_note: string | null
  }[]
  alerts_by_status: Partial<Record<AlertStatus, number>>
  open_alerts_total: number
  top_signatures: SignatureCount[]
  top_anomalies: SignatureCount[]
  top_sources: Count[]
  retention_days: number
  oldest_event: string | null
  next_purge_at: string | null
}

/** Şifre doğruysa: telefon kodu mu isteniyor ("mfa"), yoksa ilk kurulum mu ("enroll")? */
export interface LoginStep {
  stage: 'mfa' | 'enroll'
}

export interface Enrollment {
  secret: string // QR okutulamazsa uygulamaya elle girilecek anahtar
  qr: string // data:image/svg+xml;… (yalnızca <img src> ile gösterilir)
}

export const api = {
  health: () => get<HealthResponse>('/health'),
  overview: () => get<Overview>('/stats/overview'),
  alerts: (params: Query) => get<Page<Alert>>('/alerts', params),
  alert: (id: number) => get<AlertDetail>(`/alerts/${id}`),
  events: (params: Query) => get<Page<NormalizedEvent>>('/events', params),
  rules: () => get<Rule[]>('/rules'),
  weekly: (end?: string) => get<WeeklyReport>('/reports/weekly', { end }),

  me: () => get<Me>('/auth/me'),
  setup: () => get<{ has_users: boolean }>('/auth/setup'),
  login: (username: string, password: string) =>
    sendJson<LoginStep>('POST', '/auth/login', { username, password }),
  verifyCode: (code: string) => sendJson<Me>('POST', '/auth/mfa/verify', { code }),
  startEnrollment: () => send<Enrollment>('/auth/mfa/setup', { method: 'POST' }),
  finishEnrollment: (code: string) =>
    sendJson<{ me: Me; recovery_codes: string[] }>('POST', '/auth/mfa/enable', { code }),
  logout: () => send<{ ok: boolean }>('/auth/logout', { method: 'POST' }),

  setAlertStatus: (id: number, status: AlertStatus, note: string) =>
    sendJson<AlertDetail>('PATCH', `/alerts/${id}`, { status, note }),

  rerunDetection: () =>
    send<{ created: number; updated: number }>('/detection/run', { method: 'POST' }),

  uploadLog: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return send<IngestSummary>('/ingest/upload', { method: 'POST', body: form })
  },
}
