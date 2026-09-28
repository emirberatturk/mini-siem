import { fmtTime } from '../lib/labels'

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
  signatures: 'Eşleşen imzalar',
  anomalies: 'Anomali bulguları',
  success_responses: 'Başarılı (2xx) yanıt',
}

/** Kanıt, kuraldan kurala değişen bir JSON: tanıdık alanları okunaklı biçimde göster. */
export function Evidence({ evidence }: { evidence: Record<string, unknown> }) {
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
  if ((key === 'signatures' || key === 'anomalies') && Array.isArray(v)) {
    return (
      <ul className="plain">
        {(v as { title: string; count: number; success?: number }[]).map((s) => (
          <li key={s.title}>
            {s.title} <span className="mono dim">· {s.count} istek</span>
            {s.success ? <span className="tag">{s.success} başarılı yanıt</span> : null}
          </li>
        ))}
      </ul>
    )
  }
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
