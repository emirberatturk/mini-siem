import type { AlertStatus, EventType, Severity } from './api'

export const EVENT_LABEL: Record<EventType, string> = {
  http_request: 'HTTP isteği',
  authentication_success: 'Başarılı giriş',
  authentication_failure: 'Başarısız giriş',
  authentication_lockout: 'Hesap kilidi',
  admin_access: 'Admin erişimi',
}

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Kritik',
  high: 'Yüksek',
  medium: 'Orta',
  low: 'Düşük',
}

export const STATUSES: AlertStatus[] = [
  'new',
  'investigating',
  'confirmed',
  'false_positive',
  'resolved',
]

export const STATUS_LABEL: Record<AlertStatus, string> = {
  new: 'Yeni',
  investigating: 'İnceleniyor',
  confirmed: 'Doğrulandı',
  false_positive: 'Yanlış alarm',
  resolved: 'Çözüldü',
}

// Backend'deki durum makinesinin aynısı (backend yine de kontrol eder; bu sadece arayüz için)
export const NEXT_STATUS: Record<AlertStatus, AlertStatus[]> = {
  new: ['investigating', 'false_positive'],
  investigating: ['confirmed', 'false_positive', 'resolved'],
  confirmed: ['resolved'],
  false_positive: ['investigating'],
  resolved: ['investigating'],
}

export const NOTE_REQUIRED = (from: AlertStatus, to: AlertStatus) =>
  to === 'false_positive' || to === 'resolved' || from === 'false_positive' || from === 'resolved'

export const RULE_LABEL: Record<string, string> = {
  'AUTH-001': 'Başarısız giriş patlaması',
  'CORR-001': 'Başarısız → başarılı giriş',
  'AUTH-002': 'Tanınmayan cihazdan giriş',
  'ADMIN-001': 'Yetkisiz admin denemesi',
  'RECON-001': 'Aşırı 404 / tarama',
  'RECON-002': 'Israrlı yoklama',
  'RATE-001': 'Anormal istek hızı',
  'SIG-001': 'Web saldırı imzası',
}

/** API'den liste (olay arama) ya da virgüllü metin (yükleme özeti) gelebilir. */
export const sigList = (v?: string[] | string): string[] =>
  Array.isArray(v) ? v : v ? v.split(',').filter(Boolean) : []

// Sadece kurallarımızda kullanılan teknikler. Kaynak: attack.mitre.org
export const MITRE: Record<string, { name: string; tactic: string }> = {
  T1110: { name: 'Brute Force', tactic: 'Credential Access' },
  'T1110.001': { name: 'Brute Force: Password Guessing', tactic: 'Credential Access' },
  T1078: { name: 'Valid Accounts', tactic: 'Initial Access · Persistence' },
  'T1595.003': { name: 'Active Scanning: Wordlist Scanning', tactic: 'Reconnaissance' },
  // İmza (Sigma) kurallarından gelenler
  T1190: { name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
  T1189: { name: 'Drive-by Compromise', tactic: 'Initial Access' },
  T1083: { name: 'File and Directory Discovery', tactic: 'Discovery' },
  'T1505.003': { name: 'Server Software Component: Web Shell', tactic: 'Persistence' },
}

export const mitreUrl = (id: string) =>
  `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`

export const fmtNumber = (v: number) => v.toLocaleString('tr-TR')

export const fmtTime = (iso: string) =>
  new Date(iso).toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' })

export const fmtShortTime = (iso: string, withDate: boolean) =>
  new Date(iso).toLocaleString('tr-TR', {
    timeZone: 'Europe/Istanbul',
    ...(withDate ? { day: '2-digit', month: 'short' } : {}),
    hour: '2-digit',
    minute: '2-digit',
  })
