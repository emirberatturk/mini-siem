import type { AlertStatus, Severity } from '../lib/api'
import { SEVERITY_LABEL, STATUS_LABEL } from '../lib/labels'

// Renk asla tek başına anlam taşımaz: her rozette ikon + yazı var (renk körlüğü, yazıcı)
const SEVERITY_ICON: Record<Severity, string> = {
  critical: '◆',
  high: '▲',
  medium: '●',
  low: '○',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`sev sev-${severity}`}>
      <span aria-hidden>{SEVERITY_ICON[severity]}</span>
      {SEVERITY_LABEL[severity]}
    </span>
  )
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  return <span className={`status status-${status}`}>{STATUS_LABEL[status]}</span>
}
