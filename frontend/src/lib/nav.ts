export type PageId = 'overview' | 'alerts' | 'hunt' | 'rules' | 'upload'

export interface HuntFilters {
  ip?: string
  event_type?: string
  status?: string
  path?: string
  since?: string
  until?: string
}

export interface AlertFilters {
  ip?: string
  rule_id?: string
  severity?: string
  status?: string
}

/** Sayfalar arası pivot: "IP → olaylar → alert" gibi soruşturma adımları. */
export type Go = (
  page: PageId,
  opts?: { alertId?: number; hunt?: HuntFilters; alerts?: AlertFilters },
) => void
