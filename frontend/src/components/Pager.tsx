import { fmtNumber } from '../lib/labels'

export function Pager({
  page,
  total,
  size,
  onPage,
}: {
  page: number
  total: number
  size: number
  onPage: (p: number) => void
}) {
  const pages = Math.max(Math.ceil(total / size), 1)
  return (
    <div className="pager">
      <span className="muted">{fmtNumber(total)} kayıt</span>
      <button className="btn btn-ghost" disabled={page === 0} onClick={() => onPage(page - 1)}>
        ← Önceki
      </button>
      <span className="muted">{page + 1} / {pages}</span>
      <button className="btn btn-ghost" disabled={page + 1 >= pages} onClick={() => onPage(page + 1)}>
        Sonraki →
      </button>
    </div>
  )
}
