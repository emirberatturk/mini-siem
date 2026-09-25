import type { ReactNode } from 'react'
import type { Count } from '../lib/api'
import { fmtNumber } from '../lib/labels'

/** Yatay çubuk listesi: sıralı büyüklük karşılaştırması için en okunaklı biçim. */
export function BarList({
  items,
  label = (k) => k,
  onSelect,
  empty = 'Veri yok',
  mono = false,
}: {
  items: Count[]
  label?: (key: string) => ReactNode
  onSelect?: (key: string) => void
  empty?: string
  mono?: boolean
}) {
  if (!items.length) return <div className="muted empty">{empty}</div>
  const max = Math.max(...items.map((i) => i.count))
  return (
    <ul className="barlist">
      {items.map((item) => {
        const content = (
          <>
            <span className={`barlist-label${mono ? ' mono' : ''}`}>
              {label(item.key)}
              {item.proxy && <span className="tag" title="Bir kişi değil: birçok ziyaretçinin ortak çıkış noktası">aracı sunucu</span>}
            </span>
            <span className="barlist-value">{fmtNumber(item.count)}</span>
            <span className="barlist-track" aria-hidden>
              <span className="barlist-bar" style={{ width: `${(item.count / max) * 100}%` }} />
            </span>
          </>
        )
        return (
          <li key={item.key}>
            {onSelect ? (
              <button className="barlist-row clickable" onClick={() => onSelect(item.key)}>
                {content}
              </button>
            ) : (
              <div className="barlist-row">{content}</div>
            )}
          </li>
        )
      })}
    </ul>
  )
}
