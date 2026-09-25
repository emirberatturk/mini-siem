import { useEffect, useRef, useState } from 'react'
import type { TimelineBucket } from '../lib/api'
import { fmtNumber, fmtShortTime } from '../lib/labels'

const H = 190
const PAD = { top: 12, right: 12, bottom: 26, left: 44 }
const ALERT_STRIP = 22

/**
 * Yığılmış çubuk grafiği: her dilimde "başarısız giriş" + "diğer istekler" = toplam olay.
 * İki seri aynı birimde (olay sayısı) olduğu için tek eksen yeterli.
 * Alert'ler ayrı bir şeritte gösterilir: farklı bir ölçü, aynı eksene sıkıştırılmaz.
 */
export function Timeline({
  buckets,
  bucketMinutes,
}: {
  buckets: TimelineBucket[]
  bucketMinutes: number
}) {
  const wrap = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(800)
  const [hover, setHover] = useState<number | null>(null)

  useEffect(() => {
    const el = wrap.current
    if (!el) return
    const ro = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  if (!buckets.length) return <div className="muted empty">Henüz olay yok</div>

  const plotW = Math.max(width - PAD.left - PAD.right, 50)
  const plotH = H - PAD.top - PAD.bottom
  const max = Math.max(...buckets.map((b) => b.events), 1)
  const step = plotW / buckets.length
  const barW = Math.max(Math.min(step - 2, 28), 1) // 2px boşluk çubukları ayırır
  const y = (v: number) => PAD.top + plotH - (v / max) * plotH
  const ticks = [0, Math.round(max / 2), max]
  const multiDay =
    new Date(buckets[buckets.length - 1].start).getTime() - new Date(buckets[0].start).getTime() >
    20 * 3600_000
  const labelEvery = Math.ceil(buckets.length / Math.max(Math.floor(plotW / 90), 1))
  const hb = hover !== null ? buckets[hover] : null

  return (
    <div className="timeline" ref={wrap}>
      <div className="legend">
        <span>
          <i className="swatch s1" /> İstekler
        </span>
        <span>
          <i className="swatch s2" /> Başarısız giriş
        </span>
        <span>
          <i className="swatch alert-dot" /> Yeni alert
        </span>
        <span className="muted">dilim: {bucketMinutes >= 60 ? `${bucketMinutes / 60} sa` : `${bucketMinutes} dk`}</span>
      </div>

      <svg width={width} height={H + ALERT_STRIP} role="img" aria-label="Olay zaman çizelgesi">
        {ticks.map((t) => (
          <g key={t}>
            <line className="grid" x1={PAD.left} x2={PAD.left + plotW} y1={y(t)} y2={y(t)} />
            <text className="axis" x={PAD.left - 8} y={y(t) + 4} textAnchor="end">
              {fmtNumber(t)}
            </text>
          </g>
        ))}

        {buckets.map((b, i) => {
          const x = PAD.left + i * step + (step - barW) / 2
          const other = b.events - b.auth_failures
          const r = Math.min(3, barW / 2)
          return (
            <g key={b.start} className={hover === i ? 'bar-hover' : undefined}>
              {other > 0 && (
                <rect className="s1" x={x} y={y(b.events)} width={barW}
                  height={Math.max(y(b.auth_failures) - y(b.events) - (b.auth_failures ? 1 : 0), 1)}
                  rx={r} />
              )}
              {b.auth_failures > 0 && (
                <rect className="s2" x={x} y={y(b.auth_failures)} width={barW}
                  height={Math.max(y(0) - y(b.auth_failures), 1)} rx={r} />
              )}
              {b.alerts > 0 && (
                <g>
                  <circle className="alert-dot" cx={x + barW / 2} cy={H + 8} r={5} />
                  {b.alerts > 1 && (
                    <text className="axis" x={x + barW / 2 + 8} y={H + 12}>{b.alerts}</text>
                  )}
                </g>
              )}
              {i % labelEvery === 0 && (
                <text className="axis" x={x + barW / 2} y={H - 8}
                  textAnchor={x + barW / 2 > PAD.left + plotW - 40 ? 'end' : 'middle'}>
                  {fmtShortTime(b.start, multiDay)}
                </text>
              )}
              {/* Görünmez geniş hedef: ince çubuğun üzerine gelmek kolay olsun */}
              <rect x={PAD.left + i * step} y={PAD.top} width={step} height={plotH + ALERT_STRIP + 14}
                fill="transparent" onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} />
            </g>
          )
        })}
        <line className="baseline" x1={PAD.left} x2={PAD.left + plotW} y1={y(0)} y2={y(0)} />
      </svg>

      {hb && hover !== null && (
        <div
          className="tooltip"
          style={{
            left: Math.min(PAD.left + hover * step + step / 2, width - 170),
            top: PAD.top + 20,
          }}
        >
          <div className="tooltip-title">{fmtShortTime(hb.start, true)}</div>
          <div><i className="swatch s1" /> İstek <strong>{fmtNumber(hb.events - hb.auth_failures)}</strong></div>
          <div><i className="swatch s2" /> Başarısız giriş <strong>{fmtNumber(hb.auth_failures)}</strong></div>
          <div><i className="swatch alert-dot" /> Yeni alert <strong>{hb.alerts}</strong></div>
        </div>
      )}
    </div>
  )
}
