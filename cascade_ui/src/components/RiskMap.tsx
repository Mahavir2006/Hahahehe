import { memo, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react"
import { Maximize2, Minus, Plus, X } from "lucide-react"
import { INDIA_PATH_D } from "@/data/indiaBoundary"
import { assets, assetById, dependencies, downstreamOf, levelColor, sectorOf, type Asset } from "@/data/derive"

/** Spread assets that share a city (e.g. Delhi NCR) around their centre so each marker is clickable. */
function layout(list: Asset[]) {
  const pos = new Map<string, { x: number; y: number; ax: number; ay: number }>()
  const groups: Asset[][] = []
  for (const a of list) {
    const g = groups.find((g) => Math.hypot(g[0].x - a.x, g[0].y - a.y) < 26)
    if (g) g.push(a)
    else groups.push([a])
  }
  for (const g of groups) {
    const cx = g.reduce((s, a) => s + a.x, 0) / g.length
    const cy = g.reduce((s, a) => s + a.y, 0) / g.length
    g.forEach((a, i) => {
      if (g.length === 1) return pos.set(a.id, { x: a.x, y: a.y, ax: a.x, ay: a.y })
      const ang = (i / g.length) * Math.PI * 2 - Math.PI / 2
      const r = 26 + g.length * 4
      pos.set(a.id, { x: cx + Math.cos(ang) * r, y: cy + Math.sin(ang) * r, ax: cx, ay: cy })
    })
  }
  return pos
}

const CITIES: [string, number, number][] = [
  ["Delhi NCR", 395, 300],
  ["Lucknow", 520, 342],
  ["Jaipur", 330, 330],
  ["Bhopal", 420, 432],
  ["Sambalpur", 610, 460],
  ["Dehradun", 452, 200],
  ["Varanasi", 568, 378],
]

export const RiskMap = memo(function RiskMap({
  selected,
  onSelect,
  sector = "All",
  minLevel = "All",
  compact = false,
  legend = true,
  info,
}: {
  selected: string | null
  onSelect: (id: string | null) => void
  sector?: string
  minLevel?: string
  compact?: boolean
  legend?: boolean
  /** When given, a small glass card with this content opens next to the selected marker. */
  info?: (a: Asset) => ReactNode
}) {
  const [zoom, setZoom] = useState(1)
  const [hover, setHover] = useState<string | null>(null)
  const [cardPos, setCardPos] = useState<{ left: number; top: number; flip: boolean } | null>(null)
  const wrap = useRef<HTMLDivElement>(null)
  const nodes = useRef(new Map<string, SVGGElement>())
  const pos = useMemo(() => layout(assets), [])
  const focus = hover ?? selected
  const downstream = useMemo(() => (focus ? downstreamOf(focus) : new Set<string>()), [focus])
  const order = ["Low", "Medium", "High", "Critical"]
  const visible = (a: Asset) => (sector === "All" || a.org === sector) && (minLevel === "All" || order.indexOf(a.level) >= order.indexOf(minLevel))

  // frame the populated north/central region; zoom scales around it
  const base = { x: 250, y: 150, w: 470, h: 360 }
  const w = base.w / zoom
  const h = base.h / zoom
  const vb = `${base.x + (base.w - w) / 2} ${base.y + (base.h - h) / 2} ${w} ${h}`

  // place the info card next to the selected marker (measured in screen pixels, so it follows zoom/resize)
  useLayoutEffect(() => {
    if (!info || !selected) return setCardPos(null)
    const place = () => {
      const n = nodes.current.get(selected)
      const box = wrap.current?.getBoundingClientRect()
      if (!n || !box) return
      const r = n.getBoundingClientRect()
      const left = r.left + r.width / 2 - box.left
      const top = r.top + r.height / 2 - box.top
      setCardPos({ left, top, flip: left > box.width - 280 })
    }
    place()
    const ro = new ResizeObserver(place)
    if (wrap.current) ro.observe(wrap.current)
    return () => ro.disconnect()
  }, [info, selected, zoom])

  useEffect(() => {
    if (!info) return
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onSelect(null)
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [info, onSelect])

  const sel = selected ? assetById.get(selected) : undefined

  return (
    <div ref={wrap} className={`riskmap ${compact ? "compact" : ""}`}>
      <svg viewBox={vb} role="img" aria-label="Map of monitored infrastructure assets in India with dependency links" onClick={(e) => info && e.target === e.currentTarget && onSelect(null)}>
        <defs>
          <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
            <path d="M20 0H0V20" className="m-grid" />
          </pattern>
          <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto">
            <path d="M0 1L10 5L0 9z" fill="#ef5b5b" />
          </marker>
        </defs>
        <rect x="0" y="0" width="1000" height="840" fill="url(#grid)" onClick={() => info && onSelect(null)} />
        <path d={INDIA_PATH_D} className="m-land" onClick={() => info && onSelect(null)} />

        {dependencies.map((d) => {
          const a = pos.get(d.from)
          const b = pos.get(d.to)
          if (!a || !b) return null
          const hot = focus && (d.from === focus || downstream.has(d.from)) && downstream.has(d.to)
          return (
            <line
              key={d.from + d.to}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              className={`m-link ${d.kind} ${hot ? "hot flow" : ""}`}
              markerEnd={hot ? "url(#arr)" : undefined}
              opacity={focus && !hot ? 0.35 : 0.9}
            />
          )
        })}

        {assets.map((a) => {
          const p = pos.get(a.id)!
          const show = visible(a)
          const isSel = a.id === selected
          const isDown = downstream.has(a.id)
          const r = 3.6 + (a.risk / 100) * 4.4
          return (
            <g
              key={a.id}
              ref={(el) => {
                if (el) nodes.current.set(a.id, el)
              }}
              transform={`translate(${p.x},${p.y})`}
              opacity={show ? (focus && !isSel && !isDown && a.id !== focus ? 0.45 : 1) : 0.12}
              className="node"
              role="button"
              tabIndex={show ? 0 : -1}
              aria-pressed={isSel}
              aria-label={`${a.id} ${a.name}, ${a.level} risk ${a.risk.toFixed(1)}`}
              onClick={() => onSelect(a.id)}
              onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), onSelect(a.id))}
              onMouseEnter={() => setHover(a.id)}
              onMouseLeave={() => setHover(null)}
            >
              {p.ax !== p.x && <line x1={0} y1={0} x2={p.ax - p.x} y2={p.ay - p.y} className="m-leader" />}
              {a.level === "Critical" && <circle r={r + 6} fill="none" stroke={levelColor.Critical} className="pulse" />}
              <circle r={r + 2.5} fill={sectorOf[a.org].color} opacity={0.85} />
              <circle r={r} fill={levelColor[a.level]} className={`m-dot ${isSel ? "sel" : isDown ? "down" : ""}`} />
              {(a.level === "Critical" || isSel || a.id === hover) && (
                <text y={-r - 5} textAnchor="middle" className="lbl">
                  {a.id}
                </text>
              )}
            </g>
          )
        })}
        {!compact && (
          <g className="cities">
            {CITIES.map(([t, x, y]) => (
              <text key={t} x={x} y={y}>
                {t}
              </text>
            ))}
          </g>
        )}
      </svg>

      <div className="map-zoom glass" role="group" aria-label="Zoom">
        <button aria-label="Zoom in" onClick={() => setZoom((z) => Math.min(3, z + 0.4))}>
          <Plus size={15} />
        </button>
        <button aria-label="Zoom out" onClick={() => setZoom((z) => Math.max(0.8, z - 0.4))}>
          <Minus size={15} />
        </button>
        <button aria-label="Reset zoom" onClick={() => setZoom(1)}>
          <Maximize2 size={14} />
        </button>
      </div>

      {info && sel && cardPos && (
        <div
          className={`map-card glass ${cardPos.flip ? "flip" : ""}`}
          style={{ left: cardPos.left, top: cardPos.top }}
          role="dialog"
          aria-label={`${sel.id} summary`}
        >
          <button className="map-card-x" aria-label="Close" onClick={() => onSelect(null)}>
            <X size={13} />
          </button>
          {info(sel)}
        </div>
      )}

      {legend && (
        <div className="map-legend glass" aria-label="Legend">
          <div>
            {(["Critical", "High", "Medium", "Low"] as const).map((l) => (
              <span key={l}>
                <i style={{ background: levelColor[l] }} />
                {l}
              </span>
            ))}
          </div>
          <div>
            {Object.values(sectorOf).map((s) => (
              <span key={s.label}>
                <i className="ring" style={{ borderColor: s.color }} />
                {s.label}
              </span>
            ))}
          </div>
          <div>
            <span>
              <em className="ln" /> dependency
            </span>
            <span>
              <em className="ln dash" /> inferred
            </span>
            <span>
              <em className="ln hot" /> cascade
            </span>
          </div>
        </div>
      )}
    </div>
  )
})
