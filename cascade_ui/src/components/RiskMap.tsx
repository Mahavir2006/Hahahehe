import { memo, useMemo, useState } from "react"
import { Maximize2, Minus, Plus } from "lucide-react"
import { INDIA_PATH_D } from "@/data/indiaBoundary"
import { assets, dependencies, downstreamOf, levelColor, sectorOf, type Asset } from "@/data/derive"

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

export const RiskMap = memo(function RiskMap({
  selected,
  onSelect,
  sector = "All",
  minLevel = "All",
  compact = false,
}: {
  selected: string | null
  onSelect: (id: string) => void
  sector?: string
  minLevel?: string
  compact?: boolean
}) {
  const [zoom, setZoom] = useState(1)
  const [hover, setHover] = useState<string | null>(null)
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

  return (
    <div className={`riskmap ${compact ? "compact" : ""}`}>
      <svg viewBox={vb} role="img" aria-label="Map of monitored infrastructure assets in India with dependency links">
        <defs>
          <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
            <path d="M20 0H0V20" fill="none" stroke="rgba(148,163,184,.07)" strokeWidth="1" />
          </pattern>
          <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto">
            <path d="M0 1L10 5L0 9z" fill="#ef5b5b" />
          </marker>
        </defs>
        <rect x="0" y="0" width="1000" height="840" fill="url(#grid)" />
        <path d={INDIA_PATH_D} fill="#13283a" stroke="#3d6283" strokeWidth="2" strokeLinejoin="round" />

        {/* dependency links */}
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
              stroke={hot ? "#ef5b5b" : d.kind === "confirmed" ? "#3b5873" : "#5b6b7c"}
              strokeWidth={hot ? 2.4 : 1.2}
              strokeDasharray={d.kind === "potential" ? "4 3" : undefined}
              markerEnd={hot ? "url(#arr)" : undefined}
              className={hot ? "flow" : ""}
              opacity={focus && !hot ? 0.35 : 0.9}
            />
          )
        })}

        {/* assets */}
        {assets.map((a) => {
          const p = pos.get(a.id)!
          const show = visible(a)
          const isSel = a.id === selected
          const isDown = downstream.has(a.id)
          const r = 5 + (a.risk / 100) * 6
          return (
            <g
              key={a.id}
              transform={`translate(${p.x},${p.y})`}
              opacity={show ? (focus && !isSel && !isDown && a.id !== focus ? 0.45 : 1) : 0.12}
              className="node"
              role="button"
              tabIndex={show ? 0 : -1}
              aria-label={`${a.id} ${a.name}, ${a.level} risk ${a.risk.toFixed(1)}`}
              onClick={() => onSelect(a.id)}
              onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), onSelect(a.id))}
              onMouseEnter={() => setHover(a.id)}
              onMouseLeave={() => setHover(null)}
            >
              {p.ax !== p.x && <line x1={0} y1={0} x2={p.ax - p.x} y2={p.ay - p.y} stroke="#2c4157" strokeWidth="0.8" />}
              {a.level === "Critical" && <circle r={r + 6} fill="none" stroke={levelColor.Critical} className="pulse" />}
              <circle r={r + 2.5} fill={sectorOf[a.org].color} opacity={0.9} />
              <circle r={r} fill={levelColor[a.level]} stroke={isSel ? "#fff" : isDown ? "#ef5b5b" : "#0b1520"} strokeWidth={isSel || isDown ? 2 : 1.2} />
              {(a.level === "Critical" || isSel || a.id === hover) && (
                <text y={-r - 6} textAnchor="middle" className="lbl">
                  {a.id}
                </text>
              )}
            </g>
          )
        })}
        {!compact && (
          <g className="cities">
            {[
              ["Delhi NCR", 395, 300],
              ["Lucknow", 520, 342],
              ["Jaipur", 330, 330],
              ["Bhopal", 420, 432],
              ["Sambalpur", 610, 460],
              ["Dehradun", 452, 200],
              ["Varanasi", 568, 378],
            ].map(([t, x, y]) => (
              <text key={t as string} x={x as number} y={y as number}>
                {t}
              </text>
            ))}
          </g>
        )}
      </svg>

      <div className="map-zoom" role="group" aria-label="Zoom">
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

      <div className="map-legend" aria-label="Legend">
        <div>
          <b>Risk</b>
          {(["Critical", "High", "Medium", "Low"] as const).map((l) => (
            <span key={l}>
              <i style={{ background: levelColor[l] }} />
              {l}
            </span>
          ))}
        </div>
        <div>
          <b>Sector (ring)</b>
          {Object.values(sectorOf).map((s) => (
            <span key={s.label}>
              <i style={{ background: s.color }} />
              {s.label}
            </span>
          ))}
        </div>
        <div>
          <b>Links</b>
          <span>
            <em className="ln" /> attested dependency
          </span>
          <span>
            <em className="ln dash" /> AI-inferred path
          </span>
          <span>
            <em className="ln hot" /> cascade from selection
          </span>
        </div>
      </div>
    </div>
  )
})
