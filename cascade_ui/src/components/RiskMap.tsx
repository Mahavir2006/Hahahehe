import { memo, useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react"
import { ChevronDown, Maximize2, Minimize2, Minus, Plus, X } from "lucide-react"
import { assets, assetById, dependencies, downstreamOf, levelColor, sectorOf, type Asset } from "@/data/derive"
import { CITY_LABELS, INDIA, locate, neighbourPaths, statePaths } from "@/data/geo"
import { ATTACK_TYPES, threatStream, type ThreatEvent } from "@/data/threats"

/* Frame: India in the middle with neighbouring land visible on both sides. */
const FRAME = { x: -230, y: -40, w: INDIA.w + 460, h: INDIA.h + 80 }
const MAX_ZOOM = 5
/** External origins around India (sea and borders); traffic is tracked only where it lands in India. */
const ORIGINS: [number, number][] = [
  [-190, 170], [-170, 430], [-60, 650], [120, -30], [430, -35], [790, 110], [800, 430], [690, 690],
]

/** Assets in one city sit on top of each other; fan them out so every marker is clickable. */
function layout(list: Asset[]) {
  const raw = new Map(list.map((a) => [a.id, locate(a.location)]))
  const pos = new Map<string, { x: number; y: number; ax: number; ay: number }>()
  const groups: Asset[][] = []
  for (const a of list) {
    const p = raw.get(a.id)!
    const g = groups.find((g) => {
      const q = raw.get(g[0].id)!
      return Math.hypot(q[0] - p[0], q[1] - p[1]) < 9
    })
    if (g) g.push(a)
    else groups.push([a])
  }
  for (const g of groups) {
    const cx = g.reduce((s, a) => s + raw.get(a.id)![0], 0) / g.length
    const cy = g.reduce((s, a) => s + raw.get(a.id)![1], 0) / g.length
    g.forEach((a, i) => {
      if (g.length === 1) return pos.set(a.id, { x: cx, y: cy, ax: cx, ay: cy })
      const ang = (i / g.length) * Math.PI * 2 - Math.PI / 2
      const r = 9 + g.length * 1.6
      pos.set(a.id, { x: cx + Math.cos(ang) * r, y: cy + Math.sin(ang) * r, ax: cx, ay: cy })
    })
  }
  return pos
}

/** Curved arc between two points (quadratic Bézier lifted perpendicular to the chord). */
function arc([x1, y1]: [number, number], [x2, y2]: [number, number], lift = 0.28) {
  const mx = (x1 + x2) / 2
  const my = (y1 + y2) / 2
  const dx = x2 - x1
  const dy = y2 - y1
  return `M${x1},${y1} Q${mx - dy * lift},${my + dx * lift} ${x2},${y2}`
}

interface Live extends ThreatEvent {
  born: number
}

/** World and India: static, so it is drawn once and only redrawn when the view moves. */
const BaseLayer = memo(function BaseLayer({ vb, uid }: { vb: string; uid: string }) {
  return (
    <svg className="m-base" viewBox={vb} aria-hidden>
      <defs>
        <pattern id={`dots-${uid}`} width="5" height="5" patternUnits="userSpaceOnUse">
          <circle cx="2.5" cy="2.5" r="0.8" className="m-dot-in" />
        </pattern>
        <pattern id={`dim-${uid}`} width="5" height="5" patternUnits="userSpaceOnUse">
          <circle cx="2.5" cy="2.5" r="0.7" className="m-dot-out" />
        </pattern>
        <radialGradient id={`glow-${uid}`}>
          <stop offset="0" className="m-glow-a" />
          <stop offset="1" className="m-glow-b" />
        </radialGradient>
      </defs>
      <g className="m-world">
        {neighbourPaths.map((d, i) => (
          <path key={i} d={d} fill={`url(#dim-${uid})`} />
        ))}
      </g>
      <ellipse cx={INDIA.w / 2} cy={INDIA.h / 2} rx={INDIA.w * 0.62} ry={INDIA.h * 0.55} fill={`url(#glow-${uid})`} />
      {statePaths.map((s) => (
        <path key={s.id} d={s.d} className="m-state-base" />
      ))}
      {statePaths.map((s) => (
        <path key={s.id + "d"} d={s.d} fill={`url(#dots-${uid})`} className="m-state">
          <title>{s.name}</title>
        </path>
      ))}
      {CITY_LABELS.map((c) => (
        <text key={c.name} x={c.at[0] + 7} y={c.at[1] + 11} className="m-city">
          {c.name}
        </text>
      ))}
    </svg>
  )
})

export const RiskMap = memo(function RiskMap({
  selected,
  onSelect,
  sector = "All",
  minLevel = "All",
  legend = true,
  live = true,
  cascadeShown,
  blocked,
  fitTo,
  help,
  notes,
  info,
}: {
  selected: string | null
  onSelect: (id: string | null) => void
  sector?: string
  minLevel?: string
  compact?: boolean
  legend?: boolean
  live?: boolean
  /** Cascade simulator: only these downstream assets are highlighted (revealed step by step). */
  cascadeShown?: Set<string>
  /** Cascade simulator: assets the chosen defence protected. */
  blocked?: Set<string>
  /** Zoom smoothly to frame these assets (e.g. a cascade); empty or undefined = all of India. */
  fitTo?: string[]
  /** Small help text pinned to the map's top-right corner. */
  help?: ReactNode
  /** Short labels drawn under assets (e.g. "T+25 min"). */
  notes?: Record<string, string>
  /** When given, a small glass card with this content opens next to the selected marker. */
  info?: (a: Asset) => ReactNode
}) {
  const uid = useId().replace(/:/g, "")
  const [view, setView] = useState({ k: 1, cx: INDIA.w / 2, cy: INDIA.h / 2 })
  const [hover, setHover] = useState<string | null>(null)
  const [cardPos, setCardPos] = useState<{ left: number; top: number; flip: boolean } | null>(null)
  const [events, setEvents] = useState<Live[]>([])
  const [feed, setFeed] = useState<Live[]>([])
  const [count, setCount] = useState(0)
  // live window can be minimised to a small pill; the choice is remembered
  const [hudOpen, setHudOpen] = useState(() => {
    try {
      return localStorage.getItem("cs-hud") !== "closed"
    } catch {
      return true
    }
  })
  const toggleHud = (open: boolean) => {
    setHudOpen(open)
    try {
      localStorage.setItem("cs-hud", open ? "open" : "closed")
    } catch {
      /* storage blocked: only this visit remembers */
    }
  }
  const wrap = useRef<HTMLDivElement>(null)
  const svgRef = useRef<SVGSVGElement>(null)
  const nodes = useRef(new Map<string, SVGGElement>())
  const drag = useRef<{ x: number; y: number; cx: number; cy: number } | null>(null)
  const [hint, setHint] = useState(false)
  const hintTimer = useRef<ReturnType<typeof setTimeout>>(undefined)
  const seq = useRef(0) // event ids stay unique even if the stream restarts (React dev double-mount)
  const pos = useMemo(() => layout(assets), [])
  const focus = cascadeShown ? selected : hover ?? selected
  const downstream = useMemo(() => cascadeShown ?? (focus ? downstreamOf(focus) : new Set<string>()), [focus, cascadeShown])
  const order = ["Low", "Medium", "High", "Critical"]
  const visible = (a: Asset) => (sector === "All" || a.org === sector) && (minLevel === "All" || order.indexOf(a.level) >= order.indexOf(minLevel))

  /* ----- zoom & pan, limited to India ----- */
  const clampView = useCallback((k: number, cx: number, cy: number) => {
    k = Math.min(MAX_ZOOM, Math.max(1, k))
    if (k === 1) return { k, cx: INDIA.w / 2, cy: INDIA.h / 2 } // fully zoomed out = India framed, no further
    return { k, cx: Math.min(INDIA.w, Math.max(0, cx)), cy: Math.min(INDIA.h, Math.max(0, cy)) }
  }, [])
  const vw = FRAME.w / view.k
  const vh = FRAME.h / view.k
  const vb = `${view.cx - vw / 2} ${view.cy - vh / 2} ${vw} ${vh}`
  const zoomBy = (f: number) => setView((v) => clampView(v.k * f, v.cx, v.cy))

  useEffect(() => {
    const el = svgRef.current
    if (!el) return
    const onWheel = (e: WheelEvent) => {
      if (!e.ctrlKey && !e.metaKey) {
        setHint(true)
        clearTimeout(hintTimer.current)
        hintTimer.current = setTimeout(() => setHint(false), 1400)
        return // let the page scroll
      }
      e.preventDefault()
      const box = el.getBoundingClientRect()
      setView((v) => {
        const scale = Math.max((FRAME.w / v.k) / box.width, (FRAME.h / v.k) / box.height)
        const px = v.cx + (e.clientX - box.left - box.width / 2) * scale
        const py = v.cy + (e.clientY - box.top - box.height / 2) * scale
        const k = Math.min(MAX_ZOOM, Math.max(1, v.k * (e.deltaY < 0 ? 1.2 : 1 / 1.2)))
        const t = v.k / k // keep the point under the cursor fixed
        return clampView(k, px + (v.cx - px) * t, py + (v.cy - py) * t)
      })
    }
    el.addEventListener("wheel", onWheel, { passive: false })
    return () => el.removeEventListener("wheel", onWheel)
  }, [clampView])

  const onPointerDown = (e: React.PointerEvent) => {
    if (view.k === 1 || (e.target as Element).closest(".node")) return
    drag.current = { x: e.clientX, y: e.clientY, cx: view.cx, cy: view.cy }
    ;(e.currentTarget as Element).setPointerCapture(e.pointerId)
  }
  const onPointerMove = (e: React.PointerEvent) => {
    const d = drag.current
    const el = svgRef.current
    if (!d || !el) return
    const box = el.getBoundingClientRect()
    const scale = Math.max(vw / box.width, vh / box.height)
    setView((v) => clampView(v.k, d.cx - (e.clientX - d.x) * scale, d.cy - (e.clientY - d.y) * scale))
  }
  const endDrag = () => (drag.current = null)

  const fitKey = fitTo?.join(",") ?? ""
  useEffect(() => {
    const ids = fitKey ? fitKey.split(",") : []
    const pts = ids.map((id) => pos.get(id)).filter((p): p is NonNullable<typeof p> => !!p)
    let target = { k: 1, cx: INDIA.w / 2, cy: INDIA.h / 2 }
    if (pts.length) {
      const xs = pts.map((p) => p.x)
      const ys = pts.map((p) => p.y)
      const pad = 60
      const bw = Math.max(...xs) - Math.min(...xs) + pad * 2
      const bh = Math.max(...ys) - Math.min(...ys) + pad * 2
      target = clampView(Math.min(FRAME.w / bw, FRAME.h / bh, 4), (Math.max(...xs) + Math.min(...xs)) / 2, (Math.max(...ys) + Math.min(...ys)) / 2)
    }
    let raf: ReturnType<typeof setTimeout> | undefined
    let from: typeof target | null = null
    const t0 = performance.now()
    const stepFn = () => {
      const u = Math.min(1, (performance.now() - t0) / 650)
      const e = 1 - Math.pow(1 - u, 3)
      setView((v) => {
        from ??= v
        return { k: from.k + (target.k - from.k) * e, cx: from.cx + (target.cx - from.cx) * e, cy: from.cy + (target.cy - from.cy) * e }
      })
      if (u < 1) raf = setTimeout(stepFn, 16) // timer, not rAF, so it also completes in background tabs
    }
    if (fitTo !== undefined) stepFn()
    return () => clearTimeout(raf)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fitKey, pos, clampView])

  /* ----- live threat stream ----- */
  useEffect(() => {
    if (!live) return
    const stream = threatStream()
    let timer: ReturnType<typeof setTimeout>
    const tick = () => {
      if (!document.hidden) {
        const e: Live = { ...stream.next().value!, id: ++seq.current, born: Date.now() }
        setEvents((xs) => [...xs.filter((x) => Date.now() - x.born < 2600), e].slice(-14))
        setFeed((xs) => [e, ...xs].slice(0, 6))
        setCount((c) => c + 1)
      }
      timer = setTimeout(tick, 650 + Math.random() * 700)
    }
    tick()
    return () => clearTimeout(timer)
  }, [live])

  /* ----- info card placement (screen pixels, follows zoom and resize) ----- */
  useLayoutEffect(() => {
    if (!info || !selected) return setCardPos(null)
    const place = () => {
      const n = nodes.current.get(selected)
      const box = wrap.current?.getBoundingClientRect()
      if (!n || !box) return
      const r = n.getBoundingClientRect()
      // keep the whole card inside the map: right of the marker, else left of it, else centred
      const W = 264
      const H = 230
      const x = r.left + r.width / 2 - box.left
      const y = r.top + r.height / 2 - box.top
      const left = x + 18 + W <= box.width - 8 ? x + 18 : x - 18 - W >= 8 ? x - 18 - W : Math.max(8, Math.min(box.width - W - 8, x - W / 2))
      const top = Math.max(8, Math.min(box.height - H - 8, y - H / 2))
      setCardPos({ left, top, flip: false })
    }
    place()
    const ro = new ResizeObserver(place)
    if (wrap.current) ro.observe(wrap.current)
    return () => ro.disconnect()
  }, [info, selected, view])

  useEffect(() => {
    if (!info) return
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onSelect(null)
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [info, onSelect])

  const sel = selected ? assetById.get(selected) : undefined
  const hits = useMemo(() => {
    const m = new Map<string, number>()
    for (const e of feed) m.set(e.target, (m.get(e.target) ?? 0) + 1)
    return m
  }, [feed])

  return (
    <div ref={wrap} className={`riskmap ${view.k > 1 ? "zoomed" : ""}`}>
      <BaseLayer vb={vb} uid={uid} />
      <svg
        ref={svgRef}
        className="m-overlay"
        viewBox={vb}
        role="img"
        aria-label="Live threat map of India showing monitored infrastructure assets and incoming attack activity"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={endDrag}
        onPointerLeave={endDrag}
        onClick={(e) => info && !(e.target as Element).closest(".node") && onSelect(null)}
      >
        <defs>
          <marker id={`arr-${uid}`} viewBox="0 0 10 10" refX="8" refY="5" markerWidth="4" markerHeight="4" orient="auto">
            <path d="M0 1L10 5L0 9z" fill="var(--danger)" />
          </marker>
        </defs>
        {/* cascade links, only for the asset in focus */}
        {focus &&
          dependencies
            .filter((d) => (d.from === focus || downstream.has(d.from)) && downstream.has(d.to))
            .map((d) => {
              const a = pos.get(d.from)
              const b = pos.get(d.to)
              if (!a || !b) return null
              return <path key={d.from + d.to} d={arc([a.x, a.y], [b.x, b.y], 0.18)} className={`m-cascade ${d.kind}`} markerEnd={`url(#arr-${uid})`} />
            })}

        {/* live attack arcs */}
        {events.map((e) => {
          const to = pos.get(e.target)
          if (!to) return null
          const from = e.from ? pos.get(e.from) : undefined
          const start: [number, number] = from ? [from.x, from.y] : ORIGINS[e.origin]
          const color = ATTACK_TYPES[e.type].color
          return (
            <g key={e.id} className="m-attack" style={{ "--c": color } as React.CSSProperties}>
              <path d={arc(start, [to.x, to.y], from ? 0.2 : 0.22)} pathLength={1} className="m-trail" />
              <path d={arc(start, [to.x, to.y], from ? 0.2 : 0.22)} pathLength={1} className="m-comet" />
              <circle cx={to.x} cy={to.y} r={4} className="m-impact" />
            </g>
          )
        })}

        {/* assets */}
        {assets.map((a) => {
          const p = pos.get(a.id)!
          const show = visible(a)
          const isSel = a.id === selected
          const isDown = downstream.has(a.id)
          const r = (4 + (a.risk / 100) * 3.4) / Math.sqrt(view.k)
          return (
            <g
              key={a.id}
              ref={(el) => {
                if (el) nodes.current.set(a.id, el)
              }}
              transform={`translate(${p.x},${p.y})`}
              opacity={show ? (focus && !isSel && !isDown && a.id !== focus ? 0.45 : 1) : 0.12}
              className={`node ${blocked?.has(a.id) ? "blocked" : ""}`}
              role="button"
              tabIndex={show ? 0 : -1}
              aria-pressed={isSel}
              aria-label={`${a.id} ${a.name}, ${a.location}, ${a.level} risk ${a.risk.toFixed(1)}`}
              onClick={() => onSelect(a.id)}
              onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), onSelect(a.id))}
              onMouseEnter={() => setHover(a.id)}
              onMouseLeave={() => setHover(null)}
            >
              {p.ax !== p.x && <line x1={0} y1={0} x2={p.ax - p.x} y2={p.ay - p.y} className="m-leader" />}
              {(a.level === "Critical" || hits.has(a.id)) && <circle r={r * 2.2} className="pulse" stroke={levelColor[a.level]} />}
              <circle r={r + 1.8} className="m-halo" />
              <circle r={r + 1.4} fill="none" stroke={sectorOf[a.org].color} strokeWidth={1.1 / Math.sqrt(view.k)} />
              <circle r={r} fill={levelColor[a.level]} className={`m-node ${isSel ? "sel" : isDown ? "down" : ""}`} style={{ "--lc": levelColor[a.level] } as React.CSSProperties} />
              {notes?.[a.id] && (
                <text y={r + 10 / Math.sqrt(view.k)} textAnchor="middle" className="m-note" style={{ fontSize: 7.5 / Math.sqrt(view.k) }}>
                  {notes[a.id]}
                </text>
              )}
              {(a.level === "Critical" || isSel || a.id === hover || !!notes?.[a.id]) && (
                <text y={-r - 4} textAnchor="middle" className="lbl" style={{ fontSize: 8 / Math.sqrt(view.k) }}>
                  {a.id}
                </text>
              )}
            </g>
          )
        })}
      </svg>

      {hint && <div className="map-hint glass">Hold Ctrl (⌘ on Mac) and scroll to zoom</div>}
      {help && <div className="map-help glass">{help}</div>}
      <div className="map-zoom glass" role="group" aria-label="Zoom (India only)">
        <button aria-label="Zoom in" onClick={() => zoomBy(1.5)} disabled={view.k >= MAX_ZOOM}>
          <Plus size={15} />
        </button>
        <button aria-label="Zoom out" onClick={() => zoomBy(1 / 1.5)} disabled={view.k <= 1}>
          <Minus size={15} />
        </button>
        <button aria-label="Reset to all of India" onClick={() => setView(clampView(1, 0, 0))} disabled={view.k <= 1}>
          <Maximize2 size={14} />
        </button>
      </div>

      {live && !hudOpen && (
        <button className="threat-pill glass" onClick={() => toggleHud(true)} aria-label="Show live threat activity" aria-expanded={false}>
          <span className="live-dot" />
          <span>Live · India</span>
          <b>{count}</b>
          <ChevronDown size={14} aria-hidden />
        </button>
      )}
      {live && hudOpen && (
        <div className="threat-hud glass" aria-live="off">
          <div className="hud-head">
            <span className="live-dot" /> Live threats · India
            <b>{count}</b>
            <button className="hud-min" onClick={() => toggleHud(false)} aria-label="Minimise live threat activity" aria-expanded>
              <Minimize2 size={13} />
            </button>
          </div>
          <ul>
            {feed.map((e) => (
              <li key={e.id}>
                <i style={{ background: ATTACK_TYPES[e.type].color }} />
                <span>
                  <strong>{e.target}</strong> {ATTACK_TYPES[e.type].label}
                </span>
                <small>{assetById.get(e.target)?.location}</small>
              </li>
            ))}
          </ul>
          <small className="hud-note">Simulated from project detections</small>
        </div>
      )}

      {info && sel && cardPos && (
        <div className={`map-card glass ${cardPos.flip ? "flip" : ""}`} style={{ left: cardPos.left, top: cardPos.top }} role="dialog" aria-label={`${sel.id} summary`}>
          <button className="map-card-x" aria-label="Close" onClick={() => onSelect(null)}>
            <X size={13} />
          </button>
          {info(sel)}
        </div>
      )}

      {legend && (
        <div className="map-legend glass" aria-label="Legend">
          <div>
            {Object.values(ATTACK_TYPES).map((t) => (
              <span key={t.label}>
                <i style={{ background: t.color }} />
                {t.label}
              </span>
            ))}
          </div>
          <div>
            <b>Asset risk</b>
            {(["Critical", "High", "Medium", "Low"] as const).map((l) => (
              <span key={l}>
                <i style={{ background: levelColor[l] }} />
                {l}
              </span>
            ))}
            <b>Ring</b>
            {Object.values(sectorOf).map((s) => (
              <span key={s.label}>
                <i className="ring" style={{ borderColor: s.color }} />
                {s.label}
              </span>
            ))}
          </div>
        </div>
      )}
      <span className="map-credit">India map: @svg-maps/india (CC BY 4.0) · borders: Natural Earth</span>
    </div>
  )
})
