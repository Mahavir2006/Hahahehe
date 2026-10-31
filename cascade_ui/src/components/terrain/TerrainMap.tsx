import { memo, useCallback, useEffect, useMemo, useRef, useState, type CSSProperties, type PointerEvent as ReactPointerEvent, type ReactElement } from "react"
import { Check, Hospital, Layers3, Map as MapIcon, Maximize2, Minus, Network, Plus, Waves, X, Zap } from "lucide-react"
import regionTexture from "./assets/relief-region.webp"
import groundTexture from "./assets/relief-ground.webp"
import {
  GROUND_EXTENT,
  REGION_EXTENT,
  damPath,
  footprintPath,
  landBounds,
  landmass,
  landmassPath,
  orgGeometries,
  powerPath,
  pylons,
  reservoirPath,
  rivers,
  roads,
  toPath,
  zoneBoundaryPath,
  zoneById,
  zones,
  type Pt,
  type Zone,
} from "./geography"
import { assets, assetById, dependencies, downstreamOf, orgByCode, organisations, type Asset, type OrgCode } from "../../data/infrastructure"
import "./terrain.css"

/* Camera model ------------------------------------------------------------ */

const THETA = -0.14 // plane rotation in terrain view
const SQUASH = 0.6 // vertical foreshortening (tilt)
const DEPTH = 13 // slab thickness, plane units
const LIFT = 9 // raised height of a selected organisation
const MIN_K = 1
const MAX_K = 5
const HULL = landmass.filter((_, i) => i % 5 === 0)

interface Cam {
  k: number
  cx: number
  cy: number
  tilt: number
  lift: number
}

interface Anchor {
  sx: number
  sy: number
  px: number
  py: number
}

/**
 * Viewport layout in screen pixels. The fit rectangle frames the whole region and
 * may extend beneath translucent HUD panels; the safe rectangle is unobstructed
 * and is used for focus fitting, floating cards and map controls.
 */
interface Frame {
  w: number
  h: number
  fx: number
  fy: number
  fw: number
  fh: number
  sx: number
  sy: number
  sw: number
  sh: number
}

const EMPTY_FRAME: Frame = {
  w: 0,
  h: 0,
  fx: 0,
  fy: 0,
  fw: 0,
  fh: 0,
  sx: 0,
  sy: 0,
  sw: 0,
  sh: 0,
}

/* The surrounding ground texture fades out before its edges in plane space. */
const GROUND_CX = (GROUND_EXTENT.x0 + GROUND_EXTENT.x1) / 2
const GROUND_CY = (GROUND_EXTENT.y0 + GROUND_EXTENT.y1) / 2
const GROUND_RX = (GROUND_EXTENT.x1 - GROUND_EXTENT.x0) / 2
const GROUND_RY = (GROUND_EXTENT.y1 - GROUND_EXTENT.y0) / 2

interface View {
  m: [number, number, number, number, number, number]
  sc: number
  b: number
  depth: number
  lift: number
}

const PAD = { x: 20, y: 44 }

function projection(tilt: number) {
  const th = THETA * tilt
  return { cs: Math.cos(th), sn: Math.sin(th), s: 1 - (1 - SQUASH) * tilt }
}

function projectedBounds(points: Pt[], tilt: number) {
  const { cs, sn, s } = projection(tilt)
  let x0 = Infinity
  let y0 = Infinity
  let x1 = -Infinity
  let y1 = -Infinity
  for (const [x, y] of points) {
    const px = x * cs - y * sn
    const py = (x * sn + y * cs) * s
    x0 = Math.min(x0, px)
    x1 = Math.max(x1, px)
    y0 = Math.min(y0, py)
    y1 = Math.max(y1, py)
  }
  return { x0, y0, x1, y1 }
}

function unproject(px: number, py: number, tilt: number): Pt {
  const { cs, sn, s } = projection(tilt)
  const y = py / s
  return [px * cs + y * sn, -px * sn + y * cs]
}

function baseScale(frame: Frame, tilt: number) {
  const bb = projectedBounds(HULL, tilt)
  return Math.max(0.05, Math.min((frame.fw - PAD.x * 2) / (bb.x1 - bb.x0), (frame.fh - PAD.y * 2) / (bb.y1 - bb.y0 + DEPTH * tilt)))
}

/** Screen position of the camera centre: the middle of the fit rectangle. */
function viewOrigin(frame: Frame, b: number, tilt: number): Pt {
  return [frame.fx + frame.fw / 2, frame.fy + frame.fh / 2 - (DEPTH * b * tilt) / 2]
}

function makeView(frame: Frame, cam: Cam): View {
  const { cs, sn, s } = projection(cam.tilt)
  const b = baseScale(frame, cam.tilt)
  const sc = b * cam.k
  const pcx = cam.cx * cs - cam.cy * sn
  const pcy = (cam.cx * sn + cam.cy * cs) * s
  const [ox, oy] = viewOrigin(frame, b, cam.tilt)
  return {
    m: [sc * cs, sc * s * sn, -sc * sn, sc * s * cs, ox - sc * pcx, oy - sc * pcy],
    sc,
    b,
    depth: DEPTH * sc * cam.tilt,
    lift: LIFT * sc * cam.tilt * cam.lift,
  }
}

const toScreen = (v: View, x: number, y: number): Pt => [v.m[0] * x + v.m[2] * y + v.m[4], v.m[1] * x + v.m[3] * y + v.m[5]]

function toPlane(v: View, sx: number, sy: number): Pt {
  const [a, b, c, d, e, f] = v.m
  const det = a * d - b * c
  const x = sx - e
  const y = sy - f
  return [(d * x - c * y) / det, (-b * x + a * y) / det]
}

function centerForAnchor(frame: Frame, cam: Cam, anchor: Anchor): Pt {
  const { cs, sn, s } = projection(cam.tilt)
  const b = baseScale(frame, cam.tilt)
  const sc = b * cam.k
  const [ox, oy] = viewOrigin(frame, b, cam.tilt)
  const ppx = anchor.px * cs - anchor.py * sn
  const ppy = (anchor.px * sn + anchor.py * cs) * s
  return unproject(ppx - (anchor.sx - ox) / sc, ppy - (anchor.sy - oy) / sc, cam.tilt)
}

const clampCenter = (x: number, y: number): Pt => [
  Math.max(landBounds.x0, Math.min(landBounds.x1, x)),
  Math.max(landBounds.y0, Math.min(landBounds.y1, y)),
]

/** Zoom and centre that frame `points` inside the unobstructed safe rectangle. */
function fitTarget(frame: Frame, points: Pt[], tilt: number, pad: number, minK: number): Focus {
  const bb = projectedBounds(points, tilt)
  const b = baseScale(frame, tilt)
  const fitK = Math.min((frame.sw - pad * 2) / (b * (bb.x1 - bb.x0)), (frame.sh - pad * 2) / (b * (bb.y1 - bb.y0)))
  const k = Math.max(minK, Math.min(MAX_K, fitK))
  const sc = b * k
  const [ox, oy] = viewOrigin(frame, b, tilt)
  const [cx, cy] = unproject(
    (bb.x0 + bb.x1) / 2 - (frame.sx + frame.sw / 2 - ox) / sc,
    (bb.y0 + bb.y1) / 2 - (frame.sy + frame.sh / 2 - oy) / sc,
    tilt,
  )
  return { k, cx, cy }
}

/** Whole-region framing: the landmass centred in the fit rectangle. */
function regionFocus(tilt: number): Focus {
  const bb = projectedBounds(HULL, tilt)
  const [cx, cy] = unproject((bb.x0 + bb.x1) / 2, (bb.y0 + bb.y1) / 2, tilt)
  return { k: 1, cx, cy }
}

const smooth = (e0: number, e1: number, v: number) => {
  const t = Math.max(0, Math.min(1, (v - e0) / (e1 - e0)))
  return t * t * (3 - 2 * t)
}

const mixRGB = (a: number[], b: number[], t: number) => `rgb(${a.map((v, i) => Math.round(v + (b[i] - v) * t)).join(",")})`
const ORG_RGB: Record<OrgCode, number[]> = { WGEC: [40, 184, 197], MetroWater: [233, 154, 67], CCMN: [66, 185, 139] }
const orgIcon = { WGEC: Zap, MetroWater: Waves, CCMN: Hospital }

/* Static terrain layers (plane coordinates) -------------------------------- */

const facilityPath = assets
  .map((asset, i) => {
    const angle = ((i * 37) % 60) / 100 - 0.3
    const ca = Math.cos(angle)
    const sa = Math.sin(angle)
    const corners: Pt[] = [
      [-9, -6],
      [9, -6],
      [9, 6],
      [-9, 6],
    ]
    return toPath(
      corners.map(([x, y]): Pt => [asset.x + x * ca - y * sa, asset.y + x * sa + y * ca]),
      true,
    )
  })
  .join("")

const WaterLayer = memo(function WaterLayer() {
  return (
    <g>
      {rivers.map((river) => (
        <path key={`bank-${river.id}`} d={river.d} className="tm-river-bank" strokeWidth={river.width * 2.8} />
      ))}
      <path d={reservoirPath} className="tm-lake" />
      {rivers.map((river) => (
        <path key={river.id} d={river.d} className="tm-river" strokeWidth={river.width} />
      ))}
      <path d={damPath} className="tm-dam" />
    </g>
  )
})

const RoadLayer = memo(function RoadLayer({ tier }: { tier: 1 | 2 | 3 }) {
  return (
    <g className={`tm-roads tm-road-${tier}`}>
      {roads
        .filter((road) => road.tier === tier)
        .map((road) => (
          <path key={road.id} d={road.d} />
        ))}
    </g>
  )
})

const PowerLayer = memo(function PowerLayer() {
  return (
    <g>
      <path d={powerPath} className="tm-power" />
      {pylons.map(([x, y], i) => (
        <circle key={i} cx={x} cy={y} r={1.15} className="tm-pylon" />
      ))}
    </g>
  )
})

const BuildingLayer = memo(function BuildingLayer() {
  return (
    <g>
      <path d={footprintPath} className="tm-building-shadow" transform="translate(0.7 0.9)" />
      <path d={footprintPath} className="tm-building" />
      <path d={facilityPath} className="tm-facility" />
    </g>
  )
})

const ZoneLines = memo(function ZoneLines() {
  return <path d={zoneBoundaryPath} className="tm-zone-lines" />
})

interface OrgLayerProps {
  fill: boolean
  line: boolean
}

const OrgLayer = memo(function OrgLayer({ fill, line }: OrgLayerProps) {
  return (
    <g>
      {organisations.map((org) => (
        <g key={org.code} className={`tm-org tm-org-${org.slug}`}>
          {fill && <path d={orgGeometries[org.code].fillPath} className="tm-org-fill" />}
          {line && (
            <>
              <path d={orgGeometries[org.code].boundaryPath} className="tm-org-halo" />
              <path d={orgGeometries[org.code].boundaryPath} className="tm-org-line" />
            </>
          )}
        </g>
      ))}
    </g>
  )
})

/* Component --------------------------------------------------------------- */

export interface MapSelection {
  org: OrgCode | null
  zone: string | null
}

interface Layers {
  regions: boolean
  zones: boolean
  water: boolean
  roads: boolean
  power: boolean
  buildings: boolean
  dependencies: boolean
}

const LAYER_LABELS: Array<[keyof Layers, string]> = [
  ["regions", "Organisation regions"],
  ["zones", "Service zones"],
  ["water", "Rivers & reservoir"],
  ["roads", "Road network"],
  ["power", "Transmission lines"],
  ["buildings", "Buildings & sites"],
  ["dependencies", "Dependency paths"],
]

interface Lod {
  zones: number
  minor: number
  detail: number
}

interface Focus {
  k: number
  cx: number
  cy: number
}

interface SurfaceProps {
  lod: Lod
  layers: Layers
  terrainOpacity: number
  zoneList: Zone[]
  selection: MapSelection
  riskZone: string | null
  cascadeZones: Set<string>
  onZone: (zone: Zone) => void
  onHover: (id: string | null) => void
}

function Surface({ lod, layers, terrainOpacity, zoneList, selection, riskZone, cascadeZones, onZone, onHover }: SurfaceProps) {
  return (
    <>
      <image
        href={regionTexture}
        x={REGION_EXTENT.x0}
        y={REGION_EXTENT.y0}
        width={REGION_EXTENT.x1 - REGION_EXTENT.x0}
        height={REGION_EXTENT.y1 - REGION_EXTENT.y0}
        preserveAspectRatio="none"
        opacity={terrainOpacity}
      />
      {layers.regions && <OrgLayer fill line={false} />}
      {layers.zones && lod.zones > 0.01 && (
        <g opacity={lod.zones}>
          <ZoneLines />
        </g>
      )}
      {layers.water && <WaterLayer />}
      {layers.roads && lod.minor > 0.01 && (
        <g opacity={lod.minor}>
          <RoadLayer tier={3} />
        </g>
      )}
      {layers.roads && (
        <>
          <RoadLayer tier={2} />
          <RoadLayer tier={1} />
        </>
      )}
      {layers.buildings && lod.detail > 0.01 && (
        <g opacity={lod.detail}>
          <BuildingLayer />
        </g>
      )}
      {layers.power && lod.minor > 0.01 && (
        <g opacity={lod.minor}>
          <PowerLayer />
        </g>
      )}
      {layers.regions && <OrgLayer fill={false} line />}
      {zoneList.map((zone) => {
        const state = [
          zone.id === selection.zone && "is-selected",
          zone.id === riskZone && "is-risk",
          cascadeZones.has(zone.id) && "is-cascade",
        ]
          .filter(Boolean)
          .join(" ")
        return (
          <path
            key={zone.id}
            d={zone.d}
            className={`tm-zone ${state}`}
            onClick={() => onZone(zone)}
            onPointerEnter={() => onHover(zone.id)}
            onPointerLeave={() => onHover(null)}
          />
        )
      })}
    </>
  )
}

interface DragState {
  id: number
  x: number
  y: number
  lx: number
  ly: number
  active: boolean
}

let mapCount = 0

export interface TerrainMapProps {
  selectedAssetId?: string | null
  onAssetSelect?: (asset: Asset) => void
  /** "modifier" requires Ctrl/⌘ + wheel so page scrolling is not hijacked. */
  wheelZoom?: "always" | "modifier"
  className?: string
}

export function TerrainMap({ selectedAssetId = null, onAssetSelect, wheelZoom = "modifier", className = "" }: TerrainMapProps) {
  const uid = useMemo(() => `tm${++mapCount}`, [])
  const containerRef = useRef<HTMLDivElement>(null)
  const fitRef = useRef<HTMLDivElement>(null)
  const safeRef = useRef<HTMLDivElement>(null)
  const [frame, setFrame] = useState<Frame>(EMPTY_FRAME)
  const frameRef = useRef(frame)
  const [mode, setMode] = useState<"terrain" | "network">("terrain")
  const [scope, setScope] = useState<"organisation" | "asset">("organisation")
  const [selection, setSelection] = useState<MapSelection>({ org: null, zone: null })
  const [liftedOrg, setLiftedOrg] = useState<OrgCode | null>(null)
  const [hoverZone, setHoverZone] = useState<string | null>(null)
  const [layers, setLayers] = useState<Layers>({ regions: true, zones: true, water: true, roads: true, power: true, buildings: true, dependencies: true })
  const [layersOpen, setLayersOpen] = useState(false)
  const [hint, setHint] = useState(false)
  const [dragging, setDragging] = useState(false)
  const hintTimer = useRef(0)

  /* Animated camera */
  const initial: Cam = { k: 1, cx: 500, cy: 350, tilt: 1, lift: 0 }
  const [cam, setCam] = useState<Cam>(initial)
  const cur = useRef<Cam>(initial)
  const tgt = useRef<Cam>(initial)
  const anchor = useRef<Anchor | null>(null)
  const raf = useRef(0)
  const last = useRef(0)
  const reduceMotion = useMemo(() => typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches, [])

  const tick = useCallback(
    (now: number) => {
      const dt = last.current ? Math.min(48, now - last.current) : 16
      last.current = now
      const a = reduceMotion ? 1 : 1 - Math.exp(-dt / 110)
      const c = { ...cur.current }
      const t = tgt.current
      let moving = false
      const lk = Math.log(c.k)
      const lt = Math.log(t.k)
      if (Math.abs(lt - lk) > 0.0008) {
        c.k = Math.exp(lk + (lt - lk) * a)
        moving = true
      } else c.k = t.k
      for (const key of ["tilt", "lift"] as const) {
        const d = t[key] - c[key]
        if (Math.abs(d) > 0.002) {
          c[key] += d * a
          moving = true
        } else c[key] = t[key]
      }
      if (anchor.current && c.k !== t.k) {
        ;[c.cx, c.cy] = centerForAnchor(frameRef.current, c, anchor.current)
      } else {
        anchor.current = null
        for (const key of ["cx", "cy"] as const) {
          const d = t[key] - c[key]
          if (Math.abs(d) > 0.05) {
            c[key] += d * a
            moving = true
          } else c[key] = t[key]
        }
      }
      cur.current = c
      setCam(c)
      if (moving) raf.current = requestAnimationFrame(tick)
      else {
        raf.current = 0
        last.current = 0
      }
    },
    [reduceMotion],
  )

  const animate = useCallback(() => {
    if (!raf.current) raf.current = requestAnimationFrame(tick)
  }, [tick])

  useEffect(() => () => cancelAnimationFrame(raf.current), [])

  const zoomAt = useCallback(
    (sx: number, sy: number, factor: number) => {
      const f = frameRef.current
      if (!f.w) return
      const [px, py] = toPlane(makeView(f, cur.current), sx, sy)
      const k = Math.max(MIN_K, Math.min(MAX_K, tgt.current.k * factor))
      const a = { sx, sy, px, py }
      const [cx, cy] = clampCenter(...centerForAnchor(f, { ...tgt.current, k }, a))
      anchor.current = a
      tgt.current = { ...tgt.current, k, cx, cy }
      animate()
    },
    [animate],
  )

  /* Zoom about the middle of the unobstructed area (buttons and keyboard) */
  const zoomAtCenter = useCallback(
    (factor: number) => {
      const f = frameRef.current
      zoomAt(f.sx + f.sw / 2, f.sy + f.sh / 2, factor)
    },
    [zoomAt],
  )

  /* Measure the viewport, its region-fit rectangle and its unobstructed area */
  useEffect(() => {
    const root = containerRef.current
    const fit = fitRef.current
    const safe = safeRef.current
    if (!root || !fit || !safe) return
    const measure = () => {
      const r = root.getBoundingClientRect()
      if (!r.width || !r.height) return
      const f = fit.getBoundingClientRect()
      const s = safe.getBoundingClientRect()
      const next: Frame = {
        w: Math.round(r.width),
        h: Math.round(r.height),
        fx: Math.round(f.left - r.left),
        fy: Math.round(f.top - r.top),
        fw: Math.max(160, Math.round(f.width)),
        fh: Math.max(120, Math.round(f.height)),
        sx: Math.round(s.left - r.left),
        sy: Math.round(s.top - r.top),
        sw: Math.max(160, Math.round(s.width)),
        sh: Math.max(120, Math.round(s.height)),
      }
      const prev = frameRef.current
      if ((Object.keys(next) as Array<keyof Frame>).every((key) => next[key] === prev[key])) return
      frameRef.current = next
      setFrame(next)
      if (!prev.w) {
        cur.current = { ...cur.current, ...regionFocus(cur.current.tilt) }
        tgt.current = { ...cur.current }
        setCam(cur.current)
      }
    }
    measure()
    const observer = new ResizeObserver(measure)
    observer.observe(root)
    observer.observe(fit)
    observer.observe(safe)
    return () => observer.disconnect()
  }, [])

  /* Camera follows selection and view mode */
  useEffect(() => {
    if (!frame.w) return
    const tilt = mode === "terrain" ? 1 : 0
    const zone = selection.zone ? zoneById.get(selection.zone) : undefined
    let focus: Focus
    if (zone) focus = fitTarget(frame, zone.points, tilt, 80, 2.2)
    else if (selection.org) focus = fitTarget(frame, orgGeometries[selection.org].zones.flatMap((z) => z.points), tilt, 36, 1.2)
    else focus = regionFocus(tilt)
    if (selection.org) setLiftedOrg(selection.org)
    anchor.current = null
    tgt.current = { ...focus, tilt, lift: selection.org && mode === "terrain" ? 1 : 0 }
    animate()
    // Re-fit only when the focus or the available space changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selection.org, selection.zone, mode, frame])

  /* Wheel zoom */
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const onWheel = (event: WheelEvent) => {
      if (wheelZoom === "modifier" && !event.ctrlKey && !event.metaKey) {
        setHint(true)
        window.clearTimeout(hintTimer.current)
        hintTimer.current = window.setTimeout(() => setHint(false), 1400)
        return
      }
      event.preventDefault()
      const rect = el.getBoundingClientRect()
      const delta = Math.max(-80, Math.min(80, event.deltaY * (event.deltaMode === 1 ? 16 : 1)))
      zoomAt(event.clientX - rect.left, event.clientY - rect.top, Math.exp(-delta * 0.004))
    }
    el.addEventListener("wheel", onWheel, { passive: false })
    return () => el.removeEventListener("wheel", onWheel)
  }, [wheelZoom, zoomAt])

  /* Drag to pan (capture only once the pointer actually moves) */
  const drag = useRef<DragState | null>(null)
  const suppressClick = useRef(false)
  const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.button !== 0 || (event.target as HTMLElement).closest("[data-map-ui]")) return
    drag.current = { id: event.pointerId, x: event.clientX, y: event.clientY, lx: event.clientX, ly: event.clientY, active: false }
    suppressClick.current = false
  }
  const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    const d = drag.current
    if (!d || d.id !== event.pointerId) return
    if (!d.active) {
      if (Math.hypot(event.clientX - d.x, event.clientY - d.y) < 4) return
      d.active = true
      containerRef.current?.setPointerCapture(event.pointerId)
      setDragging(true)
    }
    const v = makeView(frameRef.current, cur.current)
    const [a, b, c, dd] = v.m
    const det = a * dd - b * c
    const dx = -(event.clientX - d.lx)
    const dy = -(event.clientY - d.ly)
    d.lx = event.clientX
    d.ly = event.clientY
    const [cx, cy] = clampCenter(cur.current.cx + (dd * dx - c * dy) / det, cur.current.cy + (-b * dx + a * dy) / det)
    anchor.current = null
    cur.current = { ...cur.current, cx, cy }
    tgt.current = { ...tgt.current, cx, cy, k: cur.current.k }
    setCam(cur.current)
  }
  const onPointerUp = () => {
    if (drag.current?.active) {
      suppressClick.current = true
      setDragging(false)
    }
    drag.current = null
  }

  const selectZone = (zone: Zone) => {
    if (suppressClick.current) return
    if (zone.org && selection.org !== zone.org) setSelection({ org: zone.org, zone: null })
    else setSelection({ org: zone.org, zone: zone.id })
  }
  const clearSelection = () => {
    if (suppressClick.current) return
    setSelection({ org: null, zone: null })
  }
  const fitAll = () => {
    setSelection({ org: null, zone: null })
    anchor.current = null
    tgt.current = { ...tgt.current, ...regionFocus(tgt.current.tilt) }
    animate()
  }
  const setDetail = (level: number) => zoomAtCenter(level / tgt.current.k)

  /* Derived view state */
  const view = frame.w ? makeView(frame, cam) : null
  const k = cam.k
  const lod = { zones: smooth(1.12, 1.45, k), minor: smooth(1.45, 1.9, k), detail: smooth(1.95, 2.45, k) }
  const detailLevel = k >= 2.2 ? "Sites" : k >= 1.45 ? "Zones" : "Region"
  const terrainOpacity = 0.3 + 0.7 * cam.tilt
  const selectedAsset = selectedAssetId ? assetById.get(selectedAssetId) : undefined
  const downstream = useMemo(() => (selectedAssetId ? downstreamOf(selectedAssetId) : new Set<string>()), [selectedAssetId])
  const cascadeZones = useMemo(
    () => new Set([...downstream].map((id) => assetById.get(id)?.zone).filter((z): z is string => !!z && z !== selectedAsset?.zone)),
    [downstream, selectedAsset],
  )
  const showLift = liftedOrg !== null && cam.lift > 0.01

  const visibleAssets = assets.filter((asset) => {
    if (selection.org && asset.org !== selection.org) return asset.id === selectedAssetId || downstream.has(asset.id)
    if (scope === "asset" || mode === "network" || selection.org) return true
    return asset.level === "Critical" || asset.level === "High" || asset.id === selectedAssetId || downstream.has(asset.id) || k >= 1.9
  })
  const visibleIds = new Set(visibleAssets.map((a) => a.id))

  const screenOf = (x: number, y: number, org: OrgCode | null): Pt => {
    if (!view) return [0, 0]
    const [sx, sy] = toScreen(view, x, y)
    return [sx, sy - (showLift && org === liftedOrg ? view.lift : 0)]
  }

  const matrix = view ? `matrix(${view.m.map((n) => n.toFixed(4)).join(" ")})` : ""
  const surfaceProps = {
    lod,
    layers,
    terrainOpacity,
    selection,
    riskZone: selectedAsset?.zone ?? null,
    cascadeZones,
    onZone: selectZone,
    onHover: setHoverZone,
  }

  const walls: ReactElement[] = []
  if (view && view.depth > 0.5) {
    const n = Math.max(4, Math.min(26, Math.round(view.depth / 2)))
    for (let i = n; i >= 1; i--) {
      walls.push(
        <use
          key={`w${i}`}
          href={`#${uid}-land`}
          transform={`translate(0 ${((view.depth * i) / n).toFixed(2)}) ${matrix}`}
          fill={mixRGB([30, 52, 64], [8, 14, 20], i / n)}
        />,
      )
    }
  }
  const liftWalls: ReactElement[] = []
  if (view && showLift && liftedOrg && view.lift > 0.5) {
    const n = Math.max(3, Math.min(16, Math.round(view.lift / 1.5)))
    for (let i = 0; i < n; i++) {
      liftWalls.push(
        <path
          key={`l${i}`}
          d={orgGeometries[liftedOrg].fillPath}
          transform={`translate(0 ${(-(view.lift * i) / n).toFixed(2)}) ${matrix}`}
          fill={mixRGB([10, 18, 24], ORG_RGB[liftedOrg], 0.2 + (0.3 * i) / n)}
        />,
      )
    }
  }

  /* Screen vignette centred on the region, elliptical to match the fit area */
  const fcx = frame.fx + frame.fw / 2
  const fcy = frame.fy + frame.fh / 2
  const vrx = Math.max(200, frame.fw * 0.8)
  const vry = Math.max(160, frame.fh * 0.88)

  const depsToDraw = layers.dependencies ? dependencies.filter((dep) => visibleIds.has(dep.from) && visibleIds.has(dep.to)) : []
  const zoneCard = selection.zone ? zoneById.get(selection.zone) : undefined
  const hovered = hoverZone && hoverZone !== selection.zone ? zoneById.get(hoverZone) : undefined

  return (
    <div
      ref={containerRef}
      className={`tm-root ${dragging ? "is-dragging" : ""} ${className}`}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerUp}
      onDoubleClick={(event) => {
        if ((event.target as HTMLElement).closest("[data-map-ui]")) return
        const rect = containerRef.current!.getBoundingClientRect()
        zoomAt(event.clientX - rect.left, event.clientY - rect.top, 1.8)
      }}
      onKeyDown={(event) => {
        if (event.key === "Escape") setSelection(selection.zone ? { org: selection.org, zone: null } : { org: null, zone: null })
        else if (event.key === "+" || event.key === "=") {
          event.preventDefault()
          zoomAtCenter(1.4)
        } else if (event.key === "-" || event.key === "_") {
          event.preventDefault()
          zoomAtCenter(1 / 1.4)
        } else if (event.key === "0") fitAll()
      }}
      tabIndex={0}
      aria-label="Synthetic infrastructure terrain map"
    >
      {view && (
        <svg className="tm-svg" width={frame.w} height={frame.h}>
          <defs>
            <path id={`${uid}-land`} d={landmassPath} />
            <clipPath id={`${uid}-clip`}>
              <path d={landmassPath} />
            </clipPath>
            {liftedOrg && (
              <clipPath id={`${uid}-org`}>
                <path d={orgGeometries[liftedOrg].fillPath} />
              </clipPath>
            )}
            <radialGradient
              id={`${uid}-vignette`}
              gradientUnits="userSpaceOnUse"
              cx={fcx}
              cy={fcy}
              r={vrx}
              gradientTransform={`translate(${fcx} ${fcy}) scale(1 ${(vry / vrx).toFixed(4)}) translate(${-fcx} ${-fcy})`}
            >
              <stop offset="0.52" className="tm-vignette-clear" />
              <stop offset="1" className="tm-vignette-solid" />
            </radialGradient>
            <radialGradient
              id={`${uid}-ground-fade`}
              gradientUnits="userSpaceOnUse"
              cx={GROUND_CX}
              cy={GROUND_CY}
              r={GROUND_RX}
              gradientTransform={`translate(${GROUND_CX} ${GROUND_CY}) scale(1 ${(GROUND_RY / GROUND_RX).toFixed(4)}) translate(${-GROUND_CX} ${-GROUND_CY})`}
            >
              <stop offset="0.58" stopColor="#fff" />
              <stop offset="0.98" stopColor="#000" />
            </radialGradient>
            <mask
              id={`${uid}-ground-mask`}
              maskUnits="userSpaceOnUse"
              x={GROUND_EXTENT.x0}
              y={GROUND_EXTENT.y0}
              width={GROUND_EXTENT.x1 - GROUND_EXTENT.x0}
              height={GROUND_EXTENT.y1 - GROUND_EXTENT.y0}
            >
              <rect
                x={GROUND_EXTENT.x0}
                y={GROUND_EXTENT.y0}
                width={GROUND_EXTENT.x1 - GROUND_EXTENT.x0}
                height={GROUND_EXTENT.y1 - GROUND_EXTENT.y0}
                fill={`url(#${uid}-ground-fade)`}
              />
            </mask>
            <marker id={`${uid}-arrow`} viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M0 1 L9 5 L0 9 Z" className="tm-arrow" />
            </marker>
          </defs>

          <rect width={frame.w} height={frame.h} className="tm-hit" onClick={clearSelection} />
          <g transform={`translate(0 ${view.depth.toFixed(2)})`} pointerEvents="none">
            <g transform={matrix}>
              <image
                href={groundTexture}
                x={GROUND_EXTENT.x0}
                y={GROUND_EXTENT.y0}
                width={GROUND_EXTENT.x1 - GROUND_EXTENT.x0}
                height={GROUND_EXTENT.y1 - GROUND_EXTENT.y0}
                preserveAspectRatio="none"
                className="tm-ground"
                mask={`url(#${uid}-ground-mask)`}
                opacity={0.25 + 0.4 * cam.tilt}
              />
            </g>
          </g>
          <rect width={frame.w} height={frame.h} fill={`url(#${uid}-vignette)`} pointerEvents="none" />
          <use
            href={`#${uid}-land`}
            transform={`translate(${(view.depth * 0.35).toFixed(2)} ${(view.depth * 1.4).toFixed(2)}) ${matrix}`}
            className="tm-shadow"
            pointerEvents="none"
          />
          <g pointerEvents="none">{walls}</g>

          <g transform={matrix}>
            <g clipPath={`url(#${uid}-clip)`}>
              <Surface {...surfaceProps} zoneList={zones} />
            </g>
            <use href={`#${uid}-land`} className="tm-rim" pointerEvents="none" />
          </g>

          {showLift && liftedOrg && (
            <>
              <use href={`#${uid}-land`} transform={matrix} className="tm-dim" opacity={0.42 * cam.lift} pointerEvents="none" />
              <g pointerEvents="none">{liftWalls}</g>
              <g transform={`translate(0 ${(-view.lift).toFixed(2)})`}>
                <g transform={matrix}>
                  <g clipPath={`url(#${uid}-org)`}>
                    <Surface {...surfaceProps} zoneList={orgGeometries[liftedOrg].zones} />
                  </g>
                  <path d={orgGeometries[liftedOrg].boundaryPath} className={`tm-lift-rim tm-org-${orgByCode[liftedOrg].slug}`} pointerEvents="none" />
                </g>
              </g>
            </>
          )}

          <g pointerEvents="none">
            {depsToDraw.map((dep) => {
              const from = assetById.get(dep.from)!
              const to = assetById.get(dep.to)!
              const [x1, y1] = screenOf(from.x, from.y, from.org)
              const [x2, y2] = screenOf(to.x, to.y, to.org)
              const length = Math.hypot(x2 - x1, y2 - y1)
              const rise = Math.min(80, length * 0.32) * cam.tilt + length * 0.08
              const active = selectedAssetId !== null && (dep.from === selectedAssetId || downstream.has(dep.from)) && downstream.has(dep.to)
              const d = `M${x1.toFixed(1)} ${y1.toFixed(1)} Q${((x1 + x2) / 2).toFixed(1)} ${((y1 + y2) / 2 - rise).toFixed(1)} ${x2.toFixed(1)} ${y2.toFixed(1)}`
              return (
                <g key={`${dep.from}-${dep.to}`} className={`tm-dep tm-dep-${dep.kind} ${active ? "is-active" : ""}`}>
                  <path d={d} className="tm-dep-casing" />
                  <path d={d} className="tm-dep-line" markerEnd={`url(#${uid}-arrow)`} />
                </g>
              )
            })}
          </g>
        </svg>
      )}

      {/* Labels and markers (screen space) */}
      {view && (
        <div className="tm-overlay">
          {scope === "organisation" &&
            !selection.org &&
            k < 1.8 &&
            organisations.map((org) => {
              const [x, y] = screenOf(...orgGeometries[org.code].anchor, null)
              const Icon = orgIcon[org.code]
              const critical = assets.filter((a) => a.org === org.code && a.level === "Critical").length
              return (
                <button
                  key={org.code}
                  data-map-ui
                  className={`tm-org-tag tm-org-${org.slug}`}
                  style={{ transform: `translate3d(${x}px, ${y}px, 0) translate(-50%, -50%)`, opacity: 1 - smooth(1.45, 1.8, k) }}
                  onClick={() => setSelection({ org: org.code, zone: null })}
                >
                  <Icon size={14} />
                  <span className="tm-org-tag-name">{org.code}</span>
                  <span className="tm-org-tag-meta">
                    {org.totalAssets} assets{critical ? ` · ${critical} critical` : ""}
                  </span>
                </button>
              )
            })}

          {zones.map((zone) => {
            const pinned = zone.id === selection.zone || (selection.org !== null && zone.org === selection.org)
            const opacity = pinned ? 1 : layers.zones ? smooth(1.4, 1.7, k) : 0
            if (opacity < 0.02 || zone.id === selection.zone) return null
            const [x, y] = screenOf(zone.centroid[0], zone.centroid[1] + 16, zone.org)
            return (
              <span key={zone.id} className="tm-zone-label" style={{ transform: `translate3d(${x}px, ${y}px, 0) translate(-50%, -50%)`, opacity }}>
                {zone.name}
              </span>
            )
          })}

          {hovered && k < 1.4 && (
            <span
              className="tm-tooltip"
              style={{ transform: `translate3d(${screenOf(hovered.centroid[0], hovered.centroid[1], hovered.org).join("px, ")}px, 0) translate(-50%, -50%)` }}
            >
              <strong>{hovered.name}</strong>
              <span>{hovered.org ?? "Unassigned land"}</span>
            </span>
          )}

          {visibleAssets.map((asset) => {
            const [x, y] = screenOf(asset.x, asset.y, asset.org)
            const Icon = orgIcon[asset.org]
            const selected = asset.id === selectedAssetId
            const showLabel = selected || scope === "asset" || mode === "network" || k >= 2.1 || selection.org === asset.org
            return (
              <button
                key={asset.id}
                data-map-ui
                data-risk={asset.level.toLowerCase()}
                className={`tm-marker ${selected ? "is-selected" : ""} ${downstream.has(asset.id) ? "is-downstream" : ""}`}
                style={{ transform: `translate3d(${x}px, ${y}px, 0)` }}
                onClick={() => onAssetSelect?.(asset)}
                aria-label={`${asset.id} ${asset.name}, ${asset.level} risk`}
              >
                <span className="tm-marker-ground" />
                <span className="tm-marker-stem" />
                <span className="tm-marker-head">
                  <Icon size={12} strokeWidth={2} />
                </span>
                {showLabel && (
                  <span className="tm-marker-label">
                    <strong>{asset.id}</strong>
                    {(k >= 2.1 || selected || scope === "asset") && <span>{asset.name}</span>}
                  </span>
                )}
              </button>
            )
          })}

          {zoneCard && (
            <ZoneCard
              zone={zoneCard}
              position={screenOf(zoneCard.centroid[0], zoneCard.centroid[1], zoneCard.org)}
              frame={frame}
              onClose={() => setSelection({ org: selection.org, zone: null })}
              onAsset={(asset) => onAssetSelect?.(asset)}
            />
          )}
        </div>
      )}

      {/* Region-fit and unobstructed areas, positioned by --tm-* custom properties */}
      <div ref={fitRef} className="tm-fit" aria-hidden="true" />
      <div ref={safeRef} className="tm-safe">
        <div className="tm-top">
          <div className="tm-toolbar" data-map-ui>
            <div className="tm-segment">
              <button className={mode === "terrain" ? "is-active" : ""} onClick={() => setMode("terrain")}>
                <MapIcon size={14} /> Terrain
              </button>
              <button className={mode === "network" ? "is-active" : ""} onClick={() => setMode("network")}>
                <Network size={14} /> Network
              </button>
            </div>
            <div className="tm-segment tm-scope">
              <button className={scope === "organisation" ? "is-active" : ""} onClick={() => setScope("organisation")}>
                Organisations
              </button>
              <button className={scope === "asset" ? "is-active" : ""} onClick={() => setScope("asset")}>
                Assets
              </button>
            </div>
          </div>

          <div className="tm-controls" data-map-ui>
            <div className="tm-layers">
              <button className={`tm-icon-button ${layersOpen ? "is-active" : ""}`} onClick={() => setLayersOpen((v) => !v)} title="Map layers" aria-expanded={layersOpen}>
                <Layers3 size={16} />
              </button>
              {layersOpen && (
                <div className="tm-layer-menu">
                  <div className="tm-menu-title">Map layers</div>
                  {LAYER_LABELS.map(([key, label]) => (
                    <button key={key} onClick={() => setLayers((prev) => ({ ...prev, [key]: !prev[key] }))}>
                      <span className={`tm-check ${layers[key] ? "is-on" : ""}`}>{layers[key] && <Check size={11} strokeWidth={3} />}</span>
                      {label}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <div className="tm-zoom">
              <button className="tm-icon-button" title="Zoom in (+)" onClick={() => zoomAtCenter(1.6)}>
                <Plus size={16} />
              </button>
              <button className="tm-icon-button" title="Zoom out (−)" onClick={() => zoomAtCenter(1 / 1.6)}>
                <Minus size={16} />
              </button>
              <button className="tm-icon-button" title="Fit region (0)" onClick={fitAll}>
                <Maximize2 size={15} />
              </button>
            </div>
          </div>
        </div>

        <div className={`tm-hint ${hint ? "is-visible" : ""}`}>Hold Ctrl or ⌘ and scroll to zoom · drag to pan</div>

        <div className="tm-bottom">
          <div className="tm-legend" data-map-ui>
            <span>
              <i className="tm-legend-solid" /> Confirmed dependency
            </span>
            <span>
              <i className="tm-legend-dashed" /> Potential cascade
            </span>
            <span className="tm-legend-risk">
              <i data-risk="critical" />
              <i data-risk="high" />
              <i data-risk="medium" />
              <i data-risk="low" /> Risk
            </span>
          </div>
          <div className="tm-footer" data-map-ui>
            <div className="tm-segment tm-orgs">
              <button className={!selection.org ? "is-active" : ""} onClick={() => setSelection({ org: null, zone: null })}>
                All
              </button>
              {organisations.map((org) => (
                <button key={org.code} className={selection.org === org.code ? "is-active" : ""} onClick={() => setSelection({ org: org.code, zone: null })}>
                  <span className={`tm-dot tm-org-${org.slug}`} />
                  {org.code}
                </button>
              ))}
            </div>
            <div className="tm-segment tm-detail">
              <span className="tm-segment-label">Detail</span>
              {(
                [
                  ["Region", 1],
                  ["Zones", 1.7],
                  ["Sites", 2.8],
                ] as const
              ).map(([label, level]) => (
                <button key={label} className={detailLevel === label ? "is-active" : ""} onClick={() => setDetail(level)}>
                  {label}
                </button>
              ))}
            </div>
          </div>
          <div className="tm-disclaimer">Synthetic terrain · illustrative layout, not real geography</div>
        </div>
      </div>
    </div>
  )
}

interface ZoneCardProps {
  zone: Zone
  position: Pt
  frame: Frame
  onClose: () => void
  onAsset: (asset: Asset) => void
}

function ZoneCard({ zone, position, frame, onClose, onAsset }: ZoneCardProps) {
  const zoneAssets = assets.filter((asset) => asset.zone === zone.id)
  const width = 264
  const left = Math.max(frame.sx + 8, Math.min(frame.sx + frame.sw - width - 56, position[0] + 28))
  const top = Math.max(frame.sy + 52, Math.min(frame.sy + frame.sh - 250, position[1] - 60))
  const org = zone.org ? orgByCode[zone.org] : null
  const style: CSSProperties = { left, top, width }
  return (
    <div className="tm-card" style={style} data-map-ui>
      <div className="tm-card-head">
        <div>
          <span className="tm-card-eyebrow">{zone.kind}</span>
          <strong>{zone.name}</strong>
        </div>
        <button className="tm-icon-button tm-card-close" onClick={onClose} aria-label="Close zone details">
          <X size={14} />
        </button>
      </div>
      <div className="tm-card-org">
        {org ? (
          <>
            <span className={`tm-dot tm-org-${org.slug}`} />
            {org.code} · {org.name}
          </>
        ) : (
          "Unassigned land · no monitored operator"
        )}
      </div>
      {zoneAssets.length ? (
        <div className="tm-card-assets">
          {zoneAssets.map((asset) => (
            <button key={asset.id} onClick={() => onAsset(asset)} data-risk={asset.level.toLowerCase()}>
              <i />
              <span>
                <strong>{asset.id}</strong> {asset.name}
              </span>
              <em>{asset.risk.toFixed(1)}</em>
            </button>
          ))}
        </div>
      ) : (
        <p className="tm-card-empty">No monitored assets in this zone.</p>
      )}
    </div>
  )
}
