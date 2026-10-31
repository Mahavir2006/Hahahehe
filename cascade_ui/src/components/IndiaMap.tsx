import { memo, useMemo, useState, useRef, type PointerEvent as ReactPointerEvent } from "react"
import {
  Shield,
  AlertTriangle,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Lock,
  CheckCircle2,
  Radio,
  Zap,
  Activity,
  Flame,
  ArrowRight,
} from "lucide-react"
import {
  assets,
  assetById,
  dependencies,
  downstreamOf,
  type Asset,
} from "../data/infrastructure"

// Authentic polygon boundary of India (coordinate space 0..1000 width, 0..850 height)
export const INDIA_BOUNDARY: [number, number][] = [
  // Siachen & Karakoram
  [380, 52], [405, 62], [425, 76], [445, 102], [460, 126], [445, 150], [465, 160], [475, 180],
  // Aksai Chin & Ladakh eastern border
  [485, 192], [495, 215],
  // Himachal / Uttarakhand border with Tibet/Nepal
  [515, 230], [540, 250], [575, 275],
  // Nepal northern border to Sikkim
  [615, 285], [645, 290], [675, 280], [685, 260], [700, 280],
  // Bhutan border
  [715, 280], [745, 275],
  // Arunachal Pradesh & Himalayan border
  [765, 260], [805, 240], [840, 245], [865, 265], [855, 290],
  // Nagaland / Manipur / Myanmar border
  [835, 315], [820, 360], [810, 400], [805, 435],
  // Mizoram / Tripura south
  [785, 445], [775, 415], [765, 390],
  // Meghalaya & Bangladesh border
  [745, 375], [720, 335], [690, 335],
  // Siliguri corridor & West Bengal
  [660, 325], [675, 360], [700, 395],
  // Ganges delta / Kolkata / Sundarbans
  [690, 430], [670, 445],
  // Odisha coast (Bay of Bengal)
  [645, 470], [615, 505], [580, 550],
  // Andhra Pradesh coast
  [555, 590], [525, 630],
  // Tamil Nadu coast
  [505, 665], [490, 715],
  // Southern tip (Kanyakumari)
  [455, 770], [445, 755],
  // Kerala (Malabar coast)
  [435, 700], [420, 645],
  // Karnataka & Goa coast
  [400, 595], [375, 555], [355, 515],
  // Maharashtra coast (Mumbai)
  [335, 465], [320, 425], [310, 415],
  // Gujarat (Gulf of Khambhat & Kathiawar/Saurashtra peninsula)
  [290, 405], [260, 415], [225, 410], [215, 380], [240, 360],
  // Gulf of Kutch & Rann of Kutch
  [205, 345], [190, 320], [230, 300],
  // Rajasthan (Thar Desert / Pakistan border)
  [250, 290], [270, 250], [295, 220],
  // Punjab / Jammu border with Pakistan
  [305, 200], [295, 170], [280, 130], [300, 95], [330, 75], [360, 55]
]

// Convert polygon to SVG path string
export const INDIA_PATH_D = INDIA_BOUNDARY.reduce(
  (acc, [x, y], i) => (i === 0 ? `M ${x} ${y}` : `${acc} L ${x} ${y}`),
  ""
) + " Z"

function isPointInPoly(x: number, y: number, poly: [number, number][]): boolean {
  let inside = false
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const xi = poly[i][0]
    const yi = poly[i][1]
    const xj = poly[j][0]
    const yj = poly[j][1]
    const intersect = yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi
    if (intersect) inside = !inside
  }
  return inside
}

// Compute elevation heuristic for topographic shading (0.0 = low plains/coasts, 1.0 = Himalayas)
function getElevation(x: number, y: number): number {
  if (y < 260) {
    const distToNorth = Math.max(0, (260 - y) / 210)
    return Math.min(1.0, 0.45 + distToNorth * 0.55)
  }
  if (x > 700 && y < 350) return 0.65
  if (x > 340 && x < 420 && y > 450 && y < 700) return 0.55
  if (x > 380 && x < 580 && y > 380 && y < 650) return 0.38
  return 0.2
}

interface Dot {
  x: number
  y: number
  inside: boolean
  elevation: number
}

function generateDotMatrix(): Dot[] {
  const dots: Dot[] = []
  const step = 11.5
  for (let y = 35; y <= 790; y += step) {
    for (let x = 160; x <= 880; x += step) {
      const inside = isPointInPoly(x, y, INDIA_BOUNDARY)
      if (inside) {
        dots.push({
          x,
          y,
          inside: true,
          elevation: getElevation(x, y),
        })
      } else {
        if ((Math.round(x / step) + Math.round(y / step)) % 2 === 0 && Math.random() < 0.22) {
          dots.push({
            x,
            y,
            inside: false,
            elevation: 0,
          })
        }
      }
    }
  }
  return dots
}

// Regional support linkages (Which region supplies / supports which region)
export interface RegionalSupportFlow {
  id: string
  fromRegion: string
  toRegion: string
  fromCoords: [number, number]
  toCoords: [number, number]
  capacityMW: string
  label: string
  color: string
}

export const REGIONAL_SUPPORT_FLOWS: RegionalSupportFlow[] = [
  {
    id: "RS-1",
    fromRegion: "Northern Hydro Corridor (Tehri)",
    toRegion: "National Capital Grid (New Delhi)",
    fromCoords: [438, 205],
    toCoords: [410, 265],
    capacityMW: "2,400 MW",
    label: "Tehri Hydro Generation Feed",
    color: "#42b98b",
  },
  {
    id: "RS-2",
    fromRegion: "Western Protection Relay (Bhopal)",
    toRegion: "Central Switching (Agra 400kV)",
    fromCoords: [430, 415],
    toCoords: [425, 310],
    capacityMW: "1,800 MW",
    label: "Inter-State Synchronous Tie-Line",
    color: "#28b8c5",
  },
  {
    id: "RS-3",
    fromRegion: "Eastern Hydro Hub (Hirakud)",
    toRegion: "Ganga Basin Pumping (Varanasi)",
    fromCoords: [625, 440],
    toCoords: [565, 360],
    capacityMW: "850 MLD",
    label: "Hydraulic Balance & Telemetry",
    color: "#38bdf8",
  },
  {
    id: "RS-4",
    fromRegion: "Rajasthan Solar Belt (Jaipur)",
    toRegion: "Delhi NCR Pumping Works",
    fromCoords: [350, 310],
    toCoords: [418, 275],
    capacityMW: "920 MW",
    label: "Clean Feeder Priority Corridor",
    color: "#eab308",
  },
]

// Attack Vector types similar to Radware
export type AttackCategory = "web" | "ddos" | "scada" | "scanners" | "support"

interface IndiaMapProps {
  selectedAssetId?: string | null
  onAssetSelect?: (asset: Asset) => void
  onBannerAction?: (asset: Asset) => void
  liveAttackActive?: boolean
  isNodeIsolated?: boolean
  onToggleIsolation?: () => void
  className?: string
}

export const IndiaMap = memo(function IndiaMap({
  selectedAssetId,
  onAssetSelect,
  onBannerAction,
  liveAttackActive = false,
  isNodeIsolated = false,
  onToggleIsolation,
  className = "",
}: IndiaMapProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [scale, setScale] = useState(1.0)
  const [offset, setOffset] = useState({ x: 0, y: 0 })
  const [isDragging, setIsDragging] = useState(false)
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 })
  const [hoveredAsset, setHoveredAsset] = useState<Asset | null>(null)
  const [bannerDismissed, setBannerDismissed] = useState(false)

  // Visible Attack Categories Filter (Radware-style toggles)
  const [activeCategories, setActiveCategories] = useState<Record<AttackCategory, boolean>>({
    web: true,
    ddos: true,
    scada: true,
    scanners: true,
    support: true,
  })

  const toggleCategory = (cat: AttackCategory) => {
    setActiveCategories((prev) => ({ ...prev, [cat]: !prev[cat] }))
  }

  // Generate dots once
  const dots = useMemo(() => generateDotMatrix(), [])

  // Downstream impact calculation
  const downstream = useMemo(
    () => (selectedAssetId ? downstreamOf(selectedAssetId) : new Set<string>()),
    [selectedAssetId]
  )

  // Drag pan handlers
  const handlePointerDown = (e: ReactPointerEvent) => {
    if ((e.target as HTMLElement).closest("[data-interactive]")) return
    setIsDragging(true)
    setDragStart({ x: e.clientX - offset.x, y: e.clientY - offset.y })
    ;(e.target as HTMLElement).setPointerCapture(e.pointerId)
  }

  const handlePointerMove = (e: ReactPointerEvent) => {
    if (!isDragging) return
    setOffset({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    })
  }

  const handlePointerUp = (e: ReactPointerEvent) => {
    setIsDragging(false)
    try {
      ;(e.target as HTMLElement).releasePointerCapture(e.pointerId)
    } catch {}
  }

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault()
    const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92
    setScale((prev) => Math.max(0.7, Math.min(2.5, prev * zoomFactor)))
  }

  const resetView = () => {
    setScale(1.0)
    setOffset({ x: 0, y: 0 })
  }

  const criticalAsset = useMemo(() => assets.find((a) => a.id === "PG-003") || assets[0], [])

  return (
    <div
      ref={containerRef}
      className={`india-map-container ${className}`}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerUp}
      onWheel={handleWheel}
      style={{ touchAction: "none" }}
    >
      {/* Background ambient radial glows */}
      <div className="india-map-ambient-glow" />
      <div className="india-map-ambient-glow-himalayas" />

      {/* Main SVG Map Canvas */}
      <svg
        className="india-map-svg"
        viewBox="0 0 1000 840"
        preserveAspectRatio="xMidYMid meet"
        style={{
          transform: `translate(${offset.x}px, ${offset.y}px) scale(${scale})`,
          transformOrigin: "center center",
          transition: isDragging ? "none" : "transform 150ms ease-out",
        }}
      >
        <defs>
          {/* Glowing filters */}
          <filter id="india-dot-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur in="SourceGraphic" stdDeviation="1.8" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          <filter id="india-node-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur in="SourceGraphic" stdDeviation="3.5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          <filter id="india-laser-glow" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          {/* Gradients */}
          <linearGradient id="india-contour-grad" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#42b98b" stopOpacity="0.8" />
            <stop offset="35%" stopColor="#28b8c5" stopOpacity="0.6" />
            <stop offset="70%" stopColor="#1e8591" stopOpacity="0.4" />
            <stop offset="100%" stopColor="#12515b" stopOpacity="0.2" />
          </linearGradient>

          <radialGradient id="india-pulse-grad" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#e45b5b" stopOpacity="0.8" />
            <stop offset="50%" stopColor="#e45b5b" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#e45b5b" stopOpacity="0" />
          </radialGradient>

          <radialGradient id="shield-grad" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#42b98b" stopOpacity="0.75" />
            <stop offset="70%" stopColor="#28b8c5" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#12515b" stopOpacity="0" />
          </radialGradient>

          {/* Laser motion gradients */}
          <linearGradient id="attack-laser-grad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#e45b5b" stopOpacity="0" />
            <stop offset="70%" stopColor="#e45b5b" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#ffffff" stopOpacity="1" />
          </linearGradient>

          <linearGradient id="support-energy-grad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#42b98b" stopOpacity="0.1" />
            <stop offset="70%" stopColor="#42b98b" stopOpacity="0.85" />
            <stop offset="100%" stopColor="#a7f3d0" stopOpacity="1" />
          </linearGradient>

          {/* Arrow markers */}
          <marker id="arrow-attack" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#e45b5b" />
          </marker>
          <marker id="arrow-support" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 10 5 L 0 9 z" fill="#42b98b" />
          </marker>
        </defs>

        {/* India Landmass Outline (Subtle ambient stroke & glow) */}
        <path
          d={INDIA_PATH_D}
          fill="rgba(8, 22, 28, 0.45)"
          stroke="rgba(40, 184, 197, 0.22)"
          strokeWidth="1.2"
          strokeLinejoin="round"
        />

        {/* Coordinate scan grid lines (matching reference image) */}
        <g stroke="rgba(40, 184, 197, 0.04)" strokeWidth="0.8" strokeDasharray="3 6">
          <line x1="100" y1="200" x2="900" y2="200" />
          <line x1="100" y1="360" x2="900" y2="360" />
          <line x1="100" y1="520" x2="900" y2="520" />
          <line x1="100" y1="680" x2="900" y2="680" />
          <line x1="300" y1="50" x2="300" y2="800" />
          <line x1="500" y1="50" x2="500" y2="800" />
          <line x1="700" y1="50" x2="700" y2="800" />
        </g>

        {/* Topographic Point Cloud Matrix */}
        <g className="india-dots-layer">
          {dots.map((dot, i) => {
            if (!dot.inside) {
              return (
                <circle
                  key={`bg-${i}`}
                  cx={dot.x}
                  cy={dot.y}
                  r="0.9"
                  fill="rgba(40, 184, 197, 0.12)"
                />
              )
            }

            let color = "rgba(40, 184, 197, 0.55)"
            let radius = 1.3
            if (dot.elevation > 0.65) {
              color = "rgba(228, 200, 90, 0.88)"
              radius = 1.8
            } else if (dot.elevation > 0.45) {
              color = "rgba(66, 185, 139, 0.78)"
              radius = 1.6
            } else if (dot.elevation > 0.3) {
              color = "rgba(40, 184, 197, 0.65)"
              radius = 1.4
            }

            return (
              <circle
                key={`dot-${i}`}
                cx={dot.x}
                cy={dot.y}
                r={radius}
                fill={color}
              />
            )
          })}
        </g>

        {/* 1. REGIONAL SUPPORT FLOW CONDUITS (Radware-style regional support arrows) */}
        {activeCategories.support && (
          <g className="india-regional-support-flows">
            {REGIONAL_SUPPORT_FLOWS.map((flow) => {
              const [x1, y1] = flow.fromCoords
              const [x2, y2] = flow.toCoords
              const midX = (x1 + x2) / 2
              const midY = (y1 + y2) / 2 - 35
              const pathD = `M ${x1} ${y1} Q ${midX} ${midY} ${x2} ${y2}`

              return (
                <g key={flow.id}>
                  {/* Base path */}
                  <path
                    d={pathD}
                    fill="none"
                    stroke={flow.color}
                    strokeWidth="1.6"
                    strokeOpacity="0.45"
                    strokeDasharray="4 3"
                  />
                  {/* Moving pulse photon / arrowhead */}
                  <g>
                    <circle r="3.5" fill={flow.color} filter="url(#india-laser-glow)">
                      <animateMotion path={pathD} dur="3s" repeatCount="indefinite" />
                    </circle>
                    <polygon points="-3,-2 3,0 -3,2" fill="#ffffff">
                      <animateMotion path={pathD} dur="3s" repeatCount="indefinite" rotate="auto" />
                    </polygon>
                  </g>
                </g>
              )
            })}
          </g>
        )}

        {/* 2. STANDARD INFRASTRUCTURE DEPENDENCY ARCS */}
        <g className="india-dependency-arcs">
          {dependencies.map((dep, idx) => {
            const from = assetById.get(dep.from)
            const to = assetById.get(dep.to)
            if (!from || !to) return null

            const isPathActive =
              selectedAssetId === dep.from ||
              selectedAssetId === dep.to ||
              downstream.has(dep.from) ||
              downstream.has(dep.to)

            const dx = to.x - from.x
            const dy = to.y - from.y
            const dist = Math.hypot(dx, dy)
            const midX = (from.x + to.x) / 2
            const midY = (from.y + to.y) / 2 - Math.min(45, dist * 0.25)
            const pathD = `M ${from.x} ${from.y} Q ${midX} ${midY} ${to.x} ${to.y}`

            return (
              <g key={`dep-${idx}`}>
                <path
                  d={pathD}
                  fill="none"
                  stroke={isPathActive ? "#28b8c5" : "rgba(40, 184, 197, 0.2)"}
                  strokeWidth={isPathActive ? "1.8" : "1.0"}
                  strokeDasharray={dep.kind === "potential" ? "4 4" : "none"}
                />
                {isPathActive && (
                  <circle r="2.5" fill="#28b8c5" filter="url(#india-node-glow)">
                    <animateMotion path={pathD} dur="2.8s" repeatCount="indefinite" />
                  </circle>
                )}
              </g>
            )
          })}
        </g>

        {/* 3. RADWARE LIVE MOTION ATTACK SIMULATION (Active when liveAttackActive is TRUE) */}
        {liveAttackActive && (
          <g className="india-live-attack-motion">
            {/* Attacker Origin Cluster (Offshore botnet / foreign ingress) */}
            <g transform="translate(180, 140)">
              <circle r="12" fill="rgba(228, 91, 91, 0.2)" />
              <circle r="5" fill="#e45b5b" filter="url(#india-laser-glow)" />
              <text x="14" y="4" fill="#ff7676" fontSize="10" fontWeight="700">
                APT-41 CLUSTER (194.26.29.112)
              </text>
            </g>

            {/* Inbound Attack Vector: Attacker -> PG-003 Northern Grid Gateway */}
            <path
              d="M 180 140 Q 280 180 410 265"
              fill="none"
              stroke="#e45b5b"
              strokeWidth="2.4"
              strokeDasharray="6 3"
              markerEnd="url(#arrow-attack)"
              filter="url(#india-laser-glow)"
            />

            {/* Moving Laser Projectiles along inbound attack trajectory */}
            <g>
              <circle r="4.5" fill="#ffffff" filter="url(#india-laser-glow)">
                <animateMotion path="M 180 140 Q 280 180 410 265" dur="1.2s" repeatCount="indefinite" />
              </circle>
              <circle r="3" fill="#e45b5b">
                <animateMotion path="M 180 140 Q 280 180 410 265" dur="1.2s" repeatCount="indefinite" />
              </circle>
            </g>

            {/* Cascading Lateral Threat Propagation (PG-003 -> PG-001 Agra -> JB-014 Water -> AI-009 Hospital) */}
            {!isNodeIsolated ? (
              <g className="india-cascading-propagation">
                {/* Vector 1: PG-003 -> PG-001 (Agra Substation) */}
                <path
                  d="M 410 265 Q 418 285 425 310"
                  fill="none"
                  stroke="#e45b5b"
                  strokeWidth="2.2"
                  filter="url(#india-laser-glow)"
                />
                <circle r="3.2" fill="#ff3333">
                  <animateMotion path="M 410 265 Q 418 285 425 310" dur="1.5s" repeatCount="indefinite" />
                </circle>

                {/* Vector 2: PG-001 -> JB-014 (Yamuna Water Pump) */}
                <path
                  d="M 425 310 Q 420 292 418 275"
                  fill="none"
                  stroke="#e99a43"
                  strokeWidth="2.0"
                  strokeDasharray="3 3"
                />
                <circle r="3" fill="#e99a43">
                  <animateMotion path="M 425 310 Q 420 292 418 275" dur="1.8s" repeatCount="indefinite" />
                </circle>

                {/* Vector 3: JB-014 -> AI-009 (AIIMS Trauma Power) */}
                <path
                  d="M 418 275 L 413 278"
                  fill="none"
                  stroke="#e45b5b"
                  strokeWidth="2.0"
                />
              </g>
            ) : (
              /* When ISOLATED: Show emerald containment barrier & severed state */
              <g className="india-isolated-barrier">
                {/* Hexagonal Shield over PG-003 */}
                <g transform="translate(410, 265)">
                  <polygon
                    points="0,-24 21,-12 21,12 0,24 -21,12 -21,-12"
                    fill="url(#shield-grad)"
                    stroke="#42b98b"
                    strokeWidth="2.2"
                    filter="url(#india-node-glow)"
                  >
                    <animateTransform
                      attributeName="transform"
                      type="rotate"
                      from="0"
                      to="360"
                      dur="16s"
                      repeatCount="indefinite"
                    />
                  </polygon>
                  <circle r="14" fill="none" stroke="#42b98b" strokeWidth="1.5" strokeDasharray="3 3" />
                  <text y="38" textAnchor="middle" fill="#42b98b" fontSize="10" fontWeight="800">
                    ISOLATED & DEFENDED
                  </text>
                </g>

                {/* Severed Indicator */}
                <g transform="translate(420, 290)">
                  <rect x="-35" y="-10" width="70" height="20" rx="4" fill="#0b1118" stroke="#42b98b" strokeWidth="1" />
                  <text x="0" y="3" textAnchor="middle" fill="#42b98b" fontSize="9" fontWeight="700">
                    ✕ CASCADE SEVERED
                  </text>
                </g>
              </g>
            )}
          </g>
        )}

        {/* 4. PULSATING RADAR RINGS FOR CRITICAL ASSETS */}
        <g className="india-radar-pulses">
          {assets
            .filter((a) => a.level === "Critical" || (liveAttackActive && a.id === "PG-003"))
            .map((asset) => (
              <g key={`pulse-${asset.id}`} transform={`translate(${asset.x}, ${asset.y})`}>
                <circle r="18" fill="url(#india-pulse-grad)">
                  <animate attributeName="r" values="10;34;46" dur="2.4s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.85;0.3;0" dur="2.4s" repeatCount="indefinite" />
                </circle>
                <circle r="12" fill="none" stroke="#e45b5b" strokeWidth="1" strokeDasharray="2 2">
                  <animateTransform attributeName="transform" type="rotate" from="0" to="360" dur="10s" repeatCount="indefinite" />
                </circle>
              </g>
            ))}
        </g>

        {/* 5. INTERACTIVE ASSET NODES ON THE MAP */}
        <g className="india-assets-layer">
          {assets.map((asset) => {
            const isSelected = selectedAssetId === asset.id
            const isCritical = asset.level === "Critical"
            const isHigh = asset.level === "High"

            let badgeColor = "#42b98b"
            let badgeBg = "rgba(66, 185, 139, 0.2)"
            let badgeBorder = "#42b98b"

            if (isCritical || (liveAttackActive && asset.id === "PG-003")) {
              badgeColor = "#e45b5b"
              badgeBg = "rgba(228, 91, 91, 0.32)"
              badgeBorder = "#e45b5b"
            } else if (isHigh) {
              badgeColor = "#e99a43"
              badgeBg = "rgba(233, 154, 67, 0.25)"
              badgeBorder = "#e99a43"
            }

            return (
              <g
                key={asset.id}
                data-interactive="true"
                transform={`translate(${asset.x}, ${asset.y})`}
                className={`india-asset-node ${isSelected ? "is-selected" : ""}`}
                onClick={() => onAssetSelect?.(asset)}
                onMouseEnter={() => setHoveredAsset(asset)}
                onMouseLeave={() => setHoveredAsset(null)}
                style={{ cursor: "pointer" }}
              >
                {/* Outer halo */}
                {(isSelected || hoveredAsset?.id === asset.id) && (
                  <circle
                    r="16"
                    fill="none"
                    stroke={badgeColor}
                    strokeWidth="1.5"
                    strokeDasharray="3 3"
                    className="india-node-ring-spin"
                  />
                )}

                {/* Main badge node */}
                <circle
                  r={isSelected ? "9" : "7.5"}
                  fill={badgeBg}
                  stroke={badgeBorder}
                  strokeWidth={isSelected ? "2.2" : "1.6"}
                  filter={isCritical || isSelected ? "url(#india-node-glow)" : undefined}
                />

                {/* Inner dot */}
                {isCritical ? (
                  <circle r="3.2" fill="#e45b5b" />
                ) : isHigh ? (
                  <circle r="2.8" fill="#e99a43" />
                ) : (
                  <circle r="2.4" fill="#42b98b" />
                )}

                {/* Node label */}
                <text
                  x="12"
                  y="4"
                  fill={isSelected ? "#ffffff" : "rgba(231, 237, 243, 0.88)"}
                  fontSize="10"
                  fontFamily="Inter, system-ui, sans-serif"
                  fontWeight={isSelected ? "650" : "500"}
                  letterSpacing="0.02em"
                  className="india-node-text"
                >
                  {asset.location}
                </text>
              </g>
            )
          })}
        </g>
      </svg>

      {/* RADWARE-STYLE ATTACK TYPES & REGION CONDUIT TOGGLE LEGEND (Top-Left of Map) */}
      <div data-interactive="true" className="radware-attack-types-legend glass-panel">
        <div className="text-[10px] uppercase font-bold tracking-wider text-[#9aaab8] mb-2 flex items-center justify-between">
          <span>Vectors &amp; Conduits</span>
          <span className="text-[9px] text-[#28b8c5]">Live Motion</span>
        </div>
        <div className="flex flex-col gap-1.5">
          <button
            onClick={() => toggleCategory("scada")}
            className={`radware-type-toggle ${activeCategories.scada ? "is-active text-[#00f5d4]" : "opacity-40"}`}
          >
            <span className="w-2 h-2 rounded-full bg-[#00f5d4] shadow-[0_0_6px_#00f5d4]" />
            <span>SCADA &amp; Gateway Intrusions</span>
          </button>
          <button
            onClick={() => toggleCategory("web")}
            className={`radware-type-toggle ${activeCategories.web ? "is-active text-[#ff4d6d]" : "opacity-40"}`}
          >
            <span className="w-2 h-2 rounded-full bg-[#ff4d6d] shadow-[0_0_6px_#ff4d6d]" />
            <span>Web Attackers (CVE-2024-3400)</span>
          </button>
          <button
            onClick={() => toggleCategory("ddos")}
            className={`radware-type-toggle ${activeCategories.ddos ? "is-active text-[#ffb703]" : "opacity-40"}`}
          >
            <span className="w-2 h-2 rounded-full bg-[#ffb703] shadow-[0_0_6px_#ffb703]" />
            <span>DDoS &amp; Telemetry Floods</span>
          </button>
          <button
            onClick={() => toggleCategory("support")}
            className={`radware-type-toggle ${activeCategories.support ? "is-active text-[#42b98b]" : "opacity-40"}`}
          >
            <span className="w-2 h-2 rounded-full bg-[#42b98b] shadow-[0_0_6px_#42b98b]" />
            <span>Regional Power/Water Support</span>
          </button>
        </div>
      </div>

      {/* FLOATING VULNERABILITY ALERT PILL (Only when live attack is active or alert not dismissed) */}
      {!bannerDismissed && (
        <div
          data-interactive="true"
          className={`india-hud-alert-pill ${liveAttackActive ? "is-breach" : ""}`}
          onClick={() => {
            if (criticalAsset) {
              onAssetSelect?.(criticalAsset)
              onBannerAction?.(criticalAsset)
            }
          }}
        >
          <span className="india-hud-alert-icon">
            {liveAttackActive ? <Flame size={13} className="text-[#e45b5b] animate-pulse" /> : <AlertTriangle size={13} />}
          </span>
          <span className="india-hud-alert-text">
            {liveAttackActive
              ? "ATTACK DETECTED: PG-003 Northern Grid SCADA Gateway · CVE-2024-3400 Exploitation"
              : "Unsafe Connection to SCADA Gateway · New Delhi (Port 8443 WAN Exposure)"}
          </span>
          <button
            className="india-hud-alert-close"
            onClick={(e) => {
              e.stopPropagation()
              setBannerDismissed(true)
            }}
          >
            ×
          </button>
        </div>
      )}

      {/* FLOATING MAP ZOOM CONTROLS */}
      <div data-interactive="true" className="india-map-controls-pill">
        <button onClick={() => setScale((s) => Math.max(0.7, s / 1.25))} title="Zoom out" className="india-ctrl-btn">
          <ZoomOut size={13} />
        </button>
        <button onClick={resetView} title="Reset view" className="india-ctrl-btn text-xs font-semibold">
          {Math.round(scale * 100)}%
        </button>
        <button onClick={() => setScale((s) => Math.min(2.5, s * 1.25))} title="Zoom in" className="india-ctrl-btn">
          <ZoomIn size={13} />
        </button>
        <span className="india-ctrl-divider" />
        <button onClick={resetView} title="Center India" className="india-ctrl-btn">
          <Maximize2 size={13} />
        </button>
      </div>

      {/* HOVER TOOLTIP */}
      {hoveredAsset && (
        <div
          className="india-map-tooltip"
          style={{
            left: `${(hoveredAsset.x / 1000) * 100}%`,
            top: `${(hoveredAsset.y / 840) * 100}%`,
          }}
        >
          <div className="flex items-center gap-1.5">
            <span className={`india-tooltip-dot level-${hoveredAsset.level.toLowerCase()}`} />
            <strong>{hoveredAsset.name}</strong>
          </div>
          <div className="india-tooltip-sub">
            {hoveredAsset.location} · {hoveredAsset.vulnerability}
          </div>
          <div className="india-tooltip-risk">
            Risk Score: <strong>{hoveredAsset.risk}</strong> · {hoveredAsset.exposure}
          </div>
        </div>
      )}
    </div>
  )
})
