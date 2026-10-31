import { memo, useState, useMemo, useRef, type PointerEvent as ReactPointerEvent } from "react"
import {
  Shield,
  AlertTriangle,
  ZoomIn,
  ZoomOut,
  Maximize2,
  ChevronRight,
  ChevronLeft,
  X,
  ExternalLink,
  Flame,
  Radio,
  Lock,
  ArrowRight,
  Share2,
  Zap,
  Activity,
  Layers,
  Filter,
} from "lucide-react"

export interface AttackStream {
  id: string
  fromCountry: string
  toCountry: string
  fromCoords: [number, number]
  toCoords: [number, number]
  type: "volumetric" | "protocol" | "intrusion" | "scanner" | "proxy"
  label: string
  color: string
  duration: string
}

export interface RegionConduit {
  id: string
  name: string
  fromRegion: string
  toRegion: string
  fromCoords: [number, number]
  toCoords: [number, number]
  color: string
  flow: "forward" | "bidirectional"
  description: string
  telemetryRate: string
  duration: string
}

// Coordinate mapping on the cleaned world map canvas (viewBox 0 0 801 430)
export const CASCADE_ATTACKS: AttackStream[] = [
  // US -> India (Volumetric Ingress, red)
  {
    id: "att-1",
    fromCountry: "United States",
    toCountry: "India",
    fromCoords: [200, 165],
    toCoords: [645, 235],
    type: "volumetric",
    label: "Volumetric Ingress",
    color: "#ff4d6d",
    duration: "2.8s",
  },
  // US -> Iran (Edge Intrusion, cyan)
  {
    id: "att-2",
    fromCountry: "United States",
    toCountry: "Iran",
    fromCoords: [200, 165],
    toCoords: [581, 200],
    type: "intrusion",
    label: "Edge Intrusion",
    color: "#00f5d4",
    duration: "3.2s",
  },
  // China -> India (Protocol Anomaly, yellow)
  {
    id: "att-3",
    fromCountry: "China",
    toCountry: "India",
    fromCoords: [700, 185],
    toCoords: [645, 235],
    type: "protocol",
    label: "Protocol Anomaly",
    color: "#ffb703",
    duration: "2.1s",
  },
  // UK -> Australia (Perimeter Scanner, purple)
  {
    id: "att-4",
    fromCountry: "United Kingdom",
    toCountry: "Australia",
    fromCoords: [445, 120],
    toCoords: [765, 330],
    type: "scanner",
    label: "Perimeter Scanner",
    color: "#c77dff",
    duration: "3.6s",
  },
  // France -> US (Proxy Tunneling, magenta)
  {
    id: "att-5",
    fromCountry: "France",
    toCountry: "United States",
    fromCoords: [475, 145],
    toCoords: [200, 165],
    type: "proxy",
    label: "Proxy Tunneling",
    color: "#9d4edd",
    duration: "3.0s",
  },
  // Singapore -> India (Edge Intrusion, cyan)
  {
    id: "att-6",
    fromCountry: "Singapore",
    toCountry: "India",
    fromCoords: [705, 275],
    toCoords: [645, 235],
    type: "intrusion",
    label: "Edge Intrusion",
    color: "#00f5d4",
    duration: "2.4s",
  },
  // Italy -> India (Protocol Anomaly, yellow)
  {
    id: "att-7",
    fromCountry: "Italy",
    toCountry: "India",
    fromCoords: [485, 160],
    toCoords: [645, 235],
    type: "protocol",
    label: "Protocol Anomaly",
    color: "#ffb703",
    duration: "2.7s",
  },
  // Brazil -> US (Perimeter Scanner, purple)
  {
    id: "att-8",
    fromCountry: "Brazil",
    toCountry: "United States",
    fromCoords: [305, 325],
    toCoords: [200, 165],
    type: "scanner",
    label: "Perimeter Scanner",
    color: "#c77dff",
    duration: "3.4s",
  },
  // Canada -> Iran (Volumetric Ingress, red)
  {
    id: "att-9",
    fromCountry: "Canada",
    toCountry: "Iran",
    fromCoords: [195, 110],
    toCoords: [581, 200],
    type: "volumetric",
    label: "Volumetric Ingress",
    color: "#ff4d6d",
    duration: "3.1s",
  },
]

// Region-to-Region Support Conduits ("what region supports what region")
export const REGION_CONDUITS: RegionConduit[] = [
  // Transatlantic Cyber Grid: US <-> UK/EU
  {
    id: "conduit-1",
    name: "Transatlantic Resilience Grid",
    fromRegion: "United States Grid",
    toRegion: "United Kingdom / EU",
    fromCoords: [200, 165],
    toCoords: [445, 120],
    color: "#10b981",
    flow: "bidirectional",
    description: "Frequency synchronization & mutual SCADA threat defense telemetry",
    telemetryRate: "1.4 TB/s",
    duration: "3.8s",
  },
  // Gulf Energy & Power Corridor: Gulf -> India
  {
    id: "conduit-2",
    name: "Middle East Energy-Grid Corridor",
    fromRegion: "Gulf Energy Hub",
    toRegion: "India (PG-003 Master)",
    fromCoords: [560, 215],
    toCoords: [645, 235],
    color: "#00f5d4",
    flow: "forward",
    description: "Port LNG telemetry pipeline & regional power grid frequency balancing",
    telemetryRate: "820 GB/s",
    duration: "3.0s",
  },
  // Indo-Pacific Telemetry Backbone: Singapore -> India
  {
    id: "conduit-3",
    name: "Indo-Pacific Telemetry Shield",
    fromRegion: "Singapore Hub",
    toRegion: "India (PG-003 Master)",
    fromCoords: [705, 275],
    toCoords: [645, 235],
    color: "#38bdf8",
    flow: "forward",
    description: "Undersea fiber-optic SCADA backup channel with failover rerouting",
    telemetryRate: "2.1 TB/s",
    duration: "2.6s",
  },
  // Commonwealth Defense Grid: UK <-> Australia
  {
    id: "conduit-4",
    name: "Commonwealth Cyber Shield",
    fromRegion: "United Kingdom",
    toRegion: "Australia National Grid",
    fromCoords: [445, 120],
    toCoords: [765, 330],
    color: "#34d399",
    flow: "bidirectional",
    description: "Strategic OT threat intelligence sharing & frequency monitoring",
    telemetryRate: "640 GB/s",
    duration: "4.5s",
  },
  // Nordic Clean Hydro Interconnector: Scandinavia -> UK
  {
    id: "conduit-5",
    name: "Nordic Hydro-Energy Conduit",
    fromRegion: "Nordic Grid Hub",
    toRegion: "United Kingdom",
    fromCoords: [475, 90],
    toCoords: [445, 120],
    color: "#a7f3d0",
    flow: "forward",
    description: "High-voltage direct current interconnector frequency stabilization",
    telemetryRate: "490 GB/s",
    duration: "3.2s",
  },
]

interface CascadeWorldMapProps {
  onNavigateDetail?: (metric: string) => void
  onSelectCountry?: (country: string) => void
  liveAttackActive?: boolean
  selectedAssetId?: string
}

export const CascadeWorldMap = memo(function CascadeWorldMap({
  onNavigateDetail,
  onSelectCountry,
  liveAttackActive = false,
  selectedAssetId = "PG-003",
}: CascadeWorldMapProps) {
  // Zoom & Pan state
  const [scale, setScale] = useState(1.0)
  const [offset, setOffset] = useState({ x: 0, y: 0 })
  const [isDragging, setIsDragging] = useState(false)
  const dragStart = useRef({ x: 0, y: 0 })

  // Filters for attack types + regional support conduits
  const [filters, setFilters] = useState({
    volumetric: true,
    protocol: true,
    intrusion: true,
    scanner: true,
    proxy: true,
    conduits: true, // Regional support arrows
  })

  // Selected interactive hotspot modal
  const [activeHotspot, setActiveHotspot] = useState<{
    title: string
    subtitle: string
    type: "country" | "conduit"
    metrics: { label: string; value: string; color?: string }[]
    recommendation?: string
  } | null>(null)

  const toggleFilter = (type: keyof typeof filters) => {
    setFilters((prev) => ({ ...prev, [type]: !prev[type] }))
  }

  // Pointer drag controls
  const handlePointerDown = (e: ReactPointerEvent<HTMLDivElement>) => {
    const target = e.target as HTMLElement
    if (target.closest("[data-interactive='true']")) return
    setIsDragging(true)
    dragStart.current = { x: e.clientX - offset.x, y: e.clientY - offset.y }
  }

  const handlePointerMove = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (!isDragging) return
    setOffset({
      x: e.clientX - dragStart.current.x,
      y: e.clientY - dragStart.current.y,
    })
  }

  const handlePointerUp = () => setIsDragging(false)

  const handleWheel = (e: React.WheelEvent<HTMLDivElement>) => {
    e.preventDefault()
    const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92
    setScale((prev) => Math.max(0.8, Math.min(2.8, prev * zoomFactor)))
  }

  const resetView = () => {
    setScale(1.0)
    setOffset({ x: 0, y: 0 })
  }

  // Active attacks based on filter
  const visibleAttacks = useMemo(() => {
    return CASCADE_ATTACKS.filter((a) => filters[a.type])
  }, [filters])

  // Active conduits based on filter
  const visibleConduits = useMemo(() => {
    return filters.conduits ? REGION_CONDUITS : []
  }, [filters.conduits])

  return (
    <div
      className="relative w-full h-full min-h-[580px] overflow-hidden bg-[#060b11] select-none flex items-center justify-center"
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerUp}
      onWheel={handleWheel}
      style={{ touchAction: "none" }}
    >
      {/* -------------------------------------------------------------
          CLONED CLEAN WORLD MAP CANVAS & SVG OVERLAYS
          ------------------------------------------------------------- */}
      <div
        className="relative w-full h-full flex items-center justify-center"
        style={{
          transform: `translate(${offset.x}px, ${offset.y}px) scale(${scale})`,
          transformOrigin: "center center",
          transition: isDragging ? "none" : "transform 140ms ease-out",
        }}
      >
        <svg
          className="w-full h-full max-h-[820px]"
          viewBox="0 0 801 430"
          preserveAspectRatio="xMidYMid meet"
        >
          <defs>
            {/* Glow filters */}
            <filter id="cascade-laser-glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur in="SourceGraphic" stdDeviation="2" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            <filter id="cascade-conduit-glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur in="SourceGraphic" stdDeviation="2.8" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            <filter id="cascade-target-glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            {/* Directional support chevron arrow marker */}
            <marker
              id="arrow-support-forward"
              viewBox="0 0 10 10"
              refX="6"
              refY="5"
              markerWidth="5"
              markerHeight="5"
              orient="auto-start-reverse"
            >
              <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#10b981" />
            </marker>
          </defs>

          {/* 1. CLONED HIGH-TECH WORLD MAP IMAGE BACKDROP (100% Cleaned, Zero Residual Text/Boxes/Social Icons) */}
          <image
            href="/cascade_world_map.jpg"
            x="0"
            y="0"
            width="801"
            height="430"
            preserveAspectRatio="none"
            className="opacity-95"
          />

          {/* 2. REGION SUPPORT CONDUITS ("what region supports what region") */}
          <g className="cascade-region-conduits">
            {visibleConduits.map((conduit) => {
              const [x1, y1] = conduit.fromCoords
              const [x2, y2] = conduit.toCoords
              const midX = (x1 + x2) / 2
              const midY = (y1 + y2) / 2 + 18
              const pathD = `M ${x1} ${y1} Q ${midX} ${midY} ${x2} ${y2}`

              return (
                <g
                  key={conduit.id}
                  className="cursor-pointer group"
                  onClick={() => {
                    setActiveHotspot({
                      title: conduit.name,
                      subtitle: `${conduit.fromRegion} -> ${conduit.toRegion}`,
                      type: "conduit",
                      metrics: [
                        { label: "Conduit Type", value: "Regional Resilience Link", color: "#10b981" },
                        { label: "Bandwidth / Telemetry", value: conduit.telemetryRate, color: "#28b8c5" },
                        { label: "Flow Topology", value: conduit.flow.toUpperCase(), color: "#42b98b" },
                        { label: "Grid Status", value: "Active & Synchronized", color: "#10b981" },
                      ],
                      recommendation: conduit.description,
                    })
                  }}
                >
                  {/* Outer ambient glow path */}
                  <path
                    d={pathD}
                    fill="none"
                    stroke={conduit.color}
                    strokeWidth="3"
                    strokeOpacity="0.22"
                    filter="url(#cascade-conduit-glow)"
                  />

                  {/* Pulsing dashed telemetry conduit path */}
                  <path
                    d={pathD}
                    fill="none"
                    stroke={conduit.color}
                    strokeWidth="1.6"
                    strokeDasharray="6 4"
                    strokeOpacity="0.8"
                    markerEnd="url(#arrow-support-forward)"
                  />

                  {/* Flowing animated energy telemetry packet */}
                  <circle r="3" fill="#ffffff" filter="url(#cascade-laser-glow)">
                    <animateMotion path={pathD} dur={conduit.duration} repeatCount="indefinite" />
                  </circle>
                  <circle r="1.8" fill={conduit.color}>
                    <animateMotion path={pathD} dur={conduit.duration} repeatCount="indefinite" />
                  </circle>
                </g>
              )
            })}
          </g>

          {/* 3. LIVE MOTION CYBER ATTACK ARCS */}
          <g className="cascade-attack-arcs">
            {visibleAttacks.map((att) => {
              const [x1, y1] = att.fromCoords
              const [x2, y2] = att.toCoords
              const dx = x2 - x1
              const dy = y2 - y1
              const dist = Math.hypot(dx, dy)
              const midX = (x1 + x2) / 2
              const midY = (y1 + y2) / 2 - Math.min(65, dist * 0.22)
              const pathD = `M ${x1} ${y1} Q ${midX} ${midY} ${x2} ${y2}`

              return (
                <g key={att.id}>
                  {/* Subtle curved arc baseline */}
                  <path
                    d={pathD}
                    fill="none"
                    stroke={att.color}
                    strokeWidth="1.2"
                    strokeOpacity="0.45"
                    strokeDasharray="3 3"
                  />

                  {/* Glowing moving projectile bullet */}
                  <g filter="url(#cascade-laser-glow)">
                    <circle r="3" fill="#ffffff">
                      <animateMotion path={pathD} dur={att.duration} repeatCount="indefinite" />
                    </circle>
                    <circle r="1.8" fill={att.color}>
                      <animateMotion path={pathD} dur={att.duration} repeatCount="indefinite" />
                    </circle>
                  </g>

                  {/* Target node impact ripples */}
                  <circle cx={x2} cy={y2} r="3" fill="none" stroke={att.color} strokeWidth="1">
                    <animate attributeName="r" values="2;12;18" dur={att.duration} repeatCount="indefinite" />
                    <animate attributeName="opacity" values="0.9;0.3;0" dur={att.duration} repeatCount="indefinite" />
                  </circle>
                </g>
              )
            })}
          </g>

          {/* 4. CONCENTRATED TARGET STRIKES ON INDIA (When Live Attack Active) */}
          {liveAttackActive && (
            <g className="cascade-live-target-assault">
              <path
                d="M 200 165 Q 400 130 645 235"
                fill="none"
                stroke="#ff4d6d"
                strokeWidth="2.4"
                filter="url(#cascade-target-glow)"
              />
              <path
                d="M 700 185 Q 675 190 645 235"
                fill="none"
                stroke="#ffb703"
                strokeWidth="2.2"
                filter="url(#cascade-target-glow)"
              />
              <circle cx="645" cy="235" r="8" fill="none" stroke="#ff4d6d" strokeWidth="2">
                <animate attributeName="r" values="6;28;38" dur="1.2s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="1;0.4;0" dur="1.2s" repeatCount="indefinite" />
              </circle>
            </g>
          )}

          {/* 5. INTERACTIVE COUNTRY TAGS & HOTSPOTS */}
          {/* Iran Tag */}
          <g
            transform="translate(581, 200)"
            className="cursor-pointer"
            onClick={() => {
              setActiveHotspot({
                title: "Iran Regional Energy Telemetry",
                subtitle: "Middle East Critical Node (Active Monitoring)",
                type: "country",
                metrics: [
                  { label: "Observed Inbound Attacks", value: "48,210 req/s", color: "#ff4d6d" },
                  { label: "Target Vector", value: "Intrusion & SCADA Probe", color: "#00f5d4" },
                  { label: "Grid Status", value: "High Vulnerability Index", color: "#ffb703" },
                ],
                recommendation: "Apply perimeter edge filtering and enable encrypted mutual TLS on telemetry gateway.",
              })
              onSelectCountry?.("iran")
            }}
          >
            <rect x="-18" y="-9" width="36" height="18" rx="3" fill="#0b1720" stroke="#28b8c5" strokeWidth="1" />
            <text x="0" y="3.5" textAnchor="middle" fill="#28b8c5" fontSize="10" fontWeight="700">
              Iran
            </text>
          </g>

          {/* India (PG-003 Master) Node Beacon */}
          <g
            transform="translate(645, 235)"
            className="cursor-pointer"
            onClick={() => {
              setActiveHotspot({
                title: "India: Northern Grid SCADA Master (PG-003)",
                subtitle: "New Delhi Command Center - National Critical Asset",
                type: "country",
                metrics: [
                  { label: "Active Threat Vector", value: liveAttackActive ? "CVE-2024-3400 PAN-OS Zero-Day" : "Normal Monitored State", color: liveAttackActive ? "#ff4d6d" : "#42b98b" },
                  { label: "Regional Load Monitored", value: "41.2 GW", color: "#28b8c5" },
                  { label: "Cascading Risk Multiplier", value: liveAttackActive ? "3.84x Exponential" : "0.08x Nominal", color: liveAttackActive ? "#ff4d6d" : "#10b981" },
                  { label: "Compromise Economics", value: liveAttackActive ? "$4,821,400 Loss (Ticking)" : "$0 Protected", color: liveAttackActive ? "#ff4d6d" : "#10b981" },
                ],
                recommendation: liveAttackActive
                  ? "CRITICAL: Trigger isolation immediately to sever the command-and-control telemetry cascade."
                  : "All 7 regional telemetry links nominal. Grid operating at 50.02 Hz standard frequency.",
              })
              onSelectCountry?.("india")
            }}
          >
            <circle r="8" fill="rgba(40, 184, 197, 0.25)" />
            <circle r="4" fill="#28b8c5" className="animate-pulse" />
            <rect x="10" y="-9" width="68" height="18" rx="3" fill="#0b1720" stroke="#28b8c5" strokeWidth="1" />
            <text x="44" y="3.5" textAnchor="middle" fill="#ffffff" fontSize="9" fontWeight="700">
              India (PG-003)
            </text>
          </g>

          {/* United States Tag */}
          <g
            transform="translate(200, 165)"
            className="cursor-pointer"
            onClick={() => {
              setActiveHotspot({
                title: "United States Cyber Grid",
                subtitle: "Eastern & Western Interconnection Hub",
                type: "country",
                metrics: [
                  { label: "Outbound Attack Share", value: "78% (Top Attacker Source)", color: "#ff4d6d" },
                  { label: "Inbound Attack Share", value: "34% (Top Attacked Target)", color: "#ffb703" },
                  { label: "Transatlantic Conduit", value: "Active Synchronization", color: "#10b981" },
                ],
                recommendation: "Review cross-border IP reputation lists and BGP prefix hijacks.",
              })
              onSelectCountry?.("usa")
            }}
          >
            <rect x="-25" y="-9" width="50" height="18" rx="3" fill="#0b1720" stroke="rgba(100, 120, 200, 0.7)" strokeWidth="1" />
            <text x="0" y="3.5" textAnchor="middle" fill="#9aaab8" fontSize="9" fontWeight="700">
              US Grid
            </text>
          </g>

          {/* China Tag */}
          <g
            transform="translate(700, 185)"
            className="cursor-pointer"
            onClick={() => {
              setActiveHotspot({
                title: "China Regional Grid Hub",
                subtitle: "State Grid Telemetry & Inbound Traffic",
                type: "country",
                metrics: [
                  { label: "DDoS Vectors", value: "High Volumetric UDP Flood", color: "#ffb703" },
                  { label: "Active Probes", value: "Port 502 Modbus / SCADA", color: "#c77dff" },
                ],
              })
              onSelectCountry?.("china")
            }}
          >
            <rect x="-18" y="-9" width="36" height="18" rx="3" fill="#0b1720" stroke="rgba(100, 110, 180, 0.6)" strokeWidth="1" />
            <text x="0" y="3.5" textAnchor="middle" fill="#9aaab8" fontSize="9" fontWeight="700">
              China
            </text>
          </g>

          {/* UK Tag */}
          <g
            transform="translate(445, 120)"
            className="cursor-pointer"
            onClick={() => onSelectCountry?.("uk")}
          >
            <rect x="-14" y="-9" width="28" height="18" rx="3" fill="#0b1720" stroke="rgba(140, 120, 220, 0.6)" strokeWidth="1" />
            <text x="0" y="3.5" textAnchor="middle" fill="#9aaab8" fontSize="9" fontWeight="700">
              UK
            </text>
          </g>

          {/* Australia Tag */}
          <g
            transform="translate(765, 330)"
            className="cursor-pointer"
            onClick={() => onSelectCountry?.("australia")}
          >
            <rect x="-16" y="-9" width="32" height="18" rx="3" fill="#0b1720" stroke="rgba(90, 100, 160, 0.6)" strokeWidth="1" />
            <text x="0" y="3.5" textAnchor="middle" fill="#9aaab8" fontSize="9" fontWeight="700">
              AUS
            </text>
          </g>

          {/* Brazil Tag */}
          <g
            transform="translate(305, 325)"
            className="cursor-pointer"
            onClick={() => onSelectCountry?.("brazil")}
          >
            <rect x="-16" y="-9" width="32" height="18" rx="3" fill="#0b1720" stroke="rgba(110, 115, 180, 0.6)" strokeWidth="1" />
            <text x="0" y="3.5" textAnchor="middle" fill="#9aaab8" fontSize="9" fontWeight="700">
              BRA
            </text>
          </g>
        </svg>
      </div>

      {/* -------------------------------------------------------------
          SLEEK TOP BAR: CASCADESHIELD SENTINEL & TELEMETRY CONTROLS
          (Clean, Unobtrusive, No Floating Junk Boxes)
          ------------------------------------------------------------- */}
      <div data-interactive="true" className="absolute top-3 left-4 z-20 flex items-center gap-3">
        {/* CascadeShield Sleek Header Pill */}
        <div className="flex items-center gap-2.5 bg-[#070e17]/90 backdrop-blur-md px-3 py-1.5 rounded-lg border border-[rgba(40,184,197,0.22)] shadow-xl">
          <div className="flex items-center justify-center w-6 h-6 rounded bg-[#102d38] border border-[#28b8c5]/40 text-[#28b8c5]">
            <Shield size={14} />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-white text-xs font-black tracking-wider uppercase">CascadeShield</span>
            <span className="text-[9px] px-1.5 py-0.2 rounded bg-[#102b28] text-[#34d399] border border-[#10b981]/30 font-bold">
              SENTINEL
            </span>
          </div>
        </div>

        {/* Compact Horizontal Layer Filters Bar */}
        <div className="flex items-center gap-1.5 bg-[#070e17]/85 backdrop-blur-md px-2.5 py-1.5 rounded-lg border border-[rgba(40,184,197,0.18)] shadow-lg">
          <span className="text-[10px] text-[#687987] font-semibold uppercase flex items-center gap-1 mr-1">
            <Filter size={10} /> Filters:
          </span>

          <button
            onClick={() => toggleFilter("volumetric")}
            className={`px-2 py-0.5 rounded text-[10px] font-semibold transition-all flex items-center gap-1 ${
              filters.volumetric
                ? "bg-[#ff4d6d]/20 text-[#ff7676] border border-[#ff4d6d]/40"
                : "text-[#687987] hover:text-[#9aaab8]"
            }`}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-[#ff4d6d]" /> Volumetric
          </button>

          <button
            onClick={() => toggleFilter("protocol")}
            className={`px-2 py-0.5 rounded text-[10px] font-semibold transition-all flex items-center gap-1 ${
              filters.protocol
                ? "bg-[#ffb703]/20 text-[#ffb703] border border-[#ffb703]/40"
                : "text-[#687987] hover:text-[#9aaab8]"
            }`}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-[#ffb703]" /> Protocol
          </button>

          <button
            onClick={() => toggleFilter("intrusion")}
            className={`px-2 py-0.5 rounded text-[10px] font-semibold transition-all flex items-center gap-1 ${
              filters.intrusion
                ? "bg-[#00f5d4]/20 text-[#00f5d4] border border-[#00f5d4]/40"
                : "text-[#687987] hover:text-[#9aaab8]"
            }`}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-[#00f5d4]" /> Intrusion
          </button>

          <button
            onClick={() => toggleFilter("conduits")}
            className={`px-2 py-0.5 rounded text-[10px] font-semibold transition-all flex items-center gap-1 ${
              filters.conduits
                ? "bg-[#10b981]/25 text-[#34d399] border border-[#10b981]/50 shadow-[0_0_8px_rgba(16,185,129,0.3)]"
                : "text-[#687987] hover:text-[#9aaab8]"
            }`}
            title="Shows what region supports what region"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-[#10b981] animate-pulse" /> Regional Conduits
          </button>
        </div>
      </div>

      {/* -------------------------------------------------------------
          BOTTOM-LEFT ZOOM / VIEWPORT CONTROLS
          ------------------------------------------------------------- */}
      <div data-interactive="true" className="absolute bottom-3 left-4 z-20 flex items-center gap-1.5 bg-[#0a121c]/90 backdrop-blur-md p-1 rounded-lg border border-[rgba(40,184,197,0.2)] shadow-xl">
        <button
          onClick={() => setScale((s) => Math.min(2.8, s * 1.15))}
          className="p-1.5 rounded hover:bg-[#142230] text-[#9aaab8] hover:text-white"
          title="Zoom In"
        >
          <ZoomIn size={13} />
        </button>
        <button
          onClick={() => setScale((s) => Math.max(0.8, s * 0.85))}
          className="p-1.5 rounded hover:bg-[#142230] text-[#9aaab8] hover:text-white"
          title="Zoom Out"
        >
          <ZoomOut size={13} />
        </button>
        <button
          onClick={resetView}
          className="px-2 py-1 rounded hover:bg-[#142230] text-[10px] text-[#9aaab8] hover:text-white font-mono"
          title="Reset View"
        >
          Reset ({Math.round(scale * 100)}%)
        </button>
      </div>

      {/* -------------------------------------------------------------
          INTERACTIVE TELEMETRY DRILLDOWN POPUP
          ------------------------------------------------------------- */}
      {activeHotspot && (
        <div
          data-interactive="true"
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-40 w-96 bg-[#070d14]/95 backdrop-blur-xl border border-[rgba(40,184,197,0.35)] rounded-xl p-4 shadow-2xl flex flex-col gap-3 animate-in fade-in zoom-in-95 duration-150"
        >
          <div className="flex items-start justify-between pb-2 border-b border-[#1b2b3a]">
            <div>
              <div className="flex items-center gap-2">
                {activeHotspot.type === "conduit" ? (
                  <Share2 size={16} className="text-[#10b981]" />
                ) : (
                  <Shield size={16} className="text-[#28b8c5]" />
                )}
                <h3 className="text-white font-bold text-sm">{activeHotspot.title}</h3>
              </div>
              <p className="text-[#687987] text-xs mt-0.5">{activeHotspot.subtitle}</p>
            </div>
            <button
              onClick={() => setActiveHotspot(null)}
              className="p-1 text-[#687987] hover:text-white hover:bg-[#101b24] rounded"
            >
              <X size={16} />
            </button>
          </div>

          <div className="space-y-2">
            {activeHotspot.metrics.map((m, idx) => (
              <div key={idx} className="flex items-center justify-between text-xs py-1 px-2 rounded bg-[#0b1622]/80">
                <span className="text-[#9aaab8]">{m.label}</span>
                <span className="font-bold font-mono" style={{ color: m.color || "#ffffff" }}>
                  {m.value}
                </span>
              </div>
            ))}
          </div>

          {activeHotspot.recommendation && (
            <div className="text-[11px] p-2 rounded bg-[#0e1f2c] border border-[#1b3447] text-[#8cb0c4]">
              <strong className="text-[#28b8c5]">Telemetry Conduit Intel: </strong>
              {activeHotspot.recommendation}
            </div>
          )}

          <div className="flex items-center gap-2 pt-1">
            <button
              onClick={() => {
                setActiveHotspot(null)
                onNavigateDetail?.("Risk Intelligence")
              }}
              className="flex-1 py-1.5 rounded bg-[#102a36] hover:bg-[#173847] text-[#28b8c5] border border-[#28b8c5]/40 text-xs font-bold flex items-center justify-center gap-1.5 transition-colors"
            >
              <span>Detailed Analytics</span>
              <ArrowRight size={13} />
            </button>
            <button
              onClick={() => {
                setActiveHotspot(null)
                onNavigateDetail?.("Live Attack Demo")
              }}
              className="py-1.5 px-3 rounded bg-[#5a161f] hover:bg-[#721b27] text-[#ff9999] text-xs font-bold transition-colors"
            >
              Simulate
            </button>
          </div>
        </div>
      )}
    </div>
  )
})

// Export aliases
export const RadwareWorldMap = CascadeWorldMap
