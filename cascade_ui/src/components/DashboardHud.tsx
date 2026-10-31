import { useState, useEffect } from "react"
import {
  Shield,
  AlertTriangle,
  Bell,
  Activity,
  ChevronDown,
  User,
  SlidersHorizontal,
  RotateCcw,
  Volume2,
  TrendingUp,
  Download,
  Flame,
  Lock,
  CheckCircle2,
  DollarSign,
  Zap,
  ArrowRight,
  ExternalLink,
} from "lucide-react"

// Waveform visualizer data
const WAVEFORM_BARS = [
  18, 25, 42, 65, 80, 52, 44, 90, 72, 60, 48, 85, 95, 78, 62, 45, 70, 88, 55, 38,
  64, 82, 91, 58, 42, 75, 60, 48, 32, 54, 70, 85, 62, 44, 58, 77, 65, 50, 40, 25,
]

// 1. Alerts Intensity in Blocks (Left Side HUD)
export function AlertsIntensityChart({ onDrillDown }: { onDrillDown?: () => void }) {
  const [timeframe, setTimeframe] = useState("Monthly Trend")
  const [windowRange, setWindowRange] = useState("Last 12 Hour")

  return (
    <div
      className="hud-intensity-wrap group cursor-pointer"
      onClick={onDrillDown}
      title="Click for detailed telemetry & rules analytics"
    >
      <div className="flex items-center justify-between">
        <div className="hud-subhead group-hover:text-[#28b8c5] transition-colors">Alerts Intensity in Blocks</div>
        <span className="text-[10px] text-[#687987] group-hover:text-[#28b8c5] flex items-center gap-1">
          Details <ArrowRight size={10} />
        </span>
      </div>

      {/* Waveform / Frequency visualizer */}
      <div className="hud-waveform-container">
        {/* Min/max threshold markers */}
        <div className="hud-wave-markers">
          <span className="hud-marker-tag">316</span>
          <span className="hud-marker-tag text-right">564</span>
        </div>

        <div className="hud-waveform-bars">
          {WAVEFORM_BARS.map((height, i) => (
            <div
              key={i}
              className={`hud-wave-bar ${height > 75 ? "is-peak" : height > 50 ? "is-mid" : ""}`}
              style={{ height: `${height}%` }}
            />
          ))}
        </div>

        {/* Lower threshold indicators */}
        <div className="hud-wave-lower-markers">
          <span>72</span>
          <span className="hud-center-dot">▲ 50</span>
          <span>100</span>
        </div>
      </div>

      {/* Control pills row */}
      <div className="hud-filter-pills" onClick={(e) => e.stopPropagation()}>
        <button className="hud-pill-btn">
          <span>{timeframe}</span>
          <ChevronDown size={11} />
        </button>
        <button className="hud-pill-btn">
          <span>{windowRange}</span>
          <ChevronDown size={11} />
        </button>
        <button className="hud-pill-icon-btn" title="Audio / Signal">
          <Volume2 size={12} />
        </button>
        <button className="hud-pill-icon-btn" title="Reset view">
          <RotateCcw size={12} />
        </button>
        <button className="hud-pill-icon-btn" title="Export data">
          <Download size={12} />
        </button>
      </div>
    </div>
  )
}

// 2. Circular Radial Arc Gauge (Right Side HUD)
export function RadialGauge({
  label,
  current,
  total,
  percent,
  color = "#42b98b",
  onDrillDown,
}: {
  label: string
  current: string
  total: string
  percent: number // 0 to 100
  color?: string
  onDrillDown?: () => void
}) {
  const radius = 28
  const stroke = 4
  const normalizedRadius = radius - stroke * 2
  const circumference = normalizedRadius * 2 * Math.PI
  const arcLength = circumference * 0.72
  const strokeDashoffset = arcLength - (percent / 100) * arcLength

  return (
    <div
      className="hud-radial-gauge-item group cursor-pointer transition-all hover:translate-x-[-3px]"
      onClick={onDrillDown}
      title={`Click for ${label} detailed breakdown`}
    >
      <div className="hud-radial-svg-wrap">
        <svg height={radius * 2} width={radius * 2} className="hud-gauge-svg">
          <circle
            stroke="rgba(40, 184, 197, 0.15)"
            fill="transparent"
            strokeWidth={stroke}
            strokeDasharray={`${arcLength} ${circumference}`}
            style={{ strokeDashoffset: 0 }}
            r={normalizedRadius}
            cx={radius}
            cy={radius}
            transform={`rotate(140 ${radius} ${radius})`}
            strokeLinecap="round"
          />
          <circle
            stroke={color}
            fill="transparent"
            strokeWidth={stroke}
            strokeDasharray={`${arcLength} ${circumference}`}
            style={{ strokeDashoffset }}
            r={normalizedRadius}
            cx={radius}
            cy={radius}
            transform={`rotate(140 ${radius} ${radius})`}
            strokeLinecap="round"
          />
        </svg>
      </div>
      <div className="hud-gauge-details">
        <div className="hud-gauge-label group-hover:text-white transition-colors">{label}</div>
        <div className="hud-gauge-metric">
          <strong style={{ color }}>{current}</strong>
          <span>/ {total}</span>
        </div>
      </div>
    </div>
  )
}

// 3. Personnel / AI Sentinel Stack (Right Side HUD)
export function PersonnelStack({ onDrillDown }: { onDrillDown?: () => void }) {
  const agents = [
    { name: "Sem Brinkman", role: "SecOps Lead", status: "Active" },
    { name: "James Carter", role: "SCADA Sentinel", status: "Monitoring" },
    { name: "David Moore", role: "Containment Officer", status: "Standby" },
  ]

  return (
    <div className="hud-personnel-stack" onClick={onDrillDown} title="Click to view AI Agent pipeline traces">
      <div className="text-[10px] text-[#687987] font-semibold uppercase tracking-wider mb-1 px-1 flex items-center justify-between">
        <span>Incident Responders</span>
        <span className="text-[#42b98b]">3 Ready</span>
      </div>
      {agents.map((agent, i) => (
        <div key={i} className="hud-person-row hover:border-[#28b8c5]">
          <div className="hud-person-avatar">
            <User size={12} />
          </div>
          <span className="hud-person-name">{agent.name}</span>
          <span className="text-[10px] text-[#687987] ml-auto">{agent.role}</span>
          <ChevronDown size={11} className="hud-person-arrow ml-1" />
        </div>
      ))}
    </div>
  )
}

// 4. CascadeShield Global Threat Vectors & Attacked Sectors (Right Side HUD)
export function GlobalAttackVectors({ onDrillDown }: { onDrillDown?: () => void }) {
  const vectors = [
    { name: "TCP SYN Flood", percent: 53, color: "#ffb703" },
    { name: "Modbus/OT Command Injection", percent: 43, color: "#e45b5b" },
    { name: "WAN Gateway Exploit (CVE-2024-3400)", percent: 28, color: "#ff4d6d" },
    { name: "UDP Telemetry Flood", percent: 14, color: "#28b8c5" },
  ]

  const targets = [
    { sector: "Northern Power Grid (WGEC)", share: 78, tag: "Primary" },
    { sector: "Delhi Jal Board Water Pumping", share: 14, tag: "Secondary" },
    { sector: "AIIMS Clinical & Trauma Hub", share: 8, tag: "Tertiary" },
  ]

  return (
    <div className="hud-threat-vectors-card" onClick={onDrillDown}>
      <div className="hud-section-label">Top Attack Vectors</div>
      <div className="space-y-2 mt-1.5">
        {vectors.map((v) => (
          <div key={v.name} className="text-xs">
            <div className="flex justify-between items-center text-[11px] mb-1">
              <span className="text-[#9aaab8] truncate max-w-[150px]">{v.name}</span>
              <strong className="text-white font-mono">{v.percent}%</strong>
            </div>
            <div className="w-full h-1.5 bg-[#141d26] rounded-full overflow-hidden">
              <div className="h-full rounded-full" style={{ width: `${v.percent}%`, background: v.color }} />
            </div>
          </div>
        ))}
      </div>

      <div className="hud-section-label mt-3 pt-2 border-t border-[#1f2d3a]">Top Attacked Sectors</div>
      <div className="space-y-1.5 mt-1">
        {targets.map((t) => (
          <div key={t.sector} className="flex items-center justify-between text-[11px] p-1.5 rounded bg-[#101923] border border-[#1b2734]">
            <span className="text-[#e7edf3] truncate max-w-[160px]">{t.sector}</span>
            <span className="font-bold text-[#28b8c5]">{t.share}%</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// 5. 360 View by Blocks (Bottom Left HUD)
export function BlockView360({ onDrillDown }: { onDrillDown?: () => void }) {
  const rows = 5
  const cols = 12

  const highlights = [
    { r: 2, c: 3, type: "shield" },
    { r: 1, c: 7, type: "shield" },
    { r: 3, c: 9, type: "alert" },
    { r: 4, c: 8, type: "danger" },
  ]

  return (
    <div className="hud-block-view-wrap cursor-pointer" onClick={onDrillDown} title="Click to view 360 block security details">
      <div className="flex items-center justify-between">
        <div className="hud-block-title hover:text-[#28b8c5] transition-colors">360 View by Blocks</div>
        <span className="text-[10px] text-[#687987]">60 Cells Monitored</span>
      </div>
      <div className="hud-block-grid-area">
        <div className="hud-block-row-labels">
          <span>Attack</span>
          <span>Delete</span>
          <span>Failure</span>
          <span>Lockout</span>
        </div>

        <div className="hud-micro-matrix">
          {Array.from({ length: rows }).map((_, r) => (
            <div key={r} className="hud-matrix-row">
              {Array.from({ length: cols }).map((_, c) => {
                const hl = highlights.find((h) => h.r === r && h.c === c)
                return (
                  <span
                    key={c}
                    className={`hud-matrix-dot ${hl ? `is-${hl.type}` : ""}`}
                  />
                )
              })}
            </div>
          ))}

          <div className="hud-matrix-pill">
            <span className="hud-matrix-pill-alert">⚠️ Unsafe SCADA Gateway Link</span>
          </div>
        </div>
      </div>
    </div>
  )
}

// 6. Total Attacks by Alerts (Bottom Center-Right HUD)
export function TotalAttacksStats({ onDrillDown }: { onDrillDown?: () => void }) {
  return (
    <div className="hud-total-attacks-wrap cursor-pointer" onClick={onDrillDown} title="Click to inspect portfolio risk distribution">
      <div className="hud-attacks-header flex items-center justify-between">
        <span>Total Attacks by Alerts</span>
        <span className="text-[10px] text-[#687987]">Live Sync</span>
      </div>
      <div className="hud-attacks-items">
        <div className="hud-attack-stat">
          <div className="hud-stat-tag">
            <Shield size={13} className="text-[#42b98b]" />
            <span>Protected</span>
          </div>
          <div className="hud-stat-num">
            <strong>882k</strong>
            <small>/ 992k</small>
          </div>
        </div>

        <div className="hud-attack-stat">
          <div className="hud-stat-tag">
            <AlertTriangle size={13} className="text-[#e45b5b]" />
            <span>Danger</span>
          </div>
          <div className="hud-stat-num">
            <strong>1.2k</strong>
            <small>/ 992k</small>
          </div>
        </div>

        <div className="hud-attack-stat">
          <div className="hud-stat-tag">
            <Bell size={13} className="text-[#e99a43]" />
            <span>Alerts</span>
          </div>
          <div className="hud-stat-num">
            <strong>7.4k</strong>
            <small>/ 992k</small>
          </div>
        </div>

        <div className="hud-attack-stat">
          <div className="hud-stat-tag">
            <Activity size={13} className="text-[#9aaab8]" />
            <span>Unknown</span>
          </div>
          <div className="hud-stat-num">
            <strong>1.1k</strong>
            <small>/ 992k</small>
          </div>
        </div>
      </div>
    </div>
  )
}

// 7. National Grid Frequency Stream Waveform (Bottom timeline frequency chart)
export function FrequencyStreamWaveform() {
  return (
    <div className="hud-frequency-stream-bar">
      <div className="flex items-center justify-between text-[10px] text-[#687987] font-mono px-2 py-0.5">
        <span>0:30 MIN</span>
        <span>0:50 MIN</span>
        <span className="text-[#28b8c5] font-bold">● NOW</span>
      </div>
      {/* Stream waveform visualization */}
      <div className="hud-stream-svg-box">
        <svg viewBox="0 0 600 32" className="w-full h-8" preserveAspectRatio="none">
          {/* Web Attackers line */}
          <path
            d="M 0 16 Q 50 14 100 16 T 200 15 T 300 17 T 400 14 T 500 16 T 600 15"
            fill="none"
            stroke="#ff4d6d"
            strokeWidth="1.2"
            opacity="0.8"
          />
          {/* DDoS spikes */}
          <polyline
            points="0,26 40,26 45,6 50,26 120,26 125,4 130,26 210,26 215,8 220,26 310,26 315,3 320,26 430,26 435,5 440,26 530,26 535,4 540,26 600,26"
            fill="none"
            stroke="#ffb703"
            strokeWidth="1.4"
          />
          {/* SCADA Intrusion spikes */}
          <polyline
            points="0,28 70,28 75,12 80,28 180,28 185,10 190,28 290,28 295,9 300,28 390,28 395,11 400,28 480,28 485,7 490,28 600,28"
            fill="none"
            stroke="#00f5d4"
            strokeWidth="1.2"
          />
        </svg>
      </div>
      <div className="flex items-center justify-end gap-3 text-[9px] px-2 text-[#9aaab8]">
        <span className="text-[#ff4d6d]">WEB ATTACKERS</span>
        <span className="text-[#ffb703]">DDOS ATTACKERS</span>
        <span className="text-[#00f5d4]">INTRUDERS</span>
      </div>
    </div>
  )
}

// 8. LIVE ATTACK SIMULATION & COMPROMISE ECONOMICS CONTROL PANEL
export function CompromiseEconomicsPanel({
  isIsolated,
  onToggleIsolation,
  onResetDemo,
}: {
  isIsolated: boolean
  onToggleIsolation: () => void
  onResetDemo: () => void
}) {
  const [lossAmount, setLossAmount] = useState(245000)

  useEffect(() => {
    if (isIsolated) return
    const interval = setInterval(() => {
      setLossAmount((prev) => prev + Math.floor(Math.random() * 850 + 400))
    }, 1000)
    return () => clearInterval(interval)
  }, [isIsolated])

  return (
    <div className="hud-compromise-economics-box glass-panel">
      {/* Header */}
      <div className="flex items-center justify-between pb-2 border-b border-[#202e3a]">
        <div className="flex items-center gap-2">
          <span className="p-1 rounded bg-[#e45b5b]/20 text-[#e45b5b]">
            <Flame size={15} className={!isIsolated ? "animate-pulse" : ""} />
          </span>
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider">
              Live Attack Simulation · Compromise Economics
            </h3>
            <p className="text-[11px] text-[#9aaab8]">Real-time financial &amp; infrastructure cascade exposure</p>
          </div>
        </div>

        {/* Status indicator */}
        <span
          className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
            isIsolated
              ? "bg-[#42b98b]/20 text-[#42b98b] border border-[#42b98b]/40"
              : "bg-[#e45b5b]/20 text-[#e45b5b] border border-[#e45b5b]/40 animate-pulse"
          }`}
        >
          {isIsolated ? "✓ Node Isolated & Contained" : "● Active Breach in Progress"}
        </span>
      </div>

      {/* Vulnerability & Attack Origin */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-2 my-2 text-xs">
        <div className="p-2 rounded bg-[#101822] border border-[#1d2b38]">
          <span className="text-[10px] text-[#687987] uppercase block font-semibold">Active Vulnerability</span>
          <strong className="text-[#e45b5b] text-[13px]">CVE-2024-3400 (CVSS 10.0)</strong>
          <span className="text-[10px] text-[#9aaab8] block mt-0.5">GlobalProtect WAN Command Injection</span>
        </div>

        <div className="p-2 rounded bg-[#101822] border border-[#1d2b38]">
          <span className="text-[10px] text-[#687987] uppercase block font-semibold">Target Asset</span>
          <strong className="text-white text-[13px]">PG-003 · Northern Grid SCADA Gateway</strong>
          <span className="text-[10px] text-[#28b8c5] block mt-0.5">New Delhi · Port 8443 WAN Exposure</span>
        </div>

        <div className="p-2 rounded bg-[#101822] border border-[#1d2b38]">
          <span className="text-[10px] text-[#687987] uppercase block font-semibold">Downstream Cascade Risk</span>
          <strong className={isIsolated ? "text-[#42b98b]" : "text-[#e99a43]"}>
            {isIsolated ? "0 Downstream (Severed)" : "Agra 400kV → Jal Board → AIIMS"}
          </strong>
          <span className="text-[10px] text-[#9aaab8] block mt-0.5">
            {isIsolated ? "Containment barrier active" : "Estimated cascade: 4 hours"}
          </span>
        </div>
      </div>

      {/* Live Financial & Capacity Economics Ticker */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 my-2">
        <div className="p-2.5 rounded bg-[#0d141e] border border-[#1b2836]">
          <span className="text-[10px] text-[#687987] uppercase">Financial Loss Velocity</span>
          <div className="text-lg font-bold font-mono text-[#ff4d6d] mt-0.5">
            ${isIsolated ? "0.00" : "14,500"} <span className="text-[10px] text-[#9aaab8] font-normal">/ min</span>
          </div>
        </div>

        <div className="p-2.5 rounded bg-[#0d141e] border border-[#1b2836]">
          <span className="text-[10px] text-[#687987] uppercase">Cascading Loss Exposure</span>
          <div className="text-lg font-bold font-mono text-white mt-0.5">
            ${lossAmount.toLocaleString()}
          </div>
        </div>

        <div className="p-2.5 rounded bg-[#0d141e] border border-[#1b2836]">
          <span className="text-[10px] text-[#687987] uppercase">Grid Capacity at Risk</span>
          <div className="text-lg font-bold font-mono text-[#eab308] mt-0.5">
            {isIsolated ? "0 MW" : "1,450 MW"}
          </div>
        </div>

        <div className="p-2.5 rounded bg-[#0d141e] border border-[#1b2836]">
          <span className="text-[10px] text-[#687987] uppercase">Population at Risk</span>
          <div className="text-lg font-bold font-mono text-[#38bdf8] mt-0.5">
            {isIsolated ? "0 Protected" : "4.2M Citizens"}
          </div>
        </div>
      </div>

      {/* ISOLATION ACTION BUTTON & STATUS */}
      <div className="flex items-center justify-between pt-2 border-t border-[#202e3a] mt-2 flex-wrap gap-2">
        <div className="text-xs text-[#9aaab8]">
          {!isIsolated ? (
            <span className="text-[#fca5a5] flex items-center gap-1.5">
              <AlertTriangle size={13} className="text-[#e45b5b]" />
              Cascading lateral spread active across PowerGrid, Jal Board, and AIIMS.
            </span>
          ) : (
            <span className="text-[#a7f3d0] flex items-center gap-1.5">
              <CheckCircle2 size={13} className="text-[#42b98b]" />
              $2,420,000 potential loss avoided. Node severed; downstream infrastructure secured.
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onResetDemo}
            className="px-3 py-1.5 rounded text-xs font-semibold bg-[#16212c] text-[#9aaab8] hover:text-white border border-[#233241] flex items-center gap-1"
          >
            <RotateCcw size={12} /> Reset Simulation
          </button>

          <button
            onClick={onToggleIsolation}
            className={`px-4 py-1.5 rounded text-xs font-bold transition-all shadow-lg flex items-center gap-1.5 ${
              isIsolated
                ? "bg-[#28b8c5] text-[#0b1118] hover:bg-[#38c9d6]"
                : "bg-[#e45b5b] text-white hover:bg-[#f06e6e] animate-bounce"
            }`}
          >
            <Lock size={13} />
            {isIsolated ? "Restore Node Connectivity" : "⚡ Isolate Node (PG-003) & Sever Cascade"}
          </button>
        </div>
      </div>
    </div>
  )
}


// Aliases for compatibility
export const RadwareAttackVectors = GlobalAttackVectors
export const RadwareTimelineWaveform = FrequencyStreamWaveform
