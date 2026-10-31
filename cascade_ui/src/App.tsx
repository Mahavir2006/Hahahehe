import { useMemo, useState } from "react"
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowRight,
  Bell,
  Blocks,
  Bot,
  Building2,
  Check,
  ChevronDown,
  ChevronRight,
  CircleGauge,
  Clock3,
  Database,
  ExternalLink,
  Eye,
  FileCheck2,
  Filter,
  GitBranch,
  Globe2,
  Hospital,
  Layers3,
  ListFilter,
  LockKeyhole,
  Map,
  MapPin,
  Menu,
  Network,
  PanelRightClose,
  Plus,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
  Sparkles,
  Trash2,
  UserRound,
  Waves,
  X,
  Zap,
  ZoomIn,
  ZoomOut,
} from "lucide-react"
import { Cell, Pie, PieChart, ResponsiveContainer } from "recharts"
import { TerrainMap } from "./components/terrain/TerrainMap"
import { IndiaMap } from "./components/IndiaMap"
import { CascadeWorldMap } from "./components/CascadeWorldMap"
import {
  AlertsIntensityChart,
  RadialGauge,
  PersonnelStack,
  GlobalAttackVectors,
  BlockView360,
  TotalAttacksStats,
  FrequencyStreamWaveform,
  CompromiseEconomicsPanel,
} from "./components/DashboardHud"
import { Maximize2, Flame, AlertCircle } from "lucide-react"
import {
  GlobalSimulationBanner,
  GlobalClockAndModelBadge,
  IncidentStrip,
  RankedNeedsAttentionTable,
  RiskOverTimeAndWhatChanged,
  DetectTelemetryAndRules,
  PredictShapAndTrendPanel,
  CascadePreviewPanel,
  RecommendPlannerPanel,
  ScenarioSimulationControls,
  ModelCardView,
  TrustGovernanceBlock,
} from "./components/PS03Components"
import {
  exposureFindings,
  getAssetPredictDetails,
  detectionsData,
} from "./data/cascadeshieldData"
import { assets, assetById, organisations as orgData, orgByCode, riskHex, type Asset } from "./data/infrastructure"

type Page =
  | "Command Centre"
  | "Live Attack Demo"
  | "Security Operations"
  | "Infrastructure View"
  | "Asset Inventory"
  | "Risk Intelligence"
  | "AI Agent Activity"
  | "Remediation Centre"
  | "Blockchain Audit"
  | "Settings"
type Risk = "Critical" | "High" | "Medium" | "Low"

interface NavItem {
  label: Page
  icon: typeof Shield
}

const nav: NavItem[] = [
  { label: "Command Centre", icon: CircleGauge },
  { label: "Live Attack Demo", icon: Flame },
  { label: "Security Operations", icon: Layers3 },
  { label: "Infrastructure View", icon: Map },
  { label: "Asset Inventory", icon: Database },
  { label: "Risk Intelligence", icon: ShieldAlert },
  { label: "AI Agent Activity", icon: Bot },
  { label: "Remediation Centre", icon: FileCheck2 },
  { label: "Blockchain Audit", icon: Blocks },
  { label: "Settings", icon: Settings },
]

const orgIcons = { WGEC: Zap, MetroWater: Waves, CCMN: Hospital }
const orgColors = { WGEC: "#28B8C5", MetroWater: "#E99A43", CCMN: "#42B98B" }
const organisations = orgData.map((org) => ({ ...org, icon: orgIcons[org.code], color: orgColors[org.code] }))
const riskColors = riskHex

const pageDescriptions: Record<Page, string> = {
  "Command Centre": "Live threat map & regional grid performance (Splunk / CascadeShield Sentinel Matrix)",
  "Live Attack Demo": "Interactive live cyber attack simulation, compromise economics & node isolation",
  "Security Operations": "PS-03 Deep Dive: telemetry rules, model explanations & scenario replay",
  "Infrastructure View": "Explore infrastructure assets and dependency pathways",
  "Asset Inventory": "Search and assess all monitored infrastructure assets",
  "Risk Intelligence": "Evidence, model explanations and downstream consequence analysis",
  "AI Agent Activity": "Review agent executions, decisions and system traces",
  "Remediation Centre": "Compare controls, simulate outcomes and manage approvals",
  "Blockchain Audit": "Verify registrations, attestations and approval records",
  Settings: "Organisation, access and assessment preferences",
}

function Button({
  children,
  variant = "secondary",
  className = "",
  onClick,
  disabled = false,
  title,
}: {
  children: React.ReactNode
  variant?: "primary" | "secondary" | "danger" | "ghost"
  className?: string
  onClick?: () => void
  disabled?: boolean
  title?: string
}) {
  return (
    <button
      title={title}
      disabled={disabled}
      onClick={onClick}
      className={`btn btn-${variant} ${className}`}
    >
      {children}
    </button>
  )
}

function Badge({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode
  tone?: string
}) {
  return <span className={`badge badge-${tone.toLowerCase()}`}>{children}</span>
}

function SectionTitle({
  eyebrow,
  title,
  action,
}: {
  eyebrow?: string
  title: string
  action?: React.ReactNode
}) {
  return (
    <div className="section-title">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h2>{title}</h2>
      </div>
      {action}
    </div>
  )
}

function LeftHoverNavbar({
  page,
  setPage,
  glowingNav,
}: {
  page: Page
  setPage: (p: Page) => void
  glowingNav: string | null
}) {
  return (
    <aside className="left-hover-navbar">
      <div className="left-hover-brand">
        <div className="left-hover-brand-icon">
          <Shield size={20} />
        </div>
        <div className="overflow-hidden">
          <strong className="block text-white text-sm font-bold tracking-tight">CascadeShield</strong>
          <span className="block text-[10px] text-[#687987] uppercase tracking-wider">SecOps Cyber Grid</span>
        </div>
      </div>
      <nav className="left-hover-nav-list">
        {nav.map(({ label, icon: Icon }) => {
          const isGlowing = glowingNav === label
          const isActive = page === label
          return (
            <button
              key={label}
              onClick={() => setPage(label)}
              className={`left-hover-nav-item ${isActive ? "is-active" : ""} ${isGlowing ? "is-glowing" : ""}`}
              title={label}
            >
              <div className="nav-icon-wrap">
                <Icon size={17} />
              </div>
              <span className="truncate">{label}</span>
              {isActive && <ChevronRight size={13} className="ml-auto text-[#28b8c5]" />}
            </button>
          )
        })}
      </nav>
      <div className="p-3 border-t border-[#1a2634] text-[10px] text-[#687987] flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-[#42b98b] animate-ping" />
        <span className="truncate">Grid Telemetry Live</span>
      </div>
    </aside>
  )
}

function Sidebar({
  page,
  setPage,
  open,
  setOpen,
}: {
  page: Page
  setPage: (p: Page) => void
  open: boolean
  setOpen: (v: boolean) => void
}) {
  return (
    <aside className={`sidebar ${open ? "sidebar-open" : ""}`}>
      <div className="brand">
        <div className="brand-mark">
          <Shield size={21} strokeWidth={1.7} />
          <span className="brand-pulse" />
        </div>
        <div>
          <strong>CascadeShield</strong>
          <span>Infrastructure resilience</span>
        </div>
        <Button
          variant="ghost"
          className="sidebar-close"
          onClick={() => setOpen(false)}
        >
          <X size={18} />
        </Button>
      </div>
      <nav className="nav-list">
        <div className="nav-caption">Workspace</div>
        {nav.map(({ label, icon: Icon }) => (
          <button
            key={label}
            onClick={() => {
              setPage(label)
              setOpen(false)
            }}
            className={`nav-item ${page === label ? "active" : ""}`}
          >
            <Icon size={17} strokeWidth={1.7} />
            <span>{label}</span>
            {page === label && <ChevronRight size={14} className="nav-arrow" />}
          </button>
        ))}
      </nav>
      <div className="org-switcher">
        <div className="org-title">
          <span>Active organisations</span>
          <Badge tone="healthy">3 online</Badge>
        </div>
        {organisations.map(({ code, name, color, icon: Icon }) => (
          <button className="org-row" key={code}>
            <span className="org-icon" style={{ color }}>
              <Icon size={15} />
            </span>
            <span>
              <strong>{code}</strong>
              <small>{name}</small>
            </span>
            <span className="status-dot" style={{ background: color }} />
          </button>
        ))}
        <button className="manage-orgs">
          Manage organisations <ArrowRight size={13} />
        </button>
      </div>
    </aside>
  )
}

function Header({
  page,
  onMenu,
  onSearch,
  onToggleIncidents,
  activeIncidentsCount = 2,
}: {
  page: Page
  onMenu: () => void
  onSearch: (v: string) => void
  onToggleIncidents?: () => void
  activeIncidentsCount?: number
}) {
  return (
    <header className="topbar">
      <Button variant="ghost" className="menu-btn" onClick={onMenu}>
        <Menu size={20} />
      </Button>
      <div className="page-heading">
        <h1>{page}</h1>
        <p>{pageDescriptions[page]}</p>
      </div>
      <div className="top-actions">
        <label className="global-search">
          <Search size={16} />
          <input
            onChange={(e) => onSearch(e.target.value)}
            placeholder="Search assets, advisories, organisations…"
          />
          <kbd>⌘ K</kbd>
        </label>
        <Button
          variant="secondary"
          className="icon-btn"
          title={`${activeIncidentsCount} Active Incident Alerts`}
          onClick={onToggleIncidents}
        >
          <Bell size={17} />
          <span className="notification-dot" />
        </Button>
        <button className="profile">
          <span className="avatar">AL</span>
          <span>
            <strong>Alex Lin</strong>
            <small>Security Lead</small>
          </span>
          <ChevronDown size={14} />
        </button>
      </div>
    </header>
  )
}

function Kpis() {
  const items = [
    ["Org risk now", "71.8%", ShieldAlert, "7,184 bp · Predict Layer", "critical"],
    ["Change since yesterday", "-42 bp", ArrowDownRight, "↓ Improving trend", "healthy"],
    ["Assets above threshold", "05", AlertTriangle, "> 60% threshold limit", "high"],
    ["Open incidents", "02", Flame, "PG-003 active incident", "critical"],
    ["New detections today", "14", Zap, "Across R1–R6 rules", "medium"],
  ] as const
  return (
    <div className="kpi-grid">
      {items.map(([label, value, Icon, meta, tone]) => (
        <div className={`kpi-card tone-${tone}`} key={label}>
          <div className="kpi-top">
            <span>{label}</span>
            <Icon size={17} />
          </div>
          <div className="kpi-value">{value}</div>
          <div className="kpi-meta">{meta}</div>
        </div>
      ))}
    </div>
  )
}

interface ActiveRiskProps {
  asset: Asset
  onDetails: () => void
  onContain: () => void
}

function ActiveRisk({ asset, onDetails, onContain }: ActiveRiskProps) {
  const org = orgByCode[asset.org]
  const delta = asset.risk - 75
  const steps = asset.cascade.split(" → ")
  return (
    <aside className="risk-panel panel">
      <SectionTitle eyebrow="Selected asset" title="Active risk" action={<Badge tone={asset.level}>{asset.level}</Badge>} />
      <div className="asset-identity">
        <div className={`risk-icon tone-${asset.level.toLowerCase()}`}>
          <ShieldAlert size={20} />
        </div>
        <div>
          <strong>{asset.id}</strong>
          <span>{asset.name}</span>
        </div>
      </div>
      <div className="risk-score-block">
        <div>
          <span>Risk score</span>
          <strong style={{ color: riskColors[asset.level] }}>{asset.risk.toFixed(2)}</strong>
          <small>/ 100</small>
        </div>
        <div className="risk-bar">
          <i style={{ width: `${asset.risk}%`, background: riskColors[asset.level] }} />
        </div>
        <p className={delta >= 0 ? "above" : ""}>
          {delta >= 0 ? `${delta.toFixed(2)} points above` : `${Math.abs(delta).toFixed(2)} points below`} critical threshold (75)
        </p>
      </div>
      <div className="stat-pair">
        <div>
          <span>Compromise likelihood</span>
          <strong>{asset.likelihood}%</strong>
        </div>
        <div>
          <span>Impact</span>
          <strong>{asset.impact}%</strong>
        </div>
      </div>
      <div className="info-list">
        <div>
          <span>Organisation</span>
          <strong>
            {org.code} · {org.name}
          </strong>
        </div>
        <div>
          <span>Primary finding</span>
          <strong>{asset.vulnerability}</strong>
        </div>
        <div>
          <span>Exposure</span>
          <strong>{asset.exposure}</strong>
        </div>
        <div className="cascade">
          <span>Potential cascade</span>
          <strong>
            {steps.map((step, i) => (
              <span key={step}>
                {i > 0 && <ArrowRight size={12} />}
                {step}
              </span>
            ))}
          </strong>
        </div>
      </div>
      <div className="risk-actions">
        <Button className="grow" onClick={onDetails}>
          <Eye size={15} />
          View details
        </Button>
        <Button className="grow" variant="danger" onClick={onContain}>
          <LockKeyhole size={15} />
          Start containment
        </Button>
      </div>
      <div className="updated">
        <Clock3 size={12} />
        Assessed 8 minutes ago · click any marker on the map to inspect it
      </div>
    </aside>
  )
}

function RiskDistribution() {
  const data = [
    { name: "Critical", value: 4 },
    { name: "High", value: 11 },
    { name: "Medium", value: 18 },
    { name: "Low", value: 42 },
  ]
  return (
    <section className="panel dashboard-panel">
      <SectionTitle
        eyebrow="Portfolio exposure"
        title="Risk distribution"
        action={
          <Button variant="ghost">
            View report <ArrowRight size={14} />
          </Button>
        }
      />
      <div className="donut-wrap">
        <div className="donut">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                innerRadius={45}
                outerRadius={65}
                paddingAngle={3}
                dataKey="value"
                stroke="none"
              >
                {data.map((d) => (
                  <Cell key={d.name} fill={riskColors[(d.name as Risk)]} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="donut-total">
            <strong>75</strong>
            <span>assets</span>
          </div>
        </div>
        <div className="risk-legend">
          {data.map((d) => (
            <div key={d.name}>
              <span
                className="legend-dot"
                style={{ background: riskColors[(d.name as Risk)] }}
              />
              <span>{d.name}</span>
              <strong>{d.value}</strong>
              <small>{Math.round((d.value / 75) * 100)}%</small>
            </div>
          ))}
        </div>
      </div>
      <div className="panel-foot">
        <ArrowDownRight size={14} /> Critical exposure down{" "}
        <strong>8.4%</strong> over 30 days
      </div>
    </section>
  )
}

const agents = [
  ["Intake", "Completed"],
  ["Risk", "Completed"],
  ["Cascade", "Running"],
  ["Planner", "Waiting"],
  ["Critic", "Waiting"],
  ["Executor", "Waiting"],
]
function AgentPipeline({ onTrace }: { onTrace: () => void }) {
  return (
    <section className="panel dashboard-panel agent-panel">
      <SectionTitle
        eyebrow="Assessment run · CS-2841"
        title="AI agent pipeline"
        action={<Badge tone="running">In review</Badge>}
      />
      <div className="pipeline">
        {agents.map(([name, status], i) => (
          <div className="agent-step" key={name}>
            <div className={`agent-node ${status.toLowerCase()}`}>
              {status === "Completed" ? (
                <Check size={14} />
              ) : status === "Running" ? (
                <Activity size={14} />
              ) : (
                <span>{i + 1}</span>
              )}
            </div>
            <strong>{name}</strong>
            <span>{status}</span>
            {i < agents.length - 1 && <i />}
          </div>
        ))}
      </div>
      <div className="agent-insight">
        <Bot size={17} />
        <div>
          <strong>Cascade Agent is evaluating 14 dependency paths</strong>
          <p>2 plausible cross-organisation propagation routes identified.</p>
        </div>
      </div>
      <Button variant="secondary" className="full" onClick={onTrace}>
        <GitBranch size={15} />
        Open execution trace <ArrowRight size={14} />
      </Button>
    </section>
  )
}

function RecommendedAction({
  onApprove,
  onSimulate,
}: {
  onApprove: () => void
  onSimulate: () => void
}) {
  return (
    <section className="panel dashboard-panel action-panel">
      <SectionTitle
        eyebrow="Priority recommendation"
        title="Recommended action"
        action={<Badge tone="high">Approval required</Badge>}
      />
      <div className="recommendation">
        <div className="recommend-icon">
          <LockKeyhole size={18} />
        </div>
        <div>
          <strong>Isolate PG-003 and restrict external access</strong>
          <p>
            Preserve access through the internal jump host while the gateway is
            patched and revalidated.
          </p>
        </div>
      </div>
      <div className="risk-reduction">
        <div>
          <span>Current risk</span>
          <strong>79.13</strong>
        </div>
        <ArrowRight size={18} />
        <div>
          <span>Projected risk</span>
          <strong className="healthy">31.40</strong>
        </div>
        <div className="reduction">
          <span>−60%</span>reduction
        </div>
      </div>
      <div className="action-meta">
        <span>
          <Activity size={14} />
          Low operational impact
        </span>
        <span>
          <UserRound size={14} />2 approvers required
        </span>
      </div>
      <div className="action-buttons">
        <Button variant="primary" onClick={onApprove}>
          <Check size={15} />
          Approve & execute
        </Button>
        <Button variant="secondary" onClick={onSimulate}>
          <SlidersHorizontal size={15} />
          Simulate alternatives
        </Button>
      </div>
    </section>
  )
}

interface PageDrawerProps {
  openDrawer: (asset: Asset) => void
}

interface CommandCentreProps extends PageDrawerProps {
  openModal: (mode: string) => void
  openTrace: () => void
}

interface CommandCentreProps extends PageDrawerProps {
  openModal: (mode: string) => void
  openTrace: () => void
  onNavigateWithGlow: (page: Page) => void
}

function CommandCentre({ openDrawer, openModal, openTrace, onNavigateWithGlow }: CommandCentreProps) {
  const [selectedId, setSelectedId] = useState("PG-003")
  const selected = assetById.get(selectedId) ?? assets[0]
  const [statsInterval, setStatsInterval] = useState("1 hour")
  const [mapMode, setMapMode] = useState<"radware" | "national">("radware")

  return (
    <div className="relative w-full h-[calc(100vh-140px)] min-h-[760px] overflow-hidden bg-[#060b11] flex flex-col">
      {/* Top Map Mode Switcher Pill */}
      <div className="absolute top-3 left-1/2 -translate-x-1/2 z-40 flex items-center bg-[#0a121c]/95 backdrop-blur-md p-1 rounded-full border border-[rgba(40,184,197,0.3)] shadow-2xl">
        <button
          onClick={() => setMapMode("radware")}
          className={`px-3.5 py-1 rounded-full text-xs font-bold transition-all flex items-center gap-1.5 ${
            mapMode === "radware"
              ? "bg-[#28b8c5] text-[#060b11] shadow-[0_0_14px_rgba(40,184,197,0.8)]"
              : "text-[#9aaab8] hover:text-white"
          }`}
        >
          <span>🌐</span> Global Cyber Threat Matrix
        </button>
        <button
          onClick={() => setMapMode("national")}
          className={`px-3.5 py-1 rounded-full text-xs font-bold transition-all flex items-center gap-1.5 ${
            mapMode === "national"
              ? "bg-[#28b8c5] text-[#060b11] shadow-[0_0_14px_rgba(40,184,197,0.8)]"
              : "text-[#9aaab8] hover:text-white"
          }`}
        >
          <span>⚡</span> National Critical Grid (India)
        </button>
      </div>

      {/* Main Mid Section: Map at Centre-Left + Blended Dashboard at Right */}
      <div className="relative flex-1 flex overflow-hidden">
        {/* Map Canvas (Centre-Left) */}
        <div className="flex-1 relative h-full">
          {mapMode === "radware" ? (
            <CascadeWorldMap
              onNavigateDetail={(metric) => onNavigateWithGlow("Risk Intelligence")}
              onSelectCountry={(country) => {
                if (country === "india") onNavigateWithGlow("Security Operations")
                else onNavigateWithGlow("Risk Intelligence")
              }}
            />
          ) : (
            <IndiaMap
              selectedAssetId={selectedId}
              onAssetSelect={(asset) => {
                setSelectedId(asset.id)
                openDrawer(asset)
              }}
              liveAttackActive={false}
            />
          )}
        </div>

        {/* Right Blended HUD Dashboard Panel (Image 2 + Radware Vectors) */}
        <div className="w-[340px] xl:w-[380px] h-full overflow-y-auto bg-gradient-to-r from-transparent via-[#081018]/90 to-[#060b11] border-l border-[rgba(40,184,197,0.18)] backdrop-blur-xl p-4 flex flex-col gap-3 shadow-[-12px_0_35px_rgba(0,0,0,0.6)] z-20">
          <div className="flex items-center justify-between pb-2 border-b border-[#1b2836]">
            <div>
              <span className="text-white text-xs font-extrabold uppercase tracking-wider block">Live Threat Intel</span>
              <span className="text-[10px] text-[#28b8c5]">Interval: {statsInterval}</span>
            </div>
            <select
              value={statsInterval}
              onChange={(e) => setStatsInterval(e.target.value)}
              className="bg-[#101923] text-white border border-[#202e3a] rounded px-2 py-1 text-xs"
            >
              <option>1 hour</option>
              <option>12 hour</option>
              <option>24 hour</option>
              <option>Real-time</option>
            </select>
          </div>

          {/* Radial Gauges */}
          <div className="space-y-2">
            <RadialGauge
              label="Malicious Ingress"
              current="981"
              total="1.7k"
              percent={58}
              color="#e99a43"
              onDrillDown={() => onNavigateWithGlow("Risk Intelligence")}
            />
            <RadialGauge
              label="Monitored Perimeter Assets"
              current="2.4k"
              total="8k"
              percent={30}
              color="#42b98b"
              onDrillDown={() => onNavigateWithGlow("Asset Inventory")}
            />
          </div>

          {/* Alert Intensity */}
          <div className="p-3 rounded-lg bg-[#0b141e]/90 border border-[rgba(40,184,197,0.14)]">
            <AlertsIntensityChart onDrillDown={() => onNavigateWithGlow("Risk Intelligence")} />
          </div>

          {/* Top Attackers, Top Attacked & Vectors */}
          <GlobalAttackVectors onDrillDown={() => onNavigateWithGlow("Security Operations")} />

          {/* SOC Personnel On-Duty Stack */}
          <PersonnelStack onDrillDown={() => onNavigateWithGlow("AI Agent Activity")} />
        </div>
      </div>

      {/* Bottom Blended HUD Floor Panel */}
      <div className="w-full bg-gradient-to-t from-[#060b11] via-[#08121c]/95 to-transparent border-t border-[rgba(40,184,197,0.18)] backdrop-blur-xl px-5 py-2.5 z-20 flex flex-col gap-2">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-center">
          <BlockView360 onDrillDown={() => onNavigateWithGlow("Security Operations")} />
          <TotalAttacksStats onDrillDown={() => onNavigateWithGlow("Risk Intelligence")} />
        </div>
        <FrequencyStreamWaveform />
      </div>
    </div>
  )
}

function LiveAttackDemoPage({
  openDrawer,
  openModal,
}: {
  openDrawer: (asset: Asset) => void
  openModal: (mode: string) => void
}) {
  const [isIsolated, setIsIsolated] = useState(false)
  const [selectedId, setSelectedId] = useState("PG-003")

  return (
    <div className="workspace">
      {/* 1. Compromise Economics & Isolation Control Bar */}
      <CompromiseEconomicsPanel
        isIsolated={isIsolated}
        onToggleIsolation={() => setIsIsolated((prev) => !prev)}
        onResetDemo={() => setIsIsolated(false)}
      />

      {/* 2. Full Live Attack Trajectory Map with motion arrows */}
      <div className="relative w-full h-[620px] rounded-xl overflow-hidden border border-[#202e3a] bg-[#080d12] shadow-2xl">
        <IndiaMap
          selectedAssetId={selectedId}
          onAssetSelect={(asset) => {
            setSelectedId(asset.id)
            openDrawer(asset)
          }}
          liveAttackActive={true}
          isNodeIsolated={isIsolated}
          onToggleIsolation={() => setIsIsolated((prev) => !prev)}
        />
      </div>
    </div>
  )
}

function SecurityOperationsPage({
  openDrawer,
  openModal,
}: {
  openDrawer: (asset: Asset) => void
  openModal: (mode: string) => void
}) {
  const [selectedId, setSelectedId] = useState("PG-003")
  const selected = assetById.get(selectedId) ?? assets[0]
  const [activeTab, setActiveTab] = useState<"Overview" | "Detect" | "Recommend" | "Scenarios" | "ModelCard">("Overview")

  return (
    <div className="workspace space-y-4">
      {/* Top Incident Banner */}
      <IncidentStrip onInspectAsset={openDrawer} />

      {/* Top KPI Bar */}
      <Kpis />

      {/* PS-03 Sub-navigation Tabs */}
      <div className="flex items-center gap-1.5 flex-wrap pb-2 border-b border-[#202e3a]">
        <button
          className={`ps03-sector-btn ${activeTab === "Overview" ? "is-active" : ""}`}
          onClick={() => setActiveTab("Overview")}
        >
          Overview &amp; Attention Table
        </button>
        <button
          className={`ps03-sector-btn ${activeTab === "Detect" ? "is-active" : ""}`}
          onClick={() => setActiveTab("Detect")}
        >
          Detect &amp; Rules (R1–R6)
        </button>
        <button
          className={`ps03-sector-btn ${activeTab === "Recommend" ? "is-active" : ""}`}
          onClick={() => setActiveTab("Recommend")}
        >
          Recommend &amp; What-If
        </button>
        <button
          className={`ps03-sector-btn ${activeTab === "Scenarios" ? "is-active" : ""}`}
          onClick={() => setActiveTab("Scenarios")}
        >
          Scenario Replay (demo_week)
        </button>
        <button
          className={`ps03-sector-btn ${activeTab === "ModelCard" ? "is-active" : ""}`}
          onClick={() => setActiveTab("ModelCard")}
        >
          Model Card &amp; Trust
        </button>
      </div>

      {/* Tab Panels */}
      <div className="space-y-4">
        {activeTab === "Overview" && (
          <>
            <RankedNeedsAttentionTable
              onSelectAsset={(a) => {
                setSelectedId(a.id)
                openDrawer(a)
              }}
              onAction={(a) => {
                setSelectedId(a.id)
                openModal("contain")
              }}
            />
            <RiskOverTimeAndWhatChanged />
          </>
        )}

        {activeTab === "Detect" && (
          <DetectTelemetryAndRules
            onSelectAsset={(a) => {
              setSelectedId(a.id)
              openDrawer(a)
            }}
          />
        )}

        {activeTab === "Recommend" && (
          <RecommendPlannerPanel
            asset={selected}
            onExecuteAction={(act) => openModal(act.toLowerCase())}
          />
        )}

        {activeTab === "Scenarios" && (
          <ScenarioSimulationControls
            currentDay={5}
            onSetDay={(d) => console.log("Set simulated day:", d)}
            onInjectEvent={(assetId, episode) => {
              openModal("contain")
            }}
          />
        )}

        {activeTab === "ModelCard" && (
          <>
            <ModelCardView />
            <TrustGovernanceBlock />
          </>
        )}
      </div>
    </div>
  )
}

function InfrastructurePage({ openDrawer }: PageDrawerProps) {
  const [selectedId, setSelectedId] = useState<string | null>("PG-003")
  return (
    <div className="workspace workspace-map">
      <div className="workspace-tools">
        <div>
          <Badge tone="healthy">{assets.length} priority assets mapped</Badge>
          <span className="muted">75 monitored · 22 service zones · 13 dependency paths</span>
        </div>
        <div>
          <Button variant="primary">
            <Plus size={15} />
            Register asset
          </Button>
        </div>
      </div>
      <section className="map-stage map-stage-large">
        <TerrainMap
          wheelZoom="always"
          selectedAssetId={selectedId}
          onAssetSelect={(asset) => {
            setSelectedId(asset.id)
            openDrawer(asset)
          }}
        />
      </section>
    </div>
  )
}

function AssetInventory({
  search,
  openDrawer,
}: {
  search: string
  openDrawer: (a: Asset) => void
}) {
  const [risk, setRisk] = useState("All")
  const filtered = assets.filter(
    (a) =>
      (risk === "All" || a.level === risk) &&
      `${a.id} ${a.name} ${a.org}`.toLowerCase().includes(search.toLowerCase()),
  )
  return (
    <div className="workspace">
      <div className="filterbar">
        <label className="table-search">
          <Search size={15} />
          <input placeholder="Search asset inventory" defaultValue={search} />
        </label>
        <div className="filter-pills">
          {["All", "Critical", "High", "Medium", "Low"].map((r) => (
            <button
              className={risk === r ? "active" : ""}
              onClick={() => setRisk(r)}
              key={r}
            >
              {r}
            </button>
          ))}
        </div>
        <Button variant="secondary">
          <ListFilter size={15} />
          More filters
        </Button>
        <Button variant="secondary">
          Export <ExternalLink size={14} />
        </Button>
      </div>
      {/* Exposure Findings X1-X3 (Know Layer) */}
      <div className="ps03-card mb-4">
        <div className="ps03-card-header">
          <div>
            <h3>Exposure Findings (X1–X3)</h3>
            <p className="ps03-subtitle">Automated perimeter and boundary exposure detection</p>
          </div>
          <span className="ps03-badge-layer">Know · Exposure</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {exposureFindings.map((xf) => (
            <div key={xf.code} className="p-3 bg-[#111a23] rounded-lg border border-[#202e3a]">
              <div className="flex items-center justify-between">
                <span className="ps03-badge-layer font-bold">{xf.code}</span>
                <span className={`ps03-badge-sev sev-${xf.severity.toLowerCase()}`}>{xf.severity}</span>
              </div>
              <strong className="block text-sm text-[#e7edf3] mt-1.5">{xf.title}</strong>
              <p className="text-xs text-[#9aaab8] mt-1">{xf.description}</p>
              <div className="flex justify-between items-center text-[11px] text-[#687987] mt-2 pt-2 border-t border-[#202e3a]">
                <span>Target: <strong>{xf.assetId}</strong></span>
                <span>{xf.discovered}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="table-panel">
        <div className="table-summary">
          <span>
            <strong>{filtered.length}</strong> assets shown
          </span>
          <span>Last assessment sync · 8 min ago · Real CISA/KEV &amp; Synthetic</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Asset</th>
                <th>Organisation</th>
                <th>Type / Zone</th>
                <th>Internet Exposed</th>
                <th>Vulnerability &amp; KEV</th>
                <th>Likelihood</th>
                <th>Impact</th>
                <th>Risk Score</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {filtered.map((a) => {
                const pred = getAssetPredictDetails(a.id)
                const isInternet = a.exposure.includes("Internet")
                return (
                  <tr key={a.id} onClick={() => openDrawer(a)}>
                    <td>
                      <strong>{a.id}</strong>
                      <span>{a.name}</span>
                    </td>
                    <td>{a.org}</td>
                    <td>
                      <div>
                        <strong>{a.type}</strong>
                        <span className="block text-xs text-[#687987]">Zone: {a.zone}</span>
                      </div>
                    </td>
                    <td>
                      {isInternet ? (
                        <span className="ps03-badge-sev sev-critical">Internet-Facing</span>
                      ) : (
                        <span className="text-xs text-[#9aaab8]">{a.exposure}</span>
                      )}
                    </td>
                    <td>
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <Badge tone={a.vulnerability === "Patched" ? "healthy" : "high"}>
                          {a.vulnerability}
                        </Badge>
                        {pred.vulnData.kevBadge && (
                          <span className="ps03-badge-sev sev-critical text-[10px]">KEV</span>
                        )}
                      </div>
                    </td>
                    <td>{a.likelihood}%</td>
                    <td>{a.impact}%</td>
                    <td>
                      <div className="risk-cell">
                        <strong style={{ color: riskColors[a.level] }}>
                          {a.risk.toFixed(2)}
                        </strong>
                        <Badge tone={a.level}>{a.level}</Badge>
                      </div>
                    </td>
                    <td>
                      <ChevronRight size={16} />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {filtered.length === 0 && (
            <EmptyState
              title="No matching assets"
              body="Adjust your search or risk filters to see more results."
            />
          )}
        </div>
      </div>
    </div>
  )
}

function RiskIntelligence() {
  const [tab, setTab] = useState("Overview")
  return (
    <div className="workspace detail-workspace">
      <div className="entity-header">
        <div className="entity-icon">
          <Zap size={20} />
        </div>
        <div>
          <span>WGEC · Grid Utility</span>
          <h2>PG-003 · Northern Grid SCADA Gateway</h2>
        </div>
        <Badge tone="critical">Critical risk</Badge>
        <Button variant="secondary">Generate report</Button>
      </div>
      <div className="tabs">
        {[
          "Overview",
          "Vulnerabilities",
          "Model explanation",
          "Risk history",
          "Consequences",
        ].map((t) => (
          <button
            key={t}
            className={tab === t ? "active" : ""}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </div>
      <div className="risk-intel-grid">
        <section className="panel score-card">
          <span>Compromise likelihood</span>
          <strong>82%</strong>
          <div className="mini-bar">
            <i style={{ width: "82%" }} />
          </div>
          <p>Probability of compromise within the assessment horizon.</p>
          <small>+11% after advisory ingestion</small>
        </section>
        <section className="panel score-card">
          <span>Operational impact</span>
          <strong>95%</strong>
          <div className="mini-bar impact">
            <i style={{ width: "95%" }} />
          </div>
          <p>Severity if the asset becomes unavailable or untrusted.</p>
          <small>Critical service dependency</small>
        </section>
        <section className="panel score-card final">
          <span>Final risk score</span>
          <strong>79.13</strong>
          <div className="mini-bar">
            <i style={{ width: "79.13%" }} />
          </div>
          <p>Combined likelihood, impact and control effectiveness.</p>
          <small>Critical threshold · 75</small>
        </section>
        <section className="panel explanation-card">
          <SectionTitle
            eyebrow="Model explanation"
            title="Why this asset is high risk"
          />
          <div className="factor-list">
            {[
              ["Internet-facing management interface", "+18.4"],
              ["Known exploited vulnerability", "+16.9"],
              ["Privileged trust relationship", "+12.6"],
              ["Network segmentation control", "−7.2"],
            ].map(([f, v]) => (
              <div key={f}>
                <span>{f}</span>
                <strong className={v.startsWith("−") ? "healthy" : ""}>
                  {v}
                </strong>
              </div>
            ))}
          </div>
          <div className="model-note">
            <Sparkles size={16} />
            <p>
              These factors explain 71% of this assessment. Model version{" "}
              <strong>CRI-4.8</strong>.
            </p>
          </div>
        </section>
        <section className="panel consequence-card">
          <SectionTitle
            eyebrow="Cross-organisation"
            title="Downstream consequences"
          />
          <div className="consequence-flow">
            <div>
              <Zap size={16} />
              <strong>PG-003</strong>
              <span>Initial access</span>
            </div>
            <ArrowRight />
            <div>
              <Waves size={16} />
              <strong>JB-014</strong>
              <span>Pressure loss</span>
            </div>
            <ArrowRight />
            <div>
              <Hospital size={16} />
              <strong>AI-021</strong>
              <span>Clinical delay</span>
            </div>
          </div>
          <p>
            Estimated time to consequential impact: <strong>4–7 hours</strong>{" "}
            without containment.
          </p>
        </section>
      </div>
    </div>
  )
}

function AgentActivity({ openTrace }: { openTrace: () => void }) {
  const runs = [
    [
      "CS-2841",
      "PG-003 risk reassessment",
      "Cascade Agent",
      "Running",
      "8 min ago",
      "14 paths evaluated",
    ],
    [
      "CS-2839",
      "CVE advisory intake",
      "Intake Agent",
      "Completed",
      "24 min ago",
      "8 assets matched",
    ],
    [
      "CS-2836",
      "Containment plan review",
      "Critic Agent",
      "Failed",
      "1h ago",
      "Constraint data missing",
    ],
    [
      "CS-2828",
      "Weekly portfolio scan",
      "Risk Agent",
      "Completed",
      "Yesterday",
      "75 assets assessed",
    ],
  ]
  return (
    <div className="workspace">
      <div className="workspace-tools">
        <div className="filter-pills">
          <button className="active">All runs</button>
          <button>Running</button>
          <button>Completed</button>
          <button>Failed</button>
        </div>
        <Button variant="secondary">
          <Filter size={15} />
          Filter agents
        </Button>
      </div>
      <div className="trace-grid">
        {runs.map(([id, title, agent, status, time, output]) => (
          <button onClick={openTrace} className="trace-card panel" key={id}>
            <div className={`trace-state ${status.toLowerCase()}`}>
              {status === "Failed" ? (
                <X />
              ) : status === "Completed" ? (
                <Check />
              ) : (
                <Activity />
              )}
            </div>
            <div>
              <span>
                {id} · {time}
              </span>
              <strong>{title}</strong>
              <p>{agent}</p>
            </div>
            <div className="trace-output">
              <span>Latest output</span>
              <strong>{output}</strong>
            </div>
            <Badge tone={status}>{status}</Badge>
            <ChevronRight />
          </button>
        ))}
      </div>
    </div>
  )
}

function RemediationCentre({ openModal }: { openModal: (m: string) => void }) {
  const [selected, setSelected] = useState(0)
  const plans = [
    {
      name: "Targeted isolation",
      risk: 31.4,
      reduction: 60,
      impact: "Low",
      time: "15 min",
      recommended: true,
    },
    {
      name: "Emergency patch",
      risk: 38.2,
      reduction: 52,
      impact: "Medium",
      time: "2–4 hrs",
      recommended: false,
    },
    {
      name: "Full network isolation",
      risk: 18.7,
      reduction: 76,
      impact: "Severe",
      time: "10 min",
      recommended: false,
    },
  ]
  return (
    <div className="workspace">
      <div className="remediation-intro">
        <div>
          <Badge tone="critical">PG-003 · Critical</Badge>
          <h2>Compare containment strategies</h2>
          <p>
            Projected outcomes account for dependency risk, operational
            constraints and existing controls.
          </p>
        </div>
        <Button variant="secondary" onClick={() => openModal("simulate")}>
          <SlidersHorizontal size={15} />
          New simulation
        </Button>
      </div>
      <div className="plan-grid">
        {plans.map((p, i) => (
          <button
            key={p.name}
            onClick={() => setSelected(i)}
            className={`plan-card panel ${selected === i ? "selected" : ""}`}
          >
            {p.recommended && <Badge tone="healthy">AI recommended</Badge>}
            <div className="plan-check">
              {selected === i && <Check size={13} />}
            </div>
            <h3>{p.name}</h3>
            <div className="plan-risk">
              <span>Projected risk</span>
              <strong>{p.risk}</strong>
              <small>−{p.reduction}%</small>
            </div>
            <div className="plan-details">
              <div>
                <span>Operational impact</span>
                <strong>{p.impact}</strong>
              </div>
              <div>
                <span>Time to implement</span>
                <strong>{p.time}</strong>
              </div>
            </div>
          </button>
        ))}
      </div>
      <section className="panel approval-panel">
        <div>
          <SectionTitle eyebrow="Selected plan" title={plans[selected].name} />
          <p>
            Restrict external access at the edge firewall, revoke active
            sessions and preserve the internal managed jump path.
          </p>
        </div>
        <div className="approval-route">
          <span>Approval route</span>
          <div>
            <span className="approver">AL</span>
            <span>Security lead</span>
            <ArrowRight />
            <span className="approver">RO</span>
            <span>Operations owner</span>
          </div>
        </div>
        <div className="action-buttons">
          <Button variant="primary" onClick={() => openModal("approve")}>
            <Check size={15} />
            Submit for approval
          </Button>
          <Button variant="secondary">Save draft</Button>
        </div>
      </section>
    </div>
  )
}

function BlockchainAudit() {
  const records = [
    [
      "0x84A…19F",
      "Dependency attestation",
      "WGEC ↔ MetroWater",
      "Verified",
      "Today · 09:42",
    ],
    [
      "0x17C…8D2",
      "Remediation approval",
      "Plan RP-4492",
      "Verified",
      "Yesterday · 16:18",
    ],
    [
      "0xC21…3AA",
      "Organisation registration",
      "CCMN",
      "Verified",
      "12 Jun · 11:05",
    ],
    [
      "0x991…E40",
      "Asset ownership update",
      "JB-014",
      "Pending",
      "12 Jun · 10:31",
    ],
  ]
  return (
    <div className="workspace">
      <div className="audit-summary">
        <div className="panel">
          <Blocks size={19} />
          <span>Verified records</span>
          <strong>1,248</strong>
          <small>100% integrity</small>
        </div>
        <div className="panel">
          <FileCheck2 size={19} />
          <span>Dependency attestations</span>
          <strong>18</strong>
          <small>Across 3 organisations</small>
        </div>
        <div className="panel">
          <Clock3 size={19} />
          <span>Pending verification</span>
          <strong>01</strong>
          <small>Submitted 34m ago</small>
        </div>
      </div>
      <section className="panel audit-table">
        <SectionTitle
          eyebrow="Immutable activity record"
          title="Audit ledger"
          action={<Button variant="secondary">Verify record</Button>}
        />
        <table>
          <thead>
            <tr>
              <th>Transaction</th>
              <th>Record type</th>
              <th>Subject</th>
              <th>Status</th>
              <th>Timestamp</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {records.map((r) => (
              <tr key={r[0]}>
                <td>
                  <code>{r[0]}</code>
                </td>
                <td>{r[1]}</td>
                <td>{r[2]}</td>
                <td>
                  <Badge tone={r[3] === "Verified" ? "healthy" : "medium"}>
                    {r[3]}
                  </Badge>
                </td>
                <td>{r[4]}</td>
                <td>
                  <ExternalLink size={14} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  )
}

function SettingsPage() {
  return (
    <div className="workspace settings-grid">
      <aside className="settings-nav panel">
        <button className="active">General</button>
        <button>Organisations</button>
        <button>Risk model</button>
        <button>Notifications</button>
        <button>Access control</button>
        <button>Integrations</button>
      </aside>
      <section className="panel settings-content">
        <SectionTitle
          eyebrow="Workspace preferences"
          title="General settings"
        />
        <div className="setting-row">
          <div>
            <strong>Assessment horizon</strong>
            <p>Time window used by compromise likelihood models.</p>
          </div>
          <Button variant="secondary">
            30 days <ChevronDown size={14} />
          </Button>
        </div>
        <div className="setting-row">
          <div>
            <strong>Human approval threshold</strong>
            <p>Require review before actions above this operational impact.</p>
          </div>
          <Button variant="secondary">
            Medium impact <ChevronDown size={14} />
          </Button>
        </div>
        <div className="setting-row">
          <div>
            <strong>Cross-organisation sharing</strong>
            <p>Share signed dependency evidence with registered partners.</p>
          </div>
          <button className="switch active">
            <span />
          </button>
        </div>
        <div className="setting-row">
          <div>
            <strong>Prototype mode</strong>
            <p>Clearly label actions that are not connected to a backend.</p>
          </div>
          <button className="switch active">
            <span />
          </button>
        </div>
        <Button variant="primary">Save preferences</Button>
      </section>
    </div>
  )
}

interface EmptyStateProps {
  title: string
  body: string
}

function EmptyState({ title, body }: EmptyStateProps) {
  return (
    <div className="empty-state">
      <Search size={24} />
      <strong>{title}</strong>
      <p>{body}</p>
    </div>
  )
}

function DetailDrawer({
  asset,
  onClose,
}: {
  asset: Asset | null
  onClose: () => void
}) {
  if (!asset) return null
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer">
        <div className="drawer-head">
          <div>
            <span>Asset detail</span>
            <h2>{asset.id}</h2>
          </div>
          <Button variant="ghost" onClick={onClose}>
            <PanelRightClose size={20} />
          </Button>
        </div>
        <div className="drawer-title">
          <div className="entity-icon">
            <Zap size={20} />
          </div>
          <div>
            <strong>{asset.name}</strong>
            <span>
              {asset.org} · {asset.type}
            </span>
          </div>
          <Badge tone={asset.level}>{asset.level}</Badge>
        </div>
        <div className="drawer-score">
          <div>
            <span>Risk score</span>
            <strong style={{ color: riskColors[asset.level] }}>
              {asset.risk.toFixed(2)}
            </strong>
          </div>
          <div>
            <span>Likelihood</span>
            <strong>{asset.likelihood}%</strong>
          </div>
          <div>
            <span>Impact</span>
            <strong>{asset.impact}%</strong>
          </div>
        </div>
        {/* 1. Predict Layer: Risk Gauge & Basis Points, SHAP 'Why' Panel, Holt Trend */}
        <div className="drawer-section">
          <h3>Predict Analysis (PS-03 Layer)</h3>
          <PredictShapAndTrendPanel asset={asset} />
        </div>

        {/* 2. Impact Layer: Cascade Preview & Before/After Containment Toggle */}
        <div className="drawer-section">
          <h3>Impact Assessment (Cascade)</h3>
          <CascadePreviewPanel asset={asset} />
        </div>

        {/* 3. Vulnerability Panel (Know Layer) */}
        <div className="drawer-section">
          <h3>Vulnerability Intelligence</h3>
          {(() => {
            const pred = getAssetPredictDetails(asset.id)
            const v = pred.vulnData
            return (
              <div className="info-list">
                <div>
                  <span>CVE ID</span>
                  <strong className="text-[#e45b5b]">{v.cveId}</strong>
                </div>
                <div>
                  <span>CVSS / EPSS</span>
                  <strong>{v.cvss.toFixed(1)} / {(v.epss * 100).toFixed(1)}%</strong>
                </div>
                <div>
                  <span>CISA KEV Status</span>
                  {v.kevBadge ? (
                    <span className="ps03-badge-sev sev-critical">Listed in KEV</span>
                  ) : (
                    <span className="text-xs text-[#9aaab8]">Not in KEV</span>
                  )}
                </div>
                <div>
                  <span>Patch Age</span>
                  <strong>{v.patchAgeDays} days unpatched</strong>
                </div>
                <div>
                  <span>Data Source</span>
                  <span className="text-xs font-semibold text-[#28b8c5]">{v.source}</span>
                </div>
              </div>
            )
          })()}
        </div>

        {/* 4. Asset Context & Exposure */}
        <div className="drawer-section">
          <h3>Asset Context</h3>
          <div className="info-list">
            <div>
              <span>Exposure</span>
              <strong className={asset.exposure.includes("Internet") ? "text-[#e45b5b]" : ""}>
                {asset.exposure}
              </strong>
            </div>
            <div>
              <span>Zone</span>
              <strong>{asset.zone}</strong>
            </div>
            <div>
              <span>Location</span>
              <strong>{asset.location}</strong>
            </div>
            <div>
              <span>Data Confidence</span>
              <strong>High · 94%</strong>
            </div>
          </div>
        </div>

        <div className="drawer-actions">
          <Button variant="primary">Open risk intelligence</Button>
          <Button variant="secondary">View asset record</Button>
        </div>
      </aside>
    </>
  )
}

interface ModalProps {
  mode: string | null
  onClose: () => void
}

function Modal({ mode, onClose }: ModalProps) {
  const [done, setDone] = useState(false)
  if (!mode) return null
  const isSim = mode === "simulate"
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <div className="modal panel">
        <div className="modal-head">
          <div className={`modal-icon ${isSim ? "" : "danger"}`}>
            {isSim ? <SlidersHorizontal /> : <ShieldAlert />}
          </div>
          <div>
            <span>
              {isSim ? "What-if simulation" : "Human approval required"}
            </span>
            <h2>
              {isSim
                ? "Simulate containment alternatives"
                : "Review high-impact action"}
            </h2>
          </div>
          <Button variant="ghost" onClick={onClose}>
            <X size={19} />
          </Button>
        </div>
        {done ? (
          <div className="success-state">
            <Check size={26} />
            <h3>Prototype request recorded</h3>
            <p>
              No backend execution occurred. In production, this request would
              enter the organisation approval queue.
            </p>
            <Button variant="primary" onClick={onClose}>
              Close
            </Button>
          </div>
        ) : (
          <>
            <div className="modal-body">
              <div className="prototype-callout">
                <AlertTriangle size={16} />
                <p>
                  <strong>Prototype interaction</strong> — this demo will not
                  change live infrastructure.
                </p>
              </div>
              <div className="modal-action-summary">
                <strong>
                  {isSim
                    ? "Compare controls for PG-003"
                    : "Isolate WG-003 and restrict external access"}
                </strong>
                <p>
                  {isSim
                    ? "Model risk reduction against operational constraints without affecting live systems."
                    : "This action may terminate active remote sessions. Two independent approvals are required."}
                </p>
              </div>
              {!isSim && (
                <label className="approval-check">
                  <input type="checkbox" />
                  <span>
                    I reviewed the operational impact and rollback procedure.
                  </span>
                </label>
              )}
            </div>
            <div className="modal-footer">
              <Button variant="secondary" onClick={onClose}>
                Cancel
              </Button>
              <Button variant="primary" onClick={() => setDone(true)}>
                {isSim ? "Run prototype simulation" : "Submit approval request"}
              </Button>
            </div>
          </>
        )}
      </div>
    </>
  )
}

interface TraceDrawerProps {
  open: boolean
  onClose: () => void
}

function TraceDrawer({ open, onClose }: TraceDrawerProps) {
  const [tab, setTab] = useState("Output")
  if (!open) return null
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer trace-drawer">
        <div className="drawer-head">
          <div>
            <span>Execution trace</span>
            <h2>CS-2841</h2>
          </div>
          <Button variant="ghost" onClick={onClose}>
            <X size={20} />
          </Button>
        </div>
        <div className="trace-title">
          <Badge tone="running">Running</Badge>
          <h3>Cross-organisation cascade assessment</h3>
          <p>Started today at 09:48 · Cascade Agent</p>
        </div>
        <div className="tabs">
          {["Input", "Output", "Events", "Errors"].map((t) => (
            <button
              className={tab === t ? "active" : ""}
              onClick={() => setTab(t)}
              key={t}
            >
              {t}
            </button>
          ))}
        </div>
        <div className="code-panel">
          <div>
            <span>agent</span>
            <code>cascade-agent@2.4.1</code>
          </div>
          <div>
            <span>assessment_id</span>
            <code>CS-2841</code>
          </div>
          <div>
            <span>paths_evaluated</span>
            <code>14</code>
          </div>
          <div>
            <span>confirmed_paths</span>
            <code>1</code>
          </div>
          <div>
            <span>potential_paths</span>
            <code>2</code>
          </div>
          <div>
            <span>result</span>
            <code>{`{"source":"PG-003","downstream":["JB-014","AI-021"],"confidence":0.86}`}</code>
          </div>
        </div>
        <div className="drawer-section">
          <h3>Agent reasoning summary</h3>
          <p>
            The agent identified an authenticated trust relationship from the
            remote access gateway to grid control, then followed signed
            dependencies to water telemetry and hospital service continuity.
          </p>
        </div>
        <div className="trace-disclaimer">
          <LockKeyhole size={15} />
          Inputs and outputs are retained for audit review.
        </div>
      </aside>
    </>
  )
}

export default function App() {
  const [page, setPage] = useState<Page>("Command Centre")
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [drawerAsset, setDrawerAsset] = useState<Asset | null>(null)
  const [modal, setModal] = useState<string | null>(null)
  const [traceOpen, setTraceOpen] = useState(false)
  const [search, setSearch] = useState("")
  const [simulatedDay, setSimulatedDay] = useState(6)
  const [selectedSector, setSelectedSector] = useState("All Sectors")
  const [incidentsOpen, setIncidentsOpen] = useState(false)
  const [glowingNav, setGlowingNav] = useState<string | null>(null)

  const handleNavigateWithGlow = (targetPage: Page) => {
    setPage(targetPage)
    setGlowingNav(targetPage)
    setTimeout(() => {
      setGlowingNav(null)
    }, 3500)
  }

  const content = useMemo(() => {
    switch (page) {
      case "Command Centre":
        return (
          <CommandCentre
            openDrawer={setDrawerAsset}
            openModal={setModal}
            openTrace={() => setTraceOpen(true)}
            onNavigateWithGlow={handleNavigateWithGlow}
          />
        )
      case "Live Attack Demo":
        return (
          <LiveAttackDemoPage
            openDrawer={setDrawerAsset}
            openModal={setModal}
          />
        )
      case "Security Operations":
        return (
          <SecurityOperationsPage
            openDrawer={setDrawerAsset}
            openModal={setModal}
          />
        )
      case "Infrastructure View":
        return <InfrastructurePage openDrawer={setDrawerAsset} />
      case "Asset Inventory":
        return <AssetInventory search={search} openDrawer={setDrawerAsset} />
      case "Risk Intelligence":
        return <RiskIntelligence />
      case "AI Agent Activity":
        return <AgentActivity openTrace={() => setTraceOpen(true)} />
      case "Remediation Centre":
        return <RemediationCentre openModal={setModal} />
      case "Blockchain Audit":
        return <BlockchainAudit />
      case "Settings":
        return <SettingsPage />
    }
  }, [page, search])

  return (
    <div className="app-shell">
      {/* 1. Left Vertical Hover Navbar with Glow Effect */}
      <LeftHoverNavbar
        page={page}
        setPage={handleNavigateWithGlow}
        glowingNav={glowingNav}
      />

      {/* Main Workspace (Offset for collapsed 64px navbar) */}
      <main className="main-shell-hover">
        <GlobalSimulationBanner />

        <Header
          page={page}
          onMenu={() => setSidebarOpen(true)}
          onSearch={setSearch}
          onToggleIncidents={() => setIncidentsOpen((v) => !v)}
          activeIncidentsCount={2}
        />

        <GlobalClockAndModelBadge
          simulatedDay={simulatedDay}
          onDayChange={(delta) => setSimulatedDay((d) => Math.max(1, Math.min(6, d + delta)))}
          onReset={() => setSimulatedDay(1)}
          selectedSector={selectedSector}
          onSectorChange={setSelectedSector}
        />

        {incidentsOpen && (
          <div className="ps03-incidents-dropdown glass-panel">
            <div className="ps03-dropdown-title">
              <Flame size={15} color="#f87171" />
              <strong>Active Incidents (2)</strong>
            </div>
            <div
              className="ps03-dropdown-item"
              onClick={() => {
                const a = assetById.get("PG-003")
                if (a) setDrawerAsset(a)
                setIncidentsOpen(false)
              }}
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-white">PG-003 — Primary Substation SCADA</span>
                <span className="badge badge-critical text-xs">CRITICAL</span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">Trigger: Exploit Attempt + Lateral Ping · Age: 12m</p>
            </div>
            <div
              className="ps03-dropdown-item"
              onClick={() => {
                const a = assetById.get("PG-019")
                if (a) setDrawerAsset(a)
                setIncidentsOpen(false)
              }}
            >
              <div className="flex items-center justify-between">
                <span className="font-semibold text-white">PG-019 — Perimeter Telemetry Gateway</span>
                <span className="badge badge-high text-xs">HIGH</span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">Trigger: Suspicious Ingress Beacon · Age: 41m</p>
            </div>
          </div>
        )}

        {content}
      </main>
      <DetailDrawer asset={drawerAsset} onClose={() => setDrawerAsset(null)} />
      <Modal mode={modal} onClose={() => setModal(null)} />
      <TraceDrawer open={traceOpen} onClose={() => setTraceOpen(false)} />
    </div>
  )
}
