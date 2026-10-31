import { useState, useMemo } from "react"
import {
  AlertTriangle,
  Check,
  ChevronRight,
  Clock,
  Database,
  ExternalLink,
  Flame,
  Info,
  Layers,
  Lock,
  Play,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldAlert,
  Sliders,
  TrendingDown,
  TrendingUp,
  User,
  Zap,
  Activity,
  FileText,
  Radio,
  SlidersHorizontal,
  Workflow,
  Sparkles,
  Cpu,
  GitBranch,
} from "lucide-react"
import {
  rulesMetrics,
  detectionsData,
  exposureFindings,
  whatChangedFeed,
  riskTimelineData,
  demoWeekScript,
  modelCardData,
  getAssetPredictDetails,
  type DetectionEvent,
  type WhatChangedItem,
  type RiskTimePoint,
} from "../data/cascadeshieldData"
import {
  assets,
  assetById,
  dependencies,
  downstreamOf,
  organisations,
  type Asset,
  type OrgCode,
} from "../data/infrastructure"

// -----------------------------------------------------------------------------
// GLOBAL ELEMENTS
// -----------------------------------------------------------------------------

export function GlobalSimulationBanner() {
  return (
    <div className="ps03-simulation-banner">
      <div className="ps03-banner-content">
        <span className="ps03-banner-badge">SIMULATION ONLY</span>
        <span className="ps03-banner-text">
          Nothing shown is a real attacker or real incident. All data, traces and scenarios are synthetic and replayed for evaluation.
        </span>
      </div>
    </div>
  )
}

export function GlobalClockAndModelBadge({
  simulatedDay,
  onDayChange,
  onReset,
  selectedSector,
  onSectorChange,
}: {
  simulatedDay: number
  onDayChange: (delta: number) => void
  onReset: () => void
  selectedSector: string
  onSectorChange: (sec: string) => void
}) {
  return (
    <div className="ps03-global-bar">
      {/* Sector switcher */}
      <div className="ps03-sector-pills">
        <span className="ps03-label">Sector:</span>
        {["All Sectors", "Power (WGEC)", "Water (MetroWater)", "Hospital (CCMN)"].map((sec) => (
          <button
            key={sec}
            className={`ps03-sector-btn ${selectedSector === sec ? "is-active" : ""}`}
            onClick={() => onSectorChange(sec)}
          >
            {sec}
          </button>
        ))}
      </div>

      {/* Clock controls */}
      <div className="ps03-clock-controls">
        <div className="ps03-clock-display">
          <Clock size={13} className="text-[#28b8c5]" />
          <span>Simulated Day: <strong>Day {simulatedDay}</strong> of 7</span>
        </div>
        <button className="ps03-clock-btn" onClick={() => onDayChange(1)} title="Advance 1 day">
          +1 day
        </button>
        <button className="ps03-clock-btn" onClick={() => onDayChange(7)} title="Advance 7 days">
          +7 days
        </button>
        <button className="ps03-clock-btn is-reset" onClick={onReset} title="Reset simulation clock">
          <RotateCcw size={11} /> Reset
        </button>
      </div>

      {/* Model badge */}
      <div className="ps03-model-badge">
        <Cpu size={12} className="text-[#42b98b]" />
        <span>Model: <code>{modelCardData.versionHash}</code></span>
        <span className="ps03-badge-sep">·</span>
        <span className="text-[#9aaab8]">{modelCardData.source}</span>
        <span className="ps03-badge-tick" title="Fail-closed policy active & verified">
          <Check size={11} strokeWidth={3} /> fail-closed OK
        </span>
      </div>
    </div>
  )
}

// -----------------------------------------------------------------------------
// 7. REACTIVE PATH (INCIDENT STRIP & TIMELINE)
// -----------------------------------------------------------------------------

export function IncidentStrip({
  onInspectAsset,
}: {
  onInspectAsset: (asset: Asset) => void
}) {
  const [stage, setStage] = useState<number>(4) // 4 = awaiting approval
  const [approved, setApproved] = useState(false)
  const [released, setReleased] = useState(false)
  const [showLessons, setShowLessons] = useState(false)

  const steps = [
    "Event",
    "Triage",
    "Reassess",
    "Cascade preview",
    "Recommend",
    "Awaiting approval",
    "Approved",
    "Verified",
    "Released",
    "Lessons",
  ]

  const handleApprove = () => {
    setApproved(true)
    setStage(7) // verified
  }

  const handleRelease = () => {
    setReleased(true)
    setStage(8) // released
  }

  const targetAsset = assetById.get("PG-003")!

  return (
    <div className="ps03-incident-strip">
      <div className="ps03-incident-top">
        <div className="ps03-incident-alert-tag">
          <Flame size={14} className="animate-pulse" />
          <span>ACTIVE INCIDENT</span>
        </div>
        <div className="ps03-incident-summary">
          <strong>Asset:</strong>{" "}
          <button
            className="ps03-incident-asset-link"
            onClick={() => onInspectAsset(targetAsset)}
          >
            PG-003 (Northern Grid SCADA Gateway)
          </button>
          <span className="ps03-badge-sep">·</span>
          <strong>Trigger:</strong> R6 Exploit indicator (CVE-2024-3400)
          <span className="ps03-badge-sep">·</span>
          <strong>Age:</strong> 42m
        </div>

        {/* Approve & Release Buttons */}
        <div className="ps03-incident-actions">
          {!approved ? (
            <button className="ps03-btn-approve" onClick={handleApprove}>
              <Check size={12} /> Approve Containment
              <small>(not the on-chain gate)</small>
            </button>
          ) : !released ? (
            <button className="ps03-btn-release" onClick={handleRelease}>
              <Play size={12} /> Release Quarantine
              <small>(not the on-chain gate)</small>
            </button>
          ) : (
            <button
              className="ps03-btn-lessons"
              onClick={() => setShowLessons(!showLessons)}
            >
              <FileText size={12} /> Lessons Learned
            </button>
          )}
        </div>
      </div>

      {/* Incident Timeline */}
      <div className="ps03-incident-timeline">
        {steps.map((st, idx) => {
          const isDone = idx < stage
          const isCurrent = idx === stage
          return (
            <div
              key={st}
              className={`ps03-timeline-step ${isDone ? "is-done" : ""} ${
                isCurrent ? "is-current" : ""
              }`}
            >
              <div className="ps03-step-dot" />
              <span className="ps03-step-label">{st}</span>
              {idx < steps.length - 1 && <div className="ps03-step-line" />}
            </div>
          )
        })}
      </div>

      {/* Isolation verification check */}
      {approved && (
        <div className="ps03-isolation-check">
          <Check size={13} className="text-[#42b98b]" />
          <span>
            <strong>Isolation Verification:</strong> Graph topology check confirms PG-003 is severed from 400kV Substation Agra & SLDC links. Zero active downstream cascade propagation.
          </span>
        </div>
      )}

      {/* Lessons learned popup/card */}
      {showLessons && (
        <div className="ps03-lessons-card">
          <h4>Post-Incident Lessons Learned (Feeding Prevention Loop)</h4>
          <ul>
            <li><strong>Root Cause:</strong> Router ACL rule omitted management port 8443 during change ticket CHG-89412.</li>
            <li><strong>Prevention Rule Added:</strong> R5 Config change rule now evaluates perimeter WAN ACL diffs prior to commit.</li>
            <li><strong>Automated Ingestion:</strong> Vendor Tehri Dam link (PG-019) enrolled in mandatory hardware MFA token policy.</li>
          </ul>
        </div>
      )}
    </div>
  )
}

// -----------------------------------------------------------------------------
// 1. OVERVIEW: RANKED "NEEDS ATTENTION" TABLE
// -----------------------------------------------------------------------------

export function RankedNeedsAttentionTable({
  onSelectAsset,
  onAction,
}: {
  onSelectAsset: (asset: Asset) => void
  onAction: (asset: Asset) => void
}) {
  // Sort assets by risk descending
  const sortedAssets = useMemo(() => {
    return [...assets].sort((a, b) => b.risk - a.risk).slice(0, 7)
  }, [])

  return (
    <div className="ps03-card ps03-ranked-card">
      <div className="ps03-card-header">
        <div>
          <h3>Ranked "Needs Attention" Assets</h3>
          <p className="ps03-subtitle">Prioritized by multi-factor cascade risk & exploit severity</p>
        </div>
        <span className="ps03-badge-layer">Predict · Recommend</span>
      </div>

      <div className="ps03-table-responsive">
        <table className="ps03-table">
          <thead>
            <tr>
              <th>Asset</th>
              <th>Sector</th>
              <th>Risk (% & bp)</th>
              <th>Change</th>
              <th>Top Contributing Reason</th>
              <th>Protected Status</th>
              <th>Trend (7d)</th>
              <th className="text-right">Action</th>
            </tr>
          </thead>
          <tbody>
            {sortedAssets.map((asset) => {
              const details = getAssetPredictDetails(asset.id)
              const riskBp = Math.round(asset.risk * 100)
              const deltaBp = asset.level === "Critical" ? +140 : asset.level === "High" ? +65 : -35
              const topReason = details.shapFactors[0]?.feature || "High exposure score"

              return (
                <tr key={asset.id} onClick={() => onSelectAsset(asset)} className="ps03-row-clickable">
                  <td>
                    <div className="ps03-asset-cell">
                      <strong>{asset.id}</strong>
                      <span>{asset.name}</span>
                    </div>
                  </td>
                  <td>
                    <span className={`ps03-sector-tag org-${asset.org.toLowerCase()}`}>
                      {asset.org}
                    </span>
                  </td>
                  <td>
                    <div className="ps03-risk-cell">
                      <span className={`ps03-risk-badge level-${asset.level.toLowerCase()}`}>
                        {asset.risk.toFixed(1)}%
                      </span>
                      <small>{riskBp} bp</small>
                    </div>
                  </td>
                  <td>
                    <span className={`ps03-delta-tag ${deltaBp > 0 ? "is-up" : "is-down"}`}>
                      {deltaBp > 0 ? `↑ +${deltaBp} bp` : `↓ ${deltaBp} bp`}
                    </span>
                  </td>
                  <td>
                    <span className="ps03-reason-cell" title={topReason}>
                      {topReason}
                    </span>
                  </td>
                  <td>
                    {details.protectedLifeCritical ? (
                      <span className="ps03-protected-tag">
                        <Shield size={11} /> Life-Critical
                      </span>
                    ) : (
                      <span className="text-[#687987] text-xs">Standard</span>
                    )}
                  </td>
                  <td>
                    <div className="ps03-sparkline-wrap">
                      <svg width="60" height="20" className="ps03-sparkline">
                        <polyline
                          fill="none"
                          stroke={deltaBp > 0 ? "#e45b5b" : "#42b98b"}
                          strokeWidth="1.5"
                          points={details.sparkline
                            .map((val, idx) => `${idx * 12},${20 - (val / 100) * 18}`)
                            .join(" ")}
                        />
                      </svg>
                    </div>
                  </td>
                  <td className="text-right">
                    <button
                      className="ps03-action-btn"
                      onClick={(e) => {
                        e.stopPropagation()
                        onAction(asset)
                      }}
                    >
                      Mitigate
                    </button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// -----------------------------------------------------------------------------
// 1. OVERVIEW: RISK-OVER-TIME CHART & "WHAT CHANGED" FEED
// -----------------------------------------------------------------------------

export function RiskOverTimeAndWhatChanged() {
  const [selectedDayMarker, setSelectedDayMarker] = useState<RiskTimePoint | null>(riskTimelineData[2])

  return (
    <div className="ps03-grid-2col">
      {/* Risk Over Time Chart with Markers */}
      <div className="ps03-card">
        <div className="ps03-card-header">
          <div>
            <h3>Risk Over Time</h3>
            <p className="ps03-subtitle">Org risk trajectory by day with event, patch & incident markers</p>
          </div>
          <span className="ps03-badge-layer">Predict</span>
        </div>

        <div className="ps03-chart-timeline-area">
          <svg viewBox="0 0 500 160" className="w-full h-40">
            {/* Horizontal gridlines */}
            <line x1="40" y1="20" x2="480" y2="20" stroke="rgba(40,184,197,0.1)" />
            <line x1="40" y1="60" x2="480" y2="60" stroke="rgba(40,184,197,0.1)" />
            <line x1="40" y1="100" x2="480" y2="100" stroke="rgba(40,184,197,0.1)" />
            <line x1="40" y1="140" x2="480" y2="140" stroke="rgba(40,184,197,0.1)" />

            <text x="10" y="24" fill="#687987" fontSize="10">80%</text>
            <text x="10" y="64" fill="#687987" fontSize="10">60%</text>
            <text x="10" y="104" fill="#687987" fontSize="10">40%</text>
            <text x="10" y="144" fill="#687987" fontSize="10">20%</text>

            {/* Threshold reference line at 60% */}
            <line x1="40" y1="60" x2="480" y2="60" stroke="#e99a43" strokeDasharray="3 3" strokeWidth="1" />
            <text x="410" y="55" fill="#e99a43" fontSize="9">Threshold 60%</text>

            {/* Line graph */}
            <polyline
              fill="none"
              stroke="#28b8c5"
              strokeWidth="2.5"
              points={riskTimelineData
                .map((pt, i) => `${45 + i * 70},${150 - (pt.risk / 100) * 140}`)
                .join(" ")}
            />

            {/* Points & Event markers */}
            {riskTimelineData.map((pt, i) => {
              const cx = 45 + i * 70
              const cy = 150 - (pt.risk / 100) * 140
              const hasMarker = !!pt.eventMarker
              const isSelected = selectedDayMarker?.day === pt.day

              return (
                <g key={pt.day} onClick={() => setSelectedDayMarker(pt)} className="cursor-pointer">
                  {hasMarker && (
                    <circle
                      cx={cx}
                      cy={cy}
                      r="9"
                      fill={pt.eventMarker?.type === "incident" ? "rgba(228,91,91,0.25)" : "rgba(66,185,139,0.25)"}
                      className="animate-ping"
                    />
                  )}
                  <circle
                    cx={cx}
                    cy={cy}
                    r={isSelected ? 6 : 4}
                    fill={pt.eventMarker?.type === "incident" ? "#e45b5b" : pt.eventMarker?.type === "patch" ? "#42b98b" : "#28b8c5"}
                    stroke="#0b1118"
                    strokeWidth="2"
                  />
                  <text x={cx} y="156" fill="#9aaab8" fontSize="9" textAnchor="middle">
                    {pt.day.replace(" (Today)", "").replace(" (Forecast)", "*")}
                  </text>
                </g>
              )
            })}
          </svg>

          {/* Marker callout details */}
          {selectedDayMarker?.eventMarker && (
            <div className={`ps03-event-callout type-${selectedDayMarker.eventMarker.type}`}>
              <span className="ps03-callout-day">{selectedDayMarker.day}:</span>
              <strong>{selectedDayMarker.eventMarker.label}</strong>
              <span className="ml-auto text-xs">Risk: {selectedDayMarker.risk}% ({selectedDayMarker.riskBp} bp)</span>
            </div>
          )}
        </div>
      </div>

      {/* "What Changed" Feed (>= 100 bp movement) */}
      <div className="ps03-card">
        <div className="ps03-card-header">
          <div>
            <h3>"What Changed" Feed</h3>
            <p className="ps03-subtitle">Assets whose risk moved by at least 100 bp with root cause</p>
          </div>
          <span className="ps03-badge-layer">Proactive</span>
        </div>

        <div className="ps03-changed-feed">
          {whatChangedFeed.map((item) => (
            <div key={item.id} className="ps03-feed-item">
              <div className="ps03-feed-top">
                <strong>{item.assetId}</strong>
                <span className="text-[#9aaab8]">{item.assetName}</span>
                <span className={`ps03-delta-tag ${item.deltaBp > 0 ? "is-up" : "is-down"} ml-auto`}>
                  {item.deltaBp > 0 ? `+${item.deltaBp} bp` : `${item.deltaBp} bp`}
                </span>
              </div>
              <div className="ps03-feed-cause">{item.cause}</div>
              <div className="ps03-feed-meta">
                <span>{item.sector}</span>
                <span>·</span>
                <span>{item.timestamp}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// -----------------------------------------------------------------------------
// 3. DETECT (TELEMETRY AND RULES TABLE + RULE PERFORMANCE)
// -----------------------------------------------------------------------------

export function DetectTelemetryAndRules({
  onSelectAsset,
}: {
  onSelectAsset: (asset: Asset) => void
}) {
  return (
    <div className="ps03-grid-2col mt-4">
      {/* Detections table */}
      <div className="ps03-card">
        <div className="ps03-card-header">
          <div>
            <h3>Detections Table</h3>
            <p className="ps03-subtitle">Real-time alerts classified by detection rule R1-R6</p>
          </div>
          <span className="ps03-badge-layer">Detect</span>
        </div>

        <div className="ps03-table-responsive max-h-72 overflow-y-auto">
          <table className="ps03-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Asset</th>
                <th>Rule</th>
                <th>Severity</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {detectionsData.map((det) => (
                <tr key={det.id}>
                  <td className="text-xs text-[#9aaab8]">{det.time}</td>
                  <td>
                    <button
                      className="text-left font-semibold hover:text-[#28b8c5]"
                      onClick={() => {
                        const asset = assetById.get(det.assetId)
                        if (asset) onSelectAsset(asset)
                      }}
                    >
                      {det.assetId}
                    </button>
                  </td>
                  <td>
                    <span className="ps03-rule-tag">
                      <strong>{det.ruleId}</strong>: {det.ruleName}
                    </span>
                  </td>
                  <td>
                    <span className={`ps03-badge-sev sev-${det.severity.toLowerCase()}`}>
                      {det.severity}
                    </span>
                  </td>
                  <td className="text-xs max-w-xs truncate" title={det.evidence}>
                    {det.evidence}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Rule Performance Card (from rules_metrics.json) */}
      <div className="ps03-card">
        <div className="ps03-card-header">
          <div>
            <h3>Rule Performance (Precision & Recall)</h3>
            <p className="ps03-subtitle">Read live from <code>rules_metrics.json</code> for rules R1-R6</p>
          </div>
          <span className="ps03-badge-layer">Detect</span>
        </div>

        <div className="ps03-rule-grid">
          {rulesMetrics.map((r) => (
            <div key={r.id} className="ps03-rule-stat-card">
              <div className="flex items-center justify-between">
                <span className="ps03-rule-code">{r.id}</span>
                <span className="text-xs text-[#9aaab8]">{r.samples} samples</span>
              </div>
              <strong className="text-sm block mt-1">{r.name}</strong>

              <div className="mt-2 space-y-1">
                <div className="flex justify-between text-xs">
                  <span className="text-[#9aaab8]">Precision</span>
                  <span className="font-semibold text-[#42b98b]">{(r.precision * 100).toFixed(1)}%</span>
                </div>
                <div className="ps03-bar-track">
                  <div className="ps03-bar-fill bg-[#42b98b]" style={{ width: `${r.precision * 100}%` }} />
                </div>

                <div className="flex justify-between text-xs pt-1">
                  <span className="text-[#9aaab8]">Recall</span>
                  <span className="font-semibold text-[#28b8c5]">{(r.recall * 100).toFixed(1)}%</span>
                </div>
                <div className="ps03-bar-track">
                  <div className="ps03-bar-fill bg-[#28b8c5]" style={{ width: `${r.recall * 100}%` }} />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// -----------------------------------------------------------------------------
// 4. PREDICT: SHAP "WHY" PANEL, MISSING DATA, HOLT TREND
// -----------------------------------------------------------------------------

export function PredictShapAndTrendPanel({ asset }: { asset: Asset }) {
  const details = getAssetPredictDetails(asset.id)
  const riskBp = Math.round(asset.risk * 100)

  return (
    <div className="ps03-predict-panel">
      {/* Risk Gauge in Basis Points */}
      <div className="ps03-gauge-box">
        <div className="flex justify-between items-center mb-1">
          <span className="text-xs text-[#9aaab8]">Likelihood & Impact Model Risk:</span>
          <span className="text-sm font-bold text-[#e7edf3]">{asset.risk.toFixed(2)}%</span>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-black text-[#28b8c5]">{riskBp}</span>
          <span className="text-xs text-[#9aaab8]">basis points (bp)</span>
        </div>
        <div className="ps03-bar-track mt-2 h-2">
          <div
            className={`ps03-bar-fill ${asset.risk > 70 ? "bg-[#e45b5b]" : asset.risk > 45 ? "bg-[#e99a43]" : "bg-[#42b98b]"}`}
            style={{ width: `${asset.risk}%` }}
          />
        </div>
      </div>

      {/* SHAP "Why" Panel */}
      <div className="mt-4">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-[#9aaab8]">
            "Why" Panel: SHAP Feature Contributions
          </h4>
          <span className="text-[10px] text-[#687987]">Plain Language</span>
        </div>

        <div className="space-y-2 mt-2">
          {details.shapFactors.map((sf, idx) => (
            <div key={idx} className="ps03-shap-row">
              <span className="text-xs flex-1 text-[#e7edf3]">{sf.feature}</span>
              <span className={`text-xs font-bold ${sf.direction === "positive" ? "text-[#e45b5b]" : "text-[#42b98b]"}`}>
                {sf.bpDelta > 0 ? `+${sf.bpDelta} bp` : `${sf.bpDelta} bp`}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Missing-Data Indicator */}
      {details.missingDataIndicator && (
        <div className="ps03-missing-data-alert">
          <Info size={13} className="text-[#e99a43]" />
          <span>{details.missingDataIndicator}</span>
        </div>
      )}

      {/* Holt Forecast Trend Card */}
      <div className="ps03-trend-card mt-3">
        <div className="flex justify-between items-center">
          <span className="text-xs font-semibold text-[#e7edf3]">Holt Forecast Trend:</span>
          <span className="text-xs font-bold text-[#e99a43]">
            {details.holtForecastDays} days until threshold
          </span>
        </div>
        <p className="text-[11px] text-[#9aaab8] mt-1">
          Backtest error: <strong>4.27 days</strong> (vs 11.7 days for naive baseline forecast).
        </p>
      </div>

      {/* Telemetry Overlay Note */}
      {details.evidenceFloorActive && (
        <div className="ps03-evidence-floor-note">
          <Radio size={12} className="text-[#28b8c5]" />
          <span>Evidence floor applied (assumption): active alert rules clamp risk score.</span>
        </div>
      )}
    </div>
  )
}

// -----------------------------------------------------------------------------
// 5. IMPACT (CASCADE PREVIEW & BEFORE/AFTER TOGGLE)
// -----------------------------------------------------------------------------

export function CascadePreviewPanel({ asset }: { asset: Asset }) {
  const [containmentActive, setContainmentActive] = useState(false)
  const downstream = useMemo(() => downstreamOf(asset.id), [asset.id])

  const initialAffected = downstream.size + 1
  const protectedReached = [...downstream].filter((id) => assetById.get(id)?.level === "Critical").length
  const initialImpactScore = Math.min(100, (initialAffected * 18.5) + (protectedReached * 22))

  // When containment active: cascade severed!
  const currentAffected = containmentActive ? 1 : initialAffected
  const currentProtected = containmentActive ? 0 : protectedReached
  const currentImpactScore = containmentActive ? 18.5 : initialImpactScore

  return (
    <div className="ps03-cascade-panel">
      {/* Before / After toggle */}
      <div className="flex items-center justify-between pb-3 border-b border-[#293846]">
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-[#9aaab8]">
            Cascade Preview Graph
          </h4>
          <span className="text-xs text-[#687987]">Downstream failure propagation pathway</span>
        </div>
        <div className="ps03-toggle-wrap">
          <button
            className={`ps03-toggle-btn ${!containmentActive ? "is-active" : ""}`}
            onClick={() => setContainmentActive(false)}
          >
            Without Containment
          </button>
          <button
            className={`ps03-toggle-btn ${containmentActive ? "is-active" : ""}`}
            onClick={() => setContainmentActive(true)}
          >
            With Level 1 Containment
          </button>
        </div>
      </div>

      {/* Impact Numbers */}
      <div className="grid grid-cols-3 gap-3 my-3">
        <div className="ps03-stat-mini">
          <span className="text-[#9aaab8]">Services Affected</span>
          <strong className={containmentActive ? "text-[#42b98b]" : "text-[#e45b5b]"}>
            {currentAffected}
          </strong>
        </div>
        <div className="ps03-stat-mini">
          <span className="text-[#9aaab8]">Protected Nodes</span>
          <strong className={containmentActive ? "text-[#42b98b]" : "text-[#e99a43]"}>
            {currentProtected}
          </strong>
        </div>
        <div className="ps03-stat-mini">
          <span className="text-[#9aaab8]">Impact Score</span>
          <strong className={containmentActive ? "text-[#42b98b]" : "text-[#e45b5b]"}>
            {currentImpactScore.toFixed(0)} / 100
          </strong>
        </div>
      </div>

      {/* Cascade pathway node view */}
      <div className="ps03-cascade-graph-box">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="ps03-cascade-node root-node">{asset.id} ({asset.name})</span>
          {!containmentActive ? (
            <>
              <ChevronRight size={14} className="text-[#e45b5b]" />
              {[...downstream].map((downId) => {
                const downAsset = assetById.get(downId)
                return (
                  <span key={downId} className="ps03-cascade-node down-node">
                    {downId} {downAsset ? `(${downAsset.location})` : ""}
                  </span>
                )
              })}
            </>
          ) : (
            <>
              <span className="text-[#42b98b] font-bold text-xs">✕ SEVERED</span>
              <span className="ps03-cascade-node severed-node">
                Downstream isolated (400kV Substation, Jal Board & AIIMS protected)
              </span>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

// -----------------------------------------------------------------------------
// 6. RECOMMEND (PLANNER ACTION CARDS & WHAT-IF)
// -----------------------------------------------------------------------------

export function RecommendPlannerPanel({
  asset,
  onExecuteAction,
}: {
  asset: Asset
  onExecuteAction: (act: string) => void
}) {
  const [selectedAction, setSelectedAction] = useState<string>("ISOLATE_ASSET")

  const actionPlans = [
    {
      action: "RESTRICT_ACCESS",
      level: 1,
      title: "Enforce Perimeter MFA & Revoke VPN",
      riskBefore: asset.risk,
      riskAfter: Math.max(15, asset.risk - 28.5),
      preCheck: "Protected asset, so Level 1 only",
      activeInBase: true,
    },
    {
      action: "ISOLATE_ASSET",
      level: 1,
      title: "Isolate to Microsegmented Honeynet VLAN",
      riskBefore: asset.risk,
      riskAfter: Math.max(12, asset.risk - 51.0),
      preCheck: "Protected asset, Level 1 safe; zero grid trip",
      activeInBase: true,
    },
    {
      action: "ROTATE_CREDENTIALS",
      level: 2,
      title: "Immediate Active Directory & Kerberos Rotate",
      riskBefore: asset.risk,
      riskAfter: Math.max(20, asset.risk - 34.0),
      preCheck: "Requires secondary operator attestation",
      activeInBase: true,
    },
    {
      action: "ENABLE_MONITORING",
      level: 3,
      title: "Deep PCAP Telemetry Capture (Passive)",
      riskBefore: asset.risk,
      riskAfter: Math.max(30, asset.risk - 12.0),
      preCheck: "Level 3 inactive in base build",
      activeInBase: false,
    },
  ]

  const currentPlan = actionPlans.find((p) => p.action === selectedAction) || actionPlans[1]

  return (
    <div className="ps03-card mt-4">
      <div className="ps03-card-header">
        <div>
          <h3>Recommend (Planner) Action Cards & What-If Simulation</h3>
          <p className="ps03-subtitle">Containment policies with automated pre-check and instant risk simulation</p>
        </div>
        <span className="ps03-badge-layer">Recommend · Plan</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Action cards list */}
        <div className="space-y-2">
          {actionPlans.map((plan) => (
            <div
              key={plan.action}
              onClick={() => setSelectedAction(plan.action)}
              className={`ps03-action-card-select ${selectedAction === plan.action ? "is-selected" : ""}`}
            >
              <div className="flex items-center justify-between">
                <span className="ps03-action-name">{plan.action}</span>
                <span className={`ps03-level-tag ${plan.activeInBase ? "is-active" : "is-inactive"}`}>
                  Level {plan.level} {plan.activeInBase ? "(Active)" : "(Base Locked)"}
                </span>
              </div>
              <p className="text-xs text-[#e7edf3] mt-1">{plan.title}</p>
              <div className="flex items-center justify-between text-xs mt-2 pt-1 border-t border-[#293846]">
                <span className="text-[#9aaab8]">{plan.preCheck}</span>
                <span className="text-[#42b98b] font-bold">
                  {plan.riskBefore.toFixed(1)}% → {plan.riskAfter.toFixed(1)}%
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* What-If Panel */}
        <div className="ps03-whatif-box">
          <div className="flex items-center gap-2">
            <Sparkles size={14} className="text-[#28b8c5]" />
            <h4 className="text-sm font-semibold text-[#e7edf3]">What-If Simulation Engine</h4>
          </div>

          <div className="mt-3 p-3 bg-[#0e161e] rounded-lg border border-[#202e3a]">
            <span className="text-xs text-[#9aaab8]">Simulating execution of:</span>
            <div className="text-base font-bold text-[#28b8c5] mt-0.5">{currentPlan.action}</div>
            <p className="text-xs text-[#9aaab8] mt-1">{currentPlan.preCheck}</p>

            <div className="grid grid-cols-2 gap-3 mt-4 pt-3 border-t border-[#202e3a]">
              <div>
                <span className="text-xs text-[#9aaab8]">Risk Before</span>
                <div className="text-xl font-bold text-[#e45b5b]">{currentPlan.riskBefore.toFixed(1)}%</div>
                <small className="text-[#687987]">{Math.round(currentPlan.riskBefore * 100)} bp</small>
              </div>
              <div>
                <span className="text-xs text-[#9aaab8]">Risk After Action</span>
                <div className="text-xl font-bold text-[#42b98b]">{currentPlan.riskAfter.toFixed(1)}%</div>
                <small className="text-[#42b98b]">
                  -{Math.round((currentPlan.riskBefore - currentPlan.riskAfter) * 100)} bp drop
                </small>
              </div>
            </div>

            <button
              className="btn btn-primary w-full mt-4"
              disabled={!currentPlan.activeInBase}
              onClick={() => onExecuteAction(currentPlan.action)}
            >
              Dispatch Approval Request ({currentPlan.action})
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// -----------------------------------------------------------------------------
// 8. SCENARIO AND SIMULATION CONTROLS (DEMO_WEEK)
// -----------------------------------------------------------------------------

export function ScenarioSimulationControls({
  currentDay,
  onSetDay,
  onInjectEvent,
}: {
  currentDay: number
  onSetDay: (d: number) => void
  onInjectEvent: (assetId: string, episode: string) => void
}) {
  const [selectedAsset, setSelectedAsset] = useState<string>("PG-003")
  const [selectedEpisode, setSelectedEpisode] = useState<string>("Exploit indicator (CVE-2024-3400)")

  return (
    <div className="ps03-card mt-4">
      <div className="ps03-card-header">
        <div>
          <h3>Scenario & Simulation Controls (demo_week)</h3>
          <p className="ps03-subtitle">Replay multi-day cyber-physical threat cascade or inject custom synthetic episodes</p>
        </div>
        <span className="ps03-badge-layer">Scenario · Replay</span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Scenario Loader: demo_week script */}
        <div className="lg:col-span-2 space-y-2">
          {demoWeekScript.map((step) => {
            const isNow = step.day === currentDay
            return (
              <div
                key={step.day}
                onClick={() => onSetDay(step.day)}
                className={`ps03-script-row ${isNow ? "is-now" : ""}`}
              >
                <div className="flex items-center gap-2">
                  <span className="ps03-day-marker">Day {step.day}</span>
                  <strong>{step.title}</strong>
                  {isNow && <span className="ps03-now-badge">NOW AT DAY {currentDay}</span>}
                  <span className="text-xs text-[#9aaab8] ml-auto">Target: {step.targetAsset}</span>
                </div>
                <p className="text-xs text-[#9aaab8] mt-1">{step.description}</p>
              </div>
            )
          })}
        </div>

        {/* Inject-event form */}
        <div className="ps03-inject-box">
          <h4 className="text-sm font-semibold text-[#e7edf3] mb-2 flex items-center gap-2">
            <Zap size={13} className="text-[#e99a43]" /> Inject Custom Event
          </h4>

          <div className="space-y-3">
            <div>
              <label className="text-xs text-[#9aaab8] block mb-1">Target Asset:</label>
              <select
                className="ps03-select"
                value={selectedAsset}
                onChange={(e) => setSelectedAsset(e.target.value)}
              >
                {assets.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.id} · {a.name} ({a.location})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-[#9aaab8] block mb-1">Episode Type:</label>
              <select
                className="ps03-select"
                value={selectedEpisode}
                onChange={(e) => setSelectedEpisode(e.target.value)}
              >
                <option value="Auth failures (R1)">R1: Auth failures burst (Kerberos brute-force)</option>
                <option value="Remote access (R2)">R2: Remote access anomaly (MFA bypass)</option>
                <option value="Lateral movement (R3)">R3: Lateral movement (PsExec over SMB)</option>
                <option value="OT protocol (R4)">R4: OT protocol write (Modbus function 0x06)</option>
                <option value="Config change (R5)">R5: Config change (Unscheduled setpoint change)</option>
                <option value="Exploit indicator (R6)">R6: Exploit indicator (CVE-2024-3400)</option>
              </select>
            </div>

            <button
              className="btn btn-danger w-full mt-2"
              onClick={() => onInjectEvent(selectedAsset, selectedEpisode)}
            >
              Inject Episode to Telemetry Stream
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// -----------------------------------------------------------------------------
// 9. MODEL CARD VIEW
// -----------------------------------------------------------------------------

export function ModelCardView() {
  return (
    <div className="ps03-card mt-4">
      <div className="ps03-card-header">
        <div>
          <h3>CascadeShield Model Card</h3>
          <p className="ps03-subtitle">
            Model version: <code>{modelCardData.versionHash}</code> · Source: {modelCardData.source}
          </p>
        </div>
        <span className="ps03-badge-layer">Governance · AI</span>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 my-3">
        <div className="ps03-stat-mini">
          <span className="text-[#9aaab8]">ROC-AUC</span>
          <strong className="text-[#42b98b]">{modelCardData.rocAuc}</strong>
        </div>
        <div className="ps03-stat-mini">
          <span className="text-[#9aaab8]">PR-AUC</span>
          <strong className="text-[#28b8c5]">{modelCardData.prAuc}</strong>
        </div>
        <div className="ps03-stat-mini">
          <span className="text-[#9aaab8]">Brier Score</span>
          <strong className="text-[#e7edf3]">{modelCardData.brierScore}</strong>
        </div>
        <div className="ps03-stat-mini">
          <span className="text-[#9aaab8]">Top-k Precision</span>
          <strong className="text-[#42b98b]">{(modelCardData.topKPrecision * 100).toFixed(1)}%</strong>
        </div>
        <div className="ps03-stat-mini">
          <span className="text-[#9aaab8]">Oracle AUC</span>
          <strong className="text-[#d4a853]">{modelCardData.oracleAuc}</strong>
        </div>
      </div>

      {/* Baseline comparisons */}
      <div className="mt-4">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-[#9aaab8] mb-2">
          Comparison with Baselines
        </h4>
        <div className="ps03-table-responsive">
          <table className="ps03-table">
            <thead>
              <tr>
                <th>Model / Heuristic</th>
                <th>ROC-AUC</th>
                <th>PR-AUC</th>
                <th>Brier Score</th>
              </tr>
            </thead>
            <tbody>
              {modelCardData.baselines.map((bl) => (
                <tr key={bl.model} className={bl.model.includes("CascadeShield") ? "font-bold bg-[#16232e]" : ""}>
                  <td>{bl.model}</td>
                  <td className="text-[#42b98b]">{bl.rocAuc}</td>
                  <td className="text-[#28b8c5]">{bl.prAuc}</td>
                  <td>{bl.brier}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Training data note */}
      <div className="ps03-evidence-floor-note mt-3">
        <Info size={13} className="text-[#28b8c5]" />
        <span><strong>Training-data Note:</strong> {modelCardData.trainingNote}</span>
      </div>
    </div>
  )
}

// -----------------------------------------------------------------------------
// 10. TRUST AND GOVERNANCE (USP BLOCK)
// -----------------------------------------------------------------------------

export function TrustGovernanceBlock() {
  const [killSwitchArmed, setKillSwitchArmed] = useState(false)

  return (
    <div className="ps03-card mt-4">
      <div className="ps03-card-header">
        <div>
          <h3>Trust & Governance (On-Chain USP Block)</h3>
          <p className="ps03-subtitle">Cryptographic attestations, sealed envelopes and fail-closed rollback</p>
        </div>
        <span className="ps03-badge-layer">Trust · Chain</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 my-3">
        {/* Approval gate status */}
        <div className="ps03-stat-mini">
          <div className="flex items-center gap-1.5 text-xs text-[#9aaab8]">
            <Check size={12} className="text-[#42b98b]" /> Gate Status
          </div>
          <strong className="text-[#42b98b] text-sm">Dual Signed (2/2)</strong>
          <small className="text-[#687987]">ECDSA secp256k1 verified</small>
        </div>

        {/* Sealed envelope status */}
        <div className="ps03-stat-mini">
          <div className="flex items-center gap-1.5 text-xs text-[#9aaab8]">
            <Lock size={12} className="text-[#28b8c5]" /> Sealed Envelope
          </div>
          <strong className="text-[#28b8c5] text-sm">SEC-PRIV Enclave</strong>
          <small className="text-[#687987]">SHA-256 commit hash verified</small>
        </div>

        {/* Audit log block */}
        <div className="ps03-stat-mini">
          <div className="flex items-center gap-1.5 text-xs text-[#9aaab8]">
            <Activity size={12} className="text-[#d4a853]" /> On-Chain Block
          </div>
          <strong className="text-[#d4a853] text-sm">#18,492,041</strong>
          <small className="text-[#687987]">Tx: 0x7f4e...9a12</small>
        </div>

        {/* Kill switch & rollback */}
        <div className="ps03-stat-mini">
          <div className="flex items-center gap-1.5 text-xs text-[#9aaab8]">
            <ShieldAlert size={12} className="text-[#e45b5b]" /> Kill Switch
          </div>
          <div className="flex items-center justify-between mt-1">
            <span className={`text-xs font-bold ${killSwitchArmed ? "text-[#e45b5b]" : "text-[#42b98b]"}`}>
              {killSwitchArmed ? "ARMED (Fail-Closed)" : "STANDBY"}
            </span>
            <button
              className="text-[10px] px-2 py-0.5 rounded bg-[#202e3a] hover:bg-[#293846]"
              onClick={() => setKillSwitchArmed(!killSwitchArmed)}
            >
              Toggle
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
