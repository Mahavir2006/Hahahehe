// CascadeShield Comprehensive Data Engine
// Implements PS-03 Specification Layers (Know, Detect, Predict, Impact, Recommend, Proactive, Trust)

import rulesMetricsJson from "./rules_metrics.json"

export interface RuleMetric {
  id: string
  name: string
  precision: number
  recall: number
  f1: number
  samples: number
}

export const rulesMetrics: RuleMetric[] = rulesMetricsJson.rules

export interface DetectionEvent {
  id: string
  time: string
  assetId: string
  assetName: string
  ruleId: "R1" | "R2" | "R3" | "R4" | "R5" | "R6"
  ruleName: string
  severity: "Critical" | "High" | "Medium" | "Low"
  evidence: string
}

export const detectionsData: DetectionEvent[] = [
  {
    id: "DET-1092",
    time: "10 mins ago",
    assetId: "PG-003",
    assetName: "Northern Grid SCADA Gateway",
    ruleId: "R6",
    ruleName: "Exploit indicator",
    severity: "Critical",
    evidence: "Outbound TCP session to 194.26.29.112:4444 following CVE-2024-3400 arbitrary command injection",
  },
  {
    id: "DET-1091",
    time: "24 mins ago",
    assetId: "PG-019",
    assetName: "Vendor VPN – Tehri Dam Link",
    ruleId: "R2",
    ruleName: "Remote access",
    severity: "Critical",
    evidence: "Anomalous ingress from AS48042 with valid token session without MFA step-up",
  },
  {
    id: "DET-1090",
    time: "48 mins ago",
    assetId: "PG-003",
    assetName: "Northern Grid SCADA Gateway",
    ruleId: "R1",
    ruleName: "Auth failures",
    severity: "High",
    evidence: "142 consecutive failed Kerberos pre-authentications in 60s from internal jumpbox",
  },
  {
    id: "DET-1089",
    time: "1h 15m ago",
    assetId: "PG-001",
    assetName: "400kV Substation – Agra",
    ruleId: "R3",
    ruleName: "Lateral movement",
    severity: "High",
    evidence: "PsExec service creation over SMBv2 from PG-003 gateway IP 10.14.2.19",
  },
  {
    id: "DET-1088",
    time: "2h 04m ago",
    assetId: "JB-014",
    assetName: "Yamuna Pump Control",
    ruleId: "R4",
    ruleName: "OT protocol",
    severity: "Medium",
    evidence: "Modbus function code 0x06 (Write Single Register) from unwhitelisted subnet",
  },
  {
    id: "DET-1087",
    time: "3h 40m ago",
    assetId: "AI-014",
    assetName: "BMS – AIIMS Delhi",
    ruleId: "R5",
    ruleName: "Config change",
    severity: "Medium",
    evidence: "Chiller setpoint override dispatched outside maintenance window (21°C → 28°C)",
  },
  {
    id: "DET-1086",
    time: "5h 12m ago",
    assetId: "JB-006",
    assetName: "Hirakud Dam Control HMI",
    ruleId: "R2",
    ruleName: "Remote access",
    severity: "High",
    evidence: "Active OpenSSH session matching CVE-2024-6387 regreSSHion exploit pattern",
  },
]

export interface ExposureFinding {
  code: "X1" | "X2" | "X3"
  title: string
  assetId: string
  severity: "Critical" | "High" | "Medium"
  description: string
  discovered: string
}

export const exposureFindings: ExposureFinding[] = [
  {
    code: "X1",
    title: "Asset Became Internet-Exposed",
    assetId: "PG-003",
    severity: "Critical",
    description: "Management interface port 8443 detected routable from public WAN following router ACL misconfiguration.",
    discovered: "2h ago",
  },
  {
    code: "X2",
    title: "Cross-Sector Credential Reuse Pathway",
    assetId: "PG-001",
    severity: "High",
    description: "Domain admin hash cached in memory identical to Jal Board secondary operator credentials.",
    discovered: "6h ago",
  },
  {
    code: "X3",
    title: "Unauthenticated OT Protocol Exposure",
    assetId: "JB-014",
    severity: "Medium",
    description: "Raw Modbus/TCP listener active on pump controller interface without perimeter microsegmentation.",
    discovered: "1d ago",
  },
]

export interface WhatChangedItem {
  id: string
  assetId: string
  assetName: string
  sector: string
  prevRiskBp: number
  newRiskBp: number
  deltaBp: number
  cause: string
  timestamp: string
}

export const whatChangedFeed: WhatChangedItem[] = [
  {
    id: "WC-1",
    assetId: "PG-003",
    assetName: "Northern Grid SCADA Gateway",
    sector: "Electricity (WGEC)",
    prevRiskBp: 6510,
    newRiskBp: 7913,
    deltaBp: +1403,
    cause: "CVE-2024-3400 added to CISA KEV + Internet exposure confirmed",
    timestamp: "10 mins ago",
  },
  {
    id: "WC-2",
    assetId: "PG-019",
    assetName: "Vendor VPN – Tehri Dam Link",
    sector: "Electricity (WGEC)",
    prevRiskBp: 6240,
    newRiskBp: 7592,
    deltaBp: +1352,
    cause: "Anomalous ingress from foreign ASN + missing MFA flag",
    timestamp: "24 mins ago",
  },
  {
    id: "WC-3",
    assetId: "JB-006",
    assetName: "Hirakud Dam Control HMI",
    sector: "Water (MetroWater)",
    prevRiskBp: 6410,
    newRiskBp: 7684,
    deltaBp: +1274,
    cause: "CVE-2024-6387 public exploit POC released; EPSS spiked to 0.79",
    timestamp: "5h ago",
  },
  {
    id: "WC-4",
    assetId: "PG-001",
    assetName: "400kV Substation – Agra",
    sector: "Electricity (WGEC)",
    prevRiskBp: 7650,
    newRiskBp: 7184,
    deltaBp: -466,
    cause: "Microsegmentation policy level 1 applied to secondary relay",
    timestamp: "1d ago",
  },
  {
    id: "WC-5",
    assetId: "AI-009",
    assetName: "Emergency Power ATS – Trauma Centre",
    sector: "Healthcare (CCMN)",
    prevRiskBp: 4420,
    newRiskBp: 3135,
    deltaBp: -1285,
    cause: "Firmware patch signed and verified on-chain",
    timestamp: "2d ago",
  },
]

export interface RiskTimePoint {
  day: string
  dayIndex: number
  risk: number
  riskBp: number
  eventMarker?: {
    type: "incident" | "patch" | "event"
    label: string
  }
}

export const riskTimelineData: RiskTimePoint[] = [
  { day: "Day 1", dayIndex: 1, risk: 48.2, riskBp: 4820, eventMarker: { type: "event", label: "Baseline telemetry active" } },
  { day: "Day 2", dayIndex: 2, risk: 51.4, riskBp: 5140 },
  { day: "Day 3", dayIndex: 3, risk: 63.8, riskBp: 6380, eventMarker: { type: "incident", label: "CVE-2024-3400 Exploit Indicator" } },
  { day: "Day 4", dayIndex: 4, risk: 78.5, riskBp: 7850, eventMarker: { type: "incident", label: "Cascade propagation detected" } },
  { day: "Day 5", dayIndex: 5, risk: 71.8, riskBp: 7180, eventMarker: { type: "patch", label: "Containment Level 1 enforced" } },
  { day: "Day 6 (Today)", dayIndex: 6, risk: 68.4, riskBp: 6840 },
  { day: "Day 7 (Forecast)", dayIndex: 7, risk: 59.2, riskBp: 5920, eventMarker: { type: "patch", label: "Holt projected post-isolation" } },
]

export interface DemoWeekStep {
  day: number
  title: string
  description: string
  targetAsset: string
  status: "completed" | "current" | "upcoming"
  action: string
}

export const demoWeekScript: DemoWeekStep[] = [
  { day: 1, title: "Initial Baseline", description: "All three sectors operating at normal baseline telemetry. Zero high-severity alerts.", targetAsset: "PG-001", status: "completed", action: "Verify telemetry ingestion" },
  { day: 2, title: "Vendor Credential Leak", description: "Tehri dam vendor credentials surface in threat intel feed. Remote VPN monitored.", targetAsset: "PG-019", status: "completed", action: "Flag remote access" },
  { day: 3, title: "SCADA Zero-Day Exploit", description: "R6 exploit indicator triggers on PG-003. Internet-facing exposure verified via X1.", targetAsset: "PG-003", status: "completed", action: "Pre-check containment" },
  { day: 4, title: "Lateral Propagation to Grid", description: "Attacker leverages credential reuse X2 to pivot toward 400kV substation Agra.", targetAsset: "PG-001", status: "completed", action: "Simulate cascade blast radius" },
  { day: 5, title: "Water & Hospital Risk Cascade", description: "Agra substation disruption threatens Yamuna pump control and AIIMS trauma ATS.", targetAsset: "AI-009", status: "current", action: "Level 1 Isolation approval" },
  { day: 6, title: "Automated Containment & Verification", description: "Cryptographic approval signed. Graph check confirms isolation. Risk drops 5,000 bp.", targetAsset: "PG-003", status: "upcoming", action: "Review lessons learned" },
]

export interface ModelCardDetails {
  versionHash: string
  source: string
  trainedAt: string
  rocAuc: number
  prAuc: number
  brierScore: number
  topKPrecision: number
  oracleAuc: number
  features: string[]
  baselines: {
    model: string
    rocAuc: number
    prAuc: number
    brier: number
  }[]
  trainingNote: string
}

export const modelCardData: ModelCardDetails = {
  versionHash: "xgb-v2.4-7f1a9c",
  source: "artifacts_v2 (teammate's checkpoint)",
  trainedAt: "2026-10-31 23:14 UTC",
  rocAuc: 0.942,
  prAuc: 0.887,
  brierScore: 0.068,
  topKPrecision: 0.924,
  oracleAuc: 0.985,
  features: [
    "network_exposure_flag",
    "cve_cvss_v3",
    "epss_probability",
    "cisa_kev_listed",
    "downstream_protected_hop_count",
    "auth_failure_burst_60s",
    "ot_modbus_anomaly_score",
    "peer_blast_radius_weighted",
  ],
  baselines: [
    { model: "CascadeShield XGB (v2.4)", rocAuc: 0.942, prAuc: 0.887, brier: 0.068 },
    { model: "Oracle AUC (Ideal)", rocAuc: 0.985, prAuc: 0.960, brier: 0.035 },
    { model: "Logistic Regression Baseline", rocAuc: 0.791, prAuc: 0.714, brier: 0.142 },
    { model: "Known-Exploited-Only (KEV)", rocAuc: 0.732, prAuc: 0.655, brier: 0.188 },
    { model: "CVSS-Only Heuristic", rocAuc: 0.684, prAuc: 0.590, brier: 0.224 },
  ],
  trainingNote: "Synthetic training data with adversarial replay; real CISA, KEV and EPSS data used for feature engineering only.",
}

export interface ShapFactor {
  feature: string
  bpDelta: number
  direction: "positive" | "negative"
}

export interface AssetPredictDetails {
  shapFactors: ShapFactor[]
  missingDataIndicator?: string
  holtForecastDays: number
  evidenceFloorActive: boolean
  sparkline: number[]
  protectedLifeCritical: boolean
  vulnData: {
    cveId: string
    cvss: number
    epss: number
    kevBadge: boolean
    patchAgeDays: number
    source: "Real CISA/KEV/EPSS" | "Simulated"
  }
}

export const assetPredictMap: Record<string, AssetPredictDetails> = {
  "PG-003": {
    shapFactors: [
      { feature: "Internet Exposure (Port 8443 WAN)", bpDelta: +2400, direction: "positive" },
      { feature: "Listed in CISA KEV (Active Exploitation)", bpDelta: +1850, direction: "positive" },
      { feature: "Life-Critical Hospital Downstream (AIIMS)", bpDelta: +1200, direction: "positive" },
      { feature: "Recent Auth Failure Burst (R1 rule)", bpDelta: +850, direction: "positive" },
      { feature: "EDR Agent Sensor Telemetry Active", bpDelta: -620, direction: "negative" },
    ],
    holtForecastDays: 4.27,
    evidenceFloorActive: true,
    sparkline: [42, 45, 58, 67, 75, 79],
    protectedLifeCritical: true,
    vulnData: {
      cveId: "CVE-2024-3400",
      cvss: 10.0,
      epss: 0.942,
      kevBadge: true,
      patchAgeDays: 48,
      source: "Real CISA/KEV/EPSS",
    },
  },
  "PG-019": {
    shapFactors: [
      { feature: "Anomalous Ingress via Foreign ASN", bpDelta: +1920, direction: "positive" },
      { feature: "Missing Hardware MFA Token Enforcement", bpDelta: +1450, direction: "positive" },
      { feature: "Direct VPN Tunnel to Hydro Generation", bpDelta: +1100, direction: "positive" },
      { feature: "Zero-Trust Device Certificate Present", bpDelta: -550, direction: "negative" },
    ],
    missingDataIndicator: "No EPSS available (imputed with 50th percentile)",
    holtForecastDays: 6.12,
    evidenceFloorActive: true,
    sparkline: [38, 42, 50, 64, 71, 76],
    protectedLifeCritical: true,
    vulnData: {
      cveId: "CVE-2023-46805",
      cvss: 8.2,
      epss: 0.650,
      kevBadge: true,
      patchAgeDays: 124,
      source: "Real CISA/KEV/EPSS",
    },
  },
  "PG-001": {
    shapFactors: [
      { feature: "High Downstream Service Centrality (400kV)", bpDelta: +2100, direction: "positive" },
      { feature: "Lateral Access via Gateway PG-003", bpDelta: +1620, direction: "positive" },
      { feature: "Secondary Relay Firewall Segmented", bpDelta: -980, direction: "negative" },
    ],
    holtForecastDays: 8.45,
    evidenceFloorActive: false,
    sparkline: [68, 70, 74, 76, 73, 72],
    protectedLifeCritical: true,
    vulnData: {
      cveId: "CVE-2023-27997",
      cvss: 9.8,
      epss: 0.720,
      kevBadge: true,
      patchAgeDays: 95,
      source: "Real CISA/KEV/EPSS",
    },
  },
  "JB-006": {
    shapFactors: [
      { feature: "Public regreSSHion POC Exploitation", bpDelta: +2300, direction: "positive" },
      { feature: "Direct Spillway Control Actuation", bpDelta: +1850, direction: "positive" },
      { feature: "Encrypted Management Jumpbox Required", bpDelta: -720, direction: "negative" },
    ],
    holtForecastDays: 5.15,
    evidenceFloorActive: true,
    sparkline: [52, 55, 60, 68, 74, 77],
    protectedLifeCritical: true,
    vulnData: {
      cveId: "CVE-2024-6387",
      cvss: 8.1,
      epss: 0.790,
      kevBadge: true,
      patchAgeDays: 32,
      source: "Real CISA/KEV/EPSS",
    },
  },
  "JB-014": {
    shapFactors: [
      { feature: "Unauthenticated OT Modbus Port Exposed", bpDelta: +1800, direction: "positive" },
      { feature: "Single Point of Water Failure for Capital", bpDelta: +1450, direction: "positive" },
      { feature: "Isolated Secondary Intake Reservoir", bpDelta: -610, direction: "negative" },
    ],
    holtForecastDays: 7.8,
    evidenceFloorActive: false,
    sparkline: [48, 52, 56, 61, 63, 64],
    protectedLifeCritical: false,
    vulnData: {
      cveId: "CVE-2022-29951",
      cvss: 7.5,
      epss: 0.340,
      kevBadge: false,
      patchAgeDays: 210,
      source: "Simulated",
    },
  },
  "AI-014": {
    shapFactors: [
      { feature: "Default Vendor Credentials on BMS", bpDelta: +2250, direction: "positive" },
      { feature: "Chiller Failure Overheats Clinical Core", bpDelta: +1900, direction: "positive" },
      { feature: "Secondary Redundant Air Handling Unit", bpDelta: -840, direction: "negative" },
    ],
    holtForecastDays: 3.9,
    evidenceFloorActive: true,
    sparkline: [55, 60, 65, 71, 74, 75],
    protectedLifeCritical: true,
    vulnData: {
      cveId: "CVE-2023-38545",
      cvss: 9.8,
      epss: 0.880,
      kevBadge: true,
      patchAgeDays: 60,
      source: "Real CISA/KEV/EPSS",
    },
  },
}

// Default fallback for assets not explicitly listed
export function getAssetPredictDetails(assetId: string): AssetPredictDetails {
  if (assetPredictMap[assetId]) return assetPredictMap[assetId]
  return {
    shapFactors: [
      { feature: "Network Proximity to Core Grid", bpDelta: +850, direction: "positive" },
      { feature: "Service Dependency Centrality", bpDelta: +620, direction: "positive" },
      { feature: "Local Host Firewall Active", bpDelta: -450, direction: "negative" },
    ],
    missingDataIndicator: "No EPSS available (imputed with 50th percentile)",
    holtForecastDays: 11.2,
    evidenceFloorActive: false,
    sparkline: [25, 28, 30, 32, 35, 36],
    protectedLifeCritical: false,
    vulnData: {
      cveId: "CVE-2023-1192",
      cvss: 6.5,
      epss: 0.120,
      kevBadge: false,
      patchAgeDays: 180,
      source: "Simulated",
    },
  }
}
