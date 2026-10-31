// Single source for every number the UI shows. Demo asset data is simulated; project facts come from the
// CascadeShield repository (backend/risk/artifacts/metrics.json, tests and contracts).
import { assets, assetById, dependencies, downstreamOf, organisations, type Asset, type RiskLevel } from "./infrastructure"
import { getAssetPredictDetails, detectionsData, exposureFindings, whatChangedFeed, riskTimelineData } from "./cascadeshieldData"

export { assets, assetById, dependencies, downstreamOf, organisations, detectionsData, exposureFindings, whatChangedFeed, riskTimelineData }
export type { Asset, RiskLevel }

export const LEVELS: RiskLevel[] = ["Critical", "High", "Medium", "Low"]
export const levelColor: Record<RiskLevel, string> = { Critical: "#ef5b5b", High: "#f0a04b", Medium: "#e3c55a", Low: "#3fbf8c" }
export const sectorOf: Record<string, { label: string; color: string; icon: "power" | "water" | "health" }> = {
  WGEC: { label: "Power", color: "#38bdf8", icon: "power" },
  MetroWater: { label: "Water", color: "#a78bfa", icon: "water" },
  CCMN: { label: "Healthcare", color: "#f472b6", icon: "health" },
}
export const THRESHOLDS = { critical: 75, high: 60, medium: 40 }

export const predict = (id: string) => getAssetPredictDetails(id)
export const isInternet = (a: Asset) => a.exposure.toLowerCase().includes("internet")
export const isUnpatched = (a: Asset) => a.vulnerability !== "Patched"

/** Assets ranked by risk, highest first (risk prioritisation). */
export const ranked = [...assets].sort((a, b) => b.risk - a.risk)

/* ---------- preventive recommendations with estimated risk reduction ---------- */

export interface Action {
  id: string
  kind: "Patch" | "Segment" | "Access control" | "Monitoring" | "Incident response"
  title: string
  detail: string
  reduction: number // fraction of the asset's risk removed (estimated by the what-if model)
  effort: "Low" | "Medium" | "High"
  downtime: string
}

export function actionsFor(a: Asset): Action[] {
  const p = predict(a.id)
  const out: Action[] = []
  const credentialIssue = /credential/i.test(a.vulnerability)
  if (isUnpatched(a) && !credentialIssue) {
    const cve = a.vulnerability.startsWith("CVE") ? a.vulnerability : p.vulnData.cveId
    out.push({
      id: `${a.id}-patch`,
      kind: "Patch",
      title: p.vulnData.kevBadge ? `Patch ${cve} now (known exploited)` : `Patch ${a.vulnerability.startsWith("CVE") ? cve : a.vulnerability + " vulnerabilities"}`,
      detail: `Apply the vendor fix in the next maintenance window; CVSS ${p.vulnData.cvss.toFixed(1)}, EPSS ${(p.vulnData.epss * 100).toFixed(0)}%.`,
      reduction: p.vulnData.kevBadge ? 0.42 : 0.24,
      effort: "Medium",
      downtime: "30–60 min",
    })
  }
  if (isInternet(a)) {
    out.push({ id: `${a.id}-seg`, kind: "Segment", title: "Remove internet exposure", detail: "Move the management interface behind the OT DMZ jump host and block WAN access at the edge firewall.", reduction: 0.3, effort: "Low", downtime: "None" })
  } else if (a.exposure === "Partner network") {
    out.push({ id: `${a.id}-seg`, kind: "Segment", title: "Segment the partner link", detail: "Restrict the partner VLAN to the required protocols and ports (allow-list).", reduction: 0.18, effort: "Medium", downtime: "15 min" })
  }
  if (/credential|vpn|remote/i.test(a.vulnerability + a.type + a.name)) {
    out.push({ id: `${a.id}-iam`, kind: "Access control", title: "Enforce MFA and rotate credentials", detail: "Replace default or shared credentials and require hardware MFA for remote sessions.", reduction: credentialIssue ? 0.38 : 0.22, effort: "Low", downtime: "None" })
  }
  if (a.risk >= THRESHOLDS.high) {
    out.push({ id: `${a.id}-mon`, kind: "Monitoring", title: "Enhanced monitoring", detail: "Turn on the D1–D6 detection rules at high sensitivity and forward alerts to the SOC.", reduction: 0.08, effort: "Low", downtime: "None" })
    out.push({ id: `${a.id}-ir`, kind: "Incident response", title: "Pre-stage the containment playbook", detail: "Prepare the isolation runbook and approvers so containment takes minutes, not hours.", reduction: 0.05, effort: "Low", downtime: "None" })
  }
  if (!out.length) out.push({ id: `${a.id}-mon`, kind: "Monitoring", title: "Keep under routine monitoring", detail: "No urgent action; reassess when a new advisory arrives.", reduction: 0.03, effort: "Low", downtime: "None" })
  return out
}

/** Risk after applying a set of actions (reductions compound multiplicatively). */
export function riskAfter(a: Asset, chosen: Action[]) {
  return chosen.reduce((r, act) => r * (1 - act.reduction), a.risk)
}

export function levelOf(risk: number): RiskLevel {
  return risk >= THRESHOLDS.critical ? "Critical" : risk >= THRESHOLDS.high ? "High" : risk >= THRESHOLDS.medium ? "Medium" : "Low"
}

/* ---------- portfolio-level figures ---------- */

const mean = (xs: number[]) => xs.reduce((s, x) => s + x, 0) / xs.length
export const portfolio = {
  total: assets.length,
  avgRisk: mean(assets.map((a) => a.risk)),
  byLevel: Object.fromEntries(LEVELS.map((l) => [l, assets.filter((a) => a.level === l).length])) as Record<RiskLevel, number>,
  urgent: assets.filter((a) => a.risk >= THRESHOLDS.high).length,
  internet: assets.filter(isInternet).length,
  unpatched: assets.filter(isUnpatched).length,
  kev: assets.filter((a) => predict(a.id).vulnData.kevBadge).length,
  cascadeSources: assets.filter((a) => downstreamOf(a.id).size >= 2).length,
  detections: detectionsData.length,
}
export const orgRisk = organisations.map((o) => {
  const own = assets.filter((a) => a.org === o.code)
  return { ...o, sector: sectorOf[o.code], count: own.length, avg: mean(own.map((a) => a.risk)), max: Math.max(...own.map((a) => a.risk)), critical: own.filter((a) => a.level === "Critical").length }
})

/** Ordered cascade chain from a source asset (breadth-first, with the edge that reaches each hop). */
export function cascadeChain(id: string) {
  const out: { asset: Asset; via: string; kind: string; depth: number }[] = []
  const seen = new Set([id])
  let frontier = [{ id, depth: 0 }]
  while (frontier.length) {
    const next: typeof frontier = []
    for (const f of frontier)
      for (const d of dependencies.filter((d) => d.from === f.id && !seen.has(d.to))) {
        seen.add(d.to)
        const asset = assetById.get(d.to)
        if (asset) out.push({ asset, via: d.label, kind: d.kind, depth: f.depth + 1 })
        next.push({ id: d.to, depth: f.depth + 1 })
      }
    frontier = next
  }
  return out
}

/* ---------- facts about the CascadeShield platform (from the repository) ---------- */

export const MODEL = {
  name: "M1",
  version: "1e50403a7534041c",
  estimator: "Gradient-boosted trees (HistGradientBoosting) with monotonic constraints",
  calibration: "Sigmoid (Platt) calibration on a held-out split",
  explain: "SHAP TreeExplainer: per-asset factor contributions",
  features: 24,
  rows: "16,000 training rows (2,000 assets × 8 windows), plus a second generator for robustness",
  realData: "Real CISA CSAF OT advisories, CISA KEV and NVD, time-matched",
  labels: "Synthetic compromise labels (simulated data)",
  threshold: 0.36,
  metrics: [
    { label: "ROC-AUC (held-out assets)", value: 0.7548 },
    { label: "ROC-AUC (future time window)", value: 0.7641 },
    { label: "ROC-AUC (unseen generator B)", value: 0.7237 },
    { label: "PR-AUC (held-out assets)", value: 0.5531 },
    { label: "Precision @ 0.36", value: 0.6592 },
    { label: "Recall @ 0.36", value: 0.4142 },
    { label: "Brier score (lower is better)", value: 0.1099 },
    { label: "Calibration error ECE", value: 0.0165 },
  ],
  ceiling: { auc: 0.7592, share: 0.983 },
  baselines: [
    { name: "M1 (ours)", auc: 0.7548, ours: true },
    { name: "B3 Logistic regression", auc: 0.7572 },
    { name: "B1 CVSS score only", auc: 0.6525 },
    { name: "B2 Known-exploited flag only", auc: 0.6075 },
  ],
  bands: { low: 7.8, medium: 14.62, high: 44.84 },
}

export const AGENTS = [
  { name: "Intake", does: "Reads a CERT-In / CISA advisory, extracts CVEs and products, matches them to the asset inventory. Treats advisory text as data (prompt-injection guard).", out: "Matched findings" },
  { name: "Risk", does: "Scores each asset: M1 compromise likelihood × operational impact, with the SHAP 'why' and a trend forecast.", out: "Risk score + reasons" },
  { name: "Cascade", does: "Walks the attested cross-organisation dependency graph to estimate which services degrade next and how fast.", out: "Cascade chain + sealed alerts" },
  { name: "Planner", does: "Proposes preventive actions (patch, segment, access control, monitoring) that respect maintenance windows, with predicted risk reduction.", out: "Remediation plan" },
  { name: "Critic", does: "Independently re-checks the plan against safety constraints; its verdict is anchored on-chain before any approval can start.", out: "Verdict on AuditLog" },
  { name: "Executor", does: "Runs only after humans approve on ApprovalGate; applies the (simulated) plan and re-scores to confirm the reduction.", out: "Executed + re-scored" },
]

export const CONTRACTS = [
  { name: "OrgRegistry", does: "Registers organisations, their roles (agent, approver, safety officer) and public encryption keys." },
  { name: "AttestationRegistry", does: "Stores salted commitments of risk bands, findings and two-sided dependency edges — never plaintext." },
  { name: "AuditLog", does: "Anchors Merkle roots of every agent trace so any later tampering is detected." },
  { name: "ApprovalGate", does: "Human multi-signature approval; the AI cannot vote and a critic verdict must be anchored first." },
  { name: "FirmwareRegistry", does: "Known-good firmware hashes for the supply-chain check; tampered or unknown firmware is flagged." },
  { name: "AlertBus", does: "Delivers sealed early-warning cascade alerts only to directly dependent organisations." },
]

export const PRIVACY = [
  { title: "Nothing readable on-chain", body: "Risk bands, findings and alert severity are stored as salted commitments; an observer cannot learn which asset is weak." },
  { title: "Sealed envelopes", body: "Details travel encrypted (X25519 + AES-GCM) in fixed-size envelopes, so even the size reveals nothing." },
  { title: "Blinded keys", body: "Advisory and dedupe keys are blinded, so attackers cannot link an on-chain record to a public CVE." },
  { title: "Verifiable, not visible", body: "A partner can open its own envelope and check it against the commitment; everyone else sees only that a valid record exists." },
]

export const QUALITY = [
  { label: "Backend tests passing", value: "193" },
  { label: "Smart-contract tests passing", value: "168" },
  { label: "End-to-end demo checks", value: "26 / 26" },
  { label: "Detection rules", value: "D1–D6 + X1" },
]
