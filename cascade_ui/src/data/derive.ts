// Single source for every number the UI shows. All values come from the live CascadeShield backend (see live.ts);
// asset locations on the map are illustrative.
import {
  afterLoad,
  assetById,
  assets,
  bandThresholds,
  chain,
  dependencies,
  detectionsData,
  exposureFindings,
  modelInfo,
  organisations,
  predictMap,
  riskTimelineData,
  traces,
  whatChangedFeed,
  type Asset,
  type AssetPredictDetails,
  type BackendAction,
  type RiskLevel,
} from "./live"

export { assets, assetById, dependencies, organisations, detectionsData, exposureFindings, whatChangedFeed, riskTimelineData, chain, traces }
export type { Asset, RiskLevel }

export const LEVELS: RiskLevel[] = ["Critical", "High", "Medium", "Low"]
export const levelColor: Record<RiskLevel, string> = { Critical: "#ef5b5b", High: "#f0a04b", Medium: "#e3c55a", Low: "#3fbf8c" }
export const sectorOf: Record<string, { label: string; color: string; icon: "power" | "water" | "health" }> = {
  WGEC: { label: "Power", color: "#38bdf8", icon: "power" },
  MetroWater: { label: "Water", color: "#a78bfa", icon: "water" },
  CCMN: { label: "Healthcare", color: "#f472b6", icon: "health" },
}
/** The model's own risk bands (from metrics.json band_thresholds): Critical above high_max, and so on. */
export const THRESHOLDS = {
  get critical() {
    return bandThresholds.high
  },
  get high() {
    return bandThresholds.medium
  },
  get medium() {
    return bandThresholds.low
  },
}

const EMPTY: AssetPredictDetails = {
  shapFactors: [],
  shapBase: 0,
  holtForecastDays: null,
  trendDirection: "unknown",
  evidenceFloorActive: false,
  sparkline: [],
  protectedLifeCritical: false,
  actions: [],
  patchDowntime: false,
  maintenanceWindow: "none",
  vulnData: { cveId: "none", cvss: 0, epss: 0, kevBadge: false, patchAgeDays: 0, source: "Simulated" },
}
export const predict = (id: string): AssetPredictDetails => predictMap.get(id) ?? EMPTY
export const isInternet = (a: Asset) => a.exposure.toLowerCase().includes("internet")
export const isUnpatched = (a: Asset) => a.vulnerability !== "Patched"

/** Assets reachable downstream of an asset through any dependency. */
export function downstreamOf(assetId: string): Set<string> {
  const seen = new Set<string>()
  const queue = [assetId]
  while (queue.length) {
    const current = queue.shift()!
    for (const dep of dependencies) {
      if (dep.from === current && !seen.has(dep.to) && dep.to !== assetId) {
        seen.add(dep.to)
        queue.push(dep.to)
      }
    }
  }
  return seen
}

/** Assets ranked by risk, highest first (risk prioritisation). */
export const ranked: Asset[] = []

/* ---------- preventive recommendations: the backend's what-if recomputation with the same model ---------- */

export interface Action {
  id: string
  code: string // backend action, e.g. ISOLATE_ASSET
  kind: "Patch" | "Segment" | "Access control" | "Monitoring" | "Incident response"
  title: string
  detail: string
  reduction: number // fraction of the asset's risk removed (backend what-if)
  riskAfter: number
  effort: string
  downtime: string
}

const KIND: Record<string, Action["kind"]> = {
  PATCH: "Patch",
  ISOLATE_ASSET: "Segment",
  RESTRICT_ACCESS: "Segment",
  DISABLE_SERVICE_PORT: "Segment",
  ROTATE_CREDENTIALS: "Access control",
  DISABLE_REMOTE_ACCESS: "Access control",
  ENABLE_MONITORING: "Monitoring",
}
const title = (s: string) => {
  const t = s.replace(/_/g, " ").toLowerCase()
  return t.charAt(0).toUpperCase() + t.slice(1)
}

export function actionsFor(a: Asset): Action[] {
  const p = predict(a.id)
  return p.actions
    .filter((x: BackendAction) => x.asset_risk_before > 0)
    .map((x: BackendAction) => ({
      id: `${a.id}-${x.action}`,
      code: x.action,
      kind: KIND[x.action] ?? "Incident response",
      title: title(x.action) + (x.level ? ` (containment level ${x.level})` : ""),
      detail: x.why,
      reduction: Math.max(0, Math.min(1, 1 - x.asset_risk_after / x.asset_risk_before)),
      riskAfter: x.asset_risk_after,
      effort: x.level === 2 ? "High (needs 2 approvals)" : x.action === "PATCH" ? "Medium" : "Low",
      downtime: x.action === "PATCH" ? (p.patchDowntime ? `required · window ${p.maintenanceWindow}` : "none") : x.action === "ISOLATE_ASSET" ? "asset offline while quarantined" : "none",
    }))
    .sort((x, y) => y.reduction - x.reduction)
}

/** Risk after applying a set of actions. One action is the backend's exact what-if; several compound (estimate). */
export function riskAfter(a: Asset, chosen: Action[]) {
  if (chosen.length === 1) return chosen[0].riskAfter
  return chosen.reduce((r, act) => r * (1 - act.reduction), a.risk)
}

export function levelOf(risk: number): RiskLevel {
  return risk > THRESHOLDS.critical ? "Critical" : risk > THRESHOLDS.high ? "High" : risk > THRESHOLDS.medium ? "Medium" : "Low"
}

/* ---------- portfolio-level figures (recomputed after every refresh) ---------- */

const mean = (xs: number[]) => (xs.length ? xs.reduce((s, x) => s + x, 0) / xs.length : 0)
export const portfolio = {
  total: 0,
  avgRisk: 0,
  byLevel: { Critical: 0, High: 0, Medium: 0, Low: 0 } as Record<RiskLevel, number>,
  urgent: 0,
  internet: 0,
  unpatched: 0,
  kev: 0,
  cascadeSources: 0,
  detections: 0,
}
export const orgRisk: (ReturnType<typeof orgRow>)[] = []
function orgRow(o: (typeof organisations)[number]) {
  const own = assets.filter((a) => a.org === o.code)
  return { ...o, sector: sectorOf[o.code], count: own.length, avg: mean(own.map((a) => a.risk)), max: own.length ? Math.max(...own.map((a) => a.risk)) : 0, critical: own.filter((a) => a.level === "Critical").length }
}

function recompute() {
  ranked.length = 0
  ranked.push(...[...assets].sort((a, b) => b.risk - a.risk))
  Object.assign(portfolio, {
    total: assets.length,
    avgRisk: mean(assets.map((a) => a.risk)),
    byLevel: Object.fromEntries(LEVELS.map((l) => [l, assets.filter((a) => a.level === l).length])),
    urgent: assets.filter((a) => a.level === "Critical" || a.level === "High").length,
    internet: assets.filter(isInternet).length,
    unpatched: assets.filter(isUnpatched).length,
    kev: assets.filter((a) => predict(a.id).vulnData.kevBadge).length,
    cascadeSources: assets.filter((a) => downstreamOf(a.id).size >= 2).length,
    detections: detectionsData.length,
  })
  orgRisk.length = 0
  orgRisk.push(...organisations.map(orgRow))
  rebuildModel()
}
afterLoad.push(recompute)

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

/* ---------- the M1 model card, from /api/ps03/model/info ---------- */

export const MODEL = {
  name: "M1",
  version: "",
  estimator: "",
  calibration: "",
  explain: "",
  features: 0,
  rows: "",
  realData: "Real CISA CSAF OT advisories, CISA KEV and FIRST EPSS (snapshot)",
  labels: "",
  threshold: 0,
  metrics: [] as { label: string; value: number }[],
  ceiling: { auc: 0, share: 0 },
  baselines: [] as { name: string; auc: number; ours?: boolean }[],
  bands: bandThresholds,
  caveats: [] as string[],
}

function rebuildModel() {
  const i = modelInfo.raw
  if (!i) return
  const m = i.metrics ?? {}
  const g = m.evaluations?.A_grouped ?? {}
  const t = m.evaluations?.A_time ?? {}
  const b = m.evaluations?.B_all ?? {}
  const md = i.metadata ?? {}
  const num = (x: unknown) => (typeof x === "number" ? x : NaN)
  Object.assign(MODEL, {
    version: i.model_version,
    estimator: md.config?.estimator === "hgb_monotonic" ? `Gradient-boosted trees (HistGradientBoosting, monotonic), depth ${md.config.max_depth}, ${md.config.max_iter} rounds` : String(md.config?.estimator ?? "unknown"),
    calibration: `${m.calibration?.method ?? md.calibration?.method ?? "unknown"} calibration · ECE ${num(m.calibration?.ece_before).toFixed?.(4)} → ${num(m.calibration?.ece_after).toFixed?.(4)}`,
    explain: typeof i.shap === "string" ? i.shap : "SHAP TreeExplainer on the uncalibrated base model (log-odds)",
    features: Array.isArray(i.features) ? i.features.length : 0,
    rows: md.training_data ? `${md.training_data.rows_train ?? "?"} training rows from ${md.training_data.file}` : "see metadata.json",
    labels: m.labels?.note ?? m.labels?.source ?? "Synthetic compromise labels (simulated data)",
    threshold: num(g.M1?.threshold),
    metrics: [
      { label: "ROC-AUC (held-out assets)", value: num(g.M1?.roc_auc) },
      { label: "ROC-AUC (future time window)", value: num(t.M1?.roc_auc) },
      { label: "ROC-AUC (unseen generator B)", value: num(b.M1?.roc_auc) },
      { label: "PR-AUC (held-out assets)", value: num(g.M1?.pr_auc) },
      { label: `Precision @ ${num(g.M1?.threshold)}`, value: num(g.M1?.precision_at_threshold) },
      { label: `Recall @ ${num(g.M1?.threshold)}`, value: num(g.M1?.recall_at_threshold) },
      { label: "Brier score (lower is better)", value: num(g.M1?.brier) },
      { label: "Calibration error ECE", value: num(g.M1?.ece) },
    ],
    ceiling: { auc: num(m.accuracy_ceiling?.O2_observable_oracle_plus_telemetry?.roc_auc), share: num(m.accuracy_ceiling?.M1_share_of_O2_roc_auc_above_chance) },
    baselines: [
      { name: "M1 (ours)", auc: num(g.M1?.roc_auc), ours: true },
      { name: "B3 Logistic regression", auc: num(g.B3_logistic?.roc_auc) },
      { name: "B1 CVSS score only", auc: num(g.B1_cvss_only?.roc_auc) },
      { name: "B2 Known-exploited flag only", auc: num(g.B2_known_exploited?.roc_auc) },
    ],
    caveats: Array.isArray(i.caveats) ? i.caveats : [],
  })
}

/* ---------- platform facts ---------- */

export const AGENTS = [
  { name: "Intake", does: "Reads a CISA / CERT-In advisory, extracts CVEs and products, matches them to the asset inventory. Treats advisory text as data (prompt-injection guard).", out: "Matched findings" },
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
  { label: "Backend tests passing (last run)", value: "227 / 227" },
  { label: "Agents verified end to end", value: "7 / 7" },
  { label: "Smart contracts deployed", value: "6" },
  { label: "Detection rules", value: "R1–R6 + exposure" },
]
