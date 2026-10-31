// Thin client for the CascadeShield API (proxied to http://localhost:8000 by vite.config.ts).
export type Role = 'admin' | 'org:power' | 'org:water' | 'org:hospital'
export const ORGS = ['power', 'water', 'hospital'] as const
export type Org = (typeof ORGS)[number]

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

let role: Role = 'admin'
export const setRole = (r: Role) => { role = r }
export const orgsFor = (r: Role): Org[] => (r === 'admin' ? [...ORGS] : [r.slice(4) as Org])

async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', 'X-Dev-Role': role, ...(init.headers || {}) },
  })
  if (!res.ok) {
    let detail = res.statusText
    try { detail = (await res.json()).detail ?? detail } catch { /* not json */ }
    throw new ApiError(res.status, `${res.status} ${detail}`)
  }
  return res.json() as Promise<T>
}

export interface Factor { factor: string; feature: string; value: number; contribution_logodds: number; text: string }
export interface Score {
  asset_id: string; org: string; likelihood: number; impact: number; risk: number; band: Band
  likelihood_bp: number; impact_bp: number; risk_bp: number; top_factors: Factor[]; model_version: string; missing: string[]
}
export type Band = 'low' | 'medium' | 'high' | 'critical' | 'unknown'
export interface OrgRisk { aggregate: number; scores: Score[] }
export interface Asset { asset_id: string; name: string; type: string; vendor: string; model: string; zone: string; criticality: number; internet_exposed: boolean }
export interface Why {
  asset_id: string; likelihood: number; impact: number; risk: number; band: Band
  source_cves: { cve: string; cvss: number | null; known_exploited: boolean; version_match: string }[]
  key_factors: Factor[]; missing_or_clipped: string[]; source_tags: Record<string, string>
  data_freshness: Record<string, string>; cascade_assumptions: Record<string, unknown>
}
export interface Change { feature: string; before: number; after: number; delta_logodds: number; sentence: string }
export interface Trend { asset_id?: string; points?: number; direction: string; slope_per_day?: number | null; days_to_next_band?: number | null }
export interface Detection { asset_id: string; rule: string; finding_type: 'active_attack' | 'exposure'; severity: string; evidence: string; event_time?: string; source: string; episode_type?: string }
export interface GraphNode { org: string; service_hash: string; band: Band; criticality: string; label: string }
export interface GraphEdge { consumer_org: string; consumer_service: string; provider_org: string; provider_service: string; strength: string; tolerance: number; confirmed: boolean; disclosed: boolean }
export interface CascadeStep { org: string; service: string; label: string; p_degraded: number; time_to_impact_minutes: number; criticality_bucket: string }
export interface Plan { org: string; plan_id: string; risk_before: number; risk_after: number; steps: number; critic?: { verdict: string } }
export interface Approval { org: string; request_id: string; plan_id: string }
export interface PlanStep {
  step_id: string; action: string; target_assets: string[]; impact_class: 'LOW' | 'MEDIUM' | 'HIGH'
  expected_risk_delta: number; rationale: string; scheduled_window: string | null; est_downtime_min: number
}

export const api = {
  health: () => call<{ ok: boolean; chain_connected: boolean }>('/api/health'),
  chainStatus: () => call<{ connected: boolean; chain_id: number; block: number; contracts: Record<string, string>; pending_writes: number; paused: boolean; audit_lengths: Record<string, number> }>('/api/chain/status'),
  assets: (org: Org) => call<Asset[]>(`/api/orgs/${org}/assets`),
  risk: (org: Org) => call<OrgRisk>(`/api/orgs/${org}/risk`),
  services: (org: Org) => call<{ service_id: string; name: string; band: Band; risk: number; criticality: string }[]>(`/api/orgs/${org}/services`),
  why: (org: Org, id: string) => call<Why>(`/api/orgs/${org}/assets/${id}/why`),
  whatChanged: (org: Org, id: string) => call<{ changes: Change[] }>(`/api/orgs/${org}/assets/${id}/what-changed`),
  trend: (org: Org, id: string) => call<Trend>(`/api/orgs/${org}/assets/${id}/trend`),
  trends: (org: Org) => call<Trend[]>(`/api/orgs/${org}/trends`),
  detections: (org: Org) => call<Detection[]>(`/api/orgs/${org}/findings/detections`),
  crossGraph: () => call<{ nodes: GraphNode[]; edges: GraphEdge[] }>('/api/cross-org/graph'),
  cascade: (org: Org, service: string) => call<{ chain: CascadeStep[] }>(`/api/cross-org/cascade?source_org=${org}&source_service=${service}`),
  plans: () => call<Plan[]>('/api/plans'),
  plan: (id: string) => call<{ plan_id: string; steps: PlanStep[]; risk_before: number; risk_after: number; total_delta: number }>(`/api/plans/${id}`),
  approvals: () => call<Approval[]>('/api/approvals'),
  approval: (rid: string) => call<{ status: string; impact: string; required: number; approvals: number; needs_safety_officer: boolean; seconds_left: number; plan_id: string }>(`/api/approvals/${rid}`),
  approve: (rid: string, org: Org, approver: number) => call(`/api/approvals/${rid}/approve`, { method: 'POST', body: JSON.stringify({ org, approver }) }),
  execute: (planId: string) => call<{ actual_delta: number; drift: number }>(`/api/plans/${planId}/execute`, { method: 'POST', body: JSON.stringify({}) }),
  ingest: (text: string) => call<Record<string, { status: string; request_id?: string }>>('/api/advisories', { method: 'POST', body: JSON.stringify({ text, source: 'dashboard' }) }),
  auditVerify: (org: Org) => call<{ ok: boolean; first_mismatch?: number; reason?: string }>(`/api/audit/verify?org=${org}`),
  events: (limit = 50) => call<{ block: number; contract: string; name: string; args: Record<string, unknown> }[]>(`/api/chain/events?limit=${limit}`),
  model: () => call<ModelCard>('/api/ml/model'),
}

export interface ModelCard {
  model_version: string; estimator: string; calibration: string; epss_source: string; labels: string
  operating_threshold: { value: number; rule: string }
  band_thresholds: { low_max: number; medium_max: number; high_max: number }
  held_out_A: Record<string, { roc_auc: number; pr_auc: number; top5_precision: number }>
  generator_B: Record<string, { roc_auc: number; pr_auc: number }>
  accuracy_ceiling?: Record<string, { roc_auc: number; pr_auc: number } | number | string>
  learned: string[]; deterministic: string[]; statistical: string[]
}
