// Live data store: every number the UI shows comes from the CascadeShield backend (FastAPI on :8000, proxied as /api).
// Arrays and objects are filled in place, so modules that import them always see the latest values; components
// re-render through useLive() whenever a refresh lands.
import { useSyncExternalStore } from "react"

export type OrgCode = "WGEC" | "MetroWater" | "CCMN"
export type RiskLevel = "Critical" | "High" | "Medium" | "Low"
export type BackendOrg = "power" | "water" | "hospital"

export const ORG_CODE: Record<BackendOrg, OrgCode> = { power: "WGEC", water: "MetroWater", hospital: "CCMN" }
export const BACKEND_ORG: Record<OrgCode, BackendOrg> = { WGEC: "power", MetroWater: "water", CCMN: "hospital" }
const ORGS: BackendOrg[] = ["power", "water", "hospital"]

export interface Organisation {
  code: OrgCode
  name: string
  sector: string
  totalAssets: number
  slug: string
}

export interface Asset {
  id: string
  name: string
  org: OrgCode
  zone: string
  type: string
  exposure: string
  vulnerability: string
  likelihood: number
  impact: number
  risk: number
  level: RiskLevel
  x: number
  y: number
  cascade: string
  location: string
}

export interface Dependency {
  from: string
  to: string
  kind: "confirmed" | "potential"
  label: string
}

export interface DetectionEvent {
  id: string
  time: string
  assetId: string
  assetName: string
  ruleId: string
  ruleName: string
  severity: "Critical" | "High" | "Medium" | "Low"
  evidence: string
  simDay: number
}

export interface ExposureFinding {
  code: string
  title: string
  assetId: string
  severity: "Critical" | "High" | "Medium" | "Low"
  description: string
  discovered: string
}

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

export interface RiskTimePoint {
  day: string
  dayIndex: number
  risk: number
  riskBp: number
}

export interface ShapFactor {
  feature: string
  bpDelta: number
  direction: "positive" | "negative"
}

export interface BackendAction {
  action: string
  level: number | null
  asset_risk_before: number
  asset_risk_after: number
  asset_risk_delta: number
  why: string
}

export interface AssetPredictDetails {
  shapFactors: ShapFactor[]
  shapBase: number
  missingDataIndicator?: string
  holtForecastDays: number | null
  trendDirection: string
  evidenceFloorActive: boolean
  sparkline: number[]
  protectedLifeCritical: boolean
  actions: BackendAction[]
  patchDowntime: boolean
  maintenanceWindow: string
  vulnData: {
    cveId: string
    cvss: number
    epss: number
    kevBadge: boolean
    patchAgeDays: number
    source: "Real CISA/KEV/EPSS" | "Simulated"
  }
}

/* ------------------------------------------------------------------ http */

export class ApiError extends Error {}
const ROLE = { "X-Dev-Role": "admin" }

export async function api<T = any>(path: string, body?: unknown): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      headers: body === undefined ? ROLE : { ...ROLE, "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    })
  } catch {
    throw new ApiError("backend unreachable")
  }
  const text = await res.text()
  const data = text ? JSON.parse(text) : null
  if (!res.ok) {
    const d = data?.detail
    throw new ApiError(`${res.status} ${typeof d === "string" ? d : d ? JSON.stringify(d) : res.statusText}`)
  }
  return data as T
}

async function pool<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length)
  let i = 0
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (i < items.length) {
        const k = i++
        out[k] = await fn(items[k])
      }
    }),
  )
  return out
}

/* ------------------------------------------------------------------ live containers (filled in place) */

export const organisations: Organisation[] = []
export const assets: Asset[] = []
export const assetById = new Map<string, Asset>()
export const dependencies: Dependency[] = []
export const detectionsData: DetectionEvent[] = []
export const exposureFindings: ExposureFinding[] = []
export const whatChangedFeed: WhatChangedItem[] = []
export const riskTimelineData: RiskTimePoint[] = []
export const predictMap = new Map<string, AssetPredictDetails>()
export const sim = { day: 0, date: "", modelVersion: "", banner: "", lastUpdate: "", error: "" as string, refreshing: false }
export const chain = {
  connected: false,
  chainId: 0,
  block: 0,
  contracts: {} as Record<string, string>,
  auditLengths: {} as Record<string, number>,
  events: [] as { block: number; tx: string; contract: string; event: string; org: string }[],
  reassessments: 0,
}
export const traces: { org: string; count: number }[] = []
export const modelInfo: { raw: any } = { raw: null }
export const bandThresholds = { low: 7.8, medium: 14.62, high: 44.84 }

/* ------------------------------------------------------------------ change notification */

let version = 0
const listeners = new Set<() => void>()
const bump = () => {
  version++
  listeners.forEach((l) => l())
}
export function useLive() {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l)
      return () => listeners.delete(l)
    },
    () => version,
  )
}

/* ------------------------------------------------------------------ mapping helpers */

const LEVEL: Record<string, RiskLevel> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" }
const sev = (s: string) => LEVEL[String(s).toLowerCase()] ?? "Low"
const sentence = (s: string) => {
  const t = s.replace(/^(R\d+|EXP)_/, "").replace(/_/g, " ").toLowerCase()
  return t.charAt(0).toUpperCase() + t.slice(1)
}
const replace = <T,>(arr: T[], items: T[]) => {
  arr.length = 0
  arr.push(...items)
}

// Illustrative placement on the map's India outline (1000x840 space). Locations are not real asset sites.
const CITIES: Record<BackendOrg, [string, number, number][]> = {
  power: [["Delhi", 28.6, 77.2], ["Agra", 27.18, 78.01], ["Jaipur", 26.9, 75.8], ["Kota", 25.18, 75.83], ["Bhopal", 23.26, 77.4], ["Dehradun", 30.32, 78.03], ["Panipat", 29.39, 76.97], ["Lucknow", 26.85, 80.95]],
  water: [["Varanasi", 25.32, 82.97], ["Prayagraj", 25.43, 81.85], ["Kanpur", 26.45, 80.33], ["Haridwar", 29.95, 78.16], ["Mathura", 27.49, 77.67], ["Gwalior", 26.22, 78.18]],
  hospital: [["New Delhi", 28.61, 77.21], ["Lucknow", 26.85, 80.95], ["Jaipur", 26.92, 75.79], ["Chandigarh", 30.73, 76.78], ["Bhopal", 23.26, 77.41], ["Indore", 22.72, 75.86]],
}
const project = (lat: number, lon: number) => ({ x: 410 + (lon - 77.2) * 32, y: 265 + (28.6 - lat) * 28 })

/* ------------------------------------------------------------------ loading */

let inventory: Record<string, any> = {}
let lifeCriticalIds = new Set<string>()
const riskHistory = new Map<string, [number, number][]>()

function toPredict(id: string, w: any): AssetPredictDetails {
  const inv = inventory[id]
  const v = [...(w?.vulnerabilities ?? [])].sort((x: any, y: any) => (y.cvss ?? 0) - (x.cvss ?? 0))
  const mainV = v.find((x: any) => x.exploited) ?? v[0]
  const t = w?.trend
  const hist = (riskHistory.get(id) ?? []).map(([, r]) => r)
  return {
    shapFactors: (w?.shap?.factors ?? []).map((f: any) => ({
      feature: `${f.label} = ${typeof f.value === "number" ? +f.value.toFixed(2) : f.value}`,
      bpDelta: Math.round(f.contribution_logodds * 100),
      direction: f.contribution_logodds >= 0 ? "positive" : "negative",
    })),
    shapBase: w?.shap?.base_value ?? 0,
    missingDataIndicator: w?.missing?.length ? w.missing.join(", ") : undefined,
    holtForecastDays: t?.est_days_to_next_band ?? null,
    trendDirection: t?.direction ?? "unknown",
    evidenceFloorActive: false,
    // Holt level, then every score seen this session
    sparkline: [typeof t?.level_bp === "number" ? t.level_bp / 100 : null, ...hist].filter((x): x is number => typeof x === "number" && isFinite(x)),
    protectedLifeCritical: lifeCriticalIds.has(id),
    actions: w?.recommended_actions ?? [],
    patchDowntime: !!inv?.patch_requires_downtime,
    maintenanceWindow: inv?.maintenance_window ?? "none",
    vulnData: {
      cveId: mainV?.cve ?? "none",
      cvss: mainV?.cvss ?? 0,
      epss: mainV?.epss ?? 0,
      kevBadge: v.some((x: any) => x.exploited),
      patchAgeDays: w?.asset?.days_since_patch ?? 0,
      source: mainV?.source === "real_snapshot" ? "Real CISA/KEV/EPSS" : "Simulated",
    },
  }
}

/** SHAP, vulnerabilities, trend and what-if actions per asset; runs in the background after the core data. */
let explainRun = 0
export async function loadExplanations(ids: string[] = assets.map((a) => a.id), concurrency = 4) {
  const run = ++explainRun
  let since = 0
  await pool(ids, concurrency, async (id) => {
    const a = assetById.get(id)
    if (!a || run !== explainRun) return
    const w = await api(`/api/ps03/orgs/${BACKEND_ORG[a.org]}/assets/${id}/why`).catch(() => null)
    if (w && run === explainRun) predictMap.set(id, toPredict(id, w))
    if (++since >= 10) {
      since = 0
      afterLoad.forEach((h) => h())
      bump()
    }
  })
  if (run === explainRun) {
    afterLoad.forEach((h) => h())
    bump()
  }
}
/** Explanations for one asset, fetched now (used when its panel opens). */
export async function explainNow(id: string) {
  const a = assetById.get(id)
  if (!a) return
  const w = await api(`/api/ps03/orgs/${BACKEND_ORG[a.org]}/assets/${id}/why`).catch(() => null)
  if (w) {
    predictMap.set(id, toPredict(id, w))
    afterLoad.forEach((h) => h())
    bump()
  }
}

async function loadAll() {
  const health = await api("/api/ps03/health")
  sim.day = health.sim_day
  sim.date = health.date
  sim.banner = health.banner

  const perOrg = await Promise.all(
    ORGS.map(async (o) => {
      const [inv, att, services, changes, history] = await Promise.all([
        api<any[]>(`/api/orgs/${o}/assets`),
        api(`/api/ps03/orgs/${o}/attention?limit=100`),
        api<any[]>(`/api/orgs/${o}/services`),
        api(`/api/ps03/orgs/${o}/changes?since_day=${Math.max(0, health.sim_day - 7)}`),
        api(`/api/ps03/orgs/${o}/history`),
      ])
      return { o, inv, att, services, changes, history }
    }),
  )
  const [det, cross, info, chainStatus, chainLive, traceList] = await Promise.all([
    api("/api/ps03/detections"),
    api("/api/cross-org/graph"),
    api("/api/ps03/model/info"),
    api("/api/chain/status"),
    api("/api/ps03/chain/live?limit=12"),
    api<any[]>("/api/traces").catch(() => []),
  ])

  // inventory + scores
  inventory = {}
  const lifeCritical = new Set<string>()
  const newAssets: Asset[] = []
  for (const { o, inv, att, services } of perOrg) {
    const score = new Map<string, any>(att.items.map((x: any) => [x.asset_id, x]))
    for (const s of services) if (s.criticality === "life_critical") s.required_assets.forEach((id: string) => lifeCritical.add(id))
    inv.forEach((a: any, i: number) => {
      inventory[a.asset_id] = a
      const s = score.get(a.asset_id) ?? {}
      const vulns = [...(a.risk_ctx?.vulns ?? [])].sort((x: any, y: any) => (y.cvss ?? 0) - (x.cvss ?? 0))
      const [city, lat, lon] = CITIES[o][i % CITIES[o].length]
      const p = project(lat, lon)
      newAssets.push({
        id: a.asset_id,
        name: a.name,
        org: ORG_CODE[o],
        zone: a.zone,
        type: a.type,
        exposure: a.internet_exposed ? "Internet-facing" : `${a.zone} network`,
        vulnerability: vulns.length ? (vulns.length > 1 ? `${vulns[0].cve} +${vulns.length - 1}` : vulns[0].cve) : "Patched",
        likelihood: Math.round((s.likelihood ?? 0) * 100),
        impact: Math.round((s.impact ?? 0) * 100),
        risk: s.risk ?? 0,
        level: sev(s.band ?? "low"),
        x: p.x,
        y: p.y,
        cascade: (a.depends_on ?? []).join(" → ") || "None identified",
        location: city,
      })
    })
  }

  replace(
    organisations,
    perOrg.map(({ o, inv }) => ({ code: ORG_CODE[o], name: { power: "Grid Utility", water: "Water Board", hospital: "City Hospital" }[o], sector: { power: "Electricity", water: "Water", hospital: "Healthcare" }[o], totalAssets: inv.length, slug: o })),
  )

  // dependencies: intra-org (asset depends_on) + cross-org service edges, mapped to the riskiest asset of each service
  const deps: Dependency[] = []
  for (const a of Object.values(inventory)) for (const up of a.depends_on ?? []) deps.push({ from: up, to: a.asset_id, kind: "confirmed", label: `${a.name} depends on it` })
  const riskOf = (id: string) => newAssets.find((x) => x.id === id)?.risk ?? 0
  const svcByLabel = new Map<string, any>()
  for (const { o, services } of perOrg) for (const s of services) svcByLabel.set(`${o}:${s.name}`, s)
  const nodeLabel = new Map<string, string>(cross.nodes.map((n: any) => [`${n.org}:${n.service_hash}`, n.label]))
  const top = (s: any) => [...(s?.required_assets ?? [])].sort((x, y) => riskOf(y) - riskOf(x))[0]
  for (const e of cross.edges) {
    const pl = nodeLabel.get(`${e.provider_org}:${e.provider_service}`)
    const cl = nodeLabel.get(`${e.consumer_org}:${e.consumer_service}`)
    const from = top(svcByLabel.get(pl ?? ""))
    const to = top(svcByLabel.get(cl ?? ""))
    if (from && to) deps.push({ from, to, kind: e.confirmed ? "confirmed" : "potential", label: `${pl?.split(":")[1]} → ${cl?.split(":")[1]}` })
  }

  // risk seen per simulated day during this session (for the sparklines)
  lifeCriticalIds = lifeCritical
  for (const a of newAssets) {
    const h = riskHistory.get(a.id) ?? []
    if (h[h.length - 1]?.[0] !== health.sim_day) h.push([health.sim_day, a.risk])
    riskHistory.set(a.id, h.slice(-30))
  }

  // detections + exposure findings
  const name = (id: string) => newAssets.find((x) => x.id === id)?.name ?? id
  replace(
    detectionsData,
    [...det.active_attack]
      .sort((x: any, y: any) => y.sim_day - x.sim_day)
      .map((f: any) => ({
        id: f.finding_id,
        time: `${f.event_time} · day ${f.sim_day}`,
        assetId: f.asset_id,
        assetName: name(f.asset_id),
        ruleId: String(f.rule_id).split("_")[0],
        ruleName: sentence(f.rule_id),
        severity: sev(f.severity),
        evidence: (f.evidence ?? []).join("; "),
        simDay: f.sim_day,
      })),
  )
  replace(
    exposureFindings,
    [...det.exposure]
      .sort((x: any, y: any) => y.sim_day - x.sim_day)
      .map((f: any) => ({ code: f.rule_id, title: sentence(f.rule_id), assetId: f.asset_id, severity: sev(f.severity), description: (f.evidence ?? []).join("; "), discovered: `${f.event_time} · day ${f.sim_day}` })),
  )

  // what changed (last 7 simulated days, >= 1 risk point)
  replace(
    whatChangedFeed,
    perOrg
      .flatMap(({ o, changes }) =>
        changes.items.map((c: any, i: number) => ({
          id: `${o}-${i}-${c.asset_id}-${c.to_sim_day}`,
          assetId: c.asset_id,
          assetName: name(c.asset_id),
          sector: o,
          prevRiskBp: c.from_risk_bp,
          newRiskBp: c.to_risk_bp,
          deltaBp: c.to_risk_bp - c.from_risk_bp,
          cause: c.reasons?.[0]?.text ?? `${c.from_band} → ${c.to_band}`,
          timestamp: `day ${c.to_sim_day}`,
        })),
      )
      .filter((c: WhatChangedItem) => Math.abs(c.deltaBp) >= 100)
      .sort((x: WhatChangedItem, y: WhatChangedItem) => Math.abs(y.deltaBp) - Math.abs(x.deltaBp)),
  )

  // portfolio risk over time: mean of each org's last aggregate per simulated day (last 30 days)
  const byDay = new Map<number, Map<string, number>>()
  for (const { o, history } of perOrg) for (const h of history.aggregate) (byDay.get(h.sim_day) ?? byDay.set(h.sim_day, new Map()).get(h.sim_day)!).set(o, h.aggregate_bp)
  const days = [...byDay.keys()].sort((a, b) => a - b).slice(-30)
  replace(
    riskTimelineData,
    days.map((d) => {
      const vals = [...byDay.get(d)!.values()]
      const bp = Math.round(vals.reduce((s, x) => s + x, 0) / vals.length)
      return { day: `Day ${d}`, dayIndex: d, risk: bp / 100, riskBp: bp }
    }),
  )

  // model, chain, traces
  modelInfo.raw = info
  sim.modelVersion = info.model_version
  const bt = info.metrics?.band_thresholds
  if (bt) Object.assign(bandThresholds, { low: bt.risk_band_low_max, medium: bt.risk_band_medium_max, high: bt.risk_band_high_max })
  Object.assign(chain, {
    connected: chainStatus.connected,
    chainId: chainStatus.chain_id,
    block: chainStatus.block,
    contracts: chainStatus.contracts ?? {},
    auditLengths: chainStatus.audit_lengths ?? {},
    events: chainLive.events ?? [],
    reassessments: chainLive.reassessments ?? 0,
  })
  const counts = new Map<string, number>()
  for (const t of traceList) counts.set(t.org, (counts.get(t.org) ?? 0) + 1)
  replace(traces, [...counts].map(([org, count]) => ({ org, count })))

  replace(assets, newAssets)
  assetById.clear()
  newAssets.forEach((a) => assetById.set(a.id, a))
  const seenEdge = new Set<string>()
  replace(
    dependencies,
    deps.filter((d) => d.from !== d.to && !seenEdge.has(d.from + ">" + d.to) && !!seenEdge.add(d.from + ">" + d.to)),
  )
}

let loading: Promise<void> | null = null
export function refresh(): Promise<void> {
  if (loading) return loading
  sim.refreshing = true
  bump()
  loading = loadAll()
    .then(() => {
      sim.error = ""
      sim.lastUpdate = new Date().toLocaleTimeString()
      // explanations stream in afterwards, highest risk first, without blocking the pages
      queueMicrotask(() => loadExplanations([...assets].sort((x, y) => y.risk - x.risk).map((a) => a.id)))
    })
    .catch((e) => {
      sim.error = e instanceof Error ? e.message : String(e)
      throw e
    })
    .finally(() => {
      loading = null
      sim.refreshing = false
      afterLoad.forEach((h) => h())
      bump()
    })
  return loading
}
export const afterLoad: (() => void)[] = []

/** Poll the backend clock; reload everything when the simulated day moves (live mode advances it). */
export function startPolling(ms = 8000) {
  let lastDay = sim.day
  const tick = async () => {
    if (document.hidden) return
    try {
      const h = await api("/api/ps03/health")
      if (h.sim_day !== lastDay) {
        lastDay = h.sim_day
        await refresh()
      } else {
        const c = await api("/api/ps03/chain/live?limit=12")
        Object.assign(chain, { block: c.block, events: c.events ?? [], reassessments: c.reassessments ?? 0 })
        if (sim.error) sim.error = ""
        bump()
      }
    } catch (e) {
      sim.error = e instanceof Error ? e.message : String(e)
      bump()
    }
  }
  const id = setInterval(tick, ms)
  return () => clearInterval(id)
}

/** Run an action against the backend, then reload the data so every page reflects it. */
export async function mutate<T>(fn: () => Promise<T>): Promise<T> {
  const r = await fn()
  await refresh().catch(() => {})
  return r
}
