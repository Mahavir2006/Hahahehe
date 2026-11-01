// Cascade simulation over the dependency graph: if one asset is compromised, which assets degrade, when,
// and with what probability — and what containment would prevent. Simulated model for the demo.
import { assetById, dependencies, type Asset } from "./derive"

/** Minutes for a failure to propagate across each kind of link (demo assumptions). */
const DELAY: Record<string, number> = {
  "Remote access path": 10,
  "Vendor access path": 12,
  "Control link": 15,
  "Generation feed": 20,
  "Power supply": 20,
  "Cooling control": 25,
  "Flow control": 30,
  "Standby power": 30,
  "Pressure telemetry": 35,
  Telemetry: 40,
  "Credential reuse": 45,
  "Pressure loss impact": 90,
}
const STRENGTH = { confirmed: 0.85, potential: 0.5 }

export const CONSEQUENCE: Record<string, string> = {
  WGEC: "Power supply disrupted",
  MetroWater: "Water pumping and pressure lost",
  CCMN: "Clinical services delayed",
}

export interface SimOptions {
  /** Isolate the source after this many minutes (null = no containment). */
  containAt: number | null
  /** Partner/cross-organisation links are segmented (blocked). */
  segmentPartners: boolean
}

export interface SimStep {
  asset: Asset
  from: string
  via: string
  kind: "confirmed" | "potential"
  hop: number
  minute: number
  p: number
  status: "impacted" | "prevented"
  reason?: string
}

export function simulate(sourceId: string, opt: SimOptions): SimStep[] {
  const src = assetById.get(sourceId)
  if (!src) return []
  const out: SimStep[] = []
  const best = new Map<string, number>([[sourceId, 0]])
  // Dijkstra-style by arrival time so each asset is reached by its fastest path
  const queue: { id: string; minute: number; p: number; hop: number; blocked: string | null }[] = [{ id: sourceId, minute: 0, p: 1, hop: 0, blocked: null }]
  while (queue.length) {
    queue.sort((a, b) => a.minute - b.minute)
    const cur = queue.shift()!
    for (const d of dependencies.filter((x) => x.from === cur.id)) {
      const target = assetById.get(d.to)
      if (!target) continue
      const minute = cur.minute + (DELAY[d.label] ?? 30)
      if ((best.get(d.to) ?? Infinity) <= minute) continue
      best.set(d.to, minute)
      const p = cur.p * STRENGTH[d.kind]
      const crossOrg = assetById.get(d.from)!.org !== target.org
      let reason = cur.blocked
      if (!reason && opt.segmentPartners && crossOrg) reason = "partner link segmented"
      if (!reason && opt.containAt !== null && minute > opt.containAt) reason = `source isolated at ${opt.containAt} min`
      out.push({ asset: target, from: d.from, via: d.label, kind: d.kind, hop: cur.hop + 1, minute, p, status: reason ? "prevented" : "impacted", reason: reason ?? undefined })
      queue.push({ id: d.to, minute, p, hop: cur.hop + 1, blocked: reason })
    }
  }
  // a later, faster path may reach an asset again: keep only the earliest arrival per asset
  const first = new Map<string, SimStep>()
  for (const st of out) if (!first.has(st.asset.id) || first.get(st.asset.id)!.minute > st.minute) first.set(st.asset.id, st)
  return [...first.values()].sort((a, b) => a.minute - b.minute)
}

export const fmtMin = (m: number) => (m < 60 ? `${m} min` : `${Math.floor(m / 60)} h ${m % 60 ? `${m % 60} min` : ""}`.trim())
