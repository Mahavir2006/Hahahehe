// Simulated live threat stream for India only. Seeded from the project's detections, exposure findings and
// asset risk, so the busiest targets on the map are the assets the model rates riskiest. Not real traffic.
import { assets, dependencies, detectionsData, exposureFindings, predict, type Asset } from "./derive"

export type AttackType = "exploit" | "intrusion" | "bruteforce" | "recon" | "ot" | "lateral"

export const ATTACK_TYPES: Record<AttackType, { label: string; color: string }> = {
  exploit: { label: "Exploit attempt", color: "#ff4d5e" },
  intrusion: { label: "Remote-access intrusion", color: "#ff9f43" },
  bruteforce: { label: "Brute force", color: "#ffd166" },
  recon: { label: "Scanning / recon", color: "#4cc9f0" },
  ot: { label: "OT protocol abuse", color: "#b388ff" },
  lateral: { label: "Lateral movement", color: "#f472b6" },
}

const RULE_TYPE: Record<string, AttackType> = {
  "Exploit indicator": "exploit",
  "Remote access": "intrusion",
  "Auth failures": "bruteforce",
  "OT protocol": "ot",
  "Lateral movement": "lateral",
  "Config change": "recon",
}

export interface ThreatEvent {
  id: number
  type: AttackType
  target: string // asset id
  from: string | null // asset id for lateral movement, otherwise an external origin
  origin: number // index into the external origins
  note: string
}

function rng(seed: number) {
  let s = seed >>> 0
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32)
}

/** Weighted pick: riskier assets attract more activity. */
function pickAsset(r: () => number): Asset {
  const total = assets.reduce((s, a) => s + a.risk ** 2, 0)
  let x = r() * total
  for (const a of assets) if ((x -= a.risk ** 2) <= 0) return a
  return assets[0]
}

function typeFor(a: Asset, r: () => number): AttackType {
  const p = predict(a.id)
  const roll = r()
  if (p.vulnData.kevBadge && roll < 0.45) return "exploit"
  if (/vpn|remote|gateway/i.test(a.type + a.name) && roll < 0.65) return "intrusion"
  if (/plc|hmi|scada|ot|telemetry/i.test(a.type) && roll < 0.75) return "ot"
  return roll < 0.88 ? "recon" : "bruteforce"
}

/** Endless, repeatable event sequence: real detections first, then seeded traffic. */
export function* threatStream(seed = 42): Generator<Omit<ThreatEvent, "id">> {
  const r = rng(seed)
  for (const d of detectionsData) {
    const t = RULE_TYPE[d.ruleName] ?? "recon"
    const dep = t === "lateral" ? dependencies.find((x) => x.to === d.assetId) : undefined
    yield { type: t, target: d.assetId, from: dep?.from ?? null, origin: Math.floor(r() * 8), note: d.evidence }
  }
  for (const x of exposureFindings) yield { type: "recon", target: x.assetId, from: null, origin: Math.floor(r() * 8), note: x.title }
  for (;;) {
    if (r() < 0.14) {
      const dep = dependencies[Math.floor(r() * dependencies.length)]
      yield { type: "lateral", target: dep.to, from: dep.from, origin: 0, note: `Movement along ${dep.label.toLowerCase()} link` }
      continue
    }
    const a = pickAsset(r)
    const type = typeFor(a, r)
    yield { type, target: a.id, from: null, origin: Math.floor(r() * 8), note: `${ATTACK_TYPES[type].label} on ${a.type.toLowerCase()} ${a.id}` }
  }
}
