// Incident response: what happens after an analyst decides to act. Each incident walks through the steps the
// platform performs (agents, ApprovalGate, AlertBus, teams), on an accelerated clock for the demo.
import { useSyncExternalStore } from "react"
import { appendAudit } from "./audit"
import { actionsFor, assetById, riskAfter } from "./derive"

export type ResponseAction = "isolate" | "plan" | "monitor"

export const TEAMS = [
  { id: "soc", label: "SOC on-call (Tier 2)", who: "Security operations" },
  { id: "field", label: "Field engineering at the site", who: "Plant / site team" },
  { id: "owner", label: "Asset-owner organisation", who: "Owning utility or hospital" },
  { id: "downstream", label: "Downstream organisations", who: "Sealed alert via AlertBus" },
  { id: "certin", label: "CERT-In incident report", who: "Required within 6 hours" },
  { id: "ciso", label: "CISO / management", who: "Escalation" },
] as const
export type TeamId = (typeof TEAMS)[number]["id"]

export const ACTIONS: Record<ResponseAction, { label: string; detail: string }> = {
  isolate: { label: "Isolate now", detail: "Emergency containment: cut external and partner access, keep the internal jump host. Pre-approved playbook, runs immediately." },
  plan: { label: "Apply the preventive plan", detail: "Patch, segment and harden as recommended. Needs two human approvals on ApprovalGate before it runs." },
  monitor: { label: "Monitor closely", detail: "Raise detection sensitivity and watch. No change to the asset yet." },
}

export interface Step {
  at: number // seconds after the incident opens (accelerated demo clock)
  label: string
  actor: string
  kind: "you" | "agent" | "human" | "chain" | "team"
}

export interface Incident {
  id: string
  title: string
  source: string
  assets: string[]
  action: ResponseAction
  teams: TeamId[]
  opened: number
  steps: Step[]
}

let incidents: Incident[] = []
let listeners = new Set<() => void>()
const emit = () => {
  incidents = [...incidents]
  listeners.forEach((l) => l())
}
let seq = 1040

export function openIncident(input: { title: string; source: string; assets: string[]; action: ResponseAction; teams: TeamId[] }): Incident {
  const main = assetById.get(input.assets[0])!
  const fixes = actionsFor(main)
  const after = input.action === "isolate" ? main.risk * 0.45 : input.action === "plan" ? riskAfter(main, fixes) : main.risk
  const teamLabel = (id: TeamId) => TEAMS.find((t) => t.id === id)!.label
  const steps: Step[] = [{ at: 0, label: `Incident opened · ${ACTIONS[input.action].label.toLowerCase()} chosen`, actor: "You", kind: "you" }]
  let t = 2
  if (input.action === "isolate") {
    steps.push({ at: t, label: `Executor agent isolates ${input.assets.slice(0, 3).join(", ")} (emergency playbook)`, actor: "Executor agent", kind: "agent" })
    steps.push({ at: (t += 3), label: "Containment verified: external sessions dropped, jump host intact", actor: "Executor agent", kind: "agent" })
  } else if (input.action === "plan") {
    steps.push({ at: t, label: `Planner agent drafts ${fixes.length} actions within the maintenance window`, actor: "Planner agent", kind: "agent" })
    steps.push({ at: (t += 3), label: "Critic agent checks safety constraints; verdict anchored on AuditLog", actor: "Critic agent", kind: "chain" })
    steps.push({ at: (t += 3), label: "Approver 1 signs on ApprovalGate", actor: "Security lead", kind: "human" })
    steps.push({ at: (t += 3), label: "Approver 2 signs — plan approved", actor: "Operations owner", kind: "human" })
    steps.push({ at: (t += 2), label: "Executor agent applies the plan", actor: "Executor agent", kind: "agent" })
  } else {
    steps.push({ at: t, label: "Detection rules D1–D6 raised to high sensitivity on the affected assets", actor: "Risk agent", kind: "agent" })
  }
  for (const id of input.teams) {
    t += 2
    const label =
      id === "downstream"
        ? "Sealed early-warning alert delivered to dependent organisations (AlertBus)"
        : id === "certin"
          ? "CERT-In incident report drafted and filed (6-hour window)"
          : `${teamLabel(id)} notified and assigned`
    steps.push({ at: t, label, actor: id === "downstream" ? "Cascade agent" : id === "certin" ? "Compliance" : TEAMS.find((x) => x.id === id)!.who, kind: id === "downstream" ? "chain" : "team" })
  }
  steps.push({ at: (t += 3), label: `Risk re-scored: ${main.id} ${main.risk.toFixed(1)} → ${after.toFixed(1)}`, actor: "Risk agent", kind: "agent" })
  steps.push({ at: (t += 2), label: input.action === "monitor" ? "Watching — will escalate automatically on the next detection" : "Contained · monitoring continues", actor: "CascadeShield", kind: "agent" })

  const inc: Incident = { id: `INC-${++seq}`, ...input, opened: Date.now(), steps }
  incidents = [inc, ...incidents]
  emit()
  appendAudit({ kind: input.action === "isolate" ? "Execution" : "Approval", actor: "Analyst (you)", contract: input.action === "isolate" ? "ApprovalGate (emergency)" : "ApprovalGate", subject: `${inc.id} · ${main.id}`, detail: `${ACTIONS[input.action].label}; notified ${input.teams.length} team(s)` })
  if (input.teams.includes("downstream")) appendAudit({ kind: "Alert", actor: "Cascade agent", contract: "AlertBus", subject: `${inc.id}`, detail: "Sealed alert to dependent organisations" })
  return inc
}

export function useIncidents() {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l)
      return () => listeners.delete(l)
    },
    () => incidents,
  )
}

/* ----- the response dialog can be opened from anywhere ----- */

export interface ResponseRequest {
  title: string
  source: string
  assets: string[]
  action?: ResponseAction
}
let request: ResponseRequest | null = null
let reqListeners = new Set<() => void>()
export function requestResponse(r: ResponseRequest | null) {
  request = r
  reqListeners.forEach((l) => l())
}
export function useResponseRequest() {
  return useSyncExternalStore(
    (l) => {
      reqListeners.add(l)
      return () => reqListeners.delete(l)
    },
    () => request,
  )
}

// one live incident from today's detections so the section is never empty
openIncident({ title: "Exploit indicator on the grid SCADA gateway", source: "Detection R6", assets: ["PG-003", "PG-008", "PG-001"], action: "isolate", teams: ["soc", "field", "downstream"] })
incidents[0].opened -= 60_000 // already finished by the time the page opens
listeners = new Set()
reqListeners = new Set()
