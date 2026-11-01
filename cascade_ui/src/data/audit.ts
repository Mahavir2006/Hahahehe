// Tamper-evident audit trail for the demo. Each entry's hash covers the previous hash plus its own content,
// mirroring the AuditLog contract: change any entry and every later link breaks. Lives in memory for the session.
import { useSyncExternalStore } from "react"

export type AuditKind = "Attestation" | "Detection" | "Critic verdict" | "Approval" | "Execution" | "Alert" | "Scenario" | "Simulation"

export interface AuditEntry {
  n: number
  time: string
  kind: AuditKind
  actor: string // agent or human role
  contract: string
  subject: string
  detail: string
  prev: string
  hash: string
}

/** 256-bit hex digest built from four FNV-1a lanes (fast, deterministic; stands in for keccak256 in the demo). */
export function digest(text: string): string {
  let out = ""
  for (let lane = 0; lane < 8; lane++) {
    let h = (2166136261 ^ (lane * 16777619)) >>> 0
    for (let i = 0; i < text.length; i++) h = Math.imul(h ^ text.charCodeAt(i), 16777619) >>> 0
    out += h.toString(16).padStart(8, "0")
  }
  return "0x" + out
}

const GENESIS = "0x" + "0".repeat(64)
const body = (e: Omit<AuditEntry, "prev" | "hash">) => [e.n, e.time, e.kind, e.actor, e.contract, e.subject, e.detail].join("|")

let entries: AuditEntry[] = []
let listeners = new Set<() => void>()
const emit = () => {
  entries = [...entries]
  listeners.forEach((l) => l())
}

export function appendAudit(e: Omit<AuditEntry, "n" | "time" | "prev" | "hash"> & { time?: string }) {
  const prev = entries.at(-1)?.hash ?? GENESIS
  const base = { ...e, n: entries.length + 1, time: e.time ?? new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) }
  entries.push({ ...base, prev, hash: digest(prev + body(base)) })
  emit()
}

/** Recompute the chain; returns the first entry whose stored hash no longer matches, or null if intact. */
export function verifyAudit(): number | null {
  let prev = GENESIS
  for (const e of entries) {
    if (e.prev !== prev || digest(prev + body(e)) !== e.hash) return e.n
    prev = e.hash
  }
  return null
}

/** Demo: silently edit one entry's content (as an attacker with database access would). */
export function tamperAudit(n: number) {
  entries = entries.map((e) => (e.n === n ? { ...e, detail: e.detail + " [edited]" } : e))
  emit()
}

/** Undo the demo tampering by rebuilding the chain from the original seed + session events. */
export function restoreAudit() {
  const clean = entries.map((e) => ({ ...e, detail: e.detail.replace(/ \[edited\]$/, "") }))
  entries = []
  for (const e of clean) appendAudit(e)
}

export function useAudit() {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l)
      return () => listeners.delete(l)
    },
    () => entries,
  )
}

// Seed: illustrative entries so the tamper demo has a chain to verify (the real on-chain record is on Chain Proof).
;[
  { time: "09:12:04", kind: "Attestation", actor: "Org: Grid Utility", contract: "AttestationRegistry", subject: "Grid Utility ↔ Water Board", detail: "Dependency edge confirmed by both sides (sealed terms)" },
  { time: "09:12:31", kind: "Attestation", actor: "Org: Water Board", contract: "AttestationRegistry", subject: "Water Board ↔ City Hospital", detail: "Dependency edge confirmed by both sides (sealed terms)" },
  { time: "09:40:12", kind: "Detection", actor: "Intake agent", contract: "AttestationRegistry", subject: "CVE-2024-3400", detail: "Advisory matched to inventory; finding committed (blinded)" },
  { time: "09:40:55", kind: "Attestation", actor: "Risk agent", contract: "AttestationRegistry", subject: "power asset (sealed)", detail: "Risk band commitment published (band sealed, not readable)" },
  { time: "09:41:20", kind: "Alert", actor: "Cascade agent", contract: "AlertBus", subject: "Grid Utility → Water Board", detail: "Sealed early-warning alert sent to the direct consumer" },
  { time: "09:42:03", kind: "Critic verdict", actor: "Critic agent", contract: "AuditLog", subject: "Plan (example)", detail: "APPROVE_FOR_GATE — constraints and maintenance window respected" },
  { time: "09:42:10", kind: "Approval", actor: "Planner agent", contract: "ApprovalGate", subject: "Plan (example)", detail: "Approval requested; 2 human approvers required" },
].forEach((e) => appendAudit(e as Parameters<typeof appendAudit>[0]))
listeners = new Set()
