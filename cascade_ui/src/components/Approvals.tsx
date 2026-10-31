import { useCallback, useEffect, useRef, useState } from "react"
import { Check, RotateCcw, Play, X } from "lucide-react"
import { api, mutate } from "@/data/live"
import { Card, EmptyState, Tag, toast } from "./ui"

interface Plan {
  org: string
  plan_id: string
  risk_before: number
  risk_after: number
  steps: number
  critic?: { verdict: string; anchor_status?: string }
}
interface Voter {
  approver: string
  safety_officer: boolean
  voted: boolean
}
interface Request {
  request_id: string
  org: string
  plan_id: string
  status: string
  impact: string
  required: number
  approvals: number
  rejections: number
  approvers: Voter[]
  seconds_left: number
}

const short = (h: string) => `${h.slice(0, 10)}…${h.slice(-6)}`

/** Live human-approval queue on ApprovalGate: vote, execute after approval, roll back. */
export function Approvals() {
  const [plans, setPlans] = useState<Plan[] | null>(null)
  const [reqs, setReqs] = useState<Record<string, Request>>({})
  const [done, setDone] = useState<Record<string, "executed" | "rolled back">>({})
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState("")
  const inFlight = useRef(false) // one vote/execute at a time, even on fast double clicks

  const load = useCallback(async () => {
    try {
      const [ps, pending] = await Promise.all([api<Plan[]>("/api/plans"), api<{ request_id: string; plan_id: string }[]>("/api/approvals")])
      const views = await Promise.all(pending.map((p) => api<Request>(`/api/approvals/${p.request_id}`).then((v) => ({ ...v, plan_id: p.plan_id }))))
      setPlans(ps.reverse())
      setReqs(Object.fromEntries(views.map((v) => [v.plan_id, v])))
      setError("")
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }, [])
  useEffect(() => {
    load()
    const id = setInterval(() => !document.hidden && load(), 10_000)
    return () => clearInterval(id)
  }, [load])

  const run = async (key: string, label: string, fn: () => Promise<unknown>, after?: () => void) => {
    if (inFlight.current) return
    inFlight.current = true
    setBusy(key)
    try {
      await mutate(fn)
      after?.()
      toast(label)
    } catch (e) {
      toast(`${label} failed`, e instanceof Error ? e.message : String(e), "warn")
    } finally {
      inFlight.current = false
      setBusy(null)
      load()
    }
  }

  if (error && !plans) return <Card title="Human approvals (ApprovalGate)"><EmptyState title="Could not load plans" body={error} action={<button className="btn" onClick={load}>Retry</button>} /></Card>

  return (
    <Card title="Human approvals (ApprovalGate, live)" sub="Plans from the Planner + Critic agents · AI cannot vote · execution only after the on-chain threshold">
      {!plans ? (
        <p className="muted">Loading plans…</p>
      ) : !plans.length ? (
        <EmptyState title="No plans yet" body="Plans appear when an advisory is ingested or a quarantine is requested from an asset panel." />
      ) : (
        <ol className="plan">
          {plans.slice(0, 12).map((p) => {
            const r = reqs[p.plan_id]
            const state = done[p.plan_id]
            const approved = r?.status === "Approved"
            return (
              <li key={p.plan_id}>
                <span className="rank">{p.org.slice(0, 1).toUpperCase()}</span>
                <div className="plan-body">
                  <strong>
                    <code>{p.plan_id}</code> <Tag tone={p.critic?.verdict === "APPROVE_FOR_GATE" ? "ok" : "warn"}>Critic: {p.critic?.verdict ?? "none"}</Tag>
                  </strong>
                  <small>
                    {p.org} · {p.steps} steps · org risk {p.risk_before.toFixed(1)} → {p.risk_after.toFixed(1)}
                  </small>
                  {r && (
                    <small className="muted">
                      Request {short(r.request_id)} · {r.status} · {r.approvals}/{r.required} approvals · impact {r.impact} · {Math.round(r.seconds_left / 60)} min left
                    </small>
                  )}
                  {state ? <Tag tone="info">{state}</Tag> : !r && <Tag>no open approval request (approved and run, rejected, or expired)</Tag>}
                </div>
                <div className="row-actions">
                  {r && r.status === "Pending" &&
                    r.approvers.map((v, i) =>
                      v.voted ? (
                        <Tag key={v.approver} tone="ok">
                          <Check size={11} /> approver {i + 1}
                        </Tag>
                      ) : (
                        <button key={v.approver} className="btn btn-primary" disabled={busy !== null} onClick={() => run(p.plan_id, `Approver ${i + 1} approved ${p.plan_id}`, () => api(`/api/approvals/${r.request_id}/approve`, { org: p.org, approver: i }, 120_000))}>
                          Approve as {i + 1}
                          {v.safety_officer ? " (safety)" : ""}
                        </button>
                      ),
                    )}
                  {r && r.status === "Pending" && (
                    <button className="btn btn-ghost" disabled={busy !== null} onClick={() => run(p.plan_id, `Rejected ${p.plan_id}`, () => api(`/api/approvals/${r.request_id}/reject`, { org: p.org, approver: r.approvers.findIndex((v) => !v.voted) }))}>
                      <X size={13} /> Reject
                    </button>
                  )}
                  {approved && state !== "executed" && (
                    <button className="btn btn-ok" disabled={busy !== null} onClick={() => run(p.plan_id, `Executor ran ${p.plan_id}`, () => api(`/api/plans/${p.plan_id}/execute`, { request_id: r.request_id }, 120_000), () => setDone((d) => ({ ...d, [p.plan_id]: "executed" })))}>
                      <Play size={13} /> Execute
                    </button>
                  )}
                  {state === "executed" && (
                    <button className="btn btn-ghost" disabled={busy !== null} onClick={() => run(p.plan_id, `Rolled back ${p.plan_id}`, () => api(`/api/plans/${p.plan_id}/rollback`, {}, 120_000), () => setDone((d) => ({ ...d, [p.plan_id]: "rolled back" })))}>
                      <RotateCcw size={13} /> Roll back
                    </button>
                  )}
                </div>
              </li>
            )
          })}
        </ol>
      )}
    </Card>
  )
}
