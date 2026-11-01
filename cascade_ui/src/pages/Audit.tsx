import { lazy, Suspense, useMemo, useState } from "react"
import { CheckCircle2, ShieldX, Undo2 } from "lucide-react"
import { Skeleton, Tag, toast } from "@/components/ui"
import { restoreAudit, tamperAudit, useAudit, verifyAudit, type AuditKind } from "@/data/audit"

const HowItWorks = lazy(() => import("./Platform"))
const short = (h: string) => `${h.slice(0, 10)}…${h.slice(-6)}`
const TONE: Partial<Record<AuditKind, "danger" | "warn" | "ok" | "info">> = { Approval: "ok", Execution: "ok", Alert: "warn", Detection: "danger", "Critic verdict": "info", Scenario: "info", Simulation: "info" }

/** Audit Trail: every decision as a hash-chained record you can verify and tamper-test. */
export default function Audit() {
  const entries = useAudit()
  const [tab, setTab] = useState<"log" | "how">("log")
  const [kind, setKind] = useState<"All" | AuditKind>("All")
  const [check, setCheck] = useState<{ ok: boolean; at: number | null } | null>(null)
  const kinds = useMemo(() => ["All", ...new Set(entries.map((e) => e.kind))] as ("All" | AuditKind)[], [entries])
  const list = [...entries].reverse().filter((e) => kind === "All" || e.kind === kind)
  const tampered = entries.some((e) => e.detail.endsWith("[edited]"))

  const verify = () => {
    const bad = verifyAudit()
    setCheck({ ok: bad === null, at: bad })
    toast(bad === null ? "Chain verified" : "Tampering detected", bad === null ? `All ${entries.length} entries match their hashes` : `Entry #${bad} no longer matches its hash`, bad === null ? "ok" : "warn")
  }

  return (
    <div className="page">
      <div className="seg" role="tablist" aria-label="Audit views">
        <button role="tab" aria-selected={tab === "log"} className={tab === "log" ? "active" : ""} onClick={() => setTab("log")}>
          Audit log
        </button>
        <button role="tab" aria-selected={tab === "how"} className={tab === "how" ? "active" : ""} onClick={() => setTab("how")}>
          How the trust layer works
        </button>
      </div>

      {tab === "how" ? (
        <Suspense fallback={<Skeleton h={420} />}>
          <HowItWorks />
        </Suspense>
      ) : (
        <>
          <div className="audit-bar glass">
            <div>
              <strong>{entries.length} recorded decisions</strong>
              <small>Agents, organisations and you. Each hash covers the previous one — edit any entry and the chain breaks from there.</small>
            </div>
            <div className="audit-actions">
              <button className="btn btn-primary" onClick={verify}>
                <CheckCircle2 size={14} /> Verify chain
              </button>
              {tampered ? (
                <button
                  className="btn"
                  onClick={() => {
                    restoreAudit()
                    setCheck(null)
                  }}
                >
                  <Undo2 size={14} /> Restore
                </button>
              ) : (
                <button
                  className="btn"
                  onClick={() => {
                    tamperAudit(Math.max(1, Math.ceil(entries.length / 2)))
                    setCheck(null)
                    toast("One entry was edited", "Now press Verify chain", "warn")
                  }}
                >
                  <ShieldX size={14} /> Simulate tampering
                </button>
              )}
            </div>
          </div>

          {check && (
            <div className={`audit-check ${check.ok ? "ok" : "bad"}`} role="status">
              {check.ok ? <CheckCircle2 size={16} /> : <ShieldX size={16} />}
              {check.ok ? `Intact: all ${entries.length} hashes match.` : `Broken at entry #${check.at}: its content no longer matches the hash that later entries were built on.`}
            </div>
          )}

          <div className="seg wrap" role="group" aria-label="Filter by type">
            {kinds.map((k) => (
              <button key={k} aria-pressed={kind === k} className={kind === k ? "active" : ""} onClick={() => setKind(k)}>
                {k}
              </button>
            ))}
          </div>

          <section className="glass pane">
            <div className="table-wrap">
              <table className="tbl ledger">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Time</th>
                    <th>Event</th>
                    <th className="hide-sm">Recorded by</th>
                    <th className="hide-sm">Previous hash</th>
                    <th>Entry hash</th>
                  </tr>
                </thead>
                <tbody>
                  {list.map((e) => {
                    const broken = check && !check.ok && check.at !== null && e.n >= check.at
                    return (
                      <tr key={e.n} className={broken ? "broken" : ""}>
                        <td>{e.n}</td>
                        <td>{e.time}</td>
                        <td>
                          <Tag tone={TONE[e.kind] ?? "neutral"}>{e.kind}</Tag> <strong>{e.subject}</strong>
                          <small>{e.detail}</small>
                        </td>
                        <td className="hide-sm">
                          {e.actor}
                          <small>{e.contract}</small>
                        </td>
                        <td className="hide-sm">
                          <code>{short(e.prev)}</code>
                        </td>
                        <td>
                          <code className="hash">{short(e.hash)}</code>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
            <p className="muted small">On-chain entries hold commitments and hashes only; risk details stay sealed between the organisations involved. Demo hashes use a fast stand-in for keccak256.</p>
          </section>
        </>
      )}
    </div>
  )
}
