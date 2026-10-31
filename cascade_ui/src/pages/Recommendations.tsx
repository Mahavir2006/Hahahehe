import { useMemo, useState } from "react"
import { Check } from "lucide-react"
import { useNav } from "@/app/nav"
import { Card, Level, Tag, toast } from "@/components/ui"
import { actionsFor, levelColor, levelOf, portfolio, ranked, riskAfter, type Action } from "@/data/derive"

const KINDS: Action["kind"][] = ["Patch", "Segment", "Access control", "Monitoring", "Incident response"]

export default function Recommendations() {
  const { openAsset } = useNav()
  const [kinds, setKinds] = useState<Set<Action["kind"]>>(new Set(KINDS))
  const [approved, setApproved] = useState<Record<string, number>>({})

  // every action across the portfolio, ranked by absolute risk removed
  const all = useMemo(
    () =>
      ranked
        .flatMap((a) => actionsFor(a).map((x) => ({ a, x, gain: a.risk - riskAfter(a, [x]) })))
        .filter((r) => kinds.has(r.x.kind))
        .sort((p, q) => q.gain - p.gain),
    [kinds],
  )
  const top = all.slice(0, 10)
  const before = portfolio.avgRisk
  const afterAvg = ranked.reduce((s, a) => s + riskAfter(a, actionsFor(a).filter((x) => top.some((t) => t.x.id === x.id))), 0) / ranked.length

  const approve = (id: string, title: string) => {
    // optimistic: count the vote immediately
    setApproved((s) => ({ ...s, [id]: Math.min(2, (s[id] ?? 0) + 1) }))
    toast((approved[id] ?? 0) + 1 >= 2 ? "Approved — ready to execute" : "Approval 1 of 2 recorded", title)
  }

  return (
    <div className="page">
      <Card title="If you do the top 10 actions" sub="Estimated by the what-if model on the simulated portfolio">
        <div className="impact">
          <div>
            <span>Average risk now</span>
            <strong style={{ color: levelColor[levelOf(before)] }}>{before.toFixed(1)}</strong>
          </div>
          <div>
            <span>After top 10 actions</span>
            <strong style={{ color: levelColor[levelOf(afterAvg)] }}>{afterAvg.toFixed(1)}</strong>
          </div>
          <div>
            <span>Reduction</span>
            <strong className="ok">−{(((before - afterAvg) / before) * 100).toFixed(0)}%</strong>
          </div>
          <div>
            <span>Critical assets left</span>
            <strong>{ranked.filter((a) => levelOf(riskAfter(a, actionsFor(a).filter((x) => top.some((t) => t.x.id === x.id)))) === "Critical").length}</strong>
          </div>
        </div>
        <div className="seg wrap" role="group" aria-label="Action types">
          {KINDS.map((k) => (
            <button
              key={k}
              aria-pressed={kinds.has(k)}
              className={kinds.has(k) ? "active" : ""}
              onClick={() =>
                setKinds((s) => {
                  const n = new Set(s)
                  if (n.has(k)) n.delete(k)
                  else n.add(k)
                  return n.size ? n : s
                })
              }
            >
              {k}
            </button>
          ))}
        </div>
      </Card>

      <Card title="Prioritised action plan" sub="Biggest risk reduction first · every action needs 2 human approvals (ApprovalGate)">
        <ol className="plan">
          {top.map(({ a, x, gain }, i) => {
            const after = riskAfter(a, [x])
            const votes = approved[x.id] ?? 0
            return (
              <li key={x.id}>
                <span className="rank">{i + 1}</span>
                <div className="plan-body">
                  <strong>
                    <Tag tone="info">{x.kind}</Tag> {x.title}
                  </strong>
                  <small>{x.detail}</small>
                  <small className="muted">
                    Effort {x.effort} · downtime {x.downtime}
                  </small>
                </div>
                <button className="link plan-asset" onClick={() => openAsset(a.id)}>
                  {a.id}
                </button>
                <div className="plan-gain">
                  <span>
                    <b style={{ color: levelColor[a.level] }}>{a.risk.toFixed(1)}</b> → <b style={{ color: levelColor[levelOf(after)] }}>{after.toFixed(1)}</b>
                  </span>
                  <small className="ok">−{gain.toFixed(1)} pts</small>
                  <Level level={levelOf(after)} />
                </div>
                <button className={`btn ${votes >= 2 ? "btn-ok" : "btn-primary"}`} disabled={votes >= 2} onClick={() => approve(x.id, `${x.title} · ${a.id}`)}>
                  {votes >= 2 ? (
                    <>
                      <Check size={14} /> Approved
                    </>
                  ) : (
                    `Approve (${votes}/2)`
                  )}
                </button>
              </li>
            )
          })}
        </ol>
      </Card>
    </div>
  )
}
