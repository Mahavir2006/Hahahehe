import { useMemo, useState } from "react"
import { useNav } from "@/app/nav"
import { Card, Level, Tag } from "@/components/ui"
import { Approvals } from "@/components/Approvals"
import { useLive } from "@/data/live"
import { actionsFor, levelColor, levelOf, portfolio, ranked, riskAfter, type Action } from "@/data/derive"

const KINDS: Action["kind"][] = ["Patch", "Segment", "Access control", "Monitoring", "Incident response"]

export default function Recommendations() {
  const { openAsset } = useNav()
  const [kinds, setKinds] = useState<Set<Action["kind"]>>(new Set(KINDS))
  const v = useLive()

  // every action across the portfolio, ranked by absolute risk removed
  const all = useMemo(
    () =>
      ranked
        .flatMap((a) => actionsFor(a).map((x) => ({ a, x, gain: a.risk - riskAfter(a, [x]) })))
        .filter((r) => kinds.has(r.x.kind))
        .sort((p, q) => q.gain - p.gain),
    [kinds, v],
  )
  const top = all.slice(0, 10)
  const before = portfolio.avgRisk
  const afterAvg = ranked.reduce((s, a) => s + riskAfter(a, actionsFor(a).filter((x) => top.some((t) => t.x.id === x.id))), 0) / ranked.length


  return (
    <div className="page">
      <Card title="If you do the top 10 actions" sub="Backend what-if: each action re-scored with the same M1 model on the live portfolio">
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

      <Card title="Prioritised action plan" sub="Biggest risk reduction first · open an asset to safety-check and submit a quarantine for approval">
        <ol className="plan">
          {top.map(({ a, x, gain }, i) => {
            const after = riskAfter(a, [x])
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
                <button className="btn btn-primary" onClick={() => openAsset(a.id)}>
                  Review
                </button>
              </li>
            )
          })}
        </ol>
      </Card>

      <Approvals />
    </div>
  )
}
