import { useMemo, useState } from "react"
import { ArrowRight, Check, KeyRound, Radar, ShieldAlert, TimerOff, Cpu } from "lucide-react"
import { useNav } from "@/app/nav"
import { Level, Tag, toast } from "@/components/ui"
import { appendAudit } from "@/data/audit"
import { requestResponse } from "@/data/incidents"
import { actionsFor, assets, levelColor, levelOf, predict, riskAfter, riskTimelineData, sectorOf, whatChangedFeed, type Action, type Asset } from "@/data/derive"
import { useLive } from "@/data/live"

interface Scenario {
  id: string
  icon: typeof Radar
  title: string
  trigger: string
  /** Extra compromise likelihood (points) this situation adds to an asset, with the reason. */
  effect: (a: Asset) => { add: number; why: string } | null
  fixes: Action["kind"][]
}

const SCENARIOS: Scenario[] = [
  {
    id: "kev",
    icon: ShieldAlert,
    title: "A CVE in our estate is now exploited in the wild",
    trigger: "CISA adds a CVE we run to the Known Exploited Vulnerabilities list",
    effect: (a) => (predict(a.id).vulnData.kevBadge || (a.vulnerability.startsWith("CVE") && a.exposure !== "Private") ? { add: 14, why: "known-exploited CVE on this asset" } : null),
    fixes: ["Patch", "Segment"],
  },
  {
    id: "creds",
    icon: KeyRound,
    title: "Vendor remote-access credentials leak",
    trigger: "Threat intel finds vendor VPN logins for sale",
    effect: (a) => (/vpn|remote|gateway/i.test(a.type + a.name) ? { add: 18, why: "reachable with leaked vendor credentials" } : a.exposure === "Partner network" ? { add: 7, why: "reachable from the partner network" } : null),
    fixes: ["Access control", "Monitoring"],
  },
  {
    id: "firmware",
    icon: Cpu,
    title: "Tampered firmware found at a supplier",
    trigger: "FirmwareRegistry hash mismatch for a vendor's OT controllers",
    effect: (a) => (/plc|hmi|scada|bms|ot|telemetry/i.test(a.type) ? { add: 12, why: "runs controller firmware from the affected supplier" } : null),
    fixes: ["Monitoring", "Incident response"],
  },
  {
    id: "scan",
    icon: Radar,
    title: "Surge in scanning against Indian OT",
    trigger: "Sensor network sees 5× normal scanning of OT ports",
    effect: (a) => (a.exposure.includes("Internet") ? { add: 12, why: "internet-facing" } : a.exposure === "Partner network" ? { add: 5, why: "partner-exposed" } : null),
    fixes: ["Segment", "Monitoring"],
  },
  {
    id: "patch",
    icon: TimerOff,
    title: "Next patch window is missed",
    trigger: "Maintenance slips by 30 days",
    effect: (a) => (a.vulnerability !== "Patched" ? { add: 8, why: "open vulnerability stays unpatched 30 more days" } : null),
    fixes: ["Patch"],
  },
]

/** Recompute risk with extra likelihood, keeping each asset's own calibration of likelihood × impact. */
function riskWith(a: Asset, add: number) {
  const scale = a.risk / ((a.likelihood * a.impact) / 100)
  return Math.min(99, (Math.min(99, a.likelihood + add) * a.impact * scale) / 100)
}

export default function Proactive() {
  const { openAsset } = useNav()
  const [sid, setSid] = useState("kev")
  const [applied, setApplied] = useState<Record<string, boolean>>({})
  const [day, setDay] = useState(7)
  useLive()
  const sc = SCENARIOS.find((s) => s.id === sid)!

  const rows = useMemo(
    () =>
      assets
        .map((a) => {
          const e = sc.effect(a)
          if (!e) return null
          const projected = riskWith(a, e.add)
          const fixes = actionsFor(a).filter((x) => sc.fixes.includes(x.kind))
          const prevented = riskAfter({ ...a, risk: projected }, fixes)
          return { a, why: e.why, projected, fixes, prevented }
        })
        .filter((r): r is NonNullable<typeof r> => !!r)
        .sort((x, y) => y.projected - x.projected),
    [sc],
  )
  const crossing = rows.filter((r) => levelOf(r.projected) !== r.a.level)
  const isApplied = applied[sid]
  // the last 7 simulated days from the backend; each day's biggest real risk change is the event of the day
  const week = riskTimelineData.slice(-7)
  const point = week[day - 1]
  const step = (() => {
    const ch = whatChangedFeed.filter((c) => point && c.timestamp === `day ${point.dayIndex}`).sort((x, y) => Math.abs(y.deltaBp) - Math.abs(x.deltaBp))[0]
    if (!ch) return undefined
    const up = ch.deltaBp > 0
    return {
      title: `${ch.assetId} ${up ? "rose" : "fell"} ${Math.abs(ch.deltaBp / 100).toFixed(1)} risk points`,
      description: `${ch.assetName}: ${ch.cause}.`,
      targetAsset: ch.assetId,
      action: up ? "Re-scored; pre-stage containment if it keeps rising" : "Re-scored; lower risk confirmed",
    }
  })()

  const apply = () => {
    setApplied((s) => ({ ...s, [sid]: true }))
    appendAudit({ kind: "Scenario", actor: "Analyst (you)", contract: "ApprovalGate", subject: sc.title, detail: `Preventive plan requested for ${rows.length} asset(s) before the threat lands` })
    toast("Preventive plan sent for approval", `${rows.reduce((n, r) => n + r.fixes.length, 0)} actions across ${rows.length} assets`)
  }

  return (
    <div className="page">
      <div className="scen-grid" role="tablist" aria-label="Scenarios">
        {SCENARIOS.map((s) => (
          <button key={s.id} role="tab" aria-selected={s.id === sid} className={`glass scen-card ${s.id === sid ? "active" : ""}`} onClick={() => setSid(s.id)}>
            <s.icon size={18} aria-hidden />
            <strong>{s.title}</strong>
            <small>{s.trigger}</small>
          </button>
        ))}
      </div>

      <div className="scen-body">
        <section className="glass pane">
          <div className="pane-row">
            <h2 className="pane-title">If this happens — predicted impact</h2>
            <Tag tone={crossing.length ? "danger" : "ok"}>{crossing.length} asset(s) jump a risk band</Tag>
          </div>
          {rows.length ? (
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Asset</th>
                    <th className="hide-sm">Why it's affected</th>
                    <th>Today</th>
                    <th>If it happens</th>
                    <th>With preventive fixes</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.a.id} tabIndex={0} onClick={() => openAsset(r.a.id)} onKeyDown={(e) => e.key === "Enter" && openAsset(r.a.id)}>
                      <td>
                        <strong>{r.a.id}</strong>
                        <small style={{ color: sectorOf[r.a.org].color }}>{r.a.name}</small>
                      </td>
                      <td className="hide-sm">{r.why}</td>
                      <td>
                        <b style={{ color: levelColor[r.a.level] }}>{r.a.risk.toFixed(1)}</b>
                      </td>
                      <td>
                        <div className="risk-cell">
                          <b style={{ color: levelColor[levelOf(r.projected)] }}>{r.projected.toFixed(1)}</b>
                          <Level level={levelOf(r.projected)} />
                        </div>
                      </td>
                      <td>
                        <div className="risk-cell">
                          <b style={{ color: levelColor[levelOf(r.prevented)] }}>{r.prevented.toFixed(1)}</b>
                          <small>{r.fixes.map((f) => f.kind).join(" + ") || "monitor"}</small>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="muted">No monitored asset is exposed to this situation.</p>
          )}
          <div className="scen-actions">
            <button className="btn btn-danger" disabled={!rows.length} onClick={() => requestResponse({ title: sc.title, source: "Proactive scenario", assets: rows.map((r) => r.a.id), action: "isolate" })}>
              Respond now — isolate & notify
            </button>
            <button className="btn btn-primary" disabled={!rows.length || isApplied} onClick={apply}>
              {isApplied ? (
                <>
                  <Check size={14} /> Preventive plan requested
                </>
              ) : (
                <>
                  Request preventive plan <ArrowRight size={14} />
                </>
              )}
            </button>
            <small className="muted">Requests go to human approvers and are recorded in the Audit Trail.</small>
          </div>
        </section>

        <section className="glass pane">
          <h2 className="pane-title">Last 7 simulated days — what the monitoring saw</h2>
          <input className="day-slider" type="range" min={1} max={7} value={day} onChange={(e) => setDay(Number(e.target.value))} aria-label="Day of the simulated week" />
          <div className="day-ticks">
            {Array.from({ length: 7 }, (_, i) => (
              <button key={i} className={day === i + 1 ? "active" : ""} onClick={() => setDay(i + 1)}>
                {week[i] ? `D${week[i].dayIndex}` : `D${i + 1}`}
              </button>
            ))}
          </div>
          <div className="day-card">
            <span className="eyebrow">Simulated day {point?.dayIndex ?? "–"}{day === week.length ? " · today" : ""}</span>
            <strong>{step?.title ?? "Steady state"}</strong>
            <p>{step?.description ?? "No asset moved by a full risk point; monitoring continues."}</p>
            <dl className="kv">
              <dt>Portfolio risk</dt>
              <dd>{point?.risk.toFixed(1)}</dd>
              <dt>System response</dt>
              <dd>{step?.action ?? "Routine reassessment"}</dd>
              {step && (
                <>
                  <dt>Asset in focus</dt>
                  <dd>
                    <button className="link" onClick={() => openAsset(step.targetAsset)}>
                      {step.targetAsset}
                    </button>
                  </dd>
                </>
              )}
            </dl>
          </div>
        </section>
      </div>
    </div>
  )
}
