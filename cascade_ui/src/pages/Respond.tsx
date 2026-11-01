import { useEffect, useState } from "react"
import { Bot, CheckCircle2, Circle, Link2, Siren, UserCheck, Users, UserRound } from "lucide-react"
import { useNav } from "@/app/nav"
import { Tag } from "@/components/ui"
import { ranked, levelColor } from "@/data/derive"
import { ACTIONS, TEAMS, requestResponse, useIncidents, type Step } from "@/data/incidents"

const ICON: Record<Step["kind"], typeof Bot> = { you: UserRound, agent: Bot, human: UserCheck, chain: Link2, team: Users }
const WHO: Record<Step["kind"], string> = { you: "You", agent: "Automated", human: "Human approver", chain: "On-chain", team: "Team" }

/** Incident Response: every response in flight, step by step, with who (or what) does each step. */
export default function Respond() {
  const incidents = useIncidents()
  const { openAsset } = useNav()
  const [now, setNow] = useState(Date.now())
  const [openId, setOpenId] = useState<string | null>(incidents[0]?.id ?? null)
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 500)
    return () => clearInterval(t)
  }, [])
  useEffect(() => setOpenId((id) => id ?? incidents[0]?.id ?? null), [incidents])
  const top = ranked[0]

  return (
    <div className="page">
      <div className="respond-top glass">
        <div>
          <strong>{incidents.length} incident(s)</strong>
          <small>Open one from a detection, a cascade simulation, a proactive scenario or any asset with “Respond now”.</small>
        </div>
        <button className="btn btn-primary" onClick={() => requestResponse({ title: `Contain ${top.name}`, source: "Manual", assets: [top.id] })}>
          <Siren size={14} /> New response for {top.id}
        </button>
      </div>

      <div className="inc-list">
        {incidents.map((inc) => {
          const elapsed = (now - inc.opened) / 1000
          const done = inc.steps.filter((s) => s.at <= elapsed).length
          const finished = done === inc.steps.length
          const open = openId === inc.id
          return (
            <section key={inc.id} className={`glass inc ${open ? "open" : ""}`}>
              <button className="inc-head" aria-expanded={open} onClick={() => setOpenId(open ? null : inc.id)}>
                <span className={`inc-dot ${finished ? "ok" : "live"}`} />
                <span className="inc-title">
                  <strong>
                    {inc.id} · {inc.title}
                  </strong>
                  <small>
                    {inc.source} · {ACTIONS[inc.action].label} · {inc.teams.length} team(s)
                  </small>
                </span>
                <Tag tone={finished ? "ok" : "warn"}>{finished ? "Contained" : `Step ${done} of ${inc.steps.length}`}</Tag>
              </button>
              <div className="meter">
                <span style={{ width: `${(done / inc.steps.length) * 100}%`, background: finished ? "var(--ok)" : "var(--accent)" }} />
              </div>
              {open && (
                <div className="inc-body">
                  <div className="inc-assets">
                    {inc.assets.map((id) => (
                      <button key={id} className="link" onClick={() => openAsset(id)}>
                        {id}
                      </button>
                    ))}
                    <span className="muted small">· notified: {inc.teams.map((t) => TEAMS.find((x) => x.id === t)!.label).join(", ") || "nobody"}</span>
                  </div>
                  <ol className="inc-steps">
                    {inc.steps.map((s, i) => {
                      const Icon = ICON[s.kind]
                      const state = s.at <= elapsed ? "done" : i === done ? "now" : "next"
                      return (
                        <li key={i} className={state}>
                          {state === "done" ? <CheckCircle2 size={16} /> : <Circle size={16} />}
                          <div>
                            <strong>{s.label}</strong>
                            <small>
                              <Icon size={12} /> {s.actor} · {WHO[s.kind]}
                            </small>
                          </div>
                          <time>+{s.at}s</time>
                        </li>
                      )
                    })}
                  </ol>
                </div>
              )}
            </section>
          )
        })}
      </div>
      <p className="muted small">
        Timings are accelerated for the demo. In the platform these steps are carried out by the agents, ApprovalGate and AlertBus, and each one is recorded in the Audit Trail. Highest-risk asset right now:{" "}
        <b style={{ color: levelColor[top.level] }}>{top.id}</b>.
      </p>
    </div>
  )
}
