import { useEffect, useRef, useState } from "react"
import { Bot, ScrollText, ShieldCheck, Siren, UserCheck, X } from "lucide-react"
import { useNav } from "@/app/nav"
import { assetById, levelColor, orgRisk, sectorOf } from "@/data/derive"
import { ACTIONS, TEAMS, openIncident, requestResponse, useResponseRequest, type ResponseAction, type TeamId } from "@/data/incidents"
import { toast } from "./ui"

/** "Respond now": choose the immediate action and who gets the work; the platform does the rest. */
export function ResponseDialog() {
  const req = useResponseRequest()
  const { go } = useNav()
  const [action, setAction] = useState<ResponseAction>("isolate")
  const [teams, setTeams] = useState<Set<TeamId>>(new Set(["soc", "field", "owner", "downstream"]))
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!req) return
    setAction(req.action ?? "isolate")
    const crossOrg = new Set(req.assets.map((id) => assetById.get(id)?.org)).size > 1
    setTeams(new Set<TeamId>(["soc", "field", "owner", ...(crossOrg ? (["downstream", "certin"] as TeamId[]) : [])]))
    const prev = document.activeElement as HTMLElement | null
    setTimeout(() => ref.current?.querySelector<HTMLElement>("input,button")?.focus(), 0)
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && requestResponse(null)
    window.addEventListener("keydown", onKey)
    document.body.classList.add("locked")
    return () => {
      window.removeEventListener("keydown", onKey)
      document.body.classList.remove("locked")
      prev?.focus?.()
    }
  }, [req])

  if (!req) return null
  const assets = req.assets.map((id) => assetById.get(id)!).filter(Boolean)
  const orgs = [...new Set(assets.map((a) => orgRisk.find((o) => o.code === a.org)!.name))]

  const submit = () => {
    const inc = openIncident({ title: req.title, source: req.source, assets: req.assets, action, teams: [...teams] })
    requestResponse(null)
    toast(`${inc.id} opened`, `${ACTIONS[action].label} · ${teams.size} team(s) notified — follow it in Incident Response`)
    go("respond")
  }

  return (
    <>
      <div className="scrim show" style={{ zIndex: 70 }} onClick={() => requestResponse(null)} aria-hidden />
      <div ref={ref} className="respond glass-strong" role="dialog" aria-modal="true" aria-label="Respond to incident">
        <header className="respond-head">
          <Siren size={18} aria-hidden />
          <div>
            <span className="eyebrow">Respond now · {req.source}</span>
            <h2>{req.title}</h2>
          </div>
          <button className="icon-btn" aria-label="Close" onClick={() => requestResponse(null)}>
            <X size={18} />
          </button>
        </header>

        <div className="respond-body">
          <div className="respond-assets">
            {assets.map((a) => (
              <span key={a.id} style={{ borderColor: sectorOf[a.org].color }}>
                <b style={{ color: levelColor[a.level] }}>{a.id}</b> {a.name}
              </span>
            ))}
          </div>
          <p className="muted small">Organisations involved: {orgs.join(", ")}</p>

          <h3 className="pane-title mt">1 · Immediate action</h3>
          <div className="radio-list" role="radiogroup" aria-label="Immediate action">
            {(Object.keys(ACTIONS) as ResponseAction[]).map((k) => (
              <label key={k}>
                <input type="radio" name="action" checked={action === k} onChange={() => setAction(k)} />
                <span>
                  <strong>{ACTIONS[k].label}</strong>
                  <small>{ACTIONS[k].detail}</small>
                </span>
              </label>
            ))}
          </div>

          <h3 className="pane-title mt">2 · Notify and assign</h3>
          <div className="team-grid">
            {TEAMS.map((t) => (
              <label key={t.id}>
                <input
                  type="checkbox"
                  checked={teams.has(t.id)}
                  onChange={() =>
                    setTeams((s) => {
                      const n = new Set(s)
                      if (n.has(t.id)) n.delete(t.id)
                      else n.add(t.id)
                      return n
                    })
                  }
                />
                <span>
                  <strong>{t.label}</strong>
                  <small>{t.who}</small>
                </span>
              </label>
            ))}
          </div>

          <h3 className="pane-title mt">3 · What CascadeShield does next</h3>
          <ol className="auto-steps">
            {action === "plan" ? (
              <>
                <li><Bot size={14} /> Planner agent drafts the steps inside the maintenance window</li>
                <li><ShieldCheck size={14} /> Critic agent checks safety; verdict anchored on-chain</li>
                <li><UserCheck size={14} /> Two humans sign on ApprovalGate (the AI cannot vote)</li>
                <li><Bot size={14} /> Executor agent applies the plan and re-scores the risk</li>
              </>
            ) : action === "isolate" ? (
              <>
                <li><Bot size={14} /> Executor agent runs the pre-approved isolation playbook immediately</li>
                <li><Bot size={14} /> Containment is verified and the asset re-scored</li>
              </>
            ) : (
              <li><Bot size={14} /> Risk agent raises detection sensitivity and escalates on the next hit</li>
            )}
            <li><ScrollText size={14} /> Every step is written to the Audit Trail; partners get sealed alerts only</li>
          </ol>
        </div>

        <footer className="respond-foot">
          <button className="btn" onClick={() => requestResponse(null)}>
            Cancel
          </button>
          <button className="btn btn-primary" onClick={submit}>
            <Siren size={14} /> {ACTIONS[action].label} and notify {teams.size}
          </button>
        </footer>
      </div>
    </>
  )
}
