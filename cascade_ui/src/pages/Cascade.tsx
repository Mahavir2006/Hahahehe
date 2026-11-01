import { useEffect, useMemo, useRef, useState } from "react"
import { HeartPulse, Pause, Play, RotateCcw, ShieldCheck } from "lucide-react"
import { useNav } from "@/app/nav"
import { RiskMap } from "@/components/RiskMap"
import { Level, Tag } from "@/components/ui"
import { appendAudit } from "@/data/audit"
import { requestResponse } from "@/data/incidents"
import { CONSEQUENCE, fmtMin, simulate, type SimOptions } from "@/data/cascadeSim"
import { assetById, levelColor, ranked, sectorOf } from "@/data/derive"

/** Ready-made attack scenarios: each compromises one real asset from the inventory. */
const SCENARIOS = [
  { id: "PG-003", title: "Grid SCADA gateway exploited", how: "CVE-2024-3400 on the internet-facing gateway" },
  { id: "PG-019", title: "Vendor VPN abused", how: "Leaked vendor credentials on the Tehri dam link" },
  { id: "JB-006", title: "Dam control HMI hijacked", how: "OpenSSH flaw on the partner-network HMI" },
  { id: "AI-014", title: "Hospital BMS taken over", how: "Default credentials on the building system" },
  { id: "PG-001", title: "Substation compromised", how: "Credential reuse from the control network" },
]

const CONTAIN = [
  { label: "No defence", value: null },
  { label: "Isolate source within 15 min", value: 15 },
  { label: "Isolate source within 60 min", value: 60 },
] as const

/** Cascade Simulator: compromise one asset and watch the failure spread across organisations over time. */
export default function Cascade() {
  const { focusAsset, openAsset } = useNav()
  const sources = useMemo(() => ranked.filter((a) => simulate(a.id, { containAt: null, segmentPartners: false }).length > 0), [])
  const [src, setSrc] = useState(focusAsset && sources.some((s) => s.id === focusAsset) ? focusAsset : SCENARIOS[0].id)
  const [opt, setOpt] = useState<SimOptions>({ containAt: null, segmentPartners: false })
  const [clock, setClock] = useState(0) // simulated minutes elapsed
  const [running, setRunning] = useState(false)
  const timer = useRef<ReturnType<typeof setInterval>>(undefined)

  const steps = useMemo(() => simulate(src, opt), [src, opt])
  const baseline = useMemo(() => simulate(src, { containAt: null, segmentPartners: false }), [src])
  const end = Math.max(30, ...steps.map((s) => s.minute)) + 10
  const started = running || clock > 0
  const reached = useMemo(() => steps.filter((s) => s.minute <= clock), [steps, clock])
  const shown = useMemo(() => new Set(reached.filter((s) => s.status === "impacted").map((s) => s.asset.id)), [reached])
  const blocked = useMemo(() => new Set(reached.filter((s) => s.status === "prevented").map((s) => s.asset.id)), [reached])
  const impacted = steps.filter((s) => s.status === "impacted")
  const a = assetById.get(src)!

  // camera: zoom onto the attacked asset, then widen as the cascade reaches further
  const fitTo = useMemo(() => (started ? [src, ...reached.map((s) => s.asset.id)] : [src, ...steps.map((s) => s.asset.id)]), [started, src, reached, steps])
  const notes = useMemo(() => {
    const n: Record<string, string> = { [src]: "SOURCE" }
    for (const s of reached) n[s.asset.id] = s.status === "prevented" ? "blocked" : `T+${fmtMin(s.minute)}`
    return n
  }, [reached, src])

  // scorecard (all for the chosen defence)
  const exposure = impacted.reduce((sum, s) => sum + s.asset.risk * s.p, 0)
  const exposureBase = baseline.reduce((sum, s) => sum + s.asset.risk * s.p, 0)
  const hospital = impacted.find((s) => s.asset.org === "CCMN")
  const sectors = [...new Set(impacted.map((s) => sectorOf[s.asset.org].label))]

  useEffect(() => {
    if (!running) return
    const stepMin = Math.max(5, Math.ceil(end / 50 / 5) * 5) // ~50 frames per run, whatever its length
    timer.current = setInterval(() => setClock((c) => (c >= end ? c : Math.min(end, c + stepMin))), 120)
    return () => clearInterval(timer.current)
  }, [running, end])
  useEffect(() => {
    if (running && clock >= end) {
      setRunning(false)
      appendAudit({ kind: "Simulation", actor: "Analyst (you)", contract: "off-chain", subject: src, detail: `Cascade simulation: ${impacted.length} impacted, ${steps.length - impacted.length} prevented` })
    }
  }, [clock, end, running, src, impacted.length, steps.length])

  const reset = (next?: Partial<{ src: string; opt: SimOptions }>) => {
    setRunning(false)
    setClock(0)
    if (next?.src) setSrc(next.src)
    if (next?.opt) setOpt(next.opt)
  }
  const run = () => {
    if (clock >= end) setClock(0)
    setRunning(true)
  }

  return (
    <div className="page">
      <div className="scen-strip" role="tablist" aria-label="Attack scenarios">
        {SCENARIOS.filter((s) => sources.some((x) => x.id === s.id)).map((s) => (
          <button key={s.id} role="tab" aria-selected={src === s.id} className={`glass scen-chip ${src === s.id ? "active" : ""}`} onClick={() => reset({ src: s.id })}>
            <strong>{s.title}</strong>
            <small>
              {s.id} · {s.how}
            </small>
          </button>
        ))}
      </div>

      <div className="sim-layout">
        <aside className="glass pane sim-controls">
          <h2 className="pane-title">Attacked asset</h2>
          <select className="input" value={src} onChange={(e) => reset({ src: e.target.value })} aria-label="Asset to compromise">
            {sources.map((s) => (
              <option key={s.id} value={s.id}>
                {s.id} — {s.name}
              </option>
            ))}
          </select>
          <p className="muted small">
            {sectorOf[a.org].label} · {a.location} · risk {a.risk.toFixed(1)} <Level level={a.level} />
          </p>

          <h2 className="pane-title mt">Defence</h2>
          <div className="radio-list" role="radiogroup" aria-label="Containment">
            {CONTAIN.map((c) => (
              <label key={c.label}>
                <input type="radio" name="contain" checked={opt.containAt === c.value} onChange={() => reset({ opt: { ...opt, containAt: c.value } })} />
                {c.label}
              </label>
            ))}
            <label>
              <input type="checkbox" checked={opt.segmentPartners} onChange={(e) => reset({ opt: { ...opt, segmentPartners: e.target.checked } })} />
              Segment cross-organisation links
            </label>
          </div>

          <div className="sim-buttons">
            <button className="btn btn-primary" onClick={running ? () => setRunning(false) : run}>
              {running ? <Pause size={14} /> : <Play size={14} />} {running ? "Pause" : clock > 0 && clock < end ? "Resume" : "Run simulation"}
            </button>
            <button className="btn" onClick={() => reset()} aria-label="Reset simulation">
              <RotateCcw size={14} />
            </button>
          </div>
          <div className="sim-clock">
            <span>Simulated time</span>
            <b>T + {fmtMin(clock)}</b>
            <div className="meter">
              <span style={{ width: `${Math.min(100, (clock / end) * 100)}%`, background: "var(--accent)" }} />
            </div>
          </div>
        </aside>

        <section className="glass sim-map">
          <RiskMap
            selected={src}
            onSelect={(id) => id && sources.some((s) => s.id === id) && reset({ src: id })}
            live={false}
            legend={false}
            cascadeShown={started ? shown : new Set(steps.filter((s) => s.status === "impacted").map((s) => s.asset.id))}
            blocked={started ? blocked : new Set(steps.filter((s) => s.status === "prevented").map((s) => s.asset.id))}
            fitTo={fitTo}
            notes={started ? notes : { [src]: "SOURCE" }}
            help={
              <>
                <strong>Cascade Simulator</strong> Pick a scenario and a defence, press Run — the map follows the failure minute by minute.
              </>
            }
          />
        </section>

        <aside className="glass pane sim-timeline">
          <h2 className="pane-title">Impact scorecard</h2>
          <div className="scorecard">
            <div>
              <span>Assets hit</span>
              <b className={impacted.length ? "crit" : "ok"}>{impacted.length}</b>
              <small>of {baseline.length} with no defence</small>
            </div>
            <div>
              <span>Cascade risk</span>
              <b>{exposure.toFixed(0)}</b>
              <small>{exposureBase ? `−${(((exposureBase - exposure) / exposureBase) * 100).toFixed(0)}% vs no defence` : "—"}</small>
            </div>
            <div>
              <span>Sectors hit</span>
              <b>{sectors.length}</b>
              <small>{sectors.join(", ") || "none"}</small>
            </div>
            <div>
              <span>Hospital affected</span>
              <b className={hospital ? "crit" : "ok"}>{hospital ? `T+${fmtMin(hospital.minute)}` : "No"}</b>
              <small>{hospital ? hospital.asset.id : "life-critical services safe"}</small>
            </div>
          </div>
          {steps.length > impacted.length && (
            <p className="sim-saved">
              <ShieldCheck size={15} /> This defence stops {steps.length - impacted.length} of {steps.length} downstream failures.
            </p>
          )}
          {hospital && (
            <p className="sim-warn">
              <HeartPulse size={15} /> Clinical services at {hospital.asset.name} degrade {fmtMin(hospital.minute)} after the first compromise.
            </p>
          )}

          <h2 className="pane-title mt">Affected assets</h2>
          <ol className="tl">
            <li className="tl-src on">
              <time>T+0</time>
              <div>
                <strong>{a.id} compromised</strong>
                <small>{a.vulnerability} · initial access</small>
              </div>
              <b style={{ color: levelColor[a.level] }}>{a.risk.toFixed(0)}</b>
            </li>
            {steps.map((s) => (
              <li key={s.asset.id} className={`${s.minute <= clock || !started ? "on" : ""} ${s.status}`}>
                <time>T+{fmtMin(s.minute)}</time>
                <div>
                  <button className="link" onClick={() => openAsset(s.asset.id)}>
                    {s.asset.id} · {s.asset.name}
                  </button>
                  <small>
                    {s.status === "prevented" ? (
                      <Tag tone="ok">Prevented — {s.reason}</Tag>
                    ) : (
                      <>
                        <span style={{ color: sectorOf[s.asset.org].color }}>{CONSEQUENCE[s.asset.org]}</span> · {(s.p * 100).toFixed(0)}% likely · via {s.via.toLowerCase()}
                      </>
                    )}
                  </small>
                </div>
                <b style={{ color: s.status === "prevented" ? "var(--ok)" : levelColor[s.asset.level] }}>{s.asset.risk.toFixed(0)}</b>
              </li>
            ))}
          </ol>
          {impacted.length > 0 && (
            <button className="btn btn-danger full" onClick={() => requestResponse({ title: `Cascade from ${a.name}`, source: "Cascade simulation", assets: [src, ...impacted.map((s) => s.asset.id)], action: "isolate" })}>
              Respond now — contain & warn {new Set(impacted.map((s) => s.asset.org)).size} organisation(s)
            </button>
          )}
        </aside>
      </div>
    </div>
  )
}
