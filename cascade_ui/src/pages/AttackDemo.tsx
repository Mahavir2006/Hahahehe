import { useEffect, useMemo, useState } from "react"
import { Bar, BarChart, Cell, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { AlertTriangle, Bot, Bug, CheckCircle2, Circle, Cpu, Link2, Loader2, Network, Play, RotateCcw, ShieldAlert, UserCheck } from "lucide-react"
import { RiskMap } from "@/components/RiskMap"
import { Card, Tag, toast } from "@/components/ui"
import { CHART } from "@/components/viz"
import { assetById, dependencies } from "@/data/derive"
import { api, ORG_CODE } from "@/data/live"

/* End-to-end firmware supply-chain attack on the live system (backend/attack_demo.py). The implant is simulated;
   detection, the AI model, the agents, human approval, containment, the chain and the digital twin are real. */

type Stage = { id: string; title: string; actor: string; status: string; events: { t: number; who: string; what: string; tx?: string | null }[]; data: any }
type Demo = { status: string; attack: Record<string, string>; target: { org: string; asset_id: string }; stages: Stage[]; current?: string; error?: string; start_block?: number }

const ICON: Record<string, typeof Bug> = { implant: Bug, detect: Cpu, predict: ShieldAlert, agents: Bot, approve: UserCheck, contain: CheckCircle2, record: Link2 }
const WHY: Record<string, string> = {
  implant: "A firmware implant lives below the operating system: antivirus and log monitoring do not see it. The only reliable signal is that the device now runs code its vendor never published.",
  detect: "The vendor's genuine firmware hash is registered on the blockchain (FirmwareRegistry). Comparing the device's hash with that record cannot be faked by the attacker, because they cannot rewrite the chain.",
  predict: "Operators need to know how dangerous this is right now and why. SHAP breaks the AI model's score into per-input contributions, so the jump in risk is explained, not just asserted.",
  agents: "One compromised substation threatens water pumping and a hospital downstream. The agents predict where it spreads next and how fast, warn those organisations privately, and draft a plan a critic must check first.",
  approve: "Containment can cut power to a city district, so the AI is not allowed to act alone: two humans must sign on chain. The contract itself rejects any vote from the AI.",
  contain: "The executor only acts after it reads the approval from the chain, then re-scores the asset to prove the predicted risk reduction really happened.",
  record: "Every step left a tamper-evident record that the other organisations can verify, and the digital twin now reflects the attack, so the incident can be audited later without trusting any single party.",
}
const short = (h?: string | null, n = 6) => (h ? `${h.slice(0, n + 2)}…${h.slice(-4)}` : "")
const pct = (x: number) => `${Math.round(x * 100)}%`

export default function AttackDemo() {
  const [d, setD] = useState<Demo | null>(null)
  const [focus, setFocus] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const load = () => api<Demo>("/api/attack/firmware").then(setD).catch(() => {})
  useEffect(() => {
    load()
    const t = setInterval(load, 1000)
    return () => clearInterval(t)
  }, [])
  // follow the running stage unless the user picked one
  useEffect(() => {
    if (d?.status === "running" && d.current) setFocus(d.current)
  }, [d?.current, d?.status])

  const launch = async () => {
    setBusy(true)
    try {
      await api("/api/attack/firmware/launch", {})
      setFocus("implant")
      toast("Attack launched", "A trojanised firmware image is landing on the substation gateway")
    } catch (e) {
      toast("Could not launch", String((e as Error).message ?? e), "warn")
    }
    setBusy(false)
    load()
  }
  const reset = async () => {
    await api("/api/attack/firmware/reset", {})
    setFocus(null)
    toast("Device restored", "Back on vendor-published firmware. The chain keeps the history.")
    load()
  }

  const stage = (id: string) => d?.stages.find((s) => s.id === id)
  const target = d?.target.asset_id ?? "power-asset-001"
  const a = assetById.get(target)
  const reached = stage("agents")?.status === "done"
  // the attack path only: the gateway, its direct dependents, and the first asset reached in each organisation
  // the cascade agent predicts (breadth-first over confirmed dependencies), so the map stays readable
  const cascadeOrgs: string[] = (stage("agents")?.data?.cascade ?? []).map((c: any) => String(c.org))
  const path = useMemo(() => {
    const out = new Set([target])
    if (!reached) return out
    const depth = new Map([[target, 0]])
    const queue = [target]
    while (queue.length) {
      const cur = queue.shift()!
      for (const d of dependencies.filter((x) => x.from === cur && !depth.has(x.to))) {
        depth.set(d.to, depth.get(cur)! + 1)
        queue.push(d.to)
      }
    }
    const orgOf = (id: string) => assetById.get(id)?.org
    for (const [id, dd] of depth) if (dd === 1 && orgOf(id) === orgOf(target)) out.add(id)
    for (const org of cascadeOrgs) {
      const code = ORG_CODE[org as keyof typeof ORG_CODE]
      const first = [...depth].filter(([id]) => id !== target && orgOf(id) === code).sort((x, y) => x[1] - y[1])[0]
      if (first) out.add(first[0])
    }
    return out
  }, [target, reached, cascadeOrgs.join()])
  const notes = useMemo(() => {
    const n: Record<string, string> = { [target]: "IMPLANT" }
    const chain: any[] = stage("agents")?.data?.cascade ?? []
    for (const id of path) {
      if (id === target) continue
      const org = assetById.get(id)?.org
      const hit = chain.find((c) => ORG_CODE[c.org as keyof typeof ORG_CODE] === org)
      n[id] = hit ? `${String(hit.label ?? hit.org).split(":").pop()} T+${hit.time_to_impact_minutes}m` : "next hop"
    }
    if (stage("contain")?.status === "done") n[target] = "CONTAINED"
    return n
  }, [d, path, target])

  const sel = focus ? stage(focus) : undefined
  const severity = stage("predict")?.data?.after?.band ?? (stage("detect")?.status === "done" ? "critical" : "—")
  const next = (stage("agents")?.data?.cascade ?? [])[0]

  if (!d) return <div className="page"><div className="skeleton" style={{ height: 420 }} /></div>

  return (
    <div className="page attack">
      <section className="glass attack-hero">
        <div className="attack-title">
          <AlertTriangle size={22} aria-hidden />
          <div>
            <span className="eyebrow">Live attack demonstration</span>
            <h2>{d.attack.name}</h2>
            <p>{d.attack.vector}</p>
          </div>
        </div>
        <dl className="attack-facts">
          <div>
            <dt>Target</dt>
            <dd>
              {a?.name ?? target} <small>{target} · {a?.location}</small>
            </dd>
          </div>
          <div>
            <dt>Technique</dt>
            <dd className="small">{d.attack.technique}</dd>
          </div>
          <div>
            <dt>Severity</dt>
            <dd>
              <Tag tone={severity === "critical" ? "danger" : severity === "high" ? "warn" : "info"}>{String(severity).toUpperCase()}</Tag>
            </dd>
          </div>
          <div>
            <dt>Next stage</dt>
            <dd>{next ? `${next.label ?? next.org} in ~${next.time_to_impact_minutes} min (${pct(next.p_degraded)})` : "—"}</dd>
          </div>
        </dl>
        <div className="attack-ctl">
          {d.status === "running" ? (
            <button className="btn btn-danger" disabled>
              <Loader2 size={14} className="spin" /> Attack in progress…
            </button>
          ) : (
            <button className="btn btn-danger" onClick={launch} disabled={busy}>
              <Play size={14} /> {d.status === "done" ? "Run the attack again" : "Launch firmware attack"}
            </button>
          )}
          {d.status !== "running" && d.status !== "idle" && (
            <button className="btn" onClick={reset}>
              <RotateCcw size={14} /> Restore device
            </button>
          )}
        </div>
        <p className="muted small attack-note">{d.attack.simulated}</p>
        {d.status === "failed" && <p className="up small">The demo stopped: {d.error}</p>}
      </section>

      <ol className="attack-steps" aria-label="Attack stages">
        {d.stages.map((s, i) => {
          const I = ICON[s.id] ?? Circle
          return (
            <li key={s.id}>
              <button className={`glass ${s.status} ${focus === s.id ? "active" : ""}`} onClick={() => setFocus(s.id)} aria-pressed={focus === s.id}>
                <span className="as-n">{s.status === "done" ? <CheckCircle2 size={15} /> : s.status === "running" ? <Loader2 size={15} className="spin" /> : i + 1}</span>
                <I size={16} aria-hidden />
                <strong>{s.title}</strong>
                <small>{s.actor}</small>
              </button>
            </li>
          )
        })}
      </ol>

      <div className="attack-grid">
        <section className="glass attack-map">
          <RiskMap
            selected={target}
            onSelect={() => {}}
            only={path}
            live={false}
            legend={false}
            cascadeShown={reached ? new Set([...path].filter((x) => x !== target)) : new Set()}
            fitTo={[...path]}
            notes={d.status === "idle" ? { [target]: "TARGET" } : notes}
            help={
              <>
                <strong>Only this attack is shown</strong> The implanted device, then every asset the attack can reach through confirmed dependencies, with the time the
                agents predict each one is hit.
              </>
            }
          />
        </section>
        <section className="glass pane attack-detail">
          {!sel ? (
            <div className="empty">
              <Network size={22} aria-hidden />
              <strong>Launch the attack to follow it stage by stage</strong>
              <p>Each stage shows what happened, which agent or person did it, why it was needed, and what reached the blockchain.</p>
            </div>
          ) : (
            <StageDetail s={sel} />
          )}
        </section>
      </div>
    </div>
  )
}

function StageDetail({ s }: { s: Stage }) {
  const x = s.data ?? {}
  return (
    <div className="sd">
      <div className="pane-row">
        <h2 className="pane-title">{s.title}</h2>
        <Tag tone={s.status === "done" ? "ok" : s.status === "running" ? "warn" : "neutral"}>{s.status}</Tag>
      </div>
      <p className="sd-why">
        <b>Why this step:</b> {WHY[s.id]}
      </p>

      {s.id === "implant" && x.asset && (
        <dl className="kv">
          <dt>Device</dt>
          <dd>
            {x.asset.vendor} {x.asset.model} {x.asset.version} · {x.asset.zone}
          </dd>
          <dt>Vendor-published hash</dt>
          <dd>
            <code>{short(x.published_sha, 10)}</code>
          </dd>
          <dt>Hash the device now reports</dt>
          <dd>
            <code className="up">{short(x.observed_sha, 10)}</code>
          </dd>
        </dl>
      )}
      {s.id === "implant" && <FirmwareImage />}
      {s.id === "detect" && x.registry_result && (
        <dl className="kv">
          <dt>FirmwareRegistry says</dt>
          <dd>
            <Tag tone="danger">{x.registry_result}</Tag> (on-chain check)
          </dd>
          <dt>Detection rules fired</dt>
          <dd>{x.rules.join(" · ")}</dd>
          <dt>Severity</dt>
          <dd>
            <Tag tone="danger">{x.severity}</Tag>
          </dd>
        </dl>
      )}
      {s.id === "predict" && x.after && <Shap x={x} />}
      {s.id === "agents" && x.plan && <Agents x={x} />}
      {s.id === "approve" && x.request_id && (
        <dl className="kv">
          <dt>Request</dt>
          <dd>
            <code>{short(x.request_id, 10)}</code>
          </dd>
          <dt>Status on chain</dt>
          <dd>
            <Tag tone="ok">{x.status}</Tag>
          </dd>
          <dt>Approval transactions</dt>
          <dd>{x.approval_txs.map((t: string) => <code key={t}>{short(t)} </code>)}</dd>
        </dl>
      )}
      {s.id === "contain" && x.asset_after && (
        <dl className="kv">
          <dt>Risk reduction</dt>
          <dd>
            predicted = actual: <b className="ok">{x.execution?.actual_delta}</b> (drift {x.execution?.drift})
          </dd>
          <dt>Device now</dt>
          <dd>
            risk {x.asset_after.risk} · <Tag tone={x.asset_after.band === "critical" ? "danger" : "warn"}>{x.asset_after.band}</Tag> · likelihood {pct(x.asset_after.likelihood)}
          </dd>
        </dl>
      )}
      {s.id === "record" && x.events && <Record x={x} />}

      <h3 className="h3">What happened</h3>
      <ul className="sd-log">
        {s.events.map((e, i) => (
          <li key={i}>
            <time>+{e.t}s</time>
            <span>
              <b>{e.who}</b> {e.what}
              {e.tx && (
                <>
                  {" "}
                  · tx <code>{short(e.tx)}</code>
                </>
              )}
            </span>
          </li>
        ))}
        {!s.events.length && <li className="muted small">Waiting for this stage…</li>}
      </ul>
    </div>
  )
}

function Shap({ x }: { x: any }) {
  const rows = (x.shap ?? []).map((r: any) => ({ name: r.label, Before: r.before, After: r.after, delta: r.delta }))
  const top = (x.shap ?? [])[0]
  return (
    <>
      <div className="sd-score">
        <div>
          <span>Risk before</span>
          <b>{x.before.risk}</b>
          <Tag>{x.before.band}</Tag>
        </div>
        <span className="arrow">→</span>
        <div>
          <span>Risk after implant</span>
          <b className="up">{x.after.risk}</b>
          <Tag tone="danger">{x.after.band}</Tag>
        </div>
        <div>
          <span>Likelihood of compromise</span>
          <b>
            {pct(x.before.likelihood)} → {pct(x.after.likelihood)}
          </b>
        </div>
      </div>
      {x.implant_only && (
        <p className="small">
          The implant on its own takes the likelihood of compromise from <b>{pct(x.implant_only.likelihood_before)}</b> to{" "}
          <b className="up">{pct(x.implant_only.likelihood_after)}</b>. The risk figures above are the device's live score, which also includes anything else that changed meanwhile.
        </p>
      )}
      <h3 className="h3">SHAP: what the implant changed (log-odds contribution, before vs after)</h3>
      <div className="sd-chart">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={rows} layout="vertical" margin={{ left: 8, right: 16 }}>
            <XAxis type="number" stroke={CHART.axis} fontSize={11} />
            <YAxis type="category" dataKey="name" width={170} stroke={CHART.axis} fontSize={11} />
            <Tooltip contentStyle={CHART.tooltip} formatter={(v) => Number(v).toFixed(3)} />
            <ReferenceLine x={0} stroke="var(--line-2)" />
            <Bar dataKey="Before" fill="var(--dim)" isAnimationActive={false} />
            <Bar dataKey="After" isAnimationActive={false}>
              {rows.map((r: any, i: number) => (
                <Cell key={i} fill={r.After >= r.Before ? "var(--danger)" : "var(--ok)"} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      {top && (
        <p className="small">
          Biggest driver: <b>{top.label}</b> moved the score by <b className="up">{top.delta > 0 ? "+" : ""}{top.delta.toFixed(2)}</b> log-odds. Before and after differ
          only in the inputs the attack changes (firmware trust and the implant's network behaviour), so the whole change in risk is caused by the implant; other bars can
          shift a little because the model weighs inputs together. Red pushes risk up, green pulls it down.
        </p>
      )}
    </>
  )
}

function Agents({ x }: { x: any }) {
  return (
    <>
      <h3 className="h3">Where the attack goes next (Cascade agent)</h3>
      <ol className="sd-cascade">
        {x.cascade.map((c: any, i: number) => (
          <li key={i}>
            <b>T+{c.time_to_impact_minutes} min</b> {c.label ?? c.org} <Tag tone={c.p_degraded > 0.6 ? "danger" : "warn"}>{pct(c.p_degraded)} likely</Tag>
          </li>
        ))}
      </ol>
      <h3 className="h3">Potential solutions (Planner agent, checked by the Critic)</h3>
      <p className="small">
        Plan <code>{x.plan.plan_id}</code>: {x.plan.steps.length} steps, organisation risk {Number(x.plan.risk_before).toFixed(1)} → <b className="ok">{Number(x.plan.risk_after).toFixed(1)}</b> · critic:{" "}
        <Tag tone="ok">{x.critic?.verdict}</Tag> ({x.critic?.checks} checks, verdict {x.critic?.anchor_status} on AuditLog)
      </p>
      <ul className="sd-plan">
        {[...x.plan.steps]
          .sort((p: any, q: any) => (p.target_assets?.includes("power-asset-001") ? -1 : 0) - (q.target_assets?.includes("power-asset-001") ? -1 : 0) || p.expected_risk_delta - q.expected_risk_delta)
          .slice(0, 6)
          .map((st: any) => (
            <li key={st.step_id}>
              <Tag tone="info">{st.action.replace(/_/g, " ").toLowerCase()}</Tag> {st.target_assets?.join(", ")} <small>{st.rationale}</small>
            </li>
          ))}
      </ul>
      <p className="small">Sealed early-warning alerts published: {x.alerts.length} (only the dependent organisations can open them).</p>
    </>
  )
}

function Record({ x }: { x: any }) {
  return (
    <>
      <div className="sd-contracts">
        {Object.entries(x.by_contract).map(([c, n]: [string, any]) => (
          <div key={c}>
            <span>{c}</span>
            <b>{n}</b>
          </div>
        ))}
      </div>
      <h3 className="h3">On-chain records this attack produced ({x.events.length})</h3>
      <div className="table-wrap sd-events">
        <table className="tbl ledger">
          <thead>
            <tr>
              <th>Block</th>
              <th>Contract · event</th>
              <th>Transaction</th>
            </tr>
          </thead>
          <tbody>
            {x.events.map((e: any, i: number) => (
              <tr key={i}>
                <td>{e.block}</td>
                <td>
                  <strong>{e.contract}</strong>
                  <small>{e.event}</small>
                </td>
                <td>
                  <code>{short(e.tx)}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <h3 className="h3">Digital twin</h3>
      <dl className="kv">
        <dt>Fingerprint</dt>
        <dd>
          <code>{short(x.twin.root_before, 8)}</code> (block {x.twin.block_before}) → <code>{short(x.twin.root_after, 8)}</code> (block {x.twin.block_after})
        </dd>
        <dt>Twin sections changed</dt>
        <dd>{[...new Set(x.twin.changes.map((c: any) => c.section))].join(", ") || "none"}</dd>
        <dt>Drift the twin now flags</dt>
        <dd>
          {x.twin.drift.map((dr: any, i: number) => (
            <div key={i}>
              <Tag tone={dr.severity === "high" ? "danger" : "warn"}>{dr.kind.replace(/_/g, " ")}</Tag> {dr.detail}
            </div>
          ))}
        </dd>
      </dl>
    </>
  )
}

type FwLine = { op: string; text: string }
type FwImage = {
  firmware: string
  folder: string
  published_sha256: string
  vendor: { file: string; lines: string[] }
  tampered: { file: string; sha256: string; lines: FwLine[] }
  diff: FwLine[]
  added_lines: number
  changes: { what: string; effect: string; seen_by: string }[]
  note: string
}

/** The firmware "image" behind the implant stage: the vendor build, what the attacker changed, and the hashes the
 *  registry check compares. The tampered hash is computed from the file shown here (data/firmware/README.md). */
function FirmwareImage() {
  const [img, setImg] = useState<FwImage | null | false>(null)
  const [view, setView] = useState<"diff" | "tampered" | "vendor">("diff")
  useEffect(() => {
    api<FwImage>("/api/attack/firmware/image").then(setImg).catch(() => setImg(false))
  }, [])
  if (img === null) return <p className="small">Loading the firmware image…</p>
  if (img === false) return null
  const lines: FwLine[] = view === "diff" ? img.diff : view === "tampered" ? img.tampered.lines : img.vendor.lines.map((text) => ({ op: " ", text }))
  return (
    <div className="fw">
      <div className="pane-row">
        <h3 className="h3">Firmware image: what the attacker changed</h3>
        <div className="seg" role="tablist" aria-label="Firmware view">
          {(["diff", "tampered", "vendor"] as const).map((v) => (
            <button key={v} role="tab" aria-selected={view === v} className={view === v ? "active" : ""} onClick={() => setView(v)}>
              {v === "diff" ? `Changes (+${img.added_lines} lines)` : v === "tampered" ? "Tampered build" : "Vendor build"}
            </button>
          ))}
        </div>
      </div>
      <p className="small">
        {img.firmware} · <code>{img.folder}</code>. The device reports the SHA-256 of the image it runs: for the tampered build that is{" "}
        <code className="up">{short(img.tampered.sha256, 10)}</code>, computed from the file below, not the vendor-published <code>{short(img.published_sha256, 10)}</code> registered on
        the chain.
      </p>
      <pre className="fw-diff" aria-label={`${view} view of ${img.tampered.file}`}>
        {lines.map((l, i) => (
          <span key={i} className={l.op === "+" ? "fw-add" : l.op === "-" ? "fw-del" : l.op === "@" ? "fw-hunk" : "fw-ctx"}>
            {l.op === "@" ? l.text : `${l.op} ${l.text}`}
          </span>
        ))}
      </pre>
      <ol className="fw-changes">
        {img.changes.map((c) => (
          <li key={c.what}>
            <strong>{c.what}</strong> — {c.effect}. <em>Seen by {c.seen_by}.</em>
          </li>
        ))}
      </ol>
      <p className="small muted">{img.note}</p>
    </div>
  )
}
