import { Fragment, useEffect, useMemo, useRef, useState } from "react"
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { CheckCircle2, Hand, Link2, Lock, Play, XCircle } from "lucide-react"
import { useNav } from "@/app/nav"
import { Card, Tag, toast } from "@/components/ui"
import { CHART, Donut, Loading, Ring, useApi } from "@/components/viz"
import { api, mutate } from "@/data/live"
import { sectorOf } from "@/data/derive"

const ORGS = ["power", "water", "hospital"] as const
const ORG_CODE = { power: "WGEC", water: "MetroWater", hospital: "CCMN" } as const
const label = (o: string) => sectorOf[ORG_CODE[o as keyof typeof ORG_CODE]]?.label ?? o
const short = (h: string) => (h ? `${h.slice(0, 8)}…${h.slice(-4)}` : "")

/* ------------------------------------------------ 1. audit integrity */

function AuditIntegrity() {
  const [res, setRes] = useState<Record<string, any>>({})
  const [busy, setBusy] = useState(false)
  const check = async () => {
    setBusy(true)
    setRes({})
    // one organisation at a time: each check re-hashes every entry against the chain (~15 s)
    for (const o of ORGS) {
      setRes((s) => ({ ...s, [o]: { checking: true } }))
      const once = () => api(`/api/audit/verify?org=${o}`, undefined, 90_000).catch((e) => ({ error: String(e.message ?? e) }))
      let r = await once()
      // live mode keeps writing; a write landing mid-check looks like a mismatch, so re-check once before alarming
      if (!r.ok && !r.error) r = { ...(await once()), rechecked: true }
      setRes((s) => ({ ...s, [o]: r }))
    }
    setBusy(false)
  }
  useEffect(() => {
    check()
  }, [])
  const flush = async () => {
    try {
      await mutate(() => api("/api/audit/flush", {}))
      toast("Pending agent traces anchored on the chain")
      check()
    } catch (e) {
      toast("Anchoring failed", e instanceof Error ? e.message : String(e), "warn")
    }
  }
  return (
    <Card title="Is the audit trail untouched?" sub="Each organisation's local log is re-hashed and compared with the copy anchored on the blockchain" action={<button className="btn" disabled={busy} onClick={check}>{busy ? "Checking…" : "Check again"}</button>}>
      <div className="rings-row">
        {ORGS.map((o) => {
          const r = res[o]?.checking ? undefined : res[o]
          const ok = r?.ok
          const inFlight = !ok && /fewer entries|last digest/.test(r?.reason ?? "")
          return (
            <div key={o} className="ring-cell">
              <Ring value={r?.entries ?? 0} max={Math.max(1, r?.chain_length ?? 1)} label={label(o)} sub={r ? (r.error ? r.error : r.entries !== undefined ? `${r.entries} local · ${r.chain_length} on-chain` : r.reason) : res[o]?.checking ? "re-hashing every entry…" : "queued"} color={ok ? "var(--ok)" : inFlight ? "var(--warn)" : r ? "var(--danger)" : "var(--dim)"} text={r ? (ok ? "✓" : inFlight ? "…" : "✗") : "…"} />
              {r && !r.error && <Tag tone={ok ? "ok" : inFlight ? "warn" : "danger"}>{ok ? "matches the chain" : inFlight ? "a write is still in flight, check again" : `tampering suspected at entry #${r.first_mismatch}`}</Tag>}
            </div>
          )
        })}
      </div>
      <button className="btn btn-ghost" onClick={flush}>
        <Link2 size={14} /> Anchor pending traces now
      </button>
    </Card>
  )
}

/* ------------------------------------------------ 2. merkle proof */

function MerkleProof() {
  const traces = useApi<any[]>("/api/traces", 20_000)
  const recent = (traces.data ?? []).slice(-40).reverse()
  const [tid, setTid] = useState("")
  const sel = tid || recent[0]?.trace_id || ""
  const org = recent.find((t) => t.trace_id === sel)?.org ?? "power"
  const [proof, setProof] = useState<any>(null)
  const [err, setErr] = useState("")
  const load = async () => {
    setProof(null)
    setErr("")
    try {
      setProof(await api(`/api/audit/proof?org=${org}&trace_id=${sel}`))
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e))
    }
  }
  useEffect(() => {
    if (sel) load()
  }, [sel])
  const anchor = async () => {
    await api("/api/audit/flush", {}).catch(() => {})
    load()
  }
  const levels: string[] = proof?.proof ?? []
  const H = 46
  return (
    <Card title="Prove one record is on the chain" sub="A Merkle proof climbs from one agent trace (leaf) to the root stored on-chain, without revealing other records">
      <select className="input" value={sel} onChange={(e) => setTid(e.target.value)} aria-label="Agent trace">
        {recent.map((t) => (
          <option key={t.trace_id} value={t.trace_id}>
            {label(t.org)} · {t.label} · {t.steps} steps
          </option>
        ))}
      </select>
      {err ? (
        <div className="viz-msg">
          {/not anchored/.test(err) ? "This trace is not anchored yet." : err}{" "}
          <button className="btn btn-ghost" onClick={anchor}>
            Anchor it now
          </button>
        </div>
      ) : !proof ? (
        <Loading />
      ) : (
        <>
          <svg className="merkle" viewBox={`0 0 420 ${(levels.length + 2) * H}`} role="img" aria-label="Merkle proof path">
            {[...levels, null].map((sib, i) => {
              const y = (levels.length + 1 - i) * H
              return (
                <g key={i}>
                  <line x1="140" y1={y} x2="140" y2={y - H + 14} stroke="var(--accent)" strokeWidth="2" />
                  <rect x="70" y={y - 14} width="140" height="28" rx="7" className={i === 0 ? "mk-leaf" : "mk-node"} />
                  <text x="140" y={y + 4} textAnchor="middle" className="mk-t">
                    {i === 0 ? `leaf ${short(proof.leaf)}` : `hash level ${i}`}
                  </text>
                  {sib && (
                    <>
                      <line x1="210" y1={y} x2="250" y2={y} stroke="var(--line-2)" strokeDasharray="3 3" />
                      <rect x="250" y={y - 12} width="150" height="24" rx="6" className="mk-sib" />
                      <text x="325" y={y + 4} textAnchor="middle" className="mk-t dim">
                        sibling {short(sib)}
                      </text>
                    </>
                  )}
                </g>
              )
            })}
            <rect x="60" y="2" width="160" height="30" rx="8" className={proof.onchain_valid ? "mk-root ok" : "mk-root bad"} />
            <text x="140" y="22" textAnchor="middle" className="mk-t">
              root {short(proof.root)}
            </text>
          </svg>
          <p className="verdict">
            {proof.onchain_valid ? <CheckCircle2 size={16} color="var(--ok)" /> : <XCircle size={16} color="var(--danger)" />}
            {proof.onchain_valid ? `Valid: the root matches audit entry #${proof.entry_index} on the blockchain.` : "Invalid: the root does not match the chain."}
          </p>
        </>
      )}
    </Card>
  )
}

/* ------------------------------------------------ 3. agent swimlane */

const STEP = 72 // horizontal gap per trace step, wide enough for the tool name under each dot
const TYPE_COLOR: Record<string, string> = { observation: "var(--dim)", tool_call: "var(--accent)", decision: "var(--warn)", llm_call: "var(--accent-2)", error: "var(--danger)" }
function AgentSwimlane() {
  const traces = useApi<any[]>("/api/traces", 20_000)
  const list = (traces.data ?? []).filter((t) => t.steps > 2).slice(-40).reverse()
  const [tid, setTid] = useState("")
  const sel = tid || list[0]?.trace_id || ""
  const t = useApi(sel ? `/api/traces/${sel}` : null)
  const steps: any[] = t.data?.steps ?? []
  const agents = useMemo(() => [...new Set(steps.map((s) => s.agent))], [steps])
  const W = Math.max(520, steps.length * STEP + 120)
  return (
    <Card title="What did each agent do?" sub="One dot per step, one lane per agent. Blue = tool call, orange = decision, grey = observation; a ring means it wrote to the blockchain">
      <select className="input" value={sel} onChange={(e) => setTid(e.target.value)} aria-label="Trace">
        {list.map((x) => (
          <option key={x.trace_id} value={x.trace_id}>
            {label(x.org)} · {x.label} · {x.status} · {x.steps} steps
          </option>
        ))}
      </select>
      {!steps.length ? (
        <Loading error={t.error} />
      ) : (
        <div className="swim-wrap">
          <svg className="swim" width={W} height={agents.length * 44 + 20} role="img" aria-label="Agent trace swimlane">
            {agents.map((a, li) => (
              <g key={a}>
                <rect x="0" y={li * 44 + 6} width={W} height="36" className={li % 2 ? "sw-lane alt" : "sw-lane"} />
                <text x="10" y={li * 44 + 29} className="sw-name">
                  {a}
                </text>
              </g>
            ))}
            {steps.map((s, i) => {
              const li = agents.indexOf(s.agent)
              const x = 110 + i * STEP
              const y = li * 44 + 24
              const prev = steps[i - 1]
              return (
                <g key={i}>
                  {prev && <line x1={110 + (i - 1) * STEP} y1={agents.indexOf(prev.agent) * 44 + 24} x2={x} y2={y} stroke="var(--line-2)" />}
                  <circle cx={x} cy={y} r="8" fill={TYPE_COLOR[s.type] ?? "var(--dim)"} stroke={s.side_effect === "write_chain" ? "var(--text)" : "none"} strokeWidth="2.5">
                    <title>{`${s.agent} · ${s.type}${s.tool ? ` · ${s.tool}` : ""}${s.note ? ` · ${s.note}` : ""}${s.ms !== undefined ? ` · ${s.ms} ms` : ""}`}</title>
                  </circle>
                  {s.tool && (
                    <text x={x} y={y - 12} textAnchor="middle" className="sw-tool">
                      {s.tool.replace(/_/g, " ")}
                    </text>
                  )}
                </g>
              )
            })}
          </svg>
        </div>
      )}
      {t.data && (
        <p className="muted small">
          Trace {t.data.trace_id} · {t.data.status} · sealed with digest {short(t.data.digest)}
        </p>
      )}
    </Card>
  )
}

/* ------------------------------------------------ 4. chain activity */

function ChainActivity() {
  const ev = useApi<any[]>("/api/chain/events?limit=500", 20_000)
  const at = useApi<Record<string, any[]>>("/api/chain/attestations", 30_000)
  const bars = useMemo(() => {
    const m = new Map<string, number>()
    for (const e of ev.data ?? []) m.set(e.name, (m.get(e.name) ?? 0) + 1)
    return [...m].map(([name, n]) => ({ name: name.replace(/Submitted|Attestation/g, "").replace(/([a-z])([A-Z])/g, "$1 $2"), n })).sort((a, b) => b.n - a.n)
  }, [ev.data])
  const counts = at.data ? Object.entries(at.data).map(([k, v]) => ({ k, n: v.length })) : []
  return (
    <Card title="What is written on the blockchain?" sub="Last 500 contract events by type, and how many private attestations exist (contents are commitments, not readable data)">
      <div className="tiles">
        {counts.map((c) => (
          <div key={c.k} className="tile">
            <strong>{c.n}</strong>
            <small>{c.k} attestations</small>
          </div>
        ))}
      </div>
      {!bars.length ? (
        <Loading error={ev.error} />
      ) : (
        <div className="chart-md">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={bars} layout="vertical" margin={{ left: 20, right: 16 }}>
              <XAxis type="number" stroke={CHART.axis} fontSize={11} />
              <YAxis type="category" dataKey="name" width={150} stroke={CHART.axis} fontSize={11} />
              <Tooltip contentStyle={CHART.tooltip} />
              <Bar dataKey="n" name="events" fill="var(--accent-2)" radius={[0, 4, 4, 0]} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </Card>
  )
}

/* ------------------------------------------------ 5. firmware */

function Firmware() {
  const { openAsset } = useNav()
  const [res, setRes] = useState<Record<string, any>>({})
  useEffect(() => {
    ORGS.forEach((o) => api(`/api/firmware/check?org=${o}`).then((r) => setRes((s) => ({ ...s, [o]: r }))).catch(() => {}))
  }, [])
  return (
    <Card title="Is the firmware genuine?" sub="Supply-chain check: each device's firmware hash against the known-good hash registered on-chain">
      <div className="grid-3 tight">
        {ORGS.map((o) => {
          const r = res[o]?.results ?? {}
          const vals = Object.values(r) as string[]
          const n = (k: string) => vals.filter((v) => v === k).length
          const flagged = Object.entries(res[o]?.flagged ?? {}) as [string, string][]
          return (
            <div key={o}>
              <h3 className="h3">{label(o)}</h3>
              {!res[o] ? (
                <Loading />
              ) : (
                <>
                  <Donut
                    h={140}
                    center={`${n("Match")}/${vals.length}`}
                    slices={[
                      { name: "Genuine", value: n("Match"), color: "var(--ok)" },
                      { name: "Tampered", value: n("Mismatch"), color: "var(--danger)" },
                      { name: "Unknown", value: vals.length - n("Match") - n("Mismatch"), color: "var(--warn)" },
                    ]}
                  />
                  <div className="chips-row">
                    {flagged.map(([id, v]) => (
                      <button key={id} className={`chip ${v === "Mismatch" ? "bad" : "warn"}`} onClick={() => openAsset(id)}>
                        {id.replace("-asset-", " ")} · {v === "Mismatch" ? "tampered" : "unknown"}
                      </button>
                    ))}
                  </div>
                </>
              )}
            </div>
          )
        })}
      </div>
    </Card>
  )
}

/* ------------------------------------------------ 6. emergency brake */

function Brake() {
  const st = useApi("/api/chain/status", 6_000)
  const [busy, setBusy] = useState(false)
  const paused = !!st.data?.paused
  const inFlight = useRef(false)
  const flip = async () => {
    if (inFlight.current) return
    inFlight.current = true
    setBusy(true)
    try {
      await api(paused ? "/api/admin/resume" : "/api/admin/pause", {})
      toast(paused ? "Chain writes resumed" : "Chain writes paused", paused ? "Agents can write to the blockchain again" : "Nothing new is written until you resume")
    } catch (e) {
      toast("Failed", e instanceof Error ? e.message : String(e), "warn")
    } finally {
      inFlight.current = false
      setBusy(false)
      st.reload()
    }
  }
  return (
    <Card title="Emergency brake" sub="Admin can freeze every blockchain write; pending writes wait in a queue">
      <div className="brake">
        <button className={`switch ${paused ? "on" : ""}`} role="switch" aria-checked={paused} aria-label="Pause all blockchain writes" disabled={busy || !st.data} onClick={flip}>
          <span />
        </button>
        <div>
          <strong className={paused ? "bad" : "good"}>{paused ? "PAUSED" : "Running"}</strong>
          <small>
            {st.data ? `${st.data.pending_writes} pending writes · block ${st.data.block}` : "…"}
          </small>
        </div>
        {paused ? <Hand size={30} color="var(--danger)" /> : <Play size={30} color="var(--ok)" />}
      </div>
    </Card>
  )
}

/* ------------------------------------------------ 7. role lens */

const ROLES = ["admin", "org:power", "org:water", "org:hospital"]
const PROBES = [
  { k: "Power assets", p: "/api/orgs/power/assets" },
  { k: "Water assets", p: "/api/orgs/water/assets" },
  { k: "Hospital assets", p: "/api/orgs/hospital/assets" },
  { k: "Power firmware", p: "/api/firmware/check?org=power" },
  { k: "Hospital risk scores", p: "/api/ps03/orgs/hospital/attention?limit=1" },
  { k: "Shared cascade map", p: "/api/cross-org/graph" },
]
function RoleLens() {
  const [m, setM] = useState<Record<string, number>>({})
  useEffect(() => {
    for (const r of ROLES)
      for (const pr of PROBES)
        fetch(pr.p, { headers: { "X-Dev-Role": r } })
          .then((res) => setM((s) => ({ ...s, [r + pr.p]: res.status })))
          .catch(() => setM((s) => ({ ...s, [r + pr.p]: 0 })))
  }, [])
  return (
    <Card title="Who can see what?" sub="Each organisation sees only its own data; the shared cascade map holds commitments only. Live test against the API with each role">
      <div className="lens" style={{ gridTemplateColumns: `130px repeat(${PROBES.length}, minmax(0,1fr))` }}>
        <span />
        {PROBES.map((p) => (
          <b key={p.k}>{p.k}</b>
        ))}
        {ROLES.map((r) => (
          <Fragment key={r}>
            <b className="lens-role">
              {r === "admin" ? "Admin" : `${label(r.slice(4))} operator`}
            </b>
            {PROBES.map((p) => {
              const s = m[r + p.p]
              return (
                <span key={r + p.p} className={`lens-cell ${s === undefined ? "" : s < 300 ? "yes" : "no"}`} title={`HTTP ${s ?? "…"}`}>
                  {s === undefined ? "…" : s < 300 ? <CheckCircle2 size={15} /> : <Lock size={15} />}
                </span>
              )
            })}
          </Fragment>
        ))}
      </div>
    </Card>
  )
}

/* ------------------------------------------------ 8. pipeline health */

function Health() {
  const mt = useApi("/api/metrics", 15_000)
  const t = mt.data?.total
  const per = Object.entries(mt.data?.per_org ?? {}).map(([o, v]: [string, any]) => ({ org: label(o), Advisories: v.advisories, "Sent to humans": v.approvals_requested, Executed: v.executed, Failed: v.failed }))
  return (
    <Card title="How healthy is the agent pipeline?" sub="Live counters from /api/metrics since the backend started">
      {!t ? (
        <Loading error={mt.error} />
      ) : (
        <>
          <div className="rings-row">
            <Ring value={t.critic_reject_rate} max={1} label="Critic rejects" text={`${Math.round(t.critic_reject_rate * 100)}%`} color="var(--warn)" size={96} />
            <Ring value={t.llm_fallback_rate} max={1} label="LLM fallbacks" text={`${Math.round(t.llm_fallback_rate * 100)}%`} color="var(--accent-2)" size={96} />
            <Ring value={t.injection_detections} max={Math.max(1, t.advisories)} label="Injections caught" text={String(t.injection_detections)} color="var(--danger)" size={96} />
            <Ring value={Math.min(t.mean_pipeline_latency_s ?? 0, 10)} max={10} label="Avg pipeline time" text={`${(t.mean_pipeline_latency_s ?? 0).toFixed(1)}s`} color="var(--accent)" size={96} />
          </div>
          <div className="chart-sm">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={per} margin={{ top: 8, right: 8, left: -18 }}>
                <CartesianGrid stroke={CHART.grid} vertical={false} />
                <XAxis dataKey="org" stroke={CHART.axis} fontSize={11} />
                <YAxis allowDecimals={false} stroke={CHART.axis} fontSize={11} />
                <Tooltip contentStyle={CHART.tooltip} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Bar dataKey="Advisories" fill="var(--accent)" isAnimationActive={false} />
                <Bar dataKey="Sent to humans" fill="var(--warn)" isAnimationActive={false} />
                <Bar dataKey="Executed" fill="var(--ok)" isAnimationActive={false} />
                <Bar dataKey="Failed" fill="var(--danger)" isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </>
      )}
    </Card>
  )
}

export default function Trust() {
  return (
    <div className="page">
      <div className="grid-2">
        <AuditIntegrity />
        <Brake />
      </div>
      <div className="grid-2">
        <MerkleProof />
        <AgentSwimlane />
      </div>
      <div className="grid-2">
        <ChainActivity />
        <Health />
      </div>
      <Firmware />
      <RoleLens />
    </div>
  )
}
