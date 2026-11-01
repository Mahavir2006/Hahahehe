import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { CheckCircle2, Copy, FlaskConical, GitFork, History, Pause, Radio, RotateCcw, ShieldCheck, XCircle } from "lucide-react"
import { Card, Tag, toast } from "@/components/ui"
import { api } from "@/data/live"

/* The digital twin is built by the backend from contract events only (backend/twin). This page shows it live,
   lets you travel back to any block, checks that every organisation's independent replay agrees, lists where
   reality drifts from the twin, and runs what-ifs on a chain snapshot that is rolled back afterwards. */

type Twin = {
  block: number
  head: number
  events: number
  fingerprint: { root: string; sections: Record<string, string> }
  summary: Record<string, number>
  reach: Record<string, string[]>
  org_names: Record<string, string>
  state: Record<string, Record<string, any>>
}
type Point = { block: number; root: string; events: number; counts: Record<string, number>; changes: Record<string, number> }

const ORG_LABEL: Record<string, string> = { power: "Power", water: "Water", hospital: "Healthcare" }
const ORG_COLOR: Record<string, string> = { power: "#38bdf8", water: "#a78bfa", hospital: "#f472b6" }
const ORG_POS: Record<string, [number, number]> = { power: [150, 120], water: [450, 120], hospital: [300, 330] }
const short = (h?: string | null, n = 6) => (h ? `${h.slice(0, n + 2)}…${h.slice(-4)}` : "—")
const name = (t: Twin | null, id: string) => t?.org_names[id] ?? id.slice(0, 8)
const SECTION_LABEL: Record<string, string> = {
  orgs: "Organisations", services: "Services", edges: "Dependencies", findings: "Findings", alerts: "Cascade alerts",
  approvals: "Approvals", firmware: "Firmware", vendors: "Vendors", audit: "Audit anchors", challenges: "Challenges",
}

/* ------------------------------------------------------------ graph */

function TwinGraph({ t, prev }: { t: Twin; prev: Twin | null }) {
  const layout = useMemo(() => {
    const pos = new Map<string, [number, number]>()
    const byOrg: Record<string, string[]> = {}
    for (const [h, s] of Object.entries(t.state.services)) (byOrg[s.org] ??= []).push(h)
    for (const [org, list] of Object.entries(byOrg)) {
      const c = ORG_POS[t.org_names[org]] ?? [300, 220]
      list.sort().forEach((h, i) => {
        const a = (i / list.length) * Math.PI * 2 - Math.PI / 2
        pos.set(h, [c[0] + Math.cos(a) * 70, c[1] + Math.sin(a) * 58])
      })
    }
    return pos
  }, [t])
  const isNew = (section: string, key: string) => !!prev && !(key in (prev.state[section] ?? {}))
  const openAlerts = new Set(Object.values(t.state.alerts).filter((a: any) => a.status === "open").map((a: any) => a.provider_service))
  return (
    <svg className="twin-graph" viewBox="0 0 600 430" role="img" aria-label="Twin graph: organisations, their services and the dependencies confirmed on chain">
      <defs>
        <marker id="tw-arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto">
          <path d="M0 1L10 5L0 9z" className="tw-arrow" />
        </marker>
      </defs>
      {Object.entries(t.state.edges).map(([id, e]: [string, any]) => {
        const a = layout.get(e.provider_service)
        const b = layout.get(e.consumer_service)
        if (!a || !b) return null
        return (
          <line key={id} x1={a[0]} y1={a[1]} x2={b[0]} y2={b[1]} className={`tw-edge ${e.status} ${isNew("edges", id) ? "tw-new" : ""}`} markerEnd="url(#tw-arr)">
            <title>{`${name(t, e.provider_org)} → ${name(t, e.consumer_org)} · ${e.status}`}</title>
          </line>
        )
      })}
      {Object.entries(t.state.orgs).map(([id, o]: [string, any]) => {
        const n = t.org_names[id]
        const [x, y] = ORG_POS[n] ?? [300, 220]
        const pend = Object.values(t.state.approvals).filter((r: any) => r.org === id && r.status === "pending").length
        const anchors = t.state.audit[id]?.anchors ?? 0
        return (
          <g key={id} className={`tw-org ${o.active ? "" : "inactive"} ${isNew("orgs", id) ? "tw-new" : ""}`}>
            <circle cx={x} cy={y} r={34} style={{ stroke: ORG_COLOR[n] }} />
            <text x={x} y={y - 2} textAnchor="middle" className="tw-org-name">
              {ORG_LABEL[n] ?? n}
            </text>
            <text x={x} y={y + 13} textAnchor="middle" className="tw-org-sub">
              {o.active ? `${anchors} anchors` : "deactivated"}
            </text>
            {pend > 0 && (
              <g>
                <circle cx={x + 28} cy={y - 26} r={10} className="tw-badge" />
                <text x={x + 28} y={y - 22} textAnchor="middle" className="tw-badge-t">
                  {pend}
                </text>
              </g>
            )}
          </g>
        )
      })}
      {[...layout.entries()].map(([h, [x, y]]) => {
        const s = t.state.services[h]
        return (
          <g key={h} className={isNew("services", h) ? "tw-new" : ""}>
            {openAlerts.has(h) && <circle cx={x} cy={y} r={11} className="tw-alert" />}
            <circle cx={x} cy={y} r={6} className={`tw-svc ${s.band_commitment ? "attested" : ""}`} style={{ fill: ORG_COLOR[t.org_names[s.org]] }}>
              <title>{`service ${short(h)} · ${s.attestations} risk attestation(s)${s.band_commitment ? " · band sealed on chain" : ""}`}</title>
            </circle>
          </g>
        )
      })}
    </svg>
  )
}

/* ------------------------------------------------------------ page */

export default function TwinPage() {
  const [t, setT] = useState<Twin | null>(null)
  const prevRef = useRef<Twin | null>(null)
  const [prev, setPrev] = useState<Twin | null>(null)
  const [timeline, setTimeline] = useState<Point[]>([])
  const [at, setAt] = useState<number | null>(null) // null = live
  const [replaying, setReplaying] = useState(false)
  const [stream, setStream] = useState<"connecting" | "live" | "off">("connecting")
  const [err, setErr] = useState("")

  const load = useCallback(async (block: number | null) => {
    try {
      const next: Twin = await api(block === null ? "/api/twin" : `/api/twin?block=${block}`)
      setPrev(prevRef.current)
      prevRef.current = next
      setT(next)
      setErr("")
    } catch (e) {
      setErr(String((e as Error).message ?? e))
    }
  }, [])

  // live: one server-sent event per new block that changed the twin
  useEffect(() => {
    if (at !== null) return
    load(null)
    api<Point[]>("/api/twin/timeline?points=300").then(setTimeline).catch(() => {})
    const es = new EventSource("/api/twin/stream")
    es.onopen = () => setStream("live")
    es.onmessage = () => {
      load(null)
      api<Point[]>("/api/twin/timeline?points=300").then(setTimeline).catch(() => {})
    }
    es.onerror = () => setStream("off")
    return () => es.close()
  }, [at, load])

  // replay: step through the timeline so the twin visibly assembles itself from the first block
  useEffect(() => {
    if (!replaying || !timeline.length) return
    let i = 0
    let stop = false
    const step = async () => {
      if (stop) return
      if (i >= timeline.length) return setReplaying(false)
      const p = timeline[Math.min(i, timeline.length - 1)]
      setAt(p.block)
      await load(p.block)
      i += Math.max(1, Math.round(timeline.length / 45))
      setTimeout(step, 220)
    }
    step()
    return () => {
      stop = true
    }
  }, [replaying, timeline, load])

  if (!t) return <div className="page">{err ? <Card title="Digital twin unavailable"><p className="muted">{err}</p></Card> : <div className="skeleton" style={{ height: 420 }} />}</div>

  const live = at === null
  const first = timeline[0]?.block ?? 0
  const s = t.summary

  return (
    <div className="page twin">
      <section className="glass twin-bar">
        <div className="twin-id">
          <span className={`twin-live ${live ? stream : "past"}`} />
          <div>
            <strong>{live ? "Live twin" : `Twin at block ${t.block}`}</strong>
            <small>
              built from {t.events} contract events · chain head {t.head}
            </small>
          </div>
        </div>
        <button
          className="twin-root"
          title="Fingerprint (Merkle root) of the whole twin at this block"
          onClick={() => navigator.clipboard?.writeText(t.fingerprint.root).then(() => toast("Fingerprint copied", t.fingerprint.root))}
        >
          <span>fingerprint</span>
          <code>{short(t.fingerprint.root, 10)}</code>
          <Copy size={12} />
        </button>
        <div className="twin-ctl">
          {live ? (
            <button className="btn" onClick={() => setReplaying(true)} disabled={!timeline.length}>
              <History size={14} /> Replay how it assembled
            </button>
          ) : (
            <button
              className="btn btn-primary"
              onClick={() => {
                setReplaying(false)
                setAt(null)
              }}
            >
              <Radio size={14} /> Back to live
            </button>
          )}
          {replaying && (
            <button className="btn" onClick={() => setReplaying(false)} aria-label="Pause replay">
              <Pause size={14} />
            </button>
          )}
        </div>
      </section>

      <div className="twin-grid">
        <section className="glass pane twin-main">
          <div className="pane-row">
            <h2 className="pane-title">Twin of the consortium — assembled from the chain, nothing hardcoded</h2>
            <span className="muted small">solid = confirmed by both sides · dashed = one-sided · red = revoked</span>
          </div>
          <TwinGraph t={t} prev={prev} />
          <div className="twin-time">
            <input
              type="range"
              min={first}
              max={t.head}
              value={t.block}
              onChange={(e) => {
                setReplaying(false)
                const b = Number(e.target.value)
                setAt(b >= t.head ? null : b)
                if (b < t.head) load(b)
              }}
              aria-label="Time travel: twin at block"
            />
            <div className="twin-time-l">
              <span>block {first}</span>
              <span>{live ? "live" : `block ${t.block}`}</span>
              <span>head {t.head}</span>
            </div>
          </div>
          <div className="twin-counts">
            {[
              ["Organisations", s.orgs],
              ["Services", s.services],
              ["Confirmed links", s.edges_confirmed],
              ["One-sided links", s.edges_pending],
              ["Open alerts", s.alerts_open],
              ["Pending approvals", s.approvals_pending],
              ["Firmware releases", s.firmware],
              ["Audit anchors", s.anchors],
            ].map(([l, v]) => (
              <div key={l as string}>
                <span>{l}</span>
                <b>{v}</b>
              </div>
            ))}
          </div>
          <Reach t={t} />
        </section>

        <div className="twin-side">
          <Consensus root={t.fingerprint.root} live={live} />
          <Drift block={t.block} live={live} />
        </div>
      </div>

      <div className="grid-2">
        <WhatIf />
        <Overlay />
      </div>
      <Sections t={t} />
    </div>
  )
}

function Reach({ t }: { t: Twin }) {
  return (
    <div className="twin-reach">
      {Object.entries(t.reach).map(([org, to]) => (
        <span key={org}>
          <b style={{ color: ORG_COLOR[t.org_names[org]] }}>{ORG_LABEL[t.org_names[org]] ?? name(t, org)}</b> failure can reach{" "}
          {to.length ? to.map((x) => ORG_LABEL[t.org_names[x]] ?? name(t, x)).join(", ") : "no other organisation"}
        </span>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------ consensus */

function Consensus({ root, live }: { root: string; live: boolean }) {
  const [v, setV] = useState<any>(null)
  const [busy, setBusy] = useState(false)
  const run = async () => {
    setBusy(true)
    try {
      setV(await api("/api/twin/verify", undefined, 120_000))
    } catch (e) {
      toast("Verification failed", String((e as Error).message ?? e), "warn")
    }
    setBusy(false)
  }
  useEffect(() => {
    run()
  }, [])
  return (
    <Card
      title="Does everyone see the same twin?"
      sub="Each organisation replays the chain over its own connection; the contracts are asked directly"
      action={
        <button className="btn btn-sm" disabled={busy} onClick={run}>
          <ShieldCheck size={13} /> {busy ? "Verifying…" : "Verify now"}
        </button>
      }
    >
      {!v ? (
        <div className="skeleton" style={{ height: 120 }} />
      ) : (
        <>
          <div className={`twin-verdict ${v.all_agree ? "ok" : "bad"}`}>
            {v.all_agree ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
            {v.all_agree ? `${v.nodes.length}/${v.nodes.length} organisations agree at block ${v.height}` : "Disagreement found"}
          </div>
          <ul className="twin-nodes">
            {v.nodes.map((n: any) => (
              <li key={n.org}>
                <span style={{ color: ORG_COLOR[n.org] }}>{ORG_LABEL[n.org]}</span>
                <code>{short(n.root, 8)}</code>
                <small>{n.events} events · {n.seconds}s</small>
                {n.agrees ? <CheckCircle2 size={14} className="ok" /> : <XCircle size={14} className="up" />}
              </li>
            ))}
          </ul>
          <div className="twin-checks">
            {Object.entries(v.contract_checks).map(([k, c]: [string, any]) => (
              <Tag key={k} tone={c.ok === c.total ? "ok" : "danger"}>
                {k} {c.ok}/{c.total}
              </Tag>
            ))}
          </div>
          {live && v.twin_root !== root && <p className="muted small">New blocks arrived since this check; press Verify now to re-check.</p>}
        </>
      )}
    </Card>
  )
}

/* ------------------------------------------------------------ drift */

function Drift({ block, live }: { block: number; live: boolean }) {
  const [d, setD] = useState<any[] | null>(null)
  useEffect(() => {
    if (!live) return
    api("/api/twin/drift").then(setD).catch(() => setD([]))
  }, [block, live])
  return (
    <Card title="Where reality and the twin disagree" sub="Live organisation state compared with what the chain records">
      {!live ? (
        <p className="muted small">Drift is measured against the live twin. Go back to live to see it.</p>
      ) : !d ? (
        <div className="skeleton" style={{ height: 120 }} />
      ) : d.length === 0 ? (
        <p className="ok">No drift: every organisation matches its on-chain record.</p>
      ) : (
        <ul className="twin-drift">
          {d.slice(0, 12).map((x, i) => (
            <li key={i}>
              <Tag tone={x.severity === "high" ? "danger" : x.severity === "medium" ? "warn" : "info"}>{x.kind.replace(/_/g, " ")}</Tag>
              <span>
                <strong>{x.org ? ORG_LABEL[x.org] ?? x.org : ""}</strong> {x.subject} — {x.detail}
              </span>
            </li>
          ))}
          {d.length > 12 && <li className="muted small">+{d.length - 12} more</li>}
        </ul>
      )}
    </Card>
  )
}

/* ------------------------------------------------------------ what-if */

const KIND_LABEL: Record<string, string> = { segment_edge: "Cut a dependency (segment the link)", revoke_firmware: "Revoke a firmware release", deactivate_org: "Take an organisation offline" }

function WhatIf() {
  const [sc, setSc] = useState<Record<string, { target: string; label: string }[]> | null>(null)
  const [kind, setKind] = useState("segment_edge")
  const [target, setTarget] = useState("")
  const [res, setRes] = useState<any>(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    api("/api/twin/scenarios").then((x) => {
      setSc(x)
      setTarget(x.segment_edge?.[0]?.target ?? "")
    })
  }, [])
  const run = async () => {
    setBusy(true)
    setRes(null)
    try {
      const r = await api("/api/twin/fork", { kind, target }, 120_000)
      setRes(r)
      toast(r.rolled_back.untouched ? "What-if done · real chain untouched" : "What-if done", r.transaction.description, r.rolled_back.untouched ? "ok" : "warn")
    } catch (e) {
      toast("What-if failed", String((e as Error).message ?? e), "warn")
    }
    setBusy(false)
  }
  const opts = sc?.[kind] ?? []
  return (
    <Card title="What-if on a fork of the real chain" sub="One real transaction runs on a chain snapshot, the forked twin is read, then the snapshot is rolled back">
      <div className="twin-whatif-form">
        <select
          className="input"
          value={kind}
          onChange={(e) => {
            setKind(e.target.value)
            setTarget(sc?.[e.target.value]?.[0]?.target ?? "")
            setRes(null)
          }}
          aria-label="What-if"
        >
          {Object.keys(KIND_LABEL).map((k) => (
            <option key={k} value={k}>
              {KIND_LABEL[k]}
            </option>
          ))}
        </select>
        <select className="input" value={target} onChange={(e) => setTarget(e.target.value)} aria-label="Target">
          {opts.map((o) => (
            <option key={o.target} value={o.target}>
              {o.label}
            </option>
          ))}
        </select>
        <button className="btn btn-primary" disabled={busy || !target} onClick={run}>
          {busy ? <RotateCcw size={14} className="spin" /> : <GitFork size={14} />} {busy ? "Running on fork…" : "Run what-if"}
        </button>
      </div>
      {res && <ForkResult r={res} />}
      {!res && !busy && <p className="muted small">Uses the contracts themselves: the revoke, deactivate and confirmation rules are the real ones, not an imitation.</p>}
    </Card>
  )
}

function ForkResult({ r }: { r: any }) {
  const fk = r.forked
  const rb = r.rolled_back
  return (
    <div className="fork-res">
      <p>
        <FlaskConical size={14} /> <strong>{r.transaction.description}</strong>
      </p>
      <small className="muted">
        mined on the fork in block {r.transaction.block} · tx <code>{short(r.transaction.tx_hash)}</code>
      </small>
      <h3 className="h3">What changed in the twin</h3>
      <ul className="fork-changes">
        {fk.changes.slice(0, 6).map((c: any, i: number) => (
          <li key={i}>
            <Tag tone="info">{SECTION_LABEL[c.section] ?? c.section}</Tag> {short(c.key)} {c.change}
            {c.fields &&
              Object.entries(c.fields).map(([f, [a, b]]: [string, any]) => (
                <span key={f} className="muted">
                  {" "}
                  · {f}: {String(a)} → <b>{String(b)}</b>
                </span>
              ))}
          </li>
        ))}
      </ul>
      <ReachDiff before={fk.reach_before} after={fk.reach_after} sb={fk.reach_services_before} sa={fk.reach_services_after} />
      {fk.new_drift.length > 0 ? (
        <ul className="fork-changes">
          {fk.new_drift.slice(0, 4).map((d: any, i: number) => (
            <li key={i}>
              <Tag tone={d.severity === "high" ? "danger" : "warn"}>new drift</Tag> {d.subject} — {d.detail}
            </li>
          ))}
          {fk.new_drift.length > 4 && <li className="muted small">+{fk.new_drift.length - 4} more</li>}
        </ul>
      ) : (
        <p className="small muted">No new drift from this what-if.</p>
      )}
      <div className={`twin-verdict ${rb.untouched ? "ok" : "bad"}`}>
        {rb.untouched ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
        {rb.untouched
          ? `Rolled back: real chain still at block ${rb.head_after}, fingerprint unchanged (${short(rb.root_after)})`
          : "Rollback check failed"}
      </div>
    </div>
  )
}

function ReachDiff({ before, after, sb, sa }: { before: Record<string, string[]>; after: Record<string, string[]>; sb: Record<string, number>; sa: Record<string, number> }) {
  const [names, setNames] = useState<Record<string, string>>({})
  useEffect(() => {
    api("/api/twin").then((t: Twin) => setNames(t.org_names)).catch(() => {})
  }, [])
  const lab = (o: string) => ORG_LABEL[names[o]] ?? o.slice(0, 8)
  const rows = Object.keys(before).filter((o) => before[o].join() !== after[o].join() || sb[o] !== sa[o])
  if (!rows.length) return <p className="small muted">No change in how far a failure can spread.</p>
  return (
    <ul className="fork-changes">
      {rows.map((o) => (
        <li key={o}>
          A failure in <b>{lab(o)}</b> reached {sb[o]} service(s) in {before[o].map(lab).join(", ") || "no other organisation"} → now <b>{sa[o]}</b>
          {after[o].join() !== before[o].join() && <> in {after[o].map(lab).join(", ") || "no other organisation"}</>}
        </li>
      ))}
    </ul>
  )
}

/* ------------------------------------------------------------ private overlay */

function Overlay() {
  const [org, setOrg] = useState<"power" | "water" | "hospital">("power")
  const [ov, setOv] = useState<any>(null)
  useEffect(() => {
    setOv(null)
    api(`/api/twin/overlay/${org}`).then(setOv).catch(() => setOv({ error: true }))
  }, [org])
  return (
    <Card title="Private view of one organisation" sub="The shared twin holds hashes only; each organisation opens its own sealed records and checks them against the chain">
      <div className="seg" role="tablist" aria-label="Organisation">
        {(["power", "water", "hospital"] as const).map((o) => (
          <button key={o} role="tab" aria-selected={org === o} className={org === o ? "active" : ""} onClick={() => setOrg(o)}>
            {ORG_LABEL[o]}
          </button>
        ))}
      </div>
      {!ov ? (
        <div className="skeleton" style={{ height: 160, marginTop: 12 }} />
      ) : ov.error ? (
        <p className="muted">Could not load this organisation's view.</p>
      ) : (
        <div className="twin-ov">
          <table className="tbl ledger">
            <thead>
              <tr>
                <th>Service (only this org can name it)</th>
                <th>On chain (opened)</th>
                <th>Live now</th>
              </tr>
            </thead>
            <tbody>
              {ov.services.map((s: any) => (
                <tr key={s.service_hash}>
                  <td>
                    {s.name}
                    <small>
                      <code>{short(s.service_hash)}</code>
                    </small>
                  </td>
                  <td>{s.attested_band ?? <span className="muted">none</span>}</td>
                  <td className={s.current_band && s.attested_band && s.current_band !== s.attested_band ? "up" : ""}>{s.current_band}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="small">
            Dependencies: {ov.edges.filter((e: any) => e.terms_verified).length} of {ov.edges.length} with sealed terms opened and matching the chain ·
            Firmware: {ov.assets.filter((a: any) => a.firmware === "Match").length}/{ov.assets.length} assets vouched for by the registry
          </p>
        </div>
      )}
    </Card>
  )
}

/* ------------------------------------------------------------ fingerprint sections */

function Sections({ t }: { t: Twin }) {
  return (
    <Card title="How the fingerprint is made" sub="One hash per part of the twin; the Merkle root of these is the fingerprint every organisation compares">
      <div className="twin-sections">
        {Object.entries(t.fingerprint.sections).map(([k, h]) => (
          <div key={k}>
            <span>{SECTION_LABEL[k] ?? k}</span>
            <code>{short(h, 8)}</code>
          </div>
        ))}
      </div>
    </Card>
  )
}

