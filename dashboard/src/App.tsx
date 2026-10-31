import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import {
  api, ApiError, Band, Change, Detection, GraphEdge, GraphNode, ModelCard, Org, orgsFor, PlanStep, Role, Score, setRole,
  Trend, Why, CascadeStep,
} from './api'
import './App.css'

type View = 'overview' | 'map' | 'plans' | 'detections' | 'audit' | 'model'
const VIEWS: [View, string][] = [
  ['overview', 'Risk overview'], ['map', 'Infrastructure map'], ['plans', 'Plans & approvals'],
  ['detections', 'Detections'], ['audit', 'Audit & chain'], ['model', 'Model card'],
]
const BAND_ORDER: Band[] = ['critical', 'high', 'medium', 'low']

function useLoad<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const run = useCallback(() => {
    setLoading(true)
    setError(null)
    fn().then(setData).catch((e: unknown) => setError(e instanceof ApiError ? e.message : String(e))).finally(() => setLoading(false))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  useEffect(run, [run])
  return { data, error, loading, reload: run }
}

const BandPill = ({ band }: { band: Band }) => <span className={`pill band-${band}`}>{band}</span>
const Pct = (x: number) => `${(x * 100).toFixed(1)}%`

function State({ loading, error }: { loading: boolean; error: string | null }) {
  if (error) return <div className="state error">Could not load: {error}</div>
  if (loading) return <div className="state">Loading…</div>
  return null
}

// --------------------------------------------------------------------- overview
function Overview({ orgs, onPick }: { orgs: Org[]; onPick: (org: Org, id: string) => void }) {
  const [org, setOrg] = useState<Org>(orgs[0])
  useEffect(() => { if (!orgs.includes(org)) setOrg(orgs[0]) }, [orgs, org])
  const risk = useLoad(() => api.risk(org), [org])
  const assets = useLoad(() => api.assets(org), [org])
  const trends = useLoad(() => api.trends(org), [org])
  const names = useMemo(() => Object.fromEntries((assets.data ?? []).map(a => [a.asset_id, a])), [assets.data])
  const trendOf = useMemo(() => Object.fromEntries((trends.data ?? []).map(t => [t.asset_id, t])), [trends.data])
  const ranked = useMemo(() => [...(risk.data?.scores ?? [])].sort((a, b) => b.risk_bp - a.risk_bp), [risk.data])
  const counts = BAND_ORDER.map(b => [b, ranked.filter(s => s.band === b).length] as const)

  return (
    <section>
      <div className="row">
        <h2>Risk overview</h2>
        <OrgTabs orgs={orgs} org={org} setOrg={setOrg} />
      </div>
      <State loading={risk.loading} error={risk.error} />
      {risk.data && (
        <>
          <div className="kpis">
            <div className="kpi"><div className="kpi-label">Org risk (0.6 max + 0.4 mean)</div><div className="kpi-value">{risk.data.aggregate.toFixed(1)}</div></div>
            {counts.map(([b, n]) => (
              <div className={`kpi kpi-${b}`} key={b}><div className="kpi-label">{b}</div><div className="kpi-value">{n}</div></div>
            ))}
          </div>
          <table>
            <thead><tr><th>#</th><th>Asset</th><th>Zone</th><th>Risk</th><th>Band</th><th>Likelihood</th><th>Impact</th><th>Top driver</th><th>Trend</th></tr></thead>
            <tbody>
              {ranked.map((s: Score, i) => {
                const a = names[s.asset_id]
                const t: Trend | undefined = trendOf[s.asset_id]
                return (
                  <tr key={s.asset_id} className="clickable" onClick={() => onPick(org, s.asset_id)}>
                    <td>{i + 1}</td>
                    <td><b>{a?.name ?? s.asset_id}</b><div className="muted">{s.asset_id} · {a?.type}</div></td>
                    <td>{a?.zone}</td>
                    <td className="num">{s.risk.toFixed(2)}</td>
                    <td><BandPill band={s.band} /></td>
                    <td className="num">{Pct(s.likelihood)}</td>
                    <td className="num">{Pct(s.impact)}</td>
                    <td className="muted">{s.top_factors[0]?.text ?? '—'}</td>
                    <td className="muted">{t?.direction ?? '—'}{t?.days_to_next_band != null ? ` · next band ~${t.days_to_next_band}d` : ''}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          <p className="note">Likelihood is M1's calibrated probability of compromise in 90 days (trained on simulated data); impact and the final risk formula are deterministic. Bands are relative ranks set from M1's output distribution.</p>
        </>
      )}
    </section>
  )
}

function OrgTabs({ orgs, org, setOrg }: { orgs: Org[]; org: Org; setOrg: (o: Org) => void }) {
  return (
    <div className="tabs">
      {orgs.map(o => <button key={o} className={o === org ? 'active' : ''} onClick={() => setOrg(o)}>{o}</button>)}
    </div>
  )
}

// ------------------------------------------------------------------ asset panel
function AssetPanel({ org, id, onClose }: { org: Org; id: string; onClose: () => void }) {
  const why = useLoad(() => api.why(org, id), [org, id])
  const changed = useLoad(() => api.whatChanged(org, id), [org, id])
  const trend = useLoad(() => api.trend(org, id), [org, id])
  const w: Why | null = why.data
  const maxAbs = Math.max(0.01, ...(w?.key_factors ?? []).map(f => Math.abs(f.contribution_logodds)))
  return (
    <aside className="panel">
      <div className="row"><h2>{id}</h2><button onClick={onClose}>Close</button></div>
      <State loading={why.loading} error={why.error} />
      {w && (
        <>
          <div className="formula">
            <div><span className="muted">Likelihood</span><b>{Pct(w.likelihood)}</b></div>
            <span>×</span>
            <div><span className="muted">(0.3 + 0.7 × impact)</span><b>{Pct(w.impact)}</b></div>
            <span>=</span>
            <div><span className="muted">Risk</span><b>{w.risk.toFixed(2)}</b></div>
            <BandPill band={w.band} />
          </div>
          <h3>Why this score (SHAP, log-odds)</h3>
          {w.key_factors.map(f => (
            <div className="bar-row" key={f.feature}>
              <span className="bar-label">{f.factor} <span className="muted">= {f.value}</span></span>
              <span className="bar-track">
                <span className={`bar ${f.contribution_logodds > 0 ? 'up' : 'down'}`} style={{ width: `${(Math.abs(f.contribution_logodds) / maxAbs) * 100}%` }} />
              </span>
              <span className="num">{f.contribution_logodds > 0 ? '+' : ''}{f.contribution_logodds.toFixed(3)}</span>
            </div>
          ))}
          <h3>Vulnerabilities</h3>
          {w.source_cves.length === 0 ? <p className="muted">No known CVE matched to this asset.</p> : (
            <ul>{w.source_cves.map(c => <li key={c.cve}><b>{c.cve}</b> · CVSS {c.cvss ?? 'missing'}{c.known_exploited ? ' · known exploited (CISA KEV)' : ''}<div className="muted">{c.version_match}</div></li>)}</ul>
          )}
          <h3>What changed since start</h3>
          {(changed.data?.changes ?? []).length === 0 ? <p className="muted">No change in this asset's risk drivers.</p> :
            <ul>{changed.data!.changes.map((c: Change) => <li key={c.feature}>{c.sentence}</li>)}</ul>}
          <h3>Trend (statistical)</h3>
          <p>{trend.data?.direction ?? '—'}{trend.data?.slope_per_day != null ? ` · ${trend.data.slope_per_day} pts/day` : ''}{trend.data?.days_to_next_band != null ? ` · next band in ~${trend.data.days_to_next_band} days` : ''}</p>
          <h3>Data sources</h3>
          <ul className="tags">{Object.entries(w.source_tags).map(([k, v]) => <li key={k}><span className="muted">{k}:</span> {v}</li>)}</ul>
          {w.missing_or_clipped.length > 0 && <p className="note">Missing or clipped inputs: {w.missing_or_clipped.join(', ')}</p>}
          <p className="note">Model {w.data_freshness.model_version}, scored as of {w.data_freshness.scored_as_of}.</p>
        </>
      )}
    </aside>
  )
}

// --------------------------------------------------------------- infrastructure
const BAND_COLOR: Record<string, string> = { critical: '#d64545', high: '#e8833a', medium: '#d9b43c', low: '#4f9d69', unknown: '#8a8f98' }

function MapView({ orgs }: { orgs: Org[] }) {
  const g = useLoad(() => api.crossGraph(), [])
  const ref = useRef<HTMLDivElement>(null)
  const [cascadeOrg, setCascadeOrg] = useState<Org>(orgs[0])
  const services = useLoad(() => api.services(cascadeOrg), [cascadeOrg])
  const [svc, setSvc] = useState<string>('')
  const [chain, setChain] = useState<CascadeStep[] | null>(null)
  const [cErr, setCErr] = useState<string | null>(null)

  useEffect(() => {
    if (!g.data || !ref.current) return
    const nodes = g.data.nodes.map((n: GraphNode) => ({ data: { id: `${n.org}:${n.service_hash}`, label: n.label || `${n.org}:${n.service_hash.slice(0, 6)}`, org: n.org, color: BAND_COLOR[n.band] ?? BAND_COLOR.unknown } }))
    const ids = new Set(nodes.map(n => n.data.id))
    const edges = g.data.edges
      .filter((e: GraphEdge) => ids.has(`${e.provider_org}:${e.provider_service}`) && ids.has(`${e.consumer_org}:${e.consumer_service}`))
      .map((e: GraphEdge, i) => ({ data: { id: `e${i}`, source: `${e.provider_org}:${e.provider_service}`, target: `${e.consumer_org}:${e.consumer_service}`, label: `${e.strength}`, dashed: e.confirmed ? 'solid' : 'dashed' } }))
    const cy = cytoscape({
      container: ref.current, elements: [...nodes, ...edges], layout: { name: 'breadthfirst', directed: true, spacingFactor: 1.2 },
      style: [
        { selector: 'node', style: { 'background-color': 'data(color)', label: 'data(label)', color: '#e6e8eb', 'font-size': 10, 'text-wrap': 'wrap', 'text-max-width': '110px', 'text-valign': 'bottom', 'text-margin-y': 4, width: 26, height: 26 } },
        { selector: 'edge', style: { width: 2, 'line-color': '#5b6270', 'target-arrow-color': '#5b6270', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', 'line-style': 'data(dashed)' as never, label: 'data(label)', 'font-size': 8, color: '#9aa1ab' } },
      ],
    })
    return () => cy.destroy()
  }, [g.data])

  const run = () => {
    if (!svc) return
    setCErr(null)
    api.cascade(cascadeOrg, svc).then(r => setChain(r.chain)).catch(e => setCErr(String(e.message ?? e)))
  }

  return (
    <section>
      <h2>Infrastructure map</h2>
      <p className="muted">Services across organisations, coloured by their current risk band, with dependency edges (provider → consumer). Bands and edge terms are opened from sealed on-chain disclosures and verified against their commitments; dashed = one-sided (unconfirmed) edge, never used in the cascade.</p>
      <State loading={g.loading} error={g.error} />
      <div className="legend">{Object.entries(BAND_COLOR).map(([b, c]) => <span key={b}><i style={{ background: c }} />{b}</span>)}</div>
      <div ref={ref} className="graph" />
      <h3>What if this service fails?</h3>
      <div className="row left">
        <OrgTabs orgs={orgs} org={cascadeOrg} setOrg={o => { setCascadeOrg(o); setSvc(''); setChain(null) }} />
        <select value={svc} onChange={e => setSvc(e.target.value)}>
          <option value="">choose a service…</option>
          {(services.data ?? []).map(s => <option key={s.service_id} value={s.service_id}>{s.name} ({s.band})</option>)}
        </select>
        <button onClick={run} disabled={!svc}>Run cascade</button>
      </div>
      {cErr && <div className="state error">{cErr}</div>}
      {chain && (chain.length === 0 ? <p className="muted">No downstream service depends on it through a confirmed edge.</p> : (
        <table>
          <thead><tr><th>Impacted service</th><th>Org</th><th>Time to impact</th><th>P(degraded)</th><th>Criticality</th></tr></thead>
          <tbody>{chain.map(c => <tr key={`${c.org}${c.service}`}><td>{c.label || c.service.slice(0, 10)}</td><td>{c.org}</td><td className="num">~{c.time_to_impact_minutes} min</td><td className="num">{Pct(c.p_degraded)}</td><td>{c.criticality_bucket}</td></tr>)}</tbody>
        </table>
      ))}
    </section>
  )
}

// ------------------------------------------------------------------- plans
function PlansView({ orgs }: { orgs: Org[] }) {
  const plans = useLoad(() => api.plans(), [])
  const approvals = useLoad(() => api.approvals(), [])
  const [open, setOpen] = useState<string | null>(null)
  const plan = useLoad(() => (open ? api.plan(open) : Promise.resolve(null)), [open])
  const [msg, setMsg] = useState<string | null>(null)
  const pending = (approvals.data ?? []).filter(a => orgs.includes(a.org as Org))

  const act = async (fn: () => Promise<unknown>, ok: string) => {
    setMsg(null)
    try { await fn(); setMsg(ok); plans.reload(); approvals.reload() } catch (e) { setMsg(String((e as Error).message)) }
  }

  return (
    <section>
      <h2>Plans & approvals</h2>
      <p className="muted">Plans are proposed by the planner, re-checked by the independent critic, and executed only after human approval recorded on-chain (ApprovalGate). Execution is simulated.</p>
      {msg && <div className="state">{msg}</div>}
      <AdvisoryBox onDone={() => { plans.reload(); approvals.reload() }} />
      <State loading={plans.loading} error={plans.error} />
      <table>
        <thead><tr><th>Plan</th><th>Org</th><th>Steps</th><th>Org risk before → after</th><th>Critic</th><th /></tr></thead>
        <tbody>
          {(plans.data ?? []).map(p => {
            const req = pending.find(a => a.plan_id === p.plan_id)
            return (
              <tr key={p.plan_id}>
                <td className="clickable" onClick={() => setOpen(p.plan_id)}><b>{p.plan_id}</b></td>
                <td>{p.org}</td><td className="num">{p.steps}</td>
                <td className="num">{p.risk_before.toFixed(1)} → {p.risk_after.toFixed(1)}</td>
                <td>{p.critic?.verdict ?? '—'}</td>
                <td>{req ? <ApprovalActions rid={req.request_id} org={p.org as Org} planId={p.plan_id} act={act} /> : <span className="muted">no pending request</span>}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
      {plan.data && (
        <>
          <h3>{plan.data.plan_id}: predicted org risk {plan.data.risk_before.toFixed(2)} → {plan.data.risk_after.toFixed(2)}</h3>
          <table>
            <thead><tr><th>Step</th><th>Action</th><th>Asset</th><th>Impact class</th><th>Window</th><th>Risk change</th></tr></thead>
            <tbody>{plan.data.steps.map((s: PlanStep) => (
              <tr key={s.step_id}><td>{s.step_id}</td><td>{s.action}</td><td>{s.target_assets.join(', ')}</td><td><span className={`pill impact-${s.impact_class}`}>{s.impact_class}</span></td><td className="muted">{s.scheduled_window ?? '—'}</td><td className="num">{s.expected_risk_delta.toFixed(3)}</td></tr>
            ))}</tbody>
          </table>
        </>
      )}
    </section>
  )
}

function ApprovalActions({ rid, org, planId, act }: { rid: string; org: Org; planId: string; act: (fn: () => Promise<unknown>, ok: string) => void }) {
  const v = useLoad(() => api.approval(rid), [rid])
  if (!v.data) return <span className="muted">…</span>
  const d = v.data
  return (
    <div className="row left">
      <span className="pill">{d.status}</span>
      <span className="muted">{d.impact} · {d.approvals}/{d.required}{d.needs_safety_officer ? ' + safety officer' : ''}</span>
      {d.status === 'Pending' && [0, 1, 2].map(i => (
        <button key={i} onClick={() => act(() => api.approve(rid, org, i).then(v.reload), `Approver ${i} voted`)}>Approve as #{i}{i === 0 ? ' (safety)' : ''}</button>
      ))}
      {d.status === 'Approved' && <button className="primary" onClick={() => act(() => api.execute(planId), 'Executed; risk re-scored')}>Execute</button>}
    </div>
  )
}

function AdvisoryBox({ onDone }: { onDone: () => void }) {
  const [text, setText] = useState('')
  const [out, setOut] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    if (!text.trim()) { setOut('Paste an advisory first.'); return }
    setBusy(true)
    try {
      const r = await api.ingest(text)
      setOut(Object.entries(r).map(([o, p]) => `${o}: ${p.status}`).join(' · '))
      onDone()
    } catch (e) { setOut(String((e as Error).message)) } finally { setBusy(false) }
  }
  return (
    <details className="advisory">
      <summary>Ingest a new advisory</summary>
      <textarea rows={6} value={text} onChange={e => setText(e.target.value)} placeholder="Paste advisory text (CVE IDs, vendor, versions, CVSS)…" />
      <div className="row left"><button className="primary" disabled={busy} onClick={submit}>{busy ? 'Running the agents…' : 'Run pipeline'}</button>{out && <span className="muted">{out}</span>}</div>
    </details>
  )
}

// --------------------------------------------------------------- detections
function DetectionsView({ orgs }: { orgs: Org[] }) {
  const [org, setOrg] = useState<Org>(orgs[0])
  useEffect(() => { if (!orgs.includes(org)) setOrg(orgs[0]) }, [orgs, org])
  const d = useLoad(() => api.detections(org), [org])
  const rows = d.data ?? []
  const groups: [string, Detection[]][] = [['Active attack (telemetry rules D1–D6)', rows.filter(x => x.finding_type === 'active_attack')], ['Exposure (configuration)', rows.filter(x => x.finding_type === 'exposure')]]
  return (
    <section>
      <div className="row"><h2>Detections</h2><OrgTabs orgs={orgs} org={org} setOrg={setOrg} /></div>
      <p className="muted">Deterministic rules over simulated telemetry from the last 30 days; exposure and active-attack findings are never mixed. Rules D1, D2 and D5 are noisy by design (benign off-calendar activity looks similar); see the model card.</p>
      <State loading={d.loading} error={d.error} />
      {groups.map(([title, list]) => (
        <div key={title}>
          <h3>{title} · {list.length}</h3>
          {list.length === 0 ? <p className="muted">None.</p> : (
            <table>
              <thead><tr><th>Asset</th><th>Rule</th><th>Severity</th><th>Evidence</th><th>When</th></tr></thead>
              <tbody>{list.map((x, i) => <tr key={i}><td>{x.asset_id}</td><td>{x.rule}</td><td><span className={`pill sev-${x.severity}`}>{x.severity}</span></td><td>{x.evidence}</td><td className="muted">{x.event_time ?? '—'}</td></tr>)}</tbody>
            </table>
          )}
        </div>
      ))}
    </section>
  )
}

// --------------------------------------------------------------- audit/chain
function AuditView({ orgs }: { orgs: Org[] }) {
  const st = useLoad(() => api.chainStatus(), [])
  const ver = useLoad(() => Promise.all(orgs.map(o => api.auditVerify(o).then(v => [o, v] as const))), [orgs.join()])
  const ev = useLoad(() => api.events(40), [])
  return (
    <section>
      <h2>Audit & chain</h2>
      <State loading={st.loading} error={st.error} />
      {st.data && (
        <div className="kpis">
          <div className="kpi"><div className="kpi-label">Chain</div><div className="kpi-value">{st.data.connected ? `#${st.data.block}` : 'offline'}</div></div>
          <div className="kpi"><div className="kpi-label">Pending writes</div><div className="kpi-value">{st.data.pending_writes}</div></div>
          <div className="kpi"><div className="kpi-label">Kill switch</div><div className="kpi-value">{st.data.paused ? 'paused' : 'live'}</div></div>
          {(ver.data ?? []).map(([o, v]) => (
            <div className={`kpi ${v.ok ? 'kpi-low' : 'kpi-critical'}`} key={o}><div className="kpi-label">{o} audit log</div><div className="kpi-value">{v.ok ? 'verified' : `broken at #${v.first_mismatch}`}</div></div>
          ))}
        </div>
      )}
      {st.data && (
        <>
          <h3>Contracts</h3>
          <table><tbody>{Object.entries(st.data.contracts).map(([k, v]) => <tr key={k}><td>{k}</td><td className="mono">{v}</td></tr>)}</tbody></table>
        </>
      )}
      <h3>Latest on-chain events</h3>
      <p className="muted">What anyone with chain access sees: hashes, commitments and sealed ciphertext. No band, severity, dependency terms or finding outcome appears in the clear.</p>
      <table>
        <thead><tr><th>Block</th><th>Contract</th><th>Event</th><th>Fields</th></tr></thead>
        <tbody>{(ev.data ?? []).map((e, i) => <tr key={i}><td className="num">{e.block}</td><td>{e.contract}</td><td>{e.name}</td><td className="muted mono small">{Object.keys(e.args).join(', ')}</td></tr>)}</tbody>
      </table>
    </section>
  )
}

// --------------------------------------------------------------- model card
function ModelView() {
  const m = useLoad(() => api.model(), [])
  const c: ModelCard | null = m.data
  const ceil = c?.accuracy_ceiling as Record<string, { roc_auc: number; pr_auc: number }> | undefined
  return (
    <section>
      <h2>Model card</h2>
      <State loading={m.loading} error={m.error} />
      {c && (
        <>
          <p>M1 <span className="mono">{c.model_version}</span>: {c.estimator}, {c.calibration} calibration. Alert threshold {c.operating_threshold.value} ({c.operating_threshold.rule}). EPSS: {c.epss_source}. Labels: {c.labels}.</p>
          <h3>Held-out generator A</h3>
          <table>
            <thead><tr><th>Model</th><th>ROC-AUC</th><th>PR-AUC</th><th>Top-5 precision (25-asset slate)</th></tr></thead>
            <tbody>{Object.entries(c.held_out_A).map(([k, v]) => <tr key={k} className={k === 'M1' ? 'highlight' : ''}><td>{k}</td><td className="num">{v.roc_auc}</td><td className="num">{v.pr_auc}</td><td className="num">{v.top5_precision}</td></tr>)}</tbody>
          </table>
          <h3>Generator B (different label process, out-of-distribution)</h3>
          <table>
            <thead><tr><th>Model</th><th>ROC-AUC</th><th>PR-AUC</th></tr></thead>
            <tbody>{Object.entries(c.generator_B).map(([k, v]) => <tr key={k} className={k === 'M1' ? 'highlight' : ''}><td>{k}</td><td className="num">{v.roc_auc}</td><td className="num">{v.pr_auc}</td></tr>)}</tbody>
          </table>
          {ceil && (
            <>
              <h3>Accuracy ceiling</h3>
              <p>The best a model limited to observable data could reach on this simulation is ROC-AUC {ceil.O2_observable_oracle_plus_telemetry?.roc_auc}; M1 reaches {ceil.M1?.roc_auc}.</p>
            </>
          )}
          <h3>What is learned and what is not</h3>
          <ul>
            <li><b>Learned:</b> {c.learned.join(', ')}</li>
            <li><b>Deterministic:</b> {c.deterministic.join(', ')}</li>
            <li><b>Statistical:</b> {c.statistical.join(', ')}</li>
          </ul>
          <p className="note">All results are on simulated data with synthetic compromise labels; real-world accuracy is unknown until trained on real incident data. Band thresholds: low ≤ {c.band_thresholds.low_max}, medium ≤ {c.band_thresholds.medium_max}, high ≤ {c.band_thresholds.high_max}, critical above.</p>
        </>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------- app
export default function App() {
  const [role, setRoleState] = useState<Role>('admin')
  const [view, setView] = useState<View>('overview')
  const [picked, setPicked] = useState<{ org: Org; id: string } | null>(null)
  const health = useLoad(() => api.health(), [])
  const orgs = orgsFor(role)
  const changeRole = (r: Role) => { setRole(r); setRoleState(r); setPicked(null) }

  return (
    <div className="app">
      <header>
        <div>
          <h1>CascadeShield</h1>
          <div className="muted">Cross-organisation cyber-risk prediction · simulated data</div>
        </div>
        <div className="row left">
          <span className={`dot ${health.data?.chain_connected ? 'ok' : 'bad'}`} />
          <span className="muted">{health.error ? 'API offline' : health.data?.chain_connected ? 'chain connected' : 'connecting…'}</span>
          <select value={role} onChange={e => changeRole(e.target.value as Role)}>
            <option value="admin">Consortium admin</option>
            <option value="org:power">Power utility operator</option>
            <option value="org:water">Water board operator</option>
            <option value="org:hospital">Hospital operator</option>
          </select>
        </div>
      </header>
      <nav>{VIEWS.map(([k, label]) => <button key={k} className={view === k ? 'active' : ''} onClick={() => setView(k)}>{label}</button>)}</nav>
      {health.error && <div className="state error">Start the backend: <span className="mono">python scripts/serve.py --headline</span></div>}
      <main className={picked ? 'with-panel' : ''}>
        <div key={role}>
          {view === 'overview' && <Overview orgs={orgs} onPick={(org, id) => setPicked({ org, id })} />}
          {view === 'map' && <MapView orgs={orgs} />}
          {view === 'plans' && <PlansView orgs={orgs} />}
          {view === 'detections' && <DetectionsView orgs={orgs} />}
          {view === 'audit' && <AuditView orgs={orgs} />}
          {view === 'model' && <ModelView />}
        </div>
        {picked && <AssetPanel org={picked.org} id={picked.id} onClose={() => setPicked(null)} />}
      </main>
    </div>
  )
}

export type { Why }
