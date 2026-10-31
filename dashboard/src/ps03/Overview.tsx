import React from 'react'
import cytoscape from 'cytoscape'
import { api, post, Attention, Change, TREND_ARROW } from './api'
import { Band, ErrorBox, Tag, useLoad } from './common'

const BAND_COLOUR: Record<string, string> = { low: '#2e7d32', medium: '#f9a825', high: '#ef6c00', critical: '#c62828' }

export function AttentionTable({ data, onSelect }: { data: Attention; onSelect?: (id: string) => void }) {
  return (
    <table className="ps03-table">
      <thead>
        <tr>
          <th>#</th>
          <th>Asset</th>
          <th>Band</th>
          <th>Risk</th>
          <th>Likelihood</th>
          <th>Impact</th>
          <th>Trend</th>
          <th>Days high</th>
          <th>Top reason (SHAP, log-odds)</th>
          <th>Findings</th>
        </tr>
      </thead>
      <tbody>
        {data.items.map((x) => (
          <tr key={x.asset_id} onClick={() => onSelect && onSelect(x.asset_id)} className="clickable">
            <td>{x.rank}</td>
            <td>
              {x.name}
              <div className="muted">{x.asset_id}</div>
            </td>
            <td>
              <Band band={x.band} />
            </td>
            <td>{x.risk.toFixed(2)}</td>
            <td>{x.likelihood.toFixed(4)}</td>
            <td>{x.impact.toFixed(4)}</td>
            <td>{TREND_ARROW[x.trend] || x.trend}</td>
            <td>{x.days_at_high_risk}</td>
            <td>{x.top_reasons[0]}</td>
            <td>
              {Object.entries(x.finding_badges).map(([k, v]) => (
                <Tag key={k} text={`${k} ×${v}`} />
              ))}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export function ChangesList({ items }: { items: Change[] }) {
  if (!items.length) return <p className="muted">No changes yet. Advance the simulated clock.</p>
  return (
    <ul className="changes">
      {items.map((c, i) => (
        <li key={i}>
          <b>day {c.to_sim_day}</b> {c.asset_id}: <Band band={c.from_band} /> → <Band band={c.to_band} /> {c.text}
        </li>
      ))}
    </ul>
  )
}

function AssetGraph({ org, refresh }: { org: string; refresh: number }) {
  const ref = React.useRef<HTMLDivElement>(null)
  React.useEffect(() => {
    let cy: cytoscape.Core | null = null
    api<{ nodes: { id: string; band: string; risk: number }[]; edges: { from: string; to: string }[] }>(`/api/orgs/${org}/graph`)
      .then((g) => {
        if (!ref.current) return
        cy = cytoscape({
          container: ref.current,
          elements: [
            ...g.nodes.map((n) => ({ data: { id: n.id, label: `${n.id.replace(`${org}-asset-`, '')} ${n.band}`, band: n.band } })),
            ...g.edges.map((e, i) => ({ data: { id: `e${i}`, source: e.from, target: e.to } })),
          ],
          style: [
            { selector: 'node', style: { label: 'data(label)', 'font-size': 9, width: 18, height: 18, 'background-color': (n: any) => BAND_COLOUR[n.data('band')] || '#999' } },
            { selector: 'edge', style: { width: 1, 'line-color': '#bbb', 'target-arrow-shape': 'triangle', 'target-arrow-color': '#bbb', 'curve-style': 'bezier' } },
          ],
          layout: { name: 'cose', animate: false },
        })
      })
      .catch(() => undefined)
    return () => {
      if (cy) cy.destroy()
    }
  }, [org, refresh])
  return <div ref={ref} className="graph-box" aria-label="asset dependency graph (edge: asset depends on asset)" />
}

export default function Overview({ org, onSelect }: { org: string; onSelect: (id: string) => void }) {
  const [refresh, setRefresh] = React.useState(0)
  const [busy, setBusy] = React.useState(false)
  const [msg, setMsg] = React.useState<string | null>(null)
  const [actionError, setActionError] = React.useState<string | null>(null)
  const [att, err] = useLoad(() => api<Attention>(`/api/ps03/orgs/${org}/attention?limit=25`), [org, refresh])
  const [changes] = useLoad(() => api<{ items: Change[] }>(`/api/ps03/orgs/${org}/changes?since_day=-1`), [org, refresh])

  const run = async (fn: () => Promise<any>, label: string) => {
    setBusy(true)
    setActionError(null)
    try {
      const r = await fn()
      setMsg(`${label}: ${r.note || `day ${r.from_day} → ${r.to_day}, ${(r.changes || []).length} changes, ${(r.events_applied || []).length} scripted events`}`)
      setRefresh((x) => x + 1)
    } catch (e: any) {
      setActionError(String(e.message || e))
    }
    setBusy(false)
  }

  return (
    <div>
      <div className="toolbar">
        <button disabled={busy} onClick={() => run(() => post('/api/ps03/sim/advance', { days: 7, scenario: 'demo_week' }), 'Advanced 7 days')}>
          Advance 7 days (demo week)
        </button>
        <button disabled={busy} onClick={() => run(() => post('/api/ps03/sim/advance', { days: 7 }), 'Advanced 7 days')}>
          Advance 7 days (no events)
        </button>
        <button disabled={busy} onClick={() => run(() => post('/api/ps03/sim/reset'), 'Reset')}>
          Reset
        </button>
        {msg && <span className="muted">{msg}</span>}
      </div>
      <ErrorBox error={err || actionError} />
      {att && (
        <>
          <p>
            Simulated day <b>{att.sim_day}</b> · aggregate risk <b>{(att.aggregate_bp / 100).toFixed(2)}</b> · model {att.model_source}{' '}
            <code>{att.model_version}</code>
          </p>
          <div className="two-col">
            <section className="panel">
              <h3>Needs attention (ranked by risk)</h3>
              <AttentionTable data={att} onSelect={onSelect} />
            </section>
            <section className="panel">
              <h3>Asset graph (colour and label = band)</h3>
              <AssetGraph org={org} refresh={refresh} />
            </section>
          </div>
        </>
      )}
      <section className="panel">
        <h3>What changed</h3>
        <ChangesList items={(changes?.items || []).slice().reverse().slice(0, 40)} />
        <p className="muted">Reset rewinds the simulated clock and in-memory state only; on-chain attestations and audit anchors are append-only.</p>
      </section>
    </div>
  )
}
