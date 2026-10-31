import React from 'react'
import { api, post } from './api'
import { ErrorBox, SimBanner, useLoad } from './common'

export default function Plans({ org }: { org: string }) {
  const [tick, setTick] = React.useState(0)
  const [err, setErr] = React.useState<string | null>(null)
  const [out, setOut] = React.useState<any>(null)
  const [asset, setAsset] = React.useState(`${org}-asset-004`)
  const [plans, e1] = useLoad(() => api<any[]>('/api/plans'), [tick])
  const [approvals, e2] = useLoad(() => api<any[]>('/api/approvals'), [tick])
  const [levels] = useLoad(() => api<any>('/api/ps03/containment/levels'), [])
  const [verify] = useLoad(() => api<any>(`/api/ps03/containment/verify?org=${org}`), [org, tick])

  const act = async (fn: () => Promise<any>) => {
    setErr(null)
    try {
      setOut(await fn())
    } catch (e: any) {
      setErr(String(e.message || e))
    }
    setTick((t) => t + 1)
  }
  const approveAll = async (rid: string, o: string) => {
    let last = null
    for (let i = 0; i < 3; i++) {
      const v = await api<any>(`/api/approvals/${rid}`)
      if (v.status !== 'Pending') break
      last = await post(`/api/approvals/${rid}/approve`, { org: o, approver: i })
    }
    return last
  }

  return (
    <div>
      <SimBanner />
      <ErrorBox error={err || e1 || e2} />
      <section className="panel">
        <h3>Containment level 2 (quarantine asset), simulation only</h3>
        <p>
          Asset <input value={asset} onChange={(e) => setAsset(e.target.value)} />{' '}
          <button onClick={() => act(() => post('/api/ps03/containment/precheck', { org, actions: [{ action: 'ISOLATE_ASSET', targets: [asset] }] }))}>Pre-check</button>{' '}
          <button onClick={() => act(() => post('/api/ps03/containment/level2', { org, asset_id: asset }))}>Build level-2 plan</button>
        </p>
        {levels && (
          <ul>
            {Object.entries(levels.levels).map(([k, v]: any) => (
              <li key={k}>
                <b>
                  Level {k}: {v.name}
                </b>{' '}
                ({v.actions.join(', ')}) · trigger: {v.trigger} · {v.implemented}
              </li>
            ))}
          </ul>
        )}
        {verify && (
          <p>
            Verification: isolated {verify.isolated_assets.join(', ') || 'none'} · blocked edges {verify.blocked_edges.length} · allowed paths retained{' '}
            {verify.retained_allowed_paths.length}, lost {verify.lost_allowed_paths.length}
          </p>
        )}
      </section>
      {out && <pre className="pre">{JSON.stringify(out, null, 1).slice(0, 4000)}</pre>}
      <section className="panel">
        <h3>Approvals pending ({(approvals || []).length})</h3>
        <table className="ps03-table">
          <tbody>
            {(approvals || []).map((a) => (
              <tr key={a.request_id}>
                <td>{a.org}</td>
                <td>{a.plan_id}</td>
                <td>impact {a.impact}</td>
                <td>
                  <button onClick={() => act(() => approveAll(a.request_id, a.org))}>Approve (3 approvers)</button>{' '}
                  <button onClick={() => act(() => post(`/api/approvals/${a.request_id}/reject`, { org: a.org, approver: 0 }))}>Reject</button>{' '}
                  <button onClick={() => act(() => post(`/api/plans/${a.plan_id}/execute`, { request_id: a.request_id }))}>Execute</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <section className="panel">
        <h3>Plans ({(plans || []).length})</h3>
        <table className="ps03-table">
          <thead>
            <tr>
              <th>Org</th>
              <th>Plan</th>
              <th>Steps</th>
              <th>Risk before → after</th>
              <th>Critic</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {(plans || []).map((p) => (
              <tr key={p.plan_id}>
                <td>{p.org}</td>
                <td>{p.plan_id}</td>
                <td>{p.steps}</td>
                <td>
                  {p.risk_before} → {p.risk_after}
                </td>
                <td>{p.critic ? p.critic.verdict : 'not approved for gate'}</td>
                <td>
                  <button onClick={() => act(() => post(`/api/plans/${p.plan_id}/rollback`))}>Rollback</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  )
}
