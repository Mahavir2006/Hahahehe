import { api } from './api'
import { Band, ErrorBox, Tag, useLoad } from './common'

export function WhyView({ w }: { w: any }) {
  const sc = w.scores
  const maxShap = Math.max(1e-9, ...w.shap.factors.map((f: any) => Math.abs(f.contribution_logodds ?? f.contribution ?? 0)))
  return (
    <div>
      <h3>
        {w.asset.name} <span className="muted">{w.asset.asset_id}</span> <Band band={sc.band_bp} />
      </h3>
      <div className="score-row">
        <div className="score-card">
          <div className="muted">Likelihood (model)</div>
          <b>{sc.likelihood.toFixed(4)}</b>
          <div className="muted">{sc.likelihood_bp} bp</div>
        </div>
        <div className="score-card">
          <div className="muted">Impact (rule)</div>
          <b>{sc.impact.toFixed(4)}</b>
          <div className="muted">{sc.impact_bp} bp</div>
        </div>
        <div className="score-card">
          <div className="muted">Risk</div>
          <b>{(sc.risk_bp / 100).toFixed(2)}</b>
          <div className="muted">{sc.risk_bp} bp</div>
        </div>
      </div>
      <p className="muted">{sc.formula}</p>

      <h4>Why: SHAP contributions ({w.shap.unit}, base value {w.shap.base_value === null ? 'n/a' : w.shap.base_value.toFixed(3)})</h4>
      <table className="ps03-table">
        <tbody>
          {w.shap.factors.map((f: any) => {
            const v = f.contribution_logodds ?? f.contribution
            return (
              <tr key={f.feature}>
                <td>{f.label}</td>
                <td>{String(f.value)}</td>
                <td className="bar-cell">
                  <span className={`bar ${v >= 0 ? 'pos' : 'neg'}`} style={{ width: `${(Math.abs(v) / maxShap) * 100}%` }} />
                </td>
                <td>
                  {v >= 0 ? '+' : ''}
                  {v.toFixed(3)}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
      <h4>{w.share_of_risk_bar.label}</h4>
      <p className="muted">{w.share_of_risk_bar.unit}</p>
      <ul>
        {w.share_of_risk_bar.items.map((f: any) => (
          <li key={f.feature}>{f.text}</li>
        ))}
      </ul>

      <h4>Vulnerabilities</h4>
      {w.vulnerabilities.length === 0 && <p className="muted">No open vulnerabilities (has_vulnerability = 0).</p>}
      <table className="ps03-table">
        <tbody>
          {w.vulnerabilities.map((v: any) => (
            <tr key={v.cve}>
              <td>{v.cve}</td>
              <td>CVSS {v.cvss ?? 'n/a'}</td>
              <td>
                EPSS {v.epss}
                {v.epss_missing ? ' (fallback)' : ''}
              </td>
              <td>{v.exploited ? 'KEV: known exploited' : 'not on KEV'}</td>
              <td>
                <Tag text={v.source || 'advisory'} /> {v.match && <Tag text={`match: ${v.match}`} />}{' '}
                {v.epss_time_matched === false && <Tag text="EPSS not time-matched" />} {v.version_match && <Tag text={`version: ${v.version_match}`} />}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h4>Recommended actions (what-if, same model)</h4>
      <table className="ps03-table">
        <thead>
          <tr>
            <th>Action</th>
            <th>Level</th>
            <th>Asset risk before → after</th>
            <th>Org risk before → after</th>
            <th>Why</th>
          </tr>
        </thead>
        <tbody>
          {w.recommended_actions.map((a: any) => (
            <tr key={a.action}>
              <td>{a.action}</td>
              <td>{a.level ?? '-'}</td>
              <td>
                {a.asset_risk_before.toFixed(2)} → {a.asset_risk_after.toFixed(2)}
              </td>
              <td>
                {a.org_risk_before.toFixed(2)} → {a.org_risk_after.toFixed(2)}
              </td>
              <td>{a.why}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h4>Dependency path</h4>
      <p>
        Depends on: {w.dependency_path.depends_on.join(', ') || 'none'} · Dependents (transitive): {w.dependency_path.dependents_transitive.length} · Services:{' '}
        {w.dependency_path.required_by_services.map((s: any) => `${s.name} (${s.criticality})`).join(', ') || 'none'}
      </p>
      <h4>Cascade assumptions (hand-set, not learned)</h4>
      <pre className="pre">{JSON.stringify(w.cascade_assumptions, null, 1)}</pre>
      <h4>Freshness and sources</h4>
      <p>
        Sim day {w.freshness.sim_day} · EPSS as of {w.freshness.epss_asof} (time-matched: no) · CSAF snapshot <code>{String(w.freshness.snapshot_commit).slice(0, 10)}</code> · model{' '}
        {w.freshness.model_source} <code>{w.freshness.model_version}</code> · tags: {w.source_tags.map((t: string) => <Tag key={t} text={t} />)}
      </p>
      <h4>Findings ({w.findings.length})</h4>
      <ul>
        {w.findings.slice(0, 15).map((f: any) => (
          <li key={f.finding_id}>
            day {f.sim_day} <Tag text={f.finding_type} /> {f.rule_id} <Band band={f.severity} /> conf {f.confidence} · {f.evidence.join('; ')}
          </li>
        ))}
      </ul>
    </div>
  )
}

export default function AssetDetail({ org, assetId }: { org: string; assetId: string | null }) {
  const [w, err] = useLoad(() => (assetId ? api(`/api/ps03/orgs/${org}/assets/${assetId}/why`) : Promise.resolve(null)), [org, assetId])
  if (!assetId) return <p className="muted">Pick an asset in the Overview table.</p>
  return (
    <section className="panel">
      <ErrorBox error={err} />
      {w && <WhyView w={w} />}
    </section>
  )
}
