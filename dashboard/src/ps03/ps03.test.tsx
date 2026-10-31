// Render tests (no DOM library installed: server-side render to static markup under Vitest's node environment).
import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import Shell, { TABS } from './Shell'
import { AttentionTable, ChangesList } from './Overview'
import { WhyView } from './AssetDetail'
import { DetectionsView } from './Detections'
import { ModelCardView } from './ModelCard'
import { Band } from './common'

const attention = {
  org: 'power', sim_day: 2, banner: 'x', aggregate_bp: 5000, model_version: 'v', model_source: 'v1',
  items: [{ rank: 1, asset_id: 'power-asset-001', name: 'Substation Gateway', risk: 67.5, risk_bp: 6750, band: 'high', likelihood: 0.8, impact: 0.7,
    trend: 'rising', days_at_high_risk: 1, top_reasons: ['Exploit likelihood (EPSS-like) = 0.86592: +2.100 log-odds'],
    finding_badges: { 'exposure:high': 1 }, source_tags: ['real_snapshot'] }],
}

const why = {
  asset: { asset_id: 'power-asset-001', name: 'Substation Gateway' },
  vulnerabilities: [{ cve: 'CVE-2026-24858', cvss: 9.8, epss: 0.86592, exploited: true, source: 'real_snapshot', match: 'scenario', epss_time_matched: false }],
  scores: { likelihood: 0.8, impact: 0.7, risk: 67.5, band: 'high', likelihood_bp: 8000, impact_bp: 7000, risk_bp: 6320, band_bp: 'high', formula: 'f' },
  shap: { unit: 'log_odds', base_value: -1.2, factors: [{ feature: 'epss_like', label: 'Exploit likelihood (EPSS-like)', value: 0.86, contribution_logodds: 2.1 }] },
  share_of_risk_bar: { label: 'share of risk (not SHAP)', unit: 'u', items: [{ feature: 'epss_like', text: 'Exploit likelihood: +30' }] },
  dependency_path: { depends_on: ['power-asset-002'], dependents_transitive: [], required_by_services: [] },
  cascade_assumptions: { EDGE_WEIGHT: 0.6 },
  freshness: { sim_day: 2, epss_asof: '2026-10-30', snapshot_commit: '3c2594d3df', model_source: 'v1', model_version: 'v' },
  findings: [], recommended_actions: [{ action: 'PATCH', level: null, asset_risk_before: 67.5, asset_risk_after: 3.9, org_risk_before: 50, org_risk_after: 20, why: 'w' }],
  missing: [], source_tags: ['real_snapshot'],
}

describe('PS-03 dashboard', () => {
  it('shows the simulation banner and every tab, including the original Pipeline page', () => {
    const html = renderToStaticMarkup(<Shell pipeline={<p>pipeline page</p>} />)
    expect(html).toContain('Simulation only. No commands are sent to real OT equipment.')
    for (const t of TABS) expect(html).toContain(`>${t}<`)
  })

  it('renders bands as text, not colour alone', () => {
    expect(renderToStaticMarkup(<Band band="critical" />)).toContain('CRITICAL')
  })

  it('renders the attention table with band text, trend and reason', () => {
    const html = renderToStaticMarkup(<AttentionTable data={attention} />)
    expect(html).toContain('Substation Gateway')
    expect(html).toContain('HIGH')
    expect(html).toContain('↑ rising')
    expect(html).toContain('+2.100 log-odds')
  })

  it('renders what changed', () => {
    const html = renderToStaticMarkup(
      <ChangesList items={[{ org: 'power', asset_id: 'a', from_risk_bp: 2840, to_risk_bp: 6750, from_band: 'medium', to_band: 'high', to_sim_day: 2, text: 'risk 28.4 to 67.5', reasons: [] }]} />,
    )
    expect(html).toContain('risk 28.4 to 67.5')
  })

  it('renders the why panel with separate scores, SHAP, labelled share-of-risk and source tags', () => {
    const html = renderToStaticMarkup(<WhyView w={why} />)
    for (const s of ['Likelihood (model)', 'Impact (rule)', '6320 bp', 'log_odds', 'share of risk (not SHAP)', 'real_snapshot', 'EPSS not time-matched', 'KEV: known exploited', '67.50 → 3.90'])
      expect(html).toContain(s)
  })

  it('separates exposure and active-attack findings', () => {
    const f = (t: string) => ({ finding_id: t, finding_type: t, sim_day: 1, asset_id: 'a', rule_id: 'R', severity: 'high', confidence: 0.75, detection_method: 'm', evidence: ['e'], source: 'telemetry' })
    const html = renderToStaticMarkup(<DetectionsView d={{ note: 'n', exposure: [f('exposure')], active_attack: [f('active_attack')] }} />)
    expect(html).toContain('Active attack')
    expect(html).toContain('Exposure')
  })

  it('model card shows a fail-closed load error and caveats', () => {
    const html = renderToStaticMarkup(<ModelCardView m={{ source: 'v2', error: 'sha256 mismatch', caveats: ['labels are simulated; results are on simulated data'] }} />)
    expect(html).toContain('fail closed')
    expect(html).toContain('labels are simulated')
  })
})
