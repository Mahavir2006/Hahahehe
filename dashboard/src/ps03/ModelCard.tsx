import { api } from './api'
import { ErrorBox, useLoad } from './common'

export function ModelCardView({ m }: { m: any }) {
  const rules = m.rules_metrics?.rules || {}
  return (
    <div>
      {m.error && <div className="error-box">Model failed to load (fail closed): {m.error}</div>}
      <section className="panel">
        <h3>Risk model</h3>
        <p>
          Source <b>{m.source}</b> · version <code>{m.model_version}</code> · SHAP: {m.shap}
        </p>
        <p>Features: {(m.features || []).join(', ')}</p>
        <pre className="pre">{JSON.stringify(m.metadata?.metrics ?? m.metrics, null, 1)}</pre>
      </section>
      <section className="panel">
        <h3>Detection rules (simulated telemetry)</h3>
        <table className="ps03-table">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Precision</th>
              <th>Recall</th>
              <th>TP</th>
              <th>FP (maintenance)</th>
              <th>FP (other)</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(rules).map(([k, r]: any) => (
              <tr key={k}>
                <td>{k}</td>
                <td>{r.precision ?? 'n/a'}</td>
                <td>{r.recall ?? 'n/a'}</td>
                <td>{r.tp}</td>
                <td>{r.fp_maintenance}</td>
                <td>{r.fp_other}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <section className="panel">
        <h3>Trend (statistical, not ML)</h3>
        <pre className="pre">{JSON.stringify(m.trend_metrics, null, 1)}</pre>
      </section>
      <section className="panel">
        <h3>Caveats</h3>
        <ul>
          {(m.caveats || []).map((c: string) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
      </section>
    </div>
  )
}

export default function ModelCard() {
  const [m, err] = useLoad(() => api('/api/ps03/model/info'), [])
  return (
    <div>
      <ErrorBox error={err} />
      {m && <ModelCardView m={m} />}
    </div>
  )
}
