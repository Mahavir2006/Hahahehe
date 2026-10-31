import { api } from './api'
import { Band, ErrorBox, Tag, useLoad } from './common'

function FindingTable({ items }: { items: any[] }) {
  if (!items.length) return <p className="muted">None.</p>
  return (
    <table className="ps03-table">
      <thead>
        <tr>
          <th>Day</th>
          <th>Asset</th>
          <th>Rule</th>
          <th>Severity</th>
          <th>Confidence (heuristic)</th>
          <th>Method</th>
          <th>Evidence</th>
          <th>Source</th>
        </tr>
      </thead>
      <tbody>
        {items.map((f) => (
          <tr key={f.finding_id}>
            <td>{f.sim_day}</td>
            <td>{f.asset_id}</td>
            <td>{f.rule_id}</td>
            <td>
              <Band band={f.severity} />
            </td>
            <td>{f.confidence}</td>
            <td>{f.detection_method}</td>
            <td>{f.evidence.join('; ')}</td>
            <td>
              <Tag text={f.source} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export function DetectionsView({ d }: { d: { note: string; exposure: any[]; active_attack: any[] } }) {
  return (
    <div>
      <p className="muted">{d.note}</p>
      <section className="panel">
        <h3>Active attack (rules over simulated telemetry): {d.active_attack.length}</h3>
        <FindingTable items={d.active_attack} />
      </section>
      <section className="panel">
        <h3>Exposure (asset state: advisory-derived or simulated inventory): {d.exposure.length}</h3>
        <FindingTable items={d.exposure} />
      </section>
    </div>
  )
}

export default function Detections({ org }: { org: string }) {
  const [d, err] = useLoad(() => api(`/api/ps03/detections?org=${org}`), [org])
  return (
    <div>
      <ErrorBox error={err} />
      {d && <DetectionsView d={d} />}
    </div>
  )
}
