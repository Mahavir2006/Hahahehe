import { Card, Tag } from "@/components/ui"
import { MODEL } from "@/data/derive"

export default function Model() {
  return (
    <div className="page">
      <div className="grid-2">
        <Card title={`Risk model ${MODEL.name}`} sub={`version ${MODEL.version}`}>
          <dl className="kv">
            <dt>Algorithm</dt>
            <dd>{MODEL.estimator}</dd>
            <dt>Calibration</dt>
            <dd>{MODEL.calibration}</dd>
            <dt>Explanation</dt>
            <dd>{MODEL.explain}</dd>
            <dt>Inputs</dt>
            <dd>{MODEL.features} features: vulnerability severity, known exploitation, exposure, patch age, open management ports, remote access, firmware trust, detections, criticality, dependants</dd>
            <dt>Training data</dt>
            <dd>{MODEL.rows}</dd>
            <dt>Real data used</dt>
            <dd>{MODEL.realData}</dd>
            <dt>Labels</dt>
            <dd>
              <Tag tone="warn">{MODEL.labels}</Tag>
            </dd>
            <dt>Alert threshold</dt>
            <dd>{MODEL.threshold} (chosen to maximise F1, fixed before testing)</dd>
          </dl>
        </Card>

        <Card title="Does it beat simpler methods?" sub="ROC-AUC on held-out assets (higher is better)">
          <ul className="bars">
            {MODEL.baselines.map((b) => (
              <li key={b.name} className={b.ours ? "ours" : ""}>
                <span>{b.name}</span>
                <i style={{ width: `${((b.auc - 0.5) / 0.3) * 100}%` }} />
                <b>{b.auc.toFixed(3)}</b>
              </li>
            ))}
            <li className="ceiling">
              <span>Best possible on this data</span>
              <i style={{ width: `${((MODEL.ceiling.auc - 0.5) / 0.3) * 100}%` }} />
              <b>{MODEL.ceiling.auc.toFixed(3)}</b>
            </li>
          </ul>
          <p className="small">
            M1 reaches <b>{(MODEL.ceiling.share * 100).toFixed(1)}%</b> of the best achievable score, clearly beats CVSS-only and KEV-only ranking, and ties logistic regression while adding monotonic, explainable factors.
          </p>
        </Card>
      </div>

      <Card title="Test results" sub="All measured by the evaluation scripts on simulated data">
        <div className="grid-stats four">
          {MODEL.metrics.map((m) => (
            <div className="stat" key={m.label}>
              <span>{m.label}</span>
              <strong>{m.value.toFixed(3)}</strong>
            </div>
          ))}
        </div>
      </Card>

      <div className="grid-2">
        <Card title="Honest limits">
          <ul className="list">
            <li>Compromise labels are synthetic; real incident data would be needed for production accuracy claims.</li>
            <li>Recall at the alert threshold is 0.41: the model flags the riskiest assets first rather than catching every incident, so detections and rules run alongside it.</li>
            <li>Dashboard scores are on a 0–100 display scale for the demo; the model's own bands are Low &lt; {MODEL.bands.low}, Medium &lt; {MODEL.bands.medium}, High &lt; {MODEL.bands.high}, Critical above.</li>
          </ul>
        </Card>
        <Card title="Safeguards">
          <ul className="list">
            <li>Model file is checked by hash on load and fails closed if it changed.</li>
            <li>Monotonic constraints: more exposure or a known exploit can never lower risk.</li>
            <li>Leakage test, drift checks (PSI / KS), grouped bootstrap confidence intervals and a second data generator.</li>
          </ul>
        </Card>
      </div>
    </div>
  )
}
