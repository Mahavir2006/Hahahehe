import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { CHART } from "@/components/viz"
import { Card, Tag } from "@/components/ui"
import { MODEL } from "@/data/derive"
import { modelInfo, useLive } from "@/data/live"


function RuleQuality() {
  const rules = Object.entries(modelInfo.raw?.rules_metrics?.rules ?? {}).map(([k, v]: [string, any]) => ({
    rule: k.split("_")[0].toUpperCase() + " " + k.split("_").slice(1).join(" "),
    Precision: +(v.precision * 100).toFixed(1),
    Recall: +(v.recall * 100).toFixed(1),
  }))
  const t = modelInfo.raw?.trend_metrics
  const back = t ? [{ name: "Holt trend (ours)", MAE: t.mae_days_holt }, { name: "Naive last value", MAE: t.mae_days_naive_last_value }] : []
  return (
    <div className="grid-2">
      <Card title="How good are the detection rules?" sub="Precision = alerts that were real · Recall = real attacks that were caught (simulated episodes)">
        <div className="chart-md">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={rules} margin={{ top: 8, right: 8, left: -14 }}>
              <CartesianGrid stroke={CHART.grid} vertical={false} />
              <XAxis dataKey="rule" stroke={CHART.axis} fontSize={10} interval={0} angle={-18} textAnchor="end" height={50} />
              <YAxis unit="%" domain={[0, 100]} stroke={CHART.axis} fontSize={11} />
              <Tooltip contentStyle={CHART.tooltip} formatter={(v) => `${v}%`} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Bar dataKey="Precision" fill="var(--accent)" isAnimationActive={false} />
              <Bar dataKey="Recall" fill="var(--ok)" isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div>
        <p className="muted small">{modelInfo.raw?.rules_metrics?.note}</p>
      </Card>
      <Card title="Can it forecast when risk crosses a band?" sub="Average error in days, lower is better (backtest on synthetic histories)">
        <div className="chart-md">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={back} layout="vertical" margin={{ left: 20, right: 24 }}>
              <XAxis type="number" unit=" d" stroke={CHART.axis} fontSize={11} />
              <YAxis type="category" dataKey="name" width={130} stroke={CHART.axis} fontSize={11} />
              <Tooltip contentStyle={CHART.tooltip} formatter={(v) => `${v} days`} />
              <Bar dataKey="MAE" fill="var(--warn)" radius={[0, 4, 4, 0]} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div>
        {t && (
          <p className="muted small">
            {t.histories} histories · missed crossings {t.holt_missed_crossings} · false alarms {t.holt_false_alarms_on_non_crossing}
          </p>
        )}
      </Card>
    </div>
  )
}

export default function Model() {
  useLive()
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
            <dd>{MODEL.features} features (live from /api/ps03/model/info): vulnerability severity, known exploitation, exposure, patch age, open management ports, remote access, firmware trust, detections, criticality, dependants</dd>
            <dt>Training data</dt>
            <dd>{MODEL.rows}</dd>
            <dt>Real data used</dt>
            <dd>{MODEL.realData}</dd>
            <dt>Labels</dt>
            <dd>
              <Tag tone="warn">{MODEL.labels}</Tag>
            </dd>
            <dt>Alert threshold</dt>
            <dd>{MODEL.threshold} (alert threshold from metrics.json)</dd>
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
              <strong>{Number.isFinite(m.value) ? m.value.toFixed(3) : "n/a"}</strong>
            </div>
          ))}
        </div>
      </Card>

      <RuleQuality />

      <div className="grid-2">
        <Card title="Honest limits">
          <ul className="list">
            <li>Compromise labels are synthetic; real incident data would be needed for production accuracy claims.</li>
            <li>Recall at the alert threshold is 0.41: the model flags the riskiest assets first rather than catching every incident, so detections and rules run alongside it.</li>
            <li>Risk is shown on a 0–100 scale (100 × likelihood × (0.3 + 0.7 × impact)); bands are Low ≤ {MODEL.bands.low}, Medium ≤ {MODEL.bands.medium}, High ≤ {MODEL.bands.high}, Critical above.</li>
            {MODEL.caveats.slice(0, 3).map((c) => (
              <li key={c}>{c}</li>
            ))}
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
