import { lazy, Suspense, useState } from "react"
import { useNav } from "@/app/nav"
import { Card, Level, Skeleton, Sparkline, Tag } from "@/components/ui"
import { cascadeChain, levelColor, predict, ranked, sectorOf, THRESHOLDS } from "@/data/derive"

const ModelEvidence = lazy(() => import("./Model"))

export default function RiskAnalysis() {
  const [view, setView] = useState<"asset" | "model">("asset")
  const { openAsset, focusAsset } = useNav()
  const [id, setId] = useState(focusAsset ?? ranked[0].id)
  const a = ranked.find((x) => x.id === id)!
  const p = predict(a.id)
  const base = 25 // average likelihood before asset-specific factors (illustrative)
  const max = Math.max(...p.shapFactors.map((f) => Math.abs(f.bpDelta)))

  if (view === "model")
    return (
      <div className="page">
        <ViewTabs view={view} setView={setView} />
        <Suspense fallback={<Skeleton h={420} />}>
          <ModelEvidence />
        </Suspense>
      </div>
    )

  return (
    <div className="page">
      <ViewTabs view={view} setView={setView} />
      <Card title="How a risk score is made" sub="Risk = compromise likelihood (AI model) × operational impact (criticality and dependants)">
        <div className="formula">
          <div>
            <span>Likelihood</span>
            <strong>{a.likelihood}%</strong>
            <small>M1 model, calibrated probability of compromise in the window</small>
          </div>
          <b>×</b>
          <div>
            <span>Impact</span>
            <strong>{a.impact}%</strong>
            <small>asset criticality, life-safety and downstream services</small>
          </div>
          <b>=</b>
          <div>
            <span>Risk</span>
            <strong style={{ color: levelColor[a.level] }}>{a.risk.toFixed(1)}</strong>
            <Level level={a.level} />
          </div>
        </div>
        <p className="muted small">
          Bands: Critical ≥ {THRESHOLDS.critical} · High ≥ {THRESHOLDS.high} · Medium ≥ {THRESHOLDS.medium} · otherwise Low. A band only moves when the score clears the boundary by a margin (hysteresis), so alerts don't flap.
        </p>
      </Card>

      <div className="grid-side">
        <Card title="Pick an asset" sub="Highest risk first">
          <ul className="picker" role="listbox" aria-label="Assets">
            {ranked.map((x) => (
              <li key={x.id}>
                <button role="option" aria-selected={x.id === id} className={x.id === id ? "active" : ""} onClick={() => setId(x.id)}>
                  <span style={{ color: sectorOf[x.org].color }}>{x.id}</span>
                  <small>{x.name}</small>
                  <b style={{ color: levelColor[x.level] }}>{x.risk.toFixed(1)}</b>
                </button>
              </li>
            ))}
          </ul>
        </Card>

        <div className="stack">
          <Card title={`Why ${a.id} is ${a.level.toLowerCase()} risk`} sub="SHAP explanation: how much each factor moves the score (points)">
            <div className="waterfall">
              <div className="wf-row base">
                <span>Typical asset</span>
                <i style={{ width: `${base}%` }} />
                <b>{base}</b>
              </div>
              {p.shapFactors.map((f) => (
                <div key={f.feature} className="wf-row">
                  <span>{f.feature}</span>
                  <i className={f.bpDelta > 0 ? "up" : "down"} style={{ width: `${(Math.abs(f.bpDelta) / max) * 60}%` }} />
                  <b className={f.bpDelta > 0 ? "up" : "down"}>
                    {f.bpDelta > 0 ? "+" : "−"}
                    {(Math.abs(f.bpDelta) / 100).toFixed(1)}
                  </b>
                </div>
              ))}
            </div>
            {p.missingDataIndicator && <p className="note">Data gap handled: {p.missingDataIndicator}</p>}
            <div className="evidence">
              <Tag tone={p.vulnData.kevBadge ? "danger" : "neutral"}>{p.vulnData.kevBadge ? "CISA KEV: actively exploited" : "Not in KEV"}</Tag>
              <Tag>CVSS {p.vulnData.cvss.toFixed(1)}</Tag>
              <Tag>EPSS {(p.vulnData.epss * 100).toFixed(1)}%</Tag>
              <Tag>{p.vulnData.patchAgeDays} days unpatched</Tag>
              <Tag tone="info">{p.vulnData.source}</Tag>
              {p.protectedLifeCritical && <Tag tone="warn">Life-critical service downstream</Tag>}
            </div>
          </Card>

          <div className="grid-2">
            <Card title="Trend & forecast" sub="Holt trend on recent scores">
              <div className="trend">
                <Sparkline data={p.sparkline} color={levelColor[a.level]} w={220} h={60} />
                <p>
                  Rising — expected to reach the next band in <b>~{p.holtForecastDays.toFixed(1)} days</b> without action.
                </p>
              </div>
            </Card>
            <Card title="Consequence if compromised" sub="Cross-organisation cascade">
              <ul className="chips">
                {cascadeChain(a.id).map((c) => (
                  <li key={c.asset.id} style={{ borderColor: sectorOf[c.asset.org].color }}>
                    {c.asset.id} <small>{sectorOf[c.asset.org].label}</small>
                  </li>
                ))}
                {!cascadeChain(a.id).length && <li>None identified</li>}
              </ul>
              <button className="btn full" onClick={() => openAsset(a.id)}>
                See fixes and risk after
              </button>
            </Card>
          </div>
        </div>
      </div>
    </div>
  )
}

function ViewTabs({ view, setView }: { view: "asset" | "model"; setView: (v: "asset" | "model") => void }) {
  return (
    <div className="seg" role="tablist" aria-label="Risk prediction views">
      <button role="tab" aria-selected={view === "asset"} className={view === "asset" ? "active" : ""} onClick={() => setView("asset")}>
        Explain an asset
      </button>
      <button role="tab" aria-selected={view === "model"} className={view === "model" ? "active" : ""} onClick={() => setView("model")}>
        Model & evidence
      </button>
    </div>
  )
}
