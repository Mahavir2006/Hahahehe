import { ArrowRight, Globe2 } from "lucide-react"
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { useNav } from "@/app/nav"
import { RiskMap } from "@/components/RiskMap"
import { Card, Level, RiskBar, Stat, Tag } from "@/components/ui"
import { actionsFor, cascadeChain, LEVELS, levelColor, orgRisk, portfolio, predict, ranked, riskAfter, riskTimelineData, sectorOf, THRESHOLDS, whatChangedFeed, isInternet } from "@/data/derive"

export default function Dashboard() {
  const { openAsset, go, focusAsset } = useNav()
  const top = ranked.slice(0, 6)
  const head = ranked[0]
  const headChain = cascadeChain(head.id)

  return (
    <div className="page">
      <div className="grid-stats">
        <Stat label="Portfolio risk (avg)" value={portfolio.avgRisk.toFixed(1)} hint={`${portfolio.total} monitored assets`} tone="#f0a04b" />
        <Stat label="Need urgent attention" value={portfolio.urgent} hint={`High or Critical band (risk > ${THRESHOLDS.high.toFixed(1)})`} tone="#ef5b5b" />
        <Stat label="Known-exploited CVEs" value={portfolio.kev} hint="listed in CISA KEV" tone="#ef5b5b" />
        <Stat label="Internet-facing assets" value={portfolio.internet} hint={`${portfolio.unpatched} assets with open vulnerabilities`} tone="#e3c55a" />
        <Stat label="Can trigger a cascade" value={portfolio.cascadeSources} hint="reach 2+ downstream assets" tone="#38bdf8" />
      </div>

      <div className="grid-main">
        <Card title="Needs attention now" sub="Ranked by AI risk score — click a row for the full explanation" action={<button className="btn btn-ghost" onClick={() => go("assets")}>All assets <ArrowRight size={14} /></button>}>
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Asset</th>
                  <th>Risk</th>
                  <th className="hide-sm">Main reason</th>
                  <th className="hide-sm">Top fix</th>
                </tr>
              </thead>
              <tbody>
                {top.map((a, i) => {
                  const fix = actionsFor(a)[0]
                  const after = fix ? riskAfter(a, [fix]) : a.risk
                  const why = predict(a.id).shapFactors[0]
                  return (
                    <tr key={a.id} tabIndex={0} onClick={() => openAsset(a.id)} onKeyDown={(e) => e.key === "Enter" && openAsset(a.id)}>
                      <td className="rank">{i + 1}</td>
                      <td>
                        <strong>
                          {a.id} {isInternet(a) && <Globe2 size={12} className="warn-ic" aria-label="internet-facing" />}
                        </strong>
                        <small style={{ color: sectorOf[a.org].color }}>
                          {sectorOf[a.org].label} · {a.name}
                        </small>
                      </td>
                      <td>
                        <div className="risk-cell">
                          <b style={{ color: levelColor[a.level] }}>{a.risk.toFixed(1)}</b>
                          <Level level={a.level} />
                        </div>
                        <RiskBar value={a.risk} level={a.level} />
                      </td>
                      <td className="hide-sm">{why?.feature ?? "—"}</td>
                      <td className="hide-sm">
                        {fix ? (
                          <>
                            {fix.title}
                            <small className="ok">
                              → {after.toFixed(1)} (−{Math.round(fix.reduction * 100)}%)
                            </small>
                          </>
                        ) : (
                          "No action needed"
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Card>

        <Card title="Infrastructure map" sub="Hover or select an asset to see its cascade" action={<button className="btn btn-ghost" onClick={() => go("map")}>Open map <ArrowRight size={14} /></button>}>
          <RiskMap compact selected={focusAsset ?? head.id} onSelect={openAsset} />
        </Card>
      </div>

      <div className="grid-3">
        <Card title="Risk distribution" sub="Assets per band">
          <div className="dist">
            {LEVELS.map((l) => (
              <div key={l}>
                <span>
                  <Level level={l} />
                </span>
                <div className="dist-bar">
                  <i style={{ width: `${(portfolio.byLevel[l] / portfolio.total) * 100}%`, background: levelColor[l] }} />
                </div>
                <b>{portfolio.byLevel[l]}</b>
              </div>
            ))}
          </div>
          <div className="orgs">
            {orgRisk.map((o) => (
              <div key={o.code}>
                <i style={{ background: o.sector.color }} />
                <span>
                  <strong>{o.sector.label}</strong>
                  <small>{o.name}</small>
                </span>
                <b>{o.avg.toFixed(1)}</b>
                <small>{o.critical} critical</small>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Changing threat level" sub={`Portfolio risk per simulated day (mean of the three org aggregates), last ${riskTimelineData.length} days`}>
          <div className="chart">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={riskTimelineData.slice() /* recharts freezes its data; keep the live array mutable */} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
                <defs>
                  <linearGradient id="rg" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0" stopColor="#ef5b5b" stopOpacity={0.45} />
                    <stop offset="1" stopColor="#ef5b5b" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="dayIndex" tickFormatter={(d) => `D${d}`} stroke="#64748b" fontSize={11} />
                <YAxis domain={["auto", "auto"]} stroke="#64748b" fontSize={11} />
                <Tooltip contentStyle={{ background: "#0f1b27", border: "1px solid #24384c", borderRadius: 8 }} labelFormatter={(d) => `Day ${d}`} formatter={(v) => [Number(v).toFixed(1), "risk"]} />
                <Area dataKey="risk" stroke="#ef5b5b" fill="url(#rg)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <ul className="changes">
            {!whatChangedFeed.length && <li className="muted">No change of 1+ risk point in the last 7 simulated days.</li>}
            {whatChangedFeed.slice(0, 3).map((c) => (
              <li key={c.id}>
                <button onClick={() => openAsset(c.assetId)}>
                  <b className={c.deltaBp > 0 ? "up" : "ok"}>
                    {c.deltaBp > 0 ? "+" : ""}
                    {(c.deltaBp / 100).toFixed(1)}
                  </b>
                  <span>
                    <strong>{c.assetId}</strong> {c.cause} <small>{c.timestamp}</small>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </Card>

        <Card title="Worst-case cascade" sub={`If ${head.id} is compromised`}>
          <ol className="cascade-v">
            <li>
              <span className="cdot" style={{ background: levelColor[head.level] }} />
              <div>
                <strong>
                  {head.id} · {head.name}
                </strong>
                <small>{sectorOf[head.org].label} · initial access via {head.vulnerability}</small>
              </div>
            </li>
            {headChain.map((c) => (
              <li key={c.asset.id}>
                <span className="cdot" style={{ background: sectorOf[c.asset.org].color }} />
                <div>
                  <strong>
                    {c.asset.id} · {c.asset.name}
                  </strong>
                  <small>
                    {sectorOf[c.asset.org].label} · {c.via} {c.kind === "potential" && <Tag>AI-inferred</Tag>}
                  </small>
                </div>
              </li>
            ))}
          </ol>
          <button className="btn full" onClick={() => openAsset(head.id)}>
            How to stop it <ArrowRight size={14} />
          </button>
        </Card>
      </div>
    </div>
  )
}
