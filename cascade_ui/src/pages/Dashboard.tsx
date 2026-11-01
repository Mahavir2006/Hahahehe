import { useState } from "react"
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { useNav } from "@/app/nav"
import { MapInfo } from "@/components/MapInfo"
import { RiskMap } from "@/components/RiskMap"
import { assetById, cascadeChain, levelColor, LEVELS, orgRisk, portfolio, ranked, riskTimelineData, sectorOf } from "@/data/derive"

export default function Dashboard() {
  const { openAsset, go } = useNav()
  const [sel, setSel] = useState<string | null>(null)
  const focus = assetById.get(sel ?? ranked[0].id)!
  const chain = cascadeChain(focus.id)

  return (
    <div className="home">
      {/* left: posture and priorities */}
      <aside className="home-side">
        <section className="glass pane">
          <h2 className="pane-title">Security posture</h2>
          <dl className="metrics">
            <div>
              <dt>Average risk</dt>
              <dd>{portfolio.avgRisk.toFixed(1)}</dd>
            </div>
            <div>
              <dt>Assets monitored</dt>
              <dd>{portfolio.total}</dd>
            </div>
            <div>
              <dt>Require urgent action</dt>
              <dd className="crit">{portfolio.urgent}</dd>
            </div>
            <div>
              <dt>Known-exploited CVEs</dt>
              <dd className="crit">{portfolio.kev}</dd>
            </div>
            <div>
              <dt>Internet-facing</dt>
              <dd>{portfolio.internet}</dd>
            </div>
            <div>
              <dt>Cascade sources</dt>
              <dd>{portfolio.cascadeSources}</dd>
            </div>
          </dl>
        </section>

        <section className="glass pane grow">
          <div className="pane-row">
            <h2 className="pane-title">Priority assets</h2>
            <button className="text-btn" onClick={() => go("assets")}>
              View all
            </button>
          </div>
          <ol className="prio">
            {ranked.slice(0, 6).map((a, i) => (
              <li key={a.id}>
                <button className={sel === a.id ? "active" : ""} onClick={() => setSel(a.id)} onDoubleClick={() => openAsset(a.id)}>
                  <span className="prio-n">{i + 1}</span>
                  <span className="prio-main">
                    <strong>{a.id}</strong>
                    <small>{a.name}</small>
                  </span>
                  <b style={{ color: levelColor[a.level] }}>{a.risk.toFixed(1)}</b>
                </button>
              </li>
            ))}
          </ol>
        </section>
      </aside>

      {/* centre: the map */}
      <section className="glass home-map">
        <RiskMap selected={sel} onSelect={setSel} info={(a) => <MapInfo a={a} onDetails={() => {
              setSel(null)
              openAsset(a.id)
            }} />} />
      </section>

      {/* right: exposure, trend and impact */}
      <aside className="home-side">
        <section className="glass pane">
          <h2 className="pane-title">Exposure by sector</h2>
          <ul className="sectors">
            {orgRisk.map((o) => (
              <li key={o.code}>
                <div className="pane-row">
                  <span>
                    <i style={{ background: o.sector.color }} />
                    {o.sector.label}
                  </span>
                  <b>{o.avg.toFixed(1)}</b>
                </div>
                <div className="meter">
                  <span style={{ width: `${o.avg}%`, background: o.sector.color }} />
                </div>
                <small>
                  {o.name} · {o.count} assets · {o.critical} critical
                </small>
              </li>
            ))}
          </ul>
          <div className="bands">
            {LEVELS.map((l) => (
              <span key={l} style={{ flex: portfolio.byLevel[l] || 0.3, background: levelColor[l] }} title={`${l}: ${portfolio.byLevel[l]}`} />
            ))}
          </div>
          <div className="bands-key">
            {LEVELS.map((l) => (
              <span key={l}>
                {l} {portfolio.byLevel[l]}
              </span>
            ))}
          </div>
        </section>

        <section className="glass pane">
          <h2 className="pane-title">Risk trend</h2>
          <div className="trendchart">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={riskTimelineData.slice() /* recharts freezes its data; keep the live array mutable */} margin={{ top: 6, right: 4, bottom: 0, left: -26 }}>
                <defs>
                  <linearGradient id="rg" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0" stopColor="var(--accent)" stopOpacity={0.35} />
                    <stop offset="1" stopColor="var(--accent)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="dayIndex" tickFormatter={(d) => `D${d}`} stroke="var(--dim)" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis domain={["auto", "auto"]} stroke="var(--dim)" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{ background: "var(--surface)", border: "1px solid var(--line)", borderRadius: 8, color: "var(--text)", fontSize: 12 }}
                  labelFormatter={(d) => riskTimelineData[Number(d) - 1]?.day}
                  formatter={(v) => [Number(v).toFixed(1), "Risk"]}
                />
                <Area dataKey="risk" stroke="var(--accent)" fill="url(#rg)" strokeWidth={1.8} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <small className="muted">Day 7 is the model's forecast.</small>
        </section>

        <section className="glass pane grow">
          <h2 className="pane-title">Impact if {focus.id} is compromised</h2>
          {chain.length ? (
            <ol className="impact-list">
              {chain.map((c) => (
                <li key={c.asset.id}>
                  <i style={{ background: sectorOf[c.asset.org].color }} />
                  <span>
                    <strong>{c.asset.id}</strong> {c.asset.name}
                    <small>
                      {sectorOf[c.asset.org].label} · {c.via}
                      {c.kind === "potential" ? " (inferred)" : ""}
                    </small>
                  </span>
                </li>
              ))}
            </ol>
          ) : (
            <p className="muted">No downstream dependencies.</p>
          )}
        </section>
      </aside>
    </div>
  )
}
