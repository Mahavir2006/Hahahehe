import { useDeferredValue, useMemo, useState } from "react"
import { ChevronRight, Globe2 } from "lucide-react"
import { useNav } from "@/app/nav"
import { Card, EmptyState, Level, RiskBar, Tag } from "@/components/ui"
import { assets, detectionsData, exposureFindings, isInternet, levelColor, predict, sectorOf, type RiskLevel } from "@/data/derive"
import { useLive } from "@/data/live"

const PAGE = 8
type Sort = "risk" | "likelihood" | "impact" | "id"

export default function Assets() {
  const { openAsset } = useNav()
  const [q, setQ] = useState("")
  const query = useDeferredValue(q) // keeps typing responsive while filtering
  const [level, setLevel] = useState<"All" | RiskLevel>("All")
  const [sector, setSector] = useState("All")
  const [onlyKev, setOnlyKev] = useState(false)
  const [sort, setSort] = useState<Sort>("risk")
  const [page, setPage] = useState(1)
  const v = useLive()

  const rows = useMemo(() => {
    const n = query.trim().toLowerCase()
    return assets
      .filter((a) => (level === "All" || a.level === level) && (sector === "All" || a.org === sector) && (!onlyKev || predict(a.id).vulnData.kevBadge))
      .filter((a) => !n || `${a.id} ${a.name} ${a.type} ${a.location} ${a.vulnerability} ${predict(a.id).vulnData.cveId}`.toLowerCase().includes(n))
      .sort((x, y) => (sort === "id" ? x.id.localeCompare(y.id) : y[sort] - x[sort]))
  }, [query, level, sector, onlyKev, sort, v])
  const pages = Math.max(1, Math.ceil(rows.length / PAGE))
  const cur = Math.min(page, pages)
  const shown = rows.slice((cur - 1) * PAGE, cur * PAGE)
  const reset = () => setPage(1)

  return (
    <div className="page">
      <div className="grid-3">
        {exposureFindings.slice(0, 6).map((x, i) => (
          <Card key={`${x.code}-${x.assetId}-${i}`} className="finding">
            <div className="row-between">
              <Tag tone={x.severity === "Critical" ? "danger" : x.severity === "High" ? "warn" : "info"}>
                {x.code} · {x.severity}
              </Tag>
              <small className="muted">{x.discovered}</small>
            </div>
            <strong>{x.title}</strong>
            <p>{x.description}</p>
            <button className="link" onClick={() => openAsset(x.assetId)}>
              {x.assetId} <ChevronRight size={12} />
            </button>
          </Card>
        ))}
      </div>

      <Card title="Asset inventory" sub={`${rows.length} of ${assets.length} assets · vulnerability data from CISA KEV / NVD (real) and simulated telemetry`}>
        <div className="filters">
          <input className="input" type="search" placeholder="Filter by ID, name, CVE, location…" value={q} onChange={(e) => (setQ(e.target.value), reset())} aria-label="Filter assets" />
          <select className="input" value={sector} onChange={(e) => (setSector(e.target.value), reset())} aria-label="Sector">
            <option value="All">All sectors</option>
            {Object.entries(sectorOf).map(([k, s]) => (
              <option key={k} value={k}>
                {s.label}
              </option>
            ))}
          </select>
          <div className="seg" role="group" aria-label="Risk level">
            {(["All", "Critical", "High", "Medium", "Low"] as const).map((l) => (
              <button key={l} aria-pressed={level === l} className={level === l ? "active" : ""} onClick={() => (setLevel(l), reset())}>
                {l}
              </button>
            ))}
          </div>
          <label className="check">
            <input type="checkbox" checked={onlyKev} onChange={(e) => (setOnlyKev(e.target.checked), reset())} /> Known-exploited only
          </label>
          <select className="input" value={sort} onChange={(e) => setSort(e.target.value as Sort)} aria-label="Sort by">
            <option value="risk">Sort: risk</option>
            <option value="likelihood">Sort: likelihood</option>
            <option value="impact">Sort: impact</option>
            <option value="id">Sort: ID</option>
          </select>
        </div>

        {shown.length ? (
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Asset</th>
                  <th className="hide-sm">Type · location</th>
                  <th>Vulnerability</th>
                  <th className="hide-sm">Exposure</th>
                  <th className="hide-sm">Likelihood</th>
                  <th className="hide-sm">Impact</th>
                  <th>Risk</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((a) => {
                  const v = predict(a.id).vulnData
                  const det = detectionsData.filter((d) => d.assetId === a.id).length
                  return (
                    <tr key={a.id} tabIndex={0} onClick={() => openAsset(a.id)} onKeyDown={(e) => e.key === "Enter" && openAsset(a.id)}>
                      <td>
                        <strong>{a.id}</strong>
                        <small style={{ color: sectorOf[a.org].color }}>
                          {sectorOf[a.org].label} · {a.name}
                        </small>
                      </td>
                      <td className="hide-sm">
                        {a.type}
                        <small>{a.location}</small>
                      </td>
                      <td>
                        {a.vulnerability === "Patched" ? <Tag tone="ok">Patched</Tag> : <span>{a.vulnerability}</span>}
                        <small>
                          {v.cveId} · CVSS {v.cvss.toFixed(1)} {v.kevBadge && <Tag tone="danger">KEV</Tag>} {det > 0 && <Tag tone="warn">{det} detection{det > 1 ? "s" : ""}</Tag>}
                        </small>
                      </td>
                      <td className="hide-sm">
                        {isInternet(a) ? (
                          <Tag tone="danger">
                            <Globe2 size={11} /> Internet
                          </Tag>
                        ) : (
                          a.exposure
                        )}
                      </td>
                      <td className="hide-sm">{a.likelihood}%</td>
                      <td className="hide-sm">{a.impact}%</td>
                      <td>
                        <div className="risk-cell">
                          <b style={{ color: levelColor[a.level] }}>{a.risk.toFixed(1)}</b>
                          <Level level={a.level} />
                        </div>
                        <RiskBar value={a.risk} level={a.level} />
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No assets match"
            body="Try a different search or clear the filters."
            action={
              <button className="btn" onClick={() => (setQ(""), setLevel("All"), setSector("All"), setOnlyKev(false), reset())}>
                Clear filters
              </button>
            }
          />
        )}
        <nav className="pager" aria-label="Pagination">
          <button className="btn btn-ghost" disabled={cur <= 1} onClick={() => setPage(cur - 1)}>
            Previous
          </button>
          <span>
            Page {cur} of {pages}
          </span>
          <button className="btn btn-ghost" disabled={cur >= pages} onClick={() => setPage(cur + 1)}>
            Next
          </button>
        </nav>
      </Card>

      <Card title="Live detections" sub={`Rules R1–R6 on simulated telemetry · ${detectionsData.length} findings, latest 30 shown · exposure findings: ${exposureFindings.length}`}>
        <ul className="det-list">
          {detectionsData.slice(0, 30).map((d) => (
            <li key={d.id}>
              <Tag tone={d.severity === "Critical" ? "danger" : d.severity === "High" ? "warn" : "info"}>
                {d.ruleId} · {d.ruleName}
              </Tag>
              <button className="link" onClick={() => openAsset(d.assetId)}>
                {d.assetId}
              </button>
              <span>{d.evidence}</span>
              <small>{d.time}</small>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  )
}
