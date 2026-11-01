import { useEffect, useRef, useState } from "react"
import { ArrowRight, ExternalLink, Globe2, Maximize2, X } from "lucide-react"
import { actionsFor, assetById, cascadeChain, detectionsData, levelColor, levelOf, orgRisk, predict, riskAfter, sectorOf, type Asset } from "@/data/derive"
import { Level, RiskBar, Sparkline, Tag, toast } from "./ui"
import { appendAudit } from "@/data/audit"
import { requestResponse } from "@/data/incidents"
import { Siren } from "lucide-react"

/** Everything about one asset: scores, why, vulnerabilities, cascade, fixes. Used by the side panel and the full page. */
export function AssetBody({ a, wide = false }: { a: Asset; wide?: boolean }) {
  const [picked, setPicked] = useState<Set<string>>(() => new Set(actionsFor(a).slice(0, 2).map((x) => x.id)))
  useEffect(() => setPicked(new Set(actionsFor(a).slice(0, 2).map((x) => x.id))), [a])

  const p = predict(a.id)
  const actions = actionsFor(a)
  const chosen = actions.filter((x) => picked.has(x.id))
  const after = riskAfter(a, chosen)
  const chain = cascadeChain(a.id)
  const dets = detectionsData.filter((d) => d.assetId === a.id)
  const maxBp = Math.max(...p.shapFactors.map((f) => Math.abs(f.bpDelta)))

  const why = (
    <section className="ps-sec">
      <h3>Why this asset is {a.level.toLowerCase()} risk</h3>
      <ul className="factors">
        {p.shapFactors.map((f) => (
          <li key={f.feature}>
            <span>{f.feature}</span>
            <i className={f.bpDelta > 0 ? "up" : "down"} style={{ width: `${(Math.abs(f.bpDelta) / maxBp) * 100}%` }} />
            <b className={f.bpDelta > 0 ? "up" : "down"}>
              {f.bpDelta > 0 ? "+" : "−"}
              {(Math.abs(f.bpDelta) / 100).toFixed(1)}
            </b>
          </li>
        ))}
      </ul>
      {p.missingDataIndicator && <p className="note">Data gap: {p.missingDataIndicator}</p>}
    </section>
  )

  const vuln = (
    <section className="ps-sec">
      <h3>Vulnerability & exposure</h3>
      <dl className="kv">
        <dt>Finding</dt>
        <dd>{a.vulnerability}</dd>
        <dt>Main CVE</dt>
        <dd>
          {p.vulnData.cveId} {p.vulnData.kevBadge && <Tag tone="danger">CISA KEV · exploited</Tag>}
        </dd>
        <dt>CVSS / EPSS</dt>
        <dd>
          {p.vulnData.cvss.toFixed(1)} / {(p.vulnData.epss * 100).toFixed(1)}%
        </dd>
        <dt>Exposure</dt>
        <dd>
          {a.exposure.includes("Internet") ? (
            <Tag tone="danger">
              <Globe2 size={11} /> Internet-facing
            </Tag>
          ) : (
            a.exposure
          )}
        </dd>
        <dt>Unpatched for</dt>
        <dd>{p.vulnData.patchAgeDays} days</dd>
        <dt>Source</dt>
        <dd>{p.vulnData.source}</dd>
      </dl>
      {dets.length > 0 && (
        <ul className="dets">
          {dets.map((d) => (
            <li key={d.id}>
              <Tag tone={d.severity === "Critical" ? "danger" : "warn"}>
                {d.ruleId} {d.ruleName}
              </Tag>
              <span>{d.evidence}</span>
              <small>{d.time}</small>
            </li>
          ))}
        </ul>
      )}
    </section>
  )

  const cascade = (
    <section className="ps-sec">
      <h3>If compromised, what fails next</h3>
      {chain.length ? (
        <ol className="chain">
          <li>
            <b>{a.id}</b>
            <small>source</small>
          </li>
          {chain.map((c) => (
            <li key={c.asset.id}>
              <ArrowRight size={13} aria-hidden />
              <b style={{ color: sectorOf[c.asset.org].color }}>{c.asset.id}</b>
              <small>
                {c.via}
                {c.kind === "potential" ? " (AI-inferred)" : ""}
              </small>
            </li>
          ))}
        </ol>
      ) : (
        <p className="muted">No downstream dependency identified.</p>
      )}
    </section>
  )

  const fixes = (
    <section className="ps-sec">
      <h3>Recommended actions — pick to see the effect</h3>
      <ul className="acts">
        {actions.map((x) => (
          <li key={x.id}>
            <label>
              <input
                type="checkbox"
                checked={picked.has(x.id)}
                onChange={() =>
                  setPicked((s) => {
                    const n = new Set(s)
                    if (n.has(x.id)) n.delete(x.id)
                    else n.add(x.id)
                    return n
                  })
                }
              />
              <span>
                <strong>
                  <Tag tone="info">{x.kind}</Tag> {x.title}
                </strong>
                <small>{x.detail}</small>
              </span>
              <b>−{Math.round(x.reduction * 100)}%</b>
            </label>
          </li>
        ))}
      </ul>
      <div className="whatif">
        <div>
          <span>Now</span>
          <strong style={{ color: levelColor[a.level] }}>{a.risk.toFixed(1)}</strong>
        </div>
        <ArrowRight aria-hidden />
        <div>
          <span>After {chosen.length} action(s)</span>
          <strong style={{ color: levelColor[levelOf(after)] }}>{after.toFixed(1)}</strong>
          <Level level={levelOf(after)} />
        </div>
        <RiskBar value={after} level={levelOf(after)} />
      </div>
      <button className="btn btn-primary full" disabled={!chosen.length} onClick={() => {
          appendAudit({ kind: "Approval", actor: "Planner agent", contract: "ApprovalGate", subject: a.id, detail: `Approval requested: ${chosen.map((c) => c.kind.toLowerCase()).join(", ")} (risk ${a.risk.toFixed(1)} → ${after.toFixed(1)})` })
          toast("Plan sent for human approval", `${chosen.length} action(s) for ${a.id} · logged in the Audit Trail`)
        }}>
        Send plan for approval <ExternalLink size={14} />
      </button>
      <button className="btn full respond-btn" onClick={() => requestResponse({ title: `Respond to ${a.name}`, source: "Asset", assets: [a.id, ...chain.map((c) => c.asset.id)] })}>
        <Siren size={14} /> Respond now — isolate or escalate
      </button>
    </section>
  )

  const score = (
    <div className="ps-score">
      <div>
        <span>Risk score</span>
        <strong style={{ color: levelColor[a.level] }}>{a.risk.toFixed(1)}</strong>
        <Level level={a.level} />
      </div>
      <div>
        <span>Likelihood</span>
        <strong>{a.likelihood}%</strong>
        <small>AI model M1</small>
      </div>
      <div>
        <span>Impact</span>
        <strong>{a.impact}%</strong>
        <small>criticality + dependants</small>
      </div>
      <div>
        <span>Trend</span>
        <Sparkline data={p.sparkline} color={levelColor[a.level]} w={80} />
        <small>{p.holtForecastDays != null ? `next band in ~${p.holtForecastDays.toFixed(1)} d` : `trend ${p.trendDirection}`}</small>
      </div>
    </div>
  )

  if (wide)
    return (
      <>
        {score}
        <div className="asset-grid">
          <div className="glass asset-col">
            {why}
            {vuln}
            {cascade}
          </div>
          <div className="glass asset-col">{fixes}</div>
        </div>
      </>
    )
  return (
    <>
      {score}
      {why}
      {vuln}
      {cascade}
      {fixes}
    </>
  )
}

/** Sliding side panel (quick look) with a link to the full-page analysis. */
export function AssetPanel({ id, onClose, onFullPage }: { id: string | null; onClose: () => void; onFullPage: (id: string) => void }) {
  const a = id ? assetById.get(id) : undefined
  const ref = useRef<HTMLElement>(null)

  useEffect(() => {
    if (!a) return
    const prev = document.activeElement as HTMLElement | null
    ref.current?.focus()
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose()
    window.addEventListener("keydown", onKey)
    return () => {
      window.removeEventListener("keydown", onKey)
      prev?.focus?.()
    }
  }, [a, onClose])

  if (!a)
    return (
      <>
        <div className="scrim" aria-hidden />
        <aside className="panel-slide" aria-hidden />
      </>
    )
  const org = orgRisk.find((o) => o.code === a.org)!

  return (
    <>
      <div className="scrim show" onClick={onClose} aria-hidden />
      <aside ref={ref} tabIndex={-1} className="panel-slide open" role="dialog" aria-modal="true" aria-label={`Asset ${a.id}`}>
        <header className="ps-head">
          <div>
            <span className="eyebrow" style={{ color: sectorOf[a.org].color }}>
              {sectorOf[a.org].label} · {org.name}
            </span>
            <h2>
              {a.id} · {a.name}
            </h2>
            <p>
              {a.type} · {a.location} · zone {a.zone}
            </p>
          </div>
          <div className="ps-actions">
            <button className="icon-btn" aria-label="Open full analysis page" title="Open full analysis page" onClick={() => onFullPage(a.id)}>
              <Maximize2 size={16} />
            </button>
            <button className="icon-btn" aria-label="Close asset panel" onClick={onClose}>
              <X size={18} />
            </button>
          </div>
        </header>
        <AssetBody a={a} />
      </aside>
    </>
  )
}
