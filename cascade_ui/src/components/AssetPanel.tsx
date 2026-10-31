import { useEffect, useRef, useState } from "react"
import { ArrowRight, ExternalLink, Globe2, X } from "lucide-react"
import { actionsFor, assetById, cascadeChain, detectionsData, levelColor, levelOf, orgRisk, predict, riskAfter, sectorOf } from "@/data/derive"
import { api, BACKEND_ORG, explainNow, mutate } from "@/data/live"
import { Level, RiskBar, Sparkline, Tag, toast } from "./ui"

/** Sliding side panel: everything about one asset — profile, vulnerabilities, why it is risky, cascade, fixes. */
export function AssetPanel({ id, onClose }: { id: string | null; onClose: () => void }) {
  const a = id ? assetById.get(id) : undefined
  const ref = useRef<HTMLElement>(null)
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const [sending, setSending] = useState(false)

  useEffect(() => {
    if (!a) return
    setPicked(new Set(actionsFor(a).slice(0, 2).map((x) => x.id)))
    explainNow(a.id).then(() => setPicked((s) => (s.size ? s : new Set(actionsFor(a).slice(0, 2).map((x) => x.id)))))
    const prev = document.activeElement as HTMLElement | null
    ref.current?.focus()
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose()
    window.addEventListener("keydown", onKey)
    return () => {
      window.removeEventListener("keydown", onKey)
      prev?.focus?.()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [a?.id, onClose])

  const open = !!a
  if (!a)
    return (
      <>
        <div className="scrim" aria-hidden />
        <aside className="panel-slide" aria-hidden />
      </>
    )

  const p = predict(a.id)
  const orgRow = orgRisk.find((o) => o.code === a.org)
  const actions = actionsFor(a)
  const chosen = actions.filter((x) => picked.has(x.id))
  const after = riskAfter(a, chosen)
  const chain = cascadeChain(a.id)
  const dets = detectionsData.filter((d) => d.assetId === a.id).slice(0, 6)
  const maxBp = Math.max(1, ...p.shapFactors.map((f) => Math.abs(f.bpDelta)))
  const backendOrg = BACKEND_ORG[a.org]
  const send = async () => {
    setSending(true)
    try {
      const pc = await api("/api/ps03/containment/precheck", { org: backendOrg, actions: chosen.map((x) => ({ action: x.code, targets: [a.id] })) })
      if (!pc.ok) {
        toast("Safety precheck blocked the plan", (pc.blocking ?? []).join("; ").slice(0, 300), "warn")
        return
      }
      if (chosen.some((x) => x.code === "ISOLATE_ASSET")) {
        const r = await mutate(() => api("/api/ps03/containment/level2", { org: backendOrg, asset_id: a.id }))
        toast("Quarantine plan sent for human approval", `${r.plan_id} · Critic: ${r.critic?.verdict ?? "?"} · approve it under Recommendations → Human approvals`)
      } else {
        toast("Safety precheck passed", `${(pc.warnings ?? []).length} warning(s). Only containment level 2 (quarantine) can be submitted from the UI; other actions are planned by the agents when an advisory arrives.`, "ok")
      }
    } catch (e) {
      toast("Request failed", e instanceof Error ? e.message : String(e), "warn")
    } finally {
      setSending(false)
    }
  }

  return (
    <>
      <div className={`scrim ${open ? "show" : ""}`} onClick={onClose} aria-hidden />
      <aside ref={ref} tabIndex={-1} className={`panel-slide ${open ? "open" : ""}`} role="dialog" aria-modal="true" aria-label={`Asset ${a.id}`}>
        <header className="ps-head">
          <div>
            <span className="eyebrow" style={{ color: sectorOf[a.org].color }}>
              {sectorOf[a.org].label} · {orgRow?.name}
            </span>
            <h2>
              {a.id} · {a.name}
            </h2>
            <p>
              {a.type} · {a.location} · zone {a.zone}
            </p>
          </div>
          <button className="icon-btn" aria-label="Close asset panel" onClick={onClose}>
            <X size={18} />
          </button>
        </header>

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
            <small>{p.holtForecastDays != null ? `next band in ~${p.holtForecastDays.toFixed(1)} d` : p.trendDirection}</small>
          </div>
        </div>

        <section className="ps-sec">
          <h3>Why this asset is {a.level.toLowerCase()} risk (SHAP, log-odds)</h3>
          <ul className="factors">
            {p.shapFactors.map((f) => (
              <li key={f.feature}>
                <span>{f.feature}</span>
                <i className={f.bpDelta > 0 ? "up" : "down"} style={{ width: `${(Math.abs(f.bpDelta) / maxBp) * 100}%` }} />
                <b className={f.bpDelta > 0 ? "up" : "down"}>
                  {f.bpDelta > 0 ? "+" : "−"}
                  {(Math.abs(f.bpDelta) / 100).toFixed(2)}
                </b>
              </li>
            ))}
          </ul>
          {p.missingDataIndicator && <p className="note">Data gap: {p.missingDataIndicator}</p>}
        </section>

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

        <section className="ps-sec">
          <h3>Recommended actions — backend what-if, pick to see the effect</h3>
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
          <button className="btn btn-primary full" disabled={!chosen.length || sending} onClick={send}>
            {sending ? "Checking with the agents…" : "Safety-check and send for approval"} <ExternalLink size={14} />
          </button>
        </section>
      </aside>
    </>
  )
}
