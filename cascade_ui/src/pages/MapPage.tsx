import { useState } from "react"
import { useNav } from "@/app/nav"
import { RiskMap } from "@/components/RiskMap"
import { Card, Level } from "@/components/ui"
import { assetById, cascadeChain, orgRisk, sectorOf } from "@/data/derive"

export default function MapPage() {
  const { openAsset, focusAsset } = useNav()
  const [sector, setSector] = useState("All")
  const [minLevel, setMinLevel] = useState("All")
  const [sel, setSel] = useState<string>(focusAsset ?? "PG-003")
  const a = assetById.get(sel)!
  const chain = cascadeChain(sel)

  return (
    <div className="page">
      <div className="filters" role="toolbar" aria-label="Map filters">
        <div className="seg" role="group" aria-label="Sector">
          {["All", ...orgRisk.map((o) => o.code)].map((s) => (
            <button key={s} aria-pressed={sector === s} className={sector === s ? "active" : ""} onClick={() => setSector(s)}>
              {s === "All" ? "All sectors" : sectorOf[s].label}
            </button>
          ))}
        </div>
        <div className="seg" role="group" aria-label="Minimum risk">
          {["All", "Medium", "High", "Critical"].map((l) => (
            <button key={l} aria-pressed={minLevel === l} className={minLevel === l ? "active" : ""} onClick={() => setMinLevel(l)}>
              {l === "All" ? "Any risk" : `${l}+`}
            </button>
          ))}
        </div>
      </div>

      <div className="grid-map">
        <Card className="map-card">
          <RiskMap selected={sel} onSelect={setSel} sector={sector} minLevel={minLevel} />
        </Card>
        <Card title={`${a.id} · ${a.name}`} sub={`${sectorOf[a.org].label} · ${a.type} · ${a.location}`}>
          <div className="mini-score">
            <b>{a.risk.toFixed(1)}</b>
            <Level level={a.level} />
            <small>
              likelihood {a.likelihood}% × impact {a.impact}%
            </small>
          </div>
          <h3 className="h3">Downstream impact ({chain.length} assets)</h3>
          {chain.length ? (
            <ol className="cascade-v">
              {chain.map((c) => (
                <li key={c.asset.id}>
                  <span className="cdot" style={{ background: sectorOf[c.asset.org].color }} />
                  <div>
                    <button className="link" onClick={() => setSel(c.asset.id)}>
                      {c.asset.id} · {c.asset.name}
                    </button>
                    <small>
                      hop {c.depth} · {c.via}
                      {c.kind === "potential" ? " · AI-inferred" : " · attested on-chain"}
                    </small>
                  </div>
                </li>
              ))}
            </ol>
          ) : (
            <p className="muted">Nothing depends on this asset.</p>
          )}
          <button className="btn btn-primary full" onClick={() => openAsset(sel)}>
            Full analysis & fixes
          </button>
        </Card>
      </div>
    </div>
  )
}
