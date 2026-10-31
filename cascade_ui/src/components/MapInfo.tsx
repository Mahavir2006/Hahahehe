import { ArrowRight } from "lucide-react"
import { actionsFor, levelColor, predict, riskAfter, sectorOf, type Asset } from "@/data/derive"

/** Compact summary shown in the map's info card when a marker is clicked. */
export function MapInfo({ a, onDetails }: { a: Asset; onDetails: () => void }) {
  const fix = actionsFor(a)[0]
  const why = predict(a.id).shapFactors[0]
  return (
    <div className="mapinfo">
      <span className="mapinfo-sector" style={{ color: sectorOf[a.org].color }}>
        {sectorOf[a.org].label} · {a.location}
      </span>
      <strong>
        {a.id} — {a.name}
      </strong>
      <div className="mapinfo-score">
        <b style={{ color: levelColor[a.level] }}>{a.risk.toFixed(1)}</b>
        <span>{a.level} risk</span>
      </div>
      <dl>
        <dt>Main driver</dt>
        <dd>{why.feature}</dd>
        <dt>Recommended</dt>
        <dd>
          {fix.title} <em>→ {riskAfter(a, [fix]).toFixed(1)}</em>
        </dd>
      </dl>
      <button className="btn btn-primary btn-sm" onClick={onDetails}>
        Full details <ArrowRight size={13} />
      </button>
    </div>
  )
}
