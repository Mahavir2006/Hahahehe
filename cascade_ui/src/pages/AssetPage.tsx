import { ArrowLeft, Share2 } from "lucide-react"
import { useNav } from "@/app/nav"
import { AssetBody } from "@/components/AssetPanel"
import { RiskMap } from "@/components/RiskMap"
import { toast } from "@/components/ui"
import { assetById, orgRisk, ranked, sectorOf } from "@/data/derive"

/** Full-page analysis and fixes for one asset (route #/asset/<ID>). */
export default function AssetPage() {
  const { focusAsset, back, openAssetPage } = useNav()
  const a = assetById.get(focusAsset ?? "")!
  const org = orgRisk.find((o) => o.code === a.org)!
  const rank = ranked.findIndex((x) => x.id === a.id) + 1
  const i = ranked.findIndex((x) => x.id === a.id)
  const prev = ranked[i - 1]
  const next = ranked[i + 1]

  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(location.href)
      toast("Link copied", location.href)
    } catch {
      toast("Could not copy the link", "Clipboard access was blocked", "warn")
    }
  }

  return (
    <div className="page asset-page">
      <div className="asset-top">
        <button className="btn btn-ghost" onClick={back}>
          <ArrowLeft size={15} /> Back
        </button>
        <div className="asset-nav">
          {prev && (
            <button className="btn btn-sm" onClick={() => openAssetPage(prev.id)} title={`Previous by risk: ${prev.name}`}>
              ← {prev.id}
            </button>
          )}
          {next && (
            <button className="btn btn-sm" onClick={() => openAssetPage(next.id)} title={`Next by risk: ${next.name}`}>
              {next.id} →
            </button>
          )}
          <button className="btn btn-sm" onClick={copyLink} aria-label="Copy link to this analysis">
            <Share2 size={13} /> Copy link
          </button>
        </div>
      </div>

      <header className="glass asset-head">
        <span className="eyebrow" style={{ color: sectorOf[a.org].color }}>
          {sectorOf[a.org].label} · {org.name}
        </span>
        <h2>
          {a.id} — {a.name}
        </h2>
        <p>
          {a.type} · {a.location} · zone {a.zone} · priority #{rank} of {ranked.length}
        </p>
      </header>

      <AssetBody a={a} wide />

      <section className="glass asset-map">
        <h3 className="pane-title">Where it sits and what it reaches</h3>
        <RiskMap selected={a.id} onSelect={(id) => id && id !== a.id && openAssetPage(id)} live={false} legend={false} />
      </section>
    </div>
  )
}
