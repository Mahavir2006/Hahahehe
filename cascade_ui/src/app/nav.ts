import { createContext, useContext } from "react"
import { BarChart3, Boxes, FileSearch, LayoutDashboard, Radar, ScrollText, SearchX, Siren, Workflow, Wrench, type LucideIcon } from "lucide-react"

export type PageId = "dashboard" | "assets" | "risk" | "cascade" | "proactive" | "actions" | "respond" | "audit"
/** Routes that exist but are not in the menu. */
export type RouteId = PageId | "asset" | "notfound"

export interface PageDef {
  id: RouteId
  label: string
  icon: LucideIcon
  blurb: string
  howto?: string // one line: what you do on this page
  objective: string // the PS-03 objective this page answers
  load: () => Promise<{ default: React.ComponentType }>
}

export const PAGES: PageDef[] = [
  { id: "dashboard", label: "Overview", icon: LayoutDashboard, blurb: "Live risk picture across India", objective: "Predictive risk dashboard", load: () => import("@/pages/Dashboard") },
  { id: "assets", label: "Assets & Vulnerabilities", icon: Boxes, blurb: "What we run and where it is weak", howto: "Search the inventory, filter by sector or risk, and open any asset to see its CVEs, exposure and live detections.", objective: "Asset profiling · vulnerability assessment", load: () => import("@/pages/Assets") },
  { id: "risk", label: "Risk Prediction", icon: BarChart3, blurb: "Why the AI rates an asset high", howto: "Pick an asset to see how its score is built and which factors push it up or down. The second tab shows how the model was tested.", objective: "AI-based risk prediction · explainability", load: () => import("@/pages/RiskAnalysis") },
  { id: "cascade", label: "Cascade Simulator", icon: Workflow, blurb: "Test what one compromise would break", howto: "Choose an asset to compromise and a defence, press Run, and watch the failure spread to other organisations minute by minute.", objective: "Dependency & impact analysis", load: () => import("@/pages/Cascade") },
  { id: "proactive", label: "Proactive Scenarios", icon: Radar, blurb: "Prepare before an incident happens", howto: "Pick a situation that hasn't happened yet to see which assets it would push into danger and what to do now. The replay shows a full week.", objective: "From reactive to proactive risk assessment", load: () => import("@/pages/Proactive") },
  { id: "actions", label: "Recommendations", icon: Wrench, blurb: "Preventive actions and approvals", howto: "Actions are ranked by how much risk they remove. Each needs two human approvals; every vote is written to the Audit Trail.", objective: "Preventive recommendations", load: () => import("@/pages/Recommendations") },
  { id: "respond", label: "Incident Response", icon: Siren, blurb: "Act now: contain, notify, track", howto: "Every response in flight, step by step — what you decided, what the agents did, who was notified.", objective: "Immediate management and incident response", load: () => import("@/pages/Respond") },
  { id: "audit", label: "Audit Trail", icon: ScrollText, blurb: "Tamper-evident record of every decision", howto: "Every detection, alert, approval and simulation is hash-chained. Verify the chain, or simulate tampering to see it break.", objective: "Trust: private, verifiable audit", load: () => import("@/pages/Audit") },
]

/** Old links keep working. */
export const ALIASES: Record<string, PageId> = { map: "dashboard", platform: "audit", model: "risk" }

export const HIDDEN: PageDef[] = [
  { id: "asset", label: "Asset analysis", icon: FileSearch, blurb: "Full analysis and fixes for one asset", objective: "Explain why an asset is high risk", load: () => import("@/pages/AssetPage") },
  { id: "notfound", label: "Not found", icon: SearchX, blurb: "This page does not exist", objective: "", load: () => import("@/pages/NotFound") },
]

export interface Nav {
  page: RouteId
  go: (p: RouteId) => void
  /** Quick look: side panel over the current page. */
  openAsset: (id: string) => void
  /** Full-page analysis and fixes for one asset. */
  openAssetPage: (id: string) => void
  back: () => void
  focusAsset: string | null
  missing: string | null
}
export const NavContext = createContext<Nav>({ page: "dashboard", go: () => {}, openAsset: () => {}, openAssetPage: () => {}, back: () => {}, focusAsset: null, missing: null })
export const useNav = () => useContext(NavContext)
