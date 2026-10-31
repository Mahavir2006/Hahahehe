import { createContext, useContext } from "react"
import { BarChart3, Boxes, BrainCircuit, LayoutDashboard, Map, ShieldCheck, Wrench, type LucideIcon } from "lucide-react"

export type PageId = "dashboard" | "map" | "assets" | "risk" | "actions" | "platform" | "model"

export interface PageDef {
  id: PageId
  label: string
  icon: LucideIcon
  blurb: string
  objective: string // the PS-03 objective this page answers
  load: () => Promise<{ default: React.ComponentType }>
}

export const PAGES: PageDef[] = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard, blurb: "What needs attention right now", objective: "Predictive risk dashboard", load: () => import("@/pages/Dashboard") },
  { id: "map", label: "Infrastructure Map", icon: Map, blurb: "Assets, dependencies and cascade paths", objective: "Asset profiling · dependency & impact analysis", load: () => import("@/pages/MapPage") },
  { id: "assets", label: "Assets & Vulnerabilities", icon: Boxes, blurb: "Inventory, CVEs, exposure and detections", objective: "Vulnerability assessment · risk prioritisation", load: () => import("@/pages/Assets") },
  { id: "risk", label: "Risk Analysis", icon: BarChart3, blurb: "Why an asset is high risk", objective: "AI-based risk prediction", load: () => import("@/pages/RiskAnalysis") },
  { id: "actions", label: "Recommendations", icon: Wrench, blurb: "Preventive actions and their risk reduction", objective: "Preventive recommendations", load: () => import("@/pages/Recommendations") },
  { id: "platform", label: "Agents & Blockchain", icon: ShieldCheck, blurb: "How CascadeShield works end to end", objective: "Trust: AI agents, human approval, private audit trail", load: () => import("@/pages/Platform") },
  { id: "model", label: "AI Model", icon: BrainCircuit, blurb: "How the risk model was built and tested", objective: "Model evidence and limits", load: () => import("@/pages/Model") },
]

export interface Nav {
  page: PageId
  go: (p: PageId) => void
  openAsset: (id: string) => void
  focusAsset: string | null
}
export const NavContext = createContext<Nav>({ page: "dashboard", go: () => {}, openAsset: () => {}, focusAsset: null })
export const useNav = () => useContext(NavContext)
