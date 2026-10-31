// Demonstration data for the CascadeShield prototype. Replace with backend data.
// Indian infrastructure examples

export type OrgCode = "WGEC" | "MetroWater" | "CCMN"
export type RiskLevel = "Critical" | "High" | "Medium" | "Low"

export interface Organisation {
  code: OrgCode
  name: string
  sector: string
  totalAssets: number
  slug: "wgec" | "mw" | "cc"
}

export const organisations: Organisation[] = [
  { code: "WGEC", name: "POWERGRID India", sector: "Electricity", totalAssets: 24, slug: "wgec" },
  { code: "MetroWater", name: "Jal Board", sector: "Water", totalAssets: 19, slug: "mw" },
  { code: "CCMN", name: "AIIMS Network", sector: "Healthcare", totalAssets: 32, slug: "cc" },
]

export const orgByCode = Object.fromEntries(organisations.map((org) => [org.code, org])) as Record<OrgCode, Organisation>

export interface Asset {
  id: string
  name: string
  org: OrgCode
  zone: string
  type: string
  exposure: string
  vulnerability: string
  likelihood: number
  impact: number
  risk: number
  level: RiskLevel
  /** Position on the synthetic terrain plane (see components/terrain/geography). */
  x: number
  y: number
  cascade: string
  /** Indian city / location label */
  location: string
}

export const assets: Asset[] = [
  { id: "PG-003", name: "Northern Grid SCADA Gateway", org: "WGEC", zone: "control", type: "Gateway", exposure: "Internet-facing", vulnerability: "CVE-2024-3400", likelihood: 82, impact: 95, risk: 79.13, level: "Critical", x: 410, y: 265, cascade: "PG-001 → JB-014 → AI-021", location: "New Delhi" },
  { id: "PG-019", name: "Vendor VPN – Tehri Dam Link", org: "WGEC", zone: "uplands", type: "Remote access", exposure: "Internet-facing", vulnerability: "CVE-2023-46805", likelihood: 78, impact: 88, risk: 75.92, level: "Critical", x: 435, y: 220, cascade: "PG-008 → PG-001", location: "Dehradun" },
  { id: "PG-001", name: "400kV Substation – Agra", org: "WGEC", zone: "switching", type: "Substation", exposure: "Restricted", vulnerability: "2 open", likelihood: 61, impact: 92, risk: 71.84, level: "High", x: 425, y: 310, cascade: "JalBoard → AIIMS", location: "Agra" },
  { id: "PG-008", name: "SLDC Master Station", org: "WGEC", zone: "control", type: "SCADA", exposure: "Private", vulnerability: "Patched", likelihood: 34, impact: 89, risk: 48.4, level: "Medium", x: 515, y: 325, cascade: "PG-001 → JalBoard", location: "Lucknow" },
  { id: "PG-012", name: "Tehri Hydro Station", org: "WGEC", zone: "hydro", type: "Generation", exposure: "Private", vulnerability: "1 open", likelihood: 29, impact: 84, risk: 44.27, level: "Medium", x: 438, y: 205, cascade: "PG-001", location: "Tehri" },
  { id: "PG-017", name: "220kV Feeder – Jaipur", org: "WGEC", zone: "feeder", type: "Substation", exposure: "Restricted", vulnerability: "Patched", likelihood: 18, impact: 71, risk: 27.65, level: "Low", x: 350, y: 310, cascade: "AI-009", location: "Jaipur" },
  { id: "PG-021", name: "Transmission Relay – Bhopal", org: "WGEC", zone: "corridor", type: "Protection relay", exposure: "Private", vulnerability: "Patched", likelihood: 14, impact: 66, risk: 22.1, level: "Low", x: 430, y: 415, cascade: "None identified", location: "Bhopal" },
  { id: "JB-006", name: "Hirakud Dam Control HMI", org: "MetroWater", zone: "reservoir", type: "HMI", exposure: "Partner network", vulnerability: "CVE-2024-6387", likelihood: 74, impact: 91, risk: 76.84, level: "Critical", x: 625, y: 440, cascade: "JB-014 → AIIMS", location: "Sambalpur" },
  { id: "JB-014", name: "Yamuna Pump Control", org: "MetroWater", zone: "riverside", type: "PLC", exposure: "Partner network", vulnerability: "1 open", likelihood: 67, impact: 76, risk: 64.21, level: "High", x: 418, y: 275, cascade: "AI-021", location: "Delhi NCR" },
  { id: "JB-009", name: "Chlorination Unit – Sonia Vihar", org: "MetroWater", zone: "treatment", type: "PLC", exposure: "Private", vulnerability: "1 open", likelihood: 38, impact: 70, risk: 48.22, level: "Medium", x: 412, y: 268, cascade: "None identified", location: "Delhi" },
  { id: "JB-016", name: "Pressure Zone Gateway – Kanpur", org: "MetroWater", zone: "pumping", type: "Telemetry", exposure: "Partner network", vulnerability: "Patched", likelihood: 31, impact: 64, risk: 44.61, level: "Medium", x: 495, y: 340, cascade: "JB-014", location: "Kanpur" },
  { id: "JB-002", name: "Treatment Telemetry – Haridwar", org: "MetroWater", zone: "treatment", type: "Telemetry", exposure: "Private", vulnerability: "Patched", likelihood: 24, impact: 52, risk: 35.12, level: "Low", x: 440, y: 230, cascade: "JB-009", location: "Haridwar" },
  { id: "JB-011", name: "Ganga Intake Pumps", org: "MetroWater", zone: "intake", type: "Pump station", exposure: "Private", vulnerability: "Patched", likelihood: 16, impact: 58, risk: 27.9, level: "Low", x: 565, y: 360, cascade: "None identified", location: "Varanasi" },
  { id: "AI-014", name: "BMS – AIIMS Delhi", org: "CCMN", zone: "emergency", type: "BMS", exposure: "Internet-facing", vulnerability: "Default credentials", likelihood: 79, impact: 86, risk: 75.46, level: "Critical", x: 405, y: 270, cascade: "AI-021", location: "New Delhi" },
  { id: "AI-021", name: "Clinical Core – AIIMS Network", org: "CCMN", zone: "campus", type: "Server cluster", exposure: "Private", vulnerability: "3 open", likelihood: 53, impact: 98, risk: 68.72, level: "High", x: 408, y: 275, cascade: "None identified", location: "Delhi" },
  { id: "AI-005", name: "Pharmacy Cold Chain – Safdarjung", org: "CCMN", zone: "logistics", type: "IoT", exposure: "Partner network", vulnerability: "1 open", likelihood: 41, impact: 63, risk: 46.3, level: "Medium", x: 404, y: 278, cascade: "None identified", location: "Delhi" },
  { id: "AI-030", name: "Medical Gas Monitor – RML", org: "CCMN", zone: "campus", type: "OT sensors", exposure: "Private", vulnerability: "1 open", likelihood: 33, impact: 72, risk: 41.7, level: "Medium", x: 407, y: 266, cascade: "None identified", location: "Delhi" },
  { id: "AI-009", name: "Emergency Power ATS – Trauma Centre", org: "CCMN", zone: "power", type: "Power control", exposure: "Restricted", vulnerability: "Patched", likelihood: 15, impact: 99, risk: 31.35, level: "Low", x: 413, y: 278, cascade: "AI-021", location: "Delhi" },
]

export const assetById = new Map(assets.map((asset) => [asset.id, asset]))

export interface Dependency {
  from: string
  to: string
  kind: "confirmed" | "potential"
  label: string
}

/** Confirmed = attested service dependency. Potential = AI-inferred cascade path. */
export const dependencies: Dependency[] = [
  { from: "PG-003", to: "PG-008", kind: "confirmed", label: "Remote access path" },
  { from: "PG-019", to: "PG-008", kind: "confirmed", label: "Vendor access path" },
  { from: "PG-008", to: "PG-001", kind: "confirmed", label: "Control link" },
  { from: "PG-012", to: "PG-001", kind: "confirmed", label: "Generation feed" },
  { from: "PG-001", to: "JB-014", kind: "confirmed", label: "Power supply" },
  { from: "PG-017", to: "AI-009", kind: "confirmed", label: "Power supply" },
  { from: "JB-006", to: "JB-014", kind: "confirmed", label: "Flow control" },
  { from: "JB-002", to: "JB-009", kind: "confirmed", label: "Telemetry" },
  { from: "JB-016", to: "JB-014", kind: "confirmed", label: "Pressure telemetry" },
  { from: "AI-014", to: "AI-021", kind: "confirmed", label: "Cooling control" },
  { from: "AI-009", to: "AI-021", kind: "confirmed", label: "Standby power" },
  { from: "PG-003", to: "PG-001", kind: "potential", label: "Credential reuse" },
  { from: "JB-014", to: "AI-021", kind: "potential", label: "Pressure loss impact" },
]

/** Assets reachable downstream of an asset through any dependency. */
export function downstreamOf(assetId: string): Set<string> {
  const seen = new Set<string>()
  const queue = [assetId]
  while (queue.length) {
    const current = queue.shift()!
    for (const dep of dependencies) {
      if (dep.from === current && !seen.has(dep.to)) {
        seen.add(dep.to)
        queue.push(dep.to)
      }
    }
  }
  return seen
}

export const riskHex: Record<RiskLevel, string> = {
  Critical: "#E45B5B",
  High: "#E99A43",
  Medium: "#E4C85A",
  Low: "#42B98B",
}
