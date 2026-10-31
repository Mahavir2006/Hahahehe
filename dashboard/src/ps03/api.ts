// PS-03 dashboard: thin fetch helpers. Every request carries X-Dev-Role (admin by default).
export const ROLE = 'admin'
export const ORGS = [
  { id: 'power', name: 'Power Grid Utility' },
  { id: 'water', name: 'Water Board' },
  { id: 'hospital', name: 'City Hospital' },
]
export const BANNER = 'Simulation only. No commands are sent to real OT equipment.'

export async function api<T = any>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', 'X-Dev-Role': ROLE, ...(init.headers || {}) },
  })
  const text = await res.text()
  const body = text ? JSON.parse(text) : null
  if (!res.ok) {
    const detail = body && body.detail !== undefined ? body.detail : body
    throw new Error(`${res.status}: ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`)
  }
  return body as T
}

export const post = <T = any>(path: string, body?: unknown) =>
  api<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) })

export interface AttentionItem {
  rank: number
  asset_id: string
  name: string
  risk: number
  risk_bp: number
  band: string
  likelihood: number
  impact: number
  trend: string
  days_at_high_risk: number
  top_reasons: string[]
  finding_badges: Record<string, number>
  source_tags: string[]
}

export interface Attention {
  org: string
  sim_day: number
  banner: string
  aggregate_bp: number
  model_version: string
  model_source: string
  items: AttentionItem[]
}

export interface Change {
  org: string
  asset_id: string
  from_risk_bp: number
  to_risk_bp: number
  from_band: string
  to_band: string
  to_sim_day: number
  text: string
  reasons: { feature: string; text: string; delta_value: number; delta_contribution_logodds: number }[]
}

export const TREND_ARROW: Record<string, string> = { rising: '↑ rising', falling: '↓ falling', flat: '→ flat' }
