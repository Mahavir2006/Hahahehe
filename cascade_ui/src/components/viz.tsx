// Small visual building blocks for the "how does it work" pages: a polling data hook, ring gauges, a donut,
// a node-and-arrow flow and an empty/error helper. All data comes from the backend through api().
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react"
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts"
import { api } from "@/data/live"

export function useApi<T = any>(path: string | null, intervalMs = 0) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const alive = useRef(true)
  const load = useCallback(async () => {
    if (!path) return
    setLoading(true)
    try {
      const d = await api<T>(path)
      if (alive.current) {
        setData(d)
        setError("")
      }
    } catch (e) {
      if (alive.current) setError(e instanceof Error ? e.message : String(e))
    } finally {
      if (alive.current) setLoading(false)
    }
  }, [path])
  useEffect(() => {
    alive.current = true
    load()
    if (!intervalMs) return () => void (alive.current = false)
    const id = setInterval(() => !document.hidden && load(), intervalMs)
    return () => {
      alive.current = false
      clearInterval(id)
    }
  }, [load, intervalMs])
  return { data, error, loading, reload: load }
}

/** Circular gauge: value/max as an arc with a big number in the middle. */
export function Ring({ value, max = 1, label, sub, color = "#38bdf8", size = 112, text }: { value: number; max?: number; label: string; sub?: string; color?: string; size?: number; text?: string }) {
  const r = size / 2 - 9
  const c = 2 * Math.PI * r
  const f = max > 0 ? Math.max(0, Math.min(1, value / max)) : 0
  return (
    <figure className="gauge" style={{ width: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`${label}: ${text ?? value}`}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(148,163,184,.15)" strokeWidth="9" />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth="9" strokeLinecap="round" strokeDasharray={`${c * f} ${c}`} transform={`rotate(-90 ${size / 2} ${size / 2})`} style={{ transition: "stroke-dasharray .6s ease" }} />
        <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central" className="ring-num">
          {text ?? value}
        </text>
      </svg>
      <figcaption>
        <strong>{label}</strong>
        {sub && <small>{sub}</small>}
      </figcaption>
    </figure>
  )
}

/** Donut chart with a legend; slices are {name, value, color}. */
export function Donut({ slices, center, h = 170 }: { slices: { name: string; value: number; color: string }[]; center?: string; h?: number }) {
  const total = slices.reduce((s, x) => s + x.value, 0)
  return (
    <div className="donut">
      <div style={{ height: h, position: "relative" }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={slices.slice()} dataKey="value" nameKey="name" innerRadius="62%" outerRadius="92%" paddingAngle={2} stroke="none" isAnimationActive={false}>
              {slices.map((s) => (
                <Cell key={s.name} fill={s.color} />
              ))}
            </Pie>
            <Tooltip contentStyle={{ background: "#0f1b27", border: "1px solid #24384c", borderRadius: 8 }} />
          </PieChart>
        </ResponsiveContainer>
        <span className="donut-center">{center ?? total}</span>
      </div>
      <ul className="legend">
        {slices.map((s) => (
          <li key={s.name}>
            <i style={{ background: s.color }} />
            {s.name} <b>{s.value}</b>
          </li>
        ))}
      </ul>
    </div>
  )
}

export type NodeState = "idle" | "active" | "done" | "skip" | "fail"
/** A left-to-right chain of labelled nodes joined by arrows, each with a state colour. */
export function Flow({ nodes }: { nodes: { key: string; label: string; sub?: string; state: NodeState; icon?: ReactNode }[] }) {
  return (
    <ol className="flow-v2">
      {nodes.map((n, i) => (
        <li key={n.key} className={`fnode ${n.state}`}>
          {i > 0 && <span className="farrow" aria-hidden />}
          <div className="fbox">
            {n.icon}
            <strong>{n.label}</strong>
            {n.sub && <small>{n.sub}</small>}
          </div>
        </li>
      ))}
    </ol>
  )
}

export function Loading({ error, onRetry, text = "Loading…" }: { error?: string; onRetry?: () => void; text?: string }) {
  return error ? (
    <div className="viz-msg error">
      {error} {onRetry && <button className="btn btn-ghost" onClick={onRetry}>Retry</button>}
    </div>
  ) : (
    <div className="viz-msg">{text}</div>
  )
}
