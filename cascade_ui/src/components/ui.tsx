import { Component, type ReactNode, useEffect, useState } from "react"
import { AlertTriangle, CheckCircle2, Info, X } from "lucide-react"
import { levelColor, type RiskLevel } from "@/data/derive"

export function Card({ title, sub, action, children, className = "" }: { title?: string; sub?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`card ${className}`}>
      {(title || action) && (
        <header className="card-head">
          <div>
            {title && <h2>{title}</h2>}
            {sub && <p>{sub}</p>}
          </div>
          {action}
        </header>
      )}
      {children}
    </section>
  )
}

export function Level({ level }: { level: RiskLevel }) {
  return (
    <span className="level" style={{ "--c": levelColor[level] } as React.CSSProperties}>
      {level}
    </span>
  )
}

export function Tag({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "danger" | "warn" | "ok" | "info" }) {
  return <span className={`tag tag-${tone}`}>{children}</span>
}

export function RiskBar({ value, level }: { value: number; level: RiskLevel }) {
  return (
    <span className="riskbar" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(value)} aria-label="Risk score">
      <i style={{ width: `${Math.min(100, value)}%`, background: levelColor[level] }} />
    </span>
  )
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: string; tone?: string }) {
  return (
    <div className="stat" style={tone ? ({ "--c": tone } as React.CSSProperties) : undefined}>
      <span>{label}</span>
      <strong>{value}</strong>
      {hint && <small>{hint}</small>}
    </div>
  )
}

export function Sparkline({ data, color = "#38bdf8", w = 96, h = 28 }: { data: number[]; color?: string; w?: number; h?: number }) {
  const min = Math.min(...data)
  const max = Math.max(...data)
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * w},${h - ((v - min) / (max - min || 1)) * (h - 4) - 2}`).join(" ")
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export function Skeleton({ h = 120 }: { h?: number }) {
  return <div className="skeleton" style={{ height: h }} aria-hidden />
}

export function PageSkeleton() {
  return (
    <div className="page" aria-busy="true" aria-label="Loading">
      <div className="grid-stats">
        {Array.from({ length: 5 }, (_, i) => (
          <Skeleton key={i} h={92} />
        ))}
      </div>
      <div className="grid-2">
        <Skeleton h={320} />
        <Skeleton h={320} />
      </div>
    </div>
  )
}

export function EmptyState({ title, body, action }: { title: string; body: string; action?: ReactNode }) {
  return (
    <div className="empty" role="status">
      <Info size={22} aria-hidden />
      <strong>{title}</strong>
      <p>{body}</p>
      {action}
    </div>
  )
}

export class ErrorBoundary extends Component<{ children: ReactNode; resetKey?: unknown }, { error: Error | null }> {
  state = { error: null as Error | null }
  static getDerivedStateFromError(error: Error) {
    return { error }
  }
  componentDidCatch(error: Error) {
    console.error("[cascade_ui] view crashed", error)
  }
  componentDidUpdate(prev: { resetKey?: unknown }) {
    if (this.state.error && prev.resetKey !== this.props.resetKey) this.setState({ error: null })
  }
  render() {
    if (!this.state.error) return this.props.children
    return (
      <div className="empty error" role="alert">
        <AlertTriangle size={22} aria-hidden />
        <strong>This view failed to load</strong>
        <p>{this.state.error.message}</p>
        <button className="btn" onClick={() => this.setState({ error: null })}>
          Try again
        </button>
      </div>
    )
  }
}

/* ---------- toasts ---------- */

type ToastItem = { id: number; title: string; body?: string; tone: "ok" | "warn" }
let push: (t: Omit<ToastItem, "id">) => void = () => {}
export const toast = (title: string, body?: string, tone: ToastItem["tone"] = "ok") => push({ title, body, tone })

export function Toaster() {
  const [items, setItems] = useState<ToastItem[]>([])
  useEffect(() => {
    let seq = 0
    push = (t) => {
      const id = ++seq
      setItems((xs) => [...xs.slice(-3), { ...t, id }])
      setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), 4200)
    }
  }, [])
  return (
    <div className="toaster" aria-live="polite">
      {items.map((t) => (
        <div key={t.id} className={`toast toast-${t.tone}`} role="status">
          {t.tone === "ok" ? <CheckCircle2 size={16} aria-hidden /> : <AlertTriangle size={16} aria-hidden />}
          <div>
            <strong>{t.title}</strong>
            {t.body && <p>{t.body}</p>}
          </div>
          <button aria-label="Dismiss" onClick={() => setItems((xs) => xs.filter((x) => x.id !== t.id))}>
            <X size={14} />
          </button>
        </div>
      ))}
    </div>
  )
}
