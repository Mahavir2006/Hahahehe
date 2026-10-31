import React from 'react'
import { BANNER } from './api'

// Band shown as text AND colour (colour is never the only signal).
export function Band({ band }: { band: string }) {
  return <span className={`band band-${band}`}>{band.toUpperCase()}</span>
}

export function SimBanner() {
  return (
    <div className="sim-banner" role="note">
      {BANNER}
    </div>
  )
}

export function ErrorBox({ error }: { error: string | null }) {
  if (!error) return null
  return (
    <div className="error-box" role="alert">
      {error}
    </div>
  )
}

export function Tag({ text }: { text: string }) {
  return <span className="tag">{text}</span>
}

// refreshMs: poll again every refreshMs milliseconds (live views); omitted = load once per deps change
export function useLoad<T>(load: () => Promise<T>, deps: React.DependencyList, refreshMs?: number): [T | null, string | null, () => void] {
  const [data, setData] = React.useState<T | null>(null)
  const [error, setError] = React.useState<string | null>(null)
  const [tick, setTick] = React.useState(0)
  React.useEffect(() => {
    let live = true
    setError(null)
    load()
      .then((d) => live && setData(d))
      .catch((e) => live && setError(String(e.message || e)))
    return () => {
      live = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])
  React.useEffect(() => {
    if (!refreshMs) return
    const id = setInterval(() => setTick((t) => t + 1), refreshMs)
    return () => clearInterval(id)
  }, [refreshMs])
  return [data, error, () => setTick((t) => t + 1)]
}
