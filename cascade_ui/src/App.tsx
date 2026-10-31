import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react"
import { Bell, Menu, Search, Shield, X } from "lucide-react"
import { NavContext, PAGES, type PageId } from "@/app/nav"
import { AssetPanel } from "@/components/AssetPanel"
import { ErrorBoundary, PageSkeleton, Toaster } from "@/components/ui"
import { assets, assetById, detectionsData, ranked } from "@/data/derive"
import { sim, useLive } from "@/data/live"

// every page is its own lazily-loaded chunk (code splitting)
const lazyPages = Object.fromEntries(PAGES.map((p) => [p.id, lazy(p.load)])) as Record<PageId, React.LazyExoticComponent<React.ComponentType>>

function readHash(): { page: PageId; asset: string | null } {
  const [, page, asset] = location.hash.match(/^#\/([a-z]+)(?:\/([a-z0-9-]+))?/) ?? []
  return { page: PAGES.some((p) => p.id === page) ? (page as PageId) : "dashboard", asset: asset && assetById.has(asset) ? asset : null }
}

export default function App() {
  useLive() // re-render when live data refreshes
  const [{ page, asset }, setRoute] = useState(readHash)
  const [menuOpen, setMenuOpen] = useState(false)
  const [alertsOpen, setAlertsOpen] = useState(false)
  const [query, setQuery] = useState("")
  const [searchOpen, setSearchOpen] = useState(false)
  const searchRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const onHash = () => setRoute(readHash())
    window.addEventListener("hashchange", onHash)
    return () => window.removeEventListener("hashchange", onHash)
  }, [])

  const go = useCallback((p: PageId) => {
    location.hash = `#/${p}`
    setMenuOpen(false)
    window.scrollTo({ top: 0 })
  }, [])
  const openAsset = useCallback((id: string) => {
    location.hash = `#/${readHash().page}/${id}`
  }, [])
  const closeAsset = useCallback(() => {
    location.hash = `#/${readHash().page}`
  }, [])

  // keyboard: "/" or Ctrl+K focuses search, Escape closes the menu
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.key === "k" && (e.ctrlKey || e.metaKey)) || (e.key === "/" && !(e.target as HTMLElement).closest("input,textarea"))) {
        e.preventDefault()
        searchRef.current?.focus()
      }
      if (e.key === "Escape") {
        setMenuOpen(false)
        setAlertsOpen(false)
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  const suggestions = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return []
    return assets.filter((a) => `${a.id} ${a.name} ${a.location} ${a.vulnerability} ${a.type}`.toLowerCase().includes(q)).slice(0, 6)
  }, [query])

  const def = PAGES.find((p) => p.id === page)!
  const Page = lazyPages[page]
  const nav = useMemo(() => ({ page, go, openAsset, focusAsset: asset }), [page, go, openAsset, asset])
  const critical = ranked.filter((a) => a.level === "Critical")

  return (
    <NavContext.Provider value={nav}>
      <a href="#main" className="skip">
        Skip to content
      </a>

      <header className="topbar">
        <button className="icon-btn" aria-label="Open menu" aria-expanded={menuOpen} onClick={() => setMenuOpen(true)}>
          <Menu size={20} />
        </button>
        <button className="brand" onClick={() => go("dashboard")} aria-label="CascadeShield dashboard">
          <span className="brand-mark">
            <Shield size={17} />
          </span>
          <span>
            <strong>CascadeShield</strong>
            <small>Critical-infrastructure cyber-risk</small>
          </span>
        </button>

        <div className="search" role="combobox" aria-expanded={searchOpen && suggestions.length > 0} aria-haspopup="listbox">
          <Search size={15} aria-hidden />
          <input
            ref={searchRef}
            value={query}
            placeholder="Search assets, CVEs, locations…"
            aria-label="Search assets"
            onChange={(e) => {
              setQuery(e.target.value)
              setSearchOpen(true)
            }}
            onFocus={() => setSearchOpen(true)}
            onBlur={() => setTimeout(() => setSearchOpen(false), 150)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && suggestions[0]) {
                openAsset(suggestions[0].id)
                setQuery("")
              }
            }}
          />
          <kbd>/</kbd>
          {searchOpen && suggestions.length > 0 && (
            <ul className="suggest" role="listbox">
              {suggestions.map((a) => (
                <li key={a.id} role="option" aria-selected={false}>
                  <button
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => {
                      openAsset(a.id)
                      setQuery("")
                    }}
                  >
                    <strong>{a.id}</strong> {a.name}
                    <small>
                      {a.location} · {a.vulnerability}
                    </small>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <span className="sim-pill" title={sim.error ? `Backend: ${sim.error}` : `${sim.banner} Last refresh ${sim.lastUpdate}`} role="status">
          {sim.error ? "Backend offline" : `Live · sim day ${sim.day}${sim.refreshing ? " · updating" : ""}`}
        </span>
        <button className="icon-btn" aria-label={`${critical.length} critical alerts`} aria-expanded={alertsOpen} onClick={() => setAlertsOpen((v) => !v)}>
          <Bell size={18} />
          <span className="dot">{critical.length}</span>
        </button>
        {alertsOpen && (
          <div className="alerts-pop" role="dialog" aria-label="Critical alerts">
            <strong>Needs urgent attention</strong>
            {critical.map((a) => (
              <button
                key={a.id}
                onClick={() => {
                  openAsset(a.id)
                  setAlertsOpen(false)
                }}
              >
                <span>
                  {a.id} · {a.name}
                </span>
                <small>{detectionsData.find((d) => d.assetId === a.id)?.ruleName ?? a.vulnerability}</small>
              </button>
            ))}
          </div>
        )}
      </header>

      {/* hamburger menu: sliding navigation drawer */}
      <div className={`scrim ${menuOpen ? "show" : ""}`} onClick={() => setMenuOpen(false)} aria-hidden />
      <nav className={`menu ${menuOpen ? "open" : ""}`} aria-label="Main" aria-hidden={!menuOpen} inert={!menuOpen}>
        <div className="menu-head">
          <strong>Navigate</strong>
          <button className="icon-btn" aria-label="Close menu" onClick={() => setMenuOpen(false)}>
            <X size={18} />
          </button>
        </div>
        {PAGES.map((p) => (
          <button key={p.id} className={`menu-item ${p.id === page ? "active" : ""}`} aria-current={p.id === page ? "page" : undefined} onClick={() => go(p.id)} onMouseEnter={() => p.load()} onFocus={() => p.load()}>
            <p.icon size={18} aria-hidden />
            <span>
              <strong>{p.label}</strong>
              <small>{p.blurb}</small>
            </span>
          </button>
        ))}
        <p className="menu-foot">PS-03 · AI-based critical infrastructure cyber-risk prediction. Live backend data; assets and telemetry are simulated.</p>
      </nav>

      {/* desktop: compact page tabs under the top bar */}
      <div className="tabs-bar" role="tablist" aria-label="Pages">
        {PAGES.map((p) => (
          <button key={p.id} role="tab" aria-selected={p.id === page} className={p.id === page ? "active" : ""} onClick={() => go(p.id)} onMouseEnter={() => p.load()}>
            <p.icon size={15} aria-hidden /> {p.label}
          </button>
        ))}
      </div>

      <main id="main" className="main">
        <div className="page-head">
          <div>
            <span className="crumb">CascadeShield / {def.label}</span>
            <h1>{def.label}</h1>
            <p>{def.blurb}</p>
          </div>
          <span className="objective">PS-03 · {def.objective}</span>
        </div>
        <ErrorBoundary resetKey={page}>
          <Suspense fallback={<PageSkeleton />}>
            <Page />
          </Suspense>
        </ErrorBoundary>
      </main>

      <AssetPanel id={asset} onClose={closeAsset} />
      <Toaster />
    </NavContext.Provider>
  )
}
