import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react"
import { Bell, Menu, Moon, Search, Shield, Sun, X } from "lucide-react"
import { ALIASES, HIDDEN, NavContext, PAGES, type RouteId } from "@/app/nav"
import { AssetPanel } from "@/components/AssetPanel"
import { ResponseDialog } from "@/components/ResponseDialog"
import { ErrorBoundary, PageSkeleton, Toaster } from "@/components/ui"
import { assets, assetById, detectionsData, ranked } from "@/data/derive"

// every page is its own lazily-loaded chunk (code splitting)
const lazyPages = Object.fromEntries([...PAGES, ...HIDDEN].map((p) => [p.id, lazy(p.load)])) as Record<RouteId, React.LazyExoticComponent<React.ComponentType>>

interface Route {
  page: RouteId
  asset: string | null
  missing: string | null // what the user asked for when it does not exist
}

/**
 * Hash routes:  #/<page>            a page
 *               #/<page>/<ASSET-ID> a page with the asset side panel open
 *               #/asset/<ASSET-ID>  full-page analysis of one asset
 * Anything else falls back to the not-found page (an empty hash is the home page).
 */
export function readHash(hash = location.hash): Route {
  const path = hash.replace(/^#\/?/, "")
  if (!path) return { page: "dashboard", asset: null, missing: null }
  const [raw, id, ...rest] = path.split("/")
  const page: string = ALIASES[raw] ?? raw
  const known = PAGES.some((p) => p.id === page) || page === "asset"
  if (!known || rest.length) return { page: "notfound", asset: null, missing: `#/${path}` }
  if (page === "asset" && !id) return { page: "notfound", asset: null, missing: "an asset ID" }
  if (id && !assetById.has(id)) return { page: "notfound", asset: null, missing: `asset ${decodeURIComponent(id)}` }
  return { page: page as RouteId, asset: id ?? null, missing: null }
}

export default function App() {
  const [{ page, asset, missing }, setRoute] = useState(() => readHash())
  const [menuOpen, setMenuOpen] = useState(false)
  const [alertsOpen, setAlertsOpen] = useState(false)
  const [query, setQuery] = useState("")
  const [searchOpen, setSearchOpen] = useState(false)
  const searchRef = useRef<HTMLInputElement>(null)
  const [theme, setTheme] = useState<"dark" | "light">(() => (document.documentElement.dataset.theme === "light" ? "light" : "dark"))

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem("cs-theme", theme)
    } catch {
      /* storage blocked: theme still applies for this visit */
    }
  }, [theme])

  // lock page scroll behind the menu and the asset box
  useEffect(() => {
    document.body.classList.toggle("locked", menuOpen || (!!asset && page !== "asset"))
  }, [menuOpen, asset, page])

  useEffect(() => {
    const onHash = () => setRoute(readHash())
    window.addEventListener("hashchange", onHash)
    return () => window.removeEventListener("hashchange", onHash)
  }, [])

  const go = useCallback((p: RouteId) => {
    location.hash = `#/${p}`
    setMenuOpen(false)
    window.scrollTo({ top: 0 })
  }, [])
  // quick look: side panel on top of the current page (the asset page itself has no panel)
  const openAsset = useCallback((id: string) => {
    const cur = readHash().page
    location.hash = cur === "asset" || cur === "notfound" ? `#/asset/${id}` : `#/${cur}/${id}`
  }, [])
  const openAssetPage = useCallback((id: string) => {
    location.hash = `#/asset/${id}`
    window.scrollTo({ top: 0 })
  }, [])
  const closeAsset = useCallback(() => {
    location.hash = `#/${readHash().page}`
  }, [])
  const back = useCallback(() => {
    if (history.length > 1) history.back()
    else location.hash = "#/dashboard"
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

  const def = [...PAGES, ...HIDDEN].find((p) => p.id === page)!
  const Page = lazyPages[page]
  const nav = useMemo(() => ({ page, go, openAsset, openAssetPage, back, focusAsset: asset, missing }), [page, go, openAsset, openAssetPage, back, asset, missing])
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

        <span className="sim-pill" title="Asset data in this UI is simulated for the demo">
          Simulated data
        </span>
        <button className="icon-btn" aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"} onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}>
          {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
        </button>
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
      <nav className={`menu glass-strong ${menuOpen ? "open" : ""}`} aria-label="Main" aria-hidden={!menuOpen} inert={!menuOpen}>
        <div className="menu-head">
          <strong>Menu</strong>
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
        <p className="menu-foot">PS-03 · AI-based critical infrastructure cyber-risk prediction. Demo data is simulated.</p>
      </nav>

      <main id="main" className={`main ${page === "dashboard" ? "main-home" : ""}`}>
        <h1 className="sr-only">{def.label}</h1>
        <ErrorBoundary resetKey={page + (asset ?? "")}>
          <Suspense fallback={<PageSkeleton kind={page} />}>
            <Page key={page === "asset" ? asset : page} />
          </Suspense>
        </ErrorBoundary>
      </main>

      <AssetPanel id={page === "asset" ? null : asset} onClose={closeAsset} onFullPage={openAssetPage} />
      <ResponseDialog />
      <Toaster />
    </NavContext.Provider>
  )
}
