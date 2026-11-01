import { SearchX } from "lucide-react"
import { PAGES, useNav } from "@/app/nav"

/** Fallback for unknown routes and asset IDs that do not exist. */
export default function NotFound() {
  const { go, missing, back } = useNav()
  return (
    <div className="page notfound">
      <section className="glass notfound-card" role="alert">
        <SearchX size={30} aria-hidden />
        <h2>Nothing here</h2>
        <p>
          We couldn't find <code>{missing ?? "that page"}</code>. It may have been renamed, or the link is incomplete.
        </p>
        <div className="notfound-actions">
          <button className="btn btn-primary" onClick={() => go("dashboard")}>
            Go to the overview
          </button>
          <button className="btn" onClick={back}>
            Go back
          </button>
        </div>
        <nav aria-label="All pages" className="notfound-links">
          {PAGES.map((p) => (
            <button key={p.id} className="text-btn" onClick={() => go(p.id)}>
              {p.label}
            </button>
          ))}
        </nav>
      </section>
    </div>
  )
}
