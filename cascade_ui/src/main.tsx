import React from "react"
import ReactDOM from "react-dom/client"
import "@fontsource-variable/inter/wght.css" // self-hosted font (font-display: swap), no Google Fonts request
import App from "./App"
import { refresh, startPolling } from "./data/live"
import "./index.css"
import "./theme.css"
import "./map.css"
import "./skin.css"
import "./sections.css"

// one root even when this module hot-reloads
const w = window as unknown as { __csRoot?: ReactDOM.Root }
const root = (w.__csRoot ??= ReactDOM.createRoot(document.getElementById("root")!))

function Boot({ error }: { error?: string }) {
  return (
    <div className="boot" role={error ? "alert" : "status"}>
      <strong>CascadeShield</strong>
      {error ? (
        <>
          <p>Could not reach the CascadeShield backend: {error}</p>
          <p className="muted small">Start it with: .\.venv\Scripts\python.exe -m backend.ps03_serve --port 8000 --live-interval 20</p>
          <button className="btn btn-primary" onClick={start}>
            Retry
          </button>
        </>
      ) : (
        <p>Loading live data from the backend…</p>
      )}
    </div>
  )
}

function start() {
  root.render(<Boot />)
  refresh()
    .then(() => {
      ;(window as unknown as { __csStopPoll?: () => void }).__csStopPoll?.()
      ;(window as unknown as { __csStopPoll?: () => void }).__csStopPoll = startPolling()
      root.render(
        <React.StrictMode>
          <App />
        </React.StrictMode>,
      )
    })
    .catch((e) => root.render(<Boot error={e instanceof Error ? e.message : String(e)} />))
}
start()
