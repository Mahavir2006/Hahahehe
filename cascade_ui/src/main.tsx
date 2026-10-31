import React from "react"
import ReactDOM from "react-dom/client"
import "@fontsource-variable/inter/wght.css" // self-hosted font (font-display: swap), no Google Fonts request
import App from "./App"
import "./index.css"
import "./theme.css"
import "./map.css"

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
