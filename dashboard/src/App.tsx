import React, { useState, useEffect } from 'react'
import './App.css'

interface Org {
  id: string
  name: string
  sector: string
}

interface Trace {
  trace_id: string
  advisory_id: string
  org: string
  started_at: string
  status: string
}

function App() {
  const [orgs, setOrgs] = useState<{id: string, name: string, sector: string}[]>([])
  const [selectedOrg, setSelectedOrg] = useState<string>('power')
  const [traces, setTraces] = useState<any[]>([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    fetch('/api/orgs/power/assets').then(r => r.json()).then(setOrgs)
  }, [])

  useEffect(() => {
    fetchTraces()
  }, [selectedOrg])

  const fetchTraces = async () => {
    setLoading(true)
    try {
      const res = await fetch(`/api/traces?org=${selectedOrg}`)
      const data = await res.json()
      setTraces(data.traces || [])
    } catch (e) {
      console.error(e)
    }
    setLoading(false)
  }

  const handleAdvisorySubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const formData = new FormData(e.currentTarget)
    const text = formData.get('advisoryText') as string
    
    try {
      const res = await fetch('/api/advisories', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Dev-Role': 'org:power' },
        body: JSON.stringify({ text, source: 'dashboard' })
      })
      const result = await res.json()
      alert(`Advisory ingested: ${result.advisory_id}`)
    } catch (e) {
      alert('Error: ' + e)
    }
  }

  return (
    <div className="app">
      <header className="header">
        <h1>CascadeShield Dashboard</h1>
        <div className="org-selector">
          <label>Organization: </label>
          <select value={selectedOrg} onChange={e => setSelectedOrg(e.target.value)}>
            <option value="power">⚡ Power Grid Utility</option>
            <option value="water">💧 Water Board</option>
            <option value="hospital">🏥 City Hospital</option>
          </select>
        </div>
      </header>

      <main className="main">
        <section className="panel">
          <h2>Advisory Ingestion</h2>
          <form onSubmit={handleAdvisorySubmit}>
            <textarea name="advisoryText" placeholder="Paste advisory text here..." rows={6} required />
            <button type="submit">Ingest Advisory</button>
          </form>
        </section>

        <section className="panel">
          <h2>Traces / Pipeline Status</h2>
          {loading ? <p>Loading...</p> : (
            <table>
              <thead>
                <tr>
                  <th>Trace ID</th>
                  <th>Advisory</th>
                  <th>Org</th>
                  <th>Started</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {traces.map(t => (
                  <tr key={t.trace_id}>
                    <td>{t.trace_id}</td>
                    <td>{t.advisory_id}</td>
                    <td>{t.org}</td>
                    <td>{new Date(t.started_at).toLocaleString()}</td>
                    <td><span className={`status-${t.status}`}>{t.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section className="panel">
          <h2>Quick Stats</h2>
          <div className="stats-grid">
            <div className="stat-card">
              <h3>Assets</h3>
              <p className="stat-value">{orgs.length}</p>
            </div>
            <div className="stat-card">
              <h3>Traces</h3>
              <p className="stat-value">{traces.length}</p>
            </div>
            <div className="stat-card">
              <h3>Org</h3>
              <p className="stat-value">{selectedOrg}</p>
            </div>
          </div>
        </section>
      </main>
    </div>
  )
}

export default App