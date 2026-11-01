import { useState } from "react"
import { Bot, FileText, Lock, UserCheck } from "lucide-react"
import { Card, Tag } from "@/components/ui"
import { AGENTS, CONTRACTS, PRIVACY, QUALITY } from "@/data/derive"

export default function Platform() {
  const [step, setStep] = useState(0)
  const s = AGENTS[step]
  return (
    <div className="page">
      <Card title="End-to-end flow" sub="From a new advisory to an approved, audited fix">
        <ol className="flow">
          <li>
            <FileText size={18} aria-hidden />
            <strong>Advisory arrives</strong>
            <small>CERT-In / CISA advisory, asset inventory, network telemetry</small>
          </li>
          {AGENTS.map((a, i) => (
            <li key={a.name} className={i === step ? "active" : ""}>
              <button onClick={() => setStep(i)} aria-pressed={i === step}>
                <Bot size={18} aria-hidden />
                <strong>{a.name} agent</strong>
                <small>{a.out}</small>
              </button>
              {a.name === "Critic" && (
                <span className="gate">
                  <UserCheck size={14} /> humans approve
                </span>
              )}
            </li>
          ))}
        </ol>
        <div className="agent-detail" aria-live="polite">
          <Tag tone="info">Step {step + 1} of {AGENTS.length}</Tag>
          <h3>{s.name} agent</h3>
          <p>{s.does}</p>
        </div>
      </Card>

      <div className="grid-2">
        <Card title="Six smart contracts" sub="Local Ethereum chain (Hardhat) — the shared, tamper-evident record between organisations">
          <ul className="contracts">
            {CONTRACTS.map((c) => (
              <li key={c.name}>
                <code>{c.name}</code>
                <span>{c.does}</span>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Why the blockchain does not help attackers" sub="Privacy by design (SEC-PRIV)">
          <ul className="privacy">
            {PRIVACY.map((p) => (
              <li key={p.title}>
                <Lock size={15} aria-hidden />
                <div>
                  <strong>{p.title}</strong>
                  <small>{p.body}</small>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <Card title="Built and tested" sub="From the CascadeShield repository">
        <div className="grid-stats four">
          {QUALITY.map((q) => (
            <div className="stat" key={q.label}>
              <span>{q.label}</span>
              <strong>{q.value}</strong>
            </div>
          ))}
        </div>
        <p className="muted small">Next: certificate-based login, browser-signed approvals and a live ledger view (designed in docs/LOGIN_AND_LEDGER_DESIGN.md, not built yet).</p>
      </Card>
    </div>
  )
}
