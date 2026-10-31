import { useState } from "react"
import { Bot, FileText, Lock, UserCheck } from "lucide-react"
import { Card, Tag } from "@/components/ui"
import { AGENTS, chain, CONTRACTS, PRIVACY, QUALITY, traces } from "@/data/derive"
import { useLive } from "@/data/live"

const short = (h: string) => `${h.slice(0, 10)}…${h.slice(-6)}`

export default function Platform() {
  const [step, setStep] = useState(0)
  useLive()
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
        <Card title="Six smart contracts" sub={`Local Hardhat chain ${chain.chainId} · ${chain.connected ? "connected" : "DISCONNECTED"} · block ${chain.block}`}>
          <ul className="contracts">
            {CONTRACTS.map((c) => (
              <li key={c.name}>
                <code>{c.name}</code>
                <span>
                  {c.does}
                  <small className="muted">
                    {" "}
                    {chain.contracts[c.name] ? `at ${short(chain.contracts[c.name])}` : "not deployed"}
                  </small>
                </span>
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

      <Card title="Live chain feed" sub={`Latest contract events on the local chain · ${chain.reassessments} risk reassessments · audit entries ${Object.entries(chain.auditLengths).map(([o, n]) => `${o} ${n}`).join(", ")}`}>
        <div className="table-wrap">
          <table className="tbl ledger">
            <thead>
              <tr>
                <th>Block</th>
                <th>Contract · event</th>
                <th>Org</th>
                <th>Transaction hash</th>
              </tr>
            </thead>
            <tbody>
              {chain.events.map((e) => (
                <tr key={e.tx + e.event}>
                  <td>{e.block}</td>
                  <td>
                    <strong>{e.contract}</strong>
                    <small>{e.event}</small>
                  </td>
                  <td>{e.org || "—"}</td>
                  <td>
                    <code className="hash" title={e.tx}>
                      {short(e.tx)}
                    </code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="muted small">Real transactions from /api/ps03/chain/live, refreshed every 8 s. Agent traces recorded: {traces.map((t) => `${t.org} ${t.count}`).join(" · ") || "none"}.</p>
      </Card>

      <Card title="Built and tested" sub="Measured on this machine (pytest run and live agent run)">
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
