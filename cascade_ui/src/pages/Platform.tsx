import { useState } from "react"
import { ArrowDown, Bot, FileText, Lock, UserCheck } from "lucide-react"
import { Card, Tag } from "@/components/ui"
import { AGENTS, CONTRACTS, PRIVACY, QUALITY } from "@/data/derive"

// a small hash-chained ledger so every on-chain write visibly gets its own distinct hash
function fakeHash(seed: string) {
  let h = 2166136261
  let out = ""
  for (let r = 0; r < 8; r++) {
    for (const ch of seed + r) h = Math.imul(h ^ ch.charCodeAt(0), 16777619) >>> 0
    out += h.toString(16).padStart(8, "0")
  }
  return "0x" + out
}
const WRITES = [
  ["OrgRegistry", "EncryptionKeySet", "WGEC"],
  ["AttestationRegistry", "DependencyConfirmed", "WGEC ↔ Jal Board"],
  ["AttestationRegistry", "RiskAttestationSubmitted", "commitment only"],
  ["AuditLog", "CriticVerdictAnchored", "plan RP-4492"],
  ["ApprovalGate", "ApprovalRequested", "RP-4492"],
  ["ApprovalGate", "Approved", "RP-4492 · 2 of 2"],
  ["AlertBus", "AlertPublished", "sealed → Jal Board"],
  ["AuditLog", "BatchAnchored", "Merkle root of 12 traces"],
]
const ledger = WRITES.reduce<{ i: number; contract: string; event: string; subject: string; prev: string; hash: string }[]>((acc, [contract, event, subject], i) => {
  const prev = acc[i - 1]?.hash ?? "0x" + "0".repeat(64)
  acc.push({ i: i + 1, contract, event, subject, prev, hash: fakeHash(prev + contract + event + subject) })
  return acc
}, [])
const short = (h: string) => `${h.slice(0, 10)}…${h.slice(-6)}`

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

      <Card title="Audit ledger" sub="Each write links to the previous hash and gets its own — change any entry and every later hash breaks">
        <div className="table-wrap">
          <table className="tbl ledger">
            <thead>
              <tr>
                <th>#</th>
                <th>Contract · event</th>
                <th>Subject (public)</th>
                <th className="hide-sm">Previous hash</th>
                <th>Entry hash</th>
              </tr>
            </thead>
            <tbody>
              {ledger.map((e) => (
                <tr key={e.i}>
                  <td>{e.i}</td>
                  <td>
                    <strong>{e.contract}</strong>
                    <small>{e.event}</small>
                  </td>
                  <td>{e.subject}</td>
                  <td className="hide-sm">
                    <code>{short(e.prev)}</code>
                  </td>
                  <td>
                    <code className="hash">{short(e.hash)}</code>
                    <ArrowDown size={11} className="muted" aria-hidden />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="muted small">Illustrative entries for the demo; the live system computes these from contract events on the local chain.</p>
      </Card>

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
