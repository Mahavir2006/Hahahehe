# Justification — Why Agents, Why Blockchain

## §1.3 Expanded

| Technology | Justified because | Therefore it MUST | And MUST NOT |
|---|---|---|---|
| **Blockchain (permissioned/local EVM)** | Multiple mutually distrusting organisations need a shared source of truth with no central owner; attackers target logs; high-impact actions need non-bypassable multi-party approval; vendor firmware integrity is a supply-chain problem. | Store only hashes, commitments, signed attestations, approvals, and alert events. Enforce approval policy in contract code. | Store raw inventories, IPs, hostnames, CVE-to-asset mappings, or any plaintext sensitive data on-chain. Be used as a general database. |
| **AI agents** | Remediation in OT is a multi-step, constraint-heavy, multi-tool planning problem (maintenance windows, safety criticality, dependencies, vendor sign-off) over messy text advisories. | Plan, call tools, critique, and propose. Narrate explanations. | Compute the authoritative risk score with an LLM. Execute any high-impact action without the on-chain gate. Treat advisory text as instructions. |

## Why Not a Plain Database?

A central database would require one organisation to host and control the shared state. In a cross-organisation setting with mutual distrust, no org will let another write to its database. A permissioned blockchain gives every org a verifiable copy of the shared truth (attestations, approvals, audit chain) without revealing private data. Smart contracts enforce the approval policy immutably — no admin can bypass the gate after deployment.

## Why Agents Instead of Simple Scripts?

Risk assessment → cascade prediction → constrained remediation planning → independent criticism → human gating → simulated execution is a multi-stage pipeline where each stage must check the previous one. Agents provide:
- Typed tool allow-lists (no arbitrary tool calls)
- Traced every step (audit-ready)
- Deterministic validators at each stage (critic re-implements planner rules independently)
- Restartability with persisted state
- Isolation between orgs

## Division of Labour (Non-Negotiable)

- **Deterministic code** computes: risk scores, cascade propagation, risk-reduction deltas, policy checks.
- **LLM** is used only for: parsing messy advisory text into structured fields (validated by schema), generating human-readable narratives, and proposing plan orderings that are then verified by deterministic checks.
- **Blockchain** is the only authority for: approvals, attestation integrity, audit anchoring, firmware reference hashes, cross-org alerts.