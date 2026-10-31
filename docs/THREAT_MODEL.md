# Threat Model

## Threats and Controls

| # | Threat | Control | Test |
|---|---|---|---|
| T-01 | Compromised agent signer | Agent signer can only submit signed attestations and approval requests; cannot vote on approvals (BC-GATE-06); cannot execute without chain-verified approval (AG-ACT-02) | BC-GATE-06 agent cannot approve; AG-ACT-02 gate checks |
| T-02 | Compromised single approver | Threshold M required for HIGH actions; safety officer subset required; snapshot semantics prevent retroactive changes | BC-GATE-05 HIGH needs M + safety officer |
| T-03 | Colluding approvers < M | Cannot reach threshold without safety officer for HIGH; rejections can force terminal Rejected | BC-GATE-07 safety officer reject → Rejected |
| T-04 | Malicious org lying in attestations | Bilateral confirmation required for dependency edges (BC-ATT-D-01); challenge mechanism flags disputed risk attestations (BC-SEC-08) | BC-ATT-D-01 one-sided stays unconfirmed; BC-SEC-08 challenge |
| T-05 | Replayed signatures | Per-signer nonces; EIP-712 domain includes chain ID and contract address | BC-ATT-D-06 replay rejected |
| T-06 | DoS by spam | Rate limits on risk attestations (BC-ATT-R-03) and alerts (BC-ALERT-06); max pending approvals per org (BC-GATE-10) | BC-ATT-R-03 rate limit tested |
| T-07 | Front-running of approvals | No sensitive data in approval requests; only plan hash and critic digest stored | BC-GATE-02 plan hash on-chain |
| T-08 | Prompt injection → malicious request | Five-layer defence: delimiting, schema-constrained outputs, allow-listed tools, deterministic validators, no agent writes to approval gate | AG-INT-02 injection tests |
| T-09 | Tampered traces | Hash-chained audit log; Merkle batches; verify detects first mismatch index | BC-AUD-02 hash chaining; BC-AUD-07 verify |
| T-10 | Unauthorised cross-org access | PrivateStore isolation; API org scoping; no inter-org filesystem or API access | AG-TOP-05 isolation test; API-02 isolation test |
| T-11 | Censorship by block producer | Documented as out-of-scope for local dev chain; in production, sequencing would be managed by consortium | BC-SEC-04 documents ±15s timestamp tolerance |

## No Emergency Bypass

BC-GATE-15 explicitly states: no `emergencyIsolate` function. Break-glass is handled organisationally (off-chain process), not in code, because any code bypass would be a single point of failure.

## Out of Scope

- Connecting to real infrastructure
- Scanning real networks
- Public mainnet deployment
- Decentralisation beyond the local consortium