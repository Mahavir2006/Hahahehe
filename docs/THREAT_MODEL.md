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
| T-12 | **Attacker reads the chain to find targets** (anyone with RPC access, a leaked node, a block explorer, or the immutable history later) | Nothing that says *what is vulnerable* is on-chain in the clear (SEC-PRIV). Risk band/criticality, dependency strength/tolerance and alert severity/time-to-impact are salted commitments; the values are sealed (X25519 + AES-GCM) to the members that need them. Finding attestations use a blinded advisory key and a commitment, so a public advisory or CVE list cannot be hashed and looked up. Envelopes are fixed-size with unlabeled slots. | SEC-PRIV-01..05: `test_16b_nothing_sensitive_is_readable_on_chain`, Hardhat `SEC-PRIV-01/02/03`, `test_sealed_envelope_*` |
| T-13 | Relayer swaps the ciphertext under a valid signature | `keccak256(sealed)` is part of the EIP-712 struct; the contract recomputes it | Hardhat `BC-ATT-D-06 a tampered field…`, `SEC-PRIV-01` |
| T-14 | Forged or garbled disclosure | Recipients accept a value only if it opens the on-chain commitment; anything unverifiable is treated conservatively (unknown band → medium, unverified alert → high), never ignored | `_open_band` / `_open_terms` / `_alert_severity` in `cascade_agent.py`; SEC-PRIV-03 |

## What is still visible on-chain (accepted residual leakage)

| Visible | Why it stays | Mitigation / next step |
|---|---|---|
| Which orgs are members (`orgId = keccak256(name)`) and that org A depends on org B | Contracts must check a **confirmed edge** before accepting an alert ack or a challenge | Service IDs are salted hashes, so only the org pair is linkable, not which service. A production deployment could use pseudonymous org IDs per edge. |
| *When* an org attests or alerts (timestamps, counts) | Needed for audit, expiry and rate limits | Risk attestations are published on band change (AG-RSK-06); re-attesting on a fixed schedule would hide whether the band moved. |
| Repeated `dedupeKey` on alerts from the same service | De-duplication needs a stable key | It reveals "same severity as a previous alert", never which severity. |
| Ciphertext forever | Immutability | If a member's encryption key leaks later, past envelopes addressed to it can be read. Rotate keys with `setEncryptionKey`; a production design could keep envelopes off-chain and anchor only their hash. |
| Everything a **compromised member** can decrypt | Members need the shared dependency map and bands to compute the cascade | Alerts go only to direct consumers; findings go to nobody. Need-to-know scoping of bands/edges is a further step. |

## No Emergency Bypass

BC-GATE-15 explicitly states: no `emergencyIsolate` function. Break-glass is handled organisationally (off-chain process), not in code, because any code bypass would be a single point of failure.

## Out of Scope

- Connecting to real infrastructure
- Scanning real networks
- Public mainnet deployment
- Decentralisation beyond the local consortium