# Certificate login and live ledger: design

**Status: design only. Nothing in this document is implemented yet.** It records the agreed idea so it can be built
later on top of whichever dashboard and API the team keeps after combining the two integration branches. An
interactive mock-up of this flow was reviewed in the planning session; this file is its written specification.

## 1. Why

Today the dashboard picks a role from a dropdown and sends an `X-Dev-Role` header. The API trusts that header, so
anyone can claim to be any organisation's operator. That is fine for tests and wrong for a demo about trust.

The design replaces the header with **certificate-based login anchored on the blockchain**, and adds a **live ledger
panel** that shows every on-chain write with its own distinct hash. It gives judges three things to see:

1. Identity is proved, not claimed: a person proves they hold a key, and the chain says what that key may do.
2. Even the dashboard and the server cannot approve a high-impact action: only the approver's own key, used in their
   own browser, can.
3. The ledger is tamper-evident and leaks nothing sensitive: every entry is a unique hash, and the stored fields
   are commitments and ciphertext, never a risk band or a severity.

## 2. Overview

```
demo start ──► demo CA + one credential file per persona (expires in 8 h)
                         │
browser ──► pick credential file + password ──► decrypt key locally ──► sign one-time challenge
                         │
server  ──► check CA signature, expiry, revocation ──► recover signer address
        ──► ask OrgRegistry (on-chain): is this address an approver / operator / admin of that org?
        ──► session cookie: role and org come from the chain, not from the file
                         │
approver ──► signs the EIP-712 Vote in the browser ──► server relays ApprovalGate.approveWithSigs
                         │
dashboard ledger panel ──► every on-chain write: entry hash, previous hash, transaction hash, public fields
```

## 3. Credential file ("temporary cert in a file")

One file per persona, for example `demo-certs/power-safety-officer.cs-cred.json`:

```json
{
  "version": 1,
  "persona": "power-safety-officer",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n…",
  "keystore": { "...": "Ethereum keystore v3 (scrypt + AES-128-CTR), password-protected" },
  "address": "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
  "issued_at": "2026-11-01T10:00:00Z",
  "expires_at": "2026-11-01T18:00:00Z"
}
```

| Part | What it is | Why |
|---|---|---|
| `certificate_pem` | X.509 certificate issued by the demo CA. Subject: `CN=<persona>`, `O=<org>`, `OU=<role>`. A custom extension or SAN carries the Ethereum address. Valid 8 hours. | A standard identity document judges recognise; binds the key to an org and role claim. |
| `keystore` | The persona's secp256k1 private key in Ethereum keystore v3 format, encrypted with the demo password. | The browser decrypts it with `ethers` (already a dashboard dependency) and signs; the key never leaves the browser. |
| `address` | The key's Ethereum address. | Must match an address registered in `OrgRegistry`; the server re-derives it from the signature anyway. |

The keys are the existing dev keys in `data/orgs/<org>/private_keys.dev.json`, so the same addresses are already
registered on the local chain as each org's admin, agent signer and approvers. No extra on-chain setup is needed.

Why a file and not browser client certificates (mTLS): installing client certificates differs per operating system
and browser and is fragile on stage. A file plus a password works everywhere and is easy to show.

### Demo CA

- Generated fresh on every demo start with the `cryptography` package: a self-signed root
  `CascadeShield Demo Consortium CA`, valid for the demo day only.
- The CA private key stays in server memory (or a git-ignored folder) and is discarded at shutdown.
- Certificates and credential files go to `demo-certs/` (git-ignored). The demo password is printed in the terminal
  and labelled as demo-only.

## 4. Login protocol

```
Browser                                Server                              Blockchain
  │ 1. POST /api/auth/challenge          │                                    │
  │ ───────────────────────────────────► │ 2. nonce (32 random bytes),        │
  │ ◄─────────────────────────────────── │    expires in 60 s, single use     │
  │ 3. decrypt keystore with password    │                                    │
  │    sign EIP-191 message:             │                                    │
  │    "CascadeShield login\n<nonce>\n<origin>"                               │
  │ 4. POST /api/auth/login              │                                    │
  │    {certificate_pem, signature}      │                                    │
  │ ───────────────────────────────────► │ 5. certificate signed by demo CA?  │
  │                                      │    within validity? not revoked?   │
  │                                      │ 6. recover address from signature  │
  │                                      │    == certificate address?         │
  │                                      │    nonce unused and unexpired?     │
  │                                      │ 7. role lookup ──────────────────► │ OrgRegistry
  │                                      │    isOrgApprover / isOrgSafety-    │
  │                                      │    Officer / isOrgAgent / admin    │
  │                                      │ ◄───────────────────────────────── │
  │ 8. Set-Cookie: session (HttpOnly,    │                                    │
  │    SameSite=Strict, 30 min)          │                                    │
  │ ◄─────────────────────────────────── │                                    │
```

Rules:

- The role in the session comes from step 7 (the chain), never from the certificate's `OU` field alone. A certificate
  claiming "safety officer" for an address that is not a registered safety officer gets the role the chain says, or
  is refused.
- Each nonce is single-use and expires after 60 seconds (no replay).
- The signed message includes the page origin, so a signature captured on another site cannot be reused here.
- Every login attempt, successful or not, is written to the audit trail (anchored in the next Merkle batch).

### Proposed endpoints

| Method and path | Body | Returns |
|---|---|---|
| `POST /api/auth/challenge` | none | `{nonce, expires_at}` |
| `POST /api/auth/login` | `{certificate_pem, signature}` | session cookie; `{persona, org, role, address, expires_at}` |
| `POST /api/auth/logout` | none | clears the session |
| `GET /api/auth/me` | none | the current session's persona, org and role |
| `POST /api/approvals/{rid}/signed-vote` | `{signature}` (EIP-712 `Vote`) | relays `ApprovalGate.approveWithSigs`; returns the transaction hash |
| `GET /api/ledger?limit=` | none | ledger entries (section 7) |

`X-Dev-Role` stays available only when an explicit developer flag is set (`CASCADESHIELD_DEV_ROLES=1`), so the
existing tests keep working; it is off in demo mode.

## 5. Approvals signed in the browser

`ApprovalGate` already supports signed votes:

- `VOTE_TYPEHASH = keccak256("Vote(bytes32 requestId,bool approve)")`, EIP-712 domain
  `{name: "ApprovalGate", version: "1", chainId, verifyingContract}`.
- `approveWithSigs(requestId, voters[], sigs[])` recovers each signer and casts the vote as that address.
- The contract refuses votes from an org's agent signer (`AgentCannotVote`) and from addresses that are not
  approvers of that org; HIGH-impact requests still need M approvals including a safety officer (snapshot rules
  unchanged).

Flow: the approver opens the request, the dashboard shows the plan hash, impact and predicted risk drop, the browser
signs the `Vote` with the key from the credential file, and the server relays it (any account can relay; the vote
counts for the signer only). The response shows the transaction hash. The server never holds approver keys in demo
mode, so a compromised server cannot approve anything.

## 6. Personas and permissions

| Persona | On-chain identity | Can | Cannot |
|---|---|---|---|
| Power SOC analyst | power operator (human, not an approver) | see power's assets, risk and plans; ingest advisories; execute after approval | approve (not an approver); see other orgs' private data |
| Power safety officer | power approver with the safety-officer flag | review and sign approvals for power | ingest or execute |
| Power approver #2, #3 | power approvers | sign approvals | count as the safety officer |
| Water operator | water operator | see water's data; receive and acknowledge early warnings | read power's assets (403) |
| Hospital operator | hospital operator | see hospital data | read other orgs' private data |
| Consortium admin | registry admin | cross-org overview, audit verification, rotate or revoke keys | approve another org's plans |
| Outsider | no credential | public view: the ledger as any chain reader sees it | anything private |

Note: the current contracts register each org's admin, one agent signer and three approvers. A separate human
"operator" address is not registered today; the build either adds an operator list to `OrgRegistry` or maps the
analyst persona to the org admin address. That choice is recorded as an open decision (section 11).

## 7. Live ledger: a distinct hash for every on-chain write

Every time the system writes to the chain, the dashboard ledger panel shows a new entry:

| Field | Meaning |
|---|---|
| `#n` | position in the ledger |
| contract.event | for example `AttestationRegistry.RiskAttestationSubmitted`, `AlertBus.CascadeAlert`, `ApprovalGate.Approved`, `AuditLog.Anchored` |
| by | the address that signed the write |
| entry hash | `keccak256(previous entry hash ‖ this entry's canonical data)` |
| previous hash | the entry hash of `#n-1` (zero for the first entry) |
| transaction hash and block | the real transaction that carried the write, from the event indexer |
| public fields | exactly what any chain reader sees: service hashes, commitments, sealed ciphertext, plan hashes |

Why every hash is different:

- The entry hash covers the previous entry's hash, so entries form a chain. Two entries can never share a hash, and
  editing any old entry changes every hash after it.
- Commitments use a fresh random salt each time, so the same value ("critical") gives a different commitment every
  time and cannot be guessed by hashing candidate values.
- Transaction hashes are unique per transaction by construction.

The panel shows a live check that all entry and transaction hashes are unique, a "Verify chain" button that
recomputes every entry hash from its data, and (in demo mode) a "Tamper with an entry" button that edits one stored
entry so the next verification reports the exact broken position.

Relation to what exists: the per-org `AuditLog` contract already hash-chains its anchors on-chain (`prevDigest`,
`verifyChain`), and the backend already verifies traces against it. The new panel adds a consortium-wide, real-time
view of all contracts' writes, built from the event indexer, with the same chaining rule and per-entry hashes shown.

## 8. Demo script for judges (about 6 minutes)

1. One command starts the chain, the three org nodes, the API and the dashboard, and prints: credentials written to
   `demo-certs/`, demo password, expiry time.
2. Sign in as the **power SOC analyst**. All assets are calm. Press "Simulate CERT-In advisory". The substation
   gateway turns critical; "Why" shows the KEV-listed CVE as the top driver. The ledger gains the finding, risk,
   alert, critic-verdict and approval-request entries, each with its own hash.
3. Infrastructure map: run the cascade. Water is hit in about 35 minutes, the hospital in about 70.
4. In a second window, sign in as the **water operator**. The early warning has arrived; acknowledging it raises
   water's own band. Opening a power asset's URL returns 403.
5. Sign in as the **power safety officer**. Approve the plan; the browser signs and the ledger shows the vote's
   transaction hash.
6. Back as the analyst: try to approve your own plan (refused), then **execute**. Risk drops exactly as predicted;
   the execution and audit anchor appear in the ledger.
7. Attacks, live: an edited certificate (CA signature fails), an expired certificate (refused), a replayed login
   (nonce already used), an outsider view (only hashes, commitments and ciphertext).
8. Admin: "Verify chain" (all green), then "Tamper", then "Verify chain" again (exact entry reported).
9. Optional: the admin rotates the safety officer's key in `OrgRegistry`; the old credential can no longer sign in.

## 9. Threats and how the design handles them

| Threat | Handling |
|---|---|
| Faked role header | `X-Dev-Role` disabled in demo mode; roles come from the chain |
| Edited certificate | CA signature check fails |
| Expired or revoked certificate | validity and revocation list checked at every login |
| Stolen credential file | useless without the password; short expiry; admin can rotate the key on-chain |
| Replayed login signature | single-use nonce with a 60-second expiry, origin bound into the message |
| Compromised server | holds no approver keys; cannot sign votes; the contract enforces approval rules |
| Agent tries to vote | `ApprovalGate` refuses the agent signer (`AgentCannotVote`) |
| Operator approves their own plan | the operator is not a registered approver; the contract refuses |
| Cross-org data access | API checks the session's org on every org-scoped route |
| Ledger tampering | hash chain verification reports the first broken entry; on-chain `AuditLog.verifyChain` agrees |
| Chain reader learns vulnerabilities | public fields are commitments and ciphertext only (SEC-PRIV) |

## 10. Guardrails

- Demo-only identities: a new CA and new credentials on every run, 8-hour expiry, git-ignored output folder.
- No real passwords, accounts or third-party identity providers are involved.
- The dev keys are the existing local-chain test keys; they must never be used on any other network.

## 11. Implementation plan (for later)

| Piece | Where | Size |
|---|---|---|
| Demo CA and credential generator | `backend/auth/ca.py`, called by the launcher | half a day |
| Challenge, login, logout, session, on-chain role lookup | `backend/auth/session.py`, API routes | half a day |
| Replace `X-Dev-Role` with the session (dev flag keeps the header for tests) | `backend/api` | a few hours |
| Signed-vote relay | API route calling `approveWithSigs` | a few hours |
| Ledger endpoint (indexer events + entry-hash chain) | API route | a few hours |
| Login screen, keystore decrypt and signing, persona badge, outsider view | dashboard | half a day |
| Ledger panel with uniqueness check, verify and tamper | dashboard | a few hours |
| Tests: good login, forged, expired, revoked, wrong org, replayed nonce, self-approval, agent vote, ledger verify and tamper | `backend/tests` | half a day |

Open decisions before building:

1. Which dashboard and API structure to build on, after combining the two integration branches (`ml-models` and the
   current `main`).
2. How to represent a human operator who is not an approver: add an operator list to `OrgRegistry`, or map the
   analyst persona to the org admin address.
3. Whether login attempts are anchored individually or in the regular Merkle batches.
