# Demo Script — 14 Steps

Presenter's narration for `make demo` (`scripts/run_demo.py`). Each step maps to a spec requirement ID.

## Step 1 — Start chain, deploy, seed, generate data, start 3 org nodes, API, indexer
**What the audience sees:** Hardhat node starts, six contracts deploy, three orgs register, firmware catalog publishes.
**Talking point:** "We're on a permissioned local chain — no public network, no real keys."
**Spec:** CMD-01, DEMO-01

## Step 2 — Bilateral dependency handshake
**What the audience sees:** Power↔water, water↔hospital, power↔hospital edges confirmed on-chain. One extra edge attested by only one side stays unconfirmed.
**Talking point:** "Cross-org edges need both sides to attest — one org can't unilaterally create a dependency."
**Spec:** BC-ATT-D-01, BC-ATT-D-02, AG-CAS-04

## Step 3 — Baseline risk attestations
**What the audience sees:** All three orgs publish service-level risk bands on-chain.
**Talking point:** "Only service-level bands go on-chain — never asset details."
**Spec:** BC-ATT-R-01, AG-RSK-06

## Step 4 — Firmware supply-chain check
**What the audience sees:** Tampered assets flagged as `Mismatch` across all orgs.
**Talking point:** "Supply-chain integrity is verifiable on-chain — tampered firmware is detected."
**Spec:** BC-FW-05, BC-FW-06, DATA-FW-01

## Step 5 — Ingest headline advisory
**What the audience sees:** Advisory affecting a substation gateway in the power org is ingested, parsed, matched to assets, and attested.
**Talking point:** "Intake parses messy advisory text and matches it to our own inventory only."
**Spec:** AG-INT-01, AG-INT-04, AG-INT-08

## Step 6 — Risk agent scores → critical
**What the audience sees:** The affected asset scores `critical`; risk attestation updated on-chain.
**Talking point:** "Numbers come from the deterministic model, not the LLM."
**Spec:** AG-RSK-01, AG-RSK-02, AG-RSK-06

## Step 7 — Cascade agent computes cross-org chain
**What the audience sees:** Cascade propagates power→water→hospital; AlertBus alert published; water and hospital agents acknowledge and re-run locally.
**Talking point:** "The cascade stays within confirmed attestations — unconfirmed edges are listed but never used."
**Spec:** AG-CAS-02, AG-CAS-04, AG-CAS-05, AG-CAS-06

## Step 8 — Planner produces plan; Critic passes
**What the audience sees:** Plan with alternatives; risk reduction e.g. 82→41; critic verdict `APPROVE_FOR_GATE` anchored on-chain.
**Talking point:** "The critic independently re-validates every constraint — it doesn't trust the planner."
**Spec:** AG-PLN-01, AG-PLN-05, AG-CRT-01, AG-CRT-04

## Step 9 — HIGH step → approval gate
**What the audience sees:** Plan includes a HIGH step (segment network); requestApproval called; simulated approvers vote until threshold M met incl. safety officer.
**Talking point:** "No high-impact action happens without human approval — the agent cannot bypass the gate."
**Spec:** BC-GATE-04, BC-GATE-05, AG-CRT-05

## Step 10 — Executor verifies, executes, re-scores
**What the audience sees:** Executor checks on-chain approval, applies simulated actions, marks executed, re-scores — actual delta equals predicted delta.
**Talking point:** "The gate is non-bypassable: executor queries the chain before acting."
**Spec:** AG-ACT-02, AG-ACT-03, BC-GATE-08

## Step 11 — Prompt-injection advisories
**What the audience sees:** Two injection advisories ingested; `injection_suspected=true`; no unauthorised tool calls or chain writes.
**Talking point:** "Five layers of injection defence keep the agent on leash."
**Spec:** AG-INT-02, AG-INT-03, AG-SAF-01

## Step 12 — Tamper demonstration
**What the audience sees:** A local trace file is modified; `verify_audit` fails at the exact index; restoring fixes it.
**Talking point:** "Every trace is hash-chained on-chain — tampering is detectable at the exact entry."
**Spec:** BC-AUD-02, BC-AUD-07

## Step 13 — Bypass attempts
**What the audience sees:** Agent signer tries to `approve` → reverts. Tries `markExecuted` without approval → reverts.
**Talking point:** "The agent is not an approver. The executor won't act without an approved gate request."
**Spec:** BC-GATE-06, AG-ACT-02

## Step 14 — Final PASS/FAIL checklist
**What the audience sees:** Checklist mapping all 14 steps to requirement IDs, all passing.
**Spec:** DEMO-01, INT-01