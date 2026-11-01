# CascadeShield - AI-Based Critical Infrastructure Cyber-Risk Prediction

Cross-organisation cascade-risk prediction with verifiable AI agents and blockchain-anchored audit trail.

## Overview

CascadeShield implements the **D3COY PS-03** specification for cross-organisation cascade-risk prediction with verifiable AI agents. It combines:

- **AI Agent Layer**: 6 specialized agents (Intake, Risk, Cascade, Planner, Critic, Executor) orchestrated via a state machine
- **Blockchain Layer**: 6 smart contracts (OrgRegistry, AttestationRegistry, AuditLog, ApprovalGate, FirmwareRegistry, AlertBus) on local Hardhat network
- **Deterministic Operations**: Works fully offline with deterministic LLM provider for reproducible testing
- **Privacy-Preserving**: Organizations never share private inventory. The chain holds only commitments; risk bands, dependency terms and alert severity travel as sealed envelopes that only the intended members can open, so the ledger never becomes a target list for attackers

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      CASCADESHIELD                          │
├─────────────────────┬─────────────────────┬─────────────────┤
│    AI AGENT LAYER   │   BLOCKCHAIN LAYER  │   DATA LAYER    │
├─────────────────────┼─────────────────────┼─────────────────┤
│  • Intake Agent     │  • OrgRegistry      │  • Simulated    │
│  • Risk Agent       │  • AttestationReg   │    Inventories  │
│  • Cascade Agent    │  • AuditLog         │  • Advisories   │
│  • Planner Agent    │  • ApprovalGate     │  • Firmware     │
│  • Critic Agent     │  • FirmwareReg      │    Catalog      │
│  • Executor Agent   │  • AlertBus         │  • Incidents    │
│  • Orchestrator     │                     │                 │
└─────────────────────┴─────────────────────┴─────────────────┘
```

## Quick Start

### Prerequisites
- Node.js ≥ 18
- Python ≥ 3.11
- npm

### Installation

```bash
make setup              # Python + Node dependencies, contracts, data, model
```

### Run it

```bash
make demo               # 14-step end-to-end demo on its own local chain; exits 0 only if all 26 checks pass
```

```bash
python scripts/serve.py --headline   # chain + 3 org nodes + API on http://127.0.0.1:8000, headline advisory ingested
```

```bash
cd cascade_ui && npm install && npm run dev   # UI on http://localhost:8443
```

The UI (`cascade_ui/`) has eight sections, each tied to a PS-03 objective: Overview (live threat map of India),
Assets & Vulnerabilities, Risk Prediction (SHAP "why" and the model evidence), Cascade Simulator (compromise an
asset and watch the failure spread, with and without containment), Proactive Scenarios (threats that have not
happened yet, plus a week replay), Recommendations (ranked preventive actions with two-person approval), Incident
Response (isolate or apply a plan, notify and assign teams, track each step) and Audit Trail (hash-chained log with
verify and tamper test). It runs on simulated demo data and is not yet wired to the API.

### Test and verify

```bash
make test               # Hardhat contract tests + backend tests (unit, end-to-end on a live chain, API)
```

```bash
make ml-all             # rebuild the ML data, retrain, evaluate; every number in docs/ML_REPORT.md
```

```bash
make verify-spec        # requirement traceability
```

### Machine learning

M1 predicts each asset's probability of compromise in the next 90 days (gradient boosting with monotonic
constraints, calibrated, explained with SHAP); impact, final risk and the cascade stay deterministic. It is trained
on simulated assets whose CVE context is real (CISA OT advisories, CISA KEV, NVD) and whose compromise labels are
synthetic. See `docs/ML_REPORT.md` for every metric, `docs/ML_DECISIONS.md` for every choice, and
`docs/LIMITATIONS.md` for what this does not show.

## Project Structure

```
Decoy/
├── chain/                    Solidity contracts (6), Hardhat tests, deploy + seed scripts
├── backend/
│   ├── agents/               intake, risk, cascade, planner, critic, executor, orchestrator, org node runtime
│   ├── api/main.py           FastAPI (org-scoped by X-Dev-Role)
│   ├── common/               chain client + writer, sealed disclosures (sealed.py), audit, Merkle, events
│   ├── graph/cascade.py      intra-org and cross-org cascade engines (deterministic)
│   ├── risk/                 M1 features, training, inference, evaluation, detection rules D, trend M4, artifacts
│   ├── system.py             wires chain, indexer and the three org nodes
│   └── tests/                unit, end-to-end on a live chain, API
├── cascade_ui/               React + Vite UI: threat map, cascade simulator, scenarios, response, audit
├── data/
│   ├── real/, real_extra/    CISA CSAF OT advisories, CISA KEV, FIRST EPSS, NVD (checksummed)
│   ├── orgs/, advisories/    the three demo organisations and sample advisories
│   ├── ml_population.py, label_process.py, telemetry.py, build_ml_dataset.py, ml/   M1 training data
│   └── oracle_ceiling.py     accuracy-ceiling analysis
├── evaluation/               offline evaluations: rigorous metrics, M3 leakage adversary, M4 backtest, sensitivity
├── scripts/                  run_demo.py, serve.py, verify_spec.py, data fetch/build scripts
└── docs/                     architecture, threat model, limitations, ML report and decisions, diagrams
```

## Key Features

### AI Agents
- **Intake**: Parses messy advisories → structured findings with injection defense
- **Risk**: calibrated, monotonic gradient-boosted likelihood (M1) x deterministic impact, SHAP explanations, band hysteresis
- **Cascade**: Intra-org (NetworkX) + cross-org (on-chain attestations)
- **Planner**: Constraint-satisfying remediation plans (maintenance windows, vendor signoff, dependencies)
- **Critic**: Independent validation (10/10 adversarial test cases)
- **Executor**: Simulated execution with on-chain approval verification

### Blockchain Contracts
1. **OrgRegistry** - Organization identity, roles, key rotation
2. **AttestationRegistry** - Dependency (bilateral), Risk, Finding attestations
3. **AuditLog** - Hash-chained audit trail with Merkle batching
4. **ApprovalGate** - Human-in-the-loop with snapshot semantics
5. **FirmwareRegistry** - Supply-chain integrity verification
6. **AlertBus** - Cross-org early warning with confirmed edges only

### Security
- 5-layer prompt injection defense
- EIP-712 signed attestations with replay protection
- Confidential on-chain data: salted commitments + X25519/AES-GCM sealed disclosures (see `docs/THREAT_MODEL.md` T-12)
- Hash-chained audit log with Merkle inclusion proofs
- Snapshot semantics for approvals (immutable approver sets)
- Agent cannot approve or execute without on-chain gate

### Offline-First
- All LLM calls work with deterministic offline provider
- Full test suite runs without internet
- Reproducible with fixed seed (42)

## Testing

```bash
# All tests
make test

# Contract tests only
make test-chain

# Backend tests
make test-backend

# UI type-check and production build
make test-ui
```

## Demo

The automated 14-step demo (`make demo`) executes:
1. Chain startup, deployment, seeding
2. Bilateral dependency handshakes
3. Baseline risk attestations
5. Firmware supply-chain check
5. Headline advisory ingestion
6. Risk scoring → CRITICAL
7. Cross-org cascade (power→water→hospital)
8. Plan generation + Critic approval
9. HIGH impact approval flow
10. Execution + re-scoring (delta match)
11. Injection attack neutralization
12. Audit tamper detection
13. Bypass attempt rejection
14. Final checklist

## Specification Compliance

Run `make verify-spec` to verify:
- All MUST requirements have passing tests
- Solidity coverage ≥ 95% lines / 90% branches
- ML AUC ≥ 0.80
- Intake extraction accuracy ≥ 90%
- Critic catches 10/10 adversarial plans
- Zero untested MUST requirements

## Documentation

- `AGENTS_AND_BLOCKCHAIN_SPEC.md` - Complete specification
- `docs/VERIFICATION_REPORT.md` - Generated traceability report
- `docs/ARCHITECTURE.md` - System architecture
- `docs/DEMO_SCRIPT.md` - Demo narration
- `docs/THREAT_MODEL.md` - Security analysis

## License

Proprietary - D3COY PS-03 Project