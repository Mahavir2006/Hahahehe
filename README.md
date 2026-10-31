# CascadeShield - AI-Based Critical Infrastructure Cyber-Risk Prediction

Cross-organisation cascade-risk prediction with verifiable AI agents and blockchain-anchored audit trail.

## Overview

CascadeShield implements the **D3COY PS-03** specification for cross-organisation cascade-risk prediction with verifiable AI agents. It combines:

- **AI Agent Layer**: 6 specialized agents (Intake, Risk, Cascade, Planner, Critic, Executor) orchestrated via a state machine
- **Blockchain Layer**: 6 smart contracts (OrgRegistry, AttestationRegistry, AuditLog, ApprovalGate, FirmwareRegistry, AlertBus) on local Hardhat network
- **Deterministic Operations**: Works fully offline with deterministic LLM provider for reproducible testing
- **Privacy-Preserving**: Organizations never share private inventory; only on-chain attestations are shared

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
# Install all dependencies
make setup

# Start local blockchain (in separate terminal)
make chain

# Deploy contracts
make deploy

# Run all tests
make test

# Run automated demo
make demo

# Verify specification compliance
make verify-spec
```

### Development

```bash
# Start backend API
cd backend && uvicorn api.main:app --reload

# Start dashboard
cd dashboard && npm run dev

# Start Hardhat node
make chain
```

## Project Structure

```
Decoy/
├── AGENTS_AND_BLOCKCHAIN_SPEC.md   # Complete specification
├── PROGRESS.md                     # Build progress tracker
├── Makefile                        # Build commands
├── requirements.txt                # Python dependencies
├── .env.example                    # Environment template
├── chain/                          # Smart contracts (Hardhat)
│   ├── contracts/                  # 6 Solidity contracts
│   ├── scripts/                    # Deploy & seed scripts
│   └── test/                       # Hardhat tests
├── backend/                        # Python backend
│   ├── common/                     # Shared utilities
│   │   ├── crypto.py              # Canonical JSON, EIP-712, Merkle
│   │   ├── chain_client.py        # Web3 contract client
│   │   ├── chain_writer.py        # Idempotent writes, nonce mgmt
│   │   ├── event_indexer.py       # Blockchain event indexing
│   │   └── audit_anchor.py        # Merkle batch anchoring
│   ├── agents/                    # AI agents
│   │   ├── intake_agent.py        # Advisory parsing + injection defense
│   │   ├── risk_agent.py          # ML/heuristic risk scoring
│   │   ├── cascade_agent.py       # Intra/cross-org cascade
│   │   ├── planner_agent.py       # Constraint-based planning
│   │   ├── critic_agent.py        # Plan validation
│   │   ├── executor_agent.py      # Simulated execution
│   │   └── base_agent.py          # Shared infrastructure
│   ├── api/                       # FastAPI REST + SSE
│   └── common/schemas.py          # Pydantic models
├── dashboard/                      # React + Vite dashboard
│   ├── src/
│   └── package.json
├── data/                          # Data generation
│   ├── generate_dataset.py        # Deterministic dataset (seed 42)
│   └── orgs/                      # Generated org data
├── scripts/
│   ├── run_demo.py               # 14-step automated demo
│   └── verify_spec.py            # Traceability gate
└── docs/                          # Generated documentation
```

## Key Features

### AI Agents
- **Intake**: Parses messy advisories → structured findings with injection defense
- **Risk**: Gradient-boosted scoring + SHAP explanations
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

# Dashboard tests
make test-dashboard
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