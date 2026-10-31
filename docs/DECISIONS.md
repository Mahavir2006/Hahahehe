# Architecture Decisions

| Decision | Why |
|---|---|
| Python 3.14 backend with web3.py | Spec requires Python ≥3.11; web3.py is the standard Ethereum Python library |
| Hardhat + Solidity 0.8.24 | Spec fixes the stack; local EVM for development/testing |
| EIP-712 typed-data signing for attestations | OpenZeppelin standard; enables off-chain signing with on-chain verification |
| No `emergencyIsolate` in ApprovalGate | BC-GATE-15: break-glass is organisational, not in code |
| Deterministic offline LLM provider | AG-LLM-03: all tests and demo must pass without network |
| Intake → Risk → Cascade → Planner → Critic → Gate → Execute pipeline | Spec §5.1 agent topology |
| OrgNodeRuntime with PrivateStore isolation | AG-TOP-05: org A cannot read org B's private data |
| Canonical JSON for all digests | BC-AUD-08: cross-language hash consistency (Python ↔ TypeScript) |
| Merkle-batched trace anchoring | BC-AUD-03: gas-efficient batching of many traces |
| No ML model training in this agent's scope | User-directed: ML model integration is handled separately |