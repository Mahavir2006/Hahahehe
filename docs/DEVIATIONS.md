# Deviations from Spec

| Spec ID | Deviation | Reason |
|---|---|---|
| RISK-01, RISK-05 | ML model training not implemented by this agent | User directed: ML model integration is handled separately |
| BC-SEC-05 | `solhint`/`slither` not run (not installed) | Linting tools not available in environment |
| BC-SEC-06 | Solidity coverage not measured (hardhat coverage not run) | Coverage plugin not available |
| DASH-11 | No Vitest/Playwright frontend tests | Test runner not configured for dashboard |
| CMD-01 | `make setup && make test && make demo && make verify-spec` not end-to-end verified | Python dependencies (pytest) not installable in environment; chain tests pass (164/164) |
| AG-INT-07 | Extraction accuracy ≥90% not independently verified | Requires pytest + ground-truth test data |
| AG-CRT-03 | Critic 10/10 red-team test not run | Requires pytest |
| CAS-04, CAS-05 | Property/fuzz tests not run | Requires hypothesis + pytest |