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
| BC-ATT-D-01, BC-ATT-D-03 | Strength/tolerance are not on-chain as enums; both sides sign the same `termsCommitment` (salt agreed in the handshake) and the values travel sealed | In the clear they give attackers the cascade map and how long each consumer survives an outage (SEC-PRIV-01) |
| BC-ATT-R-01 | `riskBand`/`criticalityBucket` replaced by `bandCommitment` + sealed band; evidence salt is now random | A plaintext band tells attackers which service is CRITICAL right now; a salt derived from guessable inputs makes the commitment brute-forceable (SEC-PRIV-01) |
| BC-ATT-F-01, BC-ATT-F-02 | `(advisoryContentHash, cveSetHash, matched)` replaced by blinded `advisoryKey` + `findingCommitment`; idempotency keys on `advisoryKey` | Advisories and CVE lists are public, so an attacker could hash them and read "org X is affected by CVE-Y" (SEC-PRIV-02) |
| BC-ALERT-01, BC-ALERT-04 | `publish(orgId, serviceHash, alertCommitment, dedupeKey, expiry, sealedPayload)`; de-dupe on a blinded key | Plaintext severity/TTI give an attacker live feedback that an attack is working (SEC-PRIV-03) |