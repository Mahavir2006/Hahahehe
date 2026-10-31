# PS-03 completion status (branch feature/ps03-completion)

Every number below comes from a command run during this work. Simulation only: nothing sends commands to real OT equipment.

## Baseline (WP0, commit 3f2d477, before any change)

| Suite | Result |
|---|---|
| Backend `pytest backend/tests -m "not live_llm"` | **159 passed, 1 deselected** in 94 s |
| Deselected | `test_lifecycle.py::test_23_empty_and_oversized_advisories` hangs (over 4 min). Not an environment issue: `advisory_parser.extract` runs a regex with catastrophic backtracking (`([A-Z][\w+]*(?: [A-Z][\w+.]*){0,3}) version`) over the 200,000-character input. Pre-existing; not fixed (agents are out of scope) |
| Dashboard `npm test` | **No test files**: Vitest exits with code 1 |
| Dashboard `npm run build` (tsc) | **Fails**: 3 errors in `src/App.tsx` (fixed by E3) and 3 in `src/utils/canonical.ts` (pre-existing, untouched) |
| Dashboard behaviour (read, then confirmed in the browser after the fix) | Traces table always empty (`/api/traces` returns a list, the page read `data.traces`); asset count fetched for `power` only and stored as `orgs`; trace columns `advisory_id`/`started_at` do not exist |

## Final

| Suite | Result |
|---|---|
| Backend, flags off, same deselect | **198 passed, 1 deselected** (159 existing + 39 new) |
| Dashboard Vitest | **7 passed** (`src/ps03/ps03.test.tsx`, server-side render; no DOM library is installed and none was added) |
| Dashboard tsc | only the 3 pre-existing `canonical.ts` errors remain |

## Work packages

| WP | Status | Evidence |
|---|---|---|
| WP0 Baseline | done | table above; `docs/evidence/baseline_pytest_tail.txt` |
| WP1 Adapter, integer outputs | done | `backend/risk/adapter.py`, `explain.py`; `test_ps03_adapter.py` (v1 unchanged, integer repeatability, fixture v2 with a different feature list, fail closed on hash mismatch / unknown feature / missing files) |
| WP2 Real-CVE seed | done | `backend/seed_real.py`: 206 CVEs on 75 assets (56 vendor, 1 model, 18 sector_fallback). Bands at startup: 61 low, 9 medium, 5 high (was 75 low) |
| WP3 Telemetry + rules | done | `backend/detect/`; `rules_metrics.json` over 27,375 simulated asset-days: R1, R3, R4, R6 precision and recall 1.0; R5 recall 0.93; R2 precision 0.065, recall 0.91 |
| WP4 Clock, reassessor, history, trend | done | `simclock.py`, `proactive.py`, `risk/trend.py`; loop-breaker tests; `trend_metrics.json` (Holt MAE 7.5 days vs naive 21.7 on 1,162 crossing histories) |
| WP5 Routes | done | `backend/api/ps03.py`; `test_ps03_api.py` on its own Hardhat chain |
| WP6 Why / what changed | done | `explain.why`, `explain_change`; e.g. "risk 28.4 to 67.5: Exploit likelihood (EPSS-like) 0.04459 -> 0.86592; Vulnerability severity (CVSS) 8.8 -> 9.8" |
| WP8 Dashboard | done | `dashboard/src/ps03/`: Overview, Asset detail, Detections, Plans and approvals, Trust, Model card, plus the original Pipeline tab; `docs/evidence/*.jpg` |
| WP7 Containment | partial (as scoped) | Level 2 end to end in `test_ps03_api.py`: precheck, existing planner/Critic/ApprovalGate, 3 approvals, simulated execution, verification (2 blocked edges, 1 retained allow-listed path), rollback. Levels 1, 3, 4 described only |
| WP9 Verification | partial | Backend and dashboard tests run; stack walked in the browser (Overview at day 7, Asset detail, Pipeline). `scripts/verify_spec.py` and `scripts/run_demo.py` not run |
| WP10 Sensitivity | not done | skipped for time (P2) |

## Edits to existing files

| Edit | File | Change |
|---|---|---|
| E1 | `backend/risk/model.py` | `AssetCtx.extra`; `RiskModel.features` from metadata used by `likelihood`/`contributions`; `RISK_MODEL_DIR` loads through the fail-closed adapter; `features_of` merges `extra` |
| E2 | `backend/api/main.py` | one line calling `backend.api.ps03.register` (no-op unless `PS03_ENABLE=1`) |
| E3 | `dashboard/src/App.tsx` | page kept as the "Pipeline" tab with its three bugs fixed; new tab shell |
| E4 | not made | band hysteresis not implemented |

Also appended to `docs/LIMITATIONS.md`.

Runtime hooks (code lives in new files, active only on the PS-03 path): the adapter wraps `risk.apply_action` so registry features in `extra` are refreshed after each action, and adds display labels for registry features to `FACTOR_LABELS` when a v2 model loads. Level-2 plans put their telemetry finding id into `node.acked` (a provenance set the Critic already accepts), because `node.findings` must stay advisory-shaped for existing routes.

## Not done

- WP10 sensitivity analysis.
- E4 band hysteresis.
- Execution of containment levels 1, 3, 4 (described in `backend/containment.py` and on the Plans tab).
- `scripts/verify_spec.py`, `scripts/run_demo.py` not run.
- `test_23` regex hang and `canonical.ts` type errors (pre-existing, out of scope).

## Run locally

```
python -m backend.ps03_serve --port 8000      # starts/reuses Hardhat on 8545, deploys, bootstraps, sets PS03 flags
npm --prefix dashboard run dev                # http://localhost:5173
```
Optional model swap: `RISK_MODEL_DIR=backend/risk/artifacts_v2`.

## Integration onto main with the M1 model (branch feature/ps03-on-m1)

`main` (b6a1cc0) brought the teammate's M1 model (24 features, sigmoid-calibrated monotonic gradient boosting,
fail-closed loader, integer basis points, SHAP log-odds, hysteresis, M4 trend). PS-03 was merged onto it:

- `backend/risk/model.py` and `backend/risk/trend.py` are the teammate's versions; my E1 edit to model.py is dropped
  (M1 already has its own feature list, telemetry field and fail-closed loading). My Holt/EWMA over the PS-03 risk
  log moved to `backend/risk/trend_log.py`.
- `backend/risk/adapter.py` is now a thin layer over M1: `RISK_MODEL_DIR` loads M1 from another folder with M1's own
  hash and feature-schema checks; `info()` feeds the model card.
- `backend/risk/explain.py` builds on M1's `score_asset` (which already returns basis points and SHAP) and adds the
  full feature record, SHAP for every feature and the base value.
- During a PS-03 simulation the reassessor writes the PS-03 detector's 30-day aggregates into `asset.telemetry`
  (same four feature names M1 uses). They come from the PS-03 rule set, not the teammate's training rules D.
- Seeded CVEs carry `published` dates (for M1's vuln_age_days).

| Check | Result |
|---|---|
| Backend, same deselect | **217 passed, 1 deselected** (main's 182 + 35 PS-03) |
| Dashboard Vitest | 7 passed |
| Startup bands, 75 demo assets under M1 | unseeded 54 low / 19 medium / 2 high; seeded 8 low / 27 medium / 40 high (M1's bands are percentiles of its output on simulated data) |
| Demo week, power-asset-001 | the scripted KEV CVE on day 2 moves it to critical; the day-6 patch brings it back down |
