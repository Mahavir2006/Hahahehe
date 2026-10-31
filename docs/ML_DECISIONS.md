# ML decisions

Decisions taken where the build prompt left a choice. Each lists the decision, the alternatives and why.
The pass criteria in section 1 were written **before** the first training run and were not changed afterwards.

## 1. Pass criteria (fixed before training)

| # | Criterion | Kind |
|---|---|---|
| P1 | Leakage audit passes: no feature constant within a label class or perfectly separating the classes; no CVE/KEV date after t; no telemetry outside [t-30, t) | hard gate (build fails) |
| P2 | Determinism: two trainings with the same seed give the same `model_version`, the same artifact sha256 and identical predictions | hard gate |
| P3 | M1 PR-AUC on the held-out grouped split of generator A is above B3 (logistic regression) | reported; failing it is a finding, not a blocker |
| P4 | M1 ROC-AUC on held-out A is reported against the spec target 0.80; it is not a tuning goal | reported |
| P5 | Calibrated expected calibration error (ECE) on the test split is no worse than uncalibrated | reported |
| P6 | Monotonicity: sweeping each constrained feature never lowers the predicted likelihood (0 violations on 300 sampled test rows) | hard gate for the shipped model |
| P7 | Generator B AUC is reported next to generator A; no target | reported |

## 2. Decisions

| Decision | Alternatives | Why |
|---|---|---|
| Row = one asset in one 90-day window, features as of the window start t | per-asset rows; per-CVE rows | Given in the prompt; matches how the dashboard ranks assets |
| Population: generator A 2,000 assets x 8 windows = 16,000 rows; generator B 800 assets x 8 windows = 6,400 rows (different assets, different seed) | train on the 75 demo assets | Prompt range 10,000-20,000; demo assets are for inference only |
| CVE context drawn from the real CISA CSAF snapshot, matched by sector and product keyword; sector-only fallback when fewer than 5 keyword matches | fully synthetic CVEs | Real CVSS, release dates and KEV membership; match counts reported in `data/ml/MANIFEST.json` |
| EPSS feature = proxy `estimate_epss(cvss, known_exploited_at_t)` (`epss_source = proxy`) | the real `data/real/epss.jsonl` | The real file is dated 2026-10-30 and marked `time_matched: false`; using it for 2024-2025 windows would leak future information |
| Several CVEs on one asset: max CVSS, max EPSS proxy, count, any-KEV, age of oldest | mean; sum | Worst open flaw drives exploitability; tested |
| Missing CVSS/EPSS: value set to fallback 0.0 plus a `missing_*` flag; 3% / 8% of vulnerable rows have simulated feed gaps so the path is exercised | impute 5.0 silently (old behaviour) | A gap must not look like a real low-severity flaw |
| Asset type: ordinal code with an explicit `unknown` level (3% of training assets); unseen types map to `unknown` | one-hot | Keeps SHAP output readable; HistGradientBoosting treats it as categorical |
| Hidden factors in generator A: insider access, phishing exposure (IT/DMZ only), vendor remote-access hygiene, plus a sector-window campaign term; generator B: supplier compromise, insider access, targeted actor on critical assets, a stronger campaign term | fewer hidden factors | Prompt asks for at least 3 hidden factors per generator; names appear only in `data/label_process.py` |
| Label noise: 6% (A), 7% (B) of labels flipped | none | Prompt range 5-8% |
| Base compromise rate 12% before flipping (16.9% / 17.0% after) | - | Prompt range 10-20% |
| Splits: by asset into 60% train, 10% validation, 10% calibration, 20% test. Time split: train on windows 0-5 of train assets, test on windows 6-7 of test assets (disjoint in both asset and time) | random row split | An asset never appears in train and test; the time split cannot borrow from the future |
| Model choice rule: monotonic HistGradientBoosting if its cross-validated PR-AUC is within 0.01 of plain GradientBoosting and SHAP supports it; else GradientBoosting | always one | Fixed before running, as the prompt requires; SHAP support verified (sklearn 1.9.1, shap 0.51.0) |
| Search: 16 configurations (8 per estimator), 3-fold GroupKFold on training groups, scored by PR-AUC | larger search | Prompt cap is 20; test split and generator B are never used for choices |
| Calibration: sigmoid (Platt) on the calibration split with `FrozenEstimator` | isotonic | Fewer than 1,000 positives in the calibration split, so the prompt's rule selects sigmoid |
| Operating threshold: maximise F2 on the validation split | fixed 0.5 | Missing a compromise costs more than a false alarm; ranking uses probability, not the threshold |
| SHAP on the uncalibrated base model, in log-odds units | SHAP on calibrated output | Calibration keeps ranking but changes units; the unit is labelled |
| Top-k precision: test rows grouped into dashboard-sized slates of 25 assets per window (fixed seed), precision of the top 5 / 10 averaged over slates | top-k over the whole test set | A dashboard ranks one organisation's ~25 assets |
| Integer basis points for anything attested or hashed: `risk_bp = round_half_up(likelihood_bp * (30_000_000 + 7_000 * impact_bp), 100_000_000)` with `round_half_up(n, d) = (2n + d) // 2d`; risk shown = risk_bp / 100 | floats | Recomputation must match exactly on another machine |
| Band hysteresis margin 2.0 risk points | none | A change of a few hundredths must not flip an on-chain band |
| Mitigating actions change real features (patch: days_since_patch 0 and CVEs cleared; segment: not exposed; credentials: not default; disable port: one fewer management port; isolate: no exposure, no remote access, no management ports). Monitoring (x0.85) and the remaining isolation effect (x0.3) stay hand-set multipliers, documented as assumptions | multipliers for everything | The model is asked "what if this feature changed"; the two multipliers have no feature to act on |
| The spec test that required AUC >= 0.80 now asserts determinism and that M1 beats the CVSS-only baseline | keep 0.80 as a test gate | The prompt forbids treating 0.80 as a tuning goal; the value is reported instead |

## 3. Band thresholds derived from M1 (declared before computing them)

Added after the first ML run: with M1 the old thresholds (25 / 50 / 75), which were set for the previous
formula-fitted model, put the headline asset in "medium". The team chose to re-derive the thresholds from M1's own
output by a rule fixed here **before** any value is computed or any demo test is re-run:

- Population: every row of the held-out grouped test split of generator A (data/ml/gen_a.csv, `split()["test"]`).
- Risk per row: `risk = risk_bp / 100` from the shipped M1 likelihood and the same `impact_of` formula, with service
  criticality mapped from asset criticality (5 -> life_critical, 4 -> high, 3 -> medium, 1-2 -> low), because
  population rows have no service.
- Thresholds: low/medium boundary = 50th percentile, medium/high = 80th percentile, high/critical = 95th percentile
  of that risk, rounded to 2 decimals. So, by construction, about 5% of asset-windows are critical and 20% are high
  or critical.
- Script: `evaluation/band_thresholds.py`, which writes the values into `metrics.json` (`band_thresholds`) and the
  defaults in `backend/common/config.py`.
- Whatever the demo then shows is reported as-is; the thresholds are not adjusted afterwards.
