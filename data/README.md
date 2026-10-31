# data/

| Path | What | Real or simulated |
|---|---|---|
| `real/` | CISA CSAF OT advisories, CISA KEV, FIRST EPSS snapshots with checksums (`real/SOURCES.md`, `real/MANIFEST.json`) | real public data |
| `orgs/`, `advisories/`, `cross_org_dependencies.json`, `firmware_catalog.json` | demo organisations (power, water, hospital) and their advisories, built by `generate_dataset.py` | simulated |
| `historical_incidents.csv` | the old formula-generated training table; no longer used by M1 | simulated |
| `ml_population.py` | M1 population: 2,000 (A) / 800 (B) assets x 8 windows with correlated features and real, time-matched CVE context | simulated assets, real CVE context |
| `label_process.py` | the only place labels are made (generators A and B, hidden factors, label noise). Training code never imports it | synthetic |
| `telemetry.py` | daily simulated telemetry, maintenance calendar, benign anomalies and injected attack precursors | simulated |
| `build_ml_dataset.py` | builds `ml/` and `schema.json`; runs the leakage audit and fails the build on a leak | - |
| `schema.json` | every M1 feature: type, range, group, source, real or simulated, monotone constraint | - |
| `ml/gen_a.csv`, `ml/gen_b.csv` | one row per asset per 90-day window: meta columns, 24 features, `label` | see below |
| `ml/episodes_*.csv` | injected telemetry episodes (attack and benign); evaluation of rules D only, never features | simulated |
| `ml/telemetry_*.csv.gz` | the daily telemetry | simulated |
| `ml/rules_eval.json`, `ml/MANIFEST.json` | detection-rule precision/recall; file hashes, row counts, positive rates, CVE match counts, leakage audit | - |

## Columns of `ml/gen_*.csv`

Meta (never features): `asset_id`, `sector`, `asset_type`, `zone`, `window`, `window_start` (t), `max_source_date`
(latest CVE release or KEV date-added used; always <= t), `cve_ids`.

Features (definitions, ranges and sources in `schema.json`):

- Asset facts (simulated): `asset_type_code` (explicit `unknown` level), `zone_ord`, `criticality`, `safety_critical`,
  `num_dependents`, `supply_chain_flag`, `internet_exposed`, `default_credentials`, `open_mgmt_ports`,
  `remote_access_enabled`, `firmware_known`, `days_since_patch`.
- Vulnerability context at t (real CVEs, KEV and dates; EPSS is a proxy): `has_vulnerability`, `cve_count`,
  `max_cvss`, `max_epss`, `any_known_exploited`, `vuln_age_days`, `missing_cvss`, `missing_epss`.
  No vulnerability = `has_vulnerability 0` with CVSS/EPSS 0; a missing value = fallback 0 plus its `missing_*` flag.
- Telemetry from the 30 days before t, through rules D (simulated): `failed_auth_count`, `new_remote_session_flag`,
  `rule_hit_count`, `high_severity_rule_hit`.

Label: `label` = 1 if a simulated compromise occurs in (t, t+90 days]. Synthetic.

The hidden factors that drive the labels are named only inside `label_process.py` and never appear in any data file.

Rebuild: `python data/build_ml_dataset.py` (seed 42, deterministic).
