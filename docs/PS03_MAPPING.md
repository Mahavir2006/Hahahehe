# PS-03 objective to code and UI

| PS-03 objective | Code | UI |
|---|---|---|
| Asset profiling | `data/orgs/*/inventory.json`, `backend/agents/org_node.py`, `backend/seed_real.py` | Overview table; Asset detail |
| Vulnerability assessment | Intake agent (advisories); `seed_real.py` (real CSAF/KEV/EPSS); exposure findings in `backend/detect/findings.py` | Asset detail "Vulnerabilities" (source tags); Detections "Exposure" |
| AI risk prediction (likelihood and impact) | `backend/risk/model.py` (v1), `backend/risk/adapter.py` (v2 swap), `backend/risk/explain.py` (integer bp) | Overview likelihood / impact / risk; Asset detail score cards |
| Risk prioritisation | `GET /api/ps03/orgs/{org}/attention` | Overview "Needs attention" |
| Dependency and impact analysis | `backend/graph/cascade.py` (existing); `explain.dependency_path` | Overview graph; Asset detail "Dependency path" and assumptions |
| Network activity | `backend/detect/telemetry.py`, `rules.py` | Detections "Active attack" |
| Changing threat levels | `backend/simclock.py`, `backend/proactive.py`, `backend/risk/trend.py` | Overview "Advance 7 days", "What changed", trend arrows |
| Explain why an asset is high risk | `explain.why` (true SHAP; share of risk labelled as not SHAP) | Asset detail |
| How fixing reduces risk; preventive measures | existing planner + `explain.recommended_actions` (what-if); `backend/containment.py` | Asset detail "Recommended actions"; Plans and approvals |
| Trust and governance | existing contracts, ApprovalGate, audit log | Trust tab; Plans and approvals |
| Model transparency | `GET /api/ps03/model/info` | Model card |
