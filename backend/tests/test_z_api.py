"""
API integration over the live, chain-backed system. In the full suite it runs after the lifecycle tests, so plans,
approvals, alerts and traces already exist; run on its own, the fixture produces them by ingesting the headline
advisory first. Covers every route group, role isolation (API-02) and the ML endpoints.
"""
import pytest
from fastapi.testclient import TestClient

from backend.api.main import create_app
from backend.tests.conftest import adv

ADMIN = {"X-Dev-Role": "admin"}
POWER = {"X-Dev-Role": "org:power"}
WATER = {"X-Dev-Role": "org:water"}


@pytest.fixture(scope="module")
def api(system):
    if not any(n.plans for n in system.nodes.values()):
        system.ingest(adv(1))  # same headline advisory the lifecycle tests use; creates plans and traces
    return TestClient(create_app(system))


@pytest.mark.req("API-01")
def test_health_and_chain_status(api):
    assert api.get("/api/health").json() == {"ok": True, "chain_connected": True}
    st = api.get("/api/chain/status").json()
    assert st["connected"] and st["chain_id"] == 31337 and set(st["contracts"]) >= {"AttestationRegistry", "AlertBus", "ApprovalGate"}


@pytest.mark.req("API-02")
def test_roles_and_org_isolation(api):
    assert api.get("/api/orgs/power/assets", headers={"X-Dev-Role": "nobody"}).status_code == 401
    assert api.get("/api/orgs/power/assets", headers=WATER).status_code == 403
    assert api.get("/api/orgs/water/assets", headers=WATER).status_code == 200
    assert api.get("/api/orgs/power/assets/power-asset-001/why", headers=WATER).status_code == 403
    assert api.get("/api/orgs/power/findings/detections", headers=WATER).status_code == 403
    assert api.get("/api/audit/verify?org=power", headers=WATER).status_code == 403
    # another org's private service risk must not be readable through the cascade endpoint
    assert api.get("/api/cross-org/cascade?source_org=power&source_service=power-service-1", headers=WATER).status_code == 403
    assert api.post("/api/approvals/0x00/approve", json={"org": "power", "approver": 0}, headers=WATER).status_code == 403
    assert api.get("/api/orgs/nowhere/assets", headers=ADMIN).status_code == 404


@pytest.mark.req("API-01", "RISK-02")
def test_org_risk_carries_integer_ml_scores(api):
    r = api.get("/api/orgs/power/risk", headers=POWER).json()
    assert r["aggregate"] >= 0 and len(r["scores"]) == 25
    s = r["scores"][0]
    assert {"likelihood_bp", "impact_bp", "risk_bp", "band", "top_factors", "model_version"} <= set(s)
    assert all(isinstance(s[k], int) for k in ("likelihood_bp", "impact_bp", "risk_bp"))
    svcs = api.get("/api/orgs/power/services", headers=POWER).json()
    assert svcs and {"service_id", "band", "risk"} <= set(svcs[0])
    g = api.get("/api/orgs/power/graph", headers=POWER).json()
    assert len(g["nodes"]) == 25 and g["edges"]


@pytest.mark.req("RISK-03")
def test_why_what_changed_and_trend(api):
    why = api.get("/api/orgs/power/assets/power-asset-001/why", headers=POWER).json()
    assert {"likelihood", "impact", "risk", "band", "key_factors", "cascade_assumptions", "data_freshness", "source_tags"} <= set(why)
    assert why["source_tags"]["labels the model learned from"] == "synthetic"
    ch = api.get("/api/orgs/power/assets/power-asset-001/what-changed", headers=POWER).json()
    assert ch["asset_id"] == "power-asset-001" and isinstance(ch["changes"], list)
    for c in ch["changes"]:
        assert c["sentence"] and isinstance(c["delta_logodds"], float)
    tr = api.get("/api/orgs/power/assets/power-asset-001/trend", headers=POWER).json()
    assert tr["direction"] in ("rising", "falling", "flat", "insufficient history", "no history")
    assert len(api.get("/api/orgs/power/trends", headers=POWER).json()) == 25
    assert api.get("/api/orgs/power/assets/nope/why", headers=POWER).status_code == 404


@pytest.mark.req("RISK-01")
def test_detections_keep_exposure_and_active_attack_apart(api):
    d = api.get("/api/orgs/power/findings/detections", headers=POWER).json()
    assert d and {x["finding_type"] for x in d} <= {"active_attack", "exposure"}
    for x in d:
        assert x["source"] in ("telemetry", "simulated") and x["asset_id"].startswith("power-asset-")


@pytest.mark.req("RISK-05")
def test_model_card_is_measured_not_claimed(api):
    from backend.risk.inference import M1

    card = api.get("/api/ml/model", headers=WATER).json()
    assert card["model_version"] == M1.get().version
    assert card["held_out_A"]["M1"]["roc_auc"] > card["held_out_A"]["B1_cvss_only"]["roc_auc"]
    assert card["accuracy_ceiling"]["M1"]["roc_auc"] > 0.5 and "synthetic" in card["labels"]


@pytest.mark.req("AG-CAS-02", "SEC-PRIV-01")
def test_cross_org_graph_uses_verified_disclosures(api):
    g = api.get("/api/cross-org/graph", headers=WATER).json()
    assert g["nodes"] and g["edges"]
    assert all(e["disclosed"] for e in g["edges"]), "every edge's terms open and match their on-chain commitment"
    c = api.get("/api/cross-org/cascade?source_org=power&source_service=power-service-1", headers=POWER).json()
    assert c["chain"] and c["chain"][0]["time_to_impact_minutes"] >= 0


@pytest.mark.req("API-01", "BC-GATE-01")
def test_plans_approvals_traces_and_audit(api):
    plans = api.get("/api/plans", headers=POWER).json()
    assert plans and all(p["org"] == "power" for p in plans)
    assert api.get("/api/plans", headers=WATER).json() == [p for p in api.get("/api/plans", headers=ADMIN).json() if p["org"] == "water"]
    p = api.get(f"/api/plans/{plans[0]['plan_id']}", headers=POWER).json()
    assert p["plan_hash"] and p["steps"]
    assert api.get(f"/api/plans/{plans[0]['plan_id']}", headers=WATER).status_code == 403
    tr = api.get("/api/traces?org=power", headers=POWER).json()
    assert tr and all(t["org"] == "power" for t in tr)
    full = api.get(f"/api/traces/{tr[0]['trace_id']}", headers=POWER).json()
    assert full["steps"]
    assert api.get("/api/audit/verify?org=power", headers=POWER).json()["ok"] is True


@pytest.mark.req("API-01", "SEC-PRIV-05")
def test_chain_events_expose_no_plaintext_risk(api):
    evs = api.get("/api/chain/events?limit=2000", headers=ADMIN).json()
    assert evs
    leaky = {"riskBand", "criticalityBucket", "strength", "tolerance", "matched", "severity", "tti"}
    assert not any(leaky & set(e["args"]) for e in evs)
    att = api.get("/api/chain/attestations", headers=ADMIN).json()
    assert set(att) >= {"dependency", "risk", "findings", "alerts"}


@pytest.mark.req("API-01", "AG-INT-09")
def test_advisory_ingestion_is_scoped_to_the_callers_org(api):
    assert api.post("/api/advisories", json={"text": "   "}, headers=WATER).status_code == 422
    res = api.post("/api/advisories", json={"text": "Vendor bulletin VSB-API\nCVE-2024-99001: flaw in Contoso Gadget versions before 1.2.0.\nCVSS: 5.0", "source": "api-test"},
                   headers=WATER).json()
    assert set(res) == {"water"} and res["water"]["status"] in ("no_match", "duplicate")
