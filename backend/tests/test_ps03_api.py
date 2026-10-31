"""PS-03 WP5-WP7 end to end through the HTTP API on its own local Hardhat chain (simulation only).

Uses a dedicated DevChain + CascadeShieldSystem so seeding and the simulated clock never touch the session
fixtures of the existing lifecycle tests.
"""

import pytest
from fastapi.testclient import TestClient

from backend import simclock
from backend.devchain import DevChain
from backend.risk import model as M
from backend.system import CascadeShieldSystem

ADMIN = {"X-Dev-Role": "admin"}


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    for k, v in {"PS03_ENABLE": "1", "PS03_SEED_REAL": "1"}.items():
        mp.setenv(k, v)
    simclock.reset()
    dc = DevChain().start()
    s = CascadeShieldSystem(dc.url, str(dc.deployment_file), tmp_path_factory.mktemp("ps03_state"))
    s.bootstrap()
    from backend.api.main import create_app

    with TestClient(create_app(s)) as c:
        yield c, s
    simclock.reset()
    dc.stop()
    mp.undo()


def test_flags_off_registers_nothing(monkeypatch):
    monkeypatch.delenv("PS03_ENABLE", raising=False)
    from backend.api.main import create_app

    paths = {r.path for r in create_app(None).routes}
    assert not any(p.startswith("/api/ps03") for p in paths) and "/api/orgs/{org}/assets" in paths


@pytest.mark.req("PS03-WP5-01")
def test_health_attention_and_role_rules(client):
    c, _ = client
    h = c.get("/api/ps03/health").json()
    assert h["banner"].startswith("Simulation only")
    a = c.get("/api/ps03/orgs/power/attention?limit=25", headers=ADMIN).json()
    assert len(a["items"]) == 25 and a["items"][0]["risk_bp"] >= a["items"][-1]["risk_bp"]
    bands = {x["band"] for org in ("power", "water", "hospital") for x in c.get(f"/api/ps03/orgs/{org}/attention?limit=25", headers=ADMIN).json()["items"]}
    assert len(bands) >= 2, bands
    assert c.get("/api/ps03/orgs/power/attention", headers={"X-Dev-Role": "org:water"}).status_code == 403
    assert c.get("/api/ps03/orgs/water/attention", headers={"X-Dev-Role": "org:water"}).status_code == 200
    assert c.post("/api/ps03/sim/advance", json={"days": 1}, headers={"X-Dev-Role": "org:power"}).status_code == 403


@pytest.mark.req("PS03-WP6-01")
def test_why_payload_is_complete(client):
    c, _ = client
    w = c.get("/api/ps03/orgs/power/assets/power-asset-001/why", headers=ADMIN).json()
    for k in ("asset", "vulnerabilities", "scores", "shap", "share_of_risk_bar", "dependency_path", "cascade_assumptions", "freshness",
              "findings", "recommended_actions", "source_tags"):
        assert k in w, k
    sc = w["scores"]
    assert sc["risk_bp"] == (2 * sc["likelihood_bp"] * (30_000_000 + 7000 * sc["impact_bp"]) + 100_000_000) // 200_000_000
    assert w["shap"]["unit"] == "log_odds" and w["share_of_risk_bar"]["label"] == "share of risk (not SHAP)"
    assert all(v["source"] == "real_snapshot" and v["epss_time_matched"] is False for v in w["vulnerabilities"])
    assert w["freshness"]["epss_asof"] and w["freshness"]["snapshot_commit"]
    for ra in w["recommended_actions"]:
        assert ra["asset_risk_after"] <= ra["asset_risk_before"]


@pytest.mark.req("PS03-WP5-02")
def test_advance_demo_week_changes_history_trend_detections(client):
    c, _ = client
    out = c.post("/api/ps03/sim/advance", json={"days": 7, "scenario": "demo_week"}, headers=ADMIN).json()
    assert out["to_day"] == 7 and len(out["events_applied"]) == 5
    ch = c.get("/api/ps03/orgs/power/changes?since_day=0", headers=ADMIN).json()["items"]
    kev = [x for x in ch if x["asset_id"] == "power-asset-001" and x["to_sim_day"] == 2]
    assert kev and kev[0]["to_band"] in ("high", "critical") and kev[0]["reasons"]
    hist = c.get("/api/ps03/orgs/power/history", headers=ADMIN).json()
    assert [p["sim_day"] for p in hist["assets"]["power-asset-001"]][-1] == 7
    assert c.get("/api/ps03/orgs/power/trend", headers=ADMIN).json()["assets"]["power-asset-001"]["points"] >= 7
    d = c.get("/api/ps03/detections", headers=ADMIN).json()
    assert d["exposure"] and d["active_attack"]
    info = c.get("/api/ps03/model/info").json()
    assert info["source"] == "v1" and info["rules_metrics"] and info["trend_metrics"] and info["caveats"]


@pytest.mark.req("PS03-WP7-01")
def test_precheck_blocks_assets_with_dependents_and_protected(client):
    c, _ = client
    pc = c.post("/api/ps03/containment/precheck", json={"org": "hospital", "actions": [{"action": "ISOLATE_ASSET", "targets": ["hospital-asset-005"]}]}, headers=ADMIN).json()
    assert not pc["ok"] and any("protected" in b for b in pc["blocking"])
    r = c.post("/api/ps03/containment/level2", json={"org": "hospital", "asset_id": "hospital-asset-002"}, headers=ADMIN)
    assert r.status_code == 409 and any("dependent" in b for b in r.json()["detail"]["precheck"]["blocking"])


@pytest.mark.req("PS03-WP7-02")
def test_level2_quarantine_end_to_end(client):
    c, s = client
    r = c.post("/api/ps03/containment/level2", json={"org": "power", "asset_id": "power-asset-004"}, headers=ADMIN)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["critic"]["verdict"] == "APPROVE_FOR_GATE" and j["gate"]["required"] is True, j["critic"]["reasons"]
    rid, pid = j["gate"]["request_id"], j["plan_id"]
    assert any(st["action"] == "ISOLATE_ASSET" for st in j["steps"])
    for i in range(3):  # existing approval route
        if c.get(f"/api/approvals/{rid}", headers=ADMIN).json()["status"] != "Pending":
            break
        assert c.post(f"/api/approvals/{rid}/approve", json={"org": "power", "approver": i}, headers=ADMIN).status_code == 200
    ex = c.post(f"/api/plans/{pid}/execute", json={"request_id": rid}, headers=ADMIN)
    assert ex.status_code == 200, ex.text
    assert s.nodes["power"].assets["power-asset-004"].isolated
    v = c.get("/api/ps03/containment/verify?org=power", headers=ADMIN).json()
    assert "power-asset-004" in v["isolated_assets"] and v["blocked_edges"] and v["ok"] and v["retained_allowed_paths"]
    rb = c.post(f"/api/plans/{pid}/rollback", headers=ADMIN)
    assert rb.status_code == 200 and rb.json()["rolled_back"]
    assert not s.nodes["power"].assets["power-asset-004"].isolated
    assert c.get("/api/ps03/containment/verify?org=power", headers=ADMIN).json()["isolated_assets"] == []


@pytest.mark.req("PS03-WP4-03")
def test_reset_restores_day_zero(client):
    c, _ = client
    out = c.post("/api/ps03/sim/reset", headers=ADMIN).json()
    assert out["sim_day"] == 0 and M.REFERENCE_DATE == simclock.ORIGINAL_DATE and "not rewound" in out["note"]
    assert c.get("/api/ps03/health").json()["sim_day"] == 0
