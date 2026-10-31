"""PS-03 WP2-WP4: real-CVE seeding, telemetry + rules, simulated clock, reassessor, loop breakers, trend (offline)."""

import json
import threading
from collections import Counter

import pytest

from backend import simclock
from backend.agents.org_node import OrgNodeRuntime
from backend.detect.rules import RULES
from backend.proactive import MAX_STEPS, ReassessRejected, Reassessor
from backend.risk import model as M
from backend.risk import trend_log as T
from backend.seed_real import RealContext, seed_node

ORGS = ("power", "water", "hospital")


@pytest.fixture(scope="module")
def real_ctx():
    return RealContext()


@pytest.fixture()
def world(tmp_path, real_ctx):
    simclock.reset()
    nodes = {o: OrgNodeRuntime(o, None, None, tmp_path) for o in ORGS}
    for n in nodes.values():
        seed_node(n, real_ctx)
    r = Reassessor(nodes, chain_ops=False, real_ctx=real_ctx)
    r.reassess_all("asset_change", "startup")
    yield nodes, r
    simclock.reset()


@pytest.mark.req("PS03-WP2-01")
def test_seeded_vulns_are_tagged_and_bands_spread(world):
    nodes, _ = world
    vulns = [v for n in nodes.values() for a in n.assets.values() for v in a.vulns]
    assert vulns and all(v["source"] == "real_snapshot" and v["match"] in ("model", "vendor", "sector_fallback") and v["epss_time_matched"] is False for v in vulns)
    assert all(len(a.vulns) <= 3 for n in nodes.values() for a in n.assets.values())
    bands = Counter(M.score_asset(a, explain=False)["band"] for n in nodes.values() for a in n.assets.values())
    assert len(bands) >= 2, f"seeded overview must not be all one band: {bands}"


@pytest.mark.req("PS03-WP2-01")
def test_seeding_is_deterministic(tmp_path, real_ctx):
    a = OrgNodeRuntime("power", None, None, tmp_path)
    b = OrgNodeRuntime("power", None, None, tmp_path)
    seed_node(a, real_ctx), seed_node(b, real_ctx)
    assert {k: [v["cve"] for v in x.vulns] for k, x in a.assets.items()} == {k: [v["cve"] for v in x.vulns] for k, x in b.assets.items()}


@pytest.mark.req("PS03-WP3-01")
def test_telemetry_yields_both_finding_types_with_source_tags(world):
    nodes, r = world
    r.advance(7, "demo_week")
    fs = [f for d in r.detectors.values() for f in d.list()]
    types = {f["finding_type"] for f in fs}
    assert types == {"exposure", "active_attack"}
    assert all(f["source"] in ("telemetry", "advisory", "simulated") for f in fs)
    gw = [f for f in r.detectors["hospital"].list("hospital-asset-002") if f["rule_id"] == "R2_UNEXPECTED_REMOTE_ACCESS"]
    assert gw, "the scripted remote-access episode must be detected"


@pytest.mark.req("PS03-WP3-01")
def test_rules_are_plain_functions_and_metrics_exist():
    from backend.risk.model import ARTIFACTS

    assert len(RULES) == 6
    m = json.loads((ARTIFACTS / "rules_metrics.json").read_text(encoding="utf-8"))
    assert set(m["rules"]) == {r.__name__ for r in RULES}


@pytest.mark.req("PS03-WP4-01")
def test_advance_moves_patch_age_extends_history_and_explains(world):
    nodes, r = world
    a = nodes["water"].assets["water-asset-001"]
    d0 = M.features_of(a)["days_since_patch"]
    out = r.advance(7, "demo_week")
    assert simclock.now_day() == 7 and M.features_of(a)["days_since_patch"] == d0 + 7
    assert len(nodes["power"].risk_log) == 8
    ch = [c for c in out["changes"] if c["asset_id"] == "power-asset-001" and c["to_sim_day"] == 2]
    assert ch and ch[0]["to_band"] in ("high", "critical") and ch[0]["to_risk_bp"] > ch[0]["from_risk_bp"]
    assert {x["feature"] for x in ch[0]["reasons"]} & {"any_known_exploited", "max_epss", "max_cvss", "cve_count", "vuln_age_days"}
    assert T.org_trends(nodes["power"].risk_log)["power-asset-001"]["direction"] in ("rising", "flat", "falling")


@pytest.mark.req("PS03-WP4-01")
def test_same_seed_gives_identical_integers(tmp_path, real_ctx):
    def run():
        simclock.reset()
        nodes = {o: OrgNodeRuntime(o, None, None, tmp_path) for o in ORGS}
        for n in nodes.values():
            seed_node(n, real_ctx)
        r = Reassessor(nodes, chain_ops=False, real_ctx=real_ctx)
        r.reassess_all("asset_change", "startup")
        r.advance(7, "demo_week")
        out = {(o, e["sim_day"], aid): v["risk_bp"] for o, n in nodes.items() for e in n.risk_log for aid, v in e["assets"].items()}
        simclock.reset()
        return out

    a, b = run(), run()
    assert a == b and all(isinstance(v, int) for v in a.values())


@pytest.mark.req("PS03-WP4-02")
@pytest.mark.parametrize("trigger", ["attestation", "alert", "snapshot", "made_up"])
def test_forbidden_triggers_never_reassess(world, trigger):
    nodes, r = world
    n0 = len(nodes["power"].risk_log)
    with pytest.raises(ReassessRejected):
        r.reassess_all(trigger)
    assert len(nodes["power"].risk_log) == n0


@pytest.mark.req("PS03-WP4-02")
def test_at_most_one_reassessment_per_trigger(world):
    nodes, r = world
    n0 = len(nodes["power"].risk_log)
    r.reassess_all("advisory", key="ADV-1")
    assert "skipped" in r.reassess_all("advisory", key="ADV-1")
    assert len(nodes["power"].risk_log) == n0 + 1


@pytest.mark.req("PS03-WP4-02")
def test_timer_minimum_interval(world):
    nodes, r = world
    simclock.advance(1)
    r.reassess_all("timer")
    assert "skipped" in r.reassess_all("timer")


@pytest.mark.req("PS03-WP4-02")
def test_advance_is_capped(world):
    _, r = world
    out = r.advance(MAX_STEPS + 15)
    assert out["steps"] == MAX_STEPS and out["capped"] and simclock.now_day() == MAX_STEPS


@pytest.mark.req("PS03-WP4-02")
def test_concurrent_advance_is_rejected(world):
    _, r = world
    r._lock.acquire()
    try:
        with pytest.raises(ReassessRejected, match="busy"):
            r.advance(1)
    finally:
        r._lock.release()


@pytest.mark.req("PS03-WP4-03")
def test_reset_restores_clock_and_state(world):
    nodes, r = world
    cves0 = [v["cve"] for v in nodes["power"].assets["power-asset-001"].vulns]
    r.advance(3, "demo_week")
    assert M.REFERENCE_DATE != simclock.ORIGINAL_DATE
    r.reset()
    assert simclock.now_day() == 0 and M.REFERENCE_DATE == simclock.ORIGINAL_DATE and nodes["power"].risk_log == []
    assert [v["cve"] for v in nodes["power"].assets["power-asset-001"].vulns] == cves0


@pytest.mark.req("PS03-WP4-04")
def test_trend_directions_and_crossing_estimate():
    up = T.trend(list(range(8)), [1000 + 100 * i for i in range(8)])
    assert up["direction"] == "rising" and up["est_days_to_next_band"] is not None and up["est_days_to_next_band"] > 0
    assert T.trend(list(range(8)), [3000.0] * 8)["direction"] == "flat"
    down = T.trend(list(range(8)), [6000 - 200 * i for i in range(8)])
    assert down["direction"] == "falling" and down["est_days_to_next_band"] is None
