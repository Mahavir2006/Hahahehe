import json
from copy import deepcopy
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from backend.common.config import settings as cfg
from backend.graph.cascade import (CrossOrgGraph, EdgeAtt, IntraOrgGraph, NodeAtt, BAND_P)
from backend.risk import model as M

ROOT = Path(__file__).resolve().parents[2]


def ctx(**kw):
    base = dict(asset_id="x", org="power", internet_exposed=True, default_credentials=False, zone="DMZ", last_patched="2025-09-01", criticality=5, num_dependents=6, service_crit="high")
    base.update(kw)
    return M.AssetCtx(**base)


VULN = {"cve": "CVE-2023-1", "cvss": 8.8, "epss": 0.9, "exploited": True}


@pytest.mark.req("RISK-01", "RISK-05")
def test_training_is_deterministic_and_meets_auc(tmp_path):
    a = M.train(out_dir=tmp_path / "a")
    b = M.train(out_dir=tmp_path / "b")
    assert a["metrics"] == b["metrics"]
    assert a["metrics"]["auc"] >= 0.80, a["metrics"]


@pytest.mark.req("RISK-02")
def test_score_structure_and_formula():
    s = M.score_asset(ctx(vulns=[VULN]))
    assert set(s) >= {"likelihood", "impact", "risk", "band", "top_factors", "model_version"}
    assert 0 <= s["likelihood"] <= 1 and 0 <= s["impact"] <= 1 and 0 <= s["risk"] <= 100
    assert s["risk"] == pytest.approx(round(100 * s["likelihood"] * (0.3 + 0.7 * s["impact"]), 4), abs=1e-3)


@pytest.mark.req("RISK-03")
def test_factors_are_human_readable_attributions():
    s = M.score_asset(ctx(vulns=[VULN], default_credentials=True))
    assert s["top_factors"], "SHAP attribution must produce factors"
    names = {f["factor"] for f in s["top_factors"]}
    assert "Internet-exposed" in names or "Vulnerability severity (CVSS)" in names
    for f in s["top_factors"]:
        assert f["text"].startswith(f["factor"]) and ("+" in f["text"] or "-" in f["text"])
    pos = [f for f in s["top_factors"] if f["feature"] == "internet_exposed"]
    assert pos and pos[0]["points"] > 0, "being internet exposed must increase risk"


@pytest.mark.req("RISK-04")
def test_band_boundaries():
    lo, mid, hi = cfg.risk_band_low_max, cfg.risk_band_medium_max, cfg.risk_band_high_max
    assert M.band_for(0) == "low" and M.band_for(lo) == "low" and M.band_for(lo + 0.01) == "medium"
    assert M.band_for(mid) == "medium" and M.band_for(mid + 0.01) == "high"
    assert M.band_for(hi) == "high" and M.band_for(hi + 0.01) == "critical" and M.band_for(100) == "critical"


@pytest.mark.req("RISK-02")
def test_more_exposure_never_lowers_risk():
    safe = M.score_asset(ctx(internet_exposed=False, vulns=[VULN]), explain=False)["risk"]
    exposed = M.score_asset(ctx(internet_exposed=True, vulns=[VULN]), explain=False)["risk"]
    none = M.score_asset(ctx(vulns=[]), explain=False)["risk"]
    assert exposed >= safe and exposed >= none


@pytest.mark.req("RISK-06")
def test_what_if_is_pure_and_correct():
    assets = [ctx(asset_id="a", vulns=[VULN], default_credentials=True), ctx(asset_id="b", internet_exposed=False, criticality=2)]
    snapshot = deepcopy(assets)
    w = M.what_if(assets, [{"action": "PATCH", "targets": ["a"]}, {"action": "ROTATE_CREDENTIALS", "targets": ["a"]}])
    assert assets == snapshot, "what_if must not mutate its input"
    assert w["risk_after"] < w["risk_before"] and w["delta"] == pytest.approx(w["risk_after"] - w["risk_before"], abs=1e-5)
    assert any(d["asset_id"] == "a" for d in w["per_asset_delta"])
    assert M.what_if(assets, [{"action": "PATCH", "targets": ["a"]}, {"action": "ROTATE_CREDENTIALS", "targets": ["a"]}]) == w
    with pytest.raises(KeyError):
        M.what_if(assets, [{"action": "PATCH", "targets": ["nope"]}])
    with pytest.raises(ValueError):
        M.what_if(assets, [{"action": "TELEPORT", "targets": ["a"]}])


@pytest.mark.req("RISK-06")
@pytest.mark.parametrize("action", ["PATCH", "UPDATE_FIRMWARE", "ROTATE_CREDENTIALS", "SEGMENT_NETWORK", "RESTRICT_ACCESS", "ENABLE_MONITORING", "ISOLATE_ASSET", "DISABLE_SERVICE_PORT"])
def test_every_mitigating_action_lowers_risk(action):
    a = ctx(vulns=[VULN], default_credentials=True, supply_chain_flag=True)
    w = M.what_if([a], [{"action": action, "targets": ["x"]}])
    assert w["risk_after"] <= w["risk_before"]
    if action != "DISABLE_SERVICE_PORT":
        assert w["risk_after"] < w["risk_before"]


@pytest.mark.req("RISK-07")
def test_org_aggregate_mixes_max_and_mean():
    sc = [{"risk": 80.0}, {"risk": 20.0}, {"risk": 20.0}]
    assert M.aggregate(sc) == pytest.approx(0.6 * 80 + 0.4 * 40)
    assert M.aggregate([]) == 0.0


# ------------------------------------------------------------------ cascade
def intra():
    return IntraOrgGraph.load("power")


@pytest.mark.req("CAS-01", "CAS-04")
def test_intra_propagation_basic_and_cycle_safe():
    g = IntraOrgGraph("t", {"a": ["b"], "b": ["c"], "c": ["a"], "d": []}, {"s": {"name": "s", "required_assets": ["a", "d"], "criticality": "high"}})
    p = g.propagate({"a": 0.9})
    assert all(0 <= v <= 1 for v in p.values()) and p["d"] == 0.0
    assert p["b"] > 0 and p["c"] > 0, "risk flows around the cycle and terminates"
    assert g.propagate({"a": 0.9}) == p, "deterministic"


@pytest.mark.req("CAS-04")
@given(st.floats(0, 1), st.floats(0, 1))
@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
def test_monotonicity_on_real_graph(x, y):
    g = intra()
    lo, hi = min(x, y), max(x, y)
    a = next(iter(g.depends_on))
    plo, phi = g.propagate({a: lo}), g.propagate({a: hi})
    assert all(phi[k] >= plo[k] - 1e-9 for k in plo)
    slo, shi = g.service_impact(plo), g.service_impact(phi)
    assert all(shi[k] >= slo[k] - 1e-9 for k in slo)


@pytest.mark.req("CAS-04")
def test_idempotence_and_zero_input():
    g = intra()
    z = g.propagate({})
    assert all(v == 0.0 for v in z.values())
    a = next(iter(g.depends_on))
    p = g.propagate({a: 0.5})
    assert g.propagate(p) == pytest.approx(g.propagate(p)), "feeding the fixed point back changes nothing"
    again = g.propagate({k: max(v, 0) for k, v in p.items()})
    assert all(again[k] >= p[k] - 1e-9 for k in p)


def graph3():
    h = lambda n: n * 8  # noqa: E731
    nodes = [NodeAtt("power", h("p1"), "high", "high"), NodeAtt("water", h("w1"), "low", "high"), NodeAtt("hospital", h("h1"), "low", "life_critical")]
    edges = [
        EdgeAtt("water", h("w1"), "power", h("p1"), "high", 1, True),
        EdgeAtt("hospital", h("h1"), "water", h("w1"), "high", 2, True),
        EdgeAtt("hospital", h("h1"), "power", h("p1"), "high", 0, False),  # unconfirmed
    ]
    return CrossOrgGraph.from_attestations(nodes, edges), h


@pytest.mark.req("CAS-02", "CAS-03", "AG-CAS-04")
def test_cross_org_chain_order_and_unconfirmed_exclusion():
    g, h = graph3()
    r = g.cascade_from(("power", h("p1")), source_p=0.8)
    assert [c["org"] for c in r["chain"]] == ["water", "hospital"]
    assert r["chain"][0]["time_to_impact_minutes"] == 35 and r["chain"][1]["time_to_impact_minutes"] == 35 + 150
    assert len(r["unconfirmed_edges"]) == 1
    # the unconfirmed 0-bucket edge (10 min) must NOT shorten the hospital's time to impact
    assert r["chain"][1]["time_to_impact_minutes"] != 10
    assert all(0 <= c["p_degraded"] <= 1 for c in r["chain"])


@pytest.mark.req("CAS-04")
def test_cross_org_monotone_and_cycle_safe():
    g, h = graph3()
    a = g.cascade_from(("power", h("p1")), source_p=0.3)
    b = g.cascade_from(("power", h("p1")), source_p=0.9)
    assert all(y["p_degraded"] >= x["p_degraded"] for x, y in zip(a["chain"], b["chain"]))
    cyc = CrossOrgGraph.from_attestations(
        [NodeAtt("power", "aa", "high", "high"), NodeAtt("water", "bb", "high", "high")],
        [EdgeAtt("power", "aa", "water", "bb", "high", 1), EdgeAtt("water", "bb", "power", "aa", "high", 1)],
    )
    r = cyc.cascade_from(("power", "aa"), source_p=0.5)
    assert r["chain"] and all(c["p_degraded"] <= 1 for c in r["chain"])


@pytest.mark.req("CAS-05")
def test_cross_org_engine_needs_only_attestations():
    """The same result is produced from a structure built purely from public attestation fields."""
    g, h = graph3()
    full = g.cascade_from(("power", h("p1")), source_p=0.8)
    stripped = CrossOrgGraph.from_attestations(
        [NodeAtt(n.org, n.service_hash, n.band, n.criticality, "") for n in g.nodes.values()],
        [EdgeAtt(e.consumer_org, e.consumer_service, e.provider_org, e.provider_service, e.strength, e.tolerance, True) for e in g.edges]
        + [EdgeAtt(e.consumer_org, e.consumer_service, e.provider_org, e.provider_service, e.strength, e.tolerance, False) for e in g.unconfirmed],
    )
    again = stripped.cascade_from(("power", h("p1")), source_p=0.8)
    strip = lambda r: [(c["org"], c["service"], c["p_degraded"], c["time_to_impact_minutes"]) for c in r["chain"]]  # noqa: E731
    assert strip(full) == strip(again)


@pytest.mark.req("CAS-02", "BC-ATT-R-05")
def test_unknown_attestation_is_treated_medium_conservatively():
    n_unknown = NodeAtt("water", "w", "unknown", "high")
    g = CrossOrgGraph.from_attestations([n_unknown], [])
    assert g._base_p(("water", "w")) == BAND_P["medium"]
