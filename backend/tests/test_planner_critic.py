from copy import deepcopy

import pytest

from backend.agents.critic_agent import CriticAgent, HASH_EXCLUDE
from backend.agents.framework import Trace
from backend.agents.planner_agent import PlanBuilder, PlannerAgent
from backend.common.crypto import canonical_hash
from backend.risk import model as risk

VULN = {"cve": "CVE-2023-1234", "cvss": 8.8, "epss": 0.9, "exploited": True}
FID = "ADV-test000001"


def seeded(node, assets=("power-asset-001",)):
    for a in assets:
        node.assets[a].vulns = [dict(VULN)]
    node.findings[FID] = {"advisory_id": FID, "content_hash": "x", "cve_ids": ["CVE-2023-1234"], "status": "matched"}
    return node


def make_plan(node, **kw):
    scores = [risk.score_asset(a, explain=False) for a in node.contexts()]
    p = PlannerAgent(node)
    p.bind(Trace(node.org, "t"))
    return p.plan(scores, [FID], **kw)


def review(node, plan):
    c = CriticAgent(node)
    c.bind(Trace(node.org, "t"))
    return c.call("review_plan", plan=plan)


def rehash(plan):
    plan["plan_hash"] = canonical_hash({k: v for k, v in plan.items() if k not in HASH_EXCLUDE})
    return plan


def pos(plan, action, asset):
    return next(i for i, s in enumerate(plan["steps"]) if s["action"] == action and asset in s["target_assets"])


@pytest.mark.req("AG-PLN-01", "AG-PLN-04")
def test_plan_schema_and_action_library(offline_node):
    plan = make_plan(seeded(offline_node))
    for k in ("plan_id", "org", "trigger_finding_ids", "steps", "risk_before", "risk_after", "total_delta", "cross_org_risk_before", "cross_org_risk_after", "constraints_checked", "plan_hash"):
        assert k in plan
    for s in plan["steps"]:
        for k in ("step_id", "action", "target_assets", "preconditions_met", "scheduled_window", "impact_class", "est_downtime_min", "est_effort_h", "expected_risk_delta", "rationale"):
            assert k in s
        assert s["impact_class"] in ("LOW", "MEDIUM", "HIGH")
    assert plan["org"] == offline_node.org and plan["risk_after"] < plan["risk_before"]


@pytest.mark.req("AG-PLN-02")
def test_signoff_and_maintenance_window_precede_the_patch(offline_node):
    node = seeded(offline_node)
    assert node.inventory["power-asset-001"]["vendor_signoff_required"] and node.inventory["power-asset-001"]["maintenance_window"] == "none"
    plan = make_plan(node)
    a = "power-asset-001"
    assert pos(plan, "REQUEST_VENDOR_SIGNOFF", a) < pos(plan, "PATCH", a)
    assert pos(plan, "SCHEDULE_MAINTENANCE_WINDOW", a) < pos(plan, "PATCH", a)
    assert review(node, plan).verdict == "APPROVE_FOR_GATE"


@pytest.mark.req("AG-PLN-02", "AG-PLN-03")
def test_adversarial_llm_ordering_cannot_produce_an_invalid_plan(offline_node):
    node = seeded(offline_node)
    # worst possible order: patch first, prerequisites last, unknown ids in between
    evil = ["PATCH:power-asset-001", "ENABLE_MONITORING:power-asset-001", "SCHEDULE_MAINTENANCE_WINDOW:power-asset-001", "REQUEST_VENDOR_SIGNOFF:power-asset-001", "NOPE:x"]
    plan = make_plan(node, proposed_order=evil)
    a = "power-asset-001"
    assert pos(plan, "REQUEST_VENDOR_SIGNOFF", a) < pos(plan, "PATCH", a) and pos(plan, "SCHEDULE_MAINTENANCE_WINDOW", a) < pos(plan, "PATCH", a)
    assert review(node, plan).verdict == "APPROVE_FOR_GATE"


@pytest.mark.req("AG-PLN-02")
def test_safety_critical_downtime_needs_compensating_control_and_high_class(offline_node):
    node = seeded(offline_node)
    node.inventory["power-asset-001"]["safety_critical"] = True
    node.assets["power-asset-001"].safety_critical = True
    plan = make_plan(node)
    a = "power-asset-001"
    patch = plan["steps"][pos(plan, "PATCH", a)]
    assert patch["impact_class"] == "HIGH"
    assert pos(plan, "ENABLE_MONITORING", a) < pos(plan, "PATCH", a), "compensating control precedes downtime on a safety asset"
    assert review(node, plan).verdict == "APPROVE_FOR_GATE"


@pytest.mark.req("AG-PLN-02")
def test_no_two_downtime_actions_share_a_window_on_a_life_critical_service(offline_node):
    node = offline_node
    life = next(s for s in node.services.values() if s["criticality"] == "life_critical")
    pair = [a for a in life["required_assets"] if node.inventory[a]["patch_requires_downtime"]][:2]
    if len(pair) < 2:
        pair = life["required_assets"][:2]
        for a in pair:
            node.inventory[a]["patch_requires_downtime"] = True
    for a in pair:
        node.inventory[a]["maintenance_window"] = "Sun 02:00-04:00"
        node.inventory[a]["vendor_signoff_required"] = False
    seeded(node, tuple(pair))
    plan = make_plan(node)
    windows = [s["scheduled_window"] for s in plan["steps"] if s["est_downtime_min"] > 0 and any(a in life["required_assets"] for a in s["target_assets"])]
    assert len(windows) == len(set(windows)), windows
    assert review(node, plan).verdict == "APPROVE_FOR_GATE"


@pytest.mark.req("AG-PLN-03")
def test_budget_is_respected_and_min_downtime_alternative_has_none(offline_node):
    node = seeded(offline_node)
    plan = make_plan(node)
    assert plan["totals"]["downtime_min"] <= plan["budget"]["downtime_min"] and plan["totals"]["effort_h"] <= plan["budget"]["effort_h"]
    alts = {a["label"]: a for a in plan["alternatives"]}
    if "min_downtime" in alts:
        assert alts["min_downtime"]["totals"]["downtime_min"] == 0
        assert review(node, alts["min_downtime"]).verdict == "APPROVE_FOR_GATE"
    # tiny budgets produce a smaller (but still valid) plan, never an over-budget one
    pb = PlanBuilder(node)
    scores = [risk.score_asset(a, explain=False) for a in node.contexts()]
    from backend.agents.planner_agent import BuildIn

    small = pb.build(BuildIn(assessments=scores, trigger_findings=[FID], budget_downtime_min=0, budget_effort_h=1.0))
    assert small["totals"]["downtime_min"] == 0 and small["totals"]["effort_h"] <= 1.0


@pytest.mark.req("AG-PLN-05")
def test_every_claimed_delta_equals_the_what_if_recomputation(offline_node):
    node = seeded(offline_node)
    plan = make_plan(node)
    applied, prev = [], plan["risk_before"]
    for s in plan["steps"]:
        applied.append({"action": s["action"], "targets": s["target_assets"]})
        cur = risk.what_if(node.contexts(), applied)["risk_after"]
        assert s["expected_risk_delta"] == pytest.approx(cur - prev, abs=1e-6), s["step_id"]
        prev = cur
    assert plan["risk_after"] == pytest.approx(prev, abs=1e-6)
    assert plan["total_delta"] == pytest.approx(plan["risk_after"] - plan["risk_before"], abs=1e-6)
    assert sum(s["expected_risk_delta"] for s in plan["steps"]) == pytest.approx(plan["total_delta"], abs=1e-4)
    assert "reduces risk" in plan["narrative"] or "lowers" in plan["narrative"]


@pytest.mark.req("AG-PLN-06")
def test_alternatives_are_distinct_valid_plans(offline_node):
    node = seeded(offline_node, ("power-asset-001", "power-asset-002", "power-asset-004"))
    plan = make_plan(node)
    assert plan["alternatives"], "at least one alternative when feasible"
    hashes = {plan["plan_hash"], *[a["plan_hash"] for a in plan["alternatives"]]}
    assert len(hashes) == 1 + len(plan["alternatives"])
    for alt in plan["alternatives"]:
        assert review(node, alt).verdict == "APPROVE_FOR_GATE"


@pytest.mark.req("AG-PLN-07", "AG-PLN-08")
def test_planning_is_deterministic_and_hash_is_canonical(offline_node):
    node = seeded(offline_node)
    a, b = make_plan(node), make_plan(node)
    assert a["plan_hash"] == b["plan_hash"] and [s["action"] for s in a["steps"]] == [s["action"] for s in b["steps"]]
    assert a["plan_hash"] == canonical_hash({k: v for k, v in a.items() if k not in HASH_EXCLUDE})


@pytest.mark.req("AG-PLN-09")
def test_planner_never_targets_assets_outside_its_org(offline_node):
    node = seeded(offline_node)
    plan = make_plan(node)
    assert all(t in node.inventory and t.startswith("power-") for s in plan["steps"] for t in s["target_assets"])


@pytest.mark.req("AG-PLN-01")
def test_preemptive_mode_only_proposes_low_impact_hardening(offline_node):
    node = seeded(offline_node)
    node.acked.add("0xalert")
    scores = [risk.score_asset(a, explain=False) for a in node.contexts()]
    pl = PlannerAgent(node)
    pl.bind(Trace("power", "t"))
    plan = pl.plan(scores, ["0xalert"], mode="preemptive", focus=["power-asset-001"])
    assert plan["steps"] and all(s["action"] == "ENABLE_MONITORING" and s["impact_class"] == "LOW" for s in plan["steps"])
    assert review(node, plan).verdict == "APPROVE_FOR_GATE"


# ------------------------------------------------------------------ critic red team
def valid(node):
    seeded(node)
    return make_plan(node)


def verdict(node, plan, keep_hash=False):
    if not keep_hash:
        rehash(plan)
    return review(node, plan)


@pytest.mark.req("AG-CRT-01", "AG-CRT-02")
def test_critic_accepts_a_valid_plan_with_every_check_run(offline_node):
    node = offline_node
    r = review(node, valid(node))
    assert r.verdict == "APPROVE_FOR_GATE" and not r.reasons and r.checks >= 10


def _mut_drop_window(p):
    p["steps"] = [s for s in p["steps"] if s["action"] != "SCHEDULE_MAINTENANCE_WINDOW"]


def _mut_drop_signoff(p):
    p["steps"] = [s for s in p["steps"] if s["action"] != "REQUEST_VENDOR_SIGNOFF"]


def _mut_isolate_safety_no_control(p):
    p["steps"] = [dict(p["steps"][0], step_id="S99", action="ISOLATE_ASSET", impact_class="LOW", est_downtime_min=120, requires=[], scheduled_window="w", target_assets=["power-asset-009"])]
    p["steps"][0]["finding_ids"] = [FID]


def _mut_inflate(p):
    p["steps"][-1]["expected_risk_delta"] = -99.0
    p["total_delta"] = -99.0


def _mut_foreign_org_asset(p):
    p["steps"][0]["target_assets"] = ["water-asset-001"]


def _mut_unknown_finding(p):
    p["steps"][0]["finding_ids"] = ["ADV-does-not-exist"]


def _mut_duplicate(p):
    p["steps"].append(deepcopy(p["steps"][-1]))


def _mut_forward_requires(p):
    p["steps"][0]["requires"] = [p["steps"][-1]["step_id"]]


def _mut_over_budget(p):
    p["budget"] = {"downtime_min": 0, "effort_h": 0.1}


def _mut_wrong_org(p):
    p["org"] = "water"


def _mut_understated_impact(p):
    for s in p["steps"]:
        if s["action"] == "PATCH":
            s["impact_class"] = "LOW"


@pytest.mark.req("AG-CRT-03")
@pytest.mark.parametrize(
    "name,mut,want",
    [
        ("violates maintenance window", _mut_drop_window, "REVISE"),
        ("skips vendor sign-off", _mut_drop_signoff, "REVISE"),
        ("isolates safety/life-critical asset without control", _mut_isolate_safety_no_control, "ANY"),
        ("claims an inflated risk delta", _mut_inflate, "REJECT"),
        ("targets another org's asset", _mut_foreign_org_asset, "REJECT"),
        ("references a nonexistent finding", _mut_unknown_finding, "REJECT"),
        ("duplicate steps", _mut_duplicate, "ANY"),
        ("cyclic / forward ordering", _mut_forward_requires, "REVISE"),
        ("exceeds the budget", _mut_over_budget, "REVISE"),
        ("wrong org on the plan", _mut_wrong_org, "REJECT"),
        ("understates the impact class", _mut_understated_impact, "REVISE"),
    ],
)
def test_critic_catches_each_invalid_plan(offline_node, name, mut, want):
    node = offline_node
    node.inventory["power-asset-009"]["safety_critical"] = True
    p = valid(node)
    mut(p)
    r = verdict(node, p)
    assert r.verdict != "APPROVE_FOR_GATE", name
    if want != "ANY":
        assert r.verdict == want, (name, r.verdict, r.reasons)
    assert r.reasons


@pytest.mark.req("AG-CRT-03")
def test_critic_catches_hash_mismatch_and_tampering_after_review(offline_node):
    node = offline_node
    p = valid(node)
    assert review(node, p).verdict == "APPROVE_FOR_GATE"
    p["steps"][0]["rationale"] = "tampered after the hash was computed"
    r = verdict(node, p, keep_hash=True)
    assert r.verdict == "REJECT" and any("hash" in x for x in r.reasons)


@pytest.mark.req("AG-CRT-03")
def test_critic_catches_an_empty_plan_and_missing_provenance(offline_node):
    node = offline_node
    p = valid(node)
    p["steps"] = []
    p["total_delta"] = 0.0
    assert verdict(node, p).verdict != "APPROVE_FOR_GATE"
    q = valid(node)
    for s in q["steps"]:
        s["finding_ids"] = []
    assert verdict(node, q).verdict == "REJECT"
