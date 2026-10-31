"""
Containment levels (PS-03 WP7). SIMULATION ONLY: no command is sent to real OT equipment. An extension to the
preventive recommendations, built from EXISTING planner action types; the existing Critic still reviews every
plan, the existing ApprovalGate approves it, and the existing executor executes and rolls it back.

  1 Restrict            RESTRICT_ACCESS, ROTATE_CREDENTIALS, DISABLE_SERVICE_PORT
  2 Quarantine asset    ISOLATE_ASSET                        (implemented end to end)
  3 Segment zone        SEGMENT_NETWORK
  4 Boundary lockdown   SEGMENT_NETWORK for the exposed assets of ONE named zone (never "everything")

The Critic has no protected-asset or allow-listed-path check, so precheck() adds one OUTSIDE the Critic:
data/containment_allowlist.json lists protected assets (never auto-isolated) and paths that must survive.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.detect.rules import SEVERITY_ORDER

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "data" / "containment_allowlist.json"

LEVELS: Dict[int, Dict[str, Any]] = {
    1: {"name": "Restrict", "actions": ["RESTRICT_ACCESS", "ROTATE_CREDENTIALS", "DISABLE_SERVICE_PORT"],
        "trigger": "exposure finding (severity >= medium) or active_attack finding (severity >= medium)",
        "approval": "per the planner's impact class: LOW steps run without the gate, MEDIUM/HIGH need human approval",
        "implemented": "described; actions available through the normal advisory pipeline"},
    2: {"name": "Quarantine asset", "actions": ["ISOLATE_ASSET"],
        "trigger": "active_attack finding with severity >= high and confidence >= 0.7 on that asset",
        "approval": "human approval through the existing ApprovalGate (ISOLATE_ASSET is MEDIUM or HIGH impact)",
        "implemented": "end to end: trigger, precheck, plan, critic, approval, simulated execution, verification, rollback"},
    3: {"name": "Segment zone", "actions": ["SEGMENT_NETWORK"],
        "trigger": "two or more assets of one zone with active_attack findings (severity >= high) within 7 days",
        "approval": "human approval (MEDIUM/HIGH impact)", "implemented": "described only"},
    4: {"name": "Organisation-boundary lockdown", "actions": ["SEGMENT_NETWORK"],
        "trigger": "level 3 conditions in a zone that holds internet-exposed assets; scope = that one zone's exposed assets",
        "approval": "human approval (MEDIUM/HIGH impact)", "implemented": "described only"},
}
L2_MIN_SEVERITY, L2_MIN_CONFIDENCE = "high", 0.7


def level_of(action: str) -> Optional[int]:
    for k in (2, 3, 1):
        if action in LEVELS[k]["actions"]:
            return k
    return None


def allowlist() -> Dict[str, Any]:
    return json.loads(ALLOWLIST.read_text(encoding="utf-8"))


def level2_trigger(findings: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    ok = [f for f in findings if f["finding_type"] == "active_attack" and SEVERITY_ORDER.index(f["severity"]) >= SEVERITY_ORDER.index(L2_MIN_SEVERITY)
          and f["confidence"] >= L2_MIN_CONFIDENCE]
    return max(ok, key=lambda f: (f["sim_day"], f["confidence"])) if ok else None


def _life_critical(node: Any, aid: str) -> List[str]:
    return [sid for sid, s in node.services.items() if s["criticality"] == "life_critical" and aid in s["required_assets"]]


def _reachable(depends_on: Dict[str, List[str]], src: str, dst: str, removed: Set[str]) -> bool:
    if src in removed or dst in removed:
        return False
    stack, seen = [src], {src}
    while stack:
        cur = stack.pop()
        if cur == dst:
            return True
        for nxt in depends_on.get(cur, []):
            if nxt not in seen and nxt not in removed:
                seen.add(nxt)
                stack.append(nxt)
    return False


def precheck(node: Any, actions: List[Dict[str, Any]], findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    al = allowlist()
    blocking: List[str] = []
    warnings: List[str] = []
    per: Dict[str, Any] = {}
    targets = [(a["action"], t) for a in actions for t in a["targets"]]
    isolating = {t for act, t in targets if act == "ISOLATE_ASSET"}
    for act, aid in targets:
        if aid not in node.assets:
            blocking.append(f"{aid}: not an asset of {node.org}")
            continue
        inv = node.inventory[aid]
        deps = sorted(node.graph.transitive_dependents(aid))
        svcs = [sid for sid, s in node.services.items() if aid in s["required_assets"]]
        life = _life_critical(node, aid)
        info = {"action": act, "level": level_of(act), "dependents": deps, "services": svcs, "life_critical_services": life,
                "maintenance_window": inv.get("maintenance_window"), "reversible": True,
                "reversibility": "simulated state is snapshotted; the existing executor rollback restores it"}
        if act == "ISOLATE_ASSET":
            if aid in al["protected_assets"]:
                blocking.append(f"{aid}: protected asset, never auto-isolated ({al['protected_assets'][aid]})")
            if life:
                blocking.append(f"{aid}: required by life-critical service(s) {life}")
            if deps and aid not in al.get("isolation_ok_with_dependents", []):
                blocking.append(f"{aid}: {len(deps)} dependent asset(s) {deps} would lose it and no alternative path is modelled")
            trig = level2_trigger([f for f in (findings or []) if f["asset_id"] == aid])
            info["trigger_finding"] = trig
            if trig is None:
                blocking.append(f"{aid}: no active_attack finding with severity >= {L2_MIN_SEVERITY} and confidence >= {L2_MIN_CONFIDENCE}")
        if inv.get("maintenance_window") == "none":
            warnings.append(f"{aid}: no maintenance window; the planner adds SCHEDULE_MAINTENANCE_WINDOW first")
        per[aid] = info
    broken = [p for p in al["allowed_paths"] if p["from"] in node.assets and _reachable(node.graph.depends_on, p["from"], p["to"], set())
              and not _reachable(node.graph.depends_on, p["from"], p["to"], isolating)]
    for p in broken:
        blocking.append(f"allowed path {p['from']} -> {p['to']} would be cut ({p['why']})")
    return {"ok": not blocking, "blocking": blocking, "warnings": warnings, "targets": per,
            "note": "precheck runs outside the existing Critic, which still reviews every plan"}


def verify(node: Any) -> Dict[str, Any]:
    """Post-execution reachability on the depends_on graph with isolated assets removed."""
    removed = {aid for aid, a in node.assets.items() if a.isolated}
    blocked = [{"from": a, "to": d} for a, ds in node.graph.depends_on.items() for d in ds if d in removed or a in removed]
    al = allowlist()
    retained, lost, not_applicable = [], [], []
    for p in al["allowed_paths"]:
        if p["from"] not in node.assets:
            continue
        if not _reachable(node.graph.depends_on, p["from"], p["to"], set()):
            not_applicable.append(p)  # not a path in this org's depends_on graph even before containment
        else:
            (retained if _reachable(node.graph.depends_on, p["from"], p["to"], removed) else lost).append(p)
    return {"isolated_assets": sorted(removed), "blocked_edges": blocked, "retained_allowed_paths": retained, "lost_allowed_paths": lost,
            "allowed_paths_not_in_graph": not_applicable, "ok": not lost}


def build_level2_plan(orch: Any, aid: str, finding: Dict[str, Any]) -> Dict[str, Any]:
    """ISOLATE_ASSET + its prerequisites, assembled by the existing PlanBuilder, reviewed by the existing Critic and
    submitted to the existing ApprovalGate. Returns {plan, verdict, gate}."""
    from backend.agents.critic_agent import HASH_EXCLUDE
    from backend.agents.framework import Trace
    from backend.agents.planner_agent import BuildIn, PlanBuilder
    from backend.common.crypto import canonical_hash

    node = orch.node
    # the Critic accepts provenance from node.findings (advisory findings) or node.acked; telemetry findings are
    # registered in acked (node.findings keeps advisory-shaped entries only, which existing routes rely on)
    node.acked = set(getattr(node, "acked", set())) | {finding["finding_id"]}
    pb = PlanBuilder(node)
    steps = pb.repair(pb._expand([{"gid": f"ISOLATE_ASSET:{aid}", "action": "ISOLATE_ASSET", "asset": aid}]))
    dt, eff = pb.cost("ISOLATE_ASSET", aid)
    plan = pb.finalize(steps, BuildIn(assessments=[], trigger_findings=[finding["finding_id"]], label="containment-L2", mode="remediate", focus_assets=[aid]), dt, eff)
    plan["containment"] = {"level": 2, "name": LEVELS[2]["name"], "trigger_finding": finding["finding_id"], "simulation_only": True}
    # the containment tag is part of the plan content, so the hash is recomputed the way the Critic checks it
    plan["plan_hash"] = canonical_hash({k: v for k, v in plan.items() if k not in HASH_EXCLUDE})
    tr = Trace(node.org, f"ps03-containment-L2-{aid}")
    for ag in orch.agents:
        ag.bind(tr)
    verdict = orch.critic.review(plan)
    node.plans[plan["plan_id"]] = plan
    gate: Dict[str, Any] = {"required": None}
    if verdict["verdict"] == "APPROVE_FOR_GATE":
        plan["critic"] = {k: verdict[k] for k in ("verdict", "digest", "anchor_status")}
        gate = orch.request_gate(plan, verdict)
    node.audit.save_trace(tr.to_dict())
    return {"plan": plan, "verdict": {k: verdict.get(k) for k in ("verdict", "reasons", "digest")}, "gate": gate}
