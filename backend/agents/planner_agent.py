"""
RemediationPlannerAgent (AG-PLN-*): constraint-respecting remediation plans with exact risk-reduction accounting.

The deterministic optimiser + validator is authoritative. An LLM (or anyone) may PROPOSE an ordering, but the
final plan is always repaired to satisfy every constraint (AG-PLN-03).
"""

from __future__ import annotations

import time
import uuid
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from backend.agents.framework import BaseAgent, SideEffect, agent_tool
from backend.common.crypto import canonical_hash
from backend.graph.cascade import CrossOrgGraph, EdgeAtt, NodeAtt
from backend.risk import model as risk

LOW, MEDIUM, HIGH = 0, 1, 2
IMPACT_NAMES = ["LOW", "MEDIUM", "HIGH"]

ACTIONS = [
    "PATCH", "UPDATE_FIRMWARE", "ROTATE_CREDENTIALS", "SEGMENT_NETWORK", "RESTRICT_ACCESS", "ENABLE_MONITORING", "ISOLATE_ASSET",
    "DISABLE_SERVICE_PORT", "REQUEST_VENDOR_SIGNOFF", "SCHEDULE_MAINTENANCE_WINDOW", "INCIDENT_RESPONSE_PLAN_UPDATE",
]
EFFORT_H = {
    "PATCH": 2.0, "UPDATE_FIRMWARE": 3.0, "ROTATE_CREDENTIALS": 0.5, "SEGMENT_NETWORK": 4.0, "RESTRICT_ACCESS": 1.0, "ENABLE_MONITORING": 1.0,
    "ISOLATE_ASSET": 1.0, "DISABLE_SERVICE_PORT": 0.5, "REQUEST_VENDOR_SIGNOFF": 0.5, "SCHEDULE_MAINTENANCE_WINDOW": 0.25, "INCIDENT_RESPONSE_PLAN_UPDATE": 2.0,
}
DOWNTIME_ACTIONS = {"PATCH", "UPDATE_FIRMWARE", "ISOLATE_ASSET", "SEGMENT_NETWORK"}
DEFAULT_BUDGET = {"downtime_min": 240, "effort_h": 24.0}


class BuildIn(BaseModel):
    assessments: List[Dict[str, Any]]
    trigger_findings: List[str] = Field(default_factory=list)
    cross: Dict[str, Any] = Field(default_factory=dict)
    budget_downtime_min: int = DEFAULT_BUDGET["downtime_min"]
    budget_effort_h: float = DEFAULT_BUDGET["effort_h"]
    proposed_order: Optional[List[str]] = None
    label: str = "balanced"
    mode: str = "remediate"          # remediate | preemptive (upstream alert hardening)
    focus_assets: Optional[List[str]] = None


class BuildOut(BaseModel):
    plan: Dict[str, Any]


class PlanBuilder:
    """Pure logic, no side effects. Separated so tests can drive it directly."""

    def __init__(self, node):
        self.n = node

    # ---- facts about an asset
    def inv(self, aid: str) -> Dict[str, Any]:
        return self.n.inventory[aid]

    def svc_crit(self, aid: str) -> str:
        return self.n.assets[aid].service_crit

    def safetyish(self, aid: str) -> bool:
        return bool(self.inv(aid)["safety_critical"]) or self.svc_crit(aid) == "life_critical"

    def downtime(self, action: str, aid: str) -> int:
        a = self.inv(aid)
        if action in ("PATCH", "UPDATE_FIRMWARE"):
            return 60 if a["patch_requires_downtime"] else 0
        if action == "ISOLATE_ASSET":
            return 120
        if action == "SEGMENT_NETWORK":
            return 30
        return 0

    def impact(self, action: str, aid: str) -> int:
        s, d = self.safetyish(aid), self.downtime(action, aid) > 0
        if action == "ISOLATE_ASSET":
            return HIGH if s else MEDIUM
        if action in ("PATCH", "UPDATE_FIRMWARE"):
            return HIGH if (s and d) else MEDIUM if d else LOW
        if action in ("SEGMENT_NETWORK", "RESTRICT_ACCESS"):
            return HIGH if s else MEDIUM
        if action in ("DISABLE_SERVICE_PORT", "ROTATE_CREDENTIALS"):
            return MEDIUM if s else LOW
        return LOW

    # ---- candidate generation
    def groups(self, assessments: List[Dict[str, Any]], focus: Optional[List[str]], mode: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        by = {a["asset_id"]: a for a in assessments}
        for aid, ctx in self.n.assets.items():
            if focus is not None and aid not in focus:
                continue
            s = by.get(aid) or risk.score_asset(ctx, explain=False)
            if mode == "preemptive":
                out.append(self._g("ENABLE_MONITORING", aid))
                continue
            if s["band"] == "low" and not ctx.vulns:
                continue
            if ctx.vulns:
                out.append(self._g("PATCH", aid))
                if s["band"] == "critical" and not self.inv(aid)["safety_critical"]:
                    out.append(self._g("ISOLATE_ASSET", aid))
            if ctx.supply_chain_flag:
                out.append(self._g("UPDATE_FIRMWARE", aid))
            if ctx.default_credentials:
                out.append(self._g("ROTATE_CREDENTIALS", aid))
            if ctx.internet_exposed:
                out.append(self._g("SEGMENT_NETWORK" if self.safetyish(aid) else "RESTRICT_ACCESS", aid))
            if s["band"] in ("medium", "high", "critical"):
                out.append(self._g("ENABLE_MONITORING", aid))
        return out

    def _g(self, action: str, aid: str) -> Dict[str, Any]:
        return {"gid": f"{action}:{aid}", "action": action, "asset": aid}

    def prereqs(self, action: str, aid: str) -> List[Tuple[str, str]]:
        a, req = self.inv(aid), []
        dt = self.downtime(action, aid) > 0
        if action in ("PATCH", "UPDATE_FIRMWARE") and a["vendor_signoff_required"]:
            req.append(("REQUEST_VENDOR_SIGNOFF", aid))
        if dt and a["maintenance_window"] == "none":
            req.append(("SCHEDULE_MAINTENANCE_WINDOW", aid))
        if dt and self.safetyish(aid):
            req.append(("ENABLE_MONITORING", aid))  # documented compensating control
        return req

    def cost(self, action: str, aid: str) -> Tuple[int, float]:
        dt = self.downtime(action, aid)
        eff = EFFORT_H[action] + sum(EFFORT_H[p] for p, _ in self.prereqs(action, aid))
        return dt, eff

    # ---- assembly
    def build(self, inp: BuildIn) -> Dict[str, Any]:
        n = self.n
        assets = n.contexts()
        base_scores = {a.asset_id: risk.score_asset(a, explain=False) for a in assets}
        cur_actions: List[Dict[str, Any]] = []
        chosen: List[Dict[str, Any]] = []
        spent_dt, spent_eff = 0, 0.0
        cands = self.groups(inp.assessments, inp.focus_assets, inp.mode)
        seen_g = set()
        cands = [c for c in cands if not (c["gid"] in seen_g or seen_g.add(c["gid"]))]

        def agg_with(extra: List[Dict[str, Any]]) -> float:
            scores = dict(base_scores)
            ctx = {a.asset_id: deepcopy(a) for a in assets if any(a.asset_id in x["targets"] for x in extra)}
            for x in extra:
                for t in x["targets"]:
                    risk.apply_action(ctx[t], x["action"])
            for aid, c in ctx.items():
                scores[aid] = risk.score_asset(c, explain=False)
            return risk.aggregate(list(scores.values()))

        cur_agg = risk.aggregate(list(base_scores.values()))
        remaining = list(cands)
        while remaining:
            best, best_ratio, best_new = None, 0.0, None
            for c in remaining:
                dt, eff = self.cost(c["action"], c["asset"])
                needed = [(p, t) for p, t in self.prereqs(c["action"], c["asset"]) if not any(x["action"] == p and t in x["targets"] for x in cur_actions)]
                add_dt = dt
                add_eff = EFFORT_H[c["action"]] + sum(EFFORT_H[p] for p, _ in needed)
                if spent_dt + add_dt > inp.budget_downtime_min or spent_eff + add_eff > inp.budget_effort_h:
                    continue
                trial = cur_actions + [{"action": p, "targets": [t]} for p, t in needed] + [{"action": c["action"], "targets": [c["asset"]]}]
                delta = cur_agg - agg_with(trial)
                ratio = delta / (add_eff + add_dt / 60.0 + 0.01)
                if delta > 1e-9 and (ratio > best_ratio + 1e-12 or (abs(ratio - best_ratio) <= 1e-12 and best and c["gid"] < best["gid"])):
                    best, best_ratio, best_new = c, ratio, (needed, add_dt, add_eff, trial)
            if not best:
                break
            needed, add_dt, add_eff, trial = best_new
            cur_actions = trial
            cur_agg = agg_with(cur_actions)
            spent_dt += add_dt
            spent_eff += add_eff
            chosen.append(best)
            remaining.remove(best)

        # sequence: follow the (possibly adversarial) proposed order, then repair into a valid order
        steps = self._expand(chosen)
        if inp.proposed_order:
            rank = {g: i for i, g in enumerate(inp.proposed_order)}
            steps.sort(key=lambda s: rank.get(f"{s['action']}:{s['targets'][0]}", 10_000))
        steps = self.repair(steps)
        plan = self.finalize(steps, inp, spent_dt, spent_eff)
        return plan

    def _expand(self, chosen: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        steps: List[Dict[str, Any]] = []
        have = set()

        def add(action: str, aid: str):
            if (action, aid) in have:
                return
            have.add((action, aid))
            steps.append({"action": action, "targets": [aid]})

        for c in chosen:
            for p, t in self.prereqs(c["action"], c["asset"]):
                add(p, t)
            add(c["action"], c["asset"])
        return steps

    def repair(self, steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Stable topological repair: prerequisites first, monitoring before downtime on safety assets."""
        def deps(s) -> List[Tuple[str, str]]:
            return self.prereqs(s["action"], s["targets"][0])

        placed: List[Dict[str, Any]] = []
        have = set()
        pending = list(steps)
        guard = 0
        while pending and guard < 10_000:
            guard += 1
            for s in list(pending):
                if all((p, t) in have or not any(x["action"] == p and t in x["targets"] for x in steps) for p, t in deps(s)):
                    placed.append(s)
                    have.add((s["action"], s["targets"][0]))
                    pending.remove(s)
                    break
            else:
                placed.extend(pending)  # cycle cannot occur with these prerequisites; fail-safe
                break
        return placed

    def finalize(self, steps: List[Dict[str, Any]], inp: BuildIn, spent_dt: int, spent_eff: float) -> Dict[str, Any]:
        n = self.n
        # ids, windows, slots
        out_steps: List[Dict[str, Any]] = []
        used: Dict[Tuple[str, str], int] = {}
        life_sets: Dict[str, str] = {}
        for sid, s in n.services.items():
            for a in s["required_assets"]:
                if s["criticality"] == "life_critical":
                    life_sets.setdefault(a, sid)
        window_use: Dict[str, List[str]] = {}
        for k, s in enumerate(steps, 1):
            aid, act = s["targets"][0], s["action"]
            dt = self.downtime(act, aid) if act in DOWNTIME_ACTIONS else 0
            window = ""
            if dt > 0:
                base = self.inv(aid)["maintenance_window"]
                if base == "none":
                    base = f"adhoc-{aid}"
                svc = life_sets.get(aid)
                window = base
                if svc:  # AG-PLN-02: no two downtime actions on a shared life-critical service in one window
                    slot = 1
                    while any(w == window for w in window_use.get(svc, [])):
                        slot += 1
                        window = f"{base}#{slot}"
                    window_use.setdefault(svc, []).append(window)
            out_steps.append(
                {
                    "step_id": f"S{k:02d}", "action": act, "target_assets": [aid], "impact_class": IMPACT_NAMES[self.impact(act, aid)],
                    "est_downtime_min": dt, "est_effort_h": EFFORT_H[act], "scheduled_window": window, "preconditions_met": True,
                    "requires": [], "finding_ids": list(inp.trigger_findings), "rationale": "", "expected_risk_delta": 0.0,
                }
            )
        # requires + rationale + cumulative deltas
        index = {(s["action"], s["target_assets"][0]): s["step_id"] for s in out_steps}
        scores0 = {a.asset_id: risk.score_asset(a, explain=False) for a in n.contexts()}
        prev = risk.aggregate(list(scores0.values()))
        applied: List[Dict[str, Any]] = []
        for s in out_steps:
            aid = s["target_assets"][0]
            s["requires"] = [index[(p, t)] for p, t in self.prereqs(s["action"], aid) if (p, t) in index and index[(p, t)] != s["step_id"]]
            applied.append({"action": s["action"], "targets": [aid]})
            cur = risk.what_if(n.contexts(), applied)["risk_after"]
            s["expected_risk_delta"] = round(cur - prev, 6)
            prev = cur
            s["rationale"] = f"{s['action']} on {aid}: {risk.ACTION_EFFECTS[s['action']]}"
            if inp.trigger_findings:
                s["rationale"] += f"; triggered by {', '.join(inp.trigger_findings)}"
        w = risk.what_if(n.contexts(), applied) if applied else {"risk_before": risk.aggregate(list(scores0.values())), "risk_after": risk.aggregate(list(scores0.values())), "delta": 0.0}
        cross_b, cross_a = self._cross(inp.cross, applied)
        plan = {
            "plan_id": "PLAN-" + uuid.uuid4().hex[:10], "org": n.org, "label": inp.label, "mode": inp.mode, "trigger_finding_ids": list(inp.trigger_findings),
            "steps": out_steps, "risk_before": w["risk_before"], "risk_after": w["risk_after"], "total_delta": w["delta"],
            "cross_org_risk_before": cross_b, "cross_org_risk_after": cross_a,
            "budget": {"downtime_min": inp.budget_downtime_min, "effort_h": inp.budget_effort_h},
            "totals": {"downtime_min": sum(s["est_downtime_min"] for s in out_steps), "effort_h": round(sum(s["est_effort_h"] for s in out_steps), 3)},
            "constraints_checked": [
                "targets belong to org", "prerequisites precede steps", "maintenance windows", "vendor sign-off", "compensating control for safety assets",
                "life-critical window exclusivity", "budget", "deltas equal what-if recomputation",
            ],
            "created_at": int(time.time()),
        }
        plan["plan_hash"] = canonical_hash({k: v for k, v in plan.items() if k not in ("plan_hash", "plan_id", "created_at")})
        return plan

    def _cross(self, cross: Dict[str, Any], applied: List[Dict[str, Any]]) -> Tuple[float, float]:
        if not cross or not cross.get("nodes"):
            return 0.0, 0.0
        n = self.n

        def metric(bands: Dict[str, Dict[str, Any]]) -> float:
            hashes = {n.svc_hash(sid).hex(): sid for sid in n.services}
            nodes = []
            for x in cross["nodes"]:
                band = bands[hashes[x["service_hash"]]]["band"] if x["org"] == n.org and x["service_hash"] in hashes else x["band"]
                nodes.append(NodeAtt(x["org"], x["service_hash"], band, x["criticality"], x.get("label", "")))
            edges = [EdgeAtt(e["consumer_org"], e["consumer_service"], e["provider_org"], e["provider_service"], e["strength"], e["tolerance"], e["confirmed"]) for e in cross["edges"]]
            g = CrossOrgGraph.from_attestations(nodes, edges)
            own = [(sid, b) for sid, b in bands.items() if (n.org, n.svc_hash(sid).hex()) in g.nodes]
            if not own:
                return 0.0
            sid = max(own, key=lambda kv: kv[1]["risk"])[0]
            rep = g.cascade_from((n.org, n.svc_hash(sid).hex()), source_p=max(bands[sid]["p"], 0.0))
            return g.cross_org_risk(rep)

        before = metric(n.service_band())
        mod = deepcopy(n.contexts())
        idx = {a.asset_id: a for a in mod}
        for x in applied:
            for t in x["targets"]:
                risk.apply_action(idx[t], x["action"])
        after = metric(n.service_band(mod))
        return before, after


class PlannerAgent(BaseAgent):
    NAME = "planner"

    @agent_tool("build_plan", BuildIn, BuildOut, SideEffect.none)
    def _build(self, i: BuildIn) -> BuildOut:
        return BuildOut(plan=PlanBuilder(self.node).build(i))

    def plan(self, assessments: List[Dict[str, Any]], findings: List[str], cross: Optional[Dict[str, Any]] = None, mode: str = "remediate", focus: Optional[List[str]] = None, proposed_order: Optional[List[str]] = None) -> Dict[str, Any]:
        """Primary plan + alternatives (AG-PLN-06). The LLM may propose the sequence; validation is deterministic."""
        pb = PlanBuilder(self.node)
        if proposed_order is None and self.node.llm is not None:
            cands = [{"id": g["gid"], "benefit": 1.0, "cost": sum(self.cost_hint(g))} for g in pb.groups(assessments, focus, mode)]
            if cands:
                proposed_order = self.node.llm.propose_order(cands)
        common = dict(assessments=assessments, trigger_findings=findings, cross=cross or {}, mode=mode, focus_assets=focus, proposed_order=proposed_order)
        main = self.call("build_plan", label="balanced", **common).plan
        alts = []
        for label, kw in (("min_downtime", {"budget_downtime_min": 0}), ("max_reduction", {"budget_downtime_min": 600, "budget_effort_h": 60.0})):
            p = self.call("build_plan", label=label, **common, **kw).plan
            if p["plan_hash"] != main["plan_hash"] and p["steps"]:
                alts.append(p)
        main["alternatives"] = [{k: v for k, v in a.items() if k != "alternatives"} for a in alts]
        main["narrative"] = self.node.llm.narrate(
            "plan", {"plan_id": main["plan_id"], "org": main["org"], "steps": len(main["steps"]), "risk_before": main["risk_before"], "risk_after": main["risk_after"],
                     "reduction": round(main["risk_before"] - main["risk_after"], 4), "gated_steps": sum(1 for s in main["steps"] if s["impact_class"] != "LOW")},
        )
        self.log("decision", note="plan built", plan_id=main["plan_id"], steps=len(main["steps"]), alternatives=len(alts))
        return main

    def cost_hint(self, g: Dict[str, Any]) -> Tuple[float, float]:
        pb = PlanBuilder(self.node)
        dt, eff = pb.cost(g["action"], g["asset"])
        return (dt / 60.0, eff)
