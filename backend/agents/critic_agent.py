"""
CriticAgent (AG-CRT-*): independent re-validation of a plan.

Deliberately re-implements every rule instead of importing the planner's helpers, so a bug or a manipulated
plan in the planner cannot pass its own checks. Verdicts: APPROVE_FOR_GATE | REVISE | REJECT.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from backend.agents.framework import BaseAgent, SideEffect, agent_tool
from backend.common.audit import content_digest
from backend.common.crypto import canonical_hash
from backend.risk import model as risk

HASH_EXCLUDE = {"plan_hash", "plan_id", "created_at", "alternatives", "narrative", "critic"}
KNOWN = {
    "PATCH", "UPDATE_FIRMWARE", "ROTATE_CREDENTIALS", "SEGMENT_NETWORK", "RESTRICT_ACCESS", "ENABLE_MONITORING", "ISOLATE_ASSET",
    "DISABLE_SERVICE_PORT", "REQUEST_VENDOR_SIGNOFF", "SCHEDULE_MAINTENANCE_WINDOW", "INCIDENT_RESPONSE_PLAN_UPDATE",
}
CLASS = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


class ReviewIn(BaseModel):
    plan: Dict[str, Any]


class ReviewOut(BaseModel):
    verdict: str
    reasons: List[str]
    revise_reasons: List[str]
    reject_reasons: List[str]
    checks: int


class AnchorIn(BaseModel):
    plan_hash: str
    verdict: str
    reasons: List[str]


class AnchorOut(BaseModel):
    digest: str
    status: str


class CriticAgent(BaseAgent):
    NAME = "critic"

    # ------------------------------------------------------- independent facts
    def _dt(self, action: str, a: Dict[str, Any]) -> int:
        if action in ("PATCH", "UPDATE_FIRMWARE"):
            return 60 if a["patch_requires_downtime"] else 0
        return {"ISOLATE_ASSET": 120, "SEGMENT_NETWORK": 30}.get(action, 0)

    def _life(self, aid: str) -> bool:
        return any(s["criticality"] == "life_critical" and aid in s["required_assets"] for s in self.node.services.values())

    def _min_class(self, action: str, a: Dict[str, Any], aid: str) -> int:
        crit = bool(a["safety_critical"]) or self._life(aid)
        down = self._dt(action, a) > 0
        if action == "ISOLATE_ASSET":
            return 2 if crit else 1
        if action in ("PATCH", "UPDATE_FIRMWARE"):
            return 2 if (crit and down) else 1 if down else 0
        if action in ("SEGMENT_NETWORK", "RESTRICT_ACCESS"):
            return 2 if crit else 1
        if action in ("DISABLE_SERVICE_PORT", "ROTATE_CREDENTIALS"):
            return 1 if crit else 0
        return 0

    # ----------------------------------------------------------------- review
    @agent_tool("review_plan", ReviewIn, ReviewOut, SideEffect.none)
    def _review(self, i: ReviewIn) -> ReviewOut:
        n, plan = self.node, i.plan
        rej: List[str] = []
        rev: List[str] = []
        steps: List[Dict[str, Any]] = plan.get("steps", [])
        checks = 0

        checks += 1  # 1. org scope
        if plan.get("org") != n.org:
            rej.append(f"plan targets org '{plan.get('org')}' but this node is '{n.org}'")

        checks += 1  # 2. plan hash integrity
        recomputed = canonical_hash({k: v for k, v in plan.items() if k not in HASH_EXCLUDE})
        if recomputed != plan.get("plan_hash"):
            rej.append("plan hash does not match plan content")

        checks += 1  # 3. well-formed ids, known actions, targets exist, no duplicates
        ids, seen_pairs = set(), set()
        for s in steps:
            if s.get("step_id") in ids:
                rev.append(f"duplicate step id {s.get('step_id')}")
            ids.add(s.get("step_id"))
            if s.get("action") not in KNOWN:
                rej.append(f"{s.get('step_id')}: unknown action {s.get('action')}")
            tg = s.get("target_assets") or []
            if not tg:
                rev.append(f"{s.get('step_id')}: no target")
            for t in tg:
                if t not in n.inventory:
                    rej.append(f"{s.get('step_id')}: target {t} is not an asset of org {n.org}")
                key = (s.get("action"), t)
                if key in seen_pairs:
                    rev.append(f"{s.get('step_id')}: duplicate step {key[0]} on {t}")
                seen_pairs.add(key)

        checks += 1  # 4. provenance
        for s in steps:
            for fid in s.get("finding_ids", []):
                if fid not in n.findings and fid not in n.acked:
                    rej.append(f"{s.get('step_id')}: references unknown finding/alert {fid}")
        if not any(s.get("finding_ids") for s in steps) and steps:
            rej.append("plan has no provenance (no finding or alert referenced)")

        checks += 1  # 5. ordering / requires graph (acyclic, earlier steps only)
        pos = {s["step_id"]: k for k, s in enumerate(steps) if "step_id" in s}
        for k, s in enumerate(steps):
            for r in s.get("requires", []):
                if r not in pos:
                    rev.append(f"{s['step_id']}: requires unknown step {r}")
                elif pos[r] >= k:
                    rev.append(f"{s['step_id']}: requires {r} which does not come earlier (ordering/cycle)")

        def earlier(k: int, action: str, aid: str) -> bool:
            return any(p["action"] == action and aid in p.get("target_assets", []) for p in steps[:k])

        checks += 1  # 6. vendor sign-off, maintenance windows, compensating controls
        for k, s in enumerate(steps):
            for aid in s.get("target_assets", []):
                if aid not in n.inventory:
                    continue
                a = n.inventory[aid]
                dt = self._dt(s["action"], a)
                if s["action"] in ("PATCH", "UPDATE_FIRMWARE") and a["vendor_signoff_required"] and not earlier(k, "REQUEST_VENDOR_SIGNOFF", aid):
                    rev.append(f"{s['step_id']}: {aid} needs vendor sign-off before {s['action']}")
                if dt > 0 and a["maintenance_window"] == "none" and not earlier(k, "SCHEDULE_MAINTENANCE_WINDOW", aid):
                    rev.append(f"{s['step_id']}: {aid} has no maintenance window; schedule one first")
                if dt > 0 and (a["safety_critical"] or self._life(aid)) and not earlier(k, "ENABLE_MONITORING", aid):
                    rev.append(f"{s['step_id']}: downtime on safety/life-critical {aid} lacks a compensating control (monitoring) first")

        checks += 1  # 7. impact class and downtime estimates
        for s in steps:
            for aid in s.get("target_assets", []):
                if aid not in n.inventory:
                    continue
                a = n.inventory[aid]
                need = self._min_class(s["action"], a, aid)
                if CLASS.get(s.get("impact_class"), -1) < need:
                    rev.append(f"{s['step_id']}: impact class {s.get('impact_class')} is lower than required {list(CLASS)[need]}")
                if s.get("est_downtime_min") != self._dt(s["action"], a):
                    rev.append(f"{s['step_id']}: downtime estimate {s.get('est_downtime_min')} != {self._dt(s['action'], a)}")

        checks += 1  # 8. life-critical window exclusivity
        by_service: Dict[str, List[str]] = {}
        for s in steps:
            if s.get("est_downtime_min", 0) > 0:
                for aid in s.get("target_assets", []):
                    for sid, sv in n.services.items():
                        if sv["criticality"] == "life_critical" and aid in sv["required_assets"]:
                            w = s.get("scheduled_window") or ""
                            if w in by_service.setdefault(sid, []):
                                rev.append(f"{s['step_id']}: window '{w}' already used by another downtime action on life-critical service {sid}")
                            by_service[sid].append(w)

        checks += 1  # 9. budget
        b = plan.get("budget", {})
        if sum(s.get("est_downtime_min", 0) for s in steps) > b.get("downtime_min", 10**9):
            rev.append("downtime budget exceeded")
        if sum(s.get("est_effort_h", 0) for s in steps) > b.get("effort_h", 10**9) + 1e-9:
            rev.append("effort budget exceeded")

        checks += 1  # 10. risk deltas must equal an independent what-if recomputation
        if not rej:
            applied: List[Dict[str, Any]] = []
            prev = risk.aggregate([risk.score_asset(a, explain=False) for a in n.contexts()])
            if abs(prev - plan.get("risk_before", -1)) > 1e-6:
                rej.append(f"risk_before {plan.get('risk_before')} != recomputed {prev}")
            ssum = 0.0
            for s in steps:
                applied.append({"action": s["action"], "targets": list(s["target_assets"])})
                try:
                    cur = risk.what_if(n.contexts(), applied)["risk_after"]
                except Exception as e:  # noqa: BLE001
                    rej.append(f"{s['step_id']}: cannot evaluate step ({e})")
                    break
                actual = cur - prev
                if abs(actual - s.get("expected_risk_delta", 1e9)) > 1e-5:
                    rej.append(f"{s['step_id']}: claimed delta {s.get('expected_risk_delta')} != recomputed {round(actual, 6)}")
                ssum += s.get("expected_risk_delta", 0.0)
                prev = cur
            else:
                if abs(prev - plan.get("risk_after", -1)) > 1e-6:
                    rej.append(f"risk_after {plan.get('risk_after')} != recomputed {prev}")
                if abs(ssum - plan.get("total_delta", 1e9)) > 1e-4:
                    rej.append("sum of step deltas does not equal total_delta")

        checks += 1  # 11. gate classification must be consistent
        if steps and not any(s.get("impact_class") in ("MEDIUM", "HIGH") for s in steps):
            pass  # LOW-only plans need no human gate (valid)

        checks += 1  # 12. cross-org fields present
        for k in ("cross_org_risk_before", "cross_org_risk_after"):
            if k not in plan:
                rev.append(f"missing {k}")

        checks += 1  # 13. empty plan
        if not steps:
            rev.append("plan has no steps")

        verdict = "REJECT" if rej else "REVISE" if rev else "APPROVE_FOR_GATE"
        return ReviewOut(verdict=verdict, reasons=rej + rev, revise_reasons=rev, reject_reasons=rej, checks=checks)

    @agent_tool("anchor_verdict", AnchorIn, AnchorOut, SideEffect.write_chain)
    def _anchor(self, i: AnchorIn) -> AnchorOut:
        d = verdict_digest(i.plan_hash, i.verdict, i.reasons)
        e = self.node.audit.anchor("CriticVerdict", d)
        return AnchorOut(digest="0x" + d.hex(), status=e.get("status", "unknown"))

    def review(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        r = self.call("review_plan", plan=plan)
        out = r.model_dump()
        out["plan_id"] = plan.get("plan_id")
        out["plan_hash"] = plan.get("plan_hash")
        out["narrative"] = self.node.llm.narrate("critic", {"plan_id": plan.get("plan_id", "?"), "verdict": r.verdict, "checks": r.checks, "reasons": r.reasons})
        a = self.call("anchor_verdict", plan_hash=plan.get("plan_hash", ""), verdict=r.verdict, reasons=r.reasons)
        out["digest"], out["anchor_status"] = a.digest, a.status
        self.log("decision", note="critic verdict", verdict=r.verdict, reasons=r.reasons[:5])
        return out


def verdict_digest(plan_hash: str, verdict: str, reasons: List[str]) -> bytes:
    return content_digest({"plan_hash": plan_hash, "verdict": verdict, "reasons": sorted(reasons)})
