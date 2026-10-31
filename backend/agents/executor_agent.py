"""
ExecutorAgent (AG-ACT-*): applies remediation to SIMULATED state only, and only after the on-chain gate says so.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from backend.agents.framework import BaseAgent, GateViolation, SideEffect, agent_tool
from backend.common.audit import content_digest
from backend.risk import model as risk

APPROVED, EXECUTED = 2, 5
STATUS_NAMES = ["None", "Pending", "Approved", "Rejected", "Expired", "Executed", "Cancelled"]


def plan_hash_bytes(h: str) -> bytes:
    return bytes.fromhex(h.replace("0x", ""))


class GateIn(BaseModel):
    request_id: str
    plan_hash: str


class GateOut(BaseModel):
    ok: bool
    status: str


class MarkIn(BaseModel):
    request_id: str
    execution_digest: str


class MarkOut(BaseModel):
    status: str
    tx_hash: Optional[str] = None


class AnchorExecIn(BaseModel):
    digest: str
    note: str = "execution"


class AnchorExecOut(BaseModel):
    status: str


class ExecutorAgent(BaseAgent):
    NAME = "executor"

    @agent_tool("check_gate", GateIn, GateOut, SideEffect.read_chain)
    def _check(self, i: GateIn) -> GateOut:
        """AG-ACT-02: status Approved, plan hash equal, not expired, not already executed."""
        n = self.node
        rid = bytes.fromhex(i.request_id.replace("0x", ""))
        st = int(n.chain.call("ApprovalGate", "status", rid))
        if st == 0:
            raise GateViolation("approval request does not exist")
        if st != APPROVED:
            raise GateViolation(f"approval request is {STATUS_NAMES[st]}, not Approved")
        on_hash = bytes(n.chain.call("ApprovalGate", "planHashOf", rid))
        if on_hash != plan_hash_bytes(i.plan_hash):
            raise GateViolation("plan hash on-chain differs from the plan being executed")
        return GateOut(ok=True, status="Approved")

    @agent_tool("mark_executed", MarkIn, MarkOut, SideEffect.write_chain)
    def _mark(self, i: MarkIn) -> MarkOut:
        n = self.node
        r = n.writer.submit(f"exec:{n.org}:{i.request_id[:20]}", "ApprovalGate", "markExecuted", [i.request_id, i.execution_digest])
        return MarkOut(status=r.status, tx_hash=r.tx_hash)

    @agent_tool("anchor_execution", AnchorExecIn, AnchorExecOut, SideEffect.write_chain)
    def _anchor(self, i: AnchorExecIn) -> AnchorExecOut:
        e = self.node.audit.anchor("Execution", bytes.fromhex(i.digest.replace("0x", "")), idem=f"exec-anchor:{self.node.org}:{i.digest[:20]}:{i.note}")
        return AnchorExecOut(status=e.get("status", "unknown"))

    # ------------------------------------------------------------------ run
    def execute(self, plan: Dict[str, Any], request_id: Optional[str] = None, dry_run: bool = False) -> Dict[str, Any]:
        n = self.node
        steps = plan["steps"]
        gated = any(s["impact_class"] in ("MEDIUM", "HIGH") for s in steps)
        if n.writer.paused and not dry_run:
            from backend.common.chain import ChainPaused

            raise ChainPaused("executor is paused by the kill switch")
        if plan["plan_id"] in n.executed_plans and not dry_run and not n.executed_plans[plan["plan_id"]].get("rolled_back"):
            raise GateViolation("plan already executed")
        if gated:
            if not request_id:
                raise GateViolation("plan contains MEDIUM/HIGH steps and has no approval request")
            self.call("check_gate", request_id=request_id, plan_hash=plan["plan_hash"])

        snap = n.snapshot()
        before = risk.aggregate([risk.score_asset(a, explain=False) for a in n.contexts()])
        results: List[Dict[str, Any]] = []
        for s in steps:
            for aid in s["target_assets"]:
                risk.apply_action(n.assets[aid], s["action"])
            results.append({"step_id": s["step_id"], "action": s["action"], "targets": s["target_assets"], "status": "applied"})
        after = risk.aggregate([risk.score_asset(a, explain=False) for a in n.contexts()])
        record = {
            "plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "org": n.org, "request_id": request_id, "steps": results,
            "risk_before": before, "risk_after": after, "actual_delta": round(after - before, 6), "predicted_delta": plan["total_delta"],
            "drift": round(abs((after - before) - plan["total_delta"]), 6), "dry_run": dry_run,
        }
        digest = content_digest(record)
        record["result_hash"] = "0x" + digest.hex()
        if dry_run:
            n.restore(snap)
            return record
        try:
            if gated:
                m = self.call("mark_executed", request_id=request_id, execution_digest=record["result_hash"])
                if m.status not in ("confirmed", "duplicate"):
                    raise GateViolation(f"markExecuted not confirmed ({m.status})")
            self.call("anchor_execution", digest=record["result_hash"])
        except Exception:
            n.restore(snap)  # chain refused: simulated state must not diverge from what was authorised
            raise
        n.executed_plans[plan["plan_id"]] = {"snapshot": snap, "record": record, "rolled_back": False}
        self.log("decision", note="plan executed", plan_id=plan["plan_id"], actual_delta=record["actual_delta"])
        return record

    def rollback(self, plan_id: str) -> Dict[str, Any]:
        """AG-ACT-04: restore the pre-execution simulated state; the rollback itself is audit-logged."""
        n = self.node
        e = n.executed_plans.get(plan_id)
        if not e or e["rolled_back"]:
            raise KeyError("nothing to roll back")
        n.restore(e["snapshot"])
        e["rolled_back"] = True
        d = content_digest({"rollback": plan_id, "org": n.org, "to": e["record"]["risk_before"]})
        self.call("anchor_execution", digest="0x" + d.hex(), note="rollback")
        return {"plan_id": plan_id, "rolled_back": True, "digest": "0x" + d.hex()}
