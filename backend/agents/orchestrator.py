"""
Orchestrator (AG-ORC-*): per-org finite-state pipeline  Intake -> Risk -> Cascade -> Plan -> Critic -> Gate -> Execute.
State is persisted after every stage so a restarted node resumes without repeating (or duplicating chain writes).
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from backend.agents import advisory_parser as P
from backend.agents.cascade_agent import CascadeAgent
from backend.agents.critic_agent import CriticAgent
from backend.agents.executor_agent import ExecutorAgent, plan_hash_bytes
from backend.agents.framework import GateViolation, Trace
from backend.agents.intake_agent import IntakeAgent
from backend.agents.planner_agent import PlannerAgent
from backend.agents.risk_agent import RiskAgent
from backend.common.chain import ChainPaused, ChainRevert
from backend.risk import model as risk

STAGES = ["intake", "risk", "cascade", "plan", "critic", "gate", "execute"]
MAX_REVISIONS = 3
IMPACT = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
TERMINAL = {"no_match", "duplicate", "injection_blocked", "rejected", "low_only_executed", "executed", "awaiting_approval"}


class Orchestrator:
    def __init__(self, node, on_event: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.node = node
        self.on_event = on_event
        self.intake, self.risk, self.cascade = IntakeAgent(node), RiskAgent(node), CascadeAgent(node)
        self.planner, self.critic, self.executor = PlannerAgent(node), CriticAgent(node), ExecutorAgent(node)
        self.agents = [self.intake, self.risk, self.cascade, self.planner, self.critic, self.executor]
        self.dir = Path(node.state_dir) / "pipelines" / node.org
        self.dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self._sem: Optional[asyncio.Semaphore] = None
        self.metrics = {"advisories": 0, "latency_s": [], "critic_reject": 0, "critic_revise": 0, "critic_approve": 0, "llm_fallback": 0, "injection": 0, "approvals_requested": 0, "executed": 0, "failed": 0}
        load_state(node)

    # ------------------------------------------------------------------ events
    def emit(self, stage: str, status: str, pipeline_id: str, **kw: Any) -> None:
        ev = {"ts": round(time.time(), 3), "org": self.node.org, "pipeline_id": pipeline_id, "stage": stage, "status": status, **kw}
        if self.on_event:
            self.on_event(ev)

    def _save(self, p: Dict[str, Any]) -> None:
        (self.dir / f"{p['pipeline_id']}.json").write_text(json.dumps(p, indent=2, default=str), encoding="utf-8")

    def load(self, pipeline_id: str) -> Optional[Dict[str, Any]]:
        f = self.dir / f"{pipeline_id}.json"
        return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None

    # ---------------------------------------------------------------- pipeline
    def run_advisory(self, text: str, source: str = "feed", pipeline_id: Optional[str] = None) -> Dict[str, Any]:
        """Run (or resume) the pipeline for one advisory. Never raises for agent failures: status becomes 'degraded'/'failed'."""
        node = self.node
        pid = pipeline_id or ("pl-" + P.content_hash(text)[:12])
        with self.lock:
            p = self.load(pid) or {"pipeline_id": pid, "org": node.org, "source": source, "status": "running", "done": {}, "stages": {}, "started": time.time()}
            if p["status"] in TERMINAL:
                return p
            trace = Trace(node.org, f"advisory:{pid}")  # a resumed run gets a NEW trace; anchored traces are immutable
            p["trace_id"] = trace.trace_id
            p.setdefault("trace_ids", []).append(trace.trace_id)
            for a in self.agents:
                a.bind(trace)
            t0 = time.time()
            try:
                self._run(p, text, source, trace)
            except ChainPaused as e:
                p["status"], p["error"] = "paused", str(e)
            except Exception as e:  # noqa: BLE001 — AG-ORC-02: partial failure must not crash the node
                p["status"], p["error"] = "failed", f"{type(e).__name__}: {e}"
                trace.add("failure", "orchestrator", error=p["error"])
                self.metrics["failed"] += 1
                self.emit(p.get("failed_stage", "pipeline"), "failed", pid, error=p["error"])
            trace.status = p["status"]
            node.audit.save_trace(trace.to_dict())
            self.metrics["advisories"] += 1
            self.metrics["latency_s"].append(round(time.time() - t0, 3))
            if trace.flags.get("injection_suspected"):
                self.metrics["injection"] += 1
            p["finished"] = time.time()
            self._save(p)
            save_state(node)
            return p

    def _stage(self, p: Dict[str, Any], name: str, fn: Callable[[], Any]) -> Any:
        if name in p["done"]:
            return p["stages"][name]
        p["failed_stage"] = name
        self.emit(name, "started", p["pipeline_id"])
        out = fn()
        p["stages"][name] = out
        p["done"][name] = True
        self.emit(name, "completed", p["pipeline_id"])
        self._save(p)
        save_state(self.node)
        return out

    def _run(self, p: Dict[str, Any], text: str, source: str, trace: Trace) -> None:
        node, pid = self.node, p["pipeline_id"]
        finding = self._stage(p, "intake", lambda: self.intake.process(text, source))
        node.findings.setdefault(finding["advisory_id"], finding)
        if finding["status"] == "injection":
            p["status"] = "injection_blocked"
            return
        if finding["status"] == "no_match" or finding.get("duplicate"):
            p["status"] = "no_match" if finding["status"] == "no_match" else "duplicate"
            return
        if finding.get("llm_fallback"):
            self.metrics["llm_fallback"] += 1

        rk = self._stage(p, "risk", lambda: self.risk.assess(finding))
        cs = self._stage(p, "cascade", lambda: self.cascade.analyse(rk["all"]) | {"cross_input": self.cascade.call("build_cross_graph").model_dump()})
        plan = self._stage(p, "plan", lambda: self.planner.plan(rk["all"], [finding["advisory_id"]], cs.get("cross_input"), focus=None))
        verdict = self._stage(p, "critic", lambda: self._critic_loop(plan, rk, cs, finding))
        final_plan = verdict.pop("final_plan", plan) if isinstance(verdict, dict) else plan
        p["plan"] = final_plan
        node.plans[final_plan["plan_id"]] = final_plan
        if verdict["verdict"] != "APPROVE_FOR_GATE":
            p["status"] = "rejected"
            self.metrics["critic_reject"] += 1
            self.emit("critic", "rejected", pid, reasons=verdict["reasons"][:5])
            return
        self.metrics["critic_approve"] += 1
        final_plan["critic"] = {k: verdict[k] for k in ("verdict", "digest", "anchor_status")}
        gate = self._stage(p, "gate", lambda: self.request_gate(final_plan, verdict))
        if gate["required"]:
            p["status"] = "awaiting_approval"
            p["request_id"] = gate["request_id"]
            self.emit("gate", "awaiting_approval", pid, request_id=gate["request_id"])
            return
        ex = self._stage(p, "execute", lambda: self.execute(final_plan, None))
        p["status"] = "low_only_executed"
        p["execution"] = ex

    def _critic_loop(self, plan: Dict[str, Any], rk: Dict[str, Any], cs: Dict[str, Any], finding: Dict[str, Any]) -> Dict[str, Any]:
        cur, v = plan, None
        for it in range(MAX_REVISIONS):
            v = self.critic.review(cur)
            if v["verdict"] != "REVISE":
                break
            self.metrics["critic_revise"] += 1
            cur = self.planner.plan(rk["all"], [finding["advisory_id"]], cs.get("cross_input"))
        else:
            v["verdict"] = "REJECT"
            v["reasons"].append(f"still failing after {MAX_REVISIONS} revisions: escalated")
        v["final_plan"] = cur
        return v

    # -------------------------------------------------------------------- gate
    def request_gate(self, plan: Dict[str, Any], verdict: Dict[str, Any]) -> Dict[str, Any]:
        """AG-CRT-05: only a plan with an anchored APPROVE_FOR_GATE verdict may be submitted."""
        node = self.node
        if (plan.get("critic") or {}).get("verdict") != "APPROVE_FOR_GATE" or verdict.get("verdict") != "APPROVE_FOR_GATE":
            raise GateViolation("a plan must carry an APPROVE_FOR_GATE critic verdict before it can be submitted")
        if verdict.get("plan_hash") != plan["plan_hash"]:
            raise GateViolation("critic verdict belongs to a different plan")
        top = max(IMPACT[s["impact_class"]] for s in plan["steps"])
        if top == 0:
            return {"required": False}
        steps_hash = bytes.fromhex(__import__("hashlib").sha256(json.dumps([s["step_id"] for s in plan["steps"]]).encode()).hexdigest())
        expiry = node.chain.block_timestamp() + 3600
        r = node.writer.submit(
            f"gate:{node.org}:{plan['plan_hash'][:24]}", "ApprovalGate", "requestApproval",
            [node.org_id, plan_hash_bytes(plan["plan_hash"]), steps_hash, top, expiry, bytes.fromhex(verdict["digest"][2:])],
        )
        rid = None
        if r.receipt is not None:
            for lg in r.receipt["logs"]:
                try:
                    rid = "0x" + bytes(node.chain.contracts["ApprovalGate"].events.ApprovalRequested().process_log(lg)["args"]["requestId"]).hex()
                except Exception:  # noqa: BLE001
                    continue
        if rid is None:  # duplicate/deferred: find it from the persisted record
            known = [k for k, v in node.pending_approvals.items() if v["plan_hash"] == plan["plan_hash"]]
            rid = known[0] if known else None
        if rid is None:
            raise GateViolation(f"approval request not created ({r.status})")
        node.pending_approvals[rid] = {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "impact": IMPACT.get(max(plan["steps"], key=lambda s: IMPACT[s["impact_class"]])["impact_class"]), "created": time.time()}
        self.metrics["approvals_requested"] += 1
        return {"required": True, "request_id": rid, "impact": top}

    def execute(self, plan: Dict[str, Any], request_id: Optional[str]) -> Dict[str, Any]:
        rec = self.executor.execute(plan, request_id)
        # re-score, re-attest, snapshot, flush traces -> dashboards show the real post-action delta
        self.risk.call("attest_service_risk", force=True)
        self.risk.call("record_snapshot", note=f"post:{plan['plan_id']}")
        self.metrics["executed"] += 1
        return rec

    # ApprovalGate states after which a request can never be executed. "None" means this chain has no such request
    # (e.g. saved state from a previous chain); a live entry always exists on-chain, its id comes from the mined receipt.
    FINAL_STATES = ("None", "Rejected", "Expired", "Executed", "Cancelled")

    def prune_resolved_approvals(self, status_of: Callable[[str], Dict[str, Any]]) -> List[str]:
        """Drop pending requests the chain has already closed (rejected, expired, cancelled, executed elsewhere).

        Only execution removed entries before, so a rejected or expired request stayed listed as pending forever.
        status_of(request_id) returns the approver view (status, seconds_left). The chain stays the source of truth:
        if it cannot be read, nothing is removed."""
        node = self.node
        removed = []
        for rid in list(node.pending_approvals):
            try:
                v = status_of(rid)
            except Exception:  # noqa: BLE001  chain unreachable or unknown id: keep the entry, decide later
                continue
            expired = v.get("status") == "Pending" and v.get("seconds_left", 1) <= 0
            if v.get("status") in self.FINAL_STATES or expired:
                removed.append(rid)
        if removed:
            with self.lock:
                for rid in removed:
                    node.pending_approvals.pop(rid, None)
                save_state(node)
        return removed

    def continue_after_approval(self, request_id: str) -> Dict[str, Any]:
        """Call once humans approved on-chain. The executor re-verifies everything against the chain."""
        node = self.node
        info = node.pending_approvals.get(request_id)
        if not info:
            raise KeyError("unknown approval request")
        plan = node.plans[info["plan_id"]]
        trace = Trace(node.org, f"execute:{request_id[:12]}")
        for a in self.agents:
            a.bind(trace)
        with self.lock:
            rec = self.execute(plan, request_id)
            node.pending_approvals.pop(request_id, None)
            trace.status = "executed"
            node.audit.save_trace(trace.to_dict())
            save_state(node)
        self.emit("execute", "executed", request_id, plan_id=plan["plan_id"])
        return rec

    # --------------------------------------------------------------- concurrency
    async def process_many(self, texts: List[str], source: str = "feed") -> List[Dict[str, Any]]:
        """AG-ORC-03: bounded concurrency; chain writes stay ordered per signer via the writer's nonce lock."""
        from backend.common.config import settings

        sem = asyncio.Semaphore(settings.agent_max_concurrent_advisories)

        async def one(t: str) -> Dict[str, Any]:
            async with sem:
                return await asyncio.to_thread(self.run_advisory, t, source)

        return list(await asyncio.gather(*(one(t) for t in texts)))


# --------------------------------------------------------------------- persistence
def _state_file(node) -> Path:
    d = Path(node.state_dir) / "nodes"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{node.org}.json"


def save_state(node) -> None:
    data = {
        "assets": {aid: asdict(a) for aid, a in node.assets.items()}, "findings": node.findings, "plans": node.plans, "pending_approvals": node.pending_approvals,
        "upstream": node.upstream, "last_attested": node.last_attested, "history": node.history, "acked": sorted(node.acked), "baseline": node.baseline,
    }
    _state_file(node).write_text(json.dumps(data, default=str), encoding="utf-8")


def load_state(node) -> None:
    f = _state_file(node)
    if not f.exists():
        return
    d = json.loads(f.read_text(encoding="utf-8"))
    for aid, a in d["assets"].items():
        if aid in node.assets:
            node.assets[aid] = risk.AssetCtx(**a)
    node.findings, node.plans, node.pending_approvals = d["findings"], d["plans"], d["pending_approvals"]
    node.upstream, node.last_attested, node.history, node.acked, node.baseline = d["upstream"], d["last_attested"], d["history"], set(d["acked"]), d["baseline"]
