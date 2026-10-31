"""
CascadeShieldSystem: wires chain, writer, indexer and the three org nodes (each with its own agent set).
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from backend.agents.framework import MessageBus
from backend.agents.llm import LLMClient
from backend.agents.org_node import OrgNodeRuntime, STRENGTH, tolerance_bucket
from backend.agents.orchestrator import Orchestrator
from backend.common.chain import Chain, ChainWriter, ORGS, org_id
from backend.common.events import EventIndexer
from backend.humans import HumanApprover

ROOT = Path(__file__).resolve().parents[1]


class CascadeShieldSystem:
    def __init__(self, rpc_url: str = "http://127.0.0.1:8545", deployment_file: Optional[str] = None, state_dir: Optional[Path] = None, llm_provider: str = "offline"):
        self.state_dir = Path(state_dir) if state_dir else ROOT / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.chain = Chain(rpc_url, deployment_file)
        self.writer = ChainWriter(self.chain, self.state_dir / "writer.db")
        self.indexer = EventIndexer(self.chain, self.state_dir / "events.db")
        self.bus = MessageBus()
        self.events: List[Dict[str, Any]] = []
        self._ev_lock = threading.Lock()
        self.nodes: Dict[str, OrgNodeRuntime] = {}
        self.orch: Dict[str, Orchestrator] = {}
        for org in ORGS:
            node = OrgNodeRuntime(org, self.chain, self.writer, self.state_dir, llm=LLMClient(llm_provider), bus=self.bus)
            node.indexer = self.indexer
            self.nodes[org] = node
            self.orch[org] = Orchestrator(node, on_event=self._on_event)
        self.humans = {org: HumanApprover(self.chain, org) for org in ORGS}
        self.chain.verify_genesis()

    def _on_event(self, ev: Dict[str, Any]) -> None:
        with self._ev_lock:
            self.events.append(ev)

    # ------------------------------------------------------------------ setup
    def bootstrap(self, extra_unilateral: bool = True) -> Dict[str, Any]:
        """Supply-chain check, bilateral dependency handshake + attestations, baseline risk attestations."""
        out: Dict[str, Any] = {"supply_chain": {}, "edges": [], "baseline": {}}
        for org, node in self.nodes.items():
            out["supply_chain"][org] = node.supply_chain_check()
        deps = json.loads((ROOT / "data" / "cross_org_dependencies.json").read_text(encoding="utf-8"))
        for d in deps:
            c, p = self.nodes[d["consumer_org"]], self.nodes[d["provider_org"]]
            ch = c.handshake_accept(p.handshake_offer(d["provider_service"]))  # consumer learns provider hash
            ph = p.handshake_accept(c.handshake_offer(d["consumer_service"]))  # provider learns consumer hash
            assert ch == p.svc_hash(d["provider_service"]) and ph == c.svc_hash(d["consumer_service"])
            strength, tol = STRENGTH[d["dependency_strength"]], tolerance_bucket(d["tolerance_minutes"])
            r1 = c.attest_dependency(d["consumer_org"], c.svc_hash(d["consumer_service"]), d["provider_org"], ph if False else p.svc_hash(d["provider_service"]), strength, tol)
            r2 = p.attest_dependency(d["consumer_org"], c.svc_hash(d["consumer_service"]), d["provider_org"], p.svc_hash(d["provider_service"]), strength, tol)
            out["edges"].append({"edge": f"{d['consumer_org']}:{d['consumer_service']} -> {d['provider_org']}:{d['provider_service']}", "consumer": r1.status, "provider": r2.status})
        if extra_unilateral:
            # An edge only ONE side attests: must stay unconfirmed and never feed the cascade (BC-ATT-D-01 / AG-CAS-04).
            h, pw = self.nodes["hospital"], self.nodes["power"]
            svc = next(iter(h.services))
            r = h.attest_dependency("hospital", h.svc_hash(svc), "power", pw.svc_hash(next(iter(pw.services))), 1, 0)
            out["unilateral"] = r.status
        for org, node in self.nodes.items():
            orch = self.orch[org]
            trace_agent = orch.risk
            from backend.agents.framework import Trace

            tr = Trace(org, "baseline")
            trace_agent.bind(tr)
            res = trace_agent.assess(None, force_attest=True)
            node.audit.save_trace(tr.to_dict())
            out["baseline"][org] = {"aggregate": res["org_aggregate"], "attested": len(res["attested"])}
        self.indexer.sync()
        return out

    # ----------------------------------------------------------------- running
    def ingest(self, text: str, source: str = "feed", orgs: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
        """Every org node processes the shared advisory against ITS OWN private inventory."""
        res = {}
        for org in orgs or ORGS:
            res[org] = self.orch[org].run_advisory(text, source)
        self.indexer.sync()
        return res

    def react_all(self) -> Dict[str, Any]:
        """Each org polls the chain for alerts relevant via confirmed edges, acknowledges, and hardens pre-emptively."""
        self.indexer.sync()
        out = {}
        for org, orch in self.orch.items():
            from backend.agents.framework import Trace

            tr = Trace(org, "react-to-alerts")
            orch.cascade.bind(tr)
            reacted = orch.cascade.react_to_alerts()
            out[org] = reacted
            if reacted["reacted"]:
                orch.risk.bind(tr)
                orch.risk.call("attest_service_risk", force=True)
            self.nodes[org].audit.save_trace(tr.to_dict())
        self.indexer.sync()
        return out

    def flush_audit(self) -> Dict[str, Any]:
        return {org: n.audit.flush_traces() for org, n in self.nodes.items()}

    def verify_audit(self) -> Dict[str, Any]:
        return {org: n.audit.verify() for org, n in self.nodes.items()}

    # ------------------------------------------------------------- kill switch
    def pause(self, by: str = "approver") -> None:
        """AG-SAF-04: audit-log the pause on-chain FIRST (approver-signed), then block all agent writes."""
        for org, node in self.nodes.items():
            node.audit.anchor("Pause", bytes.fromhex(f"{int(time.time()*1000):064x}"), signer=f"{org}/approver0")
        self.writer.pause()

    def resume(self) -> None:
        self.writer.resume()
        for org, node in self.nodes.items():
            node.audit.anchor("Resume", bytes.fromhex(f"{int(time.time()*1000):064x}"), signer=f"{org}/approver0")

    def metrics(self) -> Dict[str, Any]:
        m = {org: o.metrics for org, o in self.orch.items()}
        agg = {"advisories": sum(x["advisories"] for x in m.values()), "critic_reject_rate": 0.0, "llm_fallback_rate": 0.0, "injection_detections": sum(x["injection"] for x in m.values()),
               "gate_requests": sum(x["approvals_requested"] for x in m.values()), "executed": sum(x["executed"] for x in m.values())}
        lat = [t for x in m.values() for t in x["latency_s"]]
        agg["mean_pipeline_latency_s"] = round(sum(lat) / len(lat), 3) if lat else 0.0
        reviews = sum(x["critic_reject"] + x["critic_approve"] for x in m.values())
        agg["critic_reject_rate"] = round(sum(x["critic_reject"] for x in m.values()) / reviews, 3) if reviews else 0.0
        agg["llm_fallback_rate"] = round(sum(x["llm_fallback"] for x in m.values()) / max(agg["advisories"], 1), 3)
        return {"per_org": m, "total": agg}
