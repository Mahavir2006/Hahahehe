"""
FastAPI surface (section 9). Org-scoped endpoints require X-Dev-Role: `admin` or `org:<id>`; an org role can never
read another org's private data (API-02).
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from backend.agents.executor_agent import STATUS_NAMES
from backend.agents.framework import GateViolation
from backend.common.chain import ORGS, ChainPaused, ChainRevert, org_id
from backend.system import CascadeShieldSystem

ROOT = Path(__file__).resolve().parents[2]


class Advisory(BaseModel):
    text: str
    source: str = "api"


class Vote(BaseModel):
    org: str
    approver: int = 0


class ExecuteReq(BaseModel):
    request_id: Optional[str] = None


def create_app(system: Optional[CascadeShieldSystem] = None) -> FastAPI:
    app = FastAPI(title="CascadeShield API", version="1.0")
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    holder: Dict[str, Any] = {"sys": system}

    def S() -> CascadeShieldSystem:
        if holder["sys"] is None:
            holder["sys"] = CascadeShieldSystem(
                os.environ.get("CHAIN_RPC_URL", "http://127.0.0.1:8545"), os.environ.get("DEPLOYMENT_FILE"), Path(os.environ.get("STATE_DIR", ROOT / "state"))
            )
        return holder["sys"]

    app.state.holder = holder

    def role(x_dev_role: str = Header(default="admin")) -> str:
        if x_dev_role == "admin" or (x_dev_role.startswith("org:") and x_dev_role[4:] in ORGS):
            return x_dev_role
        raise HTTPException(401, "invalid X-Dev-Role (use 'admin' or 'org:<power|water|hospital>')")

    def need_org(org: str, r: str) -> None:
        if org not in ORGS:
            raise HTTPException(404, "unknown org")
        if r != "admin" and r != f"org:{org}":
            raise HTTPException(403, f"role {r} may not read private data of {org}")

    def need_admin(r: str) -> None:
        if r != "admin":
            raise HTTPException(403, "admin only")

    def find_plan(plan_id: str, r: str):
        for org, n in S().nodes.items():
            if plan_id in n.plans:
                need_org(org, r)
                return org, n.plans[plan_id]
        raise HTTPException(404, "plan not found")

    # ---------------------------------------------------------------- basics
    @app.get("/api/health")
    def health():
        return {"ok": True, "chain_connected": S().chain.is_connected()}

    @app.post("/api/advisories")
    def ingest(a: Advisory, r: str = Depends(role)):
        if not a.text.strip():
            raise HTTPException(422, "empty advisory")
        orgs = [r[4:]] if r.startswith("org:") else None
        res = S().ingest(a.text, a.source, orgs)
        return {org: {k: p.get(k) for k in ("pipeline_id", "status", "request_id", "error", "trace_id")} for org, p in res.items()}

    @app.get("/api/advisories")
    def advisories(r: str = Depends(role)):
        out = []
        for org, n in S().nodes.items():
            if r == "admin" or r == f"org:{org}":
                out += [{"org": org, "advisory_id": f["advisory_id"], "status": f["status"], "cves": f["cve_ids"], "injection_suspected": f["injection_suspected"]} for f in n.findings.values()]
        return out

    @app.get("/api/findings")
    def findings(r: str = Depends(role)):
        out = []
        for org, n in S().nodes.items():
            if r == "admin" or r == f"org:{org}":
                out += [{"org": org, **{k: v for k, v in f.items() if k != "product_ranges"}} for f in n.findings.values()]
        return out

    # ------------------------------------------------------------- org private
    @app.get("/api/orgs/{org}/assets")
    def assets(org: str, r: str = Depends(role)):
        need_org(org, r)
        n = S().nodes[org]
        return [{**n.inventory[aid], "risk_ctx": {"vulns": a.vulns, "supply_chain_flag": a.supply_chain_flag}} for aid, a in n.assets.items()]

    @app.get("/api/orgs/{org}/risk")
    def org_risk(org: str, r: str = Depends(role)):
        need_org(org, r)
        return S().nodes[org].org_risk()

    @app.get("/api/orgs/{org}/services")
    def services(org: str, r: str = Depends(role)):
        need_org(org, r)
        n = S().nodes[org]
        return [{**v, "service_id": k, "band": n.service_band()[k]["band"], "risk": n.service_band()[k]["risk"]} for k, v in n.services.items()]

    def asset_of(org: str, asset_id: str, r: str):
        need_org(org, r)
        n = S().nodes[org]
        if asset_id not in n.assets:
            raise HTTPException(404, "unknown asset")
        return n, n.assets[asset_id]

    @app.get("/api/orgs/{org}/assets/{asset_id}/why")
    def asset_why(org: str, asset_id: str, r: str = Depends(role)):
        from backend.risk import model as M

        _, a = asset_of(org, asset_id, r)
        return M.why(a)

    @app.get("/api/orgs/{org}/assets/{asset_id}/what-changed")
    def asset_what_changed(org: str, asset_id: str, r: str = Depends(role)):
        """SHAP-delta contributors to the change in compromise likelihood since the node booted."""
        from backend.risk import inference as I, model as M

        n, a = asset_of(org, asset_id, r)
        before, after = n.feature_baseline[asset_id], M.features_of(a)
        return {"asset_id": asset_id, "since": "node start", "changes": I.what_changed(before, after)}

    @app.get("/api/orgs/{org}/assets/{asset_id}/trend")
    def asset_trend(org: str, asset_id: str, r: str = Depends(role)):
        from backend.risk import trend

        n, _ = asset_of(org, asset_id, r)
        return trend.asset_trend(getattr(n, "history", []), asset_id)

    @app.get("/api/orgs/{org}/trends")
    def org_trends(org: str, r: str = Depends(role)):
        """M4 for every asset: direction, slope and days to the next band (statistical, not ML)."""
        from backend.risk import trend

        need_org(org, r)
        n = S().nodes[org]
        return [trend.asset_trend(getattr(n, "history", []), aid) for aid in n.assets]

    @app.get("/api/orgs/{org}/findings/detections")
    def detections(org: str, r: str = Depends(role)):
        """Detection-rule (active_attack) and configuration (exposure) findings; never mixed."""
        need_org(org, r)
        n = S().nodes[org]
        return [{"asset_id": aid, **f} for aid, fs in n.detections.items() for f in fs]

    @app.get("/api/ml/model")
    def ml_model(r: str = Depends(role)):
        """Model card: what is learned, how it was evaluated, and its limits. Contains no org data."""
        from backend.common.config import settings
        from backend.risk.inference import M1

        m = M1.get()
        metrics_p = ROOT / "backend" / "risk" / "artifacts" / "metrics.json"
        mt = json.loads(metrics_p.read_text(encoding="utf-8")) if metrics_p.exists() else {}
        ev = mt.get("evaluations", {})
        return {
            "model_version": m.version, "estimator": m.meta["config"]["estimator"], "calibration": m.meta["calibration"]["method"],
            "operating_threshold": m.meta["operating_threshold"], "epss_source": m.meta["epss_source"], "labels": m.meta["labels"],
            "band_thresholds": {"low_max": settings.risk_band_low_max, "medium_max": settings.risk_band_medium_max, "high_max": settings.risk_band_high_max},
            "held_out_A": {k: {x: v.get(x) for x in ("roc_auc", "pr_auc", "top5_precision")} for k, v in ev.get("A_grouped", {}).items()},
            "generator_B": {k: {x: v.get(x) for x in ("roc_auc", "pr_auc")} for k, v in ev.get("B_all", {}).items()},
            "accuracy_ceiling": mt.get("accuracy_ceiling"), "pass_criteria": mt.get("pass_criteria"),
            "learned": ["M1 compromise likelihood"], "deterministic": ["impact", "final risk", "cascade", "what-if wiring", "critic", "approval gate", "detection rules D"],
            "statistical": ["M4 trend"],
        }

    @app.get("/api/orgs/{org}/graph")
    def graph(org: str, r: str = Depends(role)):
        need_org(org, r)
        n = S().nodes[org]
        return {"nodes": [{"id": a, "risk": x["risk"], "band": x["band"]} for a, x in {s["asset_id"]: s for s in n.org_risk()["scores"]}.items()], "edges": [{"from": a, "to": d} for a, ds in n.graph.depends_on.items() for d in ds]}

    # ---------------------------------------------------------------- public
    @app.get("/api/cross-org/graph")
    def cross_graph(r: str = Depends(role)):
        S().indexer.sync()
        return _cross(S())

    def _cross(s: CascadeShieldSystem):
        from backend.agents.cascade_agent import CascadeAgent

        return CascadeAgent(s.nodes["power"]).call("build_cross_graph").model_dump()

    @app.get("/api/cross-org/cascade")
    def cross_cascade(source_org: str = Query(...), source_service: str = Query(...), r: str = Depends(role)):
        s = S()
        s.indexer.sync()
        from backend.agents.cascade_agent import CascadeAgent

        need_org(source_org, r)  # the source service's id and current band are the source org's private data (API-02)
        ag = CascadeAgent(s.nodes[source_org])
        g = ag.cross_graph()
        n = s.nodes[source_org]
        if source_service not in n.services:
            raise HTTPException(404, "unknown service for that org")
        key = (source_org, n.svc_hash(source_service).hex())
        return g.cascade_from(key, source_p=max(n.service_band()[source_service]["p"], 0.5))

    # ------------------------------------------------------------ plans/approvals
    @app.get("/api/plans")
    def plans(r: str = Depends(role)):
        return [{"org": org, "plan_id": p["plan_id"], "risk_before": p["risk_before"], "risk_after": p["risk_after"], "steps": len(p["steps"]), "critic": p.get("critic")}
                for org, n in S().nodes.items() if r in ("admin", f"org:{org}") for p in n.plans.values()]

    @app.get("/api/plans/{plan_id}")
    def plan(plan_id: str, r: str = Depends(role)):
        return find_plan(plan_id, r)[1]

    def prune(org: str) -> None:
        """Forget approval requests the chain has already closed, so they stop showing as pending."""
        s = S()
        s.orch[org].prune_resolved_approvals(s.humans[org].view)

    @app.post("/api/plans/{plan_id}/submit-for-approval")
    def submit(plan_id: str, r: str = Depends(role)):
        org, p = find_plan(plan_id, r)
        prune(org)
        for rid, info in S().nodes[org].pending_approvals.items():
            if info["plan_id"] == plan_id:
                return {"request_id": rid, "status": "already submitted"}
        raise HTTPException(409, "plan has no pending approval (not gated, rejected by the critic, or already executed)")

    @app.get("/api/approvals")
    def approvals(r: str = Depends(role)):
        out = []
        for org, n in S().nodes.items():
            if r in ("admin", f"org:{org}"):
                prune(org)
                out += [{"org": org, "request_id": rid, **info} for rid, info in n.pending_approvals.items()]
        return out

    @app.get("/api/approvals/{rid}")
    def approval(rid: str, r: str = Depends(role)):
        for org, n in S().nodes.items():
            if rid in n.pending_approvals or r == "admin":
                try:
                    v = S().humans[org].view(rid)
                    return {**v, "plan_id": n.pending_approvals.get(rid, {}).get("plan_id")}
                except ChainRevert:
                    continue
        raise HTTPException(404, "request not found")

    def _vote(rid: str, v: Vote, approve: bool):
        s = S()
        try:
            (s.humans[v.org].approve if approve else s.humans[v.org].reject)(rid, v.approver)
        except ChainRevert as e:
            raise HTTPException(409, f"chain refused: {e.name}")
        view = s.humans[v.org].view(rid)
        if not approve:
            prune(v.org)  # a rejection can close the request; drop it from the pending list right away
        return view

    @app.post("/api/approvals/{rid}/approve")
    def approve(rid: str, v: Vote, r: str = Depends(role)):
        need_org(v.org, r)  # only that org's operators (or admin) may cast its approvers' votes
        return _vote(rid, v, True)

    @app.post("/api/approvals/{rid}/reject")
    def reject(rid: str, v: Vote, r: str = Depends(role)):
        need_org(v.org, r)
        return _vote(rid, v, False)

    @app.post("/api/plans/{plan_id}/execute")
    def execute(plan_id: str, req: ExecuteReq, r: str = Depends(role)):
        org, p = find_plan(plan_id, r)
        n = S().nodes[org]
        rid = req.request_id or next((k for k, i in n.pending_approvals.items() if i["plan_id"] == plan_id), None)
        try:
            if rid:
                return S().orch[org].continue_after_approval(rid)
            return S().orch[org].execute(p, None)
        except GateViolation as e:
            raise HTTPException(409, f"gate violation: {e}")
        except ChainPaused as e:
            raise HTTPException(503, str(e))

    @app.post("/api/plans/{plan_id}/rollback")
    def rollback(plan_id: str, r: str = Depends(role)):
        org, _ = find_plan(plan_id, r)
        try:
            return S().orch[org].executor.rollback(plan_id)
        except KeyError:
            raise HTTPException(404, "plan was not executed")

    # --------------------------------------------------------------- traces/audit
    @app.get("/api/traces")
    def traces(org: Optional[str] = None, r: str = Depends(role)):
        out = []
        for o, n in S().nodes.items():
            if (org and o != org) or r not in ("admin", f"org:{o}"):
                continue
            for f in sorted(n.audit.trace_dir.glob("*.json")):
                d = json.loads(f.read_text(encoding="utf-8"))
                out.append({"org": o, "trace_id": d["trace_id"], "label": d["label"], "status": d["status"], "steps": len(d["steps"]), "digest": d.get("digest")})
        return out

    @app.get("/api/traces/{tid}")
    def trace(tid: str, r: str = Depends(role)):
        for o, n in S().nodes.items():
            f = n.audit.trace_dir / f"{tid}.json"
            if f.exists():
                need_org(o, r)
                d = json.loads(f.read_text(encoding="utf-8"))
                d["inclusion"] = n.audit.inclusion_proof(tid)
                return d
        raise HTTPException(404, "trace not found")

    @app.get("/api/audit/verify")
    def audit_verify(org: str, r: str = Depends(role)):
        need_org(org, r)
        return S().nodes[org].audit.verify()

    @app.get("/api/audit/proof")
    def audit_proof(org: str, trace_id: str, r: str = Depends(role)):
        need_org(org, r)
        n = S().nodes[org]
        p = n.audit.inclusion_proof(trace_id)
        if not p:
            raise HTTPException(404, "trace not anchored yet")
        return {**p, "onchain_valid": n.audit.verify_inclusion_onchain(trace_id)}

    @app.post("/api/audit/flush")
    def audit_flush(r: str = Depends(role)):
        need_admin(r)
        return S().flush_audit()

    # ------------------------------------------------------------------- chain
    @app.get("/api/chain/status")
    def chain_status():
        s = S()
        return {
            "connected": s.chain.is_connected(), "chain_id": s.chain.chain_id, "block": s.chain.block_number() if s.chain.is_connected() else None,
            "contracts": s.chain.addresses, "pending_writes": s.writer.pending_count(), "paused": s.writer.paused,
            "audit_lengths": {o: s.chain.call("AuditLog", "length", org_id(o)) for o in ORGS},
        }

    @app.get("/api/chain/events")
    def chain_events(contract: Optional[str] = None, name: Optional[str] = None, limit: int = 100):
        S().indexer.sync()
        return S().indexer.query(contract, name, limit)

    @app.get("/api/chain/attestations")
    def attestations():
        s = S()
        s.indexer.sync()
        return {
            "dependency": s.indexer.query("AttestationRegistry", "DependencyAttestationSubmitted", 500),
            "risk": s.indexer.query("AttestationRegistry", "RiskAttestationSubmitted", 500),
            "findings": s.indexer.query("AttestationRegistry", "FindingAttestationSubmitted", 500),
            "challenges": s.indexer.query("AttestationRegistry", "ChallengeSubmitted", 100),
            "alerts": s.indexer.query("AlertBus", "CascadeAlert", 200),
        }

    @app.get("/api/firmware/check")
    def firmware(org: str, r: str = Depends(role)):
        need_org(org, r)
        res = S().nodes[org].supply_chain_check()
        return {"org": org, "results": res, "flagged": {k: v for k, v in res.items() if v != "Match"}}

    # -------------------------------------------------------------- stream/admin
    @app.get("/api/stream")
    async def stream(max_events: int = 0):
        async def gen():
            sent = 0
            while True:
                evs = S().events
                while sent < len(evs):
                    yield f"data: {json.dumps(evs[sent])}\n\n"
                    sent += 1
                    if max_events and sent >= max_events:
                        return
                if max_events and sent >= max_events:
                    return
                await asyncio.sleep(0.5)
                if max_events == -1:
                    return

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.post("/api/admin/pause")
    def pause(r: str = Depends(role)):
        need_admin(r)
        S().pause()
        return {"paused": True}

    @app.post("/api/admin/resume")
    def resume(r: str = Depends(role)):
        need_admin(r)
        S().resume()
        return {"paused": False}

    @app.get("/api/metrics")
    def metrics():
        return S().metrics()

    from backend.api.ps03 import register; register(app, S, role, need_org, need_admin)  # noqa: E702  PS-03 (no-op unless PS03_ENABLE=1)
    return app


app = create_app()  # the system (chain connection, nodes) is created lazily on first request
