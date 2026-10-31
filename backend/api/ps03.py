"""
PS-03 routes (WP5), registered from backend/api/main.py by one line (edit E2). Everything is gated by
PS03_ENABLE=1; with it unset register() adds nothing and the API behaves exactly as before.

Same X-Dev-Role rules as the existing API: org roles read only their own org; simulation controls are admin only.
Hooks (middleware, additive): the first API request seeds real CVE context (PS03_SEED_REAL=1) and runs a startup
assessment; a successful POST /api/advisories triggers an "advisory" reassessment (keyed on the number of
findings, so a duplicate advisory does not trigger twice); execute/rollback trigger "asset_change".
SIMULATION ONLY: nothing here sends commands to real OT equipment.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, Field

from backend import containment, simclock
from backend.proactive import ReassessRejected, Reassessor
from backend.risk import adapter
from backend.risk import explain as X
from backend.risk import model as risk
from backend.risk import trend_log as T

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "backend" / "risk" / "artifacts"
SIM_BANNER = "Simulation only. No commands are sent to real OT equipment."


def flag(name: str) -> bool:
    return os.environ.get(name, "0") == "1"


# ------------------------------------------------------------------ models
class AdvanceReq(BaseModel):
    days: int = Field(7, ge=1, le=365)
    scenario: Optional[str] = None


class ActionReq(BaseModel):
    action: str
    targets: List[str]


class PrecheckReq(BaseModel):
    org: str
    actions: List[ActionReq]


class Level2Req(BaseModel):
    org: str
    asset_id: str


class AttentionItem(BaseModel):
    rank: int
    asset_id: str
    name: str
    risk: float
    risk_bp: int
    band: str
    likelihood: float
    impact: float
    trend: str
    days_at_high_risk: int
    top_reasons: List[str]
    finding_badges: Dict[str, int]
    source_tags: List[str]


class AttentionOut(BaseModel):
    org: str
    sim_day: int
    banner: str
    aggregate_bp: int
    model_version: str
    model_source: str
    items: List[AttentionItem]


class Ps03:
    def __init__(self, S: Callable[[], Any]):
        self.S = S
        self.lock = threading.Lock()
        self.r: Optional[Reassessor] = None
        self.ctx = None
        self.seed_summary: Dict[str, Any] = {}

    def ensure(self) -> Reassessor:
        with self.lock:
            if self.r is None:
                from backend.seed_real import RealContext, seed_node

                s = self.S()
                self.ctx = RealContext()
                if flag("PS03_SEED_REAL"):
                    self.seed_summary = {org: seed_node(n, self.ctx) for org, n in s.nodes.items()}
                from backend.risk import adapter as _ad

                _ad.load_configured()  # RISK_MODEL_DIR or the committed artifact; fails closed
                self.r = Reassessor(s.nodes, s.orch, chain_ops=not flag("PS03_NO_CHAIN_OPS"),
                                    labels_path=Path(s.state_dir) / "ps03_episode_labels.jsonl", real_ctx=self.ctx)
                self.r.reassess_all("asset_change", key="startup")
            return self.r

    def detector(self, org: str):
        return self.ensure().detectors[org]


def register(app: FastAPI, S: Callable[[], Any], role: Callable, need_org: Callable, need_admin: Callable) -> None:
    if not flag("PS03_ENABLE"):
        return
    P = Ps03(S)
    app.state.ps03 = P

    @app.middleware("http")
    async def ps03_hooks(request: Request, call_next):
        path, method = request.url.path, request.method
        if path.startswith("/api/") and not path.startswith("/api/health") and not path.startswith("/api/ps03/health"):
            import asyncio

            await asyncio.to_thread(P.ensure)
        resp = await call_next(request)
        if resp.status_code < 300 and method == "POST":
            import asyncio

            try:
                if path == "/api/advisories":
                    n = sum(len(x.findings) for x in S().nodes.values())
                    await asyncio.to_thread(P.ensure().reassess_all, "advisory", f"findings={n}")
                elif path.startswith("/api/plans/") and (path.endswith("/execute") or path.endswith("/rollback")):
                    await asyncio.to_thread(P.ensure().reassess_all, "asset_change", path)
            except ReassessRejected:
                pass
        return resp

    def latest(org: str) -> Dict[str, Any]:
        log = S().nodes[org].risk_log
        if not log:
            raise HTTPException(409, "no reassessment yet")
        return log[-1]

    def epss_asof() -> Optional[str]:
        return P.ctx.epss_asof if P.ctx else None

    def snapshot_commit() -> Optional[str]:
        return (P.ctx.manifest.get("sources", {}).get("csaf", {}) or {}).get("commit") if P.ctx else None

    # ---------------------------------------------------------------- reads
    @app.get("/api/ps03/health")
    def ps03_health():
        r = P.r
        return {"banner": SIM_BANNER, "flags": {k: os.environ.get(k) for k in ("PS03_ENABLE", "PS03_SEED_REAL", "PS03_HYSTERESIS", "RISK_MODEL_DIR")},
                "initialised": r is not None, "sim_day": simclock.now_day(), "date": simclock.now_date().isoformat(),
                "counts": None if r is None else {"risk_log_entries": {o: len(n.risk_log) for o, n in S().nodes.items()},
                                                  "findings": {o: len(d.findings) for o, d in r.detectors.items()}, "changes": len(r.changes),
                                                  "rejected_triggers": len(r.rejected)},
                "seed": P.seed_summary}

    @app.get("/api/ps03/orgs/{org}/attention", response_model=AttentionOut)
    def attention(org: str, limit: int = Query(10, ge=1, le=100), r: str = Depends(role)):
        need_org(org, r)
        R = P.ensure()
        n, e = S().nodes[org], latest(org)
        trends = T.org_trends(n.risk_log)
        det = R.detectors[org]
        rows = []
        for aid, v in e["assets"].items():
            shap = sorted(v["shap"].items(), key=lambda kv: -abs(kv[1]))[:3]
            feats = v["features"]
            reasons = [f"{risk.FACTOR_LABELS.get(f, f)} = {feats.get(f):g}: {c:+.3f} log-odds" for f, c in shap]
            badges: Dict[str, int] = {}
            for h in det.list(aid):
                if e["sim_day"] - h["sim_day"] < 30:
                    k = f"{h['finding_type']}:{h['severity']}"
                    badges[k] = badges.get(k, 0) + 1
            rows.append({"asset_id": aid, "name": n.inventory[aid]["name"], "risk": v["risk_bp"] / 100, "risk_bp": v["risk_bp"], "band": v["band"],
                         "likelihood": v["likelihood_bp"] / 10000, "impact": v["impact_bp"] / 10000, "trend": trends.get(aid, {}).get("direction", "flat"),
                         "days_at_high_risk": R.days_at_high(org, aid), "top_reasons": reasons, "finding_badges": badges,
                         "source_tags": X.source_tags(n.assets[aid])})
        rows.sort(key=lambda x: (-x["risk_bp"], x["asset_id"]))
        items = [{"rank": i + 1, **x} for i, x in enumerate(rows[:limit])]
        return {"org": org, "sim_day": e["sim_day"], "banner": SIM_BANNER, "aggregate_bp": e["aggregate_bp"], "model_version": e["model_version"],
                "model_source": e["model_source"], "items": items}

    @app.get("/api/ps03/orgs/{org}/assets/{asset_id}/why")
    def why(org: str, asset_id: str, r: str = Depends(role)):
        need_org(org, r)
        R = P.ensure()
        n = S().nodes[org]
        if asset_id not in n.assets:
            raise HTTPException(404, "unknown asset")
        out = X.why(n, asset_id, R.detectors[org], simclock.now_day(), epss_asof(), snapshot_commit())
        out["trend"] = T.org_trends(n.risk_log).get(asset_id)
        out["banner"] = SIM_BANNER
        return out

    @app.get("/api/ps03/orgs/{org}/history")
    def history(org: str, r: str = Depends(role)):
        need_org(org, r)
        return P.ensure().history(org)

    @app.get("/api/ps03/orgs/{org}/changes")
    def changes(org: str, since_day: int = -1, r: str = Depends(role)):
        need_org(org, r)
        R = P.ensure()
        return {"org": org, "since_day": since_day, "items": [c for c in R.changes if c["org"] == org and c["to_sim_day"] > since_day],
                "events": [e for e in R.events_log if e["org"] == org and e["applied_on_sim_day"] > since_day]}

    @app.get("/api/ps03/orgs/{org}/trend")
    def trend(org: str, r: str = Depends(role)):
        need_org(org, r)
        P.ensure()
        return {"org": org, "note": "statistical trend (Holt/EWMA), not ML", "assets": T.org_trends(S().nodes[org].risk_log)}

    @app.get("/api/ps03/detections")
    def detections(org: Optional[str] = None, r: str = Depends(role)):
        R = P.ensure()
        orgs = [org] if org else ([o for o in R.detectors] if r == "admin" else [r[4:]])
        for o in orgs:
            need_org(o, r)
        items = [f for o in orgs for f in R.detectors[o].list()]
        return {"note": "rules over SIMULATED telemetry (not a trained detector); exposure findings from asset state",
                "exposure": [f for f in items if f["finding_type"] == "exposure"], "active_attack": [f for f in items if f["finding_type"] == "active_attack"]}

    @app.get("/api/ps03/model/info")
    def model_info():
        out = adapter.info()
        for name in ("rules_metrics.json", "trend_metrics.json"):
            p = ARTIFACTS / name
            out[name.replace(".json", "")] = json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
        out["caveats"] = [
            "labels are simulated; results are on simulated data",
            "M1 is trained on simulated assets with real time-matched CVE context; its labels come from a synthetic process (docs/ML_REPORT.md)",
            "real data context (CISA CSAF/KEV, FIRST EPSS) is matched to demo assets at vendor level; EPSS is current-day, not time-matched",
            "detections are deterministic rules on simulated telemetry, not a trained detector",
            "cascade and what-if constants are hand-set assumptions",
        ]
        return out

    @app.get("/api/ps03/chain/live")
    def chain_live(limit: int = Query(25, ge=1, le=200)):
        """Real on-chain activity from the local chain: latest block and the most recent events (tx hash, block,
        contract, event, org). Nothing here is generated; it is read from the chain through the event indexer."""
        from backend.common.chain import ORGS as _ORGS, org_id as _org_id

        s = S()
        s.indexer.sync()
        names = {"0x" + bytes(_org_id(o)).hex(): o for o in _ORGS}
        evs = []
        for e in s.indexer.query(None, None, limit):
            a = e.get("args") or {}
            org = next((names.get(str(a.get(k)).lower()) for k in ("orgId", "consumerOrg", "providerOrg", "org") if a.get(k) is not None and names.get(str(a.get(k)).lower())), None)
            evs.append({"block": e["block"], "tx": e["tx"], "contract": e["contract"], "event": e["name"], "org": org})
        R = P.r
        return {"block": s.chain.block_number(), "chain_id": s.chain.chain_id, "events_indexed": s.indexer.count(), "events": evs,
                "sim_day": simclock.now_day(), "auto_advance_seconds": getattr(app.state, "ps03_live_interval", None),
                "reassessments": None if R is None else sum(len(n.risk_log) for n in S().nodes.values())}

    # ---------------------------------------------------------------- simulation controls (admin)
    @app.post("/api/ps03/sim/advance")
    def advance(req: AdvanceReq, r: str = Depends(role)):
        need_admin(r)
        try:
            return P.ensure().advance(req.days, req.scenario)
        except ReassessRejected as e:
            raise HTTPException(409, str(e))
        except (ValueError, FileNotFoundError) as e:
            raise HTTPException(400, str(e))

    @app.post("/api/ps03/sim/reset")
    def reset(r: str = Depends(role)):
        need_admin(r)
        R = P.ensure()
        try:
            out = R.reset()
        except ReassessRejected as e:
            raise HTTPException(409, str(e))
        R.reassess_all("asset_change", key="reset")
        return out

    # ---------------------------------------------------------------- containment (simulation)
    @app.get("/api/ps03/containment/levels")
    def levels():
        return {"banner": SIM_BANNER, "levels": containment.LEVELS, "allowlist": containment.allowlist()}

    @app.post("/api/ps03/containment/precheck")
    def precheck(req: PrecheckReq, r: str = Depends(role)):
        need_org(req.org, r)
        R = P.ensure()
        return containment.precheck(S().nodes[req.org], [a.model_dump() for a in req.actions], R.detectors[req.org].list())

    @app.post("/api/ps03/containment/level2")
    def level2(req: Level2Req, r: str = Depends(role)):
        """Precheck, then build an ISOLATE_ASSET plan through the existing planner/critic/gate. Approve, execute and
        roll back with the existing /api/approvals and /api/plans routes."""
        need_org(req.org, r)
        R = P.ensure()
        n = S().nodes[req.org]
        pc = containment.precheck(n, [{"action": "ISOLATE_ASSET", "targets": [req.asset_id]}], R.detectors[req.org].list())
        if not pc["ok"]:
            raise HTTPException(409, {"precheck": pc})
        trig = pc["targets"][req.asset_id]["trigger_finding"]
        res = containment.build_level2_plan(S().orch[req.org], req.asset_id, trig)
        return {"banner": SIM_BANNER, "precheck": pc, "plan_id": res["plan"]["plan_id"], "steps": res["plan"]["steps"],
                "critic": res["verdict"], "gate": res["gate"], "next": "approve via POST /api/approvals/{request_id}/approve, then POST /api/plans/{plan_id}/execute"}

    @app.get("/api/ps03/containment/verify")
    def verify(org: str, r: str = Depends(role)):
        need_org(org, r)
        P.ensure()
        return containment.verify(S().nodes[org])
