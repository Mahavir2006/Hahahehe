"""
RiskAgent (AG-RSK-*): authoritative numbers come from the deterministic model; text is narration only.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from backend.agents.framework import BaseAgent, SideEffect, agent_tool
from backend.common.audit import content_digest
from backend.risk import model as risk


class ApplyIn(BaseModel):
    finding: Dict[str, Any]


class ApplyOut(BaseModel):
    assets: List[str]


class ScoreIn(BaseModel):
    asset_ids: Optional[List[str]] = None


class ScoreOut(BaseModel):
    assessments: List[Dict[str, Any]]
    org_aggregate: float


class AttestRiskIn(BaseModel):
    force: bool = False


class AttestRiskOut(BaseModel):
    attested: List[Dict[str, Any]]


class SnapshotIn(BaseModel):
    note: str = ""


class SnapshotOut(BaseModel):
    digest: str
    anchored: bool


class RiskAgent(BaseAgent):
    NAME = "risk"

    @agent_tool("apply_findings", ApplyIn, ApplyOut, SideEffect.write_local)
    def _apply(self, i: ApplyIn) -> ApplyOut:
        f = i.finding
        touched = []
        for m in f.get("matches", []):
            a = self.node.assets[m["asset_id"]]
            cve = (f.get("cve_ids") or ["UNKNOWN"])[0]
            if not any(v["cve"] == cve for v in a.vulns):
                # no silent defaults: a missing CVSS/EPSS stays None and becomes the documented fallback + missing_* flag
                a.vulns.append(
                    {"cve": cve, "cvss": f.get("cvss_base"), "epss": f.get("epss_like"), "exploited": bool(f.get("exploited_in_wild")),
                     "version_match": m.get("match_reason", "advisory matched to inventory")}
                )
            touched.append(m["asset_id"])
        return ApplyOut(assets=touched)

    @agent_tool("score_assets", ScoreIn, ScoreOut, SideEffect.none)
    def _score(self, i: ScoreIn) -> ScoreOut:
        assets = [self.node.assets[a] for a in (i.asset_ids or list(self.node.assets))]
        out = []
        for a in assets:
            s = risk.score_asset(a)
            s["asset_name"] = a.name
            if i.asset_ids:
                s["narrative"] = self.node.llm.narrate("risk", s)  # narration validated against s (AG-RSK-05)
            out.append(s)
        agg = risk.aggregate([risk.score_asset(a, explain=False) for a in self.node.contexts()])
        return ScoreOut(assessments=out, org_aggregate=agg)

    @agent_tool("attest_service_risk", AttestRiskIn, AttestRiskOut, SideEffect.write_chain)
    def _attest(self, i: AttestRiskIn) -> AttestRiskOut:
        """Publish service-level risk bands (no asset details) when a band changed (AG-RSK-06)."""
        bands = self.node.service_band()
        last = getattr(self.node, "last_attested", {})
        done = []
        for sid, b in bands.items():
            band = risk.band_with_hysteresis(b["risk"], last.get(sid))  # a tiny score change cannot flip the on-chain band
            if not i.force and last.get(sid) == band:
                continue
            r = self.node.attest_risk(sid, band, b["criticality"], {"service": sid, "risk": b["risk"], "model": risk.RiskModel.get().version})
            if r.status in ("confirmed", "duplicate"):
                last[sid] = band
            done.append({"service": sid, "band": band, "status": r.status, "tx": r.tx_hash})
        self.node.last_attested = last
        return AttestRiskOut(attested=done)

    @agent_tool("record_snapshot", SnapshotIn, SnapshotOut, SideEffect.write_chain)
    def _snapshot(self, i: SnapshotIn) -> SnapshotOut:
        """AG-RSK-04: append a hashed risk snapshot to the per-asset history and anchor it."""
        scores = [risk.score_asset(a, explain=False) for a in self.node.contexts()]
        snap = {"org": self.node.org, "ts": round(time.time(), 3), "aggregate": risk.aggregate(scores), "assets": {s["asset_id"]: s["risk"] for s in scores}, "note": i.note}
        hist = getattr(self.node, "history", [])
        snap["prev"] = hist[-1]["digest"] if hist else None
        d = content_digest(snap)
        snap["digest"] = "0x" + d.hex()
        hist.append(snap)
        self.node.history = hist
        e = self.node.audit.anchor("RiskSnapshot", d)
        return SnapshotOut(digest=snap["digest"], anchored=e.get("status") == "anchored")

    def assess(self, finding: Optional[Dict[str, Any]] = None, force_attest: bool = False) -> Dict[str, Any]:
        applied: List[str] = []
        if finding:
            applied = self.call("apply_findings", finding=finding).assets
        focus = applied or None
        before = getattr(self.node, "baseline", None)
        res = self.call("score_assets", asset_ids=focus)
        full = self.call("score_assets")
        if self.node.baseline is None:
            self.node.baseline = full.org_aggregate
        att = self.call("attest_service_risk", force=force_attest)
        snap = self.call("record_snapshot", note=(finding or {}).get("advisory_id", "baseline"))
        self.log("decision", note="risk assessed", aggregate=full.org_aggregate, attested=len(att.attested))
        return {
            "assessments": res.assessments,
            "org_aggregate": full.org_aggregate,
            "all": full.assessments,
            "attested": att.attested,
            "snapshot": snap.model_dump(),
            "affected_assets": applied,
        }
