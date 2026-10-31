"""
CascadeAgent (AG-CAS-*): intra-org propagation on private data, cross-org propagation on PUBLIC attestations only,
early-warning alerts through AlertBus, and reaction to other orgs' alerts.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from backend.agents.framework import BaseAgent, SideEffect, agent_tool
from backend.common.chain import ORG_NAMES, org_id
from backend.graph.cascade import (BAND_NAMES, CRIT_NAMES, STRENGTH_NAMES, CrossOrgGraph, EdgeAtt, NodeAtt)
from backend.common.config import settings


class IntraIn(BaseModel):
    p0: Dict[str, float]


class IntraOut(BaseModel):
    asset_p: Dict[str, float]
    service_p: Dict[str, float]


class GraphIn(BaseModel):
    pass


class GraphOut(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]


class AlertIn(BaseModel):
    service_id: str
    severity: int
    tti: int
    evidence: str = ""


class AlertOut(BaseModel):
    status: str
    alert_id: Optional[str] = None


class PollIn(BaseModel):
    service_id: str


class PollOut(BaseModel):
    alert_ids: List[str]


class AckIn(BaseModel):
    alert_id: str
    service_id: str


class AckOut(BaseModel):
    status: str


SEVERITY = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class CascadeAgent(BaseAgent):
    NAME = "cascade"

    # ------------------------------------------------------------ intra-org
    @agent_tool("intra_cascade", IntraIn, IntraOut, SideEffect.none)
    def _intra(self, i: IntraIn) -> IntraOut:
        p = self.node.graph.propagate(i.p0)
        return IntraOut(asset_p=p, service_p=self.node.graph.service_impact(p))

    # ------------------------------------------------------------ public graph
    @agent_tool("build_cross_graph", GraphIn, GraphOut, SideEffect.read_chain)
    def _graph(self, i: GraphIn) -> GraphOut:
        """Public attestations only. Edge confirmation is read from the contract, not assumed."""
        n = self.node
        edges, seen = [], set()
        evs = n.indexer.query("AttestationRegistry", "DependencyAttestationSubmitted", limit=5000) if n.indexer else []
        for ev in evs:
            a = ev["args"]
            key = (a["consumerOrg"], a["consumerServiceHash"], a["providerOrg"], a["providerServiceHash"])
            if key in seen:
                continue
            seen.add(key)
            co, po = ORG_NAMES[a["consumerOrg"]], ORG_NAMES[a["providerOrg"]]
            ch, ph = bytes.fromhex(a["consumerServiceHash"][2:]), bytes.fromhex(a["providerServiceHash"][2:])
            confirmed = bool(n.chain.call("AttestationRegistry", "isEdgeConfirmed", org_id(co), ch, org_id(po), ph))
            edges.append(
                {
                    "consumer_org": co, "consumer_service": a["consumerServiceHash"][2:], "provider_org": po, "provider_service": a["providerServiceHash"][2:],
                    "strength": STRENGTH_NAMES[a["strength"]], "tolerance": a["tolerance"], "confirmed": confirmed,
                }
            )
        nodes_k = {}
        for e in edges:
            nodes_k[(e["consumer_org"], e["consumer_service"])] = 1
            nodes_k[(e["provider_org"], e["provider_service"])] = 1
        nodes = []
        for (o, h) in nodes_k:
            hb = bytes.fromhex(h)
            valid = bool(n.chain.call("AttestationRegistry", "isRiskAttestationValid", org_id(o), hb))
            band, crit = "unknown", "medium"
            if valid:
                r = n.chain.call("AttestationRegistry", "getLatestRiskAttestation", org_id(o), hb)
                band, crit = BAND_NAMES[int(r[2])], CRIT_NAMES[int(r[3])]
            nodes.append({"org": o, "service_hash": h, "band": band, "criticality": crit, "label": n.labels.get(h, f"{o}:{h[:8]}")})
        return GraphOut(nodes=nodes, edges=edges)

    def cross_graph(self) -> CrossOrgGraph:
        g = self.call("build_cross_graph")
        return CrossOrgGraph.from_attestations(
            [NodeAtt(n["org"], n["service_hash"], n["band"], n["criticality"], n["label"]) for n in g.nodes],
            [EdgeAtt(e["consumer_org"], e["consumer_service"], e["provider_org"], e["provider_service"], e["strength"], e["tolerance"], e["confirmed"]) for e in g.edges],
        )

    # --------------------------------------------------------------- alerts
    @agent_tool("publish_alert", AlertIn, AlertOut, SideEffect.write_chain)
    def _publish(self, i: AlertIn) -> AlertOut:
        n = self.node
        sh = n.svc_hash(i.service_id)
        ev = bytes.fromhex(__import__("hashlib").sha256(i.evidence.encode()).hexdigest())
        expiry = n.chain.block_timestamp() + 3600
        key = f"alert:{n.org}:{sh.hex()[:16]}:{i.severity}:{n.chain.block_timestamp() // 300}"
        r = n.writer.submit(key, "AlertBus", "publish", [n.org_id, sh, i.severity, i.tti, ev, expiry])
        aid = None
        if r.receipt is not None:
            for lg in r.receipt["logs"]:
                try:
                    parsed = n.chain.contracts["AlertBus"].events.CascadeAlert().process_log(lg)
                    aid = "0x" + bytes(parsed["args"]["alertId"]).hex()
                except Exception:  # noqa: BLE001
                    continue
        return AlertOut(status=r.status, alert_id=aid)

    @agent_tool("poll_alerts", PollIn, PollOut, SideEffect.read_chain)
    def _poll(self, i: PollIn) -> PollOut:
        n = self.node
        ids = n.chain.call("AlertBus", "affectedBy", n.org_id, n.svc_hash(i.service_id))
        return PollOut(alert_ids=["0x" + bytes(x).hex() for x in ids])

    @agent_tool("acknowledge_alert", AckIn, AckOut, SideEffect.write_chain)
    def _ack(self, i: AckIn) -> AckOut:
        n = self.node
        r = n.writer.submit(f"ack:{n.org}:{i.alert_id[:18]}:{i.service_id}", "AlertBus", "acknowledge", [i.alert_id, n.org_id, n.svc_hash(i.service_id)])
        return AckOut(status=r.status)

    # ------------------------------------------------------------ pipelines
    def analyse(self, assessments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Intra-org hypothesis (every high/critical asset compromised) + cross-org chain + alerts."""
        n = self.node
        hot = {a["asset_id"]: min(a["risk"] / 100.0 + 0.2, 1.0) for a in assessments if a["band"] in ("high", "critical")}
        intra = self.call("intra_cascade", p0=hot)
        bands = n.service_band()
        g = self.cross_graph()
        report: Dict[str, Any] = {"org": n.org, "intra": intra.model_dump(), "service_bands": bands, "chain": [], "alerts": [], "unconfirmed_edges": [e.__dict__ for e in g.unconfirmed]}
        # the most at-risk own service is the cascade source
        own = sorted(((sid, b) for sid, b in bands.items()), key=lambda kv: -kv[1]["risk"])
        if own:
            sid, b = own[0]
            key = (n.org, n.svc_hash(sid).hex())
            rep = g.cascade_from(key, source_p=max(b["p"], 0.0)) if key in g.nodes or any(k == key for k in [(e.provider_org, e.provider_service) for e in g.edges]) else None
            if rep is not None:
                report.update({"source": rep["source"], "chain": rep["chain"], "graph": rep["graph"], "cross_org_risk": g.cross_org_risk(rep)})
                if rep["chain"]:
                    report["narrative"] = n.llm.narrate("cascade", {"source_org": n.org, "affected": len(rep["chain"]), "first_tti": rep["chain"][0]["time_to_impact_minutes"], "top_p": max(c["p_degraded"] for c in rep["chain"])})
            for sid2, b2 in bands.items():
                if b2["band"] in ("high", "critical"):
                    sh = n.svc_hash(sid2).hex()
                    rep2 = g.cascade_from((n.org, sh), source_p=b2["p"]) if (n.org, sh) in g.nodes else None
                    if rep2 and rep2["chain"] and max(c["p_degraded"] for c in rep2["chain"]) >= settings.cascade_alert_threshold:
                        tti = rep2["chain"][0]["time_to_impact_minutes"]
                        bucket = 0 if tti < 15 else 1 if tti <= 60 else 2 if tti <= 240 else 3
                        out = self.call("publish_alert", service_id=sid2, severity=SEVERITY[b2["band"]], tti=bucket, evidence=f"{sid2}:{b2['risk']}")
                        report["alerts"].append({"service": sid2, "severity": b2["band"], "status": out.status, "alert_id": out.alert_id, "first_tti": tti})
        return report

    def react_to_alerts(self) -> Dict[str, Any]:
        """AG-CAS-06: poll the chain for alerts that reach our services via CONFIRMED edges, acknowledge, and raise exposure."""
        n = self.node
        reacted = []
        for sid in n.services:
            res = self.call("poll_alerts", service_id=sid)
            for aid in res.alert_ids:
                if aid in getattr(n, "acked", set()):
                    continue
                ack = self.call("acknowledge_alert", alert_id=aid, service_id=sid)
                if ack.status in ("confirmed", "duplicate"):
                    n.acked = getattr(n, "acked", set()) | {aid}
                    sev = int(n.chain.call("AlertBus", "getAlert", bytes.fromhex(aid[2:]))[2])
                    # upstream failure hypothesis: exposure of the consumer service grows with the alert severity
                    exposure = [0.15, 0.35, 0.6, 0.85][sev]
                    n.upstream[sid] = max(n.upstream.get(sid, 0.0), exposure)
                    reacted.append({"alert_id": aid, "service": sid, "ack": ack.status, "upstream_exposure": n.upstream[sid]})
                    self.log("decision", note="reacted to upstream alert", alert_id=aid, service=sid)
        return {"reacted": reacted}
