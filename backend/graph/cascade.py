"""
Cascade engines (CAS-01..05).

* IntraOrgGraph: private, per-org asset dependency propagation (cycle safe fixed point).
* CrossOrgGraph: built ONLY from public on-chain attestations; never sees private inventory.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]

EDGE_WEIGHT = 0.6          # asset -> dependent asset
SERVICE_WEIGHT = 0.7       # noisy-OR weight of a required asset on its service
BAND_P = {"low": 0.05, "medium": 0.2, "high": 0.5, "critical": 0.8}
UNKNOWN_BAND = "medium"    # BC-ATT-R-05: unknown/expired attestations are treated medium-conservatively
STRENGTH_W = {"low": 0.2, "medium": 0.5, "high": 0.8}
TOL_MIN = {0: 10, 1: 35, 2: 150, 3: 300}   # <15m, 15-60m, 1-4h, >4h (bucket midpoints, minutes)
STRENGTH_NAMES = ["low", "medium", "high"]
BAND_NAMES = ["low", "medium", "high", "critical"]
CRIT_NAMES = ["low", "medium", "high", "life_critical"]


# ------------------------------------------------------------------ intra-org
@dataclass
class IntraOrgGraph:
    org: str
    depends_on: Dict[str, List[str]]                    # asset -> assets it depends on
    services: Dict[str, Dict]                           # service_id -> {name, required_assets, criticality}

    @classmethod
    def load(cls, org: str, data_dir: Optional[Path] = None) -> "IntraOrgGraph":
        d = Path(data_dir) if data_dir else ROOT / "data"
        inv = json.loads((d / "orgs" / org / "inventory.json").read_text(encoding="utf-8"))
        svcs = json.loads((d / "orgs" / org / "services.json").read_text(encoding="utf-8"))
        return cls(
            org=org,
            depends_on={a["asset_id"]: list(a.get("depends_on", [])) for a in inv},
            services={s["service_id"]: s for s in svcs},
        )

    def dependents(self) -> Dict[str, List[str]]:
        rev: Dict[str, List[str]] = {a: [] for a in self.depends_on}
        for a, deps in self.depends_on.items():
            for d in deps:
                rev.setdefault(d, []).append(a)
        return rev

    def transitive_dependents(self, asset: str) -> set:
        rev, seen, stack = self.dependents(), set(), [asset]
        while stack:
            cur = stack.pop()
            for n in rev.get(cur, []):
                if n not in seen and n != asset:
                    seen.add(n)
                    stack.append(n)
        return seen

    def propagate(self, p0: Dict[str, float], max_iter: int = 200, tol: float = 1e-10) -> Dict[str, float]:
        """p(a) = 1 - (1-p0(a)) * prod_{d in deps(a)} (1 - w * p(d)); monotone fixed point, cycle safe."""
        p = {a: min(max(p0.get(a, 0.0), 0.0), 1.0) for a in self.depends_on}
        for _ in range(max_iter):
            delta = 0.0
            for a, deps in self.depends_on.items():
                keep = 1.0 - min(max(p0.get(a, 0.0), 0.0), 1.0)
                for d in deps:
                    keep *= 1.0 - EDGE_WEIGHT * p.get(d, 0.0)
                new = 1.0 - keep
                delta = max(delta, abs(new - p[a]))
                p[a] = new
            if delta < tol:
                break
        return p

    def service_impact(self, p: Dict[str, float]) -> Dict[str, float]:
        out = {}
        for sid, s in self.services.items():
            keep = 1.0
            for a in s["required_assets"]:
                keep *= 1.0 - SERVICE_WEIGHT * p.get(a, 0.0)
            out[sid] = round(1.0 - keep, 10)
        return out


# ------------------------------------------------------------------ cross-org
@dataclass(frozen=True)
class NodeAtt:
    org: str
    service_hash: str            # hex
    band: str                    # low|medium|high|critical|unknown
    criticality: str             # low|medium|high|life_critical
    label: str = ""              # optional human alias (never required)


@dataclass(frozen=True)
class EdgeAtt:
    consumer_org: str
    consumer_service: str
    provider_org: str
    provider_service: str
    strength: str                # low|medium|high
    tolerance: int               # 0..3
    confirmed: bool = True


@dataclass
class CrossOrgGraph:
    nodes: Dict[Tuple[str, str], NodeAtt] = field(default_factory=dict)
    edges: List[EdgeAtt] = field(default_factory=list)
    unconfirmed: List[EdgeAtt] = field(default_factory=list)

    @classmethod
    def from_attestations(cls, nodes: List[NodeAtt], edges: List[EdgeAtt]) -> "CrossOrgGraph":
        g = cls()
        for n in nodes:
            g.nodes[(n.org, n.service_hash)] = n
        for e in edges:
            (g.edges if e.confirmed else g.unconfirmed).append(e)
        return g

    def _base_p(self, key: Tuple[str, str]) -> float:
        n = self.nodes.get(key)
        band = n.band if n and n.band in BAND_P else UNKNOWN_BAND
        return BAND_P[band]

    def propagate(self, sources: Dict[Tuple[str, str], float], max_iter: int = 200, tol: float = 1e-10) -> Dict[Tuple[str, str], float]:
        """Consumers inherit risk from confirmed providers. `sources` are forced lower bounds (the incident)."""
        keys = set(self.nodes) | {(e.consumer_org, e.consumer_service) for e in self.edges} | {(e.provider_org, e.provider_service) for e in self.edges}
        p = {k: max(self._base_p(k) if k in self.nodes else 0.0, sources.get(k, 0.0)) for k in keys}
        inc: Dict[Tuple[str, str], List[EdgeAtt]] = {}
        for e in self.edges:
            inc.setdefault((e.consumer_org, e.consumer_service), []).append(e)
        for _ in range(max_iter):
            delta = 0.0
            for k in keys:
                own = max(self._base_p(k) if k in self.nodes else 0.0, sources.get(k, 0.0))
                keep = 1.0 - own
                for e in inc.get(k, []):
                    keep *= 1.0 - STRENGTH_W[e.strength] * p[(e.provider_org, e.provider_service)]
                new = 1.0 - keep
                delta = max(delta, abs(new - p[k]))
                p[k] = new
            if delta < tol:
                break
        return p

    def cascade_from(self, source: Tuple[str, str], source_p: Optional[float] = None) -> Dict:
        """Ordered impact chain downstream of `source` (CAS-03)."""
        sp = source_p if source_p is not None else max(self._base_p(source), 0.8)
        p = self.propagate({source: sp})
        # earliest time-to-impact by Dijkstra over provider->consumer edges
        outg: Dict[Tuple[str, str], List[EdgeAtt]] = {}
        for e in self.edges:
            outg.setdefault((e.provider_org, e.provider_service), []).append(e)
        tti = {source: 0}
        frontier = [source]
        while frontier:
            frontier.sort(key=lambda k: tti[k])
            cur = frontier.pop(0)
            for e in outg.get(cur, []):
                nxt = (e.consumer_org, e.consumer_service)
                t = tti[cur] + TOL_MIN[e.tolerance]
                if nxt not in tti or t < tti[nxt]:
                    tti[nxt] = t
                    frontier.append(nxt)
        chain = []
        for k, t in tti.items():
            if k == source:
                continue
            n = self.nodes.get(k)
            chain.append(
                {
                    "org": k[0],
                    "service": k[1],
                    "label": n.label if n else "",
                    "p_degraded": round(p[k], 6),
                    "time_to_impact_minutes": t,
                    "criticality_bucket": n.criticality if n else "unknown",
                }
            )
        chain.sort(key=lambda c: (c["time_to_impact_minutes"], -c["p_degraded"], c["org"], c["service"]))
        return {
            "source": {"org": source[0], "service": source[1], "p": round(sp, 6)},
            "chain": chain,
            "unconfirmed_edges": [e.__dict__ for e in self.unconfirmed],
            "graph": {
                "nodes": [{"org": k[0], "service": k[1], "p": round(v, 6), "band": self.nodes[k].band if k in self.nodes else "unknown",
                           "criticality": self.nodes[k].criticality if k in self.nodes else "unknown", "label": self.nodes[k].label if k in self.nodes else ""}
                          for k, v in sorted(p.items())],
                "edges": [{"from": [e.provider_org, e.provider_service], "to": [e.consumer_org, e.consumer_service], "strength": e.strength,
                           "tolerance": e.tolerance, "confirmed": True} for e in self.edges]
                + [{"from": [e.provider_org, e.provider_service], "to": [e.consumer_org, e.consumer_service], "strength": e.strength,
                    "tolerance": e.tolerance, "confirmed": False} for e in self.unconfirmed],
            },
        }

    def cross_org_risk(self, report: Dict) -> float:
        """Aggregate: max over downstream services of p_degraded * criticality weight, scaled to 0..100."""
        w = {"low": 0.25, "medium": 0.5, "high": 0.75, "life_critical": 1.0, "unknown": 0.5}
        vals = [c["p_degraded"] * w.get(c["criticality_bucket"], 0.5) for c in report["chain"]]
        return round(100 * max(vals), 4) if vals else 0.0
