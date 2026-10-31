"""
Sensitivity of the hand-set constants: vary each by -20% and +20% and measure how stable the top-10 ranking is
(Kendall tau on the baseline top 10, plus top-10 overlap). These constants are assumptions, not learned.

    python evaluation/sensitivity.py
"""

from __future__ import annotations

import copy
import json
from contextlib import contextmanager

import numpy as np
from scipy.stats import kendalltau

from common import ROOT, demo_nodes, record
from backend.graph import cascade as C
from backend.risk import model as M


@contextmanager
def patched(obj, name, value):
    old = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, old)


def stability(base: dict, new: dict, k: int = 10) -> dict:
    top = sorted(base, key=lambda x: (-base[x], x))[:k]
    tau = kendalltau([base[x] for x in top], [new[x] for x in top]).statistic
    new_top = set(sorted(new, key=lambda x: (-new[x], x))[:k])
    return {"kendall_tau_top10": None if np.isnan(tau) else round(float(tau), 4), "top10_overlap": len(set(top) & new_top)}


def asset_risks(assets, impact_w=None):
    if impact_w is None:
        return {a.asset_id: M.score_asset(a, explain=False)["risk"] for a in assets}

    def impact(a):
        crit = min(max(a.criticality, 1), 5) / 5.0
        return impact_w[0] * crit + impact_w[1] * float(a.safety_critical) + impact_w[2] * min(a.num_dependents / 8.0, 1.0) + impact_w[3] * M.SERVICE_CRIT.get(a.service_crit, 0.25)

    with patched(M, "impact_of", impact):
        return {a.asset_id: M.score_asset(a, explain=False)["risk"] for a in assets}


def intra(nodes):
    out = {}
    for o, n in nodes.items():
        p0 = {a.asset_id: M.score_asset(a, explain=False)["likelihood"] for a in n.contexts()}
        si = n.graph.service_impact(n.graph.propagate(p0))
        out.update({f"{o}:{s}": v for s, v in si.items()})
    return out


def cross(nodes):
    deps = json.loads((ROOT / "data" / "cross_org_dependencies.json").read_text(encoding="utf-8"))
    bands = {(o, s): b["band"] for o, n in nodes.items() for s, b in n.service_band().items()}
    crit = {(o, s): n.services[s]["criticality"] for o, n in nodes.items() for s in n.services}
    nodes_att = [C.NodeAtt(o, s, bands[(o, s)], crit[(o, s)]) for (o, s) in bands]
    edges = [C.EdgeAtt(d["consumer_org"], d["consumer_service"], d["provider_org"], d["provider_service"], d["dependency_strength"],
                       0 if d["tolerance_minutes"] < 15 else 1 if d["tolerance_minutes"] <= 60 else 2 if d["tolerance_minutes"] <= 240 else 3) for d in deps]
    g = C.CrossOrgGraph.from_attestations(nodes_att, edges)
    p = g.propagate({})
    return {f"{k[0]}:{k[1]}": v for k, v in p.items()}


def action_ranking(assets):
    top = sorted(assets, key=lambda a: -M.score_asset(a, explain=False)["risk"])[:5]
    out = {}
    for a in top:
        for act in ("ENABLE_MONITORING", "ISOLATE_ASSET", "PATCH", "SEGMENT_NETWORK", "ROTATE_CREDENTIALS"):
            out[f"{a.asset_id}:{act}"] = -M.what_if([a], [{"action": act, "targets": [a.asset_id]}])["delta"]
    return out


def main():
    nodes = demo_nodes()
    # put the headline advisory's CVE on its matched power asset so the ranking has a realistic top
    nodes["power"].assets["power-asset-001"].vulns = [{"cve": "CVE-2023-1234", "cvss": 8.8, "epss": 0.834, "exploited": True}]
    assets = [a for n in nodes.values() for a in n.contexts()]
    res = {}
    base_assets = asset_risks(assets)
    w0 = [0.45, 0.20, 0.15, 0.20]
    for i, name in enumerate(["impact_w_criticality", "impact_w_safety", "impact_w_dependents", "impact_w_service"]):
        for s in (0.8, 1.2):
            w = list(w0)
            w[i] *= s
            res[f"{name} x{s}"] = stability(base_assets, asset_risks(assets, w))
    base_intra = intra(nodes)
    for name in ("EDGE_WEIGHT", "SERVICE_WEIGHT"):
        for s in (0.8, 1.2):
            with patched(C, name, getattr(C, name) * s):
                res[f"{name} x{s}"] = stability(base_intra, intra(nodes))
    base_cross = cross(nodes)
    for name in ("BAND_P", "STRENGTH_W"):
        for s in (0.8, 1.2):
            with patched(C, name, {k: min(v * s, 1.0) for k, v in getattr(C, name).items()}):
                res[f"{name} x{s}"] = stability(base_cross, cross(nodes))
    base_act = action_ranking(assets)
    for mult, label in ((0.85, "monitoring_multiplier_0.85"), (0.3, "isolation_multiplier_0.3")):
        for s in (0.8, 1.2):
            orig = M.apply_action

            def patched_apply(a, action, mult=mult, s=s, orig=orig):
                before = a.likelihood_mult
                orig(a, action)
                if a.likelihood_mult != before and abs(a.likelihood_mult / before - mult) < 1e-9:
                    a.likelihood_mult = before * min(mult * s, 1.0)

            with patched(M, "apply_action", patched_apply):
                res[f"{label} x{s}"] = stability(base_act, action_ranking(assets))
    out = {"perturbation": "each constant x0.8 and x1.2, one at a time", "rankings": {
        "impact weights": "top-10 asset risk across the 75 demo assets", "EDGE_WEIGHT/SERVICE_WEIGHT": "top-10 service impact (intra-org)",
        "BAND_P/STRENGTH_W": "top-10 cross-org service degradation", "multipliers": "top-10 (asset, action) risk reductions"},
        "results": res, "note": "DISABLE_SERVICE_PORT no longer uses the 0.9 multiplier; it closes a management port"}
    record("constant_sensitivity", out)
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
