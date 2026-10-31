"""
PS-03 scoring and explanation path (WP1, WP6). Additive: backend/risk/model.py's score_asset is unchanged.

score_asset_v2(asset) returns a superset of score_asset's dict plus integer basis points:
    likelihood_bp, impact_bp in 0..10000 (round half up from the model's float output)
    risk_bp = round_half_up(likelihood_bp * (3000 + 7000 * impact_bp / 10000) / 10000), integer arithmetic only
risk_bp / 100 is the 0..100 risk on the same scale as score_asset's "risk".

factors_shap are true SHAP values from the model's TreeExplainer, in log-odds. The legacy top_factors keep
their old "points" (risk * shap / sum|shap|), which are a share of risk, NOT SHAP; the payload says so.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from backend.risk import adapter
from backend.risk import model as risk

TOP_N = 5


def round_half_up_div(num: int, den: int) -> int:
    return (2 * num + den) // (2 * den)


def to_bp(x: float) -> int:
    """float in [0, 1] -> integer basis points, round half up (x is clamped to [0, 1] first)."""
    x = min(max(float(x), 0.0), 1.0)
    return int(x * 10000 + 0.5)


def risk_bp_of(likelihood_bp: int, impact_bp: int) -> int:
    return round_half_up_div(likelihood_bp * (30_000_000 + 7000 * impact_bp), 100_000_000)


def shap_factors(m: "risk.RiskModel", feats: Dict[str, float], top: int = TOP_N) -> Dict[str, Any]:
    contrib = m.contributions(feats)
    unit = "log_odds" if m._explainer is not None else "occlusion_probability_delta"
    base = None
    if m._explainer is not None:
        ev = m._explainer.expected_value
        base = float(ev[-1] if hasattr(ev, "__len__") else ev)
    items = sorted(contrib.items(), key=lambda kv: -abs(kv[1]))
    return {
        "unit": unit, "base_value": base,
        "factors": [{"feature": f, "label": risk.FACTOR_LABELS.get(f, f), "value": feats.get(f),
                     "contribution_logodds" if unit == "log_odds" else "contribution": round(float(v), 6)}
                    for f, v in items[:top]],
        "all": {f: round(float(v), 6) for f, v in contrib.items()},
    }


def source_tags(a: "risk.AssetCtx") -> List[str]:
    tags = sorted({str(v.get("source", "advisory")) for v in a.vulns})
    if a.extra.get("rule_hit_count", 0) > 0:
        tags.append("telemetry")
    return tags or ["inventory"]


def score_asset_v2(a: "risk.AssetCtx", m: Optional["risk.RiskModel"] = None, explain: bool = True) -> Dict[str, Any]:
    m = m or risk.RiskModel.get()
    if a.extra:
        adapter.refresh(a)
    legacy = risk.score_asset(a, m, explain=explain)
    feats = risk.features_of(a)
    issues = adapter.check_inputs(feats, m.features)
    clipped = dict(feats)
    for it in issues:
        f = it["feature"]
        lo, hi = adapter.RANGES.get(f, (0.0, 0.0))
        if it["issue"] == "missing":
            clipped[f] = 0.0
        elif it["issue"] == "non_finite":
            clipped[f] = lo
        else:
            clipped[f] = min(max(float(clipped[f]), lo), hi)
    lik = min(max(m.likelihood(clipped) * a.likelihood_mult, 0.0), 1.0)
    imp = risk.impact_of(a)
    l_bp, i_bp = to_bp(lik), to_bp(imp)
    r_bp = risk_bp_of(l_bp, i_bp)
    out = dict(legacy)
    out.update(
        likelihood_bp=l_bp, impact_bp=i_bp, risk_bp=r_bp, band_bp=risk.band_for(r_bp / 100.0),
        top_factors_unit="share_of_risk_not_shap", missing=issues, source_tags=source_tags(a),
        model_source=adapter.model_source(m), features={f: clipped.get(f) for f in m.features},
    )
    if explain:
        out["factors_shap"] = shap_factors(m, clipped)
    return out


# ------------------------------------------------------------------ what changed (WP6)
def _fmt(v: Any) -> str:
    if isinstance(v, float):
        return f"{v:g}"
    return str(v)


def explain_change(prev: Optional[Dict[str, Any]], curr: Dict[str, Any], asset_id: str, top: int = 3) -> Optional[Dict[str, Any]]:
    """prev/curr are risk-log entries. Returns a what-changed item, or None if risk_bp and band are unchanged.
    Reasons are the features whose SHAP contribution moved most, plus the raw feature change; every number
    in the sentence is taken from the two entries."""
    c = curr["assets"].get(asset_id)
    p = (prev or {}).get("assets", {}).get(asset_id)
    if c is None or p is None:
        return None
    if c["risk_bp"] == p["risk_bp"] and c["band"] == p["band"]:
        return None
    reasons = []
    feats = sorted(set(c["features"]) | set(p["features"]))
    for f in feats:
        dv = (c["features"].get(f) or 0.0) - (p["features"].get(f) or 0.0)
        ds = (c["shap"].get(f) or 0.0) - (p["shap"].get(f) or 0.0)
        if dv == 0 and abs(ds) < 1e-9:
            continue
        reasons.append({"feature": f, "label": risk.FACTOR_LABELS.get(f, f), "from_value": p["features"].get(f), "to_value": c["features"].get(f),
                        "delta_value": round(dv, 6), "delta_contribution_logodds": round(ds, 6)})
    # features whose value changed come first; SHAP-only movers (value unchanged, contribution shifted through
    # interactions in the trees) follow and are worded as such
    reasons.sort(key=lambda r: (r["delta_value"] == 0, -abs(r["delta_contribution_logodds"]), -abs(r["delta_value"])))
    if p.get("likelihood_mult") != c.get("likelihood_mult"):
        reasons.insert(0, {"feature": "likelihood_multiplier", "label": "Mitigation multiplier", "from_value": p.get("likelihood_mult"),
                           "to_value": c.get("likelihood_mult"), "delta_value": round((c.get("likelihood_mult") or 1) - (p.get("likelihood_mult") or 1), 6),
                           "delta_contribution_logodds": 0.0})
    if prev and prev.get("model_version") != curr.get("model_version"):
        reasons.insert(0, {"feature": "model_version", "label": "model version changed", "from_value": prev.get("model_version"),
                           "to_value": curr.get("model_version"), "delta_value": 0.0, "delta_contribution_logodds": 0.0})
    reasons = reasons[:top]
    for r in reasons:
        if r["delta_value"] == 0 and r["feature"] not in ("model_version",):
            r["text"] = f"{r['label']} unchanged at {_fmt(r['to_value'])}, contribution {r['delta_contribution_logodds']:+.3f} log-odds"
        else:
            r["text"] = f"{r['label']} {_fmt(r['from_value'])} -> {_fmt(r['to_value'])}"
    sentence = f"risk {p['risk_bp'] / 100:g} to {c['risk_bp'] / 100:g}"
    if reasons:
        sentence += ": " + "; ".join(r["text"] for r in reasons)
    return {"asset_id": asset_id, "from_sim_day": prev["sim_day"] if prev else None, "to_sim_day": curr["sim_day"],
            "from_risk_bp": p["risk_bp"], "to_risk_bp": c["risk_bp"], "from_band": p["band"], "to_band": c["band"],
            "reasons": reasons, "text": sentence}


# ------------------------------------------------------------------ why (WP6)
def cascade_assumptions() -> Dict[str, Any]:
    from backend.graph import cascade as C

    return {
        "note": "hand-set constants (assumptions, not learned); see docs/SENSITIVITY.md",
        "EDGE_WEIGHT": C.EDGE_WEIGHT, "SERVICE_WEIGHT": C.SERVICE_WEIGHT, "BAND_P": C.BAND_P, "UNKNOWN_BAND": C.UNKNOWN_BAND,
        "STRENGTH_W": C.STRENGTH_W, "risk_formula": "risk = 100 * likelihood * (0.3 + 0.7 * impact)",
        "impact_weights": {"criticality": 0.45, "safety_critical": 0.20, "dependents": 0.15, "service_criticality": 0.20},
        "what_if_multipliers": {"ENABLE_MONITORING": 0.85, "ISOLATE_ASSET": 0.3, "DISABLE_SERVICE_PORT": 0.9},
    }


def dependency_path(node: Any, aid: str) -> Dict[str, Any]:
    g = node.graph
    upstream, stack = [], list(g.depends_on.get(aid, []))
    seen = {aid}
    while stack:
        cur = stack.pop(0)
        if cur in seen:
            continue
        seen.add(cur)
        upstream.append(cur)
        stack += g.depends_on.get(cur, [])
    services = [{"service_id": sid, "name": s["name"], "criticality": s["criticality"]} for sid, s in node.services.items() if aid in s["required_assets"]]
    return {"depends_on": g.depends_on.get(aid, []), "upstream_transitive": upstream,
            "dependents_transitive": sorted(g.transitive_dependents(aid)), "required_by_services": services,
            "cross_org": "service-level cascade is computed from on-chain attestations: GET /api/cross-org/cascade"}


def recommended_actions(node: Any, aid: str, score: Dict[str, Any]) -> List[Dict[str, Any]]:
    from backend.agents.planner_agent import PlanBuilder
    from backend.containment import level_of

    pb = PlanBuilder(node)
    groups = pb.groups([score], [aid], "remediate")
    out = []
    ctxs = node.contexts()
    for g in groups:
        w = risk.what_if(ctxs, [{"action": g["action"], "targets": [aid]}])
        b, a = w["before_scores"][aid]["risk"], w["after_scores"][aid]["risk"]
        out.append({"action": g["action"], "level": level_of(g["action"]), "asset_risk_before": b, "asset_risk_after": a,
                    "asset_risk_delta": round(a - b, 4), "org_risk_before": w["risk_before"], "org_risk_after": w["risk_after"],
                    "why": f"{g['action']}: {risk.ACTION_EFFECTS[g['action']]} (what-if recomputation with the same model)"})
    out.sort(key=lambda x: x["asset_risk_delta"])
    return out


def why(node: Any, aid: str, detector: Any = None, sim_day: int = 0, epss_asof: Optional[str] = None, snapshot_commit: Optional[str] = None) -> Dict[str, Any]:
    a = node.assets[aid]
    inv = node.inventory[aid]
    s = score_asset_v2(a)
    shap = s["factors_shap"]
    findings = detector.list(aid) if detector is not None else []
    return {
        "asset": {k: inv.get(k) for k in ("asset_id", "name", "type", "vendor", "model", "firmware_version", "zone", "criticality",
                                          "safety_critical", "open_ports", "maintenance_window", "firmware_state")}
                 | {"internet_exposed": a.internet_exposed, "default_credentials": a.default_credentials, "last_patched": a.last_patched,
                    "days_since_patch": risk.days_since(a.last_patched), "supply_chain_flag": a.supply_chain_flag, "isolated": a.isolated,
                    "likelihood_multiplier": a.likelihood_mult, "service_criticality": a.service_crit, "num_dependents": a.num_dependents},
        "vulnerabilities": [{k: v.get(k) for k in ("cve", "cvss", "epss", "exploited", "source", "match", "epss_time_matched", "epss_missing",
                                                   "advisory_id", "advisory_vendor", "cwe", "version_match")} for v in a.vulns],
        "scores": {"likelihood": s["likelihood"], "impact": s["impact"], "risk": s["risk"], "band": s["band"],
                   "likelihood_bp": s["likelihood_bp"], "impact_bp": s["impact_bp"], "risk_bp": s["risk_bp"], "band_bp": s["band_bp"],
                   "formula": "risk_bp = round_half_up(likelihood_bp * (3000 + 7000 * impact_bp / 10000) / 10000)"},
        "shap": {"unit": shap["unit"], "base_value": shap["base_value"], "factors": shap["factors"]},
        "share_of_risk_bar": {"label": "share of risk (not SHAP)", "unit": "risk points = risk * shap / sum|shap|", "items": s["top_factors"]},
        "dependency_path": dependency_path(node, aid),
        "cascade_assumptions": cascade_assumptions(),
        "freshness": {"sim_day": sim_day, "epss_asof": epss_asof, "epss_time_matched": False, "snapshot_commit": snapshot_commit,
                      "model_version": s["model_version"], "model_source": s["model_source"]},
        "findings": findings,
        "recommended_actions": recommended_actions(node, aid, s),
        "missing": s["missing"],
        "source_tags": s["source_tags"],
    }
