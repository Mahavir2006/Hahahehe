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
    if isinstance(a.extra, adapter.LiveFeatures) and a.extra.static.get("rule_hit_count", 0) > 0:
        tags.append("telemetry")
    return tags or ["inventory"]


def score_asset_v2(a: "risk.AssetCtx", m: Optional["risk.RiskModel"] = None, explain: bool = True) -> Dict[str, Any]:
    m = m or risk.RiskModel.get()
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
    reasons.sort(key=lambda r: (-abs(r["delta_contribution_logodds"]), -abs(r["delta_value"])))
    if p.get("likelihood_mult") != c.get("likelihood_mult"):
        reasons.insert(0, {"feature": "likelihood_multiplier", "label": "Mitigation multiplier", "from_value": p.get("likelihood_mult"),
                           "to_value": c.get("likelihood_mult"), "delta_value": round((c.get("likelihood_mult") or 1) - (p.get("likelihood_mult") or 1), 6),
                           "delta_contribution_logodds": 0.0})
    if prev and prev.get("model_version") != curr.get("model_version"):
        reasons.insert(0, {"feature": "model_version", "label": "model version changed", "from_value": prev.get("model_version"),
                           "to_value": curr.get("model_version"), "delta_value": 0.0, "delta_contribution_logodds": 0.0})
    reasons = reasons[:top]
    for r in reasons:
        r["text"] = f"{r['label']} {_fmt(r['from_value'])} -> {_fmt(r['to_value'])}"
    sentence = f"risk {p['risk_bp'] / 100:g} to {c['risk_bp'] / 100:g}"
    if reasons:
        sentence += ": " + "; ".join(r["text"] for r in reasons)
    return {"asset_id": asset_id, "from_sim_day": prev["sim_day"] if prev else None, "to_sim_day": curr["sim_day"],
            "from_risk_bp": p["risk_bp"], "to_risk_bp": c["risk_bp"], "from_band": p["band"], "to_band": c["band"],
            "reasons": reasons, "text": sentence}
