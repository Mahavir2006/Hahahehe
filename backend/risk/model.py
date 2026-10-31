"""
Risk scoring: learned likelihood (M1) x deterministic impact (RISK-01..07).

    risk = 100 x likelihood x (0.3 + 0.7 x impact)

computed in integer basis points so attested values recompute identically on any machine:
    likelihood_bp, impact_bp in 0..10000;  risk_bp = round_half_up(likelihood_bp * (30_000_000 + 7_000 * impact_bp), 10^8)
risk (0..100) = risk_bp / 100. Only the likelihood is learned; impact, cascade and what-if wiring are deterministic.
The authoritative numbers come from here; agents/LLMs only narrate them.
"""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from backend.common.config import settings
from backend.risk.features import ASSET_TYPE_CODE, LABELS, ZONE_ORD
from backend.risk.inference import M1, round_half_up

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = Path(__file__).resolve().parent / "artifacts"
REFERENCE_DATE = date(2026, 10, 31)  # fixed so scoring is deterministic
FACTOR_LABELS = LABELS
SERVICE_CRIT = {"low": 0.25, "medium": 0.5, "high": 0.75, "life_critical": 1.0}
BANDS = ["low", "medium", "high", "critical"]
BAND_HYSTERESIS = 2.0   # risk points a score must clear past a band boundary before an attested band changes
RiskModel = M1          # the version used in attestations is M1's stable model_version


def band_for(risk: float) -> str:
    """RISK-04: thresholds are config constants; boundaries are inclusive on the lower band."""
    if risk <= settings.risk_band_low_max:
        return "low"
    if risk <= settings.risk_band_medium_max:
        return "medium"
    if risk <= settings.risk_band_high_max:
        return "high"
    return "critical"


def band_with_hysteresis(risk: float, previous: Optional[str], margin: float = BAND_HYSTERESIS) -> str:
    """The attested band moves only when the score clears the boundary by `margin`, so a tiny change cannot flip it."""
    new = band_for(risk)
    if previous not in BANDS or new == previous:
        return new
    edges = [settings.risk_band_low_max, settings.risk_band_medium_max, settings.risk_band_high_max]
    i = BANDS.index(previous)
    upper = edges[i] if i < 3 else float("inf")
    lower = edges[i - 1] if i > 0 else float("-inf")
    if risk > upper + margin or risk <= lower - margin:
        return new
    return previous


def train(out_dir: Optional[Path] = None, seed: int = 42) -> Dict[str, Any]:
    """Retrain M1 with the shipped configuration (no search). The full pipeline is backend/risk/train_model.py."""
    from backend.risk import train_model

    cfg = json.loads((ARTIFACTS / "metadata.json").read_text(encoding="utf-8"))["config"]
    return train_model.train(out_dir, seed=seed, cfg=cfg)


# ------------------------------------------------------------------ asset context
@dataclass
class AssetCtx:
    asset_id: str
    org: str
    name: str = ""
    internet_exposed: bool = False
    default_credentials: bool = False
    zone: str = "IT"
    last_patched: str = "2026-01-01"
    criticality: int = 3
    safety_critical: bool = False
    num_dependents: int = 0
    service_crit: str = "low"
    vulns: List[Dict[str, Any]] = field(default_factory=list)  # {cve, cvss|None, epss|None, exploited, published?}
    supply_chain_flag: bool = False
    likelihood_mult: float = 1.0      # documented assumptions only: monitoring x0.85, isolation x0.3
    isolated: bool = False
    asset_type: str = "unknown"
    open_mgmt_ports: int = 0
    remote_access_enabled: bool = False
    firmware_known: bool = True
    telemetry: Dict[str, float] = field(default_factory=dict)   # aggregated rule-D features (30 days before t)


def days_since(last_patched: str) -> int:
    y, m, d = (int(p) for p in last_patched.split("-"))
    return max((REFERENCE_DATE - date(y, m, d)).days, 0)


def features_of(a: AssetCtx) -> Dict[str, Any]:
    """Feature record as of REFERENCE_DATE. No silent defaults: a gap becomes the documented fallback 0 plus a flag."""
    vulns = a.vulns
    cvss = [float(v["cvss"]) for v in vulns if v.get("cvss") is not None]
    epss = [float(v["epss"]) for v in vulns if v.get("epss") is not None]
    pub = [date.fromisoformat(v["published"][:10]) for v in vulns if v.get("published")]
    has = int(bool(vulns))
    return {
        "asset_type_code": ASSET_TYPE_CODE.get(a.asset_type, ASSET_TYPE_CODE["unknown"]),
        "zone_ord": ZONE_ORD.get(a.zone, 0), "criticality": a.criticality, "safety_critical": int(a.safety_critical),
        "num_dependents": a.num_dependents, "supply_chain_flag": int(a.supply_chain_flag), "internet_exposed": int(a.internet_exposed),
        "default_credentials": int(a.default_credentials), "open_mgmt_ports": a.open_mgmt_ports,
        "remote_access_enabled": int(a.remote_access_enabled), "firmware_known": int(a.firmware_known),
        "days_since_patch": days_since(a.last_patched), "has_vulnerability": has, "cve_count": len(vulns),
        "max_cvss": max(cvss) if cvss else 0.0, "max_epss": max(epss) if epss else 0.0,
        "any_known_exploited": int(any(bool(v.get("exploited")) for v in vulns)),
        "vuln_age_days": (REFERENCE_DATE - min(pub)).days if pub else 0,
        "missing_cvss": int(has and not cvss), "missing_epss": int(has and not epss),
        "failed_auth_count": a.telemetry.get("failed_auth_count", 0), "new_remote_session_flag": a.telemetry.get("new_remote_session_flag", 0),
        "rule_hit_count": a.telemetry.get("rule_hit_count", 0), "high_severity_rule_hit": a.telemetry.get("high_severity_rule_hit", 0),
    }


def impact_of(a: AssetCtx) -> float:
    crit = min(max(a.criticality, 1), 5) / 5.0
    dep = min(a.num_dependents / 8.0, 1.0)
    svc = SERVICE_CRIT.get(a.service_crit, 0.25)
    return 0.45 * crit + 0.20 * float(a.safety_critical) + 0.15 * dep + 0.20 * svc


def to_bp(x: float) -> int:
    return int(np.floor(min(max(x, 0.0), 1.0) * 10000 + 0.5))


def risk_bp_of(likelihood_bp: int, impact_bp: int) -> int:
    return round_half_up(likelihood_bp * (30_000_000 + 7_000 * impact_bp), 100_000_000)


def score_asset(a: AssetCtx, model: Optional[M1] = None, explain: bool = True) -> Dict[str, Any]:
    """RISK-02: risk = 100 * likelihood * (0.3 + 0.7 * impact), in integer basis points."""
    model = model or M1.get()
    feats = features_of(a)
    pred = model.predict(feats, explain=explain)
    lik_bp = min(max(int(np.floor(pred["likelihood_bp"] * a.likelihood_mult + 0.5)), 0), 10000)
    imp_bp = to_bp(impact_of(a))
    r_bp = risk_bp_of(lik_bp, imp_bp)
    risk = r_bp / 100
    missing = list(pred["missing"])
    if feats["has_vulnerability"] and not any(v.get("published") for v in a.vulns):
        missing.append("vuln_age_days:unknown")
    factors = []
    total = sum(abs(f["contribution_logodds"]) for f in pred["top_factors"]) or 1.0
    for f in pred["top_factors"]:
        c = f["contribution_logodds"]
        factors.append({
            "factor": f["label"], "feature": f["feature"], "value": f["value"], "contribution_logodds": c,
            "share_of_risk_not_shap": round(risk * abs(c) / total, 2),
            "text": f"{f['label']}: {'+' if c > 0 else ''}{c} log-odds",
        })
    return {
        "asset_id": a.asset_id, "org": a.org, "likelihood": lik_bp / 10000, "likelihood_bp": lik_bp,
        "impact": imp_bp / 10000, "impact_bp": imp_bp, "risk": risk, "risk_bp": r_bp, "band": band_for(risk),
        "top_factors": factors, "shap_units": "log-odds (uncalibrated base model)", "model_version": model.version,
        "missing": missing, "data_source_tags": pred["data_source_tags"],
    }


def why(a: AssetCtx, cascade_assumptions: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Dashboard 'why' payload: sources, key factors, likelihood next to impact next to risk, assumptions, freshness."""
    from backend.graph import cascade as C

    s = score_asset(a)
    meta = M1.get().meta
    return {
        "asset_id": a.asset_id, "likelihood": s["likelihood"], "impact": s["impact"], "risk": s["risk"], "band": s["band"],
        "source_cves": [{"cve": v.get("cve"), "cvss": v.get("cvss"), "known_exploited": bool(v.get("exploited")),
                         "version_match": v.get("version_match", "advisory matched to inventory"), "source": "advisory"} for v in a.vulns],
        "key_factors": s["top_factors"], "missing_or_clipped": s["missing"],
        "cascade_assumptions": cascade_assumptions or {"EDGE_WEIGHT": C.EDGE_WEIGHT, "SERVICE_WEIGHT": C.SERVICE_WEIGHT,
                                                       "BAND_P": C.BAND_P, "STRENGTH_W": C.STRENGTH_W, "note": "hand-set assumptions"},
        "data_freshness": {"scored_as_of": REFERENCE_DATE.isoformat(), "model_version": s["model_version"],
                           "training_data_sha256": meta["training_data"]["sha256"][:16]},
        "source_tags": {"asset facts": "simulated", "vulnerability": "advisory-derived", "telemetry": "telemetry-derived (simulated)",
                        "epss": "proxy", "impact": "deterministic formula", "labels the model learned from": "synthetic"},
    }


def aggregate(scores: List[Dict[str, Any]]) -> float:
    """RISK-07: 0.6 * max + 0.4 * mean over asset risks."""
    if not scores:
        return 0.0
    risks = [s["risk"] for s in scores]
    return round(0.6 * max(risks) + 0.4 * (sum(risks) / len(risks)), 4)


# ------------------------------------------------------------------------ what-if
REMOVES_VULNS = {"PATCH", "UPDATE_FIRMWARE"}
ACTION_EFFECTS = {
    "PATCH": "removes known vulnerabilities and resets patch age",
    "UPDATE_FIRMWARE": "removes known vulnerabilities, resets patch age, clears the unattested-firmware flag",
    "ROTATE_CREDENTIALS": "removes default credentials",
    "SEGMENT_NETWORK": "removes internet exposure",
    "RESTRICT_ACCESS": "removes internet exposure",
    "ENABLE_MONITORING": "multiplies likelihood by 0.85 (assumption)",
    "ISOLATE_ASSET": "removes exposure, remote access and management ports; multiplies likelihood by 0.3 (assumption)",
    "DISABLE_SERVICE_PORT": "closes one management port",
    "REQUEST_VENDOR_SIGNOFF": "enabler, no direct risk effect",
    "SCHEDULE_MAINTENANCE_WINDOW": "enabler, no direct risk effect",
    "INCIDENT_RESPONSE_PLAN_UPDATE": "organisational, no direct risk effect",
}


def apply_action(a: AssetCtx, action: str) -> None:
    """Change the real features the action changes; the two multipliers are documented assumptions."""
    if action in REMOVES_VULNS:
        a.vulns = []
        a.last_patched = REFERENCE_DATE.isoformat()
        if action == "UPDATE_FIRMWARE":
            a.supply_chain_flag = False
            a.firmware_known = True
    elif action == "ROTATE_CREDENTIALS":
        a.default_credentials = False
    elif action in ("SEGMENT_NETWORK", "RESTRICT_ACCESS"):
        a.internet_exposed = False
    elif action == "ENABLE_MONITORING":
        a.likelihood_mult *= 0.85
    elif action == "ISOLATE_ASSET":
        a.internet_exposed = False
        a.remote_access_enabled = False
        a.open_mgmt_ports = 0
        a.likelihood_mult *= 0.3
        a.isolated = True
    elif action == "DISABLE_SERVICE_PORT":
        a.open_mgmt_ports = max(a.open_mgmt_ports - 1, 0)
    elif action in ACTION_EFFECTS:
        return
    else:
        raise ValueError(f"unknown action {action}")


def what_if(assets: List[AssetCtx], actions: List[Dict[str, Any]], model: Optional[M1] = None) -> Dict[str, Any]:
    """RISK-06: pure, side-effect free. actions = [{action, targets:[asset_id]}]."""
    model = model or M1.get()
    before = {a.asset_id: score_asset(a, model, explain=False) for a in assets}
    mod = deepcopy(assets)
    idx = {a.asset_id: a for a in mod}
    for act in actions:
        for t in act["targets"]:
            if t not in idx:
                raise KeyError(f"unknown asset {t}")
            apply_action(idx[t], act["action"])
    after = {a.asset_id: score_asset(a, model, explain=False) for a in mod}
    per_asset = [
        {"asset_id": k, "before": before[k]["risk"], "after": after[k]["risk"], "delta": round(after[k]["risk"] - before[k]["risk"], 4)}
        for k in before
        if before[k]["risk"] != after[k]["risk"]
    ]
    rb, ra = aggregate(list(before.values())), aggregate(list(after.values()))
    return {
        "risk_before": rb,
        "risk_after": ra,
        "delta": round(ra - rb, 6),
        "per_asset_delta": per_asset,
        "after_scores": after,
        "before_scores": before,
    }
