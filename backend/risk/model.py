"""
Deterministic risk model: gradient-boosted likelihood + rule-based impact (RISK-01..07).

The authoritative risk numbers come from here; agents/LLMs only narrate them.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from backend.common.config import settings

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = Path(__file__).resolve().parent / "artifacts"
REFERENCE_DATE = date(2026, 10, 31)  # fixed so scoring is deterministic

FEATURES = [
    "internet_exposed", "cvss_base", "epss_like", "default_credentials", "zone_ord",
    "days_since_patch", "criticality", "num_dependents", "safety_critical", "supply_chain_flag",
]
ZONE_ORD = {"IT": 0, "DMZ": 1, "OT": 2, "SAFETY": 3}
FACTOR_LABELS = {
    "internet_exposed": "Internet-exposed",
    "cvss_base": "Vulnerability severity (CVSS)",
    "epss_like": "Exploit likelihood (EPSS-like)",
    "default_credentials": "Default credentials in use",
    "zone_ord": "Network zone sensitivity",
    "days_since_patch": "Days since last patch",
    "criticality": "Asset criticality",
    "num_dependents": "Number of dependent assets",
    "safety_critical": "Safety-critical asset",
    "supply_chain_flag": "Unattested / tampered firmware",
}
SERVICE_CRIT = {"low": 0.25, "medium": 0.5, "high": 0.75, "life_critical": 1.0}
BANDS = ["low", "medium", "high", "critical"]


def band_for(risk: float) -> str:
    """RISK-04: thresholds are config constants; boundaries are inclusive on the lower band."""
    if risk <= settings.risk_band_low_max:
        return "low"
    if risk <= settings.risk_band_medium_max:
        return "medium"
    if risk <= settings.risk_band_high_max:
        return "high"
    return "critical"


# --------------------------------------------------------------------- training
def _frame(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out["zone_ord"] = out["zone"].map(ZONE_ORD).fillna(0).astype(int)
    return out[FEATURES].astype(float)


def train(csv_path: Optional[Path] = None, out_dir: Optional[Path] = None, seed: int = 42) -> Dict[str, Any]:
    csv_path = csv_path or ROOT / "data" / "historical_incidents.csv"
    out_dir = Path(out_dir or ARTIFACTS)
    out_dir.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(csv_path)
    X, y = _frame(df), df["compromised_within_90d"].astype(int)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=seed, stratify=y)
    model = GradientBoostingClassifier(n_estimators=200, max_depth=3, learning_rate=0.08, subsample=0.9, random_state=seed)
    model.fit(Xtr, ytr)
    proba = model.predict_proba(Xte)[:, 1]
    pred = (proba >= 0.5).astype(int)
    metrics = {
        "auc": float(roc_auc_score(yte, proba)),
        "precision": float(precision_score(yte, pred, zero_division=0)),
        "recall": float(recall_score(yte, pred, zero_division=0)),
        "n_train": int(len(Xtr)),
        "n_test": int(len(Xte)),
        "positive_rate": float(y.mean()),
    }
    joblib.dump(model, out_dir / "model.joblib")
    version = hashlib.sha256(json.dumps(metrics, sort_keys=True).encode() + (out_dir / "model.joblib").read_bytes()).hexdigest()[:16]
    meta = {"model_version": version, "features": FEATURES, "metrics": metrics, "seed": seed, "data": "synthetic (data/historical_incidents.csv)"}
    (out_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


class RiskModel:
    _instance: Optional["RiskModel"] = None

    def __init__(self, artifacts: Optional[Path] = None):
        art = Path(artifacts or ARTIFACTS)
        if not (art / "model.joblib").exists():
            train(out_dir=art)
        self.model = joblib.load(art / "model.joblib")
        self.meta = json.loads((art / "metadata.json").read_text(encoding="utf-8"))
        self.version = self.meta["model_version"]
        self._explainer = None
        try:
            import shap

            self._explainer = shap.TreeExplainer(self.model)
        except Exception:  # noqa: BLE001
            self._explainer = None
        self._baseline = None
        self._cache: Dict[tuple, float] = {}

    @classmethod
    def get(cls) -> "RiskModel":
        if cls._instance is None:
            cls._instance = RiskModel()
        return cls._instance

    def likelihood(self, row: Dict[str, float]) -> float:
        """Pure function of the feature vector, so results are memoised (what-if analysis re-scores unchanged assets constantly)."""
        key = tuple(float(row[f]) for f in FEATURES)
        hit = self._cache.get(key)
        if hit is None:
            hit = float(self.model.predict_proba(pd.DataFrame([list(key)], columns=FEATURES))[0, 1])
            if len(self._cache) > 200_000:
                self._cache.clear()
            self._cache[key] = hit
        return hit

    def contributions(self, row: Dict[str, float]) -> Dict[str, float]:
        """SHAP values in log-odds per feature; falls back to baseline-occlusion if SHAP is unavailable."""
        x = pd.DataFrame([[float(row[f]) for f in FEATURES]], columns=FEATURES)
        if self._explainer is not None:
            sv = self._explainer.shap_values(x)
            sv = np.asarray(sv[1] if isinstance(sv, list) else sv)[0]
            return {f: float(v) for f, v in zip(FEATURES, sv)}
        if self._baseline is None:
            df = pd.read_csv(ROOT / "data" / "historical_incidents.csv")
            self._baseline = _frame(df).median().to_dict()
        p0 = self.model.predict_proba(x)[0, 1]
        out = {}
        for f in FEATURES:
            xb = x.copy()
            xb[f] = self._baseline[f]
            out[f] = float(p0 - self.model.predict_proba(xb)[0, 1])
        return out


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
    vulns: List[Dict[str, Any]] = field(default_factory=list)  # {cve, cvss, epss, exploited}
    supply_chain_flag: bool = False
    likelihood_mult: float = 1.0
    isolated: bool = False


def days_since(last_patched: str) -> int:
    y, m, d = (int(p) for p in last_patched.split("-"))
    return max((REFERENCE_DATE - date(y, m, d)).days, 0)


def features_of(a: AssetCtx) -> Dict[str, float]:
    cvss = max((v.get("cvss", 0.0) for v in a.vulns), default=0.0)
    epss = max((v.get("epss", 0.0) for v in a.vulns), default=0.0)
    return {
        "internet_exposed": float(a.internet_exposed),
        "cvss_base": float(cvss),
        "epss_like": float(epss),
        "default_credentials": float(a.default_credentials),
        "zone_ord": float(ZONE_ORD.get(a.zone, 0)),
        "days_since_patch": float(days_since(a.last_patched)),
        "criticality": float(a.criticality),
        "num_dependents": float(a.num_dependents),
        "safety_critical": float(a.safety_critical),
        "supply_chain_flag": float(a.supply_chain_flag),
    }


def impact_of(a: AssetCtx) -> float:
    crit = min(max(a.criticality, 1), 5) / 5.0
    dep = min(a.num_dependents / 8.0, 1.0)
    svc = SERVICE_CRIT.get(a.service_crit, 0.25)
    return 0.45 * crit + 0.20 * float(a.safety_critical) + 0.15 * dep + 0.20 * svc


def score_asset(a: AssetCtx, model: Optional[RiskModel] = None, explain: bool = True) -> Dict[str, Any]:
    """RISK-02: risk = 100 * likelihood * (0.3 + 0.7 * impact)."""
    model = model or RiskModel.get()
    feats = features_of(a)
    base = model.likelihood(feats)
    likelihood = min(max(base * a.likelihood_mult, 0.0), 1.0)
    impact = impact_of(a)
    risk = round(100.0 * likelihood * (0.3 + 0.7 * impact), 4)
    contrib = model.contributions(feats) if explain else {}
    total_abs = sum(abs(v) for v in contrib.values()) or 1.0
    factors = []
    for f, v in sorted(contrib.items(), key=lambda kv: -abs(kv[1]))[:5]:
        pts = round(risk * v / total_abs, 1)
        if pts == 0:
            continue
        factors.append(
            {
                "factor": FACTOR_LABELS[f],
                "feature": f,
                "value": feats[f],
                "points": pts,
                "text": f"{FACTOR_LABELS[f]}: {'+' if pts > 0 else ''}{pts}",
            }
        )
    return {
        "asset_id": a.asset_id,
        "org": a.org,
        "likelihood": round(likelihood, 6),
        "impact": round(impact, 6),
        "risk": risk,
        "band": band_for(risk),
        "top_factors": factors,
        "model_version": model.version,
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
    "UPDATE_FIRMWARE": "removes known vulnerabilities, resets patch age, clears unattested-firmware flag",
    "ROTATE_CREDENTIALS": "removes default credentials",
    "SEGMENT_NETWORK": "removes internet exposure",
    "RESTRICT_ACCESS": "removes internet exposure",
    "ENABLE_MONITORING": "multiplies likelihood by 0.85",
    "ISOLATE_ASSET": "removes exposure and multiplies likelihood by 0.3",
    "DISABLE_SERVICE_PORT": "multiplies likelihood by 0.9",
    "REQUEST_VENDOR_SIGNOFF": "enabler, no direct risk effect",
    "SCHEDULE_MAINTENANCE_WINDOW": "enabler, no direct risk effect",
    "INCIDENT_RESPONSE_PLAN_UPDATE": "organisational, no direct risk effect",
}


def apply_action(a: AssetCtx, action: str) -> None:
    if action in REMOVES_VULNS:
        a.vulns = []
        a.last_patched = REFERENCE_DATE.isoformat()
        if action == "UPDATE_FIRMWARE":
            a.supply_chain_flag = False
    elif action == "ROTATE_CREDENTIALS":
        a.default_credentials = False
    elif action in ("SEGMENT_NETWORK", "RESTRICT_ACCESS"):
        a.internet_exposed = False
    elif action == "ENABLE_MONITORING":
        a.likelihood_mult *= 0.85
    elif action == "ISOLATE_ASSET":
        a.internet_exposed = False
        a.likelihood_mult *= 0.3
        a.isolated = True
    elif action == "DISABLE_SERVICE_PORT":
        a.likelihood_mult *= 0.9
    elif action in ACTION_EFFECTS:
        return
    else:
        raise ValueError(f"unknown action {action}")


def what_if(assets: List[AssetCtx], actions: List[Dict[str, Any]], model: Optional[RiskModel] = None) -> Dict[str, Any]:
    """RISK-06: pure, side-effect free. actions = [{action, targets:[asset_id]}]."""
    model = model or RiskModel.get()
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
