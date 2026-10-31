"""
Model adapter (PS-03 WP1): load a swappable risk-model artifact folder, fail closed on anything wrong.

RISK_MODEL_DIR unset  -> the committed v1 model (backend/risk/artifacts), model source "v1".
RISK_MODEL_DIR=<dir>  -> a v2 folder (CONTEXT.md section 6): metadata.json must carry sha256_model matching
                         model.joblib and a feature list drawn only from REGISTRY. A mismatch raises
                         ModelArtifactError; there is no silent fallback to v1.

Registry features beyond v1's ten live in AssetCtx.extra (a plain dict); vulnerability-derived ones are refreshed
before PS-03 scoring and after every apply_action, so what-if copies present current values. v1 never reads them.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.risk import model as risk

V1_FEATURES = list(risk.FEATURES)
VULN_FEATURES = ["has_vulnerability", "cve_count", "max_cvss", "max_epss", "any_known_exploited", "missing_epss"]
STATIC_FEATURES = ["open_mgmt_ports", "firmware_known"]
TELEMETRY_FEATURES = ["failed_auth_count", "new_remote_session_flag", "rule_hit_count", "high_severity_rule_hit"]
REGISTRY = set(V1_FEATURES + VULN_FEATURES + STATIC_FEATURES + TELEMETRY_FEATURES + ["anomaly_score"])
MGMT_PORTS = {22, 23, 80, 443, 3389, 5900, 8080, 102, 502, 44818, 2404, 1911}
# Plausible ranges for clipping/reporting in the new scoring path (v1 inputs are never altered).
RANGES: Dict[str, tuple] = {
    "internet_exposed": (0, 1), "cvss_base": (0, 10), "epss_like": (0, 1), "default_credentials": (0, 1), "zone_ord": (0, 3),
    "days_since_patch": (0, 3650), "criticality": (1, 5), "num_dependents": (0, 1000), "safety_critical": (0, 1),
    "supply_chain_flag": (0, 1), "has_vulnerability": (0, 1), "cve_count": (0, 1000), "max_cvss": (0, 10), "max_epss": (0, 1),
    "any_known_exploited": (0, 1), "missing_epss": (0, 1), "open_mgmt_ports": (0, 65535), "firmware_known": (0, 1),
    "failed_auth_count": (0, 1e6), "new_remote_session_flag": (0, 1), "rule_hit_count": (0, 1e6), "high_severity_rule_hit": (0, 1),
    "anomaly_score": (0, 1),
}


LABELS = {
    "has_vulnerability": "Has an open vulnerability", "cve_count": "Number of open CVEs", "max_cvss": "Highest CVSS",
    "max_epss": "Highest EPSS", "any_known_exploited": "Known-exploited CVE (KEV)", "missing_epss": "EPSS missing for a CVE",
    "open_mgmt_ports": "Open management ports", "firmware_known": "Firmware attested", "failed_auth_count": "Failed logins (30 days)",
    "new_remote_session_flag": "New remote session (30 days)", "rule_hit_count": "Detection rule hits (30 days)",
    "high_severity_rule_hit": "High-severity rule hit (30 days)", "anomaly_score": "Network anomaly score",
}


class ModelArtifactError(RuntimeError):
    pass


_load_error: Optional[str] = None


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def validate_dir(path: Path) -> Dict[str, Any]:
    path = Path(path)
    for f in ("model.joblib", "metadata.json"):
        if not (path / f).exists():
            raise ModelArtifactError(f"{path}: missing {f}")
    meta = json.loads((path / "metadata.json").read_text(encoding="utf-8"))
    feats = meta.get("features")
    if not isinstance(feats, list) or not feats:
        raise ModelArtifactError(f"{path}: metadata.json has no feature list")
    unknown = sorted(set(feats) - REGISTRY)
    if unknown:
        raise ModelArtifactError(f"{path}: features not in the registry: {unknown}")
    want = meta.get("sha256_model")
    if not want:
        raise ModelArtifactError(f"{path}: metadata.json has no sha256_model")
    got = sha256_file(path / "model.joblib")
    if got != want:
        raise ModelArtifactError(f"{path}: model.joblib sha256 {got[:16]}... does not match metadata sha256_model {str(want)[:16]}...")
    if not meta.get("model_version"):
        raise ModelArtifactError(f"{path}: metadata.json has no model_version")
    return meta


def load_validated(path: Path) -> "risk.RiskModel":
    """Validate, then load through the normal RiskModel (model_version used as is, never recomputed)."""
    global _load_error
    try:
        validate_dir(path)
    except ModelArtifactError as e:
        _load_error = str(e)
        raise
    for k, v in LABELS.items():  # score_asset looks up a display label for every feature of the model
        risk.FACTOR_LABELS.setdefault(k, v)
    m = risk.RiskModel(Path(path))
    base = Path(path) / "base_model.joblib"
    if base.exists():  # SHAP on the underlying tree model when model.joblib is a calibration wrapper
        import joblib
        import shap

        m._explainer = shap.TreeExplainer(joblib.load(base))
    schema = Path(path) / "schema.json"
    if m._explainer is None:  # occlusion fallback needs a baseline for every feature of THIS model
        fb = json.loads(schema.read_text(encoding="utf-8")) if schema.exists() else {}
        m._baseline = {f: float((fb.get(f) or {}).get("fallback", 0.0)) for f in m.features}
    m.source = "v2"  # type: ignore[attr-defined]
    _load_error = None
    return m


def model_source(m: Optional["risk.RiskModel"] = None) -> str:
    return getattr(m or risk.RiskModel.get(), "source", "v1")


def info() -> Dict[str, Any]:
    d = os.environ.get("RISK_MODEL_DIR")
    out: Dict[str, Any] = {"risk_model_dir": d, "source": "v2" if d else "v1"}
    try:
        m = risk.RiskModel.get()
    except Exception as e:  # noqa: BLE001
        out.update(error=str(e), loaded=False)
        return out
    art = Path(d) if d else risk.ARTIFACTS
    out.update(loaded=True, model_version=m.version, features=m.features, metadata={k: v for k, v in m.meta.items() if k != "features"},
               shap="TreeExplainer (log-odds)" if m._explainer is not None else "occlusion fallback (probability delta)")
    mf = art / "metrics.json"
    out["metrics"] = json.loads(mf.read_text(encoding="utf-8")) if mf.exists() else None
    return out


# ------------------------------------------------------------------ registry features on AssetCtx.extra
# extra stays a plain dict (the orchestrator persists assets with asdict + json). Vulnerability-derived features
# are recomputed before every PS-03 scoring and after every apply_action (hook below), so what-if copies of an
# asset (patched, isolated, ...) present current values to a model that reads them. v1 never reads them.
def vuln_features(asset: "risk.AssetCtx") -> Dict[str, float]:
    vs = asset.vulns
    cvss = [float(v["cvss"]) for v in vs if v.get("cvss") is not None]
    epss = [float(v["epss"]) for v in vs if v.get("epss") is not None]
    return {
        "has_vulnerability": float(bool(vs)), "cve_count": float(len(vs)),
        "max_cvss": max(cvss, default=0.0), "max_epss": max(epss, default=0.0),
        "any_known_exploited": float(any(v.get("exploited") for v in vs)),
        "missing_epss": float(any(v.get("epss_missing") for v in vs)),
    }


def refresh(asset: "risk.AssetCtx") -> Dict[str, float]:
    asset.extra.update(vuln_features(asset))
    return asset.extra


_original_apply_action = risk.apply_action


def _apply_action_and_refresh(a: "risk.AssetCtx", action: str) -> None:
    _original_apply_action(a, action)
    if a.extra:
        refresh(a)


def install_refresh_hook() -> None:
    """What-if, planner and executor all call risk.apply_action; keep registry features current after each action."""
    if risk.apply_action is not _apply_action_and_refresh:
        risk.apply_action = _apply_action_and_refresh


def attach_live_features(asset: "risk.AssetCtx", inventory_row: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
    install_refresh_hook()
    if not isinstance(asset.extra, dict):
        asset.extra = {}
    for f in TELEMETRY_FEATURES:
        asset.extra.setdefault(f, 0.0)
    if inventory_row is not None:
        asset.extra.setdefault("open_mgmt_ports", float(sum(1 for p in inventory_row.get("open_ports", []) if p in MGMT_PORTS)))
        asset.extra.setdefault("firmware_known", float(str(inventory_row.get("firmware_state", "")).lower() in ("attested", "match")))
    return refresh(asset)


def check_inputs(row: Dict[str, float], features: List[str]) -> List[Dict[str, Any]]:
    """Report (not alter) features that are missing, non-finite or outside their documented range."""
    out = []
    for f in features:
        if f not in row:
            out.append({"feature": f, "issue": "missing"})
            continue
        v = row[f]
        if v is None or not math.isfinite(float(v)):
            out.append({"feature": f, "issue": "non_finite", "value": v})
            continue
        lo, hi = RANGES.get(f, (-math.inf, math.inf))
        if not lo <= float(v) <= hi:
            out.append({"feature": f, "issue": "out_of_range", "value": v, "range": [lo, hi]})
    return out
