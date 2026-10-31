"""
The single M1 inference interface (the Risk Agent is its only production caller).

    predict_likelihood(features) -> {likelihood_bp, model_version, top_factors, missing, data_source_tags}

The artifact is loaded only after its sha256 matches metadata.json (written by train_model). joblib/pickle
executes code on load, so only artifacts produced by backend/risk/train_model.py in this repository are trusted;
a missing or mismatching artifact fails closed with ModelArtifactError. There is no silent heuristic fallback.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd

from backend.risk.features import FEATURES, LABELS, SCHEMA, clip

ARTIFACTS = Path(__file__).resolve().parent / "artifacts"
GROUP_TAG = {"asset": "simulated", "vulnerability": "advisory", "telemetry": "telemetry"}


class ModelArtifactError(RuntimeError):
    pass


def round_half_up(num: int, den: int) -> int:
    """Integer division rounding half up (non-negative inputs)."""
    return (2 * num + den) // (2 * den)


class M1:
    _instance: Optional["M1"] = None

    def __init__(self, artifacts: Optional[Path] = None):
        art = Path(artifacts or ARTIFACTS)
        meta_p, model_p = art / "metadata.json", art / "model.joblib"
        if not meta_p.exists() or not model_p.exists():
            raise ModelArtifactError(f"M1 artifact missing in {art}; run `make train-model`")
        self.meta = json.loads(meta_p.read_text(encoding="utf-8"))
        digest = hashlib.sha256(model_p.read_bytes()).hexdigest()
        if digest != self.meta.get("artifact_sha256"):
            raise ModelArtifactError(f"M1 artifact hash mismatch ({digest[:12]} != {str(self.meta.get('artifact_sha256'))[:12]}); refusing to load")
        b = joblib.load(model_p)
        if b.get("features") != FEATURES:
            raise ModelArtifactError("M1 artifact was trained on a different feature schema")
        self.base, self.calibrated, self.threshold = b["base"], b["calibrated"], float(b["threshold"])
        self.version = self.meta["model_version"]
        import shap

        self.explainer = shap.TreeExplainer(self.base)
        self._cache: Dict[tuple, Dict[str, Any]] = {}

    @classmethod
    def get(cls) -> "M1":
        if cls._instance is None:
            cls._instance = M1()
        return cls._instance

    def _frame(self, rec: Dict[str, float]) -> pd.DataFrame:
        return pd.DataFrame([[rec[f] for f in FEATURES]], columns=FEATURES)

    def likelihood_bp(self, rec: Dict[str, float]) -> int:
        p = float(self.calibrated.predict_proba(self._frame(rec))[0, 1])
        return int(np.floor(p * 10000 + 0.5))

    def shap(self, rec: Dict[str, float]) -> Dict[str, float]:
        sv = np.asarray(self.explainer.shap_values(self._frame(rec)))
        sv = sv.reshape(-1, len(FEATURES))[0] if sv.ndim <= 2 else sv[0, :, 1]
        return {f: float(v) for f, v in zip(FEATURES, sv)}

    def predict(self, features: Dict[str, Any], explain: bool = True) -> Dict[str, Any]:
        rec, missing = clip(features)
        key = (tuple(rec[f] for f in FEATURES), explain)
        hit = self._cache.get(key)
        if hit is None:
            out = {"likelihood_bp": self.likelihood_bp(rec), "model_version": self.version, "top_factors": [], "record": rec}
            if explain:
                contrib = self.shap(rec)
                out["top_factors"] = [
                    {"feature": f, "label": LABELS[f], "value": rec[f], "contribution_logodds": round(v, 4)}
                    for f, v in sorted(contrib.items(), key=lambda kv: (-abs(kv[1]), kv[0]))[:5] if round(v, 4) != 0
                ]
            if len(self._cache) > 200_000:
                self._cache.clear()
            self._cache[key] = hit = out
        tags = {g: GROUP_TAG[g] for g in GROUP_TAG}
        if rec.get("max_epss", 0) > 0:
            tags["epss"] = "proxy"
        return {**hit, "top_factors": [dict(x) for x in hit["top_factors"]], "missing": list(missing), "data_source_tags": tags}


def predict_likelihood(features: Dict[str, Any], explain: bool = True) -> Dict[str, Any]:
    out = M1.get().predict(features, explain)
    out.pop("record", None)
    return out


def what_changed(before: Dict[str, Any], after: Dict[str, Any], k: int = 3) -> List[Dict[str, Any]]:
    """Top-k contributors to the change in likelihood between two feature records, from SHAP deltas (log-odds)."""
    m = M1.get()
    rb, _ = clip(before)
    ra, _ = clip(after)
    sb, sa = m.shap(rb), m.shap(ra)
    deltas = sorted(((f, sa[f] - sb[f]) for f in FEATURES), key=lambda kv: (-abs(kv[1]), kv[0]))
    out = []
    for f, d in deltas[:k]:
        if round(d, 4) == 0:
            continue
        direction = "raised" if d > 0 else "lowered"
        out.append({"feature": f, "before": rb[f], "after": ra[f], "delta_logodds": round(d, 4),
                    "sentence": f"{LABELS[f]} changed from {rb[f]:g} to {ra[f]:g} and {direction} the compromise likelihood ({d:+.2f} log-odds)."})
    return out


def schema_ranges() -> Dict[str, tuple]:
    return {f: (s[1], s[2]) for f, s in SCHEMA.items()}
