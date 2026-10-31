"""
Model adapter (PS-03 WP1) over the M1 inference interface (backend/risk/inference.py).

M1 already fails closed: it refuses an artifact whose sha256 does not match metadata.json or whose feature list
differs from backend/risk/features.FEATURES, and it has no heuristic fallback. This module only adds:
  * RISK_MODEL_DIR=<dir>: load M1 from another artifact folder (same checks), model source "v2";
    unset means the committed artifact in backend/risk/artifacts, model source "v1";
  * info() for the dashboard's model card, which reports a load error instead of hiding it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from backend.risk.inference import ARTIFACTS, M1, ModelArtifactError  # noqa: F401  (re-exported)

_load_error: Optional[str] = None


def configured_dir() -> Optional[Path]:
    d = os.environ.get("RISK_MODEL_DIR")
    return Path(d) if d else None


def load_configured() -> M1:
    """Install the configured model as M1's singleton. Raises ModelArtifactError (fail closed) on a bad folder."""
    global _load_error
    d = configured_dir()
    try:
        m = M1(d) if d else M1()
    except ModelArtifactError as e:
        _load_error = str(e)
        M1._instance = None
        raise
    m.source = "v2" if d else "v1"  # type: ignore[attr-defined]
    M1._instance = m
    _load_error = None
    return m


def model_source(m: Optional[M1] = None) -> str:
    return getattr(m or M1.get(), "source", "v2" if configured_dir() else "v1")


def info() -> Dict[str, Any]:
    d = configured_dir()
    out: Dict[str, Any] = {"risk_model_dir": str(d) if d else None, "source": "v2" if d else "v1"}
    try:
        m = M1._instance or load_configured()
    except ModelArtifactError as e:
        out.update(loaded=False, error=str(e))
        return out
    art = d or ARTIFACTS
    out.update(loaded=True, model_version=m.version, features=m.meta.get("features"),
               shap="TreeExplainer on the uncalibrated base model (log-odds)",
               metadata={k: v for k, v in m.meta.items() if k != "features"})
    mf = Path(art) / "metrics.json"
    out["metrics"] = json.loads(mf.read_text(encoding="utf-8")) if mf.exists() else None
    return out
