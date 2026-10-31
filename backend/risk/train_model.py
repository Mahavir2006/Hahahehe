"""
Train M1 (compromise-likelihood classifier) on generator A.

    python -m backend.risk.train_model          # from the repo root (make train-model)

Bounded search (16 configs, GroupKFold on training groups only), the model-choice rule from
docs/ML_DECISIONS.md, sigmoid calibration on a separate calibration split, an F2 operating threshold from the
validation split. Writes backend/risk/artifacts/{model.joblib, metadata.json}. Never imports data/label_process.py.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import GradientBoostingClassifier, HistGradientBoostingClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import average_precision_score, fbeta_score
from sklearn.model_selection import GroupKFold

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.risk.features import CATEGORICAL, FEATURES, MONOTONE_INCREASING, SCHEMA  # noqa: E402

DATA = ROOT / "data" / "ml"
ARTIFACTS = Path(__file__).resolve().parent / "artifacts"
SEED = 42

GBC_GRID = [{"estimator": "gbc", "n_estimators": n, "learning_rate": lr, "max_depth": d}
            for n in (200, 300) for lr in (0.05, 0.1) for d in (2, 3)]
HGB_GRID = [{"estimator": "hgb_monotonic", "max_iter": n, "learning_rate": lr, "max_depth": 3, "l2_regularization": l2}
            for n in (200, 300) for lr in (0.05, 0.1) for l2 in (0.0, 1.0)]


def file_hash(p: Path) -> str:
    return hashlib.sha256(p.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def load(gen: str = "a") -> pd.DataFrame:
    return pd.read_csv(DATA / f"gen_{gen}.csv")


def split(df: pd.DataFrame, seed: int = SEED) -> Dict[str, pd.DataFrame]:
    """Grouped by asset: 60% train, 10% validation, 10% calibration, 20% test; plus the time-ordered split."""
    ids = np.array(sorted(df["asset_id"].unique()))
    rng = np.random.default_rng(seed)
    rng.shuffle(ids)
    n = len(ids)
    cut = [int(n * 0.6), int(n * 0.7), int(n * 0.8)]
    part = {"train": ids[:cut[0]], "valid": ids[cut[0]:cut[1]], "calib": ids[cut[1]:cut[2]], "test": ids[cut[2]:]}
    out = {k: df[df["asset_id"].isin(set(v))].reset_index(drop=True) for k, v in part.items()}
    out["time_train"] = out["train"][out["train"]["window"] <= 5].reset_index(drop=True)
    out["time_test"] = out["test"][out["test"]["window"] >= 6].reset_index(drop=True)
    return out


def make(cfg: Dict[str, Any], seed: int = SEED):
    if cfg["estimator"] == "gbc":
        return GradientBoostingClassifier(n_estimators=cfg["n_estimators"], learning_rate=cfg["learning_rate"], max_depth=cfg["max_depth"],
                                          subsample=0.8, n_iter_no_change=10, validation_fraction=0.1, random_state=seed)
    mono = [1 if f in MONOTONE_INCREASING else 0 for f in FEATURES]
    cat = [f in CATEGORICAL for f in FEATURES]
    return HistGradientBoostingClassifier(max_iter=cfg["max_iter"], learning_rate=cfg["learning_rate"], max_depth=cfg["max_depth"],
                                          l2_regularization=cfg["l2_regularization"], monotonic_cst=mono, categorical_features=cat,
                                          early_stopping=True, n_iter_no_change=10, validation_fraction=0.1, random_state=seed)


def fit(cfg: Dict[str, Any], X: pd.DataFrame, y: pd.Series, seed: int = SEED):
    return make(cfg, seed).fit(X, y)


def cv_score(cfg: Dict[str, Any], train: pd.DataFrame, folds: int = 3) -> float:
    scores = []
    for tr, va in GroupKFold(n_splits=folds).split(train, groups=train["asset_id"]):
        m = fit(cfg, train.loc[tr, FEATURES], train.loc[tr, "label"])
        scores.append(average_precision_score(train.loc[va, "label"], m.predict_proba(train.loc[va, FEATURES])[:, 1]))
    return float(np.mean(scores))


def search(train: pd.DataFrame) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    results = [{"config": c, "cv_pr_auc": round(cv_score(c, train), 6)} for c in GBC_GRID + HGB_GRID]
    best = {e: max((r for r in results if r["config"]["estimator"] == e), key=lambda r: r["cv_pr_auc"]) for e in ("gbc", "hgb_monotonic")}
    shap_ok = _shap_supported(best["hgb_monotonic"]["config"], train)
    use_mono = shap_ok and best["hgb_monotonic"]["cv_pr_auc"] >= best["gbc"]["cv_pr_auc"] - 0.01
    chosen = best["hgb_monotonic" if use_mono else "gbc"]
    rule = {"gbc_best_cv_pr_auc": best["gbc"]["cv_pr_auc"], "hgb_monotonic_best_cv_pr_auc": best["hgb_monotonic"]["cv_pr_auc"],
            "shap_supports_hgb": shap_ok, "chosen": chosen["config"]["estimator"],
            "rule": "use hgb_monotonic if its CV PR-AUC >= gbc CV PR-AUC - 0.01 and SHAP supports it"}
    return {**chosen["config"], "choice": rule}, results


def _shap_supported(cfg, train) -> bool:
    """SHAP counts as supported only if its values add up to the model's log-odds (not merely if it runs)."""
    try:
        import shap

        m = fit(cfg, train[FEATURES].head(2000), train["label"].head(2000))
        X = train[FEATURES].iloc[2000:2200]
        ex = shap.TreeExplainer(m)
        sv = np.asarray(ex.shap_values(X))
        sv = sv if sv.ndim == 2 else sv[:, :, 1]
        p = m.predict_proba(X)[:, 1]
        err = np.abs(float(np.asarray(ex.expected_value).reshape(-1)[-1]) + sv.sum(1) - np.log(p / (1 - p)))
        return bool(err.max() < 1e-3)
    except Exception:  # noqa: BLE001
        return False


def calibrate(base, calib: pd.DataFrame):
    pos = int(calib["label"].sum())
    method = "isotonic" if pos >= 1000 else "sigmoid"
    cal = CalibratedClassifierCV(FrozenEstimator(base), method=method).fit(calib[FEATURES], calib["label"])
    return cal, method, pos


def f2_threshold(y: np.ndarray, p: np.ndarray) -> float:
    grid = np.round(np.arange(0.02, 0.96, 0.01), 2)
    scores = [fbeta_score(y, (p >= t).astype(int), beta=2, zero_division=0) for t in grid]
    return float(grid[int(np.argmax(scores))])


def model_version(cfg: Dict[str, Any], data_hash: str, seed: int) -> str:
    """Stable: schema + hyperparameters + training-data content hash + seed + sklearn version. Never metrics."""
    blob = json.dumps({"schema": {f: list(s[:3]) for f, s in SCHEMA.items()}, "config": {k: v for k, v in cfg.items() if k != "choice"},
                       "data": data_hash, "seed": seed, "sklearn": sklearn.__version__}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def train(out_dir: Optional[Path] = None, seed: int = SEED, cfg: Optional[Dict[str, Any]] = None, df: Optional[pd.DataFrame] = None) -> Dict[str, Any]:
    """Train, calibrate and save M1. `cfg` skips the search (used by tests and the determinism check)."""
    out_dir = Path(out_dir or ARTIFACTS)
    out_dir.mkdir(parents=True, exist_ok=True)
    df = df if df is not None else load("a")
    s = split(df, seed)
    search_log = []
    if cfg is None:
        cfg, search_log = search(s["train"])
    base = fit(cfg, s["train"][FEATURES], s["train"]["label"], seed)
    cal, method, cal_pos = calibrate(base, s["calib"])
    thr = f2_threshold(s["valid"]["label"].values, cal.predict_proba(s["valid"][FEATURES])[:, 1])
    data_hash = file_hash(DATA / "gen_a.csv")
    version = model_version(cfg, data_hash, seed)
    bundle = {"base": base, "calibrated": cal, "features": FEATURES, "threshold": thr, "model_version": version}
    joblib.dump(bundle, out_dir / "model.joblib")
    meta = {
        "model_version": version, "artifact_sha256": hashlib.sha256((out_dir / "model.joblib").read_bytes()).hexdigest(),
        "features": FEATURES, "config": cfg, "calibration": {"method": method, "positives_in_calibration_split": cal_pos},
        "operating_threshold": {"value": thr, "rule": "maximise F2 on the validation split"},
        "training_data": {"file": "data/ml/gen_a.csv", "sha256": data_hash, "rows_train": int(len(s["train"])),
                          "positive_rate_train": round(float(s["train"]["label"].mean()), 4)},
        "seed": seed, "sklearn": sklearn.__version__, "epss_source": "proxy",
        "shap_units": "log-odds of the uncalibrated base model",
        "labels": "synthetic (data/label_process.py); results are on simulated data",
        "search": search_log,
    }
    (out_dir / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return meta


if __name__ == "__main__":
    m = train()
    print(json.dumps({k: m[k] for k in ("model_version", "config", "calibration", "operating_threshold")}, indent=2))
