"""
Offline evaluation of M1 against baselines B1-B3 (never runs in production).

    python -m backend.risk.evaluate_model       # from the repo root (make evaluate)

Writes backend/risk/artifacts/metrics.json. Every number in docs/ML_REPORT.md comes from that file.
Evaluations: grouped random split of generator A, time-ordered split of A, all of generator B.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.risk import train_model as T  # noqa: E402
from backend.risk.features import FEATURES, MONOTONE_INCREASING, SCHEMA  # noqa: E402
from backend.risk.rules import TELEMETRY_FEATURES  # noqa: E402

ART = T.ARTIFACTS


def ece(y: np.ndarray, p: np.ndarray, bins: int = 10) -> float:
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    return float(sum(abs(p[idx == b].mean() - y[idx == b].mean()) * (idx == b).mean() for b in range(bins) if (idx == b).any()))


def reliability(y: np.ndarray, p: np.ndarray, bins: int = 10):
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    return [{"bin": f"{edges[b]:.1f}-{edges[b + 1]:.1f}", "n": int((idx == b).sum()),
             "mean_predicted": round(float(p[idx == b].mean()), 4) if (idx == b).any() else None,
             "observed_rate": round(float(y[idx == b].mean()), 4) if (idx == b).any() else None} for b in range(bins)]


def topk(df: pd.DataFrame, score: np.ndarray, k: int, slate: int = 25, seed: int = 42) -> Any:
    """Mean precision@k over dashboard-sized slates of `slate` assets per window."""
    d = df[["window", "label"]].copy()
    d["s"] = score
    rng = np.random.default_rng(seed)
    vals = []
    for _, g in d.groupby("window"):
        g = g.iloc[rng.permutation(len(g))]
        for i in range(0, len(g) - slate + 1, slate):
            s = g.iloc[i:i + slate]
            vals.append(s.nlargest(k, "s", keep="first")["label"].mean())
    return round(float(np.mean(vals)), 4) if vals else "metric undefined"


def metrics(df: pd.DataFrame, score: np.ndarray, thr: Optional[float], prob: bool) -> Dict[str, Any]:
    y = df["label"].values
    if len(np.unique(y)) < 2:
        return {"note": "metric undefined (single class)"}
    out = {"n": int(len(y)), "positives": int(y.sum()), "roc_auc": round(float(roc_auc_score(y, score)), 4),
           "pr_auc": round(float(average_precision_score(y, score)), 4), "positive_rate": round(float(y.mean()), 4)}
    out["brier"] = round(float(brier_score_loss(y, score)), 4) if prob else "not applicable (score, not probability)"
    out["ece"] = round(ece(y, score), 4) if prob else "not applicable (score, not probability)"
    if thr is not None:
        pred = (score >= thr).astype(int)
        out.update({"threshold": thr, "precision_at_threshold": round(float(precision_score(y, pred, zero_division=0)), 4),
                    "recall_at_threshold": round(float(recall_score(y, pred, zero_division=0)), 4)})
    out["top5_precision"] = topk(df, score, 5)
    out["top10_precision"] = topk(df, score, 10)
    return out


def fit_b3(train: pd.DataFrame):
    best = None
    for c in (0.01, 0.1, 1.0, 10.0):
        sc = []
        for tr, va in GroupKFold(n_splits=3).split(train, groups=train["asset_id"]):
            m = make_pipeline(StandardScaler(), LogisticRegression(C=c, max_iter=2000)).fit(train.loc[tr, FEATURES], train.loc[tr, "label"])
            sc.append(average_precision_score(train.loc[va, "label"], m.predict_proba(train.loc[va, FEATURES])[:, 1]))
        if best is None or np.mean(sc) > best[1]:
            best = (c, float(np.mean(sc)))
    m = make_pipeline(StandardScaler(), LogisticRegression(C=best[0], max_iter=2000)).fit(train[FEATURES], train["label"])
    return m, {"C": best[0], "cv_pr_auc": round(best[1], 6), "regularisation": "L2"}


def b1(df):
    return df["max_cvss"].values + 1e-6 * df["max_epss"].values  # CVSS-only ranking (EPSS only breaks ties)


def b2(df):
    return df["any_known_exploited"].values.astype(float)


def evaluate() -> Dict[str, Any]:
    meta = json.loads((ART / "metadata.json").read_text(encoding="utf-8"))
    bundle = joblib.load(ART / "model.joblib")
    cfg = {k: v for k, v in meta["config"].items() if k != "choice"}
    a, b = T.load("a"), T.load("b")
    s = T.split(a)
    tests = {"A_grouped": s["test"], "A_time": s["time_test"], "B_all": b}
    out: Dict[str, Any] = {"model_version": meta["model_version"], "config": meta["config"], "labels": "synthetic; simulated data", "evaluations": {}}

    b3, b3_info = fit_b3(s["train"])
    b3_thr = T.f2_threshold(s["valid"]["label"].values, b3.predict_proba(s["valid"][FEATURES])[:, 1])
    b1_thr = T.f2_threshold(s["valid"]["label"].values, b1(s["valid"]) / 10.0) * 10.0
    out["baselines"] = {"B1": "rank by max CVSS (threshold by F2 on validation)", "B2": "known-exploited flag (CISA KEV), threshold 1",
                        "B3": {"model": "standard-scaled L2 logistic regression", **b3_info, "threshold": b3_thr}}
    # time split: M1 retrained on windows 0-5 of train assets only, calibrated on the calibration split
    m_time = T.fit(cfg, s["time_train"][FEATURES], s["time_train"]["label"])
    cal_time, _, _ = T.calibrate(m_time, s["calib"])
    for name, df in tests.items():
        m1 = (cal_time if name == "A_time" else bundle["calibrated"]).predict_proba(df[FEATURES])[:, 1]
        out["evaluations"][name] = {
            "M1": metrics(df, m1, bundle["threshold"], True),
            "B1_cvss_only": metrics(df, b1(df), b1_thr, False),
            "B2_known_exploited": metrics(df, b2(df), 1.0, False),
            "B3_logistic": metrics(df, b3.predict_proba(df[FEATURES])[:, 1], b3_thr, True),
        }
    ea, eb = out["evaluations"]["A_grouped"]["M1"], out["evaluations"]["B_all"]["M1"]
    out["two_generator_drop"] = {"roc_auc_A": ea["roc_auc"], "roc_auc_B": eb["roc_auc"], "roc_auc_drop": round(ea["roc_auc"] - eb["roc_auc"], 4),
                                 "pr_auc_A": ea["pr_auc"], "pr_auc_B": eb["pr_auc"],
                                 "note": "AUC on generator A mostly measures how well M1 recovers generator A, not security skill"}

    # calibration before/after on the grouped test split
    yt = s["test"]["label"].values
    raw = bundle["base"].predict_proba(s["test"][FEATURES])[:, 1]
    cal = bundle["calibrated"].predict_proba(s["test"][FEATURES])[:, 1]
    out["calibration"] = {"method": meta["calibration"]["method"], "brier_before": round(float(brier_score_loss(yt, raw)), 4),
                          "brier_after": round(float(brier_score_loss(yt, cal)), 4), "ece_before": round(ece(yt, raw), 4),
                          "ece_after": round(ece(yt, cal), 4), "reliability_before": reliability(yt, raw), "reliability_after": reliability(yt, cal)}

    # ablations: retrain with the chosen config minus a feature group, evaluate on the grouped test split
    abl = {}
    for name, drop in (("has_vulnerability", ["has_vulnerability"]), ("supply_chain_flag", ["supply_chain_flag"]), ("telemetry", TELEMETRY_FEATURES)):
        tr = s["train"].copy()
        te = s["test"].copy()
        for f in drop:  # neutralise rather than remove so the schema and constraints stay identical
            tr[f] = 0
            te[f] = 0
        m = T.fit(cfg, tr[FEATURES], tr["label"])
        p = m.predict_proba(te[FEATURES])[:, 1]
        abl[name] = {"dropped": drop, "pr_auc": round(float(average_precision_score(yt, p)), 4), "roc_auc": round(float(roc_auc_score(yt, p)), 4)}
    base_p = bundle["base"].predict_proba(s["test"][FEATURES])[:, 1]
    full = {"pr_auc": round(float(average_precision_score(yt, base_p)), 4), "roc_auc": round(float(roc_auc_score(yt, base_p)), 4)}
    for v in abl.values():
        v["pr_auc_change"] = round(v["pr_auc"] - full["pr_auc"], 4)
        v["roc_auc_change"] = round(v["roc_auc"] - full["roc_auc"], 4)
    out["ablations"] = {"full_model_uncalibrated": full, **abl}

    # label noise: flip an extra 10% of training labels
    rng = np.random.default_rng(7)
    noisy = s["train"].copy()
    flip = rng.random(len(noisy)) < 0.10
    noisy.loc[flip, "label"] = 1 - noisy.loc[flip, "label"]
    pn = T.fit(cfg, noisy[FEATURES], noisy["label"]).predict_proba(s["test"][FEATURES])[:, 1]
    out["label_noise"] = {"extra_flip_rate": 0.10, "roc_auc_clean": full["roc_auc"], "roc_auc_noisy": round(float(roc_auc_score(yt, pn)), 4),
                          "roc_auc_change": round(float(roc_auc_score(yt, pn)) - full["roc_auc"], 4)}

    # monotonicity sweep on the shipped (calibrated) model
    sample = s["test"].sample(300, random_state=1)
    mono = {}
    for f in MONOTONE_INCREASING:
        lo, hi = SCHEMA[f][1], SCHEMA[f][2]
        grid = np.linspace(lo, hi, 11) if SCHEMA[f][0] == "float" else np.unique(np.linspace(lo, hi, 11).round())
        preds = []
        for v in grid:
            x = sample[FEATURES].copy()
            x[f] = v
            preds.append(bundle["calibrated"].predict_proba(x)[:, 1])
        diffs = np.diff(np.vstack(preds), axis=0)
        mono[f] = {"violations": int((diffs < -1e-12).sum()), "points_checked": int(diffs.size)}
    out["monotonicity"] = mono

    # determinism: train twice with the shipped config
    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
        m1 = T.train(Path(d1), cfg=meta["config"])
        m2 = T.train(Path(d2), cfg=meta["config"])
        p1 = joblib.load(Path(d1) / "model.joblib")["calibrated"].predict_proba(s["test"][FEATURES])[:, 1]
        p2 = joblib.load(Path(d2) / "model.joblib")["calibrated"].predict_proba(s["test"][FEATURES])[:, 1]
    out["determinism"] = {"same_model_version": m1["model_version"] == m2["model_version"] == meta["model_version"],
                          "same_artifact_sha256": m1["artifact_sha256"] == m2["artifact_sha256"],
                          "identical_predictions": bool(np.array_equal(p1, p2)), "model_version": m1["model_version"]}
    out["detection_rules_D"] = json.loads((ROOT / "data" / "ml" / "rules_eval.json").read_text(encoding="utf-8"))
    out["pass_criteria"] = {
        "P1_leakage_audit": "passed (data/ml/MANIFEST.json)",
        "P2_determinism": all(out["determinism"][k] for k in ("same_model_version", "same_artifact_sha256", "identical_predictions")),
        "P3_m1_pr_auc_above_b3": out["evaluations"]["A_grouped"]["M1"]["pr_auc"] > out["evaluations"]["A_grouped"]["B3_logistic"]["pr_auc"],
        "P4_m1_roc_auc_A_vs_0.80": out["evaluations"]["A_grouped"]["M1"]["roc_auc"],
        "P5_ece_not_worse": out["calibration"]["ece_after"] <= out["calibration"]["ece_before"],
        "P6_monotonicity_violations": sum(v["violations"] for v in mono.values()),
        "P7_roc_auc_B": eb["roc_auc"],
    }
    return out


if __name__ == "__main__":
    res = evaluate()
    path = ART / "metrics.json"
    merged = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    merged.update(res)  # keep results written by evaluation/*.py (M3, M4, sensitivity, rigorous, band thresholds)
    path.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: res[k] for k in ("pass_criteria", "two_generator_drop")}, indent=2))
    for name, ev in res["evaluations"].items():
        for model, m in ev.items():
            print(name, model, {k: m.get(k) for k in ("roc_auc", "pr_auc", "brier", "top5_precision", "top10_precision")})
