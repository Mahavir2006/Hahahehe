"""
Rigorous evaluation of the shipped M1 (offline only): classification metrics with confusion matrices and bootstrap
confidence intervals, threshold sweep, per-segment performance, drift (PSI / KS) between training data, held-out
data, generator B and the live demo assets, seed stability, robustness to noise and missing data, SHAP fidelity,
inference fuzzing and latency, and what-if properties on the demo assets.

    python evaluation/rigorous.py           # writes "rigorous" into backend/risk/artifacts/metrics.json
"""

from __future__ import annotations

import time

import numpy as np
import pandas as pd
from scipy.stats import ks_2samp
from sklearn.metrics import (accuracy_score, average_precision_score, balanced_accuracy_score, confusion_matrix, f1_score,
                             fbeta_score, matthews_corrcoef, precision_score, recall_score, roc_auc_score)

from common import demo_nodes, record
from backend.risk import model as M
from backend.risk import train_model as T
from backend.risk.features import FEATURES, MONOTONE_INCREASING, SCHEMA, clip
from backend.risk.inference import M1, predict_likelihood

R = lambda x: round(float(x), 4)  # noqa: E731


def cls_metrics(y, p, thr):
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"threshold": thr, "accuracy": R(accuracy_score(y, pred)), "balanced_accuracy": R(balanced_accuracy_score(y, pred)),
            "precision": R(precision_score(y, pred, zero_division=0)), "recall": R(recall_score(y, pred, zero_division=0)),
            "f1": R(f1_score(y, pred, zero_division=0)), "f2": R(fbeta_score(y, pred, beta=2, zero_division=0)),
            "specificity": R(tn / (tn + fp)) if tn + fp else "metric undefined", "mcc": R(matthews_corrcoef(y, pred)),
            "confusion": {"tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)},
            "accuracy_of_always_negative": R(1 - y.mean())}


def bootstrap(df, p, thr, n=500, seed=42):
    """Grouped bootstrap (resample assets, not rows) 95% intervals for ROC-AUC, PR-AUC and F1."""
    rng = np.random.default_rng(seed)
    ids = df["asset_id"].values
    uniq = np.unique(ids)
    idx_by = {a: np.flatnonzero(ids == a) for a in uniq}
    y = df["label"].values
    out = {"roc_auc": [], "pr_auc": [], "f1": []}
    for _ in range(n):
        idx = np.concatenate([idx_by[a] for a in rng.choice(uniq, len(uniq), replace=True)])
        yy, pp = y[idx], p[idx]
        if len(np.unique(yy)) < 2:
            continue
        out["roc_auc"].append(roc_auc_score(yy, pp))
        out["pr_auc"].append(average_precision_score(yy, pp))
        out["f1"].append(f1_score(yy, (pp >= thr).astype(int), zero_division=0))
    return {k: {"mean": R(np.mean(v)), "ci95": [R(np.percentile(v, 2.5)), R(np.percentile(v, 97.5))]} for k, v in out.items()}


def psi(expected, actual, bins=10):
    """Population Stability Index with quantile bins from `expected` (falls back to unique values for discrete data)."""
    e, a = np.asarray(expected, float), np.asarray(actual, float)
    uniq = np.unique(e)
    if len(uniq) <= bins:
        cats = np.union1d(uniq, np.unique(a))
        ep = np.array([(e == c).mean() for c in cats])
        ap = np.array([(a == c).mean() for c in cats])
    else:
        edges = np.unique(np.quantile(e, np.linspace(0, 1, bins + 1)))
        edges[0], edges[-1] = -np.inf, np.inf
        ep = np.histogram(e, edges)[0] / len(e)
        ap = np.histogram(a, edges)[0] / len(a)
    ep, ap = np.clip(ep, 1e-4, None), np.clip(ap, 1e-4, None)
    return float(np.sum((ap - ep) * np.log(ap / ep)))


def drift_level(v):
    return "stable" if v < 0.1 else "moderate" if v < 0.25 else "significant"


def segments(df, p, thr):
    out = {}
    specs = {
        "sector": df["sector"], "zone": df["zone"],
        "asset_type_known": np.where(df["asset_type"] == "unknown", "unknown", "known"),
        "has_vulnerability": df["has_vulnerability"].astype(str), "known_exploited": df["any_known_exploited"].astype(str),
        "internet_exposed": df["internet_exposed"].astype(str),
    }
    for name, col in specs.items():
        col = np.asarray(col)
        out[name] = {}
        for v in sorted(set(col)):
            m = col == v
            y = df["label"].values[m]
            row = {"n": int(m.sum()), "positive_rate": R(y.mean())}
            if len(np.unique(y)) == 2 and m.sum() >= 30:
                row.update({"roc_auc": R(roc_auc_score(y, p[m])), "pr_auc": R(average_precision_score(y, p[m])),
                            "recall": R(recall_score(y, (p[m] >= thr).astype(int), zero_division=0)),
                            "precision": R(precision_score(y, (p[m] >= thr).astype(int), zero_division=0))})
            else:
                row["note"] = "metric undefined (single class or n < 30)"
            out[name][str(v)] = row
    return out


def main():
    m = M1.get()
    thr = m.threshold
    a, b = T.load("a"), T.load("b")
    s = T.split(a)
    sets = {"A_grouped": s["test"], "A_time": s["time_test"], "B_all": b}
    preds = {k: m.calibrated.predict_proba(v[FEATURES])[:, 1] for k, v in sets.items()}
    res = {"model_version": m.version, "operating_threshold": thr}

    # 1. classification metrics, confusion matrices, CIs
    res["classification"] = {k: {"at_operating_threshold": cls_metrics(v["label"].values, preds[k], thr),
                                 "at_0.5": cls_metrics(v["label"].values, preds[k], 0.5),
                                 "roc_auc": R(roc_auc_score(v["label"], preds[k])), "pr_auc": R(average_precision_score(v["label"], preds[k])),
                                 "bootstrap_95ci": bootstrap(v, preds[k], thr)} for k, v in sets.items()}

    # 2. threshold sweep on the grouped test split
    yt = s["test"]["label"].values
    res["threshold_sweep_A_grouped"] = [{k: c[k] for k in ("threshold", "precision", "recall", "f1", "accuracy", "specificity")}
                                        for c in (cls_metrics(yt, preds["A_grouped"], t) for t in (0.05, 0.08, 0.11, 0.15, 0.2, 0.3, 0.4, 0.5, 0.6))]

    # 3. segments
    res["segments_A_grouped"] = segments(s["test"], preds["A_grouped"], thr)
    res["segments_B"] = segments(b, preds["B_all"], thr)

    # 4. drift: features and predictions, training split as reference
    nodes = demo_nodes()
    demo = pd.DataFrame([clip(M.features_of(x))[0] for n in nodes.values() for x in n.contexts()])
    demo_p = m.calibrated.predict_proba(demo[FEATURES])[:, 1]
    ref = s["train"]
    ref_p = m.calibrated.predict_proba(ref[FEATURES])[:, 1]
    drift = {}
    for name, df, p in (("A_test_vs_train", s["test"], preds["A_grouped"]), ("A_later_windows_vs_train", s["time_test"], preds["A_time"]),
                        ("B_vs_train", b, preds["B_all"]), ("demo_assets_vs_train", demo, demo_p)):
        per = {f: R(psi(ref[f], df[f])) for f in FEATURES}
        ks = {f: R(ks_2samp(ref[f], df[f]).pvalue) for f in FEATURES}
        top = sorted(per.items(), key=lambda kv: -kv[1])[:5]
        drift[name] = {"rows": int(len(df)), "prediction_psi": R(psi(ref_p, p)), "prediction_drift": drift_level(psi(ref_p, p)),
                       "max_feature_psi": top[0][1], "features_significant_psi": [f for f, v in per.items() if v >= 0.25],
                       "features_moderate_psi": [f for f, v in per.items() if 0.1 <= v < 0.25], "top5_feature_psi": dict(top),
                       "features_ks_p_below_0.01": [f for f, v in ks.items() if v < 0.01],
                       "label_positive_rate": R(df["label"].mean()) if "label" in df else "unlabelled"}
    drift["note"] = "PSI < 0.1 stable, 0.1-0.25 moderate, >= 0.25 significant; reference = training split of generator A"
    res["drift"] = drift

    # 5. seed stability: same config, different split + model seeds
    cfg = {k: v for k, v in m.meta["config"].items() if k != "choice"}
    seeds = []
    for sd in (1, 7, 13, 21, 99):
        ss = T.split(a, seed=sd)
        base = T.fit(cfg, ss["train"][FEATURES], ss["train"]["label"], seed=sd)
        pp = base.predict_proba(ss["test"][FEATURES])[:, 1]
        seeds.append({"seed": sd, "roc_auc": R(roc_auc_score(ss["test"]["label"], pp)), "pr_auc": R(average_precision_score(ss["test"]["label"], pp))})
    res["seed_stability"] = {"runs": seeds, "roc_auc_mean": R(np.mean([x["roc_auc"] for x in seeds])), "roc_auc_std": R(np.std([x["roc_auc"] for x in seeds])),
                             "pr_auc_mean": R(np.mean([x["pr_auc"] for x in seeds])), "pr_auc_std": R(np.std([x["pr_auc"] for x in seeds]))}

    # 6. robustness: noise on continuous features, simulated feed gaps
    rng = np.random.default_rng(3)
    X = s["test"][FEATURES].copy()
    rob = {"clean": R(roc_auc_score(yt, preds["A_grouped"]))}
    for scale in (0.05, 0.10, 0.20):
        Xn = X.copy()
        for f in ("days_since_patch", "max_cvss", "max_epss", "failed_auth_count", "vuln_age_days"):
            Xn[f] = np.clip(Xn[f] * (1 + rng.normal(0, scale, len(Xn))), SCHEMA[f][1], SCHEMA[f][2])
        rob[f"multiplicative_noise_{int(scale * 100)}pct"] = R(roc_auc_score(yt, m.calibrated.predict_proba(Xn)[:, 1]))
    Xg = X.copy()
    gap = (Xg["has_vulnerability"] == 1) & (rng.random(len(Xg)) < 0.5)
    Xg.loc[gap, ["max_epss", "missing_epss"]] = [0.0, 1]
    rob["epss_missing_on_half_of_vulnerable_rows"] = R(roc_auc_score(yt, m.calibrated.predict_proba(Xg)[:, 1]))
    Xt = X.copy()
    Xt[["failed_auth_count", "new_remote_session_flag", "rule_hit_count", "high_severity_rule_hit"]] = 0
    rob["telemetry_feed_down"] = R(roc_auc_score(yt, m.calibrated.predict_proba(Xt)[:, 1]))
    res["robustness_roc_auc"] = rob

    # 7. SHAP fidelity
    sample = s["test"].sample(300, random_state=5)
    sv = np.asarray(m.explainer.shap_values(sample[FEATURES]))
    sv = sv if sv.ndim == 2 else sv[:, :, 1]
    raw = m.base.predict_proba(sample[FEATURES])[:, 1]
    base_v = float(np.asarray(m.explainer.expected_value).reshape(-1)[-1])
    err = np.abs(base_v + sv.sum(1) - np.log(raw / (1 - raw)))
    sign = {}
    for f in MONOTONE_INCREASING:
        j = FEATURES.index(f)
        hi = sample[f].values > np.median(sample[f].values)
        sign[f] = "insufficient variation" if hi.all() or not hi.any() else bool(sv[hi, j].mean() >= sv[~hi, j].mean())
    imp = dict(sorted(((f, R(np.abs(sv[:, i]).mean())) for i, f in enumerate(FEATURES)), key=lambda kv: -kv[1])[:8])
    res["shap"] = {"additivity_max_abs_error_logodds": float(f"{err.max():.2e}"), "monotone_features_higher_value_higher_shap": sign,
                   "mean_abs_shap_top8": imp}

    # 8. inference: fuzzing and latency
    rng = np.random.default_rng(11)
    bad_values = [np.nan, np.inf, -np.inf, -1e9, 1e9, "x", None]
    crashes, out_of_range, non_int = 0, 0, 0
    for _ in range(1000):
        rec = {f: (bad_values[rng.integers(len(bad_values))] if rng.random() < 0.2 else float(rng.uniform(SCHEMA[f][1] - 5, SCHEMA[f][2] + 5))) for f in FEATURES}
        if rng.random() < 0.1:
            rec.pop(FEATURES[rng.integers(len(FEATURES))])
        try:
            o = predict_likelihood(rec)
            out_of_range += not (0 <= o["likelihood_bp"] <= 10000)
            non_int += not isinstance(o["likelihood_bp"], int)
        except Exception:  # noqa: BLE001
            crashes += 1
    recs = [clip(M.features_of(x))[0] for n in nodes.values() for x in n.contexts()]
    lat = []
    for r in recs:
        m._cache.clear()
        t0 = time.perf_counter()
        m.predict(r, explain=True)
        lat.append((time.perf_counter() - t0) * 1000)
    t0 = time.perf_counter()
    m.calibrated.predict_proba(s["test"][FEATURES])
    batch_ms = (time.perf_counter() - t0) * 1000
    res["inference"] = {"fuzz_cases": 1000, "crashes": crashes, "likelihood_out_of_range": out_of_range, "non_integer_outputs": non_int,
                        "latency_ms_single_with_shap_p50": R(np.percentile(lat, 50)), "latency_ms_single_with_shap_p95": R(np.percentile(lat, 95)),
                        "batch_rows": int(len(s["test"])), "batch_ms": R(batch_ms)}

    # 9. what-if properties on every demo asset x every mitigating action
    acts = ["PATCH", "UPDATE_FIRMWARE", "ROTATE_CREDENTIALS", "SEGMENT_NETWORK", "RESTRICT_ACCESS", "ENABLE_MONITORING", "ISOLATE_ASSET", "DISABLE_SERVICE_PORT"]
    increases, checked, pure = 0, 0, True
    for n in nodes.values():
        for x in n.contexts():
            before = M.features_of(x)
            for act in acts:
                w = M.what_if([x], [{"action": act, "targets": [x.asset_id]}])
                checked += 1
                increases += w["risk_after"] > w["risk_before"]
            pure &= M.features_of(x) == before
    res["what_if_properties"] = {"asset_action_pairs": checked, "risk_increased": int(increases), "inputs_unchanged": bool(pure)}

    # 10. integer/determinism of attested values
    sc1 = [M.score_asset(x, explain=False) for n in nodes.values() for x in n.contexts()]
    M1._instance = None
    sc2 = [M.score_asset(x, explain=False) for n in nodes.values() for x in n.contexts()]
    res["reproducibility"] = {"assets": len(sc1), "identical_risk_bp_after_reload": all(p["risk_bp"] == q["risk_bp"] for p, q in zip(sc1, sc2)),
                              "all_bp_are_int": all(isinstance(p[k], int) for p in sc1 for k in ("likelihood_bp", "impact_bp", "risk_bp"))}
    record("rigorous", res)
    return res


if __name__ == "__main__":
    import json

    r = main()
    print(json.dumps({k: r[k] for k in ("classification",)}, indent=1)[:4000])
