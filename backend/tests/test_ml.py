"""ML integration tests: M1 inference contract, edge cases, data hygiene, determinism, hysteresis."""
import hashlib
import json
import math
import shutil
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from backend.risk import inference as I
from backend.risk import model as M
from backend.risk import train_model as T
from backend.risk.features import ASSET_TYPE_CODE, FEATURES, clip

ROOT = Path(__file__).resolve().parents[2]


def ctx(**kw):
    base = dict(asset_id="x", org="power", internet_exposed=True, zone="DMZ", last_patched="2025-09-01", criticality=5,
                num_dependents=6, service_crit="high", asset_type="PLC", open_mgmt_ports=2)
    base.update(kw)
    return M.AssetCtx(**base)


@pytest.mark.req("RISK-02")
def test_outputs_are_integer_basis_points():
    s = M.score_asset(ctx(vulns=[{"cve": "CVE-1", "cvss": 9.8, "epss": 0.9, "exploited": True}]))
    for k in ("likelihood_bp", "impact_bp", "risk_bp"):
        assert isinstance(s[k], int) and 0 <= s[k] <= 10000
    assert s["risk_bp"] == M.risk_bp_of(s["likelihood_bp"], s["impact_bp"]) and s["risk"] == s["risk_bp"] / 100
    assert M.risk_bp_of(10000, 10000) == 10000 and M.risk_bp_of(0, 10000) == 0 and M.risk_bp_of(10000, 0) == 3000


@pytest.mark.req("RISK-02")
def test_no_vulnerability_is_not_a_low_severity_flaw():
    f = M.features_of(ctx(vulns=[]))
    assert f["has_vulnerability"] == 0 and f["max_cvss"] == 0 and f["missing_cvss"] == 0 and f["missing_epss"] == 0
    s = M.score_asset(ctx(vulns=[]))
    assert not [m for m in s["missing"] if m.startswith("max_cvss")]


@pytest.mark.req("RISK-02")
def test_missing_epss_and_cvss_use_fallback_plus_flag_not_a_silent_default():
    f = M.features_of(ctx(vulns=[{"cve": "CVE-1", "cvss": None, "epss": None, "exploited": False}]))
    assert f["has_vulnerability"] == 1 and f["missing_cvss"] == 1 and f["missing_epss"] == 1
    assert f["max_cvss"] == 0.0 and f["max_epss"] == 0.0


@pytest.mark.req("RISK-02")
def test_several_cves_aggregate_by_max_count_and_any_kev():
    v = [{"cve": "A", "cvss": 5.0, "epss": 0.2, "exploited": False, "published": "2025-01-01"},
         {"cve": "B", "cvss": 9.1, "epss": 0.6, "exploited": True, "published": "2026-06-01"}]
    f = M.features_of(ctx(vulns=v))
    assert (f["cve_count"], f["max_cvss"], f["max_epss"], f["any_known_exploited"]) == (2, 9.1, 0.6, 1)
    assert f["vuln_age_days"] == (M.REFERENCE_DATE - pd.Timestamp("2025-01-01").date()).days


@pytest.mark.req("RISK-02")
def test_unseen_asset_type_maps_to_unknown_level():
    assert M.features_of(ctx(asset_type="quantum toaster"))["asset_type_code"] == ASSET_TYPE_CODE["unknown"]
    assert 0 <= M.score_asset(ctx(asset_type="quantum toaster"))["risk"] <= 100


@pytest.mark.req("RISK-02")
@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -5, 1e9, "garbage", None])
def test_nan_inf_and_out_of_range_inputs_are_clipped_and_flagged(bad):
    rec = {f: 0 for f in FEATURES}
    rec["days_since_patch"] = bad
    out = I.predict_likelihood(rec)
    assert 0 <= out["likelihood_bp"] <= 10000 and any(m.startswith("days_since_patch") for m in out["missing"])


@pytest.mark.req("RISK-03")
def test_top_factors_are_shap_log_odds_not_risk_points():
    s = M.score_asset(ctx(default_credentials=True, vulns=[{"cve": "C", "cvss": 9.8, "epss": 0.9, "exploited": True}]))
    assert s["shap_units"].startswith("log-odds")
    for f in s["top_factors"]:
        assert "points" not in f and isinstance(f["contribution_logodds"], float)
    m = I.M1.get()
    rec, _ = clip(M.features_of(ctx(default_credentials=True)))
    sv = m.shap(rec)
    base = float(np.asarray(m.explainer.expected_value).reshape(-1)[-1])
    raw = m.base.predict_proba(m._frame(rec))[0, 1]
    assert base + sum(sv.values()) == pytest.approx(math.log(raw / (1 - raw)), abs=1e-4), "SHAP values sum to the base model's log-odds"


@pytest.mark.req("RISK-03")
def test_what_changed_names_the_feature_that_moved():
    a, b = M.features_of(ctx()), M.features_of(ctx(default_credentials=True))
    ch = I.what_changed(a, b)
    assert ch and ch[0]["feature"] == "default_credentials" and ch[0]["delta_logodds"] > 0 and ch[0]["sentence"]


@pytest.mark.req("RISK-04")
def test_band_hysteresis_needs_a_margin_to_flip():
    hi = 50.0  # medium/high boundary
    assert M.band_with_hysteresis(hi + 0.5, "medium") == "medium"
    assert M.band_with_hysteresis(hi + M.BAND_HYSTERESIS + 0.01, "medium") == "high"
    assert M.band_with_hysteresis(hi - 0.5, "high") == "high"
    assert M.band_with_hysteresis(hi - M.BAND_HYSTERESIS - 0.01, "high") == "medium"
    assert M.band_with_hysteresis(10, None) == "low"


@pytest.mark.req("RISK-01")
def test_model_version_is_stable_and_excludes_metrics():
    meta = json.loads((T.ARTIFACTS / "metadata.json").read_text(encoding="utf-8"))
    assert T.model_version(meta["config"], meta["training_data"]["sha256"], meta["seed"]) == meta["model_version"]
    assert "metrics" not in json.dumps({k: v for k, v in meta["config"].items() if k != "choice"})


@pytest.mark.req("RISK-01")
def test_artifact_hash_mismatch_fails_closed(tmp_path):
    for f in ("model.joblib", "metadata.json"):
        shutil.copy(T.ARTIFACTS / f, tmp_path / f)
    I.M1(tmp_path)  # loads fine
    with open(tmp_path / "model.joblib", "ab") as fh:
        fh.write(b"tamper")
    with pytest.raises(I.ModelArtifactError):
        I.M1(tmp_path)
    (tmp_path / "model.joblib").unlink()
    with pytest.raises(I.ModelArtifactError):
        I.M1(tmp_path)


# ------------------------------------------------------------------ data hygiene
@pytest.mark.req("RISK-01")
def test_no_feature_uses_information_after_the_window_start():
    for g in ("a", "b"):
        df = pd.read_csv(ROOT / "data" / "ml" / f"gen_{g}.csv")
        src = pd.to_datetime(df["max_source_date"])
        assert not (src.notna() & (src > pd.to_datetime(df["window_start"]))).any()


@pytest.mark.req("RISK-01")
def test_no_asset_in_both_train_and_test_and_time_split_is_ordered():
    s = T.split(T.load("a"))
    sets = {k: set(s[k]["asset_id"]) for k in ("train", "valid", "calib", "test")}
    keys = list(sets)
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            assert not sets[keys[i]] & sets[keys[j]], (keys[i], keys[j])
    assert s["time_train"]["window"].max() < s["time_test"]["window"].min()


@pytest.mark.req("RISK-01")
def test_training_code_never_imports_the_label_process():
    for p in (ROOT / "backend" / "risk").glob("*.py"):
        assert "label_process" not in p.read_text(encoding="utf-8"), p.name


@pytest.mark.req("RISK-01")
def test_hidden_factors_never_appear_in_feature_files():
    header = (ROOT / "data" / "ml" / "gen_a.csv").read_text(encoding="utf-8").splitlines()[0]
    for name in ("insider", "phishing", "vendor_remote", "supplier", "targeted", "campaign"):
        assert name not in header
    assert json.loads((ROOT / "data" / "ml" / "MANIFEST.json").read_text(encoding="utf-8"))["generators"]["A"]["leakage_audit"]["passed"]


@pytest.mark.req("RISK-02")
def test_monotone_features_never_lower_likelihood():
    from backend.risk.features import MONOTONE_INCREASING, SCHEMA

    m = I.M1.get()
    rec, _ = clip(M.features_of(ctx(vulns=[{"cve": "C", "cvss": 6.0, "epss": 0.3, "exploited": False}])))
    for f in MONOTONE_INCREASING:
        vals = np.linspace(SCHEMA[f][1], SCHEMA[f][2], 6)
        ps = [m.likelihood_bp({**rec, f: float(v)}) for v in vals]
        assert all(b >= a for a, b in zip(ps, ps[1:])), (f, ps)
