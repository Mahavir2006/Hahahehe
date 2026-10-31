"""PS-03 WP1: model adapter, integer outputs, fail-closed loading (fixture model trained here, never committed)."""

import hashlib
import json
from copy import deepcopy

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import GradientBoostingClassifier

from backend.risk import adapter as A
from backend.risk import explain as E
from backend.risk import model as M

VULN = {"cve": "CVE-2023-1", "cvss": 8.8, "epss": 0.9, "exploited": True}
V2_FEATURES = M.FEATURES + ["has_vulnerability", "max_epss", "open_mgmt_ports", "rule_hit_count"]


def ctx(**kw):
    base = dict(asset_id="x", org="power", internet_exposed=True, zone="DMZ", last_patched="2025-09-01", criticality=5, num_dependents=6, service_crit="high")
    base.update(kw)
    return M.AssetCtx(**base)


@pytest.fixture()
def reset_model(monkeypatch):
    saved = M.RiskModel._instance
    M.RiskModel._instance = None
    yield monkeypatch
    M.RiskModel._instance = saved


def make_fixture(dirpath, features=V2_FEATURES, tamper=False):
    rng = np.random.default_rng(0)
    X = pd.DataFrame(rng.random((400, len(features))), columns=features)
    y = (X.iloc[:, 0] + X.iloc[:, -1] + rng.normal(0, 0.3, 400) > 1.0).astype(int)
    GradientBoostingClassifier(n_estimators=20, max_depth=2, random_state=0).fit(X, y)
    m = GradientBoostingClassifier(n_estimators=20, max_depth=2, random_state=0).fit(X, y)
    dirpath.mkdir(parents=True, exist_ok=True)
    joblib.dump(m, dirpath / "model.joblib")
    sha = hashlib.sha256((dirpath / "model.joblib").read_bytes()).hexdigest()
    meta = {"model_version": "fixture-v2-0001", "features": features, "sha256_model": ("0" * 64 if tamper else sha),
            "target": "compromised", "row_definition": "asset-window (fixture)", "model_family": "gb", "calibration": "none"}
    (dirpath / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    return dirpath


@pytest.mark.req("PS03-WP1-01")
def test_v1_unchanged_with_flags_off(reset_model):
    reset_model.delenv("RISK_MODEL_DIR", raising=False)
    m = M.RiskModel.get()
    assert m.features == M.FEATURES and A.model_source(m) == "v1"
    a = ctx(vulns=[VULN])
    old, new = M.score_asset(a), E.score_asset_v2(a)
    for k in old:
        assert new[k] == old[k], k
    assert new["top_factors_unit"] == "share_of_risk_not_shap" and new["factors_shap"]["unit"] == "log_odds"


@pytest.mark.req("PS03-WP1-02")
def test_integer_outputs_are_integers_and_repeatable(reset_model):
    reset_model.delenv("RISK_MODEL_DIR", raising=False)
    a = ctx(vulns=[VULN], default_credentials=True)
    r1 = E.score_asset_v2(a)
    M.RiskModel._instance = None
    r2 = E.score_asset_v2(deepcopy(a))
    for k in ("likelihood_bp", "impact_bp", "risk_bp"):
        assert isinstance(r1[k], int) and 0 <= r1[k] <= 10000 and r1[k] == r2[k]
    assert r1["risk_bp"] == E.risk_bp_of(r1["likelihood_bp"], r1["impact_bp"])
    assert abs(r1["risk_bp"] / 100 - r1["risk"]) < 0.02


@pytest.mark.req("PS03-WP1-02")
@pytest.mark.parametrize("l_bp,i_bp,expected", [(10000, 10000, 10000), (0, 10000, 0), (10000, 0, 3000), (5000, 5000, 3250), (1, 1, 0), (7997, 7125, 6388)])
def test_risk_bp_integer_formula(l_bp, i_bp, expected):
    assert E.risk_bp_of(l_bp, i_bp) == expected


@pytest.mark.req("PS03-WP1-03")
def test_fixture_v2_with_different_features_loads_and_scores(reset_model, tmp_path):
    d = make_fixture(tmp_path / "v2")
    reset_model.setenv("RISK_MODEL_DIR", str(d))
    m = M.RiskModel.get()
    assert m.features == V2_FEATURES and A.model_source(m) == "v2" and m.version == "fixture-v2-0001"
    a = ctx(vulns=[VULN])
    A.attach_live_features(a, {"open_ports": [22, 502, 8080], "firmware_state": "attested"})
    s = E.score_asset_v2(a)
    assert s["model_source"] == "v2" and set(s["features"]) == set(V2_FEATURES) and isinstance(s["risk_bp"], int)
    assert s["features"]["open_mgmt_ports"] == 3.0 and s["features"]["has_vulnerability"] == 1.0
    assert s["factors_shap"]["unit"] == "log_odds"


@pytest.mark.req("PS03-WP1-04")
def test_hash_mismatch_fails_closed(reset_model, tmp_path):
    d = make_fixture(tmp_path / "bad", tamper=True)
    reset_model.setenv("RISK_MODEL_DIR", str(d))
    with pytest.raises(A.ModelArtifactError, match="sha256"):
        M.RiskModel.get()
    assert M.RiskModel._instance is None, "must not fall back to v1"
    assert "sha256" in A.info()["error"]


@pytest.mark.req("PS03-WP1-04")
def test_unknown_feature_fails_closed(reset_model, tmp_path):
    d = make_fixture(tmp_path / "unk", features=M.FEATURES + ["mystery_signal"])
    reset_model.setenv("RISK_MODEL_DIR", str(d))
    with pytest.raises(A.ModelArtifactError, match="mystery_signal"):
        M.RiskModel.get()


@pytest.mark.req("PS03-WP1-04")
def test_missing_files_fail_closed(reset_model, tmp_path):
    reset_model.setenv("RISK_MODEL_DIR", str(tmp_path / "nothing"))
    with pytest.raises(A.ModelArtifactError, match="missing"):
        M.RiskModel.get()


@pytest.mark.req("PS03-WP1-05")
def test_live_features_follow_what_if_patch():
    a = ctx(vulns=[VULN, {"cve": "CVE-2", "cvss": None, "epss": 0.1, "exploited": False, "epss_missing": True}])
    A.attach_live_features(a, {"open_ports": [22]})
    assert a.extra["has_vulnerability"] == 1.0 and a.extra["cve_count"] == 2.0 and a.extra["max_cvss"] == 8.8 and a.extra["missing_epss"] == 1.0
    b = deepcopy(a)
    M.apply_action(b, "PATCH")
    assert b.extra["has_vulnerability"] == 0.0 and b.extra["max_cvss"] == 0.0 and b.extra["open_mgmt_ports"] == 1.0
    assert a.extra["has_vulnerability"] == 1.0, "the original asset is untouched"


@pytest.mark.req("PS03-WP1-05")
def test_what_if_copy_sees_refreshed_extras():
    a = ctx(vulns=[VULN])  # v1 features_of needs a numeric CVSS; seeded real CVEs always carry one
    A.attach_live_features(a, {"open_ports": [22]})
    w = M.what_if([a], [{"action": "PATCH", "targets": ["x"]}])
    assert w["risk_after"] < w["risk_before"] and a.extra["has_vulnerability"] == 1.0


@pytest.mark.req("PS03-WP1-05")
def test_extras_survive_state_persistence():
    import dataclasses
    import json as _json

    a = ctx(vulns=[VULN])
    A.attach_live_features(a, {"open_ports": [22]})
    d = _json.loads(_json.dumps(dataclasses.asdict(a), default=str))
    b = M.AssetCtx(**d)
    assert b.extra == a.extra and isinstance(b.extra, dict)
    assert M.score_asset(b, explain=False)["risk"] == M.score_asset(a, explain=False)["risk"]


@pytest.mark.req("PS03-WP1-05")
def test_out_of_range_inputs_are_clipped_and_reported():
    a = ctx(vulns=[VULN], criticality=9)
    s = E.score_asset_v2(a)
    assert {"feature": "criticality", "issue": "out_of_range", "value": 9.0, "range": [1, 5]} in s["missing"]
    assert s["features"]["criticality"] == 5
