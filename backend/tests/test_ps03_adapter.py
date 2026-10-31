"""PS-03 WP1 on M1: model swap via RISK_MODEL_DIR, fail-closed loading, integer outputs, PS-03 score extensions."""

import json
import shutil
from copy import deepcopy

import pytest

from backend.risk import adapter as A
from backend.risk import explain as E
from backend.risk import model as M
from backend.risk.features import FEATURES
from backend.risk.inference import ARTIFACTS, M1, ModelArtifactError

VULN = {"cve": "CVE-2023-1", "cvss": 8.8, "epss": 0.9, "exploited": True, "published": "2025-06-01"}


def ctx(**kw):
    base = dict(asset_id="x", org="power", internet_exposed=True, zone="DMZ", last_patched="2025-09-01", criticality=5, num_dependents=6, service_crit="high")
    base.update(kw)
    return M.AssetCtx(**base)


@pytest.fixture()
def reset_model(monkeypatch):
    saved = M1._instance
    M1._instance = None
    yield monkeypatch
    M1._instance = saved


def copy_artifact(dst, tamper=False):
    dst.mkdir(parents=True, exist_ok=True)
    for f in ("model.joblib", "metadata.json"):
        shutil.copy(ARTIFACTS / f, dst / f)
    if tamper:
        meta = json.loads((dst / "metadata.json").read_text(encoding="utf-8"))
        meta["artifact_sha256"] = "0" * 64
        (dst / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    return dst


@pytest.mark.req("PS03-WP1-01")
def test_default_is_committed_m1(reset_model):
    reset_model.delenv("RISK_MODEL_DIR", raising=False)
    m = A.load_configured()
    assert A.model_source(m) == "v1" and m.version == json.loads((ARTIFACTS / "metadata.json").read_text(encoding="utf-8"))["model_version"]


@pytest.mark.req("PS03-WP1-01")
def test_v2_extends_score_asset_without_changing_it(reset_model):
    reset_model.delenv("RISK_MODEL_DIR", raising=False)
    a = ctx(vulns=[VULN])
    old, new = M.score_asset(a), E.score_asset_v2(a)
    for k in old:
        assert new[k] == old[k], k
    assert new["factors_shap"]["unit"] == "log_odds" and set(new["features"]) == set(FEATURES)
    sv = new["factors_shap"]  # SHAP additivity: base value + contributions = the base model's log-odds
    import numpy as np
    import pandas as pd

    m = M1.get()
    p = float(m.base.predict_proba(pd.DataFrame([[new["features"][f] for f in FEATURES]], columns=FEATURES))[0, 1])
    assert sv["base_value"] + sum(sv["all"].values()) == pytest.approx(float(np.log(p / (1 - p))), abs=1e-3)


@pytest.mark.req("PS03-WP1-02")
def test_integer_outputs_repeatable(reset_model):
    reset_model.delenv("RISK_MODEL_DIR", raising=False)
    a = ctx(vulns=[VULN], default_credentials=True)
    r1 = E.score_asset_v2(a)
    M1._instance = None
    r2 = E.score_asset_v2(deepcopy(a))
    for k in ("likelihood_bp", "impact_bp", "risk_bp"):
        assert isinstance(r1[k], int) and 0 <= r1[k] <= 10000 and r1[k] == r2[k]
    assert r1["risk_bp"] == E.risk_bp_of(r1["likelihood_bp"], r1["impact_bp"]) and r1["risk"] == r1["risk_bp"] / 100


@pytest.mark.req("PS03-WP1-02")
@pytest.mark.parametrize("l_bp,i_bp,expected", [(10000, 10000, 10000), (0, 10000, 0), (10000, 0, 3000), (5000, 5000, 3250), (7997, 7125, 6388)])
def test_risk_bp_integer_formula(l_bp, i_bp, expected):
    assert E.risk_bp_of(l_bp, i_bp) == expected


@pytest.mark.req("PS03-WP1-03")
def test_risk_model_dir_swaps_the_model(reset_model, tmp_path):
    d = copy_artifact(tmp_path / "v2")
    reset_model.setenv("RISK_MODEL_DIR", str(d))
    m = A.load_configured()
    assert A.model_source(m) == "v2" and A.info()["source"] == "v2"
    assert E.score_asset_v2(ctx(vulns=[VULN]))["model_source"] == "v2"


@pytest.mark.req("PS03-WP1-04")
def test_hash_mismatch_fails_closed(reset_model, tmp_path):
    d = copy_artifact(tmp_path / "bad", tamper=True)
    reset_model.setenv("RISK_MODEL_DIR", str(d))
    with pytest.raises(ModelArtifactError, match="hash mismatch"):
        A.load_configured()
    assert M1._instance is None, "must not fall back to the committed model"
    assert A.info()["loaded"] is False and "hash mismatch" in A.info()["error"]


@pytest.mark.req("PS03-WP1-04")
def test_missing_folder_fails_closed(reset_model, tmp_path):
    reset_model.setenv("RISK_MODEL_DIR", str(tmp_path / "nothing"))
    with pytest.raises(ModelArtifactError, match="missing"):
        A.load_configured()


@pytest.mark.req("PS03-WP1-05")
def test_no_vulnerability_and_missing_epss_are_flags_not_defaults():
    none = M.features_of(ctx())
    assert none["has_vulnerability"] == 0 and none["max_cvss"] == 0 and none["max_epss"] == 0
    gap = M.features_of(ctx(vulns=[{"cve": "C", "cvss": 7.0, "epss": None, "exploited": False}]))
    assert gap["has_vulnerability"] == 1 and gap["missing_epss"] == 1 and gap["max_epss"] == 0
