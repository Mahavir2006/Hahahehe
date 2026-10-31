import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from eth_account import Account

ROOT = Path(__file__).resolve().parents[2]
D = ROOT / "data"
ORGS = ["power", "water", "hospital"]


def inv(o):
    return json.loads((D / "orgs" / o / "inventory.json").read_text(encoding="utf-8"))


@pytest.mark.req("DATA-ORG-01")
def test_three_orgs_with_consistent_dev_keys():
    for o in ORGS:
        k = json.loads((D / "orgs" / o / "private_keys.dev.json").read_text(encoding="utf-8"))
        assert len(k["approvers"]) == 3
        for part in [k["admin"], k["agent_signer"], *k["approvers"]]:
            assert Account.from_key(part["private_key"]).address == part["address"], "address must be derived from the key"


@pytest.mark.req("DATA-ORG-02", "DATA-GRAPH-01")
def test_asset_counts_and_graph_shape():
    for o in ORGS:
        assets = inv(o)
        assert 20 <= len(assets) <= 30
        ids = {a["asset_id"] for a in assets}
        for a in assets:
            assert set(a["depends_on"]) <= ids and a["asset_id"] not in a["depends_on"]
            for f in ("zone", "criticality", "safety_critical", "maintenance_window", "patch_requires_downtime", "vendor_signoff_required", "sbom_hash"):
                assert f in a


@pytest.mark.req("DATA-GRAPH-02")
def test_services_have_criticality_and_required_assets():
    for o in ORGS:
        s = json.loads((D / "orgs" / o / "services.json").read_text(encoding="utf-8"))
        assert len(s) >= 3
        ids = {a["asset_id"] for a in inv(o)}
        for x in s:
            assert x["criticality"] in ("low", "medium", "high", "life_critical")
            assert set(x["required_assets"]) <= ids


@pytest.mark.req("DATA-XORG-01", "DATA-XORG-02")
def test_cross_org_chain_present():
    x = json.loads((D / "cross_org_dependencies.json").read_text(encoding="utf-8"))
    assert len(x) >= 6
    pairs = {(e["provider_org"], e["consumer_org"]) for e in x}
    assert ("power", "water") in pairs and ("water", "hospital") in pairs and ("power", "hospital") in pairs
    for e in x:
        assert e["dependency_strength"] in ("low", "medium", "high") and e["tolerance_minutes"] > 0


@pytest.mark.req("DATA-ADV-01", "DATA-ADV-02")
def test_advisories_cover_match_nomatch_injection_and_headline():
    gts = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((D / "advisories").glob("*.ground_truth.json"))]
    assert len(gts) >= 12
    assert sum(1 for g in gts if g["matched_assets"]) >= 6
    assert sum(1 for g in gts if not g["matched_assets"] and not g["injection"]) >= 2
    assert sum(1 for g in gts if g["injection"]) >= 2
    svc1 = json.loads((D / "orgs" / "power" / "services.json").read_text(encoding="utf-8"))[0]
    headline_assets = {a for g in gts for a in g["matched_assets"] if a.startswith("power")}
    assert headline_assets & set(svc1["required_assets"]), "an advisory must hit the cross-org chain head service"


@pytest.mark.req("DATA-FW-01")
def test_firmware_states_per_org():
    cat = {(e["vendor"], e["model"], e["version"]): e for e in json.loads((D / "firmware_catalog.json").read_text(encoding="utf-8"))}
    for o in ORGS:
        tam = unk = 0
        for a in inv(o):
            e = cat.get((a["vendor"], a["model"], a["firmware_version"]))
            if e is None:
                unk += 1
            elif e["firmware_sha256"] != a["observed_firmware_sha256"]:
                tam += 1
        assert tam >= 2 and unk >= 1, (o, tam, unk)


@pytest.mark.req("DATA-HIST-01")
def test_history_rows():
    rows = (D / "historical_incidents.csv").read_text(encoding="utf-8").strip().splitlines()
    assert len(rows) - 1 >= 5000


@pytest.mark.req("DATA-ORG-01", "DATA-HIST-01")
def test_generator_is_deterministic(tmp_path):
    def run(out):
        subprocess.run([sys.executable, str(D / "generate_dataset.py"), "--output-dir", str(out)], check=True, capture_output=True, cwd=ROOT)
        h = hashlib.sha256()
        for p in sorted(out.rglob("*")):
            if p.is_file() and p.suffix in (".json", ".csv", ".txt"):
                h.update(p.relative_to(out).as_posix().encode() + p.read_bytes())
        return h.hexdigest()

    assert run(tmp_path / "a") == run(tmp_path / "b")
