"""
Digital twin: every claim the UI makes about the twin is checked here against a live local chain.

* built only from contract events (an independent raw replay reproduces it exactly)
* assembles itself block by block, and time travel reproduces any earlier state
* every organisation's independent replay agrees, and the contracts' own views agree with the twin
* editing the local event copy is detected, and says which part of the twin was changed
* what-ifs are real transactions on a snapshot, and the real chain is untouched afterwards
* the shared layer reveals nothing private; each organisation's overlay is opened from its own sealed data
"""

import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from backend.api.main import create_app
from backend.common.chain import ROOT
from backend.tests.conftest import adv
from backend.twin import model as M
from backend.twin.service import ORG_IDS, TwinService
from backend.twin.source import chain_events, indexer_events


@pytest.fixture(scope="module")
def twin(system):
    if not any(n.plans for n in system.nodes.values()):
        system.ingest(adv(1))  # run the headline advisory so approvals, alerts and anchors exist on the chain
    return TwinService(system)


def raw(system, upto=None):
    return chain_events(system.chain.rpc_url, system.chain.contracts, upto_block=upto)


@pytest.mark.req("TWIN-01")
def test_twin_is_built_only_from_chain_events(system, twin):
    live = twin.live()
    st = live["state"]
    # an independent decode of the raw chain gives the same twin, byte for byte
    assert M.fingerprint(M.build(raw(system, st["block"])))["root"] == live["fp"]["root"]
    # and it matches what was actually written: the three members, every declared bilateral edge, the firmware catalogue
    assert set(st["orgs"]) == set(ORG_IDS.values())
    declared = json.loads((ROOT / "data" / "cross_org_dependencies.json").read_text(encoding="utf-8"))
    assert sum(e["status"] == "confirmed" for e in st["edges"].values()) == len(declared)
    assert len(st["firmware"]) == len(json.loads((ROOT / "data" / "firmware_catalog.json").read_text(encoding="utf-8")))
    assert any(e["status"] == "pending" for e in st["edges"].values()), "the one-sided edge from bootstrap is listed, not confirmed"


@pytest.mark.req("TWIN-02")
def test_twin_assembles_itself_and_time_travel_is_exact(system, twin):
    evs = twin.live()["events"]
    tl = M.timeline(evs, max_points=10_000)
    # it starts with no organisations (only contract role grants) and gains them one registration at a time
    assert tl[0]["counts"]["orgs"] == 0 and tl[-1]["counts"]["orgs"] == 3
    org_steps = [p["counts"]["orgs"] for p in tl]
    assert sorted(set(org_steps)) == [0, 1, 2, 3] and org_steps == sorted(org_steps)
    assert [p["events"] for p in tl] == sorted(p["events"] for p in tl)
    assert tl[-1]["root"] == M.fingerprint(M.build(evs))["root"]
    for p in tl[:: max(1, len(tl) // 12)]:
        # rebuilding from scratch at that block, from the raw chain, lands on the timeline's fingerprint
        assert M.fingerprint(M.build(raw(system, p["block"])))["root"] == p["root"]
        assert twin.at(p["block"])["fp"]["root"] == p["root"]


@pytest.mark.req("TWIN-03")
def test_every_org_replay_agrees_and_contracts_agree(twin):
    v = twin.verify()
    assert [n["org"] for n in v["nodes"]] == ["power", "water", "hospital"]
    assert all(n["agrees"] and n["root"] == v["twin_root"] for n in v["nodes"])
    for name, c in v["contract_checks"].items():
        assert c["total"] > 0 and c["ok"] == c["total"], f"contract view disagrees with the twin on {name}: {c}"
    assert v["all_agree"] is True


@pytest.mark.req("TWIN-04")
def test_editing_the_local_event_copy_is_detected(system, twin):
    db = sqlite3.connect(system.indexer.db_path)
    rowid, name = db.execute("SELECT rowid, name FROM events WHERE name='DependencyEdgeConfirmed' ORDER BY block LIMIT 1").fetchone()
    try:
        db.execute("UPDATE events SET name='DependencyEdgeRevoked' WHERE rowid=?", (rowid,))
        db.commit()
        twin._cache = None
        v = twin.verify()
        assert v["all_agree"] is False
        assert all(not n["agrees"] and n["differs_in"] == ["edges"] for n in v["nodes"]), "the chain replays disagree and name the edited section"
    finally:
        db.execute("UPDATE events SET name=? WHERE rowid=?", (name, rowid))
        db.commit()
        db.close()
        twin._cache = None
    assert twin.verify()["all_agree"] is True


@pytest.mark.req("TWIN-05")
@pytest.mark.parametrize("kind", ["segment_edge", "revoke_firmware", "deactivate_org"])
def test_what_if_is_a_real_transaction_and_the_chain_is_rolled_back(system, twin, kind):
    sc = twin.scenarios()[kind]
    assert sc, f"no {kind} scenario available"
    head = system.chain.block_number()
    root = M.fingerprint(M.build(raw(system)))["root"]
    r = twin.fork(kind, sc[0]["target"])
    assert r["transaction"]["tx_hash"] and r["transaction"]["block"] > head, "a real transaction was mined on the fork"
    assert r["forked"]["root"] != root and r["forked"]["changes"]
    kinds = {d["kind"] for d in r["forked"]["drift"]}
    if kind == "segment_edge":
        ch = next(c for c in r["forked"]["changes"] if c["section"] == "edges")
        assert ch["fields"]["status"] == ["confirmed", "revoked"]
        # links are offered most-impactful first, and the predicted cut is what the forked chain really shows
        assert sc[0]["cuts"] == max(x["cuts"] for x in sc)
        cut = sum(r["forked"]["reach_services_before"].values()) - sum(r["forked"]["reach_services_after"].values())
        assert cut == sc[0]["cuts"]
    elif kind == "revoke_firmware":
        assert any(c["section"] == "firmware" and c["fields"]["revoked"] == [False, True] for c in r["forked"]["changes"])
        assert r["forked"]["new_drift"] and all(d["kind"] == "firmware" and "Revoked" in d["detail"] for d in r["forked"]["new_drift"])
    else:
        assert any(c["section"] == "orgs" and c["fields"]["active"] == [True, False] for c in r["forked"]["changes"])
        assert "inactive_party" in kinds
    rb = r["rolled_back"]
    assert rb["untouched"] and rb["head_after"] == head and rb["root_after"] == root
    assert system.chain.block_number() == head and M.fingerprint(M.build(raw(system)))["root"] == root
    assert system.indexer.last_block() <= head, "the forked blocks were never indexed"


@pytest.mark.req("TWIN-06", "SEC-PRIV-01")
def test_shared_layer_is_private_and_overlays_open_own_sealed_data(system, twin):
    live = twin.live()
    public = json.dumps(twin.public(live)).lower()
    for n in system.nodes.values():
        for s in n.services.values():
            assert s["name"].lower() not in public and s["service_id"].lower() not in public
    assert '"band"' not in public and "sealed" not in public
    ov = twin.overlay("power", live)
    assert {s["service_id"] for s in ov["services"]} == set(system.nodes["power"].services)
    assert any(s["attested_band"] for s in ov["services"]), "power opens its own sealed bands and checks them against the commitments"
    confirmed = [e for e in ov["edges"] if e["status"] == "confirmed"]
    assert confirmed and all(e["terms_verified"] for e in confirmed)
    other = {s["service_id"] for s in system.nodes["water"].services.values()}
    assert not other & {s["service_id"] for s in ov["services"]}


@pytest.mark.req("TWIN-07")
def test_firmware_drift_matches_the_contract_exactly(system, twin):
    drift = {(d["org"], d["subject"]) for d in twin.drift(twin.live()) if d["kind"] == "firmware"}
    flagged = {(o, aid) for o, n in system.nodes.items() for aid, st in n.supply_chain_check().items() if st != "Match"}
    assert flagged and drift == flagged


@pytest.mark.req("TWIN-08", "API-01")
def test_twin_api(system):
    api = TestClient(create_app(system))
    pub = api.get("/api/twin", headers={"X-Dev-Role": "org:water"}).json()
    assert pub["overlay"]["org"] == "water" and pub["fingerprint"]["root"].startswith("0x") and pub["block"] == pub["head"]
    assert "overlay" not in api.get("/api/twin", headers={"X-Dev-Role": "admin"}).json()
    early = api.get(f"/api/twin?block={pub['block'] // 2}").json()
    assert early["block"] == pub["block"] // 2 and early["events"] < pub["events"]
    assert api.get(f"/api/twin?block={pub['head'] + 1000}").status_code == 400
    assert api.get("/api/twin/timeline?points=20").json()[-1]["root"] == pub["fingerprint"]["root"]
    assert api.get("/api/twin/overlay/power", headers={"X-Dev-Role": "org:water"}).status_code == 403
    assert all(d["org"] in ("water", "Water", None) or d["org"] == "water" for d in api.get("/api/twin/drift", headers={"X-Dev-Role": "org:water"}).json())
    assert api.get("/api/twin/scenarios", headers={"X-Dev-Role": "org:power"}).status_code == 403
    assert api.post("/api/twin/fork", json={"kind": "nope", "target": "x"}).status_code == 400
    assert api.get("/api/twin/verify").json()["all_agree"] is True
