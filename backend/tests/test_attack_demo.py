"""Firmware attack demo: every stage runs on the live system and leaves real evidence."""

import time

import pytest

from backend.attack_demo import ATTACK_FEATURES, IMPLANT_SHA, TARGET, TARGET_ORG, FirmwareAttackDemo
from backend.twin.service import TwinService


@pytest.mark.req("DEMO-FW-01")
def test_firmware_attack_end_to_end(system):
    d = FirmwareAttackDemo(system, lambda: TwinService(system))
    original = system.nodes[TARGET_ORG].inventory[TARGET]["observed_firmware_sha256"]
    assert d.launch(pace=0)["started"]
    for _ in range(600):
        if d.snapshot()["status"] != "running":
            break
        time.sleep(0.5)
    st = d.snapshot()
    assert st["status"] == "done", st.get("error")
    stages = {s["id"]: s for s in st["stages"]}
    assert all(s["status"] == "done" for s in stages.values())

    assert stages["implant"]["data"]["observed_sha"] == IMPLANT_SHA != stages["implant"]["data"]["published_sha"]
    assert stages["detect"]["data"]["registry_result"] == "Mismatch"  # the contract's own verdict

    p = stages["predict"]["data"]
    assert p["implant_only"]["likelihood_after"] > p["implant_only"]["likelihood_before"]
    # the only model INPUTS that differ are the ones the implant changes, so every change in the score is the implant's;
    # tree SHAP may still shift other features' attributions through interactions with those inputs
    changed_inputs = {r["feature"] for r in p["shap"] if r["value_before"] != r["value_after"]}
    assert changed_inputs and changed_inputs <= set(ATTACK_FEATURES)
    assert {"supply_chain_flag", "firmware_known"} <= {r["feature"] for r in p["shap"]}

    ag = stages["agents"]["data"]
    assert ag["cascade"] and ag["plan"]["steps"] and ag["critic"]["verdict"] == "APPROVE_FOR_GATE" and ag["request_id"]
    assert stages["approve"]["data"]["status"] in ("Approved", "Executed")
    ex = stages["contain"]["data"]["execution"]
    assert ex["drift"] <= 1e-6, "the realised risk reduction equals the prediction"

    rec = stages["record"]["data"]
    assert {"AttestationRegistry", "AlertBus", "ApprovalGate", "AuditLog"} <= set(rec["by_contract"])
    assert all(e["block"] > st["start_block"] for e in rec["events"])
    assert rec["twin"]["root_before"] != rec["twin"]["root_after"]
    assert any(dr["kind"] == "firmware" and "Mismatch" in dr["detail"] for dr in rec["twin"]["drift"]), "the twin flags the implant"

    d.reset()
    assert system.nodes[TARGET_ORG].inventory[TARGET]["observed_firmware_sha256"] == original
    assert system.nodes[TARGET_ORG].supply_chain_check()[TARGET] == "Match"
