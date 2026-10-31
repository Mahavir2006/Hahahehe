"""
End-to-end lifecycle on a real local chain. Tests are ordered: each one builds on the state left by the previous one.
"""
import asyncio
import json
import time

import pytest
from eth_utils import keccak

from backend.agents import advisory_parser as P
from backend.agents.framework import GateViolation, IsolationError, ToolNotAllowed, Trace
from backend.agents.org_node import OrgNodeRuntime
from backend.agents.orchestrator import Orchestrator
from backend.common import sealed
from backend.common.audit import entry_hash
from backend.common.chain import ChainPaused, ChainRevert, ORGS, org_id
from pathlib import Path

from backend.tests.conftest import adv

ROOT = Path(__file__).resolve().parents[2]

S = {}  # shared between the ordered tests below


def events(system, contract, name):
    system.indexer.sync()
    return system.indexer.query(contract, name, limit=100000)


# ------------------------------------------------------------------- bootstrap
@pytest.mark.req("BC-ATT-D-01", "BC-ATT-D-02", "AG-CAS-04", "AG-RSK-06")
def test_01_bootstrap_bilateral_edges_and_baseline_attestations(system):
    boot = system.boot
    assert len(boot["edges"]) >= 6 and all(e["consumer"] in ("confirmed", "duplicate") and e["provider"] in ("confirmed", "duplicate") for e in boot["edges"])
    n = system.nodes
    # every declared edge is confirmed on-chain, using hashes only (no names ever on-chain)
    deps = json.loads((ROOT / "data" / "cross_org_dependencies.json").read_text(encoding="utf-8"))
    for d in deps:
        c, p = n[d["consumer_org"]], n[d["provider_org"]]
        assert system.chain.call("AttestationRegistry", "isEdgeConfirmed", org_id(d["consumer_org"]), c.svc_hash(d["consumer_service"]), org_id(d["provider_org"]), p.svc_hash(d["provider_service"]))
    # the edge only ONE side attested stays unconfirmed
    h, pw = n["hospital"], n["power"]
    svc = next(iter(h.services))
    assert not system.chain.call("AttestationRegistry", "isEdgeConfirmed", org_id("hospital"), h.svc_hash(svc), org_id("power"), pw.svc_hash(next(iter(pw.services))))
    # baseline service-risk attestations exist for all 9 services
    for org, node in n.items():
        for sid in node.services:
            assert system.chain.call("AttestationRegistry", "isRiskAttestationValid", org_id(org), node.svc_hash(sid))


@pytest.mark.req("BC-ATT-D-02")
def test_02_handshake_verifies_hashes_and_rejects_forgery(system):
    w, p = system.nodes["water"], system.nodes["power"]
    offer = p.handshake_offer("power-service-1")
    assert w.handshake_accept(offer) == p.svc_hash("power-service-1")
    bad = dict(offer, salt="0x" + "11" * 32)
    with pytest.raises(ValueError):
        w.handshake_accept(bad)
    # a service hash alone reveals nothing about the name: different salt -> different hash
    assert p.svc_hash("power-service-1") != p.svc_hash("power-service-2")
    assert b"Substation" not in bytes(p.svc_hash("power-service-1"))


@pytest.mark.req("BC-FW-05", "BC-FW-06", "BC-FW-03")
def test_03_supply_chain_detects_tampered_and_unknown_firmware(system):
    for org, node in system.nodes.items():
        res = system.boot["supply_chain"][org]
        assert sorted(k for k, v in res.items() if v == "Mismatch") == [f"{org}-asset-005", f"{org}-asset-011"]
        assert [k for k, v in res.items() if v == "Unknown"] == [f"{org}-asset-017"]
        assert sum(1 for v in res.values() if v == "Match") == 22
        assert node.assets[f"{org}-asset-005"].supply_chain_flag and not node.assets[f"{org}-asset-001"].supply_chain_flag


@pytest.mark.req("BC-FW-05")
def test_04_supply_chain_flag_raises_asset_risk(system):
    from backend.risk import model as risk

    a = system.nodes["power"].assets["power-asset-005"]
    flagged = risk.score_asset(a, explain=False)["risk"]
    a.supply_chain_flag = False
    clean = risk.score_asset(a, explain=False)["risk"]
    a.supply_chain_flag = True
    assert flagged > clean


# ------------------------------------------------------------------- headline
@pytest.mark.req("AG-TOP-02", "AG-INT-06", "AG-INT-08", "AG-ORC-01")
def test_05_headline_advisory_runs_the_whole_pipeline(system):
    text = adv(1)
    S["text"] = text
    S["finding_events_before"] = len(events(system, "AttestationRegistry", "FindingAttestationSubmitted"))
    res = system.ingest(text)
    S["res"] = res
    assert res["power"]["status"] == "awaiting_approval" and res["power"].get("request_id")
    assert res["water"]["status"] == "no_match" and res["hospital"]["status"] == "no_match"
    # AG-INT-08 / SEC-PRIV-02: every org attests it processed the advisory; neither the outcome nor the
    # advisory itself is readable on-chain, but each org can open its own commitment to an auditor
    after = events(system, "AttestationRegistry", "FindingAttestationSubmitted")
    assert len(after) == S["finding_events_before"] + 3
    assert all("matched" not in e["args"] and "advisoryContentHash" not in e["args"] for e in after)
    h = P.content_hash(text)
    ch = bytes.fromhex(h)
    for org in ORGS:
        node = system.nodes[org]
        none = system.chain.call("AttestationRegistry", "getFindingAttestation", org_id(org), ch)
        assert none[-1] == 0, "the public advisory hash must not find the attestation"
        f = system.chain.call("AttestationRegistry", "getFindingAttestation", org_id(org), node.blind(ch))
        assert f[0] == org_id(org) and f[2] != b"\x00" * 32
        o = node.finding_openings[h]
        assert system.chain.call("AttestationRegistry", "verifyFindingDisclosure", org_id(org), bytes.fromhex(o["advisory_key"][2:]),
                                 bytes.fromhex(o["salt"][2:]), ch, bytes.fromhex(o["cve_set_hash"][2:]), org == "power")
    S["rid"] = res["power"]["request_id"]


@pytest.mark.req("AG-CAS-02", "AG-CAS-03", "AG-CAS-05")
def test_06_cascade_reaches_water_then_hospital_and_alerts_on_chain(system):
    cs = S["res"]["power"]["stages"]["cascade"]
    chain = cs["chain"]
    assert [c["org"] for c in chain][:2] == ["water", "hospital"]
    assert chain[0]["time_to_impact_minutes"] <= chain[1]["time_to_impact_minutes"]
    assert all(0 < c["p_degraded"] <= 1 for c in chain)
    assert cs["graph"]["nodes"] and cs["graph"]["edges"], "graph payload for the dashboard"
    assert cs["alerts"] and cs["alerts"][0]["status"] == "confirmed"
    aid = cs["alerts"][0]["alert_id"]
    al = system.chain.call("AlertBus", "getAlert", bytes.fromhex(aid[2:]))
    assert al[0] == org_id("power") and al[7] == 1  # providerOrg, Status.Active
    # SEC-PRIV-03: severity/TTI are sealed to the alert's direct consumers; outsiders cannot open it
    ev = next(e["args"] for e in events(system, "AlertBus", "CascadeAlert") if e["args"]["alertId"] == aid)
    assert "severity" not in ev and "tti" not in ev
    opened = system.nodes["water"].open_disclosure(ev["sealedPayload"])
    assert opened and opened["severity"] == 3 - ["critical", "high", "medium", "low"].index(cs["alerts"][0]["severity"])
    outsider = sealed.private_key_from_secret(b"\x42" * 32)
    assert sealed.open_sealed(sealed.from_hex(ev["sealedPayload"]), outsider) is None
    # relevant to water via a CONFIRMED edge, invisible to a service without one
    wsvc = "water-service-1"
    assert bytes.fromhex(aid[2:]) in system.chain.call("AlertBus", "affectedBy", org_id("water"), system.nodes["water"].svc_hash(wsvc))


@pytest.mark.req("AG-CAS-04")
def test_07_unconfirmed_edge_is_listed_but_never_used(system):
    cs = S["res"]["power"]["stages"]["cascade"]
    assert len(cs["unconfirmed_edges"]) >= 1
    used = {(c["org"], c["service"]) for c in cs["chain"]}
    for e in cs["unconfirmed_edges"]:
        # the hospital node reached through the unconfirmed 0-bucket edge would be at 10 minutes
        assert not any(c["time_to_impact_minutes"] == 10 for c in cs["chain"])
    key = lambda e: (e["consumer_org"], e["consumer_service"], e["provider_org"], e["provider_service"])  # noqa: E731
    unconf = {key(u) for u in cs["unconfirmed_edges"]}
    flagged = [e for e in cs["cross_input"]["edges"] if key(e) in unconf]
    assert flagged and all(e["confirmed"] is False for e in flagged)
    assert all(e["confirmed"] for e in cs["cross_input"]["edges"] if key(e) not in unconf)


@pytest.mark.req("AG-RSK-01", "AG-RSK-02", "AG-RSK-04", "AG-RSK-05")
def test_08_risk_assessment_is_model_numbers_with_validated_narrative(system):
    rk = S["res"]["power"]["stages"]["risk"]
    a = next(x for x in rk["assessments"] if x["asset_id"] == "power-asset-001")
    # M1 is trained on synthetic labels with hidden factors, so a KEV-listed CVE raises this asset to medium/high,
    # not automatically to critical; the advisory's CVE must be among the drivers (docs/ML_REPORT.md)
    assert a["band"] in ("medium", "high", "critical") and a["top_factors"]
    assert any(f["feature"] in ("max_cvss", "max_epss", "any_known_exploited", "has_vulnerability") and f["contribution_logodds"] > 0 for f in a["top_factors"])
    from backend.agents.llm import validate_narrative

    assert validate_narrative(a["narrative"], {k: v for k, v in a.items() if k != "narrative"})
    assert rk["snapshot"]["anchored"]
    assert len(system.nodes["power"].history) >= 2 and system.nodes["power"].history[-1]["prev"] == system.nodes["power"].history[-2]["digest"]


@pytest.mark.req("AG-CRT-01", "AG-CRT-04", "AG-PLN-05")
def test_09_critic_verdict_is_anchored_before_the_gate(system):
    p = S["res"]["power"]
    v = p["stages"]["critic"]
    assert v["verdict"] == "APPROVE_FOR_GATE" and v["anchor_status"] == "anchored"
    assert system.chain.call("AuditLog", "hasAnchor", org_id("power"), 3, bytes.fromhex(v["digest"][2:]))
    plan = p["plan"]
    assert plan["risk_after"] < plan["risk_before"] and plan["cross_org_risk_after"] < plan["cross_org_risk_before"]
    S["plan"] = plan


# ------------------------------------------------------------------ the gate
@pytest.mark.req("BC-GATE-01", "BC-GATE-02", "UI-APP-02")
def test_10_gate_request_matches_plan_and_approver_view_is_complete(system):
    view = system.humans["power"].view(S["rid"])
    assert view["status"] == "Pending" and view["plan_hash"] == "0x" + S["plan"]["plan_hash"]
    assert view["impact"] in ("MEDIUM", "HIGH") and view["required"] >= 1 and len(view["approvers"]) == 3 and view["seconds_left"] > 0
    assert {"approvals", "rejections", "needs_safety_officer", "critic_verdict_digest"} <= set(view)


@pytest.mark.req("BC-GATE-06", "BC-GATE-08", "AG-ACT-02", "AG-SAF-01")
def test_11_the_agent_cannot_approve_execute_or_bypass(system):
    n = system.nodes["power"]
    rid = bytes.fromhex(S["rid"][2:])
    for fn, args in (("approve", [rid]), ("reject", [rid]), ("markExecuted", [rid, b"\x01" * 32])):
        with pytest.raises(ChainRevert):
            system.writer.submit(f"hack-{fn}", "ApprovalGate", fn, args, "power/agent")
    # the node-bound writer cannot be pointed at another identity
    with pytest.raises(TypeError):
        n.writer.submit("k", "ApprovalGate", "approve", [rid], "power/approver0")
    # the executor refuses without a request, with a pending one, and with someone else's
    orch = system.orch["power"]
    with pytest.raises(GateViolation):
        orch.executor.execute(S["plan"], None)
    with pytest.raises(GateViolation):
        orch.executor.execute(S["plan"], S["rid"])  # still Pending
    with pytest.raises(GateViolation):
        orch.executor.execute(S["plan"], "0x" + "ab" * 32)  # unknown request
    assert not n.executed_plans


@pytest.mark.req("AG-CRT-05", "BC-GATE-01")
def test_12_the_critic_cannot_be_skipped(system):
    orch = system.orch["power"]
    plan = dict(S["plan"])
    plan.pop("critic", None)
    with pytest.raises(GateViolation):
        orch.request_gate(plan, {"verdict": "APPROVE_FOR_GATE", "plan_hash": plan["plan_hash"], "digest": S["res"]["power"]["stages"]["critic"]["digest"]})
    plan2 = dict(S["plan"], critic={"verdict": "REVISE"})
    with pytest.raises(GateViolation):
        orch.request_gate(plan2, {"verdict": "REVISE", "plan_hash": plan["plan_hash"], "digest": "0x00"})
    # even a compromised agent that skips the orchestrator is stopped by the contract: no anchored verdict, no request
    with pytest.raises(ChainRevert) as e:
        system.writer.submit("skip-critic", "ApprovalGate", "requestApproval", [org_id("power"), b"\x05" * 32, b"\x06" * 32, 2, int(time.time()) + 9999999, b"\x07" * 32], "power/agent")
    assert e.value.name == "CriticVerdictNotAnchored"


@pytest.mark.req("BC-GATE-04", "BC-GATE-05", "AG-ACT-02", "AG-ACT-03", "AG-ORC-04")
def test_13_humans_approve_then_execution_matches_the_prediction(system):
    h = system.humans["power"]
    v = h.view(S["rid"])
    for i in range(3):
        if h.view(S["rid"])["status"] != "Pending":
            break
        h.approve(S["rid"], i)
    assert h.view(S["rid"])["status"] == "Approved"
    plan, orch = S["plan"], system.orch["power"]
    # a request approved for a DIFFERENT plan hash is refused
    other = dict(plan, plan_hash="cd" * 32)
    with pytest.raises(GateViolation):
        orch.executor.execute(other, S["rid"])
    rec = orch.continue_after_approval(S["rid"])
    assert rec["actual_delta"] == pytest.approx(plan["total_delta"], abs=1e-6) and rec["drift"] <= 1e-6
    assert h.view(S["rid"])["status"] == "Executed"
    assert any(e["stage"] == "execute" and e["status"] == "executed" for e in system.events)
    S["rec"] = rec
    with pytest.raises(GateViolation):  # one-shot
        orch.executor.execute(plan, S["rid"])


@pytest.mark.req("AG-ACT-01", "AG-ACT-04")
def test_14_execution_changed_only_simulated_state_and_rolls_back_with_an_audit_record(system):
    n = system.nodes["power"]
    a = n.assets["power-asset-001"]
    assert a.vulns == [] and not a.internet_exposed
    assert n.inventory["power-asset-001"]["internet_exposed"] is True, "the inventory (source data) is never mutated"
    before = len(n.audit._local_entries())
    out = system.orch["power"].executor.rollback(S["plan"]["plan_id"])
    assert out["rolled_back"] and len(n.audit._local_entries()) == before + 1
    assert n.assets["power-asset-001"].internet_exposed and n.assets["power-asset-001"].vulns
    with pytest.raises(KeyError):
        system.orch["power"].executor.rollback(S["plan"]["plan_id"])


@pytest.mark.req("AG-CAS-06", "BC-ALERT-03")
def test_15_downstream_orgs_acknowledge_and_harden_within_seconds(system):
    t0 = time.time()
    rea = system.react_all()
    assert time.time() - t0 < 5 * 6, "reaction time for the whole fleet"
    assert [x["service"] for x in rea["water"]["reacted"]] and [x["service"] for x in rea["hospital"]["reacted"]]
    assert not rea["power"]["reacted"], "the provider does not react to its own alert"
    aid = S["res"]["power"]["stages"]["cascade"]["alerts"][0]["alert_id"]
    assert system.chain.call("AlertBus", "acknowledgedAt", bytes.fromhex(aid[2:]), org_id("water")) > 0
    assert system.nodes["water"].upstream and system.nodes["hospital"].upstream
    again = system.react_all()
    assert not again["water"]["reacted"], "acknowledging twice is idempotent"
    # the exposure shows up in the downstream org's own service band
    assert any(b["p"] >= 0.5 for b in system.nodes["water"].service_band().values())


@pytest.mark.req("AG-RSK-06", "BC-ATT-R-01")
def test_16_risk_band_changes_are_published_on_chain(system):
    water = system.nodes["water"]
    sid = next(iter(water.upstream))
    aid = "0x" + bytes(system.chain.call("AttestationRegistry", "latestRiskId", org_id("water"), water.svc_hash(sid))).hex()
    ev = next(e["args"] for e in events(system, "AttestationRegistry", "RiskAttestationSubmitted") if e["args"]["attestationId"] == aid)
    assert "riskBand" not in ev, "the band is never public"
    d = system.nodes["power"].open_disclosure(ev["sealedBand"])  # any consortium member can open it ...
    assert system.chain.call("AttestationRegistry", "verifyBandDisclosure", bytes.fromhex(aid[2:]), bytes.fromhex(d["salt"]), d["band"], d["crit"])
    assert d["band"] >= 2, "band raised after the upstream alert"


@pytest.mark.req("SEC-PRIV-01", "SEC-PRIV-02", "SEC-PRIV-03", "SEC-PRIV-05")
def test_16b_nothing_sensitive_is_readable_on_chain(system):
    """Everything an attacker could read from any node: no plaintext bands, terms, outcomes or severities, and no
    sealed blob opens without a member key. Every member can open what is addressed to the consortium."""
    system.indexer.sync()
    leaky = {"riskBand", "criticalityBucket", "strength", "tolerance", "matched", "cveSetHash", "advisoryContentHash", "severity", "tti"}
    blobs = []
    for e in system.indexer.query(limit=100000):
        assert not leaky & set(e["args"]), (e["name"], leaky & set(e["args"]))
        for k in ("sealedTerms", "sealedBand", "sealedPayload"):
            if k in e["args"]:
                blobs.append((e["name"], sealed.from_hex(e["args"][k])))
    assert blobs and all(len(b) == sealed.SIZE for _, b in blobs), "fixed-size envelopes: length reveals nothing"
    outsider = sealed.private_key_from_secret(b"\x42" * 32)
    assert all(sealed.open_sealed(b, outsider) is None for _, b in blobs)
    for name, b in blobs:
        if name != "CascadeAlert":  # dependency terms and bands are addressed to every member
            assert all(n.open_disclosure(b) for n in system.nodes.values())


@pytest.mark.req("BC-ATT-R-04")
def test_17_selective_disclosure_roundtrip(system):
    p = system.nodes["power"]
    r = p.attest_risk("power-service-1", "high", "high", {"service": "power-service-1", "note": "audit"}, ttl=3600)
    assert r.status in ("confirmed", "duplicate")
    d = p._last_disclosure
    hist = system.chain.call("AttestationRegistry", "getRiskAttestationHistory", org_id("power"), p.svc_hash("power-service-1"))
    assert system.chain.call("AttestationRegistry", "verifyRiskDisclosure", org_id("power"), p.svc_hash("power-service-1"), hist[-1], bytes.fromhex(d["salt"][2:]), bytes.fromhex(d["assessment_hash"][2:]))
    assert not system.chain.call("AttestationRegistry", "verifyRiskDisclosure", org_id("power"), p.svc_hash("power-service-1"), hist[-1], b"\x00" * 32, bytes.fromhex(d["assessment_hash"][2:]))


@pytest.mark.req("BC-SEC-08")
def test_18_downstream_org_can_challenge_an_attestation(system):
    p = system.nodes["power"]
    hist = system.chain.call("AttestationRegistry", "getRiskAttestationHistory", org_id("power"), p.svc_hash("power-service-1"))
    r = system.nodes["water"].writer.submit("challenge-1", "AttestationRegistry", "challengeRiskAttestation", [hist[-1], org_id("water"), b"\x09" * 32])
    assert r.status == "confirmed" and system.chain.call("AttestationRegistry", "isChallenged", hist[-1])
    with pytest.raises(ChainRevert):  # an org with no confirmed edge to power-service-1's org... hospital has one; use unrelated stranger signer
        system.writer.submit("challenge-bad", "AttestationRegistry", "challengeRiskAttestation", [hist[-1], org_id("power"), b"\x09" * 32], "power/agent")


# --------------------------------------------------------------- adversarial
@pytest.mark.req("AG-INT-02", "AG-SAF-01", "AG-INT-03")
@pytest.mark.parametrize("n", [11, 12])
def test_19_prompt_injection_cannot_cause_any_action(system, n):
    before = {k: len(events(system, c, k)) for c, k in (("ApprovalGate", "ApprovalRequested"), ("ApprovalGate", "Approved"), ("ApprovalGate", "Executed"), ("AlertBus", "CascadeAlert"),
                                                      ("AttestationRegistry", "DependencyAttestationSubmitted"), ("AttestationRegistry", "RiskAttestationSubmitted"))}
    exec_before = {o: len(x.executed_plans) for o, x in system.nodes.items()}
    res = system.ingest(adv(n))
    after = {k: len(events(system, c, k)) for c, k in (("ApprovalGate", "ApprovalRequested"), ("ApprovalGate", "Approved"), ("ApprovalGate", "Executed"), ("AlertBus", "CascadeAlert"),
                                                     ("AttestationRegistry", "DependencyAttestationSubmitted"), ("AttestationRegistry", "RiskAttestationSubmitted"))}
    assert after == before, "an injected advisory must not trigger approvals, executions, alerts or attestations other than the finding"
    assert exec_before == {o: len(x.executed_plans) for o, x in system.nodes.items()}
    for org, p in res.items():
        assert p["status"] == "injection_blocked"
        f = p["stages"]["intake"]
        assert f["injection_suspected"] and f["extraction_confidence"] < 0.7 and f["matches"] == []
        assert "plan" not in p
    tr = json.loads(next(system.nodes["power"].audit.trace_dir.glob(f"{res['power']['trace_id']}.json")).read_text(encoding="utf-8"))
    assert tr["flags"].get("injection_suspected") is True


@pytest.mark.req("AG-TOP-05", "AG-SAF-01")
def test_20_org_nodes_cannot_read_each_others_private_data(system):
    p = system.nodes["power"]
    with pytest.raises(IsolationError):
        p.store.read_json("inventory.json", org="hospital")
    with pytest.raises(IsolationError):
        p.store.read_json("../hospital/inventory.json")
    with pytest.raises(IsolationError):
        p.store.read_json("private_keys.dev.json")
    assert p.store.read_json("inventory.json")[0]["org"] == "power"
    # an org node never holds another org's inventory in memory
    assert all(a.startswith("power-") for a in p.inventory)
    # matching runs only against the node's own inventory: the hospital's Cisco switch never matches at power
    f = system.orch["power"].intake.process(adv(4))
    assert f["status"] == "no_match"


@pytest.mark.req("AG-ORC-05")
def test_21_orchestrators_do_not_reference_other_orgs(system):
    for org, orch in system.orch.items():
        for v in list(vars(orch).values()) + [orch.node.__dict__.get(k) for k in ("bus",)]:
            assert not (isinstance(v, OrgNodeRuntime) and v.org != org)
        for ag in orch.agents:
            assert ag.node.org == org
    assert not [m for m in system.bus.log if m.recipient in ORGS and m.sender in ORGS and m.sender != m.recipient]


@pytest.mark.req("AG-INT-05")
def test_22_duplicate_advisories_are_not_reprocessed(system):
    before = len(events(system, "AttestationRegistry", "FindingAttestationSubmitted"))
    n_find = len(system.nodes["power"].findings)
    res = system.ingest(S["text"])
    assert all(p["status"] in ("awaiting_approval", "no_match", "low_only_executed", "executed", "duplicate") for p in res.values())
    assert len(events(system, "AttestationRegistry", "FindingAttestationSubmitted")) == before
    assert len(system.nodes["power"].findings) == n_find
    # same CVE set, different wording -> still a duplicate
    paraphrase = S["text"].replace("Siemens SICAM PAS", "Siemens SICAM-PAS gateway").replace("Description:", "Summary:")
    f = system.orch["power"].intake.process(paraphrase)
    assert f["duplicate"] is True


@pytest.mark.req("AG-INT-09")
def test_23_empty_and_oversized_advisories(system):
    with pytest.raises(ValueError):
        system.orch["power"].intake.process("   ")
    big = "CVE-2020-0001 Siemens SICAM PAS versions before 8.3.0\n" + "A" * 300_000
    f = system.orch["power"].intake.process(big)
    assert "truncated" in f["flags"]


@pytest.mark.req("AG-ORC-03", "BC-INT-02")
def test_24_twenty_parallel_advisories_without_nonce_collisions(system):
    before = len(events(system, "AttestationRegistry", "FindingAttestationSubmitted"))
    texts = [f"Vendor Security Bulletin VSB-{i}\nCVE-2024-{7000+i}: a flaw in Contoso Widget {i} versions before 2.{i}.0.\nCVSS: {4 + i % 5}.0" for i in range(20)]
    out = asyncio.run(system.orch["hospital"].process_many(texts))
    assert len(out) == 20 and all(p["status"] == "no_match" for p in out), [p.get("error") for p in out if p["status"] != "no_match"]
    assert len(events(system, "AttestationRegistry", "FindingAttestationSubmitted")) == before + 20
    assert system.writer.pending_count() == 0


@pytest.mark.req("AG-ORC-02")
def test_25_a_failing_stage_degrades_the_pipeline_without_crashing_the_node(system, monkeypatch):
    orch = system.orch["water"]
    monkeypatch.setattr(orch.risk, "assess", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    text = adv(2)  # matches water-asset-001
    p = orch.run_advisory(text.replace("CVE-2023-5678", "CVE-2023-5601"), "test")
    assert p["status"] == "failed" and "boom" in p["error"]
    assert system.orch["water"].metrics["failed"] >= 1
    # other advisories keep working
    assert system.orch["water"].run_advisory(adv(9), "test")["status"] in ("no_match", "duplicate")


@pytest.mark.req("AG-TOP-06", "AG-ORC-01")
def test_26_a_crashed_pipeline_resumes_without_duplicate_chain_writes(system, monkeypatch):
    orch = system.orch["power"]
    text = adv(5)  # ABB RTU560, all versions -> power-asset-002
    real = orch.request_gate
    calls = {"n": 0}

    def crash(*a, **k):
        calls["n"] += 1
        raise RuntimeError("simulated crash before the gate")

    monkeypatch.setattr(orch, "request_gate", crash)
    p1 = orch.run_advisory(text, "test")
    assert p1["status"] == "failed" and set(p1["done"]) >= {"intake", "risk", "cascade", "plan", "critic"}
    findings_before = len(events(system, "AttestationRegistry", "FindingAttestationSubmitted"))
    monkeypatch.setattr(orch, "request_gate", real)
    p2 = orch.run_advisory(text, "test", pipeline_id=p1["pipeline_id"])
    assert p2["status"] in ("awaiting_approval", "low_only_executed") and calls["n"] == 1
    assert len(events(system, "AttestationRegistry", "FindingAttestationSubmitted")) == findings_before, "completed stages are not repeated"
    # a brand-new system object over the same state dir continues from persisted state
    from backend.system import CascadeShieldSystem

    s2 = CascadeShieldSystem(system.chain.rpc_url, str(system.chain.deployment_file), system.state_dir)
    p3 = s2.orch["power"].run_advisory(text, "test", pipeline_id=p1["pipeline_id"])
    assert p3["status"] == p2["status"]
    assert s2.nodes["power"].assets["power-asset-002"].default_credentials == system.nodes["power"].assets["power-asset-002"].default_credentials
    assert len(events(system, "AttestationRegistry", "FindingAttestationSubmitted")) == findings_before


# -------------------------------------------------------------------- audit
@pytest.mark.req("AG-TOP-04", "BC-AUD-03", "BC-AUD-07")
def test_27_traces_are_anchored_in_merkle_batches_and_verify(system):
    flushed = system.flush_audit()
    assert all(f and f["status"] == "anchored" for f in flushed.values())
    ver = system.verify_audit()
    assert all(v["ok"] for v in ver.values()), ver
    n = system.nodes["power"]
    tid = next(t for t in (e for e in n.audit._local_entries() if e["is_batch"]))["leaves"][0]
    assert n.audit.verify_inclusion_onchain(tid)
    tr = json.loads((n.audit.trace_dir / f"{tid}.json").read_text(encoding="utf-8"))
    assert tr["digest"].startswith("0x") and tr["steps"] and {"tool_call"} & {s["type"] for s in tr["steps"]}


@pytest.mark.req("BC-AUD-02", "BC-INT-05")
def test_28_python_chain_hash_equals_the_contract(system):
    n = system.nodes["power"]
    oid = org_id("power")
    length = system.chain.call("AuditLog", "length", oid)
    last = system.chain.call("AuditLog", "lastDigest", oid)
    e = system.chain.call("AuditLog", "getAnchor", oid, length - 1)
    local = [x for x in n.audit._local_entries() if x["index"] == length - 1][0]
    py = entry_hash("power", local["kind"], bytes.fromhex(local["digest"][2:]), bytes.fromhex(local["prev"][2:]), bytes.fromhex(local["meta"][2:]), length - 1, local["is_batch"], local["count"])
    assert py == bytes(last)
    assert system.chain.call("AuditLog", "verifyChain", oid, 10_000)


@pytest.mark.req("BC-AUD-07", "AG-OBS-03")
def test_29_tampering_with_a_stored_trace_is_detected_at_the_exact_entry(system):
    n = system.nodes["power"]
    batch = next(e for e in n.audit._local_entries() if e["is_batch"])
    f = n.audit.trace_dir / f"{batch['leaves'][0]}.json"
    original = f.read_text(encoding="utf-8")
    doc = json.loads(original)
    doc["steps"][0]["tampered"] = True
    f.write_text(json.dumps(doc), encoding="utf-8")
    res = n.audit.verify()
    assert res["ok"] is False and res["first_mismatch"] == batch["index"] and "digest" in res["reason"]
    f.write_text(original, encoding="utf-8")
    assert n.audit.verify()["ok"] is True
    # deleting a trace is detected as well
    f.rename(f.with_suffix(".bak"))
    assert n.audit.verify()["ok"] is False
    f.with_suffix(".bak").rename(f)
    assert n.audit.verify()["ok"] is True


@pytest.mark.req("AG-OBS-01", "AG-OBS-02")
def test_30_metrics_and_trace_inventory(system):
    m = system.metrics()["total"]
    assert m["advisories"] >= 6 and m["injection_detections"] >= 2 and m["gate_requests"] >= 1 and m["executed"] >= 1
    assert 0 <= m["critic_reject_rate"] <= 1 and m["mean_pipeline_latency_s"] > 0


# ---------------------------------------------------------------- kill switch
@pytest.mark.req("AG-SAF-04")
def test_31_kill_switch_blocks_writes_and_is_audit_logged(system):
    n_before = {o: system.chain.call("AuditLog", "length", org_id(o)) for o in ORGS}
    system.pause()
    try:
        assert system.writer.paused
        with pytest.raises(ChainPaused):
            system.writer.submit("paused-1", "AuditLog", "anchor", [org_id("power"), 0, b"\x03" * 32, system.chain.call("AuditLog", "lastDigest", org_id("power")), b"\x00" * 32], "power/agent")
        p = system.orch["power"].run_advisory(adv(7), "test")  # iFIX -> power-asset-004
        assert p["status"] == "paused"
        with pytest.raises(ChainPaused):
            system.orch["power"].executor.execute(S["plan"], None, dry_run=False)
    finally:
        system.resume()
    assert not system.writer.paused
    for o in ORGS:
        kinds = [system.chain.call("AuditLog", "getAnchor", org_id(o), i)[0] for i in range(n_before[o], system.chain.call("AuditLog", "length", org_id(o)))]
        assert 5 in kinds and 6 in kinds, "Pause and Resume are anchored on-chain"
    assert system.orch["power"].run_advisory(adv(7), "test")["status"] in ("awaiting_approval", "low_only_executed", "paused", "failed")
