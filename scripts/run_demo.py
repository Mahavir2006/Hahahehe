#!/usr/bin/env python3
"""
Automated end-to-end demo for CascadeShield (spec section 11): one command, a real local chain, real agents.

    python scripts/run_demo.py          # exit code 0 only if every check passes

Each step prints what happened and checks it. Everything is simulated (assets, telemetry, compromise labels);
nothing connects to real infrastructure.
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass

from backend.agents.framework import GateViolation  # noqa: E402
from backend.common.chain import ChainRevert, org_id  # noqa: E402
from backend.devchain import DevChain  # noqa: E402
from backend.risk import model as M  # noqa: E402
from backend.risk.inference import M1  # noqa: E402
from backend.system import CascadeShieldSystem  # noqa: E402

CHECKS: list = []


def adv(n: int) -> str:
    return (ROOT / "data" / "advisories" / f"ADV-2023-{n:04d}.txt").read_text(encoding="utf-8")


def step(n: int, title: str) -> None:
    print(f"\n=== Step {n:>2}: {title}")


def check(req: str, ok: bool, msg: str) -> bool:
    CHECKS.append((req, bool(ok), msg))
    print(f"   [{'PASS' if ok else 'FAIL'}] {msg}  ({req})")
    return bool(ok)


def info(msg: str) -> None:
    print(f"   - {msg}")


def events(s, contract, name):
    s.indexer.sync()
    return s.indexer.query(contract, name, limit=100000)


def run() -> int:
    dc = DevChain()
    state = Path(tempfile.mkdtemp(prefix="cascadeshield-demo-"))
    try:
        step(1, "Start a local chain, deploy and seed the 6 contracts, start 3 org nodes")
        dc.start()
        s = CascadeShieldSystem(dc.url, str(dc.deployment_file), state, llm_provider="offline")
        boot = s.bootstrap(extra_unilateral=True)
        check("BC-ENV-01", s.chain.is_connected(), f"chain {s.chain.chain_id} at block {s.chain.block_number()}")
        check("SEC-PRIV-04", all(v in ("confirmed", "registered") for v in boot["encryption_keys"].values()), "each org published its encryption key")
        card = M1.get()
        info(f"risk model M1 {card.version} ({card.meta['config']['estimator']}, {card.meta['calibration']['method']} calibration, trained on synthetic labels)")

        step(2, "Bilateral dependency handshakes (both sides must sign the same sealed terms)")
        deps = json.loads((ROOT / "data" / "cross_org_dependencies.json").read_text(encoding="utf-8"))
        confirmed = sum(bool(s.chain.call("AttestationRegistry", "isEdgeConfirmed", org_id(d["consumer_org"]), s.nodes[d["consumer_org"]].svc_hash(d["consumer_service"]),
                                          org_id(d["provider_org"]), s.nodes[d["provider_org"]].svc_hash(d["provider_service"]))) for d in deps)
        check("BC-ATT-D-01", confirmed == len(deps), f"{confirmed}/{len(deps)} declared edges confirmed on-chain")
        check("BC-ATT-D-01", boot.get("unilateral") in ("confirmed", "duplicate"), "a one-sided edge was submitted and stays unconfirmed")

        step(3, "Baseline risk attestations: commitments + sealed bands, nothing readable on-chain")
        risk_ev = events(s, "AttestationRegistry", "RiskAttestationSubmitted")
        check("BC-ATT-R-01", len(risk_ev) >= 9, f"{len(risk_ev)} service risk attestations published")
        check("SEC-PRIV-01", all("riskBand" not in e["args"] for e in risk_ev), "no plaintext band in any attestation")

        step(4, "Firmware supply-chain check against FirmwareRegistry")
        sc = boot["supply_chain"]
        flagged = {o: sorted(k for k, v in r.items() if v != "Match") for o, r in sc.items()}
        check("BC-FW-05", all(len(v) == 3 for v in flagged.values()), f"tampered/unknown firmware flagged: {flagged['power']}")

        step(5, "Headline advisory arrives (every org checks it against its own inventory)")
        res = s.ingest(adv(1), source="CERT-In")
        st = {o: p["status"] for o, p in res.items()}
        check("AG-ORC-01", st["power"] == "awaiting_approval", f"pipeline status per org: {st}")
        check("SEC-PRIV-02", all("matched" not in e["args"] for e in events(s, "AttestationRegistry", "FindingAttestationSubmitted")),
              "finding attestations are blinded (the advisory and its outcome are not readable)")

        step(6, "Risk agent: M1 likelihood x impact, with the 'why'")
        a = s.nodes["power"].assets["power-asset-001"]
        sc1 = M.score_asset(a)
        info(f"power-asset-001 risk {sc1['risk']} ({sc1['band']}); likelihood {sc1['likelihood']}, impact {sc1['impact']}")
        for f in sc1["top_factors"][:3]:
            info(f"  driver: {f['text']}")
        check("AG-RSK-01", sc1["band"] in ("high", "critical"), "headline asset raised to high/critical")
        ch = s.nodes["power"].feature_baseline["power-asset-001"]
        from backend.risk.inference import what_changed

        wc = what_changed(ch, M.features_of(a))
        check("RISK-03", bool(wc), "what changed since boot: " + "; ".join(c["sentence"] for c in wc[:2]))

        step(7, "Cascade agent: power -> water -> hospital, early warning on AlertBus (sealed)")
        cs = res["power"]["stages"]["cascade"]
        chain = cs["chain"]
        for c in chain[:3]:
            info(f"  {c['org']:9s} impacted in ~{c['time_to_impact_minutes']} min, p_degraded {c['p_degraded']}")
        check("AG-CAS-02", [c["org"] for c in chain][:2] == ["water", "hospital"], "cascade reaches water, then hospital")
        check("AG-CAS-05", bool(cs["alerts"]) and cs["alerts"][0]["status"] == "confirmed", f"{len(cs['alerts'])} sealed alert(s) published")

        step(8, "Planner proposes a constraint-respecting plan; Critic re-checks it independently")
        plan = res["power"]["plan"]
        v = res["power"]["stages"]["critic"]
        info(f"plan {plan['plan_id']}: {len(plan['steps'])} steps, org risk {plan['risk_before']} -> {plan['risk_after']}")
        check("AG-CRT-04", v["verdict"] == "APPROVE_FOR_GATE" and v["anchor_status"] == "anchored", "critic verdict anchored on AuditLog before the gate")

        step(9, "Human approval through ApprovalGate (the AI cannot vote)")
        rid = res["power"]["request_id"]
        h = s.humans["power"]
        view = h.view(rid)
        info(f"request {rid[:12]}... impact {view['impact']}, needs {view['required']} approval(s), safety officer: {view['needs_safety_officer']}")
        try:
            s.writer.submit("demo-agent-vote", "ApprovalGate", "approve", [bytes.fromhex(rid[2:])], "power/agent")
            agent_blocked = False
        except ChainRevert:
            agent_blocked = True
        check("BC-GATE-06", agent_blocked, "the agent's own vote is rejected by the contract")
        for i in range(3):
            if h.view(rid)["status"] != "Pending":
                break
            h.approve(rid, i)
        check("BC-GATE-05", h.view(rid)["status"] == "Approved", "approved by human approvers")

        step(10, "Executor verifies the gate on-chain, applies the (simulated) plan, re-scores")
        rec = s.orch["power"].continue_after_approval(rid)
        info(f"predicted delta {plan['total_delta']}, actual {rec['actual_delta']}")
        check("AG-PLN-05", rec["drift"] <= 1e-6, "realised risk reduction equals the what-if prediction")
        check("AG-ACT-02", h.view(rid)["status"] == "Executed", "request marked Executed on-chain")

        step(11, "Downstream orgs receive the alert, acknowledge it and harden")
        rea = s.react_all()
        check("AG-CAS-06", bool(rea["water"]["reacted"]) and bool(rea["hospital"]["reacted"]), f"water reacted to {len(rea['water']['reacted'])}, hospital to {len(rea['hospital']['reacted'])} alert(s)")
        check("SEC-PRIV-03", all(r.get("disclosure_verified") for r in rea["water"]["reacted"]), "alert severity opened and verified against its commitment")

        step(12, "Prompt-injection advisories are treated as data")
        before = len(events(s, "ApprovalGate", "ApprovalRequested"))
        inj = [s.ingest(adv(n), source="feed") for n in (11, 12)]
        check("AG-INT-02", all(p["status"] == "injection_blocked" for r in inj for p in r.values()), "both injected advisories blocked in every org")
        check("AG-SAF-01", len(events(s, "ApprovalGate", "ApprovalRequested")) == before, "no approval request was created by them")

        step(13, "Bypass attempts")
        try:
            s.orch["power"].executor.execute(plan, None)
            bypass = False
        except GateViolation:
            bypass = True
        check("AG-ACT-02", bypass, "executing without an approved request is refused")
        try:
            s.writer.submit("demo-skip-critic", "ApprovalGate", "requestApproval", [org_id("power"), b"\x05" * 32, b"\x06" * 32, 2, int(time.time()) + 9_999_999, b"\x07" * 32], "power/agent")
            skip = False
        except ChainRevert as e:
            skip = e.name == "CriticVerdictNotAnchored"
        check("AG-CRT-05", skip, "requesting approval without an anchored critic verdict is refused by the contract")

        step(14, "Audit: Merkle-anchor every trace, verify, then detect tampering")
        s.flush_audit()
        check("BC-AUD-07", all(v["ok"] for v in s.verify_audit().values()), "all three audit logs verify against the chain")
        n = s.nodes["power"]
        batch = next(e for e in n.audit._local_entries() if e["is_batch"])
        f = n.audit.trace_dir / f"{batch['leaves'][0]}.json"
        original = f.read_text(encoding="utf-8")
        doc = json.loads(original)
        doc["steps"][0]["tampered"] = True
        f.write_text(json.dumps(doc), encoding="utf-8")
        bad = n.audit.verify()
        f.write_text(original, encoding="utf-8")
        check("BC-AUD-07", bad["ok"] is False and bad["first_mismatch"] == batch["index"], f"tampered trace detected at entry {bad.get('first_mismatch')}")
    except Exception as e:  # noqa: BLE001
        check("DEMO", False, f"demo aborted: {type(e).__name__}: {e}")
    finally:
        dc.stop()

    passed = sum(ok for _, ok, _ in CHECKS)
    print(f"\n=== Checklist: {passed}/{len(CHECKS)} passed")
    for req, ok, msg in CHECKS:
        if not ok:
            print(f"   FAIL {req}: {msg}")
    return 0 if CHECKS and passed == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(run())
