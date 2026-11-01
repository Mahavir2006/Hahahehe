"""
Firmware supply-chain attack, end to end, on the live system (demo).

A trojanised firmware image lands on one real asset (the attack is simulated: the asset's observed firmware hash
changes and the implant's network behaviour shows up in its telemetry). Everything after that is the real system:

  1 implant     the asset reports a firmware hash the vendor never published
  2 detect      FirmwareRegistry.verifyFirmware (a real contract call) says Mismatch; rule D telemetry fires
  3 predict     M1 re-scores the asset; SHAP shows which inputs moved the risk and by how much
  4 agents      a supply-chain bulletin runs the real agent pipeline: intake, risk (attestation on chain),
                cascade (sealed AlertBus alerts), planner, critic (verdict anchored on AuditLog), ApprovalGate request
  5 approve     two human approvers sign on ApprovalGate (the AI cannot vote)
  6 contain     the executor checks the gate on chain, applies the (simulated) containment and re-scores
  7 record      every contract event the attack caused, and the digital twin before and after

Nothing touches real equipment; the containment is simulated, as everywhere in CascadeShield.
"""

from __future__ import annotations

import threading
import time
import traceback
from typing import Any, Dict, List, Optional

from eth_utils import keccak

from backend.risk import model as risk
from backend.risk.inference import LABELS, M1

import difflib
import hashlib
import json

from backend.common.chain import ROOT

TARGET_ORG, TARGET = "power", "power-asset-001"
# set while a demo runs: the live simulated clock (ps03_serve auto-advance) holds still so nothing else changes the device
LIVE_HOLD = threading.Event()
# model inputs the implant changes (firmware trust + the implant's network behaviour seen by rules D)
ATTACK_FEATURES = ["supply_chain_flag", "firmware_known", "failed_auth_count", "new_remote_session_flag", "rule_hit_count", "high_severity_rule_hit"]
# the firmware "images": illustrative source files (data/firmware/README.md). The device reports the SHA-256 of the
# tampered file, so the registry mismatch shown in the demo is the real hash of the file the page displays.
FW_DIR = ROOT / "data" / "firmware" / "sicam_pas_8.2.1"
TARGET_FW = ("Siemens", "SICAM PAS", "8.2.1")
IMPLANT_SHA = "0x" + hashlib.sha256((FW_DIR / "tampered_build.c").read_bytes()).hexdigest()
IMPLANT_CHANGES = [
    {"what": "Second signing key (BACKUP_PUBKEY)", "effect": "future tampered images pass the signature check too",
     "seen_by": "FirmwareRegistry: the running image's hash is not the vendor-published one"},
    {"what": "Hidden login (MAINT_MAGIC)", "effect": "a fixed 16-byte value opens a maintenance session with no password, no MFA and no audit entry",
     "seen_by": "rules D: unexpected remote session from an unknown source, after the attacker's failed logins while probing"},
    {"what": "Beacon every 60 s", "effect": "the device sends its serial and live configuration to 203.0.113.42:4444",
     "seen_by": "rules D: outbound beaconing to an unknown host"},
]


def published_sha() -> str:
    """The vendor-published hash for the target's firmware, as registered on the chain (data/firmware_catalog.json)."""
    cat = json.loads((ROOT / "data" / "firmware_catalog.json").read_text(encoding="utf-8"))
    return next(c["firmware_sha256"] for c in cat if (c["vendor"], c["model"], c["version"]) == TARGET_FW)


def firmware_image() -> Dict[str, Any]:
    """Both firmware sources, the attacker's diff, and the hashes the registry check compares."""
    vendor = (FW_DIR / "vendor_build.c").read_text(encoding="utf-8").splitlines()
    tampered = (FW_DIR / "tampered_build.c").read_text(encoding="utf-8").splitlines()
    marks = [" "] * len(tampered)  # "+" on every line the attacker added or changed
    for tag, _i1, _i2, j1, j2 in difflib.SequenceMatcher(None, vendor, tampered).get_opcodes():
        if tag in ("insert", "replace"):
            for j in range(j1, j2):
                marks[j] = "+"
    diff = []
    for line in difflib.unified_diff(vendor, tampered, "vendor_build.c", "tampered_build.c", n=2, lineterm=""):
        if line.startswith(("---", "+++")):
            continue
        op = line[0] if line[:1] in "+-@" else " "
        diff.append({"op": op, "text": line if op == "@" else line[1:]})
    return {
        "device": TARGET, "firmware": " ".join(TARGET_FW), "folder": "data/firmware/sicam_pas_8.2.1",
        "published_sha256": published_sha(),
        "vendor": {"file": "vendor_build.c", "lines": vendor},
        "tampered": {"file": "tampered_build.c", "sha256": IMPLANT_SHA, "lines": [{"op": m, "text": t} for m, t in zip(marks, tampered)]},
        "diff": diff, "added_lines": marks.count("+"), "changes": IMPLANT_CHANGES,
        "note": "Illustrative source standing in for the firmware binary: not compilable, fictional APIs, documentation-only beacon address.",
    }
ATTACK = {
    "name": "Trojanised firmware update (supply-chain implant)",
    "technique": "MITRE ATT&CK for ICS T0857 System Firmware · ATT&CK T1195.002 Compromise Software Supply Chain",
    "vector": "A tampered SICAM PAS 8.2.1 image delivered through the vendor update channel; the implant opens a remote session and beacons out",
    "simulated": "The implant itself is simulated (firmware hash + telemetry). Detection, scoring, agents, approvals and chain records are the live system.",
}
STAGES = [
    ("implant", "Firmware implant lands", "Attacker"),
    ("detect", "Supply-chain check and detection rules", "FirmwareRegistry + rules D"),
    ("predict", "Risk re-scored by the AI model (SHAP)", "Risk model M1"),
    ("agents", "Agents investigate, predict the cascade and plan", "Intake · Risk · Cascade · Planner · Critic"),
    ("approve", "Human approval on ApprovalGate", "2 human approvers"),
    ("contain", "Containment executed and verified", "Executor agent"),
    ("record", "What the blockchain and the digital twin now hold", "Chain + digital twin"),
]


def _bulletin(run: str) -> str:
    # each run is a new incident: a fresh simulated identifier, so intake does not dedupe it against an earlier run
    cve = f"CVE-2026-{30000 + int(run) % 60000}"
    return f"""Vendor Security Bulletin VSB-{run}
Title: Trojanised firmware image for Siemens SICAM PAS distributed through the update channel

Description: A compromised build of Siemens SICAM PAS firmware 8.2.1 was distributed through the vendor update channel.
The image contains an implant that enables an unauthenticated remote session and beacons to an external server.
Devices running the affected build report a firmware hash that does not match the vendor-published hash.

Affected Products:
- Siemens SICAM PAS versions before 8.3.0

CVE: {cve} (simulated identifier for this demo)
CVSS v3.1 Base Score: 9.8 (Critical)
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

Exploitation Status: Actively exploited in the wild (CISA KEV catalog)

Recommendations:
1. Isolate affected devices from external and partner networks
2. Reflash with the vendor-signed SICAM PAS 8.3.0 image and verify the hash against FirmwareRegistry
3. Rotate credentials used by remote sessions on the device
"""


def _factors(score: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [{"feature": f.get("feature"), "label": f.get("factor") or f.get("text"), "value": f.get("value"),
             "logodds": round(float(f.get("contribution_logodds", 0.0)), 4)} for f in score.get("top_factors", [])]


class FirmwareAttackDemo:
    def __init__(self, system, twin_factory, prepare=None):
        self.S = system
        self.twin_factory = twin_factory
        self.prepare = prepare  # optional: bring the simulation back to day 0 so the attack starts from a clean baseline
        self.lock = threading.Lock()
        self.state: Dict[str, Any] = self._blank()
        self._saved: Optional[Dict[str, Any]] = None

    def _blank(self) -> Dict[str, Any]:
        return {"status": "idle", "attack": ATTACK, "target": {"org": TARGET_ORG, "asset_id": TARGET},
                "stages": [{"id": i, "title": t, "actor": a, "status": "pending", "events": [], "data": {}} for i, t, a in STAGES]}

    # ------------------------------------------------------------------ public
    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            import copy

            return copy.deepcopy(self.state)

    def launch(self, pace: float = 1.2) -> Dict[str, Any]:
        with self.lock:
            if self.state["status"] == "running":
                return {"started": False, "reason": "an attack demo is already running"}
            self.state = self._blank()
            self.state["status"] = "running"
            self.state["started_at"] = time.time()
        threading.Thread(target=self._run, args=(pace,), daemon=True).start()
        return {"started": True}

    def reset(self) -> Dict[str, Any]:
        """Put the device back on the vendor-published firmware (the chain history stays: it is append-only)."""
        n = self.S.nodes[TARGET_ORG]
        if self._saved:
            n.inventory[TARGET]["observed_firmware_sha256"] = self._saved["sha"]
            a = n.assets[TARGET]
            a.telemetry, a.firmware_known = dict(self._saved["telemetry"]), self._saved["firmware_known"]
            a.isolated, a.likelihood_mult = self._saved["isolated"], self._saved["likelihood_mult"]
            n.supply_chain_check()
        with self.lock:
            self.state = self._blank()
        return {"reset": True}

    # ------------------------------------------------------------------ run
    def _stage(self, sid: str, **kw: Any) -> Dict[str, Any]:
        with self.lock:
            st = next(s for s in self.state["stages"] if s["id"] == sid)
            st.update(kw)
            self.state["current"] = sid
            return st

    def _log(self, sid: str, who: str, what: str, tx: Optional[str] = None) -> None:
        with self.lock:
            st = next(s for s in self.state["stages"] if s["id"] == sid)
            st["events"].append({"t": round(time.time() - self.state["started_at"], 1), "who": who, "what": what, "tx": tx})

    def _run(self, pace: float) -> None:
        S, n = self.S, self.S.nodes[TARGET_ORG]
        LIVE_HOLD.set()
        try:
            if self.prepare:
                for _ in range(30):  # an advance may be mid-flight; wait for it
                    try:
                        self.prepare()
                        break
                    except Exception:  # noqa: BLE001
                        time.sleep(1)
                self._log("implant", "Simulation", "clock back to day 0: the gateway starts from its normal state, and the live clock holds while the attack runs")
            a = n.assets[TARGET]
            inv = n.inventory[TARGET]
            S.indexer.sync()
            start_block = S.chain.block_number()
            twin = self.twin_factory()
            twin_before = twin.live()
            before = risk.score_asset(a)
            rec_before = M1.get().predict(risk.features_of(a), explain=False)["record"]
            with self.lock:
                self.state["start_block"] = start_block
            # the genuine hash is the vendor's published one (the device may still be implanted from an earlier run)
            import json as _json

            from backend.common.chain import ROOT
            cat = _json.loads((ROOT / "data" / "firmware_catalog.json").read_text(encoding="utf-8"))
            genuine = next((c["firmware_sha256"] for c in cat if (c["vendor"], c["model"], c["version"]) == (inv["vendor"], inv["model"], inv["firmware_version"])), inv["observed_firmware_sha256"])
            if inv["observed_firmware_sha256"] == IMPLANT_SHA:
                inv["observed_firmware_sha256"] = genuine
                n.supply_chain_check()
            self._saved = {"sha": genuine, "telemetry": dict(a.telemetry), "firmware_known": a.firmware_known,
                           "isolated": a.isolated, "likelihood_mult": a.likelihood_mult}

            # 1 implant ----------------------------------------------------------------------------------------
            self._stage("implant", status="running", started=time.time())
            self._log("implant", "Attacker", f"pushes a tampered {inv['vendor']} {inv['model']} {inv['firmware_version']} image through the update channel")
            inv["observed_firmware_sha256"] = IMPLANT_SHA
            a.telemetry = {**a.telemetry, "new_remote_session_flag": 1, "rule_hit_count": a.telemetry.get("rule_hit_count", 0) + 9,
                           "high_severity_rule_hit": 1, "failed_auth_count": a.telemetry.get("failed_auth_count", 0) + 40}
            self._log("implant", "Implant", "opens an unauthenticated remote session and starts beaconing to an external server")
            self._stage("implant", status="done", data={"asset": {"id": TARGET, "name": inv.get("name"), "vendor": inv["vendor"], "model": inv["model"],
                        "version": inv["firmware_version"], "zone": inv.get("zone")}, "published_sha": self._saved["sha"], "observed_sha": IMPLANT_SHA})
            time.sleep(pace)

            # 2 detect -------------------------------------------------------------------------------------------
            self._stage("detect", status="running")
            sc = n.supply_chain_check()  # FirmwareRegistry.verifyFirmware on chain for every asset
            a.firmware_known = False
            self._log("detect", "Risk agent", f"FirmwareRegistry.verifyFirmware → {sc[TARGET]} (vendor-published hash differs from the device)")
            self._log("detect", "Detection rules D", "D2 new remote session · beaconing to an unknown host · 40 failed logins → high-severity rule hit")
            self._stage("detect", status="done", data={"registry_result": sc[TARGET], "rules": ["D2 new remote session", "outbound beacon", "failed-login burst"],
                        "severity": "Critical"})
            time.sleep(pace)

            # 3 predict ------------------------------------------------------------------------------------------
            self._stage("predict", status="running")
            after = risk.score_asset(a)
            m = M1.get()
            rec_after = m.predict(risk.features_of(a), explain=False)["record"]
            # isolate the implant: same record as before, with only the inputs the attack changes taken from now
            # (the live loop may change other inputs of this device meanwhile; those are not the attack's effect)
            rec_attack = {**rec_before, **{k: rec_after[k] for k in ATTACK_FEATURES if k in rec_after}}
            rec_after = rec_attack
            sb, sa = m.shap(rec_before), m.shap(rec_attack)
            lik_b, lik_a = m.likelihood_bp(rec_before) / 10000, m.likelihood_bp(rec_attack) / 10000
            # full SHAP (log-odds) per feature, before and after the implant, largest change first
            rows = [{"feature": k, "label": LABELS.get(k, k), "before": round(sb.get(k, 0.0), 4), "after": round(sa.get(k, 0.0), 4),
                     "delta": round(sa.get(k, 0.0) - sb.get(k, 0.0), 4), "value_before": rec_before.get(k), "value_after": rec_after.get(k)}
                    for k in set(sb) | set(sa)]
            rows.sort(key=lambda x: -abs(x["delta"]))
            shap = [r for r in rows if abs(r["delta"]) > 1e-4][:8]
            for must in ("supply_chain_flag", "firmware_known"):
                if not any(r["feature"] == must for r in shap):
                    shap += [r for r in rows if r["feature"] == must]
            self._log("predict", "Risk model M1", f"risk {before['risk']:.1f} → {after['risk']:.1f} ({before['band']} → {after['band']}); likelihood {before['likelihood']:.2f} → {after['likelihood']:.2f}")
            self._log("predict", "SHAP", f"implant alone: likelihood {lik_b:.0%} → {lik_a:.0%}; largest driver {shap[0]['label']} ({shap[0]['delta']:+.2f} log-odds)")
            self._stage("predict", status="done", data={"implant_only": {"likelihood_before": lik_b, "likelihood_after": lik_a},
                        "before": {k: before[k] for k in ("risk", "band", "likelihood", "impact")},
                        "after": {k: after[k] for k in ("risk", "band", "likelihood", "impact")}, "shap": shap, "model_version": after.get("model_version")})
            time.sleep(pace)

            # 4 agents -------------------------------------------------------------------------------------------
            self._stage("agents", status="running")
            run = str(int(time.time()))
            self._log("agents", "Intake agent", "reads the supply-chain bulletin, matches it to the inventory (advisory text treated as data)")
            res = S.ingest(_bulletin(run), source="vendor-bulletin", orgs=[TARGET_ORG])[TARGET_ORG]
            stg = res.get("stages", {})
            cas = stg.get("cascade", {})
            plan = res.get("plan") or {}
            crit = stg.get("critic", {})
            for c in cas.get("chain", [])[:6]:
                self._log("agents", "Cascade agent", f"{c.get('label') or c.get('org')} degraded in ~{c.get('time_to_impact_minutes')} min (probability {float(c.get('p_degraded') or 0):.0%})")
            for al in cas.get("alerts", []):
                self._log("agents", "Cascade agent", f"sealed early-warning alert on AlertBus ({al.get('status')})", al.get("tx_hash"))
            if plan:
                self._log("agents", "Planner agent", f"plan {plan.get('plan_id')}: {len(plan.get('steps', []))} steps, org risk {plan.get('risk_before')} → {plan.get('risk_after')}")
            if crit:
                self._log("agents", "Critic agent", f"verdict {crit.get('verdict')} · anchored on AuditLog: {crit.get('anchor_status')}")
            self._log("agents", "Orchestrator", f"pipeline status: {res.get('status')} · approval request {str(res.get('request_id'))[:14]}…")
            self._stage("agents", status="done", data={
                "pipeline_status": res.get("status"), "matched": stg.get("intake", {}).get("matched") if isinstance(stg.get("intake"), dict) else None,
                "cascade": cas.get("chain", []), "alerts": cas.get("alerts", []),
                "plan": {"plan_id": plan.get("plan_id"), "steps": plan.get("steps", []), "risk_before": plan.get("risk_before"), "risk_after": plan.get("risk_after"),
                         "total_delta": plan.get("total_delta")},
                "critic": {k: crit.get(k) for k in ("verdict", "anchor_status", "reasons", "checks") if k in crit},
                "request_id": res.get("request_id")})
            time.sleep(pace)

            # 5 approve ------------------------------------------------------------------------------------------
            rid = res.get("request_id")
            self._stage("approve", status="running")
            approvals = []
            if rid:
                h = S.humans[TARGET_ORG]
                view = h.view(rid)
                self._log("approve", "ApprovalGate", f"request needs {view.get('required')} approval(s) · impact {view.get('impact')}")
                for i in range(3):
                    if h.view(rid)["status"] != "Pending":
                        break
                    r = h.approve(rid, i)
                    approvals.append(r.get("tx_hash") if isinstance(r, dict) else None)
                    self._log("approve", f"Human approver {i + 1}", "signs the approval with their own key", approvals[-1])
                    time.sleep(pace / 2)
                self._stage("approve", status="done", data={"request_id": rid, "status": h.view(rid)["status"], "approval_txs": approvals})
            else:
                self._stage("approve", status="skipped", data={"reason": "the pipeline did not request approval (see agents stage)"})
            time.sleep(pace)

            # 6 contain ------------------------------------------------------------------------------------------
            self._stage("contain", status="running")
            rec = S.orch[TARGET_ORG].continue_after_approval(rid) if rid else {}
            contained = risk.score_asset(n.assets[TARGET])
            self._log("contain", "Executor agent", f"checked ApprovalGate on chain, applied the plan · predicted Δ {rec.get('predicted_delta', plan.get('total_delta'))} actual Δ {rec.get('actual_delta')}")
            self._stage("contain", status="done", data={"execution": {k: rec.get(k) for k in ("status", "actual_delta", "drift", "execution_digest", "tx_hash") if k in rec},
                        "asset_after": {k: contained[k] for k in ("risk", "band", "likelihood", "impact")}})
            time.sleep(pace)

            # 7 record -------------------------------------------------------------------------------------------
            self._stage("record", status="running")
            S.flush_audit()
            S.indexer.sync()
            evs = [e for e in S.indexer.query(None, None, 2000) if e["block"] > start_block]
            evs.sort(key=lambda e: (e["block"], e["log_index"]))
            twin_after = twin.live()
            from backend.twin import model as M

            drift = [d for d in twin.drift(twin_after, org=TARGET_ORG) if d["subject"] == TARGET or d["kind"] in ("unacknowledged_alert",)]
            self._stage("record", status="done", data={
                "events": [{"block": e["block"], "tx": e["tx"], "contract": e["contract"], "event": e["name"]} for e in evs],
                "by_contract": {c: sum(1 for e in evs if e["contract"] == c) for c in sorted({e["contract"] for e in evs})},
                "twin": {"root_before": twin_before["fp"]["root"], "root_after": twin_after["fp"]["root"], "block_before": twin_before["state"]["block"],
                         "block_after": twin_after["state"]["block"], "changes": M.diff(twin_before["state"], twin_after["state"])[:40], "drift": drift},
                "head": S.chain.block_number()})
            self._log("record", "Blockchain", f"{len(evs)} contract events across {len({e['contract'] for e in evs})} contracts since block {start_block}")
            self._log("record", "Digital twin", f"fingerprint {twin_before['fp']['root'][:12]}… → {twin_after['fp']['root'][:12]}…; drift flags the implant on {TARGET}")
            with self.lock:
                self.state["status"] = "done"
                self.state["finished_at"] = time.time()
        except Exception as e:  # noqa: BLE001
            with self.lock:
                self.state["status"] = "failed"
                self.state["error"] = f"{type(e).__name__}: {e}"
                self.state["trace"] = traceback.format_exc()[-1500:]
        finally:
            LIVE_HOLD.clear()
