"""
Readable live view of the local CascadeShield blockchain.

The Hardhat node's own log prints every raw JSON-RPC call (eth_chainId, eth_getLogs, ...), which hides what is
actually being written. This prints one plain sentence per contract event instead: which organisation did what,
on which contract, in which block. It follows the deployment the backend writes, so a backend restart (fresh
contracts) is picked up automatically. Read-only: it never sends a transaction. On start it switches off
the Hardhat node's raw RPC log (hardhat_setLoggingEnabled false; pass --node-log to keep it).

    .venv\\Scripts\\python.exe scripts\\chain_watch.py            (run from the repository root)
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.common.chain import ORGS, Chain, org_id  # noqa: E402
from backend.common.events import EventIndexer  # noqa: E402

ORG_NAME = {"power": "Grid Utility", "water": "Water Board", "hospital": "City Hospital"}
ORG_KEY = {v: k for k, v in ORG_NAME.items()}
BY_ID = {"0x" + bytes(org_id(o)).hex(): ORG_NAME[o] for o in ORGS}

# AuditLog entry kinds (backend/common/audit.py KINDS)
AUDIT_KIND = {
    0: "sealed agent decision traces",
    1: "sealed its daily risk snapshot",
    2: "sealed a remediation plan",
    3: "anchored the Critic agent's verdict",
    4: "recorded an executed plan",
    5: "recorded an emergency pause",
    6: "recorded a resume",
    7: "recorded the AI model version in use",
    8: "recorded a policy change",
}

EVENT_TEXT = {
    ("AttestationRegistry", "RiskAttestationSubmitted"): "published a sealed risk-band commitment (the band itself stays private)",
    ("AttestationRegistry", "FindingAttestationSubmitted"): "committed a vulnerability finding (blinded, not readable on-chain)",
    ("AttestationRegistry", "DependencyAttestationSubmitted"): "attested a service dependency",
    ("AttestationRegistry", "DependencyEdgeConfirmed"): "dependency confirmed by both organisations",
    ("AttestationRegistry", "DependencyEdgeRevoked"): "dependency revoked",
    ("AttestationRegistry", "ChallengeSubmitted"): "challenged an attestation",
    ("ApprovalGate", "ApprovalRequested"): "asked its human approvers to sign a plan",
    ("ApprovalGate", "Approved"): "a human approver signed the plan",
    ("ApprovalGate", "Rejected"): "a human approver rejected the plan",
    ("ApprovalGate", "ApprovalThresholdReached"): "plan approved: enough human signatures",
    ("ApprovalGate", "RequestRejected"): "plan request closed as rejected",
    ("ApprovalGate", "RequestExpired"): "plan request expired unsigned",
    ("ApprovalGate", "Executed"): "approved plan executed by the Executor agent",
    ("ApprovalGate", "Cancelled"): "plan request cancelled",
    ("AlertBus", "CascadeAlert"): "sent a sealed early-warning alert to a dependent organisation",
    ("AlertBus", "AlertAcknowledged"): "acknowledged a cascade alert",
    ("AlertBus", "AlertResolved"): "resolved a cascade alert",
    ("FirmwareRegistry", "FirmwarePublished"): "registered a known-good firmware hash",
    ("FirmwareRegistry", "FirmwareRevoked"): "revoked a firmware hash",
    ("OrgRegistry", "OrgRegistered"): "organisation registered on the network",
    ("OrgRegistry", "EncryptionKeySet"): "published its encryption key",
    ("OrgRegistry", "ApproverSetUpdated"): "updated its human approver set",
    ("OrgRegistry", "AgentSignerRotated"): "rotated its AI agent signing key",
}

# ANSI colours (Windows Terminal and VS Code render these; --plain turns them off)
C = {"dim": "\033[2m", "b": "\033[1m", "cyan": "\033[36m", "green": "\033[32m", "yellow": "\033[33m", "red": "\033[31m", "mag": "\033[35m", "x": "\033[0m"}
ORG_COLOUR = {"Grid Utility": "cyan", "Water Board": "mag", "City Hospital": "yellow"}


def paint(text: str, colour: str, on: bool) -> str:
    return f"{C[colour]}{text}{C['x']}" if on else text


def org_of(args: dict) -> str:
    for k in ("orgId", "org", "consumerOrg", "providerOrg", "requesterOrg", "senderOrg"):
        v = args.get(k)
        if v is not None and str(v).lower() in BY_ID:
            return BY_ID[str(v).lower()]
    return "Network"


_day_notes: dict = {}


def day_note(api: str, org: str, day) -> str:
    """What the risk agent found for this organisation on this simulated day (cached per org and day)."""
    key = (org, day)
    if key in _day_notes or day is None or org not in ORG_KEY:
        return _day_notes.get(key, "")
    note = ""
    try:
        items = requests.get(f"{api}/api/ps03/orgs/{ORG_KEY[org]}/changes?since_day={max(0, day - 1)}", headers={"X-Dev-Role": "admin"}, timeout=5).json()["items"]
        today = [c for c in items if c.get("to_sim_day") == day]
        moves = [f"{c['asset_id'].split('-asset-')[1]} {c['from_band']}→{c['to_band']}" for c in today if c["from_band"] != c["to_band"]]
        note = f"{len(today)} asset(s) re-scored" + (f", band moves: {', '.join(moves[:3])}" if moves else ", no band change") if today else "no asset changed"
    except Exception:  # noqa: BLE001
        pass
    _day_notes[key] = note
    return note


def describe(e: dict, api: str = "", day=None) -> str:
    a = e.get("args") or {}
    if e["contract"] == "AuditLog" and e["name"] == "Anchored":
        kind = int(a.get("kind", -1))
        what = AUDIT_KIND.get(kind, "anchored an audit record")
        batch = f" ({a.get('count')} in one Merkle batch)" if a.get("isBatch") else ""
        note = day_note(api, org_of(a), day) if kind == 1 else ""
        return f"{what}{batch} · audit #{a.get('index')}" + (f" · {note}" if note else "")
    if e["contract"] == "AttestationRegistry" and e["name"].startswith("Dependency"):
        c, p = BY_ID.get(str(a.get("consumerOrg", "")).lower()), BY_ID.get(str(a.get("providerOrg", "")).lower())
        if c and p:
            return f"{EVENT_TEXT.get((e['contract'], e['name']), e['name'])}: {c} depends on {p}"
    return EVENT_TEXT.get((e["contract"], e["name"]), f"{e['contract']}.{e['name']}")


def tone(e: dict) -> str:
    n = e["name"]
    if n in ("Executed", "ApprovalThresholdReached", "Approved"):
        return "green"
    if n in ("Rejected", "RequestRejected", "RequestExpired", "CascadeAlert", "FirmwareRevoked"):
        return "red"
    return "x"


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows consoles default to a legacy code page
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rpc", default="http://127.0.0.1:8545")
    ap.add_argument("--api", default="http://127.0.0.1:8000", help="backend, for the simulated-day headers")
    ap.add_argument("--deployment", default=str(ROOT / "chain" / "deployments" / "local.json"))
    ap.add_argument("--history", type=int, default=0, help="also print the last N blocks of history at start")
    ap.add_argument("--plain", action="store_true", help="no colours")
    ap.add_argument("--node-log", action="store_true", help="leave the Hardhat node's raw JSON-RPC log on")
    a = ap.parse_args()
    col = not a.plain
    dep = Path(a.deployment)
    tmp = Path(tempfile.mkdtemp(prefix="chainwatch-"))
    print(paint("CascadeShield blockchain · live feed (read-only)", "b", col))
    print(paint(f"node {a.rpc} · contracts from {dep.relative_to(ROOT) if dep.is_relative_to(ROOT) else dep}", "dim", col))

    stamp, indexer, chain, seen, day = None, None, None, -1, None
    while True:
        try:
            m = dep.stat().st_mtime if dep.exists() else None
            if m is None:
                print(paint("waiting for the backend to deploy the contracts…", "dim", col))
                time.sleep(3)
                continue
            if m != stamp:  # first start, or the backend restarted and deployed fresh contracts
                stamp = m
                if not a.node_log:
                    # the node prints every raw RPC call (eth_chainId, eth_getLogs, ...); this feed replaces that noise
                    requests.post(a.rpc, json={"jsonrpc": "2.0", "id": 1, "method": "hardhat_setLoggingEnabled", "params": [False]}, timeout=5)
                chain = Chain(a.rpc, str(dep))
                indexer = EventIndexer(chain, tmp / f"events-{int(m)}.sqlite")
                head = chain.block_number()
                seen = max(0, head - a.history) if a.history else head
                addrs = json.loads(dep.read_text(encoding="utf-8")).get("contracts", {})
                print(paint(f"\n▶ watching {len(addrs)} contracts deployed at block ≤{head}: {', '.join(sorted(addrs))}", "b", col))
            try:
                h = requests.get(f"{a.api}/api/ps03/health", timeout=3).json()
                if h.get("sim_day") != day:
                    day = h.get("sim_day")
                    print(paint(f"\n── Simulated day {day} · {h.get('date', '')} ──", "dim", col))
            except Exception:  # noqa: BLE001  backend down: keep showing the chain
                pass
            indexer.sync()
            evs = sorted((e for e in indexer.query(None, None, 500) if e["block"] > seen), key=lambda x: (x["block"], x["log_index"]))
            for e in evs:
                org = org_of(e.get("args") or {})
                tx = f"{e['tx'][:10]}…{e['tx'][-4:]}"
                line = f"{time.strftime('%H:%M:%S')}  block {e['block']:>5}  {paint(f'{org:<13}', ORG_COLOUR.get(org, 'x'), col)}  {paint(describe(e, a.api, day), tone(e), col)}  {paint(tx, 'dim', col)}"
                print(line, flush=True)
            if evs:
                seen = max(e["block"] for e in evs)
        except KeyboardInterrupt:
            break
        except Exception as ex:  # noqa: BLE001  node restarting etc.: report once per loop and retry
            print(paint(f"(chain not reachable: {str(ex)[:80]} · retrying)", "dim", col), flush=True)
            time.sleep(3)
        time.sleep(1.5)


if __name__ == "__main__":
    main()
