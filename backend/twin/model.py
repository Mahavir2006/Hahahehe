"""
Digital twin of the consortium, built only from contract events.

The twin is a pure function of the event log: replaying the same events always yields the same state and the same
fingerprint, whoever replays them. Nothing here is configured or hardcoded; an organisation, a dependency, a
firmware release or an approval exists in the twin only because a contract event says so.

The state holds public data only (ids, hashes, commitments, statuses). Sealed payloads are not copied into it, so
the shared twin reveals nothing an outsider could not already read from the chain.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, Iterable, List, Optional

from eth_utils import keccak

from backend.common.crypto import canonical_json
from backend.common.merkle import merkle_root

SECTORS = ["Energy", "Water", "Healthcare", "Other"]
IMPACT = ["Low", "Medium", "High"]
ANCHOR_KINDS = ["AgentTrace", "RiskSnapshot", "CriticVerdict", "Execution", "Other"]
SECTIONS = ["orgs", "services", "edges", "findings", "alerts", "approvals", "firmware", "vendors", "audit", "challenges"]


def empty() -> Dict[str, Any]:
    return {"block": -1, "events": 0, **{s: {} for s in SECTIONS}}


def _h(v: Any) -> str:
    return str(v).lower()


def apply(state: Dict[str, Any], ev: Dict[str, Any]) -> None:
    """Apply one decoded contract event (dict with block, contract, name, args) to the twin state in place."""
    a, name, b = ev["args"], ev["name"], ev["block"]
    state["block"] = max(state["block"], b)
    state["events"] += 1

    # ---- organisations
    if name == "OrgRegistered":
        state["orgs"][_h(a["orgId"])] = {
            "sector": SECTORS[a["sector"]] if 0 <= a["sector"] < len(SECTORS) else str(a["sector"]),
            "name_hash": _h(a["nameHash"]), "admin": _h(a["adminAddress"]), "agent": _h(a["agentSigner"]),
            "approvers": [], "threshold": 0, "active": True, "encryption_key": False, "since_block": b,
        }
    elif name == "AgentSignerRotated":
        if (o := state["orgs"].get(_h(a["orgId"]))) is not None:
            o["agent"] = _h(a["newSigner"])
    elif name == "ApproverSetUpdated":
        if (o := state["orgs"].get(_h(a["orgId"]))) is not None:
            o["approvers"], o["threshold"] = sorted(_h(x) for x in a["approvers"]), a["threshold"]
    elif name == "EncryptionKeySet":
        if (o := state["orgs"].get(_h(a["orgId"]))) is not None:
            o["encryption_key"] = True
    elif name in ("OrgDeactivated", "OrgReactivated"):
        if (o := state["orgs"].get(_h(a["orgId"]))) is not None:
            o["active"] = name == "OrgReactivated"

    # ---- dependencies (bilateral: each side submits; the contract confirms when both agree)
    elif name == "DependencyAttestationSubmitted":
        e = state["edges"].setdefault(_h(a["edgeId"]), {
            "consumer_org": _h(a["consumerOrg"]), "consumer_service": _h(a["consumerServiceHash"]),
            "provider_org": _h(a["providerOrg"]), "provider_service": _h(a["providerServiceHash"]),
            "terms_commitment": _h(a["termsCommitment"]), "status": "pending", "signers": [], "since_block": b,
        })
        if _h(a["signer"]) not in e["signers"]:
            e["signers"] = sorted(e["signers"] + [_h(a["signer"])])
        for side in ("consumer", "provider"):
            _service(state, e[f"{side}_org"], e[f"{side}_service"])
    elif name == "DependencyEdgeConfirmed":
        if (e := state["edges"].get(_h(a["edgeId"]))) is not None:
            e["status"] = "confirmed"
    elif name in ("DependencyEdgeRevoked", "DependencyEdgeExpired", "DependencyEdgeDisputed"):
        if (e := state["edges"].get(_h(a["edgeId"]))) is not None:
            e["status"] = {"DependencyEdgeRevoked": "revoked", "DependencyEdgeExpired": "expired", "DependencyEdgeDisputed": "disputed"}[name]

    # ---- risk, findings, challenges
    elif name == "RiskAttestationSubmitted":
        s = _service(state, _h(a["orgId"]), _h(a["serviceHash"]))
        s["attestations"] += 1
        s["band_commitment"], s["last_attested_block"] = _h(a["bandCommitment"]), b
    elif name == "RiskAttestationExpired":
        if (s := state["services"].get(_h(a["serviceHash"]))) is not None:
            s["band_commitment"] = None
    elif name == "FindingAttestationSubmitted":
        f = state["findings"].setdefault(_h(a["orgId"]), {"count": 0, "last_block": b})
        f["count"] += 1
        f["last_block"] = b
    elif name == "ChallengeSubmitted":
        state["challenges"][_h(a["attestationId"])] = state["challenges"].get(_h(a["attestationId"]), 0) + 1

    # ---- cascade alerts
    elif name == "CascadeAlert":
        state["alerts"][_h(a["alertId"])] = {
            "provider_org": _h(a["providerOrg"]), "provider_service": _h(a["providerServiceHash"]),
            "commitment": _h(a["alertCommitment"]), "expiry": a["expiry"], "status": "open", "acks": [], "dedupes": 0, "since_block": b,
        }
    elif name == "AlertDeduplicated":
        if (al := state["alerts"].get(_h(a["alertId"]))) is not None:
            al["dedupes"] += 1
    elif name == "AlertAcknowledged":
        if (al := state["alerts"].get(_h(a["alertId"]))) is not None:
            if _h(a["consumerOrg"]) not in al["acks"]:
                al["acks"] = sorted(al["acks"] + [_h(a["consumerOrg"])])
            if al["status"] == "open":
                al["status"] = "acknowledged"
    elif name == "AlertResolved":
        if (al := state["alerts"].get(_h(a["alertId"]))) is not None:
            al["status"] = "resolved"

    # ---- human approvals
    elif name == "ApprovalRequested":
        state["approvals"][_h(a["requestId"])] = {
            "org": _h(a["orgId"]), "plan_hash": _h(a["planHash"]), "impact": IMPACT[a["impact"]] if a["impact"] < len(IMPACT) else str(a["impact"]),
            "expiry": a["expiry"], "required": a["required"], "votes": [], "status": "pending", "since_block": b,
        }
    elif name == "Approved":
        if (r := state["approvals"].get(_h(a["requestId"]))) is not None and _h(a["approver"]) not in r["votes"]:
            r["votes"] = sorted(r["votes"] + [_h(a["approver"])])
    elif name in ("ApprovalThresholdReached", "RequestRejected", "RequestExpired", "Executed", "Cancelled"):
        if (r := state["approvals"].get(_h(a["requestId"]))) is not None:
            r["status"] = {"ApprovalThresholdReached": "approved", "RequestRejected": "rejected", "RequestExpired": "expired",
                           "Executed": "executed", "Cancelled": "cancelled"}[name]

    # ---- firmware supply chain
    elif name == "VendorAdded":
        state["vendors"][_h(a["vendorId"])] = {"address": _h(a["vendorAddress"]), "active": True}
    elif name == "VendorRemoved":
        if (v := state["vendors"].get(_h(a["vendorId"]))) is not None:
            v["active"] = False
    elif name == "FirmwarePublished":
        state["firmware"][fw_key(a["vendorId"], a["modelHash"], a["versionHash"])] = {
            "sha256": _h(a["firmwareSha256"]), "sbom": _h(a["sbomHash"]), "publisher": _h(a["publisher"]), "revoked": False, "since_block": b,
        }
    elif name == "FirmwareRevoked":
        if (f := state["firmware"].get(fw_key(a["vendorId"], a["modelHash"], a["versionHash"]))) is not None:
            f["revoked"], f["revoked_reason"] = True, a["reason"]

    # ---- audit anchors
    elif name == "Anchored":
        k = state["audit"].setdefault(_h(a["orgId"]), {"anchors": 0, "batches": 0, "by_kind": {}, "last_digest": None})
        k["anchors"] += 1
        k["batches"] += 1 if a["isBatch"] else 0
        kind = ANCHOR_KINDS[a["kind"]] if a["kind"] < len(ANCHOR_KINDS) else str(a["kind"])
        k["by_kind"][kind] = k["by_kind"].get(kind, 0) + 1
        k["last_digest"] = _h(a["digest"])


def _service(state: Dict[str, Any], org: str, svc: str) -> Dict[str, Any]:
    return state["services"].setdefault(svc, {"org": org, "attestations": 0, "band_commitment": None, "last_attested_block": None})


def fw_key(vendor: Any, model: Any, version: Any) -> str:
    return f"{_h(vendor)}|{_h(model)}|{_h(version)}"


def order(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(events, key=lambda e: (e["block"], e["log_index"]))


def build(events: Iterable[Dict[str, Any]], upto_block: Optional[int] = None) -> Dict[str, Any]:
    """Replay events (any order; they are sorted by block and log index) into a fresh twin."""
    st = empty()
    for ev in order(events):
        if upto_block is not None and ev["block"] > upto_block:
            break
        apply(st, ev)
    return st


def fingerprint(state: Dict[str, Any]) -> Dict[str, Any]:
    """Merkle root over one keccak leaf per section (canonical JSON), so a mismatch also says which section differs."""
    sections = {s: "0x" + keccak(canonical_json(state[s]).encode()).hex() for s in SECTIONS}
    root = merkle_root([bytes.fromhex(sections[s][2:]) for s in SECTIONS])
    return {"root": "0x" + root.hex(), "sections": sections}


def timeline(events: Iterable[Dict[str, Any]], max_points: int = 400) -> List[Dict[str, Any]]:
    """Fingerprint after every block that changed the twin (thinned evenly to max_points), for replay and time travel."""
    evs = order(events)
    blocks = sorted({e["block"] for e in evs})
    keep = set(blocks if len(blocks) <= max_points else [blocks[round(i * (len(blocks) - 1) / (max_points - 1))] for i in range(max_points)])
    st, out, i = empty(), [], 0
    for blk in blocks:
        names: Dict[str, int] = {}
        while i < len(evs) and evs[i]["block"] == blk:
            apply(st, evs[i])
            names[evs[i]["name"]] = names.get(evs[i]["name"], 0) + 1
            i += 1
        if blk in keep:
            out.append({"block": blk, "root": fingerprint(st)["root"], "events": st["events"], "counts": summary(st), "changes": names})
    return out


def summary(state: Dict[str, Any]) -> Dict[str, int]:
    e = state["edges"].values()
    return {
        "orgs": len(state["orgs"]), "services": len(state["services"]),
        "edges_confirmed": sum(x["status"] == "confirmed" for x in e), "edges_pending": sum(x["status"] == "pending" for x in e),
        "alerts_open": sum(x["status"] == "open" for x in state["alerts"].values()), "alerts": len(state["alerts"]),
        "approvals_pending": sum(x["status"] == "pending" for x in state["approvals"].values()), "approvals": len(state["approvals"]),
        "firmware": len(state["firmware"]), "firmware_revoked": sum(x["revoked"] for x in state["firmware"].values()),
        "anchors": sum(x["anchors"] for x in state["audit"].values()), "findings": sum(x["count"] for x in state["findings"].values()),
    }


def reach(state: Dict[str, Any]) -> Dict[str, List[str]]:
    """For each organisation: the other organisations a failure in it can reach through confirmed dependencies
    (provider service -> consumer service), following chains across organisations."""
    down: Dict[str, List[str]] = {}
    for e in state["edges"].values():
        if e["status"] == "confirmed":
            down.setdefault(e["provider_service"], []).append(e["consumer_service"])
    out: Dict[str, List[str]] = {}
    for org in state["orgs"]:
        start = [s for s, v in state["services"].items() if v["org"] == org]
        seen, stack = set(start), list(start)
        while stack:
            for nxt in down.get(stack.pop(), []):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        out[org] = sorted({state["services"][s]["org"] for s in seen if s in state["services"]} - {org})
    return out


def reach_services(state: Dict[str, Any]) -> Dict[str, int]:
    """For each organisation: how many services in OTHER organisations a failure in it can reach."""
    down: Dict[str, List[str]] = {}
    for e in state["edges"].values():
        if e["status"] == "confirmed":
            down.setdefault(e["provider_service"], []).append(e["consumer_service"])
    out: Dict[str, int] = {}
    for org in state["orgs"]:
        seen = {s for s, v in state["services"].items() if v["org"] == org}
        stack = list(seen)
        while stack:
            for nxt in down.get(stack.pop(), []):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        out[org] = sum(1 for s in seen if s in state["services"] and state["services"][s]["org"] != org)
    return out


def diff(before: Dict[str, Any], after: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Field-level changes between two twins (used to show what a what-if changed)."""
    out: List[Dict[str, Any]] = []
    for s in SECTIONS:
        b, a = before[s], after[s]
        for k in sorted(set(b) | set(a)):
            if k not in b:
                out.append({"section": s, "key": k, "change": "added"})
            elif k not in a:
                out.append({"section": s, "key": k, "change": "removed"})
            elif b[k] != a[k]:
                fields = sorted(f for f in set(b[k]) | set(a[k]) if b[k].get(f) != a[k].get(f)) if isinstance(b[k], dict) and isinstance(a[k], dict) else []
                out.append({"section": s, "key": k, "change": "modified", "fields": {f: [b[k].get(f), a[k].get(f)] for f in fields}})
    return out


def snapshot(state: Dict[str, Any]) -> Dict[str, Any]:
    return copy.deepcopy(state)
