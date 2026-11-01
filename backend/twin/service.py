"""
Live digital twin service: keeps the twin in step with the chain and answers what the API asks.

* live()      the twin at the chain head, rebuilt from the indexer whenever new blocks arrive
* at(block)   time travel: the twin exactly as it was after any earlier block
* overlay()   what one organisation adds privately: its own service names, the bands and dependency terms it can
              open from sealed envelopes (checked against the on-chain commitments), its assets' firmware status
* verify()    every organisation replays the chain over its own connection and must reach the same fingerprint;
              the twin is also cross-checked against the contracts' own view functions
* drift()     where reality and the twin disagree (stale attestations, untrusted firmware, unacknowledged alerts...)
* fork()      run a real what-if transaction on a snapshot of the chain, read the forked twin, then roll back
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, List, Optional

from eth_account import Account
from eth_utils import keccak

from backend.agents.org_node import BAND, CRIT
from backend.common import sealed
from backend.common.chain import ORG_NAMES, ORGS, ROOT, ChainRevert, org_id
from backend.twin import model as M
from backend.twin.source import chain_events, indexer_events

BAND_NAME = {v: k for k, v in BAND.items()}
CRIT_NAME = {v: k for k, v in CRIT.items()}
EDGE_STATE = ["proposed", "confirmed", "revoked", "expired", "disputed"]
REQ_STATUS = ["none", "pending", "approved", "rejected", "expired", "executed", "cancelled"]
FW_STATUS = ["Match", "Mismatch", "Unknown", "Revoked"]
ORG_IDS = {o: "0x" + org_id(o).hex() for o in ORGS}


def _b(h: str) -> bytes:
    return bytes.fromhex(str(h)[2:] if str(h).startswith("0x") else str(h))


class TwinService:
    def __init__(self, system):
        self.S = system
        self._lock = threading.Lock()
        self._cache: Optional[Dict[str, Any]] = None  # {"key": (last_block, count), "events", "state", "fp"}

    # ------------------------------------------------------------------ live state
    def _events(self) -> List[Dict[str, Any]]:
        with self.S.chain.gate:  # never index while a what-if fork is open
            self.S.indexer.sync()
        return indexer_events(self.S.indexer)

    def live(self) -> Dict[str, Any]:
        with self._lock:
            evs = self._events()
            key = (self.S.indexer.last_block(), len(evs))
            if not self._cache or self._cache["key"] != key:
                st = M.build(evs)
                st["block"] = key[0]  # the chain head the twin is in step with (may be past the last event)
                self._cache = {"key": key, "events": evs, "state": st, "fp": M.fingerprint(st)}
            return self._cache

    def at(self, block: int) -> Dict[str, Any]:
        evs = self.live()["events"]
        st = M.build(evs, upto_block=block)
        st["block"] = block
        return {"events": [e for e in evs if e["block"] <= block], "state": st, "fp": M.fingerprint(st)}

    def labels(self) -> Dict[str, str]:
        """Consortium members' display names (an org id is keccak of the member's name)."""
        return dict(ORG_NAMES)

    def public(self, snap: Dict[str, Any]) -> Dict[str, Any]:
        st = snap["state"]
        return {
            "block": st["block"], "events": st["events"], "fingerprint": snap["fp"], "summary": M.summary(st),
            "reach": M.reach(st), "org_names": {k: v for k, v in self.labels().items() if k in st["orgs"]},
            "state": {s: st[s] for s in M.SECTIONS},
        }

    def timeline(self, max_points: int = 400) -> List[Dict[str, Any]]:
        return M.timeline(self.live()["events"], max_points=max_points)

    # ------------------------------------------------------------------ private overlay
    def overlay(self, org: str, snap: Dict[str, Any]) -> Dict[str, Any]:
        n = self.S.nodes[org]
        st, evs = snap["state"], snap["events"]
        own = {"0x" + n.svc_hash(sid).hex(): sid for sid in n.services}
        last_risk: Dict[str, Dict[str, Any]] = {}
        for e in evs:
            if e["name"] == "RiskAttestationSubmitted" and e["args"]["serviceHash"].lower() in own:
                last_risk[e["args"]["serviceHash"].lower()] = e["args"]
        current = n.service_band()
        services = []
        for h, sid in own.items():
            attested = None
            if (a := last_risk.get(h)) is not None:
                d = n.open_disclosure(a["sealedBand"])
                if d and d.get("kind") == "risk" and sealed.band_commitment(_b(d["salt"]), d["band"], d["crit"]) == _b(a["bandCommitment"]):
                    attested = BAND_NAME.get(d["band"])
            services.append({
                "service_hash": h, "service_id": sid, "name": n.services[sid]["name"], "in_twin": h in st["services"],
                "attested_band": attested, "current_band": current.get(sid, {}).get("band"), "criticality": n.services[sid]["criticality"],
            })
        edges = []
        terms_by_edge = {}
        for e in evs:
            if e["name"] == "DependencyAttestationSubmitted":
                terms_by_edge[e["args"]["edgeId"].lower()] = e["args"]
        for eid, ed in st["edges"].items():
            if ORG_IDS.get(org) not in (ed["consumer_org"], ed["provider_org"]):
                continue
            a = terms_by_edge.get(eid)
            d = n.open_disclosure(a["sealedTerms"]) if a else None
            ok = bool(d and d.get("kind") == "dependency" and sealed.terms_commitment(_b(d["salt"]), d["strength"], d["tolerance"]) == _b(ed["terms_commitment"]))
            edges.append({"edge_id": eid, "status": ed["status"], "terms_verified": ok, "strength": d.get("strength") if ok else None, "tolerance": d.get("tolerance") if ok else None,
                          "own_service": own.get(ed["consumer_service"]) or own.get(ed["provider_service"])})
        assets = []
        for aid, a in n.inventory.items():
            f = st["firmware"].get(M.fw_key("0x" + keccak(text=a["vendor"]).hex(), "0x" + keccak(text=a["model"]).hex(), "0x" + keccak(text=a["firmware_version"]).hex()))
            status = "Unknown" if f is None else "Revoked" if f["revoked"] else "Match" if f["sha256"] == a["observed_firmware_sha256"].lower() else "Mismatch"
            assets.append({"asset_id": aid, "vendor": a["vendor"], "model": a["model"], "version": a["firmware_version"], "firmware": status})
        return {"org": org, "services": services, "edges": edges, "assets": assets}

    # ------------------------------------------------------------------ verification
    def verify(self) -> Dict[str, Any]:
        snap = self.live()
        height = snap["state"]["block"]
        nodes = []
        for org in self.S.nodes:
            t0 = time.perf_counter()
            evs = chain_events(self.S.chain.rpc_url, self.S.chain.contracts, upto_block=height)  # own connection, own decoding
            fp = M.fingerprint(M.build(evs))
            nodes.append({"org": org, "root": fp["root"], "events": len(evs), "agrees": fp["root"] == snap["fp"]["root"],
                          "seconds": round(time.perf_counter() - t0, 3),
                          "differs_in": [s for s in M.SECTIONS if fp["sections"][s] != snap["fp"]["sections"][s]]})
        checks = self.contract_checks(snap["state"])
        return {"height": height, "twin_root": snap["fp"]["root"], "nodes": nodes, "contract_checks": checks,
                "all_agree": all(x["agrees"] for x in nodes) and all(c["ok"] == c["total"] for c in checks.values())}

    def contract_checks(self, st: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Ask the contracts directly and compare with the twin (at the current head)."""
        c = self.S.chain
        res: Dict[str, Dict[str, Any]] = {}
        ok = [c.call("OrgRegistry", "isOrgActive", _b(o)) == v["active"] for o, v in st["orgs"].items()]
        res["orgs"] = {"ok": sum(ok), "total": len(ok)}
        ok = []
        for e in st["edges"].values():
            s = int(c.call("AttestationRegistry", "getEdgeState", _b(e["consumer_org"]), _b(e["consumer_service"]), _b(e["provider_org"]), _b(e["provider_service"])))
            ok.append(EDGE_STATE[s] == ("proposed" if e["status"] == "pending" else e["status"]))
        res["edges"] = {"ok": sum(ok), "total": len(ok)}
        ok = []
        now = c.block_timestamp()
        for rid, r in st["approvals"].items():
            s = REQ_STATUS[int(c.call("ApprovalGate", "getRequest", _b(rid))[4])]
            # the contract reports an unexecuted request past its expiry as expired even before anyone calls expire()
            want = "expired" if r["status"] in ("pending", "approved") and r["expiry"] <= now and s == "expired" else r["status"]
            ok.append(s == want)
        res["approvals"] = {"ok": sum(ok), "total": len(ok)}
        ok = []
        for org, n in self.S.nodes.items():
            ov = {a["asset_id"]: a["firmware"] for a in self.overlay(org, {"state": st, "events": []})["assets"]}
            for aid, a in n.inventory.items():
                r = c.call("FirmwareRegistry", "verifyFirmware", keccak(text=a["vendor"]), keccak(text=a["model"]), keccak(text=a["firmware_version"]), _b(a["observed_firmware_sha256"]))
                ok.append(FW_STATUS[int(r)] == ov[aid])
        res["firmware"] = {"ok": sum(ok), "total": len(ok)}
        return res

    # ------------------------------------------------------------------ drift
    def drift(self, snap: Dict[str, Any], org: Optional[str] = None) -> List[Dict[str, Any]]:
        st = snap["state"]
        names = self.labels()
        nm = lambda o: names.get(o, o[:10])  # noqa: E731
        now = self.S.chain.block_timestamp()
        out: List[Dict[str, Any]] = []
        for o in ([org] if org else list(self.S.nodes)):
            ov = self.overlay(o, snap)
            for s in ov["services"]:
                if s["attested_band"] is None:
                    out.append({"kind": "unattested", "severity": "medium", "org": o, "subject": s["name"],
                                "detail": f"{s['name']} has no readable risk attestation on the chain yet"})
                elif s["current_band"] and s["current_band"] != s["attested_band"]:
                    worse = BAND.get(s["current_band"], 0) > BAND.get(s["attested_band"], 0)
                    out.append({"kind": "stale_attestation", "severity": "high" if worse else "low", "org": o, "subject": s["name"],
                                "detail": f"chain says {s['attested_band']}, live assessment says {s['current_band']}"})
            for a in ov["assets"]:
                if a["firmware"] != "Match":
                    out.append({"kind": "firmware", "severity": "high" if a["firmware"] in ("Revoked", "Mismatch") else "medium", "org": o, "subject": a["asset_id"],
                                "detail": f"{a['vendor']} {a['model']} {a['version']}: registry says {a['firmware']}"})
        mine = (lambda oid: True) if not org else (lambda oid: oid == ORG_IDS[org])  # noqa: E731
        for aid, al in st["alerts"].items():
            if al["status"] == "open" and mine(al["provider_org"]):
                late = al["expiry"] <= now
                out.append({"kind": "unacknowledged_alert", "severity": "high" if late else "medium", "org": names.get(al["provider_org"]), "subject": aid[:12],
                            "detail": "cascade alert expired without acknowledgement" if late else "cascade alert not yet acknowledged by any consumer"})
        for eid, e in st["edges"].items():
            if not (mine(e["consumer_org"]) or mine(e["provider_org"])):
                continue
            if e["status"] == "pending":
                out.append({"kind": "one_sided_dependency", "severity": "low", "org": names.get(e["consumer_org"]), "subject": eid[:12],
                            "detail": f"{nm(e['consumer_org'])} declared a dependency on {nm(e['provider_org'])} that has not confirmed it"})
            if e["status"] == "confirmed" and not all(st["orgs"].get(x, {}).get("active", False) for x in (e["consumer_org"], e["provider_org"])):
                out.append({"kind": "inactive_party", "severity": "high", "org": names.get(e["consumer_org"]), "subject": eid[:12],
                            "detail": f"confirmed dependency between {nm(e['consumer_org'])} and {nm(e['provider_org'])} involves a deactivated organisation"})
        for rid, r in st["approvals"].items():
            if r["status"] == "pending" and r["expiry"] <= now and mine(r["org"]):
                out.append({"kind": "stale_approval", "severity": "medium", "org": names.get(r["org"]), "subject": rid[:12],
                            "detail": "approval request passed its expiry while still pending"})
        rank = {"high": 0, "medium": 1, "low": 2}
        return sorted(out, key=lambda d: (rank[d["severity"]], d["kind"], str(d["org"]), d["subject"]))

    # ------------------------------------------------------------------ what-if forks
    def scenarios(self) -> Dict[str, List[Dict[str, Any]]]:
        st = self.live()["state"]
        names = self.labels()
        base = sum(M.reach_services(st).values())
        edges = []
        for eid, e in st["edges"].items():
            if e["status"] != "confirmed" or e["provider_org"] == e["consumer_org"]:
                continue
            cut = M.snapshot(st)
            cut["edges"][eid]["status"] = "revoked"
            drop = base - sum(M.reach_services(cut).values())
            edges.append({"target": eid, "cuts": drop,
                          "label": f"{names.get(e['provider_org'], '?')} → {names.get(e['consumer_org'], '?')} (cuts {drop} downstream service path{'s' if drop != 1 else ''})"})
        edges.sort(key=lambda x: -x["cuts"])
        orgs = [{"target": oid, "label": names.get(oid, oid[:10])} for oid, o in st["orgs"].items() if o["active"]]
        used: Dict[str, int] = {}
        for n in self.S.nodes.values():
            for a in n.inventory.values():
                k = M.fw_key("0x" + keccak(text=a["vendor"]).hex(), "0x" + keccak(text=a["model"]).hex(), "0x" + keccak(text=a["firmware_version"]).hex())
                used[k] = used.get(k, 0) + 1
        cat = {M.fw_key("0x" + keccak(text=e["vendor"]).hex(), "0x" + keccak(text=e["model"]).hex(), "0x" + keccak(text=e["version"]).hex()): e for e in self._catalog()}
        fw = [{"target": k, "label": f"{cat[k]['vendor']} {cat[k]['model']} {cat[k]['version']} ({used[k]} assets)"}
              for k, f in st["firmware"].items() if not f["revoked"] and k in cat and used.get(k)]
        return {"segment_edge": edges, "revoke_firmware": sorted(fw, key=lambda x: x["label"]), "deactivate_org": orgs}

    @staticmethod
    def _catalog() -> List[Dict[str, Any]]:
        return json.loads((ROOT / "data" / "firmware_catalog.json").read_text(encoding="utf-8"))

    def _rpc(self, method: str, params: list) -> Any:
        r = self.S.chain.w3.provider.make_request(method, params)
        if "error" in r:
            raise RuntimeError(f"{method}: {r['error']}")
        return r["result"]

    def fork(self, kind: str, target: str) -> Dict[str, Any]:
        """Snapshot the chain, send ONE real transaction for the what-if, rebuild the twin from the forked chain,
        then revert. The live writer and the indexer are held off for the duration, so nothing real is lost."""
        c = self.S.chain
        with self._lock, c.gate:
            before_evs = chain_events(c.rpc_url, c.contracts)
            before = M.build(before_evs)
            head_before, root_before = c.block_number(), M.fingerprint(before)["root"]
            snap_id = self._rpc("evm_snapshot", [])
            tx: Dict[str, Any] = {}
            try:
                tx = self._what_if(kind, target, before)
                after_evs = chain_events(c.rpc_url, c.contracts)
                after = M.build(after_evs)
                forked = {"head": c.block_number(), "root": M.fingerprint(after)["root"],
                          "changes": M.diff(before, after), "reach_before": M.reach(before), "reach_after": M.reach(after),
                          "reach_services_before": M.reach_services(before), "reach_services_after": M.reach_services(after)}
                fork_drift = self.drift({"state": after, "events": after_evs})
            finally:
                reverted = self._rpc("evm_revert", [snap_id])
            # drift the what-if created (not the drift that already existed before the fork)
            key = lambda d: (d["kind"], str(d["org"]), d["subject"], d["detail"])  # noqa: E731
            existing = {key(d) for d in self.drift({"state": before, "events": before_evs})}
            forked["drift"] = fork_drift
            forked["new_drift"] = [d for d in fork_drift if key(d) not in existing]
            head_after = c.block_number()
            root_after = M.fingerprint(M.build(chain_events(c.rpc_url, c.contracts)))["root"]
        return {"kind": kind, "target": target, "transaction": tx, "forked": forked,
                "rolled_back": {"reverted": bool(reverted), "head_before": head_before, "head_after": head_after,
                                "root_before": root_before, "root_after": root_after,
                                "untouched": bool(reverted) and head_after == head_before and root_after == root_before}}

    def _what_if(self, kind: str, target: str, st: Dict[str, Any]) -> Dict[str, Any]:
        c = self.S.chain
        names = self.labels()
        try:
            if kind == "segment_edge":
                e = st["edges"][target]
                signer = f"{names[e['consumer_org']]}/agent"
                rc = c.transact("AttestationRegistry", "revokeDependencyAttestation",
                                [_b(e["consumer_org"]), _b(e["consumer_service"]), _b(e["provider_org"]), _b(e["provider_service"])], signer)
                what = f"{names[e['consumer_org']]} revokes its dependency on {names[e['provider_org']]} (network segmentation)"
            elif kind == "revoke_firmware":
                v, m, ver = target.split("|")
                entry = next(x for x in self._catalog() if "0x" + keccak(text=x["vendor"]).hex() == v and "0x" + keccak(text=x["model"]).hex() == m and "0x" + keccak(text=x["version"]).hex() == ver)
                signer = f"vendor/{entry['vendor']}"
                c.accounts.setdefault(signer, Account.from_key(keccak(text="vendor-key-" + entry["vendor"])))  # same derivation as chain/scripts/seed.ts
                rc = c.transact("FirmwareRegistry", "revokeFirmware", [_b(v), _b(m), _b(ver), 1], signer)
                what = f"{entry['vendor']} revokes firmware {entry['model']} {entry['version']} (compromised release)"
            elif kind == "deactivate_org":
                rc = c.transact("OrgRegistry", "deactivateOrg", [_b(target)], "deployer")
                what = f"the consortium deactivates {names.get(target, target[:10])} (organisation offline)"
            else:
                raise ValueError(f"unknown what-if {kind}")
        except KeyError as e:
            raise ValueError(f"unknown target for {kind}: {e}") from e
        except ChainRevert as e:
            raise ValueError(f"the contract refused the what-if: {e.name}") from e
        return {"description": what, "tx_hash": rc.get("tx_hash") or rc.get("transactionHash"), "block": rc.get("block") or rc.get("blockNumber")}
