"""
Audit anchoring (BC-AUD-*, BC-INT-04, BC-AUD-07).

Every agent trace is stored as a JSON file whose digest is the canonical sha256 of its content
(excluding the digest field itself). Digests are batched into Merkle roots and anchored on-chain in
a per-org hash chain. `verify` recomputes everything from local files and compares with the chain,
reporting the first mismatching entry.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from eth_abi import encode as abi_encode
from eth_utils import keccak

from backend.common.chain import Chain, ChainRevert, ChainUnavailable, ChainWriter, org_id
from backend.common.crypto import canonical_hash
from backend.common.merkle import merkle_proof, merkle_root, verify_proof

ZERO = b"\x00" * 32
KINDS = {"AgentTrace": 0, "RiskSnapshot": 1, "Plan": 2, "CriticVerdict": 3, "Execution": 4, "Pause": 5, "Resume": 6, "ModelVersion": 7, "Policy": 8}


def content_digest(obj: Dict[str, Any], exclude: tuple = ("digest", "anchor")) -> bytes:
    """32-byte digest of a JSON document (canonical sha256), ignoring bookkeeping fields."""
    body = {k: v for k, v in obj.items() if k not in exclude}
    return bytes.fromhex(canonical_hash(body).replace("0x", ""))


def entry_hash(org: str, kind: int, digest: bytes, prev: bytes, meta: bytes, index: int, is_batch: bool, count: int) -> bytes:
    """Mirror of AuditLog.computeEntryHash (checked against the contract in tests)."""
    return keccak(abi_encode(["bytes32", "uint8", "bytes32", "bytes32", "bytes32", "uint256", "bool", "uint256"], [org_id(org), kind, digest, prev, meta, index, is_batch, count]))


class AuditAnchorService:
    def __init__(self, chain: Chain, writer: ChainWriter, org: str, state_dir: Path | str):
        self.chain, self.writer, self.org = chain, writer, org
        self.dir = Path(state_dir)
        self.trace_dir = self.dir / "traces" / org
        self.trace_dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "audit").mkdir(parents=True, exist_ok=True)
        self.log_path = self.dir / "audit" / f"{org}.jsonl"
        self.queue_path = self.dir / "audit" / f"{org}.queue.json"
        self._lock = threading.RLock()

    # ------------------------------------------------------------- traces
    def save_trace(self, trace: Dict[str, Any]) -> bytes:
        digest = content_digest(trace)
        trace["digest"] = "0x" + digest.hex()
        (self.trace_dir / f"{trace['trace_id']}.json").write_text(json.dumps(trace, indent=2, sort_keys=True), encoding="utf-8")
        with self._lock:
            q = self._queue()
            if trace["trace_id"] not in [x["trace_id"] for x in q]:
                q.append({"trace_id": trace["trace_id"], "digest": trace["digest"]})
                self._save_queue(q)
        return digest

    def _queue(self) -> List[dict]:
        return json.loads(self.queue_path.read_text(encoding="utf-8")) if self.queue_path.exists() else []

    def _save_queue(self, q: List[dict]) -> None:
        self.queue_path.write_text(json.dumps(q), encoding="utf-8")

    # ------------------------------------------------------------- anchors
    def _local_entries(self) -> List[dict]:
        if not self.log_path.exists():
            return []
        return [json.loads(l) for l in self.log_path.read_text(encoding="utf-8").splitlines() if l.strip()]

    def _append_local(self, e: dict) -> None:
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(e, sort_keys=True) + "\n")

    def anchor(self, kind: str, digest: bytes, meta: bytes = ZERO, idem: Optional[str] = None, signer: Optional[str] = None) -> dict:
        """Anchor a single digest. Idempotent: the same (kind, digest) is never written twice."""
        k = KINDS[kind]
        key = idem or f"anchor:{self.org}:{k}:{digest.hex()}"
        with self._lock:
            for e in self._local_entries():
                if e["key"] == key:
                    return e
            prev = self.chain.call("AuditLog", "lastDigest", org_id(self.org))
            index = self.chain.call("AuditLog", "length", org_id(self.org))
            res = self.writer.submit(key, "AuditLog", "anchor", [org_id(self.org), k, digest, prev, meta], signer or f"{self.org}/agent")
            if res.status == "deferred":
                return {"key": key, "status": "deferred"}
            e = {
                "key": key, "index": index, "kind": k, "is_batch": False, "digest": "0x" + digest.hex(), "prev": "0x" + bytes(prev).hex(),
                "meta": "0x" + meta.hex(), "count": 1, "leaves": [], "tx": res.tx_hash, "status": "anchored",
            }
            self._append_local(e)
            return e

    def flush_traces(self, min_batch: int = 1) -> Optional[dict]:
        """Anchor queued trace digests as one Merkle batch."""
        with self._lock:
            q = self._queue()
            if len(q) < min_batch or not q:
                return None
            leaves = [bytes.fromhex(x["digest"][2:]) for x in q]
            root = merkle_root(leaves)
            key = f"batch:{self.org}:{root.hex()}"
            for e in self._local_entries():
                if e["key"] == key:
                    self._save_queue([])
                    return e
            prev = self.chain.call("AuditLog", "lastDigest", org_id(self.org))
            index = self.chain.call("AuditLog", "length", org_id(self.org))
            res = self.writer.submit(key, "AuditLog", "anchorBatch", [org_id(self.org), KINDS["AgentTrace"], root, len(leaves), prev], f"{self.org}/agent")
            if res.status == "deferred":
                return {"key": key, "status": "deferred"}
            e = {
                "key": key, "index": index, "kind": KINDS["AgentTrace"], "is_batch": True, "digest": "0x" + root.hex(), "prev": "0x" + bytes(prev).hex(),
                "meta": "0x" + ZERO.hex(), "count": len(leaves), "leaves": [x["trace_id"] for x in q], "leaf_digests": [x["digest"] for x in q],
                "tx": res.tx_hash, "status": "anchored",
            }
            self._append_local(e)
            self._save_queue([])
            return e

    def inclusion_proof(self, trace_id: str) -> Optional[dict]:
        for e in self._local_entries():
            if e["is_batch"] and trace_id in e["leaves"]:
                leaves = [bytes.fromhex(d[2:]) for d in e["leaf_digests"]]
                i = e["leaves"].index(trace_id)
                proof = merkle_proof(leaves, i)
                return {"entry_index": e["index"], "leaf": e["leaf_digests"][i], "proof": ["0x" + p.hex() for p in proof], "root": e["digest"]}
        return None

    def verify_inclusion_onchain(self, trace_id: str) -> bool:
        p = self.inclusion_proof(trace_id)
        if not p:
            return False
        return bool(self.chain.call("AuditLog", "verifyInclusion", org_id(self.org), p["entry_index"], bytes.fromhex(p["leaf"][2:]), [bytes.fromhex(x[2:]) for x in p["proof"]]))

    # -------------------------------------------------------------- verify
    def verify(self) -> Dict[str, Any]:
        """Recompute the hash chain and every batch root from LOCAL files; compare with the chain (BC-AUD-07)."""
        entries = self._local_entries()
        oid = org_id(self.org)
        chain_len = self.chain.call("AuditLog", "length", oid)
        if chain_len < len(entries):
            return {"ok": False, "first_mismatch": chain_len, "reason": "chain has fewer entries than the local log"}
        prev_hash = ZERO
        for e in entries:
            i = e["index"]
            digest = bytes.fromhex(e["digest"][2:])
            if e["is_batch"]:
                leaf_digests = []
                for tid, stored in zip(e["leaves"], e["leaf_digests"]):
                    f = self.trace_dir / f"{tid}.json"
                    if not f.exists():
                        return {"ok": False, "first_mismatch": i, "reason": f"trace file {tid} is missing"}
                    doc = json.loads(f.read_text(encoding="utf-8"))
                    d = "0x" + content_digest(doc).hex()
                    if d != stored or doc.get("digest") != stored:
                        return {"ok": False, "first_mismatch": i, "reason": f"trace {tid} content does not match its anchored digest"}
                    leaf_digests.append(bytes.fromhex(d[2:]))
                if merkle_root(leaf_digests) != digest:
                    return {"ok": False, "first_mismatch": i, "reason": "recomputed Merkle root differs from the anchored root"}
            on = self.chain.call("AuditLog", "getAnchor", oid, i)
            # (kind, isBatch, digest, prevDigest, metaHash, count, timestamp, signer)
            on_digest, on_prev = bytes(on[2]), bytes(on[3])
            if on_digest != digest:
                return {"ok": False, "first_mismatch": i, "reason": "on-chain digest differs from the local record"}
            if on_prev != prev_hash:
                return {"ok": False, "first_mismatch": i, "reason": "hash chain broken (prevDigest mismatch)"}
            prev_hash = entry_hash(self.org, e["kind"], digest, bytes.fromhex(e["prev"][2:]), bytes.fromhex(e["meta"][2:]), i, e["is_batch"], e["count"])
        if entries and chain_len == len(entries) and prev_hash != bytes(self.chain.call("AuditLog", "lastDigest", oid)):
            return {"ok": False, "first_mismatch": len(entries) - 1, "reason": "recomputed last digest differs from the chain"}
        return {"ok": True, "first_mismatch": None, "entries": len(entries), "chain_length": chain_len}
