"""
OrgNodeRuntime: one per organisation (AG-TOP-02). Holds the org's private data, its single agent key,
and the agents. It has no access to any other org's private data and can only coordinate with other orgs
through on-chain events.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional

from eth_utils import keccak

from backend.agents.framework import IsolationError, MessageBus
from backend.agents.llm import LLMClient
from backend.common.audit import AuditAnchorService
from backend.common import sealed
from backend.common.chain import ORGS, Chain, ChainWriter, WriteResult, org_id, org_salt, service_hash
from backend.graph.cascade import IntraOrgGraph
from backend.risk import model as risk

ROOT = Path(__file__).resolve().parents[2]
STRENGTH = {"low": 0, "medium": 1, "high": 2}
BAND = {"low": 0, "medium": 1, "high": 2, "critical": 3}
CRIT = {"low": 0, "medium": 1, "high": 2, "life_critical": 3}


def tolerance_bucket(minutes: int) -> int:
    return 0 if minutes < 15 else 1 if minutes <= 60 else 2 if minutes <= 240 else 3


class PrivateStore:
    """Read access to ONE org's private files. Any other org is refused (AG-TOP-05)."""

    def __init__(self, org: str, data_dir: Path):
        self.org = org
        self.base = (Path(data_dir) / "orgs" / org).resolve()

    def _path(self, org: str, name: str) -> Path:
        if org != self.org:
            raise IsolationError(f"org node '{self.org}' may not read private data of '{org}'")
        p = (self.base / name).resolve()
        if self.base not in p.parents and p != self.base:
            raise IsolationError("path escapes the org's private directory")
        if "private_keys" in name:
            raise IsolationError("key material is not readable through the data store")
        return p

    def read_json(self, name: str, org: Optional[str] = None) -> Any:
        return json.loads(self._path(org or self.org, name).read_text(encoding="utf-8"))


class NodeWriter:
    """Chain writer bound to this org's agent signer; it cannot sign as anyone else."""

    def __init__(self, shared: ChainWriter, org: str):
        self._w, self.org = shared, org

    @property
    def paused(self) -> bool:
        return self._w.paused

    def submit(self, key: str, contract: str, fn: str, args: list) -> WriteResult:
        return self._w.submit(key, contract, fn, args, f"{self.org}/agent")


class OrgNodeRuntime:
    def __init__(self, org: str, chain: Chain, writer: ChainWriter, state_dir: Path | str, data_dir: Optional[Path] = None, llm: Optional[LLMClient] = None, bus: Optional[MessageBus] = None):
        self.org = org
        self.chain = chain
        self.writer = NodeWriter(writer, org)
        self.state_dir = Path(state_dir)
        self.data_dir = Path(data_dir) if data_dir else ROOT / "data"
        self.store = PrivateStore(org, self.data_dir)
        self.llm = llm or LLMClient("offline")
        self.bus = bus or MessageBus()
        self.audit = AuditAnchorService(chain, writer, org, self.state_dir)
        self.org_id = org_id(org)
        self._agent_key = None
        self._lock = threading.RLock()
        self.labels: Dict[str, str] = {}

        inv = self.store.read_json("inventory.json")
        svcs = self.store.read_json("services.json")
        self.graph = IntraOrgGraph.load(org, self.data_dir)
        self.inventory: Dict[str, dict] = {a["asset_id"]: a for a in inv}
        self.services: Dict[str, dict] = {s["service_id"]: s for s in svcs}
        self._salt = self._derive_salt()
        self._enc_key = self._derive_enc_key()
        self.finding_openings: Dict[str, Dict[str, str]] = {}  # private: salts that open our finding commitments
        for sid, s in self.services.items():
            self.labels[self.svc_hash(sid).hex()] = f"{org}:{s['name']}"

        # simulated mutable state (executor changes live here, never anything real)
        self.assets: Dict[str, risk.AssetCtx] = self._build_assets()
        self.executed_plans: Dict[str, Dict[str, Any]] = {}
        self.pending_approvals: Dict[str, Dict[str, Any]] = {}
        self.plans: Dict[str, Dict[str, Any]] = {}
        self.findings: Dict[str, Dict[str, Any]] = {}
        self.baseline: Optional[float] = None
        self.indexer = None
        self.upstream: Dict[str, float] = {}
        self.last_attested: Dict[str, str] = {}
        self.history: List[Dict[str, Any]] = []
        self.acked: set = set()

    # -------------------------------------------------------------- identity
    def _keys(self) -> Dict[str, Any]:
        return json.loads((self.data_dir / "orgs" / self.org / "private_keys.dev.json").read_text(encoding="utf-8"))

    def _derive_salt(self) -> bytes:
        return org_salt(self.org, self._keys()["agent_signer"]["private_key"])

    def _derive_enc_key(self):
        """X25519 key that other members seal disclosures to (dev: derived from the org's admin key)."""
        return sealed.private_key_from_secret(bytes.fromhex(self._keys()["admin"]["private_key"].replace("0x", "")))

    @property
    def encryption_public_key(self) -> bytes:
        return sealed.public_bytes(self._enc_key)

    def recipients(self, orgs: Optional[List[str]] = None) -> List[bytes]:
        """Registered encryption keys of `orgs` (default: every member) plus our own, read from OrgRegistry."""
        out = [self.encryption_public_key]
        for o in orgs if orgs is not None else ORGS:
            k = bytes(self.chain.call("OrgRegistry", "encryptionKeys", org_id(o)))
            if k != bytes(32) and k not in out:
                out.append(k)
        return out

    def open_disclosure(self, blob: Any) -> Optional[Dict[str, Any]]:
        """Decrypt a sealed disclosure addressed to this org (None if we are not a recipient)."""
        raw = sealed.from_hex(blob) if isinstance(blob, str) else bytes(blob)
        return sealed.open_sealed(raw, self._enc_key)

    def blind(self, *parts: Any) -> bytes:
        return sealed.blind(self._salt, *parts)

    @property
    def agent_address(self) -> str:
        return self.chain.accounts[f"{self.org}/agent"].address

    def svc_salt(self, service_id: str) -> bytes:
        return keccak(self._salt + keccak(text=service_id))

    def svc_hash(self, service_id: str) -> bytes:
        return service_hash(self.org, service_id, self.svc_salt(service_id))

    # ------------------------------------------------------------- handshake
    def handshake_offer(self, service_id: str) -> Dict[str, str]:
        """Reveal ONE service's id+salt to ONE counterparty so it can recompute and verify the hash (BC-ATT-D-02)."""
        if service_id not in self.services:
            raise KeyError(service_id)
        return {
            "org": self.org, "service_id": service_id, "service_name": self.services[service_id]["name"],
            "salt": "0x" + self.svc_salt(service_id).hex(), "hash": "0x" + self.svc_hash(service_id).hex(),
        }

    def handshake_accept(self, offer: Dict[str, str]) -> bytes:
        recomputed = service_hash(offer["org"], offer["service_id"], bytes.fromhex(offer["salt"][2:]))
        if "0x" + recomputed.hex() != offer["hash"]:
            raise ValueError("handshake hash mismatch")
        self.labels[recomputed.hex()] = f"{offer['org']}:{offer['service_name']}"
        return recomputed

    # ----------------------------------------------------------- assets state
    def _build_assets(self) -> Dict[str, risk.AssetCtx]:
        svc_crit: Dict[str, str] = {}
        order = ["low", "medium", "high", "life_critical"]
        for s in self.services.values():
            for a in s["required_assets"]:
                if order.index(s["criticality"]) >= order.index(svc_crit.get(a, "low")):
                    svc_crit[a] = s["criticality"]
        out = {}
        for aid, a in self.inventory.items():
            out[aid] = risk.AssetCtx(
                asset_id=aid, org=self.org, name=a["name"], internet_exposed=a["internet_exposed"], default_credentials=a["default_credentials"],
                zone=a["zone"], last_patched=a["last_patched"], criticality=a["criticality"], safety_critical=a["safety_critical"],
                num_dependents=len(self.graph.transitive_dependents(aid)), service_crit=svc_crit.get(aid, "low"),
            )
        return out

    def contexts(self) -> List[risk.AssetCtx]:
        return list(self.assets.values())

    def snapshot(self) -> Dict[str, risk.AssetCtx]:
        return deepcopy(self.assets)

    def restore(self, snap: Dict[str, risk.AssetCtx]) -> None:
        self.assets = deepcopy(snap)

    def org_risk(self) -> Dict[str, Any]:
        scores = [risk.score_asset(a) for a in self.contexts()]
        return {"aggregate": risk.aggregate(scores), "scores": scores}

    # -------------------------------------------------------------- supply chain
    def supply_chain_check(self) -> Dict[str, str]:
        """BC-FW-05: compare each asset's observed firmware hash with FirmwareRegistry (Match/Mismatch/Unknown/Revoked)."""
        names = ["Match", "Mismatch", "Unknown", "Revoked"]
        out: Dict[str, str] = {}
        for aid, a in self.inventory.items():
            r = self.chain.call(
                "FirmwareRegistry", "verifyFirmware", keccak(text=a["vendor"]), keccak(text=a["model"]), keccak(text=a["firmware_version"]),
                bytes.fromhex(a["observed_firmware_sha256"][2:]),
            )
            out[aid] = names[int(r)]
            self.assets[aid].supply_chain_flag = names[int(r)] != "Match"
        return out

    # ------------------------------------------------------------- attestations
    def _next(self, mapping: str) -> int:
        return int(self.chain.call("AttestationRegistry", mapping, self.agent_address)) + 1

    def _sign(self, types: dict, msg: dict) -> bytes:
        return self.chain.sign_typed(f"{self.org}/agent", self.chain.attestation_domain(), types, msg)

    def attest_dependency(self, consumer_org: str, consumer_hash: bytes, provider_org: str, provider_hash: bytes, strength: int, tolerance: int,
                          terms_salt: bytes, ttl: int = 7 * 86400) -> WriteResult:
        """Both sides sign the same terms commitment (salt agreed in the handshake); strength/tolerance only travel sealed."""
        with self._lock:
            expiry = self.chain.block_timestamp() + ttl
            nonce = self._next("dependencyNonces")
            tc = sealed.terms_commitment(terms_salt, strength, tolerance)
            box = sealed.seal({"kind": "dependency", "strength": strength, "tolerance": tolerance, "salt": terms_salt.hex()}, self.recipients())
            msg = {
                "consumerOrg": org_id(consumer_org), "consumerServiceHash": consumer_hash, "providerOrg": org_id(provider_org),
                "providerServiceHash": provider_hash, "termsCommitment": tc, "disclosureHash": keccak(box), "nonce": nonce, "expiry": expiry,
            }
            sig = self._sign(self.chain.DEP_TYPES, msg)
            key = f"dep:{self.org}:{consumer_hash.hex()[:16]}:{provider_hash.hex()[:16]}:{tc.hex()[:16]}:{nonce}"
            return self.writer.submit(key, "AttestationRegistry", "submitDependencyAttestation", [msg["consumerOrg"], consumer_hash, msg["providerOrg"], provider_hash, tc, nonce, expiry, box, sig])

    def attest_risk(self, service_id: str, band: str, criticality: str, evidence: Dict[str, Any], ttl: int = 86400) -> WriteResult:
        with self._lock:
            sh = self.svc_hash(service_id)
            salt = sealed.random_salt()  # random: a salt derived from guessable inputs would let the commitment be brute-forced
            ev_hash = bytes.fromhex(hashlib.sha256(json.dumps(evidence, sort_keys=True, default=str).encode()).hexdigest())
            from eth_abi import encode as abi_encode

            commitment = keccak(abi_encode(["bytes32", "bytes32"], [salt, ev_hash]))
            band_salt = sealed.random_salt()
            bc = sealed.band_commitment(band_salt, BAND[band], CRIT[criticality])
            box = sealed.seal({"kind": "risk", "band": BAND[band], "crit": CRIT[criticality], "salt": band_salt.hex()}, self.recipients())
            validity = self.chain.block_timestamp() + ttl
            nonce = self._next("riskNonces")
            mv = keccak(text=risk.RiskModel.get().version)
            msg = {
                "orgId": self.org_id, "serviceHash": sh, "bandCommitment": bc, "disclosureHash": keccak(box), "modelVersionHash": mv,
                "evidenceCommitment": commitment, "validUntil": validity, "nonce": nonce,
            }
            sig = self._sign(self.chain.RISK_TYPES, msg)
            key = f"risk:{self.org}:{sh.hex()[:16]}:{bc.hex()[:12]}:{nonce}"
            res = self.writer.submit(key, "AttestationRegistry", "submitRiskAttestation", [self.org_id, sh, bc, mv, commitment, validity, nonce, box, sig])
            res.receipt = None
            self._last_disclosure = {"salt": "0x" + salt.hex(), "assessment_hash": "0x" + ev_hash.hex(), "commitment": "0x" + commitment.hex()}
            return res

    def attest_finding(self, advisory_hash_hex: str, cves: List[str], matched: bool) -> WriteResult:
        """Proof that we processed the advisory, revealing nothing: the lookup key is blinded with our secret (the
        public advisory hash cannot be looked up) and the outcome is a commitment. Nobody else needs the outcome, so
        there is no sealed copy; the opening stays private for selective disclosure to an auditor."""
        with self._lock:
            ah = bytes.fromhex(advisory_hash_hex)
            ch = keccak(text=",".join(sorted(cves)))
            ak = self.blind(ah)
            salt = sealed.random_salt()
            fc = sealed.finding_commitment(salt, ah, ch, matched)
            nonce = self._next("findingNonces")
            ts = self.chain.block_timestamp()
            msg = {"orgId": self.org_id, "advisoryKey": ak, "findingCommitment": fc, "processedAt": ts, "nonce": nonce}
            sig = self._sign(self.chain.FINDING_TYPES, msg)
            key = f"finding:{self.org}:{advisory_hash_hex[:24]}"
            res = self.writer.submit(key, "AttestationRegistry", "submitFindingAttestation", [self.org_id, ak, fc, ts, nonce, sig])
            if res.status == "confirmed":
                self.finding_openings[advisory_hash_hex] = {
                    "advisory_key": "0x" + ak.hex(), "salt": "0x" + salt.hex(), "cve_set_hash": "0x" + ch.hex(), "matched": matched,
                }
            return res

    # ---------------------------------------------------------------- status
    def service_band(self, assets: Optional[List[risk.AssetCtx]] = None, upstream: bool = True) -> Dict[str, Dict[str, Any]]:
        """Per-service risk = the risk of its most exposed required asset (+ exposure inherited from
        confirmed upstream alerts). Asset-to-asset compromise propagation is handled separately by the cascade engine."""
        scores = {a.asset_id: risk.score_asset(a, explain=False)["risk"] / 100.0 for a in (assets if assets is not None else self.contexts())}
        out = {}
        for sid, sv in self.services.items():
            vals = [scores[a] for a in sv["required_assets"] if a in scores]
            v = max(vals) if vals else 0.0  # a service is as exposed as its most exposed required asset
            if upstream:
                v = 1.0 - (1.0 - v) * (1.0 - self.upstream.get(sid, 0.0))
            out[sid] = {"risk": round(100 * v, 4), "band": risk.band_for(100 * v), "criticality": sv["criticality"], "p": v}
        return out
