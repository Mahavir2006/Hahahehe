"""
Chain access layer: web3 connection, ABIs, org key material, typed-data signing,
custom-error decoding and a durable, idempotent, pausable writer.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak, to_checksum_address
from web3 import Web3

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ["OrgRegistry", "AuditLog", "AttestationRegistry", "FirmwareRegistry", "ApprovalGate", "AlertBus"]
ORGS = ["power", "water", "hospital"]

# Publicly known Hardhat account #0 (dev chain only). Used for registry-admin operations.
HARDHAT_DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

BLOCKED_CHAIN_IDS = {1, 10, 56, 137, 42161, 8453, 43114, 250, 100}  # well-known mainnets (BC-ENV-04)


class ChainError(Exception):
    pass


class ChainUnavailable(ChainError):
    """RPC not reachable; the operation can be retried later."""


class ChainPaused(ChainError):
    """The kill switch is active; no writes are permitted (AG-SAF-04)."""


class ChainRevert(ChainError):
    """The EVM reverted. `name` is the decoded custom error (or 'Revert')."""

    def __init__(self, name: str, args: tuple = (), raw: str = ""):
        super().__init__(f"{name}{args}")
        self.name = name
        self.args_ = args
        self.raw = raw


def org_id(name: str) -> bytes:
    """bytes32 org id: keccak256(utf8(name)) — identical to ethers.id(name)."""
    return keccak(text=name)


ORG_NAMES = {"0x" + org_id(n).hex(): n for n in ORGS}


def service_hash(org: str, service_id: str, salt: bytes) -> bytes:
    """keccak256(abi.encode(orgId, keccak(serviceId), salt)); the salt never leaves the org (BC-ATT-D-02)."""
    return keccak(abi_encode(["bytes32", "bytes32", "bytes32"], [org_id(org), keccak(text=service_id), salt]))


def org_salt(org: str, signer_key: str) -> bytes:
    """Deterministic per-org secret salt derived from the org's agent key."""
    return keccak(bytes.fromhex(signer_key.replace("0x", "")) + b"service-salt")


def validate_chain_id(chain_id: int) -> None:
    if chain_id in BLOCKED_CHAIN_IDS:
        raise ChainError(f"refusing to operate on well-known public chain id {chain_id}")


def _hex(b: Any) -> str:
    if isinstance(b, (bytes, bytearray)):
        return "0x" + bytes(b).hex()
    return str(b)


class Chain:
    def __init__(
        self,
        rpc_url: str = "http://127.0.0.1:8545",
        deployment_file: Optional[str] = None,
        data_dir: Optional[Path] = None,
        chain_id: int = 31337,
    ):
        validate_chain_id(chain_id)
        self.rpc_url = rpc_url
        self.chain_id = chain_id
        self.data_dir = Path(data_dir) if data_dir else ROOT / "data"
        self.deployment_file = Path(deployment_file) if deployment_file else ROOT / "chain" / "deployments" / "local.json"
        self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
        self._nonce_locks: Dict[str, threading.Lock] = {}
        self._lock_guard = threading.Lock()
        # Held by every write, and by the digital twin while a what-if runs on a chain snapshot, so no real
        # transaction can land inside a snapshot that is about to be reverted.
        self.gate = threading.RLock()
        self.contracts: Dict[str, Any] = {}
        self._error_selectors: Dict[bytes, Any] = {}
        self.accounts: Dict[str, Any] = {}
        self._load_accounts()
        self._load_contracts()

    # ------------------------------------------------------------------ setup
    def _load_accounts(self) -> None:
        self.accounts["deployer"] = Account.from_key(HARDHAT_DEPLOYER_KEY)
        for org in ORGS:
            f = self.data_dir / "orgs" / org / "private_keys.dev.json"
            if not f.exists():
                continue
            keys = json.loads(f.read_text(encoding="utf-8"))
            self.accounts[f"{org}/admin"] = Account.from_key(keys["admin"]["private_key"])
            self.accounts[f"{org}/agent"] = Account.from_key(keys["agent_signer"]["private_key"])
            for i, a in enumerate(keys["approvers"]):
                self.accounts[f"{org}/approver{i}"] = Account.from_key(a["private_key"])

    def _load_contracts(self) -> None:
        if not self.deployment_file.exists():
            return
        dep = json.loads(self.deployment_file.read_text(encoding="utf-8"))
        self.deployment = dep
        for name in CONTRACTS:
            art = ROOT / "chain" / "artifacts" / "contracts" / f"{name}.sol" / f"{name}.json"
            abi = json.loads(art.read_text(encoding="utf-8"))["abi"]
            c = self.w3.eth.contract(address=to_checksum_address(dep["contracts"][name]), abi=abi)
            self.contracts[name] = c
            for item in abi:
                if item.get("type") == "error":
                    sig = f"{item['name']}({','.join(i['type'] for i in item['inputs'])})"
                    self._error_selectors[keccak(text=sig)[:4]] = item

    @property
    def addresses(self) -> Dict[str, str]:
        return {n: c.address for n, c in self.contracts.items()}

    def is_connected(self) -> bool:
        try:
            return bool(self.w3.is_connected())
        except Exception:
            return False

    def block_number(self) -> int:
        try:
            return int(self.w3.eth.block_number)
        except Exception as e:  # noqa: BLE001
            raise ChainUnavailable(str(e)) from e

    def verify_genesis(self) -> bool:
        """BC-INT-08: the deployed code must exist at the configured addresses (guards against a reset chain)."""
        for name, c in self.contracts.items():
            code = self.w3.eth.get_code(c.address)
            if not code or code == b"":
                raise ChainError(f"no code at {name} {c.address}: chain was reset, re-deploy required")
        return True

    # --------------------------------------------------------------- reverts
    def decode_error(self, exc: Exception) -> ChainRevert:
        data = getattr(exc, "data", None)
        if isinstance(data, dict):
            data = data.get("data")
        text = str(exc)
        if not isinstance(data, str):
            m = re.search(r"0x[0-9a-fA-F]{8,}", text)
            data = m.group(0) if m else ""
        if isinstance(data, str) and data.startswith("0x") and len(data) >= 10:
            raw = bytes.fromhex(data[2:])
            item = self._error_selectors.get(raw[:4])
            if item is not None:
                from eth_abi import decode as abi_decode

                types = [i["type"] for i in item["inputs"]]
                try:
                    vals = abi_decode(types, raw[4:]) if types else ()
                except Exception:  # noqa: BLE001
                    vals = ()
                return ChainRevert(item["name"], tuple(vals), data)
        return ChainRevert("Revert", (text[:200],), data if isinstance(data, str) else "")

    # ------------------------------------------------------------- tx sending
    def _lock_for(self, addr: str) -> threading.Lock:
        with self._lock_guard:
            return self._nonce_locks.setdefault(addr, threading.Lock())

    def transact(self, contract: str, fn: str, args: list, signer: str, gas_cap: int = 3_000_000) -> dict:
        acct = self.accounts[signer]
        c = self.contracts[contract]
        try:
            func = getattr(c.functions, fn)(*self._coerce(c, fn, args))
        except Exception as e:  # noqa: BLE001
            raise ChainError(f"bad call {contract}.{fn}: {e}") from e
        with self.gate, self._lock_for(acct.address):
            try:
                gas = func.estimate_gas({"from": acct.address})
            except Exception as e:  # noqa: BLE001
                if self._is_connection_error(e):
                    raise ChainUnavailable(str(e)) from e
                raise self.decode_error(e) from e
            try:
                tx = func.build_transaction(
                    {
                        "from": acct.address,
                        "nonce": self.w3.eth.get_transaction_count(acct.address, "pending"),
                        "gas": min(int(gas * 1.3) + 10_000, gas_cap),
                        "chainId": self.chain_id,
                        "gasPrice": self.w3.eth.gas_price,
                    }
                )
                signed = acct.sign_transaction(tx)
                txh = self.w3.eth.send_raw_transaction(signed.raw_transaction)
                rc = self.w3.eth.wait_for_transaction_receipt(txh, timeout=60)
            except ChainError:
                raise
            except Exception as e:  # noqa: BLE001
                if self._is_connection_error(e):
                    raise ChainUnavailable(str(e)) from e
                raise self.decode_error(e) from e
        if rc["status"] != 1:
            raise ChainRevert("Revert", ("transaction status 0",))
        return {"tx_hash": "0x" + bytes(rc["transactionHash"]).hex(), "block": rc["blockNumber"], "gas_used": rc["gasUsed"], "receipt": rc}

    @staticmethod
    def _is_connection_error(e: Exception) -> bool:
        s = (type(e).__name__ + " " + str(e)).lower()
        return any(k in s for k in ("connection", "timeout", "timed out", "refused", "max retries", "unreachable"))

    def _coerce(self, c, fn: str, args: list) -> list:
        """Accept 0x-hex strings for bytes types and plain ints/bools; convert hex to bytes."""
        abi = next(a for a in c.abi if a.get("type") == "function" and a["name"] == fn and len(a["inputs"]) == len(args))
        out = []
        for inp, v in zip(abi["inputs"], args):
            out.append(self._coerce_one(inp["type"], v))
        return out

    def _coerce_one(self, typ: str, v: Any):
        if typ.endswith("[]"):
            return [self._coerce_one(typ[:-2], x) for x in v]
        if typ.startswith("bytes") and isinstance(v, str):
            return bytes.fromhex(v[2:] if v.startswith("0x") else v)
        return v

    def call(self, contract: str, fn: str, *args):
        c = self.contracts[contract]
        try:
            return getattr(c.functions, fn)(*self._coerce(c, fn, list(args))).call()
        except Exception as e:  # noqa: BLE001
            if self._is_connection_error(e):
                raise ChainUnavailable(str(e)) from e
            raise self.decode_error(e) from e

    # ---------------------------------------------------------- EIP-712 signing
    def attestation_domain(self) -> dict:
        return {
            "name": "AttestationRegistry",
            "version": "1",
            "chainId": self.chain_id,
            "verifyingContract": self.contracts["AttestationRegistry"].address,
        }

    def sign_typed(self, signer: str, domain: dict, types: dict, message: dict) -> bytes:
        msg = encode_typed_data(domain_data=domain, message_types=types, message_data=message)
        return bytes(self.accounts[signer].sign_message(msg).signature)

    DEP_TYPES = {
        "DependencyAttestation": [
            {"name": "consumerOrg", "type": "bytes32"},
            {"name": "consumerServiceHash", "type": "bytes32"},
            {"name": "providerOrg", "type": "bytes32"},
            {"name": "providerServiceHash", "type": "bytes32"},
            {"name": "termsCommitment", "type": "bytes32"},
            {"name": "disclosureHash", "type": "bytes32"},
            {"name": "nonce", "type": "uint256"},
            {"name": "expiry", "type": "uint256"},
        ]
    }
    RISK_TYPES = {
        "RiskAttestation": [
            {"name": "orgId", "type": "bytes32"},
            {"name": "serviceHash", "type": "bytes32"},
            {"name": "bandCommitment", "type": "bytes32"},
            {"name": "disclosureHash", "type": "bytes32"},
            {"name": "modelVersionHash", "type": "bytes32"},
            {"name": "evidenceCommitment", "type": "bytes32"},
            {"name": "validUntil", "type": "uint256"},
            {"name": "nonce", "type": "uint256"},
        ]
    }
    FINDING_TYPES = {
        "FindingAttestation": [
            {"name": "orgId", "type": "bytes32"},
            {"name": "advisoryKey", "type": "bytes32"},
            {"name": "findingCommitment", "type": "bytes32"},
            {"name": "processedAt", "type": "uint256"},
            {"name": "nonce", "type": "uint256"},
        ]
    }

    def block_timestamp(self) -> int:
        return int(self.w3.eth.get_block("latest")["timestamp"])


# ---------------------------------------------------------------------------
# Durable idempotent writer (BC-INT-02 / BC-INT-07)
# ---------------------------------------------------------------------------
@dataclass
class WriteResult:
    status: str  # confirmed | duplicate | deferred | failed
    tx_hash: Optional[str] = None
    error: Optional[str] = None
    receipt: Optional[dict] = None


class ChainWriter:
    def __init__(self, chain: Chain, db_path: Path | str):
        self.chain = chain
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._guard = threading.Lock()
        self.paused = False
        self.on_event = None  # optional callback(name, payload)
        with self._db() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS ops (key TEXT PRIMARY KEY, status TEXT, tx_hash TEXT, payload TEXT, error TEXT, attempts INTEGER DEFAULT 0, created REAL)"
            )

    def _db(self):
        db = sqlite3.connect(self.db_path, timeout=30)
        db.row_factory = sqlite3.Row
        return db

    def pause(self) -> None:
        self.paused = True

    def resume(self) -> None:
        self.paused = False

    def pending_count(self) -> int:
        with self._db() as db:
            return db.execute("SELECT COUNT(*) FROM ops WHERE status='pending'").fetchone()[0]

    def get(self, key: str) -> Optional[dict]:
        with self._db() as db:
            r = db.execute("SELECT * FROM ops WHERE key=?", (key,)).fetchone()
            return dict(r) if r else None

    def submit(self, key: str, contract: str, fn: str, args: list, signer: str) -> WriteResult:
        if self.paused:
            raise ChainPaused("chain writes are paused by the kill switch")
        payload = json.dumps({"contract": contract, "fn": fn, "args": [_hex(a) if isinstance(a, (bytes, bytearray)) else a for a in args], "signer": signer}, default=str)
        with self._guard:
            with self._db() as db:
                row = db.execute("SELECT status, tx_hash FROM ops WHERE key=?", (key,)).fetchone()
                if row and row["status"] == "done":
                    return WriteResult("duplicate", tx_hash=row["tx_hash"])
                if not row:
                    db.execute("INSERT INTO ops(key,status,payload,created) VALUES(?,?,?,?)", (key, "pending", payload, time.time()))
        return self._execute(key, payload)

    def _execute(self, key: str, payload: str) -> WriteResult:
        p = json.loads(payload)
        try:
            out = self.chain.transact(p["contract"], p["fn"], p["args"], p["signer"])
        except ChainUnavailable as e:
            with self._db() as db:
                db.execute("UPDATE ops SET attempts=attempts+1, error=? WHERE key=?", (str(e)[:300], key))
            return WriteResult("deferred", error=str(e)[:300])
        except ChainRevert as e:
            with self._db() as db:
                db.execute("UPDATE ops SET status='failed', error=? WHERE key=?", (f"{e.name}{e.args_}"[:300], key))
            raise
        with self._db() as db:
            db.execute("UPDATE ops SET status='done', tx_hash=?, error=NULL WHERE key=?", (out["tx_hash"], key))
        return WriteResult("confirmed", tx_hash=out["tx_hash"], receipt=out["receipt"])

    def flush(self) -> int:
        """Retry every pending op once; returns the number confirmed."""
        if self.paused:
            return 0
        with self._db() as db:
            rows = db.execute("SELECT key, payload FROM ops WHERE status='pending' ORDER BY created").fetchall()
        done = 0
        for r in rows:
            try:
                res = self._execute(r["key"], r["payload"])
            except ChainRevert:
                continue
            if res.status == "confirmed":
                done += 1
            elif res.status == "deferred":
                break  # chain still down; keep order
        return done
