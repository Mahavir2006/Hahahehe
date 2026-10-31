"""
Sealed disclosures and commitments (SEC-PRIV).

The chain is readable by anyone who can reach a node, and it never forgets. So nothing that tells a reader
WHAT is vulnerable goes on-chain in the clear:

* the chain stores salted commitments (risk band, dependency terms, finding outcome, alert severity/TTI);
* the values themselves travel as a sealed envelope (event data) that only the named consortium members
  can open; each recipient checks the opened value against the on-chain commitment.

Envelope = one ephemeral X25519 key + HKDF-SHA256 + AES-256-GCM:

    version(1) | eph_pub(32) | SLOTS x [nonce(12) | wrapped_key(32+16)] | nonce(12) | ciphertext(PAD+16)

The plaintext is padded to a fixed size and the recipient table to a fixed number of unlabeled slots, so the
blob's length says nothing about the value ("low" vs "critical") or how many orgs it was addressed to.
A recipient finds its slot by trial decryption.
"""

from __future__ import annotations

import json
import secrets
from typing import Any, Dict, Iterable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from eth_abi import encode as abi_encode
from eth_utils import keccak

VERSION = 1
SLOTS = 4                # max recipients per envelope (consortium of 3 + headroom); unused slots are random
PAD = 192                # fixed plaintext size
_SLOT = 12 + 32 + 16
_HEADER = 1 + 32
SIZE = _HEADER + SLOTS * _SLOT + 12 + PAD + 16


class SealError(ValueError):
    pass


# ------------------------------------------------------------------- keys
def private_key_from_secret(secret: bytes) -> X25519PrivateKey:
    """Deterministic X25519 key from a 32-byte secret (dev: derived from the org's key file)."""
    return X25519PrivateKey.from_private_bytes(keccak(secret + b"cascadeshield/x25519-disclosure-key"))


def public_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _kek(shared: bytes, eph_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"cascadeshield/seal/v1" + eph_pub + recipient_pub).derive(shared)


# --------------------------------------------------------------- envelope
def seal(payload: Dict[str, Any], recipients: Iterable[bytes]) -> bytes:
    pubs = list(dict.fromkeys(bytes(r) for r in recipients))
    if not pubs:
        raise SealError("no recipients")
    if len(pubs) > SLOTS:
        raise SealError(f"at most {SLOTS} recipients per envelope")
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    if len(body) > PAD - 2:
        raise SealError("payload too large")
    plain = len(body).to_bytes(2, "big") + body + secrets.token_bytes(PAD - 2 - len(body))

    content_key = AESGCM.generate_key(bit_length=256)
    eph = X25519PrivateKey.generate()
    eph_pub = public_bytes(eph)
    slots = []
    for rp in pubs:
        shared = eph.exchange(X25519PublicKey.from_public_bytes(rp))
        n = secrets.token_bytes(12)
        slots.append(n + AESGCM(_kek(shared, eph_pub, rp)).encrypt(n, content_key, None))
    while len(slots) < SLOTS:
        slots.append(secrets.token_bytes(_SLOT))
    secrets.SystemRandom().shuffle(slots)

    n = secrets.token_bytes(12)
    header = bytes([VERSION]) + eph_pub
    return header + b"".join(slots) + n + AESGCM(content_key).encrypt(n, plain, header)


def open_sealed(blob: bytes, priv: X25519PrivateKey) -> Optional[Dict[str, Any]]:
    """Return the payload if `priv` is one of the recipients, else None."""
    blob = bytes(blob)
    if len(blob) != SIZE or blob[0] != VERSION:
        return None
    header, eph_pub = blob[:_HEADER], blob[1:_HEADER]
    kek = _kek(priv.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub, public_bytes(priv))
    body = _HEADER + SLOTS * _SLOT
    for i in range(SLOTS):
        slot = blob[_HEADER + i * _SLOT:_HEADER + (i + 1) * _SLOT]
        try:
            content_key = AESGCM(kek).decrypt(slot[:12], slot[12:], None)
        except InvalidTag:
            continue
        try:
            plain = AESGCM(content_key).decrypt(blob[body:body + 12], blob[body + 12:], header)
        except InvalidTag:
            return None
        size = int.from_bytes(plain[:2], "big")
        return json.loads(plain[2:2 + size])
    return None


def from_hex(h: str) -> bytes:
    return bytes.fromhex(h[2:] if h.startswith("0x") else h)


# ------------------------------------------------------------ commitments
def random_salt() -> bytes:
    return secrets.token_bytes(32)


def blind(secret: bytes, *parts: Any) -> bytes:
    """Deterministic per-org key that a reader cannot link to the public input (advisory key, alert de-dupe key)."""
    types = ["bytes32"] + ["bytes32" if isinstance(p, (bytes, bytearray)) else "uint8" for p in parts]
    return keccak(abi_encode(types, [secret, *parts]))


def terms_commitment(salt: bytes, strength: int, tolerance: int) -> bytes:
    return keccak(abi_encode(["bytes32", "uint8", "uint8"], [salt, strength, tolerance]))


def band_commitment(salt: bytes, band: int, criticality: int) -> bytes:
    return keccak(abi_encode(["bytes32", "uint8", "uint8"], [salt, band, criticality]))


def finding_commitment(salt: bytes, advisory_hash: bytes, cve_set_hash: bytes, matched: bool) -> bytes:
    return keccak(abi_encode(["bytes32", "bytes32", "bytes32", "bool"], [salt, advisory_hash, cve_set_hash, matched]))


def alert_commitment(salt: bytes, severity: int, tti: int, evidence_hash: bytes) -> bytes:
    return keccak(abi_encode(["bytes32", "uint8", "uint8", "bytes32"], [salt, severity, tti, evidence_hash]))
