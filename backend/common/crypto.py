"""
Canonical JSON and cryptographic utilities for CascadeShield.
This module provides deterministic serialization and hashing used across
the backend, agents, and audit verification. The same algorithm is
mirrored in dashboard/src/utils/canonical.ts for cross-language verification.
"""

import json
import hashlib
from typing import Any, Dict, List, Union
from dataclasses import dataclass


@dataclass(frozen=True)
class CanonicalConfig:
    """Configuration for canonical JSON serialization."""
    # Sort object keys
    sort_keys: bool = True
    # Ensure consistent UTF-8 encoding
    ensure_ascii: bool = False
    # No whitespace
    separators: tuple = (',', ':')
    # Normalize numbers (no trailing zeros, no scientific notation for ints)
    normalize_numbers: bool = True


DEFAULT_CONFIG = CanonicalConfig()


def canonical_json(obj: Any, config: CanonicalConfig = DEFAULT_CONFIG) -> str:
    """
    Produce canonical JSON string for an object.
    
    Rules:
    - Keys sorted lexicographically
    - No whitespace
    - Numbers normalized (int without decimal, float without trailing zeros)
    - UTF-8 encoding
    - Deterministic ordering for all containers
    """
    def normalize_number(obj):
        """Normalize numeric values."""
        if isinstance(obj, float):
            # Check if it's actually an integer
            if obj == int(obj):
                return int(obj)
            # Remove trailing zeros
            return float(repr(obj).rstrip('0').rstrip('.') if '.' in repr(obj) else repr(obj))
        elif isinstance(obj, int):
            return obj
        return obj
    
    def process(obj):
        if obj is None:
            return None
        elif isinstance(obj, bool):
            return obj
        elif isinstance(obj, (int, float)):
            return normalize_number(obj) if config.normalize_numbers else obj
        elif isinstance(obj, str):
            return obj
        elif isinstance(obj, (list, tuple)):
            return [process(item) for item in obj]
        elif isinstance(obj, dict):
            # Sort keys and process values
            return {k: process(v) for k, v in sorted(obj.items())}
        elif hasattr(obj, '__dict__'):
            # Handle dataclasses and objects
            return process(obj.__dict__)
        elif hasattr(obj, 'model_dump'):
            # Handle Pydantic models
            return process(obj.model_dump())
        else:
            # Fallback to string representation
            return str(obj)
    
    processed = process(obj)
    return json.dumps(
        processed,
        sort_keys=config.sort_keys,
        ensure_ascii=config.ensure_ascii,
        separators=config.separators
    )


def canonical_hash(obj: Any, config: CanonicalConfig = DEFAULT_CONFIG) -> str:
    """
    Compute SHA-256 hash of canonical JSON representation.
    Returns hex string.
    """
    canon = canonical_json(obj, config)
    return hashlib.sha256(canon.encode('utf-8')).hexdigest()


def canonical_hash_bytes(obj: Any, config: CanonicalConfig = DEFAULT_CONFIG) -> bytes:
    """Compute SHA-256 hash as bytes."""
    canon = canonical_json(obj, config)
    return hashlib.sha256(canon.encode('utf-8')).digest()


# ============================================================================
# EIP-712 Domain Separator and Typed Data Hashing
# ============================================================================

@dataclass(frozen=True)
class EIP712Domain:
    name: str
    version: str
    chain_id: int
    verifying_contract: str  # checksummed address


def eip712_domain_separator(domain: EIP712Domain) -> bytes:
    """Compute EIP-712 domain separator."""
    # keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    domain_type_hash = hashlib.sha3_256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    ).digest()
    
    name_hash = hashlib.sha3_256(domain.name.encode('utf-8')).digest()
    version_hash = hashlib.sha3_256(domain.version.encode('utf-8')).digest()
    
    # Pack chain_id as uint256 (32 bytes)
    chain_id_bytes = domain.chain_id.to_bytes(32, 'big')
    
    # Pack verifying_contract as address (20 bytes, left-padded to 32)
    contract_bytes = bytes.fromhex(domain.verifying_contract[2:]) if domain.verifying_contract.startswith('0x') else bytes.fromhex(domain.verifying_contract)
    contract_padded = b'\x00' * 12 + contract_bytes
    
    return hashlib.sha3_256(
        domain_type_hash + name_hash + version_hash + chain_id_bytes + contract_padded
    ).digest()


def eip712_type_hash(type_definition: str) -> bytes:
    """Compute type hash for a struct type definition."""
    return hashlib.sha3_256(type_definition.encode('utf-8')).digest()


def eip712_encode_data(type_hash: bytes, fields: List[tuple], values: List[Any]) -> bytes:
    """
    Encode struct data for EIP-712.
    fields: list of (name, type) tuples
    values: list of values in same order
    """
    from eth_abi import encode
    
    types = [t for _, t in fields]
    encoded = encode(types, values)
    return hashlib.sha3_256(type_hash + encoded).digest()


def eip712_signable_hash(domain: EIP712Domain, type_hash: bytes, struct_data: bytes) -> bytes:
    """Compute the final signable hash per EIP-712."""
    domain_sep = eip712_domain_separator(domain)
    return hashlib.sha3_256(b'\x19\x01' + domain_sep + struct_data).digest()


# Merkle trees live in backend/common/merkle.py (keccak, sorted pairs; OpenZeppelin-compatible).

# ============================================================================
# Test Vectors (must match TypeScript implementation)
# ============================================================================

# These test vectors are used to verify cross-language canonical JSON compatibility
TEST_VECTORS = [
    # Simple object
    ({"a": 1, "b": 2}, '{"a":1,"b":2}'),
    # Nested object
    ({"b": {"z": 1, "a": 2}, "a": 3}, '{"a":3,"b":{"a":2,"z":1}}'),
    # Array
    ([3, 1, 2], '[3,1,2]'),
    # Mixed
    ({"items": [{"id": 2}, {"id": 1}], "count": 2}, '{"count":2,"items":[{"id":2},{"id":1}]}'),
    # Numbers
    ({"int": 42, "float": 3.1400, "sci": 1e3}, '{"float":3.14,"int":42,"sci":1000}'),
    # Empty
    ({}, '{}'),
    ([], '[]'),
    # Unicode
    ({"msg": "hello \u00e9"}, '{"msg":"hello \u00e9"}'),
]


def run_test_vectors() -> bool:
    """Run test vectors and return True if all pass."""
    for obj, expected in TEST_VECTORS:
        result = canonical_json(obj)
        if result != expected:
            print(f"FAIL: {obj}")
            print(f"  Expected: {expected}")
            print(f"  Got:      {result}")
            return False
    print("All canonical JSON test vectors passed!")
    return True


if __name__ == "__main__":
    run_test_vectors()