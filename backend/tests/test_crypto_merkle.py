import json
from pathlib import Path

import pytest
from eth_utils import keccak
from hypothesis import given, strategies as st

from backend.common.crypto import TEST_VECTORS, canonical_hash, canonical_json
from backend.common.merkle import merkle_proof, merkle_root, verify_proof

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.req("BC-AUD-08")
def test_canonical_vectors():
    for obj, expected in TEST_VECTORS:
        assert canonical_json(obj) == expected


@pytest.mark.req("BC-AUD-08")
def test_shared_vector_file_is_current():
    import importlib.util

    spec = importlib.util.spec_from_file_location("gen_vectors", ROOT / "scripts" / "gen_vectors.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert json.loads((ROOT / "shared" / "canonical_vectors.json").read_text(encoding="utf-8")) == json.loads(json.dumps(m.build()))


@pytest.mark.req("BC-AUD-08")
def test_strings_keep_internal_whitespace_and_key_order_is_irrelevant():
    assert canonical_json({"a": "x y"}) == '{"a":"x y"}'
    assert canonical_hash({"b": 1, "a": 2}) == canonical_hash({"a": 2, "b": 1})


@pytest.mark.req("BC-AUD-03")
@given(st.lists(st.binary(min_size=32, max_size=32), min_size=1, max_size=40, unique=True))
def test_merkle_proofs_roundtrip(leaves):
    root = merkle_root(leaves)
    for i, leaf in enumerate(leaves):
        assert verify_proof(root, leaf, merkle_proof(leaves, i))
    assert not verify_proof(root, keccak(b"not-a-leaf"), merkle_proof(leaves, 0))


@pytest.mark.req("BC-AUD-03")
def test_merkle_rejects_empty():
    with pytest.raises(ValueError):
        merkle_root([])
