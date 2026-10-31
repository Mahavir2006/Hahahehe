import json
from pathlib import Path

import pytest
from eth_utils import keccak
from hypothesis import given, strategies as st

from backend.common import sealed
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


# ------------------------------------------------------------- sealed disclosures (SEC-PRIV)
def _member(i: int):
    k = sealed.private_key_from_secret(bytes([i]) * 32)
    return k, sealed.public_bytes(k)


@pytest.mark.req("SEC-PRIV-05")
def test_sealed_envelope_opens_only_for_recipients():
    (a, pa), (b, pb), (c, _) = _member(1), _member(2), _member(3)
    box = sealed.seal({"kind": "risk", "band": 3, "crit": 3, "salt": "00" * 32}, [pa, pb])
    assert sealed.open_sealed(box, a)["band"] == 3 and sealed.open_sealed(box, b)["band"] == 3
    assert sealed.open_sealed(box, c) is None
    tampered = bytearray(box)
    tampered[-1] ^= 1
    assert sealed.open_sealed(bytes(tampered), a) is None
    assert sealed.open_sealed(box[:-1], a) is None


@pytest.mark.req("SEC-PRIV-05")
def test_sealed_envelope_size_reveals_neither_value_nor_recipient_count():
    _, p1 = _member(1)
    pubs = [_member(i)[1] for i in range(1, 5)]
    small = sealed.seal({"kind": "risk", "band": 0}, [p1])
    large = sealed.seal({"kind": "risk", "band": 3, "pad": "x" * 100}, pubs)
    assert len(small) == len(large) == sealed.SIZE
    assert sealed.seal({"band": 1}, [p1]) != sealed.seal({"band": 1}, [p1]), "fresh randomness every time"
    with pytest.raises(sealed.SealError):
        sealed.seal({"band": 1}, pubs + [_member(9)[1]])
    with pytest.raises(sealed.SealError):
        sealed.seal({"x": "y" * 500}, [p1])


@pytest.mark.req("SEC-PRIV-01", "SEC-PRIV-02")
def test_commitments_match_solidity_encoding_and_hide_small_domains():
    from eth_abi import encode

    salt = bytes(range(32))
    assert sealed.band_commitment(salt, 3, 2) == keccak(encode(["bytes32", "uint8", "uint8"], [salt, 3, 2]))
    assert sealed.finding_commitment(salt, b"\x01" * 32, b"\x02" * 32, True) == keccak(encode(["bytes32", "bytes32", "bytes32", "bool"], [salt, b"\x01" * 32, b"\x02" * 32, True]))
    # with a random salt, the 16 possible (band, crit) pairs no longer identify the commitment
    c = sealed.band_commitment(sealed.random_salt(), 3, 3)
    assert c not in {sealed.band_commitment(b"\x00" * 32, x, y) for x in range(4) for y in range(4)}
    assert sealed.blind(b"\x07" * 32, b"\x01" * 32) != keccak(b"\x01" * 32)
