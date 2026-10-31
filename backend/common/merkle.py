"""
OpenZeppelin-compatible Merkle trees (keccak256, sorted-pair hashing).

An odd node at any level is promoted unchanged (never duplicated), which matches
OpenZeppelin's MerkleProof.verify and avoids second-preimage / duplicate-leaf issues.
"""

from typing import List, Tuple

from eth_utils import keccak


def _pair(a: bytes, b: bytes) -> bytes:
    return keccak(a + b) if a <= b else keccak(b + a)


def build_tree(leaves: List[bytes]) -> List[List[bytes]]:
    if not leaves:
        raise ValueError("cannot build a Merkle tree with no leaves")
    layers = [list(leaves)]
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(_pair(level[i], level[i + 1]) if i + 1 < len(level) else level[i])
        layers.append(nxt)
        level = nxt
    return layers


def merkle_root(leaves: List[bytes]) -> bytes:
    return build_tree(leaves)[-1][0]


def merkle_proof(leaves: List[bytes], index: int) -> List[bytes]:
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    layers = build_tree(leaves)
    proof: List[bytes] = []
    for level in layers[:-1]:
        sibling = index ^ 1
        if sibling < len(level):
            proof.append(level[sibling])
        index //= 2
    return proof


def verify_proof(root: bytes, leaf: bytes, proof: List[bytes]) -> bool:
    cur = leaf
    for sib in proof:
        cur = _pair(cur, sib)
    return cur == root


def root_and_proofs(leaves: List[bytes]) -> Tuple[bytes, List[List[bytes]]]:
    return merkle_root(leaves), [merkle_proof(leaves, i) for i in range(len(leaves))]
