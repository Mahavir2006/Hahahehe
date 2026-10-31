// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "./OrgRegistry.sol";

/// @title AuditLog
/// @notice Append-only, per-organisation hash-chained audit trail. Entries are either single
///         digests or Merkle roots committing to a batch of off-chain records (BC-AUD-*).
contract AuditLog {
    OrgRegistry public immutable orgRegistry;

    enum AnchorKind {
        AgentTrace,     // 0
        RiskSnapshot,   // 1
        Plan,           // 2
        CriticVerdict,  // 3
        Execution,      // 4
        Pause,          // 5
        Resume,         // 6
        ModelVersion,   // 7
        Policy          // 8
    }

    uint8 public constant MAX_KIND = 8;

    struct Entry {
        AnchorKind kind;
        bool isBatch;
        bytes32 digest;      // single digest, or Merkle root when isBatch
        bytes32 prevDigest;  // chain pointer: hash of previous entry
        bytes32 metaHash;
        uint256 count;       // number of leaves for a batch (1 for a single anchor)
        uint256 timestamp;
        address signer;
    }

    mapping(bytes32 => Entry[]) private _entries;
    mapping(bytes32 => bytes32) private _lastDigest;
    // orgId => kind => digest => anchored (fast lookup for ApprovalGate, no loops)
    mapping(bytes32 => mapping(uint8 => mapping(bytes32 => bool))) private _anchored;

    event Anchored(
        bytes32 indexed orgId,
        AnchorKind indexed kind,
        uint256 indexed index,
        bytes32 digest,
        bytes32 prevDigest,
        bool isBatch,
        uint256 count
    );

    error OrgNotActive(bytes32 orgId);
    error UnauthorizedSigner(bytes32 orgId, address caller);
    error InvalidPrevDigest(bytes32 orgId, bytes32 expected, bytes32 actual);
    error InvalidAnchorKind(uint8 kind);
    error EmptyBatch();
    error IndexOutOfBounds(bytes32 orgId, uint256 index);
    error NotABatch(bytes32 orgId, uint256 index);
    error ZeroDigest();
    error ZeroAddress();

    constructor(address orgRegistryAddress) {
        if (orgRegistryAddress == address(0)) revert ZeroAddress();
        orgRegistry = OrgRegistry(orgRegistryAddress);
    }

    // ------------------------------------------------------------------ writes

    /// @notice Anchor a single digest. prevDigest MUST equal the org's current lastDigest.
    function anchor(
        bytes32 orgId,
        uint8 kind,
        bytes32 digest,
        bytes32 prevDigest,
        bytes32 metaHash
    ) external returns (uint256 index) {
        return _append(orgId, kind, digest, prevDigest, metaHash, 1, false);
    }

    /// @notice Anchor a Merkle root committing to `count` off-chain records.
    function anchorBatch(
        bytes32 orgId,
        uint8 kind,
        bytes32 merkleRoot,
        uint256 count,
        bytes32 prevDigest
    ) external returns (uint256 index) {
        if (count == 0) revert EmptyBatch();
        return _append(orgId, kind, merkleRoot, prevDigest, bytes32(0), count, true);
    }

    function _append(
        bytes32 orgId,
        uint8 kind,
        bytes32 digest,
        bytes32 prevDigest,
        bytes32 metaHash,
        uint256 count,
        bool isBatch
    ) internal returns (uint256 index) {
        if (kind > MAX_KIND) revert InvalidAnchorKind(kind);
        if (digest == bytes32(0)) revert ZeroDigest();
        if (!orgRegistry.isOrgActive(orgId)) revert OrgNotActive(orgId);

        // BC-AUD-04: org agent may anchor anything; approvers may only anchor Pause/Resume.
        bool isPauseResume = (kind == uint8(AnchorKind.Pause) || kind == uint8(AnchorKind.Resume));
        bool ok = orgRegistry.isOrgAgent(orgId, msg.sender) ||
            (isPauseResume && orgRegistry.isOrgApprover(orgId, msg.sender));
        if (!ok) revert UnauthorizedSigner(orgId, msg.sender);

        bytes32 expected = _lastDigest[orgId];
        if (prevDigest != expected) revert InvalidPrevDigest(orgId, expected, prevDigest);

        index = _entries[orgId].length;
        _entries[orgId].push(
            Entry({
                kind: AnchorKind(kind),
                isBatch: isBatch,
                digest: digest,
                prevDigest: prevDigest,
                metaHash: metaHash,
                count: count,
                timestamp: block.timestamp,
                signer: msg.sender
            })
        );
        _lastDigest[orgId] = computeEntryHash(orgId, kind, digest, prevDigest, metaHash, index, isBatch, count);
        _anchored[orgId][kind][digest] = true;

        emit Anchored(orgId, AnchorKind(kind), index, digest, prevDigest, isBatch, count);
    }

    // ------------------------------------------------------------------- views

    /// @notice Canonical chain hash of an entry. Mirrored off-chain by backend/common/crypto.py.
    function computeEntryHash(
        bytes32 orgId,
        uint8 kind,
        bytes32 digest,
        bytes32 prevDigest,
        bytes32 metaHash,
        uint256 index,
        bool isBatch,
        uint256 count
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(orgId, kind, digest, prevDigest, metaHash, index, isBatch, count));
    }

    function getAnchor(bytes32 orgId, uint256 index) external view returns (Entry memory) {
        if (index >= _entries[orgId].length) revert IndexOutOfBounds(orgId, index);
        return _entries[orgId][index];
    }

    function length(bytes32 orgId) external view returns (uint256) {
        return _entries[orgId].length;
    }

    function lastDigest(bytes32 orgId) external view returns (bytes32) {
        return _lastDigest[orgId];
    }

    function hasAnchor(bytes32 orgId, uint8 kind, bytes32 digest) external view returns (bool) {
        return _anchored[orgId][kind][digest];
    }

    /// @notice Recompute the whole chain from stored entries and compare with lastDigest.
    ///         Bounded by `maxEntries` so it stays callable on large logs.
    function verifyChain(bytes32 orgId, uint256 maxEntries) external view returns (bool) {
        Entry[] storage list = _entries[orgId];
        uint256 n = list.length < maxEntries ? list.length : maxEntries;
        bytes32 prev = bytes32(0);
        for (uint256 i = 0; i < n; i++) {
            Entry storage e = list[i];
            if (e.prevDigest != prev) return false;
            prev = computeEntryHash(orgId, uint8(e.kind), e.digest, e.prevDigest, e.metaHash, i, e.isBatch, e.count);
        }
        if (n == list.length) return prev == _lastDigest[orgId];
        return true;
    }

    function verifyInclusion(
        bytes32 orgId,
        uint256 index,
        bytes32 leaf,
        bytes32[] calldata proof
    ) external view returns (bool) {
        if (index >= _entries[orgId].length) revert IndexOutOfBounds(orgId, index);
        Entry storage e = _entries[orgId][index];
        if (!e.isBatch) revert NotABatch(orgId, index);
        return MerkleProof.verify(proof, e.digest, leaf);
    }
}
