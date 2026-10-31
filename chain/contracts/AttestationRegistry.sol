// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./OrgRegistry.sol";

/// @title AttestationRegistry
/// @notice Stores three types of attestations: Dependency (bilateral), Risk, and Finding
contract AttestationRegistry is AccessControl, EIP712, ReentrancyGuard {
    using ECDSA for bytes32;

    // OrgRegistry reference
    OrgRegistry public immutable orgRegistry;

    // =========================================================================
    // Dependency Attestations (BC-ATT-D)
    // =========================================================================

    enum DependencyStrength { Low, Medium, High }
    enum ToleranceBucket { Under15m, Min15To60, Hours1To4, Over4h }
    enum EdgeState { Proposed, Confirmed, Revoked, Expired, Disputed }

    struct DependencyAttestation {
        bytes32 consumerOrg;
        bytes32 consumerServiceHash;
        bytes32 providerOrg;
        bytes32 providerServiceHash;
        DependencyStrength strength;
        ToleranceBucket tolerance;
        uint256 nonce;
        uint256 expiry;
        address signer;
        uint256 timestamp;
    }

    struct DependencyEdge {
        bytes32 edgeId;
        DependencyAttestation consumerAttestation;
        DependencyAttestation providerAttestation;
        EdgeState state;
        uint256 confirmedAt;
        uint256 revokedAt;
    }

    // edgeId => DependencyEdge
    mapping(bytes32 => DependencyEdge) public dependencyEdges;
    // consumerOrg => providerOrg => edgeId
    mapping(bytes32 => mapping(bytes32 => bytes32[])) public orgDependencyEdges;
    // signer => nonce
    mapping(address => uint256) public dependencyNonces;

    // =========================================================================
    // Risk Attestations (BC-ATT-R)
    // =========================================================================

    enum RiskBand { Low, Medium, High, Critical }
    enum CriticalityBucket { Low, Medium, High, LifeCritical }

    struct RiskAttestation {
        bytes32 orgId;
        bytes32 serviceHash;
        RiskBand riskBand;
        CriticalityBucket criticalityBucket;
        address signer;
        bytes32 modelVersionHash;
        bytes32 evidenceCommitment;
        uint256 validUntil;
        uint256 nonce;
        uint256 timestamp;
    }

    // orgId => serviceHash => latest attestation
    mapping(bytes32 => mapping(bytes32 => bytes32)) public latestRiskId;
    // orgId => serviceHash => attestationId[]
    mapping(bytes32 => mapping(bytes32 => bytes32[])) public riskAttestationHistory;
    // attestationId => RiskAttestation
    mapping(bytes32 => RiskAttestation) public riskAttestations;
    mapping(address => uint256) public riskNonces;
    mapping(bytes32 => mapping(bytes32 => uint256)) public lastRiskAttestationTimestamp;

    // =========================================================================
    // Finding Attestations (BC-ATT-F)
    // =========================================================================

    struct FindingAttestation {
        bytes32 orgId;
        bytes32 advisoryContentHash;
        bytes32 cveSetHash;
        uint256 processedAt;
        bool matched;
        uint256 nonce;
        address signer;
        uint256 timestamp;
    }

    // orgId => advisoryContentHash => attestationId
    mapping(bytes32 => mapping(bytes32 => bytes32)) public findingAttestations;
    // attestationId => FindingAttestation
    mapping(bytes32 => FindingAttestation) public findingAttestationDetails;
    mapping(address => uint256) public findingNonces;

    // =========================================================================
    // Cross-cutting
    // =========================================================================

    // Domain separator for EIP-712
    bytes32 public constant DEPENDENCY_TYPE_HASH = keccak256(
        "DependencyAttestation(bytes32 consumerOrg,bytes32 consumerServiceHash,bytes32 providerOrg,bytes32 providerServiceHash,uint8 strength,uint8 tolerance,uint256 nonce,uint256 expiry)"
    );
    bytes32 public constant RISK_TYPE_HASH = keccak256(
        "RiskAttestation(bytes32 orgId,bytes32 serviceHash,uint8 riskBand,uint8 criticalityBucket,bytes32 modelVersionHash,bytes32 evidenceCommitment,uint256 validUntil,uint256 nonce)"
    );
    bytes32 public constant FINDING_TYPE_HASH = keccak256(
        "FindingAttestation(bytes32 orgId,bytes32 advisoryContentHash,bytes32 cveSetHash,uint256 processedAt,bool matched,uint256 nonce)"
    );

    // Rate limiting for risk attestations (1 block default for tests)
    uint256 public riskAttestationMinInterval = 1;

    mapping(bytes32 => uint256) public challengeCount;
    mapping(bytes32 => mapping(bytes32 => bool)) public hasChallenged;

    // Events
    event DependencyAttestationSubmitted(
        bytes32 indexed edgeId,
        bytes32 indexed consumerOrg,
        bytes32 indexed providerOrg,
        bytes32 consumerServiceHash,
        bytes32 providerServiceHash,
        uint8 strength,
        uint8 tolerance,
        address signer,
        uint256 timestamp
    );
    event DependencyEdgeConfirmed(bytes32 indexed edgeId, uint256 timestamp);
    event DependencyEdgeRevoked(bytes32 indexed edgeId, address indexed revoker, uint256 timestamp);
    event DependencyEdgeExpired(bytes32 indexed edgeId, uint256 timestamp);
    event DependencyEdgeDisputed(bytes32 indexed edgeId, bytes32 consumerOrg, bytes32 providerOrg, uint256 timestamp);

    event RiskAttestationSubmitted(
        bytes32 indexed orgId,
        bytes32 indexed serviceHash,
        RiskBand riskBand,
        CriticalityBucket criticalityBucket,
        address indexed signer,
        uint256 timestamp
    );
    event RiskAttestationExpired(bytes32 indexed orgId, bytes32 indexed serviceHash, uint256 timestamp);

    event FindingAttestationSubmitted(
        bytes32 indexed orgId,
        bytes32 indexed advisoryContentHash,
        bool matched,
        address indexed signer,
        uint256 timestamp
    );

    event ChallengeSubmitted(
        bytes32 indexed attestationId,
        bytes32 indexed challengerOrg,
        bytes32 evidenceCommitment,
        uint256 timestamp
    );

    // Errors
    error OrgRegistryNotSet();
    error InvalidSignature();
    error InvalidSigner(bytes32 orgId);
    error OrgNotActive(bytes32 orgId);
    error InvalidNonce(address signer, uint256 expected, uint256 actual);
    error AttestationExpired(uint256 expiry);
    error EdgeAlreadyExists(bytes32 edgeId);
    error EdgeNotFound(bytes32 edgeId);
    error EdgeNotConfirmed(bytes32 edgeId);
    error EdgeAlreadyRevoked(bytes32 edgeId);
    error AttestationMismatch();
    error RateLimited(uint256 nextAllowedTimestamp);
    error DuplicateFindingAttestation();
    error InvalidRiskBand();
    error InvalidCriticalityBucket();
    error InvalidDependencyStrength();
    error InvalidToleranceBucket();
    error ChallengeNotAllowed();
    error SameOrg();
    error AttestationNotFound(bytes32 attestationId);
    error OnlyRegistryAdmin();

    // =========================================================================
    // Dependency Attestations
    // =========================================================================

    function submitDependencyAttestation(
        bytes32 consumerOrg,
        bytes32 consumerServiceHash,
        bytes32 providerOrg,
        bytes32 providerServiceHash,
        uint8 strength,
        uint8 tolerance,
        uint256 nonce,
        uint256 expiry,
        bytes calldata signature
    ) external nonReentrant {
        // Validate enums
        if (strength > 2) revert InvalidDependencyStrength();
        if (tolerance > 3) revert InvalidToleranceBucket();
        if (consumerOrg == providerOrg) revert SameOrg();

        // Verify signer is current agent signer for one of the two orgs
        address signer = _verifyDependencySignature(
            consumerOrg, consumerServiceHash, providerOrg, providerServiceHash,
            strength, tolerance, nonce, expiry, signature
        );

        // Both orgs must be active (BC-ORG-06)
        if (!orgRegistry.isOrgActive(consumerOrg)) {
            revert OrgNotActive(consumerOrg);
        }
        if (!orgRegistry.isOrgActive(providerOrg)) {
            revert OrgNotActive(providerOrg);
        }

        // Check nonce
        uint256 expectedNonce = dependencyNonces[signer] + 1;
        if (nonce != expectedNonce) {
            revert InvalidNonce(signer, expectedNonce, nonce);
        }
        dependencyNonces[signer] = nonce;

        // Check expiry
        if (expiry < block.timestamp) {
            revert AttestationExpired(expiry);
        }

        // Compute edge ID
        bytes32 edgeId = keccak256(abi.encode(
            consumerOrg, consumerServiceHash, providerOrg, providerServiceHash
        ));

        DependencyEdge storage edge = dependencyEdges[edgeId];

        if (edge.edgeId == bytes32(0)) {
            edge.edgeId = edgeId;
            orgDependencyEdges[consumerOrg][providerOrg].push(edgeId);
            orgDependencyEdges[providerOrg][consumerOrg].push(edgeId);
        } else if (edge.state == EdgeState.Revoked) {
            // A revoked edge can only come back through two FRESH attestations.
            delete edge.consumerAttestation;
            delete edge.providerAttestation;
            edge.state = EdgeState.Proposed;
            edge.confirmedAt = 0;
            edge.revokedAt = 0;
        } else if (edge.state == EdgeState.Confirmed) {
            if (edge.consumerAttestation.expiry >= block.timestamp && edge.providerAttestation.expiry >= block.timestamp) {
                revert EdgeAlreadyExists(edgeId);
            }
            // expired confirmation: both sides must re-attest
            delete edge.consumerAttestation;
            delete edge.providerAttestation;
            edge.state = EdgeState.Proposed;
            edge.confirmedAt = 0;
        }

        // Store attestation
        DependencyAttestation memory attestation = DependencyAttestation({
            consumerOrg: consumerOrg,
            consumerServiceHash: consumerServiceHash,
            providerOrg: providerOrg,
            providerServiceHash: providerServiceHash,
            strength: DependencyStrength(strength),
            tolerance: ToleranceBucket(tolerance),
            nonce: nonce,
            expiry: expiry,
            signer: signer,
            timestamp: block.timestamp
        });

        // Determine if this is consumer or provider side
        bool isConsumer = (signer == orgRegistry.getOrg(consumerOrg).agentSigner);
        bool isProvider = (signer == orgRegistry.getOrg(providerOrg).agentSigner);

        if (isConsumer) {
            edge.consumerAttestation = attestation;
            if (edge.providerAttestation.timestamp != 0 && edge.providerAttestation.expiry < block.timestamp) {
                delete edge.providerAttestation; // stale counterpart does not count
            }
        } else if (isProvider) {
            edge.providerAttestation = attestation;
            if (edge.consumerAttestation.timestamp != 0 && edge.consumerAttestation.expiry < block.timestamp) {
                delete edge.consumerAttestation;
            }
        } else {
            revert InvalidSigner(consumerOrg); // Signer must be one of the two orgs
        }

        // Check if both sides match and confirm
        if (edge.consumerAttestation.timestamp != 0 && edge.providerAttestation.timestamp != 0) {
            if (_attestationsMatch(edge.consumerAttestation, edge.providerAttestation)) {
                edge.state = EdgeState.Confirmed;
                edge.confirmedAt = block.timestamp;
                emit DependencyEdgeConfirmed(edgeId, block.timestamp);
            } else {
                edge.state = EdgeState.Disputed;
                emit DependencyEdgeDisputed(edgeId, consumerOrg, providerOrg, block.timestamp);
            }
        } else {
            edge.state = EdgeState.Proposed;
        }

        emit DependencyAttestationSubmitted(edgeId, consumerOrg, providerOrg, consumerServiceHash, providerServiceHash, strength, tolerance, signer, block.timestamp);
    }

    /// @notice Either party's current agent signer may revoke an edge (BC-ATT-D-04).
    function revokeDependencyAttestation(
        bytes32 consumerOrg,
        bytes32 consumerServiceHash,
        bytes32 providerOrg,
        bytes32 providerServiceHash
    ) external nonReentrant {
        bytes32 edgeId = keccak256(abi.encode(
            consumerOrg, consumerServiceHash, providerOrg, providerServiceHash
        ));

        DependencyEdge storage edge = dependencyEdges[edgeId];
        if (edge.edgeId == bytes32(0)) {
            revert EdgeNotFound(edgeId);
        }
        if (edge.state == EdgeState.Revoked) {
            revert EdgeAlreadyRevoked(edgeId);
        }
        if (!orgRegistry.isOrgAgent(consumerOrg, msg.sender) && !orgRegistry.isOrgAgent(providerOrg, msg.sender)) {
            revert InvalidSigner(consumerOrg);
        }

        edge.state = EdgeState.Revoked;
        edge.revokedAt = block.timestamp;

        emit DependencyEdgeRevoked(edgeId, msg.sender, block.timestamp);
    }

    function isEdgeConfirmed(
        bytes32 consumerOrg,
        bytes32 consumerServiceHash,
        bytes32 providerOrg,
        bytes32 providerServiceHash
    ) external view returns (bool) {
        bytes32 edgeId = keccak256(abi.encode(
            consumerOrg, consumerServiceHash, providerOrg, providerServiceHash
        ));
        DependencyEdge storage edge = dependencyEdges[edgeId];
        if (edge.state != EdgeState.Confirmed) {
            return false;
        }
        // Check expiry
        if (edge.consumerAttestation.expiry < block.timestamp ||
            edge.providerAttestation.expiry < block.timestamp) {
            return false;
        }
        return true;
    }

    function getEdgeState(
        bytes32 consumerOrg,
        bytes32 consumerServiceHash,
        bytes32 providerOrg,
        bytes32 providerServiceHash
    ) external view returns (EdgeState) {
        bytes32 edgeId = keccak256(abi.encode(
            consumerOrg, consumerServiceHash, providerOrg, providerServiceHash
        ));
        DependencyEdge storage edge = dependencyEdges[edgeId];
        if (edge.edgeId == bytes32(0)) {
            return EdgeState.Expired; // Treat non-existent as expired
        }
        // Check expiry
        if (edge.state == EdgeState.Confirmed) {
            if (edge.consumerAttestation.expiry < block.timestamp ||
                edge.providerAttestation.expiry < block.timestamp) {
                return EdgeState.Expired;
            }
        }
        return edge.state;
    }

    // =========================================================================
    // Risk Attestations
    // =========================================================================

    function submitRiskAttestation(
        bytes32 orgId,
        bytes32 serviceHash,
        uint8 riskBand,
        uint8 criticalityBucket,
        bytes32 modelVersionHash,
        bytes32 evidenceCommitment,
        uint256 validUntil,
        uint256 nonce,
        bytes calldata signature
    ) external nonReentrant {
        // Validate enums
        if (riskBand > 3) revert InvalidRiskBand();
        if (criticalityBucket > 3) revert InvalidCriticalityBucket();

        // Verify signer is current agent signer for orgId
        address signer = _verifyRiskSignature(
            orgId, serviceHash, riskBand, criticalityBucket,
            modelVersionHash, evidenceCommitment, validUntil, nonce, signature
        );

        // Check org is active
        if (!orgRegistry.isOrgActive(orgId)) {
            revert OrgNotActive(orgId);
        }

        // Check nonce
        uint256 expectedNonce = riskNonces[signer] + 1;
        if (nonce != expectedNonce) {
            revert InvalidNonce(signer, expectedNonce, nonce);
        }
        riskNonces[signer] = nonce;

        // Rate limiting
        uint256 lastTimestamp = lastRiskAttestationTimestamp[orgId][serviceHash];
        if (block.timestamp < lastTimestamp + riskAttestationMinInterval) {
            revert RateLimited(lastTimestamp + riskAttestationMinInterval);
        }

        // Check expiry
        if (validUntil < block.timestamp) {
            revert AttestationExpired(validUntil);
        }

        // Create attestation
        bytes32 attestationId = keccak256(abi.encode(
            orgId, serviceHash, riskBand, criticalityBucket,
            modelVersionHash, evidenceCommitment, validUntil, nonce, signer, block.timestamp
        ));

        RiskAttestation memory attestation = RiskAttestation({
            orgId: orgId,
            serviceHash: serviceHash,
            riskBand: RiskBand(riskBand),
            criticalityBucket: CriticalityBucket(criticalityBucket),
            modelVersionHash: modelVersionHash,
            evidenceCommitment: evidenceCommitment,
            validUntil: validUntil,
            nonce: nonce,
            signer: signer,
            timestamp: block.timestamp
        });

        riskAttestations[attestationId] = attestation;
        latestRiskId[orgId][serviceHash] = attestationId;
        riskAttestationHistory[orgId][serviceHash].push(attestationId);
        lastRiskAttestationTimestamp[orgId][serviceHash] = block.timestamp;

        emit RiskAttestationSubmitted(orgId, serviceHash, RiskBand(riskBand), CriticalityBucket(criticalityBucket), signer, block.timestamp);
    }

    function getLatestRiskAttestation(bytes32 orgId, bytes32 serviceHash)
        external view returns (RiskAttestation memory) {
        return riskAttestations[latestRiskId[orgId][serviceHash]];
    }

    function getRiskAttestationHistory(bytes32 orgId, bytes32 serviceHash)
        external view returns (bytes32[] memory) {
        return riskAttestationHistory[orgId][serviceHash];
    }

    function getRiskAttestation(bytes32 attestationId)
        external view returns (RiskAttestation memory) {
        return riskAttestations[attestationId];
    }

    function verifyRiskDisclosure(
        bytes32 orgId,
        bytes32 serviceHash,
        bytes32 attestationId,
        bytes32 salt,
        bytes32 assessmentHash
    ) external view returns (bool) {
        RiskAttestation storage attestation = riskAttestations[attestationId];
        if (attestation.orgId != orgId || attestation.serviceHash != serviceHash) {
            return false;
        }
        bytes32 computedCommitment = keccak256(abi.encode(salt, assessmentHash));
        return computedCommitment == attestation.evidenceCommitment;
    }

    function isRiskAttestationValid(bytes32 orgId, bytes32 serviceHash)
        external view returns (bool) {
        RiskAttestation storage attestation = riskAttestations[latestRiskId[orgId][serviceHash]];
        if (attestation.timestamp == 0) {
            return false;
        }
        return attestation.validUntil >= block.timestamp;
    }

    // =========================================================================
    // Finding Attestations
    // =========================================================================

    function submitFindingAttestation(
        bytes32 orgId,
        bytes32 advisoryContentHash,
        bytes32 cveSetHash,
        uint256 processedAt,
        bool matched,
        uint256 nonce,
        bytes calldata signature
    ) external nonReentrant {
        // Verify signer is current agent signer for orgId
        address signer = _verifyFindingSignature(
            orgId, advisoryContentHash, cveSetHash, processedAt, matched, nonce, signature
        );

        // Check org is active
        if (!orgRegistry.isOrgActive(orgId)) {
            revert OrgNotActive(orgId);
        }

        // Check nonce
        uint256 expectedNonce = findingNonces[signer] + 1;
        if (nonce != expectedNonce) {
            revert InvalidNonce(signer, expectedNonce, nonce);
        }
        findingNonces[signer] = nonce;

        // Check for duplicate (idempotent)
        bytes32 existingId = findingAttestations[orgId][advisoryContentHash];
        if (existingId != bytes32(0)) {
            // Return existing - idempotent
            emit FindingAttestationSubmitted(orgId, advisoryContentHash, matched, signer, block.timestamp);
            return;
        }

        bytes32 attestationId = keccak256(abi.encode(
            orgId, advisoryContentHash, cveSetHash, processedAt, matched, nonce, signer, block.timestamp
        ));

        FindingAttestation memory attestation = FindingAttestation({
            orgId: orgId,
            advisoryContentHash: advisoryContentHash,
            cveSetHash: cveSetHash,
            processedAt: processedAt,
            matched: matched,
            nonce: nonce,
            signer: signer,
            timestamp: block.timestamp
        });

        findingAttestations[orgId][advisoryContentHash] = attestationId;
        findingAttestationDetails[attestationId] = attestation;

        emit FindingAttestationSubmitted(orgId, advisoryContentHash, matched, signer, block.timestamp);
    }

    function getFindingAttestation(bytes32 orgId, bytes32 advisoryContentHash)
        external view returns (FindingAttestation memory) {
        bytes32 attestationId = findingAttestations[orgId][advisoryContentHash];
        if (attestationId == bytes32(0)) {
            return FindingAttestation({
                orgId: bytes32(0),
                advisoryContentHash: bytes32(0),
                cveSetHash: bytes32(0),
                processedAt: 0,
                matched: false,
                nonce: 0,
                signer: address(0),
                timestamp: 0
            });
        }
        return findingAttestationDetails[attestationId];
    }

    // =========================================================================
    // Challenge Mechanism
    // =========================================================================

    /// @notice An org with a CONFIRMED edge to the attesting org can flag a risk attestation as
    ///         disputed (BC-SEC-08). No slashing; surfaced on the dashboard.
    function challengeRiskAttestation(
        bytes32 attestationId,
        bytes32 challengerOrg,
        bytes32 evidenceCommitment
    ) external nonReentrant {
        RiskAttestation storage attestation = riskAttestations[attestationId];
        if (attestation.timestamp == 0) {
            revert AttestationNotFound(attestationId);
        }
        if (!orgRegistry.isOrgAgent(challengerOrg, msg.sender)) {
            revert InvalidSigner(challengerOrg);
        }
        if (challengerOrg == attestation.orgId) {
            revert ChallengeNotAllowed();
        }
        if (!_hasConfirmedEdgeBetween(challengerOrg, attestation.orgId)) {
            revert ChallengeNotAllowed();
        }
        if (hasChallenged[attestationId][challengerOrg]) {
            revert ChallengeNotAllowed();
        }
        hasChallenged[attestationId][challengerOrg] = true;
        challengeCount[attestationId] += 1;

        emit ChallengeSubmitted(attestationId, challengerOrg, evidenceCommitment, block.timestamp);
    }

    function isChallenged(bytes32 attestationId) external view returns (bool) {
        return challengeCount[attestationId] > 0;
    }

    function _hasConfirmedEdgeBetween(bytes32 a, bytes32 b) internal view returns (bool) {
        bytes32[] storage ids = orgDependencyEdges[a][b];
        for (uint256 i = 0; i < ids.length; i++) {
            DependencyEdge storage e = dependencyEdges[ids[i]];
            if (
                e.state == EdgeState.Confirmed &&
                e.consumerAttestation.expiry >= block.timestamp &&
                e.providerAttestation.expiry >= block.timestamp
            ) {
                return true;
            }
        }
        return false;
    }

    // =========================================================================
    // Signature Verification Helpers
    // =========================================================================

    function _verifyDependencySignature(
        bytes32 consumerOrg,
        bytes32 consumerServiceHash,
        bytes32 providerOrg,
        bytes32 providerServiceHash,
        uint8 strength,
        uint8 tolerance,
        uint256 nonce,
        uint256 expiry,
        bytes calldata signature
    ) internal view returns (address) {
        bytes32 digest = _hashDependencyAttestation(
            consumerOrg, consumerServiceHash, providerOrg, providerServiceHash,
            strength, tolerance, nonce, expiry
        );
        address signer = ECDSA.recover(digest, signature);
        
        // Verify signer is one of the two orgs' current agent signers
        address consumerSigner = orgRegistry.getOrg(consumerOrg).agentSigner;
        address providerSigner = orgRegistry.getOrg(providerOrg).agentSigner;
        
        if (signer != consumerSigner && signer != providerSigner) {
            revert InvalidSigner(consumerOrg);
        }
        
        // Verify signer matches the org they claim to represent
        // (This is enforced by the caller knowing which org they are)
        return signer;
    }

    function _verifyRiskSignature(
        bytes32 orgId,
        bytes32 serviceHash,
        uint8 riskBand,
        uint8 criticalityBucket,
        bytes32 modelVersionHash,
        bytes32 evidenceCommitment,
        uint256 validUntil,
        uint256 nonce,
        bytes calldata signature
    ) internal view returns (address) {
        bytes32 digest = _hashRiskAttestation(
            orgId, serviceHash, riskBand, criticalityBucket,
            modelVersionHash, evidenceCommitment, validUntil, nonce
        );
        address signer = ECDSA.recover(digest, signature);
        
        address expectedSigner = orgRegistry.getOrg(orgId).agentSigner;
        if (signer != expectedSigner) {
            revert InvalidSigner(orgId);
        }
        
        return signer;
    }

    function _verifyFindingSignature(
        bytes32 orgId,
        bytes32 advisoryContentHash,
        bytes32 cveSetHash,
        uint256 processedAt,
        bool matched,
        uint256 nonce,
        bytes calldata signature
    ) internal view returns (address) {
        bytes32 digest = _hashFindingAttestation(
            orgId, advisoryContentHash, cveSetHash, processedAt, matched, nonce
        );
        address signer = ECDSA.recover(digest, signature);
        
        address expectedSigner = orgRegistry.getOrg(orgId).agentSigner;
        if (signer != expectedSigner) {
            revert InvalidSigner(orgId);
        }
        
        return signer;
    }

    function _hashDependencyAttestation(
        bytes32 consumerOrg,
        bytes32 consumerServiceHash,
        bytes32 providerOrg,
        bytes32 providerServiceHash,
        uint8 strength,
        uint8 tolerance,
        uint256 nonce,
        uint256 expiry
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            DEPENDENCY_TYPE_HASH,
            consumerOrg, consumerServiceHash, providerOrg, providerServiceHash,
            strength, tolerance, nonce, expiry
        ));
        return _hashTypedDataV4(structHash);
    }

    function _hashRiskAttestation(
        bytes32 orgId,
        bytes32 serviceHash,
        uint8 riskBand,
        uint8 criticalityBucket,
        bytes32 modelVersionHash,
        bytes32 evidenceCommitment,
        uint256 validUntil,
        uint256 nonce
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            RISK_TYPE_HASH,
            orgId, serviceHash, riskBand, criticalityBucket,
            modelVersionHash, evidenceCommitment, validUntil, nonce
        ));
        return _hashTypedDataV4(structHash);
    }

    function _hashFindingAttestation(
        bytes32 orgId,
        bytes32 advisoryContentHash,
        bytes32 cveSetHash,
        uint256 processedAt,
        bool matched,
        uint256 nonce
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            FINDING_TYPE_HASH,
            orgId, advisoryContentHash, cveSetHash, processedAt, matched, nonce
        ));
        return _hashTypedDataV4(structHash);
    }

    function _attestationsMatch(
        DependencyAttestation memory a,
        DependencyAttestation memory b
    ) internal pure returns (bool) {
        return a.consumerOrg == b.consumerOrg &&
               a.consumerServiceHash == b.consumerServiceHash &&
               a.providerOrg == b.providerOrg &&
               a.providerServiceHash == b.providerServiceHash &&
               a.strength == b.strength &&
               a.tolerance == b.tolerance;
    }

    constructor(address orgRegistryAddress) EIP712("AttestationRegistry", "1") {
        if (orgRegistryAddress == address(0)) {
            revert OrgRegistryNotSet();
        }
        orgRegistry = OrgRegistry(orgRegistryAddress);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    // Admin function to set rate limit interval
    function setRiskAttestationMinInterval(uint256 interval) external {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            revert OnlyRegistryAdmin();
        }
        riskAttestationMinInterval = interval;
    }
}