// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/// @title FirmwareRegistry
/// @notice Supply-chain integrity registry for firmware verification
contract FirmwareRegistry is AccessControl, ReentrancyGuard {
    bytes32 public constant VENDOR_ROLE = keccak256("VENDOR_ROLE");
    bytes32 public constant REGISTRY_ADMIN_ROLE = keccak256("REGISTRY_ADMIN_ROLE");

    enum VerificationResult { Match, Mismatch, Unknown, Revoked }

    struct FirmwareEntry {
        bytes32 vendorId;
        bytes32 modelHash;
        bytes32 versionHash;
        bytes32 firmwareSha256;
        bytes32 sbomHash;
        uint256 releaseTimestamp;
        bool revoked;
        uint8 revocationReason; // 0=none, 1=security, 2=superseded, 3=other
        address publisher;
        uint256 publishedAt;
    }

    // vendorId => modelHash => versionHash => FirmwareEntry
    mapping(bytes32 => mapping(bytes32 => mapping(bytes32 => FirmwareEntry))) public firmwareEntries;
    
    // Track all entries for enumeration
    bytes32[] public vendorIds;
    mapping(bytes32 => bytes32[]) public vendorModels;
    mapping(bytes32 => mapping(bytes32 => bytes32[])) public modelVersions;
    
    // Vendor address => vendorId mapping
    mapping(address => bytes32) public vendorAddressToId;

    // Events
    event FirmwarePublished(
        bytes32 indexed vendorId,
        bytes32 indexed modelHash,
        bytes32 indexed versionHash,
        bytes32 firmwareSha256,
        bytes32 sbomHash,
        uint256 releaseTimestamp,
        address publisher
    );
    event FirmwareRevoked(
        bytes32 indexed vendorId,
        bytes32 indexed modelHash,
        bytes32 indexed versionHash,
        uint8 reason,
        address revoker
    );
    event VendorAdded(bytes32 indexed vendorId, address indexed vendorAddress);
    event VendorRemoved(bytes32 indexed vendorId);

    // Errors
    error OnlyRegistryAdmin();
    error OnlyVendor();
    error VendorNotAuthorized(bytes32 vendorId);
    error VendorAlreadyExists(bytes32 vendorId);
    error VendorNotFound(bytes32 vendorId);
    error FirmwareAlreadyPublished(bytes32 vendorId, bytes32 modelHash, bytes32 versionHash);
    error FirmwareNotFound(bytes32 vendorId, bytes32 modelHash, bytes32 versionHash);
    error FirmwareAlreadyRevoked(bytes32 vendorId, bytes32 modelHash, bytes32 versionHash);
    error CannotModifyPublishedFirmware();
    error InvalidBatchSize(uint256 maxSize);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRY_ADMIN_ROLE, msg.sender);
        _setRoleAdmin(VENDOR_ROLE, DEFAULT_ADMIN_ROLE);
    }

    // =========================================================================
    // Vendor Management (Registry Admin only)
    // =========================================================================

    function addVendor(bytes32 vendorId, address vendorAddress) external {
        if (!hasRole(REGISTRY_ADMIN_ROLE, msg.sender)) {
            revert OnlyRegistryAdmin();
        }
        if (hasRole(VENDOR_ROLE, vendorAddress)) {
            revert VendorAlreadyExists(vendorId);
        }
        _grantRole(VENDOR_ROLE, vendorAddress);
        vendorIds.push(vendorId);
        vendorAddressToId[vendorAddress] = vendorId;
        emit VendorAdded(vendorId, vendorAddress);
    }

    function removeVendor(bytes32 vendorId, address vendorAddress) external {
        if (!hasRole(REGISTRY_ADMIN_ROLE, msg.sender)) {
            revert OnlyRegistryAdmin();
        }
        _revokeRole(VENDOR_ROLE, vendorAddress);
        delete vendorAddressToId[vendorAddress];
        // Note: We don't remove from vendorIds array to preserve indices
        emit VendorRemoved(vendorId);
    }

    function isVendor(address addr) external view returns (bool) {
        return hasRole(VENDOR_ROLE, addr);
    }

    function getVendorId(address vendorAddress) external view returns (bytes32) {
        return vendorAddressToId[vendorAddress];
    }

    // =========================================================================
    // Firmware Publishing (Vendor only)
    // =========================================================================

    function publishFirmware(
        bytes32 vendorId,
        bytes32 modelHash,
        bytes32 versionHash,
        bytes32 firmwareSha256,
        bytes32 sbomHash,
        uint256 releaseTimestamp
    ) external nonReentrant {
        // Verify caller has VENDOR_ROLE
        if (!hasRole(VENDOR_ROLE, msg.sender)) {
            revert OnlyVendor();
        }
        // Verify caller is authorized for this vendorId
        bytes32 authorizedVendorId = vendorAddressToId[msg.sender];
        if (authorizedVendorId != vendorId) {
            revert VendorNotAuthorized(vendorId);
        }

        FirmwareEntry storage entry = firmwareEntries[vendorId][modelHash][versionHash];
        if (entry.publisher != address(0)) {
            revert FirmwareAlreadyPublished(vendorId, modelHash, versionHash);
        }

        entry.vendorId = vendorId;
        entry.modelHash = modelHash;
        entry.versionHash = versionHash;
        entry.firmwareSha256 = firmwareSha256;
        entry.sbomHash = sbomHash;
        entry.releaseTimestamp = releaseTimestamp;
        entry.revoked = false;
        entry.revocationReason = 0;
        entry.publisher = msg.sender;
        entry.publishedAt = block.timestamp;

        // Track for enumeration
        if (vendorModels[vendorId].length == 0 || 
            _findModelIndex(vendorId, modelHash) == vendorModels[vendorId].length) {
            vendorModels[vendorId].push(modelHash);
        }
        if (modelVersions[vendorId][modelHash].length == 0 ||
            _findVersionIndex(vendorId, modelHash, versionHash) == modelVersions[vendorId][modelHash].length) {
            modelVersions[vendorId][modelHash].push(versionHash);
        }

        emit FirmwarePublished(vendorId, modelHash, versionHash, firmwareSha256, sbomHash, releaseTimestamp, msg.sender);
    }

    function revokeFirmware(
        bytes32 vendorId,
        bytes32 modelHash,
        bytes32 versionHash,
        uint8 reasonCode
    ) external nonReentrant {
        if (!hasRole(VENDOR_ROLE, msg.sender)) {
            revert OnlyVendor();
        }

        FirmwareEntry storage entry = firmwareEntries[vendorId][modelHash][versionHash];
        if (entry.publisher == address(0)) {
            revert FirmwareNotFound(vendorId, modelHash, versionHash);
        }
        if (entry.revoked) {
            revert FirmwareAlreadyRevoked(vendorId, modelHash, versionHash);
        }
        if (entry.publisher != msg.sender) {
            revert VendorNotAuthorized(vendorId);
        }

        entry.revoked = true;
        entry.revocationReason = reasonCode;

        emit FirmwareRevoked(vendorId, modelHash, versionHash, reasonCode, msg.sender);
    }

    // =========================================================================
    // Verification (Public view)
    // =========================================================================

    function _verifyFirmwareInternal(
        bytes32 vendorId,
        bytes32 modelHash,
        bytes32 versionHash,
        bytes32 observedSha256
    ) internal view returns (VerificationResult) {
        FirmwareEntry storage entry = firmwareEntries[vendorId][modelHash][versionHash];
        
        if (entry.publisher == address(0)) {
            return VerificationResult.Unknown;
        }
        if (entry.revoked) {
            return VerificationResult.Revoked;
        }
        if (entry.firmwareSha256 == observedSha256) {
            return VerificationResult.Match;
        }
        return VerificationResult.Mismatch;
    }

    function verifyFirmware(
        bytes32 vendorId,
        bytes32 modelHash,
        bytes32 versionHash,
        bytes32 observedSha256
    ) external view returns (VerificationResult) {
        return _verifyFirmwareInternal(vendorId, modelHash, versionHash, observedSha256);
    }

    function verifyMany(
        bytes32[] calldata vendorIds_,
        bytes32[] calldata modelHashes,
        bytes32[] calldata versionHashes,
        bytes32[] calldata observedSha256s
    ) external view returns (VerificationResult[] memory) {
        uint256 len = vendorIds_.length;
        if (modelHashes.length != len || versionHashes.length != len || observedSha256s.length != len) {
            revert InvalidBatchSize(100);
        }
        if (len > 100) {
            revert InvalidBatchSize(100);
        }

        VerificationResult[] memory results = new VerificationResult[](len);
        for (uint256 i = 0; i < len; i++) {
            results[i] = _verifyFirmwareInternal(vendorIds_[i], modelHashes[i], versionHashes[i], observedSha256s[i]);
        }
        return results;
    }

    function getFirmwareEntry(
        bytes32 vendorId,
        bytes32 modelHash,
        bytes32 versionHash
    ) external view returns (FirmwareEntry memory) {
        return firmwareEntries[vendorId][modelHash][versionHash];
    }

    function getVendorModels(bytes32 vendorId) external view returns (bytes32[] memory) {
        return vendorModels[vendorId];
    }

    function getModelVersions(bytes32 vendorId, bytes32 modelHash) external view returns (bytes32[] memory) {
        return modelVersions[vendorId][modelHash];
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    function _findModelIndex(bytes32 vendorId, bytes32 modelHash) internal view returns (uint256) {
        bytes32[] storage models = vendorModels[vendorId];
        for (uint256 i = 0; i < models.length; i++) {
            if (models[i] == modelHash) return i;
        }
        return models.length;
    }

    function _findVersionIndex(bytes32 vendorId, bytes32 modelHash, bytes32 versionHash) internal view returns (uint256) {
        bytes32[] storage versions = modelVersions[vendorId][modelHash];
        for (uint256 i = 0; i < versions.length; i++) {
            if (versions[i] == versionHash) return i;
        }
        return versions.length;
    }
}