// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title OrgRegistry
/// @notice Manages organization identities, roles, and keys for the CascadeShield system
contract OrgRegistry is AccessControl {
    using ECDSA for bytes32;

    // Roles
    bytes32 public constant REGISTRY_ADMIN_ROLE = keccak256("REGISTRY_ADMIN_ROLE");

    // Sector enum
    enum Sector { Energy, Water, Healthcare, Other }

    // Organization struct
    struct Organization {
        bytes32 orgId;
        bytes32 nameHash;
        Sector sector;
        address adminAddress;
        address agentSigner;
        address[] approvers;
        uint8 threshold; // M of N approvers required for HIGH actions
        bool active;
        uint256 createdAt;
        uint256 updatedAt;
    }

    // Approver with metadata
    struct Approver {
        address addr;
        bool isSafetyOfficer;
    }

    // State
    mapping(bytes32 => Organization) public organizations;
    mapping(bytes32 => Approver[]) public orgApprovers;
    bytes32[] public orgIds;
    mapping(address => bytes32) public addressToOrgId;

    // Events
    event OrgRegistered(
        bytes32 indexed orgId,
        bytes32 nameHash,
        Sector sector,
        address indexed adminAddress,
        address indexed agentSigner,
        uint256 timestamp
    );
    event AgentSignerRotated(
        bytes32 indexed orgId,
        address indexed oldSigner,
        address indexed newSigner,
        uint256 timestamp
    );
    event ApproverSetUpdated(
        bytes32 indexed orgId,
        address[] approvers,
        uint8 threshold,
        uint256 timestamp
    );
    event OrgDeactivated(bytes32 indexed orgId, uint256 timestamp);
    event OrgReactivated(bytes32 indexed orgId, uint256 timestamp);

    // Errors
    error OnlyRegistryAdmin();
    error OnlyOrgAdmin(bytes32 orgId);
    error OrgNotFound(bytes32 orgId);
    error OrgAlreadyExists(bytes32 orgId);
    error OrgNotActive(bytes32 orgId);
    error InvalidApproverCount(uint256 min, uint256 max);
    error InvalidThreshold(uint8 threshold, uint256 approverCount);
    error AgentSignerCannotBeApprover();
    error DuplicateApprover(address approver);
    error ZeroAddress();
    error InvalidSector();
    error AddressAlreadyBound(address addr);

    constructor() {
        _grantRole(REGISTRY_ADMIN_ROLE, msg.sender);
    }

    // =========================================================================
    // View Functions
    // =========================================================================

    function getOrg(bytes32 orgId) external view returns (Organization memory) {
        Organization storage org = organizations[orgId];
        if (org.orgId == bytes32(0)) {
            revert OrgNotFound(orgId);
        }
        return org;
    }

    function getApproverCount(bytes32 orgId) external view returns (uint256) {
        if (organizations[orgId].orgId == bytes32(0)) {
            revert OrgNotFound(orgId);
        }
        return orgApprovers[orgId].length;
    }

    function getApproverAt(bytes32 orgId, uint256 index) external view returns (address, bool) {
        if (organizations[orgId].orgId == bytes32(0)) {
            revert OrgNotFound(orgId);
        }
        Approver storage approver = orgApprovers[orgId][index];
        return (approver.addr, approver.isSafetyOfficer);
    }

    function getThreshold(bytes32 orgId) external view returns (uint8) {
        if (organizations[orgId].orgId == bytes32(0)) {
            revert OrgNotFound(orgId);
        }
        return organizations[orgId].threshold;
    }

    function isOrgAgent(bytes32 orgId, address addr) external view returns (bool) {
        Organization storage org = organizations[orgId];
        return org.orgId != bytes32(0) && org.agentSigner == addr && org.active;
    }

    function isOrgApprover(bytes32 orgId, address addr) external view returns (bool) {
        if (!organizations[orgId].active) return false;
        Approver[] storage approvers = orgApprovers[orgId];
        for (uint256 i = 0; i < approvers.length; i++) {
            if (approvers[i].addr == addr) {
                return true;
            }
        }
        return false;
    }

    function _isApproverAddr(bytes32 orgId, address addr) internal view returns (bool) {
        Approver[] storage approvers = orgApprovers[orgId];
        for (uint256 i = 0; i < approvers.length; i++) {
            if (approvers[i].addr == addr) return true;
        }
        return false;
    }

    function isOrgSafetyOfficer(bytes32 orgId, address addr) external view returns (bool) {
        Approver[] storage approvers = orgApprovers[orgId];
        for (uint256 i = 0; i < approvers.length; i++) {
            if (approvers[i].addr == addr && approvers[i].isSafetyOfficer) {
                return true;
            }
        }
        return false;
    }

    function getAllOrgIds() external view returns (bytes32[] memory) {
        return orgIds;
    }

    function getOrgIdByAddress(address addr) external view returns (bytes32) {
        return addressToOrgId[addr];
    }

    function isOrgActive(bytes32 orgId) external view returns (bool) {
        return organizations[orgId].active;
    }

    // =========================================================================
    // Admin Functions (REGISTRY_ADMIN_ROLE only)
    // =========================================================================

    function registerOrg(
        bytes32 orgId,
        bytes32 nameHash,
        uint8 sector,
        address adminAddress,
        address agentSigner,
        address[] calldata approvers,
        uint8 threshold,
        bool[] calldata safetyOfficerFlags
    ) external {
        if (!hasRole(REGISTRY_ADMIN_ROLE, msg.sender)) {
            revert OnlyRegistryAdmin();
        }
        if (organizations[orgId].orgId != bytes32(0)) {
            revert OrgAlreadyExists(orgId);
        }
        if (adminAddress == address(0) || agentSigner == address(0)) {
            revert ZeroAddress();
        }
        if (sector > 3) {
            revert InvalidSector();
        }
        if (approvers.length < 3) {
            revert InvalidApproverCount(3, 255);
        }
        if (threshold == 0 || threshold > approvers.length) {
            revert InvalidThreshold(threshold, approvers.length);
        }
        if (safetyOfficerFlags.length != approvers.length) {
            revert InvalidApproverCount(approvers.length, approvers.length);
        }

        if (addressToOrgId[agentSigner] != bytes32(0)) {
            revert AddressAlreadyBound(agentSigner);
        }

        // Check agent signer is not in approvers
        for (uint256 i = 0; i < approvers.length; i++) {
            if (addressToOrgId[approvers[i]] != bytes32(0)) {
                revert AddressAlreadyBound(approvers[i]);
            }
            if (approvers[i] == agentSigner) {
                revert AgentSignerCannotBeApprover();
            }
            if (approvers[i] == address(0)) {
                revert ZeroAddress();
            }
            // Check for duplicates
            for (uint256 j = i + 1; j < approvers.length; j++) {
                if (approvers[i] == approvers[j]) {
                    revert DuplicateApprover(approvers[i]);
                }
            }
        }

        // At least one safety officer required
        bool hasSafetyOfficer = false;
        for (uint256 i = 0; i < safetyOfficerFlags.length; i++) {
            if (safetyOfficerFlags[i]) {
                hasSafetyOfficer = true;
                break;
            }
        }
        if (!hasSafetyOfficer) {
            revert InvalidApproverCount(1, 255); // Reuse error for "at least one safety officer"
        }

        Organization storage org = organizations[orgId];
        org.orgId = orgId;
        org.nameHash = nameHash;
        org.sector = Sector(sector);
        org.adminAddress = adminAddress;
        org.agentSigner = agentSigner;
        org.approvers = approvers;
        org.threshold = threshold;
        org.active = true;
        org.createdAt = block.timestamp;
        org.updatedAt = block.timestamp;

        // Store approvers with metadata
        for (uint256 i = 0; i < approvers.length; i++) {
            orgApprovers[orgId].push(Approver({
                addr: approvers[i],
                isSafetyOfficer: safetyOfficerFlags[i]
            }));
        }

        orgIds.push(orgId);
        addressToOrgId[agentSigner] = orgId;
        for (uint256 i = 0; i < approvers.length; i++) {
            addressToOrgId[approvers[i]] = orgId;
        }

        emit OrgRegistered(orgId, nameHash, Sector(sector), adminAddress, agentSigner, block.timestamp);
    }

    // =========================================================================
    // Org Admin Functions (org admin only)
    // =========================================================================

    function rotateAgentSigner(bytes32 orgId, address newAgentSigner) external {
        _onlyOrgAdmin(orgId);
        if (newAgentSigner == address(0)) {
            revert ZeroAddress();
        }
        Organization storage org = organizations[orgId];
        if (_isApproverAddr(orgId, newAgentSigner)) {
            revert AgentSignerCannotBeApprover();
        }
        if (addressToOrgId[newAgentSigner] != bytes32(0) && addressToOrgId[newAgentSigner] != orgId) {
            revert AddressAlreadyBound(newAgentSigner);
        }
        address oldSigner = org.agentSigner;
        org.agentSigner = newAgentSigner;
        delete addressToOrgId[oldSigner];
        org.updatedAt = block.timestamp;

        addressToOrgId[newAgentSigner] = orgId;

        emit AgentSignerRotated(orgId, oldSigner, newAgentSigner, block.timestamp);
    }

    function updateApproverSet(
        bytes32 orgId,
        address[] calldata newApprovers,
        uint8 newThreshold,
        bool[] calldata safetyOfficerFlags
    ) external {
        _onlyOrgAdmin(orgId);
        if (newApprovers.length < 3) {
            revert InvalidApproverCount(3, 255);
        }
        if (newThreshold == 0 || newThreshold > newApprovers.length) {
            revert InvalidThreshold(newThreshold, newApprovers.length);
        }
        if (safetyOfficerFlags.length != newApprovers.length) {
            revert InvalidApproverCount(newApprovers.length, newApprovers.length);
        }

        Organization storage org = organizations[orgId];
        
        // Check agent signer is not in new approvers
        for (uint256 i = 0; i < newApprovers.length; i++) {
            if (newApprovers[i] == org.agentSigner) {
                revert AgentSignerCannotBeApprover();
            }
            if (newApprovers[i] == address(0)) {
                revert ZeroAddress();
            }
            for (uint256 j = i + 1; j < newApprovers.length; j++) {
                if (newApprovers[i] == newApprovers[j]) {
                    revert DuplicateApprover(newApprovers[i]);
                }
            }
        }

        // At least one safety officer required
        bool hasSafetyOfficer = false;
        for (uint256 i = 0; i < safetyOfficerFlags.length; i++) {
            if (safetyOfficerFlags[i]) {
                hasSafetyOfficer = true;
                break;
            }
        }
        if (!hasSafetyOfficer) {
            revert InvalidApproverCount(1, 255);
        }

        // Clear old approvers from addressToOrgId mapping (not strictly necessary but clean)
        // Note: We don't remove old mappings as they might be needed for historical queries

        // Add new approvers to addressToOrgId
        for (uint256 i = 0; i < newApprovers.length; i++) {
            addressToOrgId[newApprovers[i]] = orgId;
        }

        // Clear existing approvers and add new ones
        delete orgApprovers[orgId];
        for (uint256 i = 0; i < newApprovers.length; i++) {
            orgApprovers[orgId].push(Approver({
                addr: newApprovers[i],
                isSafetyOfficer: safetyOfficerFlags[i]
            }));
        }
        org.approvers = newApprovers;
        org.threshold = newThreshold;
        org.updatedAt = block.timestamp;

        emit ApproverSetUpdated(orgId, newApprovers, newThreshold, block.timestamp);
    }

    function deactivateOrg(bytes32 orgId) external {
        if (!hasRole(REGISTRY_ADMIN_ROLE, msg.sender)) {
            revert OnlyRegistryAdmin();
        }
        Organization storage org = organizations[orgId];
        if (org.orgId == bytes32(0)) {
            revert OrgNotFound(orgId);
        }
        if (!org.active) {
            return; // Idempotent
        }
        org.active = false;
        org.updatedAt = block.timestamp;
        emit OrgDeactivated(orgId, block.timestamp);
    }

    function reactivateOrg(bytes32 orgId) external {
        if (!hasRole(REGISTRY_ADMIN_ROLE, msg.sender)) {
            revert OnlyRegistryAdmin();
        }
        Organization storage org = organizations[orgId];
        if (org.orgId == bytes32(0)) {
            revert OrgNotFound(orgId);
        }
        if (org.active) {
            return; // Idempotent
        }
        org.active = true;
        org.updatedAt = block.timestamp;
        emit OrgReactivated(orgId, block.timestamp);
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    function _onlyOrgAdmin(bytes32 orgId) internal view {
        Organization storage org = organizations[orgId];
        if (org.orgId == bytes32(0)) {
            revert OrgNotFound(orgId);
        }
        if (org.adminAddress != msg.sender) {
            revert OnlyOrgAdmin(orgId);
        }
    }
}