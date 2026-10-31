// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./OrgRegistry.sol";
import "./AttestationRegistry.sol";

/// @title AlertBus
/// @notice Cross-organisation early-warning channel (BC-ALERT-*). An alert is only *relevant* to a
///         consumer service if a bilaterally confirmed dependency edge links it to the provider service.
contract AlertBus {
    OrgRegistry public immutable orgRegistry;
    AttestationRegistry public immutable attestationRegistry;

    enum Severity { Low, Medium, High, Critical }
    enum TtiBucket { Under15m, Min15To60, Hours1To4, Over4h }
    enum Status { None, Active, Resolved }

    struct Alert {
        bytes32 providerOrg;
        bytes32 providerServiceHash;
        Severity severity;
        TtiBucket tti;
        bytes32 evidenceCommitment;
        uint256 expiry;
        uint256 createdAt;
        uint256 resolvedAt;
        Status status;
    }

    uint256 public constant RATE_WINDOW = 1 hours;
    uint256 public constant RATE_LIMIT = 30;       // alerts per org per window
    uint256 public constant DEDUPE_WINDOW = 5 minutes;
    uint256 public constant MAX_SCAN = 200;        // bound for the affectedBy view

    mapping(bytes32 => Alert) private _alerts;
    bytes32[] private _alertIds;
    mapping(bytes32 => mapping(bytes32 => uint256)) private _ackedAt;           // alertId => consumerOrg => ts
    mapping(bytes32 => mapping(bytes32 => mapping(uint8 => bytes32))) private _lastAlert; // org=>service=>sev=>id
    mapping(bytes32 => uint256) private _windowStart;
    mapping(bytes32 => uint256) private _windowCount;
    uint256 private _nonce;

    event CascadeAlert(
        bytes32 indexed alertId,
        bytes32 indexed providerOrg,
        bytes32 indexed providerServiceHash,
        Severity severity,
        TtiBucket tti,
        bytes32 evidenceCommitment,
        uint256 expiry
    );
    event AlertDeduplicated(bytes32 indexed alertId, bytes32 indexed providerOrg);
    event AlertAcknowledged(bytes32 indexed alertId, bytes32 indexed consumerOrg, bytes32 consumerServiceHash, uint256 timestamp);
    event AlertResolved(bytes32 indexed alertId, bytes32 indexed providerOrg, uint256 timestamp);

    error ZeroAddress();
    error NotOrgAgent(bytes32 orgId, address caller);
    error InvalidSeverity();
    error InvalidTti();
    error InvalidExpiry();
    error RateLimitExceeded(bytes32 orgId);
    error AlertNotFound(bytes32 alertId);
    error AlertNotActive(bytes32 alertId);
    error AlertIsExpired(bytes32 alertId);
    error NotAffected(bytes32 alertId, bytes32 consumerOrg, bytes32 consumerServiceHash);
    error AlreadyAcknowledged(bytes32 alertId, bytes32 consumerOrg);
    error NotAlertOwner(bytes32 alertId);

    constructor(address orgRegistryAddress, address attestationRegistryAddress) {
        if (orgRegistryAddress == address(0) || attestationRegistryAddress == address(0)) revert ZeroAddress();
        orgRegistry = OrgRegistry(orgRegistryAddress);
        attestationRegistry = AttestationRegistry(attestationRegistryAddress);
    }

    function publish(
        bytes32 providerOrg,
        bytes32 providerServiceHash,
        uint8 severity,
        uint8 tti,
        bytes32 evidenceCommitment,
        uint256 expiry
    ) external returns (bytes32 alertId) {
        if (!orgRegistry.isOrgAgent(providerOrg, msg.sender)) revert NotOrgAgent(providerOrg, msg.sender);
        if (severity > uint8(Severity.Critical)) revert InvalidSeverity();
        if (tti > uint8(TtiBucket.Over4h)) revert InvalidTti();
        if (expiry <= block.timestamp) revert InvalidExpiry();

        // BC-ALERT-04 de-dupe: identical active alert inside the window collapses.
        bytes32 prev = _lastAlert[providerOrg][providerServiceHash][severity];
        if (prev != bytes32(0)) {
            Alert storage p = _alerts[prev];
            if (p.status == Status.Active && p.expiry > block.timestamp && block.timestamp < p.createdAt + DEDUPE_WINDOW) {
                emit AlertDeduplicated(prev, providerOrg);
                return prev;
            }
        }

        // BC-ALERT-06 sliding(ish) window rate limit
        if (block.timestamp >= _windowStart[providerOrg] + RATE_WINDOW) {
            _windowStart[providerOrg] = block.timestamp;
            _windowCount[providerOrg] = 0;
        }
        if (_windowCount[providerOrg] >= RATE_LIMIT) revert RateLimitExceeded(providerOrg);
        _windowCount[providerOrg] += 1;

        alertId = keccak256(abi.encode(providerOrg, providerServiceHash, severity, _nonce++, block.chainid));
        _alerts[alertId] = Alert({
            providerOrg: providerOrg,
            providerServiceHash: providerServiceHash,
            severity: Severity(severity),
            tti: TtiBucket(tti),
            evidenceCommitment: evidenceCommitment,
            expiry: expiry,
            createdAt: block.timestamp,
            resolvedAt: 0,
            status: Status.Active
        });
        _alertIds.push(alertId);
        _lastAlert[providerOrg][providerServiceHash][severity] = alertId;

        emit CascadeAlert(alertId, providerOrg, providerServiceHash, Severity(severity), TtiBucket(tti), evidenceCommitment, expiry);
    }

    /// @notice A consumer agent acknowledges an alert for one of its services. Requires a confirmed edge.
    function acknowledge(bytes32 alertId, bytes32 consumerOrg, bytes32 consumerServiceHash) external {
        Alert storage a = _alerts[alertId];
        if (a.status == Status.None) revert AlertNotFound(alertId);
        if (a.status != Status.Active) revert AlertNotActive(alertId);
        if (block.timestamp > a.expiry) revert AlertIsExpired(alertId);
        if (!orgRegistry.isOrgAgent(consumerOrg, msg.sender)) revert NotOrgAgent(consumerOrg, msg.sender);
        if (!attestationRegistry.isEdgeConfirmed(consumerOrg, consumerServiceHash, a.providerOrg, a.providerServiceHash)) {
            revert NotAffected(alertId, consumerOrg, consumerServiceHash);
        }
        if (_ackedAt[alertId][consumerOrg] != 0) revert AlreadyAcknowledged(alertId, consumerOrg);
        _ackedAt[alertId][consumerOrg] = block.timestamp;
        emit AlertAcknowledged(alertId, consumerOrg, consumerServiceHash, block.timestamp);
    }

    function resolve(bytes32 alertId) external {
        Alert storage a = _alerts[alertId];
        if (a.status == Status.None) revert AlertNotFound(alertId);
        if (!orgRegistry.isOrgAgent(a.providerOrg, msg.sender)) revert NotAlertOwner(alertId);
        if (a.status != Status.Active) revert AlertNotActive(alertId);
        a.status = Status.Resolved;
        a.resolvedAt = block.timestamp;
        emit AlertResolved(alertId, a.providerOrg, block.timestamp);
    }

    // ------------------------------------------------------------------- views

    function getAlert(bytes32 alertId) external view returns (Alert memory) {
        if (_alerts[alertId].status == Status.None) revert AlertNotFound(alertId);
        return _alerts[alertId];
    }

    function alertCount() external view returns (uint256) {
        return _alertIds.length;
    }

    function alertIdAt(uint256 i) external view returns (bytes32) {
        return _alertIds[i];
    }

    function isActive(bytes32 alertId) public view returns (bool) {
        Alert storage a = _alerts[alertId];
        return a.status == Status.Active && block.timestamp <= a.expiry;
    }

    function acknowledgedAt(bytes32 alertId, bytes32 consumerOrg) external view returns (uint256) {
        return _ackedAt[alertId][consumerOrg];
    }

    /// @notice Active, unexpired alerts whose provider service has a CONFIRMED edge to this consumer service.
    ///         Scans at most MAX_SCAN most-recent alerts. Alerts without a confirmed edge are never returned.
    function affectedBy(bytes32 consumerOrg, bytes32 consumerServiceHash) external view returns (bytes32[] memory) {
        uint256 n = _alertIds.length;
        uint256 start = n > MAX_SCAN ? n - MAX_SCAN : 0;
        bytes32[] memory tmp = new bytes32[](n - start);
        uint256 c;
        for (uint256 i = start; i < n; i++) {
            bytes32 id = _alertIds[i];
            Alert storage a = _alerts[id];
            if (!isActive(id)) continue;
            if (attestationRegistry.isEdgeConfirmed(consumerOrg, consumerServiceHash, a.providerOrg, a.providerServiceHash)) {
                tmp[c++] = id;
            }
        }
        bytes32[] memory out = new bytes32[](c);
        for (uint256 j = 0; j < c; j++) out[j] = tmp[j];
        return out;
    }
}
