// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./OrgRegistry.sol";
import "./AuditLog.sol";

/// @title ApprovalGate
/// @notice Non-bypassable human-in-the-loop gate for agent actions (BC-GATE-*).
///         There is deliberately NO emergency/bypass path (BC-GATE-15).
contract ApprovalGate is EIP712, ReentrancyGuard {
    OrgRegistry public immutable orgRegistry;
    AuditLog public immutable auditLog;

    enum ImpactClass { Low, Medium, High }
    enum Status { None, Pending, Approved, Rejected, Expired, Executed, Cancelled }

    uint256 public constant MAX_PENDING_PER_ORG = 20;
    uint8 private constant CRITIC_VERDICT_KIND = 3;
    bytes32 public constant VOTE_TYPEHASH = keccak256("Vote(bytes32 requestId,bool approve)");

    struct Request {
        bytes32 orgId;
        bytes32 planHash;
        bytes32 criticVerdictDigest;
        bytes32 stepsHash;
        uint64 expiry;
        ImpactClass impact;
        Status status;
        uint8 required;          // approvals required (1 for MEDIUM, snapshot threshold for HIGH)
        uint8 approvals;
        uint8 rejections;
        bool safetyApproved;
        bool needsSafety;
        uint256 safetyMask;      // bit i set => approvers[i] is a safety officer (snapshot)
        bytes32 executionDigest;
        address[] approvers;     // snapshot (BC-GATE-03)
    }

    mapping(bytes32 => Request) private _requests;
    mapping(bytes32 => mapping(address => uint8)) private _vote; // 0 none, 1 approve, 2 reject
    mapping(bytes32 => uint256) public livePending; // per-org Pending + Approved count
    uint256 public requestNonce;

    event ApprovalRequested(bytes32 indexed requestId, bytes32 indexed orgId, bytes32 planHash, ImpactClass impact, uint256 expiry, uint8 required);
    event Approved(bytes32 indexed requestId, address indexed approver);
    event Rejected(bytes32 indexed requestId, address indexed approver);
    event ApprovalThresholdReached(bytes32 indexed requestId);
    event RequestRejected(bytes32 indexed requestId);
    event RequestExpired(bytes32 indexed requestId);
    event Executed(bytes32 indexed requestId, bytes32 executionDigest);
    event Cancelled(bytes32 indexed requestId, address indexed by);

    error ZeroAddress();
    error NotOrgAgent(bytes32 orgId, address caller);
    error NotSnapshotApprover(bytes32 requestId, address caller);
    error AgentCannotVote();
    error AlreadyVoted(bytes32 requestId, address approver);
    error LowImpactNeedsNoApproval();
    error InvalidExpiry();
    error CriticVerdictNotAnchored(bytes32 orgId, bytes32 digest);
    error TooManyPending(bytes32 orgId);
    error RequestNotFound(bytes32 requestId);
    error InvalidState(bytes32 requestId, Status current);
    error RequestIsExpired(bytes32 requestId);
    error LengthMismatch();
    error InvalidSignature();
    error NotCancellable();
    error NotExpired(bytes32 requestId);
    error ZeroPlanHash();

    constructor(address orgRegistryAddress, address auditLogAddress) EIP712("ApprovalGate", "1") {
        if (orgRegistryAddress == address(0) || auditLogAddress == address(0)) revert ZeroAddress();
        orgRegistry = OrgRegistry(orgRegistryAddress);
        auditLog = AuditLog(auditLogAddress);
    }

    // ---------------------------------------------------------------- requests

    function requestApproval(
        bytes32 orgId,
        bytes32 planHash,
        bytes32 stepsHash,
        uint8 impactClass,
        uint256 expiry,
        bytes32 criticVerdictDigest
    ) external returns (bytes32 requestId) {
        if (!orgRegistry.isOrgAgent(orgId, msg.sender)) revert NotOrgAgent(orgId, msg.sender);
        if (planHash == bytes32(0)) revert ZeroPlanHash();
        if (impactClass == uint8(ImpactClass.Low) || impactClass > uint8(ImpactClass.High)) revert LowImpactNeedsNoApproval();
        if (expiry <= block.timestamp || expiry > type(uint64).max) revert InvalidExpiry();
        // BC-GATE-01: a critic verdict must already be anchored for this org.
        if (!auditLog.hasAnchor(orgId, CRITIC_VERDICT_KIND, criticVerdictDigest)) {
            revert CriticVerdictNotAnchored(orgId, criticVerdictDigest);
        }
        if (livePending[orgId] >= MAX_PENDING_PER_ORG) revert TooManyPending(orgId);

        requestId = keccak256(abi.encode(orgId, planHash, requestNonce++, block.chainid));
        Request storage r = _requests[requestId];
        r.orgId = orgId;
        r.planHash = planHash;
        r.stepsHash = stepsHash;
        r.criticVerdictDigest = criticVerdictDigest;
        r.impact = ImpactClass(impactClass);
        r.status = Status.Pending;
        r.expiry = uint64(expiry);

        // BC-GATE-03 snapshot of approver set and threshold
        uint256 n = orgRegistry.getApproverCount(orgId);
        bool anySafety;
        for (uint256 i = 0; i < n; i++) {
            (address a, bool s) = orgRegistry.getApproverAt(orgId, i);
            r.approvers.push(a);
            if (s) {
                r.safetyMask |= (uint256(1) << i);
                anySafety = true;
            }
        }
        if (r.impact == ImpactClass.High) {
            r.required = orgRegistry.getThreshold(orgId);
            r.needsSafety = anySafety;
        } else {
            r.required = 1;
        }
        livePending[orgId] += 1;

        emit ApprovalRequested(requestId, orgId, planHash, r.impact, expiry, r.required);
    }

    // ------------------------------------------------------------------ voting

    function approve(bytes32 requestId) external nonReentrant {
        _castVote(requestId, msg.sender, true);
    }

    function reject(bytes32 requestId) external nonReentrant {
        _castVote(requestId, msg.sender, false);
    }

    /// @notice Relayer path: aggregate EIP-712 votes signed by snapshot approvers.
    function approveWithSigs(bytes32 requestId, address[] calldata voters, bytes[] calldata sigs) external nonReentrant {
        if (voters.length != sigs.length) revert LengthMismatch();
        bytes32 structHash = keccak256(abi.encode(VOTE_TYPEHASH, requestId, true));
        bytes32 digest = _hashTypedDataV4(structHash);
        for (uint256 i = 0; i < voters.length; i++) {
            address signer = ECDSA.recover(digest, sigs[i]);
            if (signer != voters[i]) revert InvalidSignature();
            _castVote(requestId, signer, true);
        }
    }

    function _castVote(bytes32 requestId, address voter, bool isApprove) internal {
        Request storage r = _requests[requestId];
        if (r.status == Status.None) revert RequestNotFound(requestId);
        if (r.status != Status.Pending) {
            // A request that is Approved cannot take more votes (and is checked for expiry below)
            revert InvalidState(requestId, _effectiveStatus(r));
        }
        if (block.timestamp > r.expiry) revert RequestIsExpired(requestId);
        if (orgRegistry.isOrgAgent(r.orgId, voter)) revert AgentCannotVote();

        (bool found, bool safety) = _lookupSnapshot(r, voter);
        if (!found) revert NotSnapshotApprover(requestId, voter);
        if (_vote[requestId][voter] != 0) revert AlreadyVoted(requestId, voter);

        if (isApprove) {
            _vote[requestId][voter] = 1;
            r.approvals += 1;
            if (safety) r.safetyApproved = true;
            emit Approved(requestId, voter);
            if (r.approvals >= r.required && (!r.needsSafety || r.safetyApproved)) {
                r.status = Status.Approved;
                emit ApprovalThresholdReached(requestId);
            }
        } else {
            _vote[requestId][voter] = 2;
            r.rejections += 1;
            emit Rejected(requestId, voter);
            if (_thresholdUnreachable(requestId, r)) {
                r.status = Status.Rejected;
                livePending[r.orgId] -= 1;
                emit RequestRejected(requestId);
            }
        }
    }

    /// @dev Unreachable when the remaining possible approvals cannot satisfy `required`,
    ///      or when every safety officer has rejected and none approved.
    function _thresholdUnreachable(bytes32 requestId, Request storage r) internal view returns (bool) {
        uint256 total = r.approvers.length;
        if (total - r.rejections < r.required) return true;
        if (r.needsSafety && !r.safetyApproved) {
            bool safetyLeft;
            for (uint256 i = 0; i < total; i++) {
                if (((r.safetyMask >> i) & 1) == 1 && _vote[requestId][r.approvers[i]] != 2) {
                    safetyLeft = true;
                    break;
                }
            }
            if (!safetyLeft) return true;
        }
        return false;
    }

    function _lookupSnapshot(Request storage r, address voter) internal view returns (bool found, bool safety) {
        uint256 n = r.approvers.length;
        for (uint256 i = 0; i < n; i++) {
            if (r.approvers[i] == voter) return (true, ((r.safetyMask >> i) & 1) == 1);
        }
        return (false, false);
    }

    // ------------------------------------------------------------ state changes

    function markExecuted(bytes32 requestId, bytes32 executionDigest) external nonReentrant {
        Request storage r = _requests[requestId];
        if (r.status == Status.None) revert RequestNotFound(requestId);
        if (!orgRegistry.isOrgAgent(r.orgId, msg.sender)) revert NotOrgAgent(r.orgId, msg.sender);
        if (r.status != Status.Approved) revert InvalidState(requestId, _effectiveStatus(r));
        if (block.timestamp > r.expiry) revert RequestIsExpired(requestId);
        r.status = Status.Executed;
        r.executionDigest = executionDigest;
        livePending[r.orgId] -= 1;
        emit Executed(requestId, executionDigest);
    }

    function cancel(bytes32 requestId) external nonReentrant {
        Request storage r = _requests[requestId];
        if (r.status == Status.None) revert RequestNotFound(requestId);
        if (r.status != Status.Pending) revert InvalidState(requestId, _effectiveStatus(r));
        (bool isApprover, ) = _lookupSnapshot(r, msg.sender);
        if (!orgRegistry.isOrgAgent(r.orgId, msg.sender) && !isApprover) revert NotCancellable();
        r.status = Status.Cancelled;
        livePending[r.orgId] -= 1;
        emit Cancelled(requestId, msg.sender);
    }

    /// @notice Anyone may flip an overdue Pending/Approved request to Expired.
    function expire(bytes32 requestId) external {
        Request storage r = _requests[requestId];
        if (r.status == Status.None) revert RequestNotFound(requestId);
        if (r.status != Status.Pending && r.status != Status.Approved) revert InvalidState(requestId, r.status);
        if (block.timestamp <= r.expiry) revert NotExpired(requestId);
        r.status = Status.Expired;
        livePending[r.orgId] -= 1;
        emit RequestExpired(requestId);
    }

    // ------------------------------------------------------------------- views

    function _effectiveStatus(Request storage r) internal view returns (Status) {
        if ((r.status == Status.Pending || r.status == Status.Approved) && block.timestamp > r.expiry) {
            return Status.Expired;
        }
        return r.status;
    }

    function status(bytes32 requestId) external view returns (Status) {
        return _effectiveStatus(_requests[requestId]);
    }

    function getRequest(bytes32 requestId)
        external
        view
        returns (
            bytes32 orgId,
            bytes32 planHash,
            bytes32 criticVerdictDigest,
            ImpactClass impact,
            Status st,
            uint256 expiry,
            uint8 required,
            uint8 approvals,
            uint8 rejections,
            bool safetyApproved,
            bool needsSafety
        )
    {
        Request storage r = _requests[requestId];
        if (r.status == Status.None) revert RequestNotFound(requestId);
        return (
            r.orgId, r.planHash, r.criticVerdictDigest, r.impact, _effectiveStatus(r), r.expiry,
            r.required, r.approvals, r.rejections, r.safetyApproved, r.needsSafety
        );
    }

    function getSnapshotApprovers(bytes32 requestId) external view returns (address[] memory, bool[] memory) {
        Request storage r = _requests[requestId];
        if (r.status == Status.None) revert RequestNotFound(requestId);
        bool[] memory flags = new bool[](r.approvers.length);
        for (uint256 i = 0; i < flags.length; i++) flags[i] = ((r.safetyMask >> i) & 1) == 1;
        return (r.approvers, flags);
    }

    function planHashOf(bytes32 requestId) external view returns (bytes32) {
        return _requests[requestId].planHash;
    }

    function hasVoted(bytes32 requestId, address voter) external view returns (bool) {
        return _vote[requestId][voter] != 0;
    }

    function isApprovedAndLive(bytes32 requestId) external view returns (bool) {
        return _effectiveStatus(_requests[requestId]) == Status.Approved;
    }

    function voteDigest(bytes32 requestId) external view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(VOTE_TYPEHASH, requestId, true)));
    }
}
