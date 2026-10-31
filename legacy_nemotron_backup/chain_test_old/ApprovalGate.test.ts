import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { ApprovalGate, OrgRegistry, AuditLog } from "../typechain-types";

describe("ApprovalGate", function () {
  async function deployFixture() {
    const [deployer, admin, agentSigner, approver1, approver2, approver3, safetyOfficer, stranger] = await ethers.getSigners();
    
    const OrgRegistry = await ethers.getContractFactory("OrgRegistry");
    const orgRegistry = await OrgRegistry.deploy();
    await orgRegistry.waitForDeployment();
    
    const AuditLog = await ethers.getContractFactory("AuditLog");
    const auditLog = await AuditLog.deploy(await orgRegistry.getAddress());
    await auditLog.waitForDeployment();
    
    const ApprovalGate = await ethers.getContractFactory("ApprovalGate");
    const approvalGate = await ApprovalGate.deploy(await orgRegistry.getAddress(), await auditLog.getAddress());
    await approvalGate.waitForDeployment();
    
    // Register org with safety officer
    const orgId = ethers.id("power");
    const nameHash = ethers.id("Grid Utility");
    const approvers = [approver1.address, approver2.address, approver3.address];
    const safetyOfficerFlags = [true, false, false]; // approver1 is safety officer
    const threshold = 2;
    
    await orgRegistry.registerOrg(orgId, nameHash, 0, admin.address, agentSigner.address, approvers, threshold, safetyOfficerFlags);
    
    // Pre-anchor a critic verdict in AuditLog
    const criticVerdictDigest = ethers.id("critic-verdict-1");
    const metaHash = ethers.id("meta");
    
    const auditDomain = {
      name: "AuditLog",
      version: "1",
      chainId: 31337,
      verifyingContract: await auditLog.getAddress()
    };
    
    const auditTypes = {
      Anchor: [
        { name: "orgId", type: "bytes32" },
        { name: "kind", type: "uint8" },
        { name: "digest", type: "bytes32" },
        { name: "prevDigest", type: "bytes32" },
        { name: "metaHash", type: "bytes32" },
        { name: "index", type: "uint256" },
        { name: "timestamp", type: "uint256" }
      ]
    };
    
    const auditValue = { orgId, kind: 3, digest: criticVerdictDigest, prevDigest: ethers.ZeroHash, metaHash, index: 0, timestamp: Math.floor(Date.now() / 1000) };
    const auditSig = await agentSigner.signTypedData(auditDomain, auditTypes, auditValue);
    await auditLog.anchor(orgId, 3, criticVerdictDigest, ethers.ZeroHash, metaHash, auditSig);
    
    return { 
      orgRegistry, 
      auditLog, 
      approvalGate, 
      deployer, 
      admin, 
      agentSigner, 
      approver1, 
      approver2, 
      approver3, 
      safetyOfficer, 
      stranger,
      orgId,
      criticVerdictDigest
    };
  });

  describe("Request Creation (BC-GATE-01, BC-GATE-02)", function () {
    it("BC-GATE-01: Should create approval request for MEDIUM impact", async function () {
      const { approvalGate, orgId, agentSigner, criticVerdictDigest } = await loadFixture(deployFixture);
      
      const planHash = ethers.id("plan-1");
      const stepIds = [1, 2, 3];
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      
      const domain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const types = {
        ApprovalRequest: [
          { name: "requestId", type: "bytes32" },
          { name: "orgId", type: "bytes32" },
          { name: "planHash", type: "bytes32" },
          { name: "stepIds", type: "uint256[]" },
          { name: "impactClass", type: "uint8" },
          { name: "expiry", type: "uint256" },
          { name: "criticVerdictDigest", type: "bytes32" }
        ]
      };
      
      const requestId = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "uint256[]", "uint8", "uint256", "bytes32", "uint256"],
        [orgId, planHash, stepIds, 1, expiry, criticVerdictDigest, Math.floor(Date.now() / 1000)]
      ));
      
      const value = { requestId, orgId, planHash, stepIds, impactClass: 1, expiry, criticVerdictDigest };
      const signature = await agentSigner.signTypedData(domain, types, value);
      
      const returnedId = await approvalGate.requestApproval(orgId, planHash, stepIds, 1, expiry, criticVerdictDigest, signature);
      expect(returnedId).to.equal(requestId);
      
      const request = await approvalGate.getRequest(requestId);
      expect(request.orgId).to.equal(orgId);
      expect(request.planHash).to.equal(planHash);
      expect(request.impactClass).to.equal(1); // Medium
      expect(request.state).to.equal(0); // Pending
      expect(request.snapshotApprovers.length).to.equal(3);
      expect(request.snapshotThreshold).to.equal(2);
      expect(request.snapshotHasSafetyOfficer).to.be.true;
    });

    it("BC-GATE-01: Should create approval request for HIGH impact", async function () {
      const { approvalGate, orgId, agentSigner, criticVerdictDigest } = await loadFixture(deployFixture);
      
      const planHash = ethers.id("plan-2");
      const stepIds = [4, 5];
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      
      const domain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const types = {
        ApprovalRequest: [
          { name: "requestId", type: "bytes32" },
          { name: "orgId", type: "bytes32" },
          { name: "planHash", type: "bytes32" },
          { name: "stepIds", type: "uint256[]" },
          { name: "impactClass", type: "uint8" },
          { name: "expiry", type: "uint256" },
          { name: "criticVerdictDigest", type: "bytes32" }
        ]
      };
      
      const requestId = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "uint256[]", "uint8", "uint256", "bytes32", "uint256"],
        [orgId, planHash, stepIds, 2, expiry, criticVerdictDigest, Math.floor(Date.now() / 1000)]
      ));
      
      const value = { requestId, orgId, planHash, stepIds, impactClass: 2, expiry, criticVerdictDigest };
      const signature = await agentSigner.signTypedData(domain, types, value);
      
      const returnedId = await approvalGate.requestApproval(orgId, planHash, stepIds, 2, expiry, criticVerdictDigest, signature);
      expect(returnedId).to.equal(requestId);
      
      const request = await approvalGate.getRequest(requestId);
      expect(request.impactClass).to.equal(2); // High
    });

    it("BC-GATE-01: Should revert for LOW impact", async function () {
      const { approvalGate, orgId, agentSigner, criticVerdictDigest } = await loadFixture(deployFixture);
      
      const planHash = ethers.id("plan-3");
      const stepIds = [6];
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      
      const domain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const types = {
        ApprovalRequest: [
          { name: "requestId", type: "bytes32" },
          { name: "orgId", type: "bytes32" },
          { name: "planHash", type: "bytes32" },
          { name: "stepIds", type: "uint256[]" },
          { name: "impactClass", type: "uint8" },
          { name: "expiry", type: "uint256" },
          { name: "criticVerdictDigest", type: "bytes32" }
        ]
      };
      
      const value = { requestId: ethers.ZeroHash, orgId, planHash, stepIds, impactClass: 0, expiry, criticVerdictDigest };
      const signature = await agentSigner.signTypedData(domain, types, value);
      
      await expect(approvalGate.requestApproval(orgId, planHash, stepIds, 0, expiry, criticVerdictDigest, signature))
        .to.be.revertedWithCustomError(approvalGate, "LowImpactNotAllowed");
    });

    it("BC-GATE-01: Should revert if critic verdict not anchored", async function () {
      const { approvalGate, orgId, agentSigner } = await loadFixture(deployFixture);
      
      const planHash = ethers.id("plan-4");
      const stepIds = [7];
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      const fakeCriticDigest = ethers.id("fake-critic");
      
      const domain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const types = {
        ApprovalRequest: [
          { name: "requestId", type: "bytes32" },
          { name: "orgId", type: "bytes32" },
          { name: "planHash", type: "bytes32" },
          { name: "stepIds", type: "uint256[]" },
          { name: "impactClass", type: "uint8" },
          { name: "expiry", type: "uint256" },
          { name: "criticVerdictDigest", type: "bytes32" }
        ]
      };
      
      const value = { requestId: ethers.ZeroHash, orgId, planHash, stepIds, impactClass: 1, expiry, criticVerdictDigest: fakeCriticDigest };
      const signature = await agentSigner.signTypedData(domain, types, value);
      
      await expect(approvalGate.requestApproval(orgId, planHash, stepIds, 1, expiry, fakeCriticDigest, signature))
        .to.be.revertedWithCustomError(approvalGate, "CriticVerdictNotAnchored");
    });

    it("BC-GATE-02: Should store planHash on-chain", async function () {
      const { approvalGate, orgId, agentSigner, criticVerdictDigest } = await loadFixture(deployFixture);
      
      const planHash = ethers.id("plan-5");
      const stepIds = [8];
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      
      const domain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const types = {
        ApprovalRequest: [
          { name: "requestId", type: "bytes32" },
          { name: "orgId", type: "bytes32" },
          { name: "planHash", type: "bytes32" },
          { name: "stepIds", type: "uint256[]" },
          { name: "impactClass", type: "uint8" },
          { name: "expiry", type: "uint256" },
          { name: "criticVerdictDigest", type: "bytes32" }
        ]
      };
      
      const requestId = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "uint256[]", "uint8", "uint256", "bytes32", "uint256"],
        [orgId, planHash, stepIds, 1, expiry, criticVerdictDigest, Math.floor(Date.now() / 1000)]
      ));
      
      const value = { requestId, orgId, planHash, stepIds, impactClass: 1, expiry, criticVerdictDigest };
      const signature = await agentSigner.signTypedData(domain, types, value);
      
      await approvalGate.requestApproval(orgId, planHash, stepIds, 1, expiry, criticVerdictDigest, signature);
      
      const request = await approvalGate.getRequest(requestId);
      expect(request.planHash).to.equal(planHash);
    });

    it("BC-GATE-10: Should enforce max pending requests per org", async function () {
      const { approvalGate, orgId, agentSigner, criticVerdictDigest } = await loadFixture(deployFixture);
      
      const domain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const types = {
        ApprovalRequest: [
          { name: "requestId", type: "bytes32" },
          { name: "orgId", type: "bytes32" },
          { name: "planHash", type: "bytes32" },
          { name: "stepIds", type: "uint256[]" },
          { name: "impactClass", type: "uint8" },
          { name: "expiry", type: "uint256" },
          { name: "criticVerdictDigest", type: "bytes32" }
        ]
      };
      
      // Create 20 requests (max)
      for (let i = 0; i < 20; i++) {
        const planHash = ethers.id(`plan-${i}`);
        const stepIds = [i];
        const expiry = Math.floor(Date.now() / 1000) + 3600;
        const requestId = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes32", "bytes32", "uint256[]", "uint8", "uint256", "bytes32", "uint256"],
          [orgId, planHash, stepIds, 1, expiry, criticVerdictDigest, Math.floor(Date.now() / 1000) + i]
        ));
        const value = { requestId, orgId, planHash, stepIds, impactClass: 1, expiry, criticVerdictDigest };
        const signature = await agentSigner.signTypedData(domain, types, value);
        await approvalGate.requestApproval(orgId, planHash, stepIds, 1, expiry, criticVerdictDigest, signature);
      }
      
      // 21st should fail
      const planHash = ethers.id("plan-21");
      const stepIds = [21];
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      const requestId = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "uint256[]", "uint8", "uint256", "bytes32", "uint256"],
        [orgId, planHash, stepIds, 1, expiry, criticVerdictDigest, Math.floor(Date.now() / 1000) + 21]
      ));
      const value = { requestId, orgId, planHash, stepIds, impactClass: 1, expiry, criticVerdictDigest };
      const signature = await agentSigner.signTypedData(domain, types, value);
      
      await expect(approvalGate.requestApproval(orgId, planHash, stepIds, 1, expiry, criticVerdictDigest, signature))
        .to.be.revertedWithCustomError(approvalGate, "MaxPendingRequestsExceeded");
    });
  });

  describe("Approve / Reject (BC-GATE-04, BC-GATE-05)", function () {
    async function createRequest(fixture: any, impactClass: number) {
      const { approvalGate, orgId, agentSigner, criticVerdictDigest } = fixture;
      
      const planHash = ethers.id(`plan-${impactClass}-${Date.now()}`);
      const stepIds = [1];
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      
      const domain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const types = {
        ApprovalRequest: [
          { name: "requestId", type: "bytes32" },
          { name: "orgId", type: "bytes32" },
          { name: "planHash", type: "bytes32" },
          { name: "stepIds", type: "uint256[]" },
          { name: "impactClass", type: "uint8" },
          { name: "expiry", type: "uint256" },
          { name: "criticVerdictDigest", type: "bytes32" }
        ]
      };
      
      const requestId = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "uint256[]", "uint8", "uint256", "bytes32", "uint256"],
        [orgId, planHash, stepIds, impactClass, expiry, criticVerdictDigest, Math.floor(Date.now() / 1000)]
      ));
      
      const value = { requestId, orgId, planHash, stepIds, impactClass, expiry, criticVerdictDigest };
      const signature = await agentSigner.signTypedData(domain, types, value);
      
      await approvalGate.requestApproval(orgId, planHash, stepIds, impactClass, expiry, criticVerdictDigest, signature);
      return requestId;
    }

    it("BC-GATE-04: Should allow snapshot approver to approve MEDIUM request", async function () {
      const fixture = await loadFixture(deployFixture);
      const { approvalGate, approver1 } = fixture;
      
      const requestId = await createRequest(fixture, 1); // Medium
      
      const domain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const types = {
        ApprovalVote: [
          { name: "requestId", type: "bytes32" },
          { name: "isApproval", type: "bool" }
        ]
      };
      
      const value = { requestId, isApproval: true };
      const signature = await approver1.signTypedData(domain, types, value);
      
      await expect(approvalGate.approve(requestId, signature))
        .to.emit(approvalGate, "Approved");
      
      const state = await approvalGate.getRequestState(requestId);
      expect(state).to.equal(1); // Approved
    });

    it("BC-GATE-05: Should require >= threshold approvals for HIGH impact", async function () {
      const fixture = await loadFixture(deployFixture);
      const { approvalGate, approver1, approver2, approver3 } = fixture;
      
      const requestId = await createRequest(fixture, 2); // High
      
      const domain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const types = {
        ApprovalVote: [
          { name: "requestId", type: "bytes32" },
          { name: "isApproval", type: "bool" }
        ]
      };
      
      // First approval (approver1 is safety officer)
      const value1 = { requestId, isApproval: true };
      const sig1 = await approver1.signTypedData(domain, types, value1);
      await approvalGate.approve(requestId, sig1);
      
      let state = await approvalGate.getRequestState(requestId);
      expect(state).to.equal(0); // Still pending (need 2)
      
      // Second approval
      const value2 = { requestId, isApproval: true };
      const sig2 = await approver2.signTypedData(domain, types, value2);
      await expect(approvalGate.approve(requestId, sig2))
        .to.emit(approvalGate, "ApprovalThresholdReached");
      
      state = await approvalGate.getRequestState(requestId);
      expect(state).to.equal(1); // Approved
    });

    it("BC-GATE-05: Should require safety officer approval for HIGH impact", async function () {
      const fixture = await loadFixture(deployFixture);
      const { approvalGate, approver2, approver3 } = fixture;
      
      const requestId = await createRequest(fixture, 2); // High
      
      const domain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const types = {
        ApprovalVote: [
          { name: "requestId", type: "bytes32" },
          { name: "isApproval", type: "bool" }
        ]
      };
      
      // Two non-safety-officer approvals
      const value1 = { requestId, isApproval: true };
      const sig1 = await approver2.signTypedData(domain, types, value1);
      await approvalGate.approve(requestId, sig1);
      
      const value2 = { requestId, isApproval: true };
      const sig2 = await approver3.signTypedData(domain, types, value2);
      await approvalGate.approve(requestId, sig2);
      
      // Should still be pending because no safety officer approved
      const state = await approvalGate.getRequestState(requestId);
      expect(state).to.equal(0); // Pending
    });

    it("BC-GATE-06: Should reject agent signer attempting to approve", async function () {
      const fixture = await loadFixture(deployFixture);
      const { approvalGate, agentSigner } = fixture;
      
      const requestId = await createRequest(fixture, 1);
      
      const domain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const types = {
        ApprovalVote: [
          { name: "requestId", type: "bytes32" },
          { name: "isApproval", type: "bool" }
        ]
      };
      
      const value = { requestId, isApproval: true };
      const signature = await agentSigner.signTypedData(domain, types, value);
      
      await expect(approvalGate.approve(requestId, signature))
        .to.be.revertedWithCustomError(approvalGate, "AgentSignerCannotApprove");
    });

    it("BC-GATE-04: Should allow snapshot approver to reject", async function () {
      const fixture = await loadFixture(deployFixture);
      const { approvalGate, approver1 } = fixture;
      
      const requestId = await createRequest(fixture, 1);
      
      const domain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const types = {
        ApprovalVote: [
          { name: "requestId", type: "bytes32" },
          { name: "isApproval", type: "bool" }
        ]
      };
      
      const value = { requestId, isApproval: false };
      const signature = await approver1.signTypedData(domain, types, value);
      
      await expect(approvalGate.reject(requestId, signature))
        .to.emit(approvalGate, "Rejected");
      
      const state = await approvalGate.getRequestState(requestId);
      expect(state).to.equal(2); // Rejected
    });

    it("BC-GATE-07: Should auto-reject when threshold unreachable", async function () {
      const fixture = await loadFixture(deployFixture);
      const { approvalGate, approver1, approver2, approver3 } = fixture;
      
      const requestId = await createRequest(fixture, 1); // Medium needs 1
      
      const domain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const types = {
        ApprovalVote: [
          { name: "requestId", type: "bytes32" },
          { name: "isApproval", type: "bool" }
        ]
      };
      
      // All three reject
      for (const approver of [approver1, approver2, approver3]) {
        const value = { requestId, isApproval: false };
        const signature = await approver.signTypedData(domain, types, value);
        await approvalGate.reject(requestId, signature);
      }
      
      const state = await approvalGate.getRequestState(requestId);
      expect(state).to.equal(2); // Rejected
    });
  });

  describe("Snapshot Semantics (BC-GATE-03)", function () {
    it("BC-GATE-03: Should not retroactively change pending requests when approvers updated", async function () {
      const fixture = await loadFixture(deployFixture);
      const { approvalGate, orgRegistry, orgId, agentSigner, approver1, approver2, approver3, criticVerdictDigest, stranger1, stranger2, stranger3, admin } = fixture;
      
      // Create request with original approvers
      const requestId = await createRequest(fixture, 1);
      
      // Update approver set
      const newApprovers = [stranger1.address, stranger2.address, stranger3.address];
      const newSafetyFlags = [true, false, false];
      await orgRegistry.connect(admin).updateApproverSet(orgId, newApprovers, 2, newSafetyFlags);
      
      // Original request should still use old snapshot
      const request = await approvalGate.getRequest(requestId);
      expect(request.snapshotApprovers).to.deep.equal([approver1.address, approver2.address, approver3.address]);
      expect(request.snapshotThreshold).to.equal(2);
      
      // New approvers should not be able to approve old request
      const domain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const types = {
        ApprovalVote: [
          { name: "requestId", type: "bytes32" },
          { name: "isApproval", type: "bool" }
        ]
      };
      
      const value = { requestId, isApproval: true };
      const sig = await stranger1.signTypedData(domain, types, value);
      
      await expect(approvalGate.approve(requestId, sig))
        .to.be.revertedWithCustomError(approvalGate, "ApproverNotInSnapshot");
    });
  });

  describe("Expiry (BC-GATE-09)", function () {
    it("BC-GATE-09: Should expire request after expiry timestamp", async function () {
      const fixture = await loadFixture(deployFixture);
      const { approvalGate, orgId, agentSigner, criticVerdictDigest } = fixture;
      
      const planHash = ethers.id("plan-expiry");
      const stepIds = [1];
      const expiry = Math.floor(Date.now() / 1000) + 1; // 1 second in future
      
      const domain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const types = {
        ApprovalRequest: [
          { name: "requestId", type: "bytes32" },
          { name: "orgId", type: "bytes32" },
          { name: "planHash", type: "bytes32" },
          { name: "stepIds", type: "uint256[]" },
          { name: "impactClass", type: "uint8" },
          { name: "expiry", type: "uint256" },
          { name: "criticVerdictDigest", type: "bytes32" }
        ]
      };
      
      const requestId = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "uint256[]", "uint8", "uint256", "bytes32", "uint256"],
        [orgId, planHash, stepIds, 1, expiry, criticVerdictDigest, Math.floor(Date.now() / 1000)]
      ));
      
      const value = { requestId, orgId, planHash, stepIds, impactClass: 1, expiry, criticVerdictDigest };
      const signature = await agentSigner.signTypedData(domain, types, value);
      
      await approvalGate.requestApproval(orgId, planHash, stepIds, 1, expiry, criticVerdictDigest, signature);
      
      // Wait for expiry
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Call expire
      await approvalGate.expire(requestId);
      
      const state = await approvalGate.getRequestState(requestId);
      expect(state).to.equal(3); // Expired
    });
  });

  describe("Execution (BC-GATE-08)", function () {
    it("BC-GATE-08: Should allow agent signer to mark executed after approval", async function () {
      const fixture = await loadFixture(deployFixture);
      const { approvalGate, orgId, agentSigner, approver1, criticVerdictDigest } = fixture;
      
      const requestId = await createRequest(fixture, 1);
      
      // Approve
      const voteDomain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const voteTypes = {
        ApprovalVote: [
          { name: "requestId", type: "bytes32" },
          { name: "isApproval", type: "bool" }
        ]
      };
      
      const voteValue = { requestId, isApproval: true };
      const voteSig = await approver1.signTypedData(voteDomain, voteTypes, voteValue);
      await approvalGate.approve(requestId, voteSig);
      
      // Mark executed
      const execDomain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const execTypes = {
        MarkExecuted: [
          { name: "requestId", type: "bytes32" },
          { name: "executionDigest", type: "bytes32" }
        ]
      };
      
      const executionDigest = ethers.id("execution-1");
      const execValue = { requestId, executionDigest };
      const execSig = await agentSigner.signTypedData(execDomain, execTypes, execValue);
      
      await expect(approvalGate.markExecuted(requestId, executionDigest, execSig))
        .to.emit(approvalGate, "Executed");
      
      const state = await approvalGate.getRequestState(requestId);
      expect(state).to.equal(4); // Executed
    });

    it("BC-GATE-08: Should revert if marking executed without approval", async function () {
      const fixture = await loadFixture(deployFixture);
      const { approvalGate, orgId, agentSigner, criticVerdictDigest } = fixture;
      
      const requestId = await createRequest(fixture, 1);
      
      const execDomain = {
        name: "ApprovalGate",
        version: "1",
        chainId: 31337,
        verifyingContract: await approvalGate.getAddress()
      };
      
      const execTypes = {
        MarkExecuted: [
          { name: "requestId", type: "bytes32" },
          { name: "executionDigest", type: "bytes32" }
        ]
      };
      
      const executionDigest = ethers.id("execution-1");
      const execValue = { requestId, executionDigest };
      const execSig = await agentSigner.signTypedData(execDomain, execTypes, execValue);
      
      await expect(approvalGate.markExecuted(requestId, executionDigest, execSig))
        .to.be.revertedWithCustomError(approvalGate, "RequestNotPending");
    });
  });
});