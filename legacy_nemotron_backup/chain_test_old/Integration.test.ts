import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { OrgRegistry, AttestationRegistry, AuditLog, ApprovalGate, FirmwareRegistry, AlertBus } from "../typechain-types";

// Hardhat default account private key for signing raw digests
const HARDHAT_ACCOUNT_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const hardhatWallet = new ethers.Wallet(HARDHAT_ACCOUNT_PRIVATE_KEY);

describe("Integration Test: Full Flow (BC-INT-01)", function () {
  async function deployFixture() {
    const [deployer, admin, agentSigner1, agentSigner2, agentSigner3, approver1, approver2, approver3, vendor1, stranger] = await ethers.getSigners();
    
    // Deploy all contracts
    const OrgRegistry = await ethers.getContractFactory("OrgRegistry");
    const orgRegistry = await OrgRegistry.deploy();
    await orgRegistry.waitForDeployment();
    
    const AuditLog = await ethers.getContractFactory("AuditLog");
    const auditLog = await AuditLog.deploy(await orgRegistry.getAddress());
    await auditLog.waitForDeployment();
    
    const AttestationRegistry = await ethers.getContractFactory("AttestationRegistry");
    const attestationRegistry = await AttestationRegistry.deploy(await orgRegistry.getAddress());
    await attestationRegistry.waitForDeployment();
    
    const FirmwareRegistry = await ethers.getContractFactory("FirmwareRegistry");
    const firmwareRegistry = await FirmwareRegistry.deploy();
    await firmwareRegistry.waitForDeployment();
    
    const ApprovalGate = await ethers.getContractFactory("ApprovalGate");
    const approvalGate = await ApprovalGate.deploy(await orgRegistry.getAddress(), await auditLog.getAddress());
    await approvalGate.waitForDeployment();
    
    const AlertBus = await ethers.getContractFactory("AlertBus");
    const alertBus = await AlertBus.deploy(await orgRegistry.getAddress(), await attestationRegistry.getAddress());
    await alertBus.waitForDeployment();
    
    // Register three orgs
    const orgs = [
      { id: "power", name: "Grid Utility", agent: agentSigner1, sector: 0 },
      { id: "water", name: "Water Board", agent: agentSigner2, sector: 1 },
      { id: "hospital", name: "City Hospital", agent: agentSigner3, sector: 2 },
    ];
    
    for (const org of orgs) {
      const orgId = ethers.id(org.id);
      const nameHash = ethers.id(org.name);
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await orgRegistry.registerOrg(orgId, nameHash, org.sector, admin.address, org.agent.address, approvers, threshold, safetyOfficerFlags);
    }
    
    // Grant vendor role - deployer has DEFAULT_ADMIN_ROLE by default
    const DEFAULT_ADMIN_ROLE = await firmwareRegistry.DEFAULT_ADMIN_ROLE();
    const VENDOR_ROLE = await firmwareRegistry.VENDOR_ROLE();
    await firmwareRegistry.grantRole(VENDOR_ROLE, vendor1.address);
    
    return { 
      orgRegistry, 
      attestationRegistry, 
      auditLog, 
      approvalGate, 
      firmwareRegistry, 
      alertBus,
      deployer, 
      admin, 
      agentSigner1, 
      agentSigner2, 
      agentSigner3, 
      approver1, 
      approver2, 
      approver3,
      vendor1,
      stranger
    };
  }

  it("BC-INT-01: Full flow - register orgs -> bilateral dependency -> risk attestation -> alert -> HIGH approval -> execute -> audit verify -> firmware mismatch", async function () {
    const { 
      orgRegistry, attestationRegistry, auditLog, approvalGate, firmwareRegistry, alertBus,
      agentSigner1, agentSigner2, agentSigner3, approver1, approver2, approver3, vendor1 
    } = await loadFixture(deployFixture);
    
    const orgId1 = ethers.id("power");
    const orgId2 = ethers.id("water");
    const orgId3 = ethers.id("hospital");
    
    // =========================================================================
    // Step 1: Bilateral dependency attestation (power <-> water)
    // =========================================================================
    const powerServiceHash = ethers.id("power-service-1");
    const waterServiceHash = ethers.id("water-service-1");
    const nonce = 1;
    const expiry = Math.floor(Date.now() / 1000) + 86400 * 365;
    
    const attDomain = {
      name: "AttestationRegistry",
      version: "1",
      chainId: 31337,
      verifyingContract: await attestationRegistry.getAddress()
    };
    
    const depTypes = {
      DependencyAttestation: [
        { name: "consumerOrg", type: "bytes32" },
        { name: "consumerServiceHash", type: "bytes32" },
        { name: "providerOrg", type: "bytes32" },
        { name: "providerServiceHash", type: "bytes32" },
        { name: "strength", type: "uint8" },
        { name: "tolerance", type: "uint8" },
        { name: "nonce", type: "uint256" },
        { name: "expiry", type: "uint256" }
      ]
    };
    
    // Power (consumer) attests dependency on Water (provider)
    const depValue1 = {
      consumerOrg: orgId1,
      consumerServiceHash: powerServiceHash,
      providerOrg: orgId2,
      providerServiceHash: waterServiceHash,
      strength: 2, // High
      tolerance: 0, // Under15m
      nonce,
      expiry
    };
    
    const sig1 = await agentSigner1.signTypedData(attDomain, depTypes, depValue1);
    const sig2 = await agentSigner2.signTypedData(attDomain, depTypes, depValue1);
    
    await attestationRegistry.submitDependencyAttestation(
      orgId1, powerServiceHash, orgId2, waterServiceHash,
      2, 0, nonce, expiry, sig1
    );
    
    await attestationRegistry.submitDependencyAttestation(
      orgId1, powerServiceHash, orgId2, waterServiceHash,
      2, 0, nonce, expiry, sig2
    );
    
    const isConfirmed = await attestationRegistry.isEdgeConfirmed(orgId1, powerServiceHash, orgId2, waterServiceHash);
    expect(isConfirmed).to.be.true;
    
    // =========================================================================
    // Step 2: Risk attestation from power org
    // =========================================================================
    const riskTypes = {
      RiskAttestation: [
        { name: "orgId", type: "bytes32" },
        { name: "serviceHash", type: "bytes32" },
        { name: "riskBand", type: "uint8" },
        { name: "criticalityBucket", type: "uint8" },
        { name: "modelVersionHash", type: "bytes32" },
        { name: "evidenceCommitment", type: "bytes32" },
        { name: "validUntil", type: "uint256" },
        { name: "nonce", type: "uint256" }
      ]
    };
    
    const riskValue = {
      orgId: orgId1,
      serviceHash: powerServiceHash,
      riskBand: 3, // Critical
      criticalityBucket: 3, // LifeCritical
      modelVersionHash: ethers.id("model-v1"),
      evidenceCommitment: ethers.id("evidence-1"),
      validUntil: Math.floor(Date.now() / 1000) + 86400,
      nonce: 1
    };
    
    const riskSig = await agentSigner1.signTypedData(attDomain, riskTypes, riskValue);
    
    await attestationRegistry.submitRiskAttestation(
      orgId1, powerServiceHash, 3, 3,
      ethers.id("model-v1"), ethers.id("evidence-1"),
      riskValue.validUntil, 1, riskSig
    );
    
    const latestRisk = await attestationRegistry.getLatestRiskAttestation(orgId1, powerServiceHash);
    expect(latestRisk.riskBand).to.equal(3);
    
    // =========================================================================
    // Step 3: Publish alert from power org
    // =========================================================================
    // AlertBus uses simple keccak256 hash with typeHash
    const alertExpiry = Math.floor(Date.now() / 1000) + 3600;
    const alertTypeHash = ethers.id("Alert(bytes32 providerOrg,bytes32 providerServiceHash,uint8 severity,uint8 ttiBucket,bytes32 evidenceCommitment,uint256 expiry)");
    const alertDigest = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "uint8", "uint8", "bytes32", "uint256"],
      [alertTypeHash, orgId1, powerServiceHash, 3, 1, ethers.id("alert-evidence"), alertExpiry]
    ));
    // Sign the raw digest using hardhat wallet's signing key
    const alertSig = hardhatWallet.signingKey.sign(alertDigest).serialized;
    
    const alertId = await alertBus.publish(
      orgId1, powerServiceHash, 3, 1, ethers.id("alert-evidence"), alertExpiry, alertSig
    );
    
    const alert = await alertBus.getAlert(alertId);
    expect(alert.status).to.equal(0); // Active
    
    // =========================================================================
    // Step 4: Create approval request (HIGH impact)
    // =========================================================================
    // First anchor critic verdict in audit log
    const criticVerdictDigest = ethers.id("critic-verdict-integration");
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
    
    const auditValue = { orgId: orgId1, kind: 3, digest: criticVerdictDigest, prevDigest: ethers.ZeroHash, metaHash, index: 0, timestamp: Math.floor(Date.now() / 1000) };
    const auditSig = await agentSigner1.signTypedData(auditDomain, auditTypes, auditValue);
    await auditLog.anchor(orgId1, 3, criticVerdictDigest, ethers.ZeroHash, metaHash, auditSig);
    
    // Create approval request
    const gateDomain = {
      name: "ApprovalGate",
      version: "1",
      chainId: 31337,
      verifyingContract: await approvalGate.getAddress()
    };
    
    const gateTypes = {
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
    
    const planHash = ethers.id("integration-plan");
    const stepIds = [1, 2, 3];
    const gateExpiry = Math.floor(Date.now() / 1000) + 3600;
    
    const requestId = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "uint256[]", "uint8", "uint256", "bytes32", "uint256"],
      [orgId1, planHash, stepIds, 2, gateExpiry, criticVerdictDigest, Math.floor(Date.now() / 1000)]
    ));
    
    const gateValue = { requestId, orgId: orgId1, planHash, stepIds, impactClass: 2, expiry: gateExpiry, criticVerdictDigest };
    const gateSig = await agentSigner1.signTypedData(gateDomain, gateTypes, gateValue);
    
    const returnedRequestId = await approvalGate.requestApproval(
      orgId1, planHash, stepIds, 2, gateExpiry, criticVerdictDigest, gateSig
    );
    expect(returnedRequestId).to.equal(requestId);
    
    // =========================================================================
    // Step 5: Approve with threshold (2 of 3) including safety officer
    // =========================================================================
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
    
    // Approver 1 (safety officer) approves
    const voteValue1 = { requestId, isApproval: true };
    const voteSig1 = await approver1.signTypedData(voteDomain, voteTypes, voteValue1);
    await approvalGate.approve(requestId, voteSig1);
    
    let state = await approvalGate.getRequestState(requestId);
    expect(state).to.equal(0); // Still pending
    
    // Approver 2 approves
    const voteValue2 = { requestId, isApproval: true };
    const voteSig2 = await approver2.signTypedData(voteDomain, voteTypes, voteValue2);
    await approvalGate.approve(requestId, voteSig2);
    
    state = await approvalGate.getRequestState(requestId);
    expect(state).to.equal(1); // Approved
    
    // =========================================================================
    // Step 6: Mark executed
    // =========================================================================
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
    
    const executionDigest = ethers.id("execution-integration");
    const execValue = { requestId, executionDigest };
    const execSig = await agentSigner1.signTypedData(execDomain, execTypes, execValue);
    
    await approvalGate.markExecuted(requestId, executionDigest, execSig);
    
    state = await approvalGate.getRequestState(requestId);
    expect(state).to.equal(4); // Executed
    
    // =========================================================================
    // Step 7: Anchor execution in audit log
    // =========================================================================
    const execAuditValue = { orgId: orgId1, kind: 4, digest: executionDigest, prevDigest: await auditLog.getLastDigest(orgId1), metaHash, index: 1, timestamp: Math.floor(Date.now() / 1000) };
    const execAuditSig = await agentSigner1.signTypedData(auditDomain, auditTypes, execAuditValue);
    await auditLog.anchor(orgId1, 4, executionDigest, execAuditValue.prevDigest, metaHash, execAuditSig);
    
    // Verify audit chain
    const length = await auditLog.length(orgId1);
    expect(length).to.be.greaterThanOrEqual(2);
    
    // =========================================================================
    // Step 8: Firmware mismatch detection
    // =========================================================================
    const vendorId = ethers.id("vendor-1");
    const modelHash = ethers.id("model-1");
    const versionHash = ethers.id("v1.0.0");
    const firmwareSha256 = ethers.id("correct-firmware");
    const sbomHash = ethers.id("sbom-1");
    const releaseTimestamp = Math.floor(Date.now() / 1000);
    
    await firmwareRegistry.connect(vendor1).publishFirmware(
      vendorId, modelHash, versionHash, firmwareSha256, sbomHash, releaseTimestamp
    );
    
    // Verify correct firmware
    const matchResult = await firmwareRegistry.verifyFirmware(vendorId, modelHash, versionHash, firmwareSha256);
    expect(matchResult).to.equal(0); // Match
    
    // Verify mismatched firmware
    const mismatchResult = await firmwareRegistry.verifyFirmware(vendorId, modelHash, versionHash, ethers.id("wrong-firmware"));
    expect(mismatchResult).to.equal(1); // Mismatch
    
    // Verify unknown firmware
    const unknownResult = await firmwareRegistry.verifyFirmware(ethers.id("unknown"), ethers.id("unknown"), ethers.id("unknown"), ethers.id("unknown"));
    expect(unknownResult).to.equal(2); // Unknown
    
    console.log("✅ Full integration flow completed successfully!");
  });
});