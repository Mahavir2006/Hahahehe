import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { OrgRegistry, AttestationRegistry } from "../typechain-types";

describe("AttestationRegistry", function () {
  async function deployFixture() {
    const [deployer, admin, agentSigner1, agentSigner2, approver1, approver2, approver3, stranger] = await ethers.getSigners();
    
    const OrgRegistry = await ethers.getContractFactory("OrgRegistry");
    const orgRegistry = await OrgRegistry.deploy();
    await orgRegistry.waitForDeployment();
    
    const AttestationRegistry = await ethers.getContractFactory("AttestationRegistry");
    const attestationRegistry = await AttestationRegistry.deploy(await orgRegistry.getAddress());
    await attestationRegistry.waitForDeployment();
    
    // Register two orgs
    const orgId1 = ethers.id("power");
    const orgId2 = ethers.id("water");
    const nameHash1 = ethers.id("Grid Utility");
    const nameHash2 = ethers.id("Water Board");
    const approvers = [approver1.address, approver2.address, approver3.address];
    const safetyOfficerFlags = [true, false, false];
    const threshold = 2;
    
    await orgRegistry.registerOrg(orgId1, nameHash1, 0, admin.address, agentSigner1.address, approvers, threshold, safetyOfficerFlags);
    await orgRegistry.registerOrg(orgId2, nameHash2, 1, admin.address, agentSigner2.address, approvers, threshold, safetyOfficerFlags);
    
    return { 
      orgRegistry, 
      attestationRegistry, 
      deployer, 
      admin, 
      agentSigner1, 
      agentSigner2, 
      approver1, 
      approver2, 
      approver3, 
      stranger,
      orgId1,
      orgId2,
      nameHash1,
      nameHash2
    };
  }

  describe("Dependency Attestations (BC-ATT-D)", function () {
    it("BC-ATT-D-01: Should submit consumer attestation", async function () {
      const { attestationRegistry, orgId1, orgId2, agentSigner1 } = await loadFixture(deployFixture);
      
      const consumerServiceHash = ethers.id("power-service-1");
      const providerServiceHash = ethers.id("water-service-1");
      const nonce = 1;
      const expiry = Math.floor(Date.now() / 1000) + 86400;
      
      // Create EIP-712 signature
      const domain = {
        name: "AttestationRegistry",
        version: "1",
        chainId: 31337,
        verifyingContract: await attestationRegistry.getAddress()
      };
      
      const types = {
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
      
      const value = {
        consumerOrg: orgId1,
        consumerServiceHash,
        providerOrg: orgId2,
        providerServiceHash,
        strength: 2, // High
        tolerance: 0, // Under15m
        nonce,
        expiry
      };
      
      const signature = await agentSigner1.signTypedData(domain, types, value);
      
      await expect(attestationRegistry.submitDependencyAttestation(
        orgId1, consumerServiceHash, orgId2, providerServiceHash,
        2, 0, nonce, expiry, signature
      )).to.emit(attestationRegistry, "DependencyAttestationSubmitted");
      
      const edgeState = await attestationRegistry.getEdgeState(orgId1, consumerServiceHash, orgId2, providerServiceHash);
      expect(edgeState).to.equal(0); // Proposed
    });

    it("BC-ATT-D-01: Should confirm edge when both sides attest", async function () {
      const { attestationRegistry, orgId1, orgId2, agentSigner1, agentSigner2 } = await loadFixture(deployFixture);
      
      const consumerServiceHash = ethers.id("power-service-1");
      const providerServiceHash = ethers.id("water-service-1");
      const nonce = 1;
      const expiry = Math.floor(Date.now() / 1000) + 86400;
      
      const domain = {
        name: "AttestationRegistry",
        version: "1",
        chainId: 31337,
        verifyingContract: await attestationRegistry.getAddress()
      };
      
      const types = {
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
      
      const value = {
        consumerOrg: orgId1,
        consumerServiceHash,
        providerOrg: orgId2,
        providerServiceHash,
        strength: 2,
        tolerance: 0,
        nonce,
        expiry
      };
      
      const sig1 = await agentSigner1.signTypedData(domain, types, value);
      const sig2 = await agentSigner2.signTypedData(domain, types, value);
      
      // Submit consumer attestation
      await attestationRegistry.submitDependencyAttestation(
        orgId1, consumerServiceHash, orgId2, providerServiceHash,
        2, 0, nonce, expiry, sig1
      );
      
      // Submit provider attestation
      await expect(attestationRegistry.submitDependencyAttestation(
        orgId1, consumerServiceHash, orgId2, providerServiceHash,
        2, 0, nonce, expiry, sig2
      )).to.emit(attestationRegistry, "DependencyEdgeConfirmed");
      
      const isConfirmed = await attestationRegistry.isEdgeConfirmed(orgId1, consumerServiceHash, orgId2, providerServiceHash);
      expect(isConfirmed).to.be.true;
    });

    it("BC-ATT-D-04: Should revert on mismatched attestations", async function () {
      const { attestationRegistry, orgId1, orgId2, agentSigner1, agentSigner2 } = await loadFixture(deployFixture);
      
      const consumerServiceHash = ethers.id("power-service-1");
      const providerServiceHash = ethers.id("water-service-1");
      const nonce = 1;
      const expiry = Math.floor(Date.now() / 1000) + 86400;
      
      const domain = {
        name: "AttestationRegistry",
        version: "1",
        chainId: 31337,
        verifyingContract: await attestationRegistry.getAddress()
      };
      
      const types = {
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
      
      const value1 = {
        consumerOrg: orgId1,
        consumerServiceHash,
        providerOrg: orgId2,
        providerServiceHash,
        strength: 2, // High
        tolerance: 0,
        nonce,
        expiry
      };
      
      const value2 = {
        consumerOrg: orgId1,
        consumerServiceHash,
        providerOrg: orgId2,
        providerServiceHash,
        strength: 1, // Medium - mismatch!
        tolerance: 0,
        nonce,
        expiry
      };
      
      const sig1 = await agentSigner1.signTypedData(domain, types, value1);
      const sig2 = await agentSigner2.signTypedData(domain, types, value2);
      
      await attestationRegistry.submitDependencyAttestation(
        orgId1, consumerServiceHash, orgId2, providerServiceHash,
        2, 0, nonce, expiry, sig1
      );
      
      await expect(attestationRegistry.submitDependencyAttestation(
        orgId1, consumerServiceHash, orgId2, providerServiceHash,
        1, 0, nonce, expiry, sig2
      )).to.emit(attestationRegistry, "DependencyEdgeDisputed");
      
      const edgeState = await attestationRegistry.getEdgeState(orgId1, consumerServiceHash, orgId2, providerServiceHash);
      expect(edgeState).to.equal(4); // Disputed
    });

    it("BC-ATT-D-06: Should reject replayed signatures", async function () {
      const { attestationRegistry, orgId1, orgId2, agentSigner1 } = await loadFixture(deployFixture);
      
      const consumerServiceHash = ethers.id("power-service-1");
      const providerServiceHash = ethers.id("water-service-1");
      const nonce = 1;
      const expiry = Math.floor(Date.now() / 1000) + 86400;
      
      const domain = {
        name: "AttestationRegistry",
        version: "1",
        chainId: 31337,
        verifyingContract: await attestationRegistry.getAddress()
      };
      
      const types = {
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
      
      const value = {
        consumerOrg: orgId1,
        consumerServiceHash,
        providerOrg: orgId2,
        providerServiceHash,
        strength: 2,
        tolerance: 0,
        nonce,
        expiry
      };
      
      const signature = await agentSigner1.signTypedData(domain, types, value);
      
      // First submission should succeed
      await attestationRegistry.submitDependencyAttestation(
        orgId1, consumerServiceHash, orgId2, providerServiceHash,
        2, 0, nonce, expiry, signature
      );
      
      // Replay with same nonce should fail
      await expect(attestationRegistry.submitDependencyAttestation(
        orgId1, consumerServiceHash, orgId2, providerServiceHash,
        2, 0, nonce, expiry, signature
      )).to.be.revertedWithCustomError(attestationRegistry, "InvalidNonce");
    });
  });

  describe("Risk Attestations (BC-ATT-R)", function () {
    it("BC-ATT-R-01: Should submit risk attestation", async function () {
      const { attestationRegistry, orgId1, agentSigner1 } = await loadFixture(deployFixture);
      
      const serviceHash = ethers.id("power-service-1");
      const nonce = 1;
      const validUntil = Math.floor(Date.now() / 1000) + 86400;
      
      const domain = {
        name: "AttestationRegistry",
        version: "1",
        chainId: 31337,
        verifyingContract: await attestationRegistry.getAddress()
      };
      
      const types = {
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
      
      const value = {
        orgId: orgId1,
        serviceHash,
        riskBand: 2, // High
        criticalityBucket: 2, // High
        modelVersionHash: ethers.id("model-v1"),
        evidenceCommitment: ethers.id("evidence-1"),
        validUntil,
        nonce
      };
      
      const signature = await agentSigner1.signTypedData(domain, types, value);
      
      await expect(attestationRegistry.submitRiskAttestation(
        orgId1, serviceHash, 2, 2, 
        ethers.id("model-v1"), ethers.id("evidence-1"),
        validUntil, nonce, signature
      )).to.emit(attestationRegistry, "RiskAttestationSubmitted");
      
      const latest = await attestationRegistry.getLatestRiskAttestation(orgId1, serviceHash);
      expect(latest.riskBand).to.equal(2);
      expect(latest.criticalityBucket).to.equal(2);
    });

    it("BC-ATT-R-04: Should verify selective disclosure", async function () {
      const { attestationRegistry, orgId1, agentSigner1 } = await loadFixture(deployFixture);
      
      const serviceHash = ethers.id("power-service-1");
      const nonce = 1;
      const validUntil = Math.floor(Date.now() / 1000) + 86400;
      const modelVersionHash = ethers.id("model-v1");
      const assessmentHash = ethers.id("assessment-data");
      const salt = ethers.id("salt-1");
      const evidenceCommitment = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32"], [salt, assessmentHash]));
      
      const domain = {
        name: "AttestationRegistry",
        version: "1",
        chainId: 31337,
        verifyingContract: await attestationRegistry.getAddress()
      };
      
      const types = {
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
      
      const value = {
        orgId: orgId1,
        serviceHash,
        riskBand: 2,
        criticalityBucket: 2,
        modelVersionHash,
        evidenceCommitment,
        validUntil,
        nonce
      };
      
      const signature = await agentSigner1.signTypedData(domain, types, value);
      
      await attestationRegistry.submitRiskAttestation(
        orgId1, serviceHash, 2, 2, 
        modelVersionHash, evidenceCommitment,
        validUntil, nonce, signature
      );
      
      // Verify disclosure
      const attestationId = await attestationRegistry.getRiskAttestationHistory(orgId1, serviceHash).then(h => h[0]);
      const verified = await attestationRegistry.verifyRiskDisclosure(orgId1, serviceHash, attestationId, salt, assessmentHash);
      expect(verified).to.be.true;
      
      // Wrong salt should fail
      const wrongSalt = ethers.id("wrong-salt");
      const wrongVerified = await attestationRegistry.verifyRiskDisclosure(orgId1, serviceHash, attestationId, wrongSalt, assessmentHash);
      expect(wrongVerified).to.be.false;
    });

    it("BC-ATT-R-03: Should rate limit risk attestations", async function () {
      const { attestationRegistry, orgId1, agentSigner1 } = await loadFixture(deployFixture);
      
      const serviceHash = ethers.id("power-service-1");
      const validUntil = Math.floor(Date.now() / 1000) + 86400;
      const nonce = 1;
      
      const domain = {
        name: "AttestationRegistry",
        version: "1",
        chainId: 31337,
        verifyingContract: await attestationRegistry.getAddress()
      };
      
      const types = {
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
      
      const value1 = {
        orgId: orgId1,
        serviceHash,
        riskBand: 2,
        criticalityBucket: 2,
        modelVersionHash: ethers.id("model-v1"),
        evidenceCommitment: ethers.id("evidence-1"),
        validUntil,
        nonce: 1
      };
      
      const sig1 = await agentSigner1.signTypedData(domain, types, value1);
      
      await attestationRegistry.submitRiskAttestation(
        orgId1, serviceHash, 2, 2, 
        ethers.id("model-v1"), ethers.id("evidence-1"),
        validUntil, 1, sig1
      );
      
      // Second attestation immediately should fail due to rate limit (minInterval = 1 block)
      const value2 = {
        ...value1,
        nonce: 2,
        evidenceCommitment: ethers.id("evidence-2")
      };
      
      const sig2 = await agentSigner1.signTypedData(domain, types, value2);
      
      await expect(attestationRegistry.submitRiskAttestation(
        orgId1, serviceHash, 2, 2, 
        ethers.id("model-v1"), ethers.id("evidence-2"),
        validUntil, 2, sig2
      )).to.be.revertedWithCustomError(attestationRegistry, "RateLimited");
    });
  });

  describe("Finding Attestations (BC-ATT-F)", function () {
    it("BC-ATT-F-01: Should submit finding attestation", async function () {
      const { attestationRegistry, orgId1, agentSigner1 } = await loadFixture(deployFixture);
      
      const advisoryContentHash = ethers.id("advisory-content-1");
      const cveSetHash = ethers.id("cve-set-1");
      const processedAt = Math.floor(Date.now() / 1000);
      const nonce = 1;
      
      const domain = {
        name: "AttestationRegistry",
        version: "1",
        chainId: 31337,
        verifyingContract: await attestationRegistry.getAddress()
      };
      
      const types = {
        FindingAttestation: [
          { name: "orgId", type: "bytes32" },
          { name: "advisoryContentHash", type: "bytes32" },
          { name: "cveSetHash", type: "bytes32" },
          { name: "processedAt", type: "uint256" },
          { name: "matched", type: "bool" },
          { name: "nonce", type: "uint256" }
        ]
      };
      
      const value = {
        orgId: orgId1,
        advisoryContentHash,
        cveSetHash,
        processedAt,
        matched: true,
        nonce
      };
      
      const signature = await agentSigner1.signTypedData(domain, types, value);
      
      await expect(attestationRegistry.submitFindingAttestation(
        orgId1, advisoryContentHash, cveSetHash, processedAt, true, nonce, signature
      )).to.emit(attestationRegistry, "FindingAttestationSubmitted");
      
      const finding = await attestationRegistry.getFindingAttestation(orgId1, advisoryContentHash);
      expect(finding.matched).to.be.true;
      expect(finding.advisoryContentHash).to.equal(advisoryContentHash);
    });

    it("BC-ATT-F-02: Should be idempotent for duplicate findings", async function () {
      const { attestationRegistry, orgId1, agentSigner1 } = await loadFixture(deployFixture);
      
      const advisoryContentHash = ethers.id("advisory-content-2");
      const cveSetHash = ethers.id("cve-set-2");
      const processedAt = Math.floor(Date.now() / 1000);
      const nonce = 1;
      
      const domain = {
        name: "AttestationRegistry",
        version: "1",
        chainId: 31337,
        verifyingContract: await attestationRegistry.getAddress()
      };
      
      const types = {
        FindingAttestation: [
          { name: "orgId", type: "bytes32" },
          { name: "advisoryContentHash", type: "bytes32" },
          { name: "cveSetHash", type: "bytes32" },
          { name: "processedAt", type: "uint256" },
          { name: "matched", type: "bool" },
          { name: "nonce", type: "uint256" }
        ]
      };
      
      const value = {
        orgId: orgId1,
        advisoryContentHash,
        cveSetHash,
        processedAt,
        matched: true,
        nonce
      };
      
      const signature = await agentSigner1.signTypedData(domain, types, value);
      
      // First submission
      await attestationRegistry.submitFindingAttestation(
        orgId1, advisoryContentHash, cveSetHash, processedAt, true, nonce, signature
      );
      
      // Second submission with same advisoryContentHash should be idempotent
      const tx = await attestationRegistry.submitFindingAttestation(
        orgId1, advisoryContentHash, cveSetHash, processedAt, true, nonce, signature
      );
      
      // Should emit event but not create duplicate
      await expect(tx).to.emit(attestationRegistry, "FindingAttestationSubmitted");
    });
  });

  describe("Challenge Mechanism", function () {
    it("Should allow challenging risk attestations", async function () {
      const { attestationRegistry, orgId1, orgId2, agentSigner1, agentSigner2 } = await loadFixture(deployFixture);
      
      const serviceHash = ethers.id("power-service-1");
      const nonce = 1;
      const validUntil = Math.floor(Date.now() / 1000) + 86400;
      
      const domain = {
        name: "AttestationRegistry",
        version: "1",
        chainId: 31337,
        verifyingContract: await attestationRegistry.getAddress()
      };
      
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
        serviceHash,
        riskBand: 2,
        criticalityBucket: 2,
        modelVersionHash: ethers.id("model-v1"),
        evidenceCommitment: ethers.id("evidence-1"),
        validUntil,
        nonce
      };
      
      const riskSig = await agentSigner1.signTypedData(domain, riskTypes, riskValue);
      
      await attestationRegistry.submitRiskAttestation(
        orgId1, serviceHash, 2, 2, 
        ethers.id("model-v1"), ethers.id("evidence-1"),
        validUntil, nonce, riskSig
      );
      
      const attestationId = (await attestationRegistry.getRiskAttestationHistory(orgId1, serviceHash))[0];
      
      // Challenge from different org
      const challengeDomain = {
        name: "AttestationRegistry",
        version: "1",
        chainId: 31337,
        verifyingContract: await attestationRegistry.getAddress()
      };
      
      const challengeTypes = {
        Challenge: [
          { name: "attestationId", type: "bytes32" },
          { name: "challengerOrg", type: "bytes32" },
          { name: "evidenceCommitment", type: "bytes32" }
        ]
      };
      
      const challengeValue = {
        attestationId,
        challengerOrg: orgId2,
        evidenceCommitment: ethers.id("challenge-evidence")
      };
      
      const challengeSig = await agentSigner2.signTypedData(challengeDomain, challengeTypes, challengeValue);
      
      await expect(attestationRegistry.challengeRiskAttestation(
        attestationId, orgId2, ethers.id("challenge-evidence"), challengeSig
      )).to.emit(attestationRegistry, "ChallengeSubmitted");
    });
  });
});