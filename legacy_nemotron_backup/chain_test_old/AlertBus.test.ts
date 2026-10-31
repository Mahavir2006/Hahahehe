import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { AlertBus, OrgRegistry, AttestationRegistry } from "../typechain-types";

describe("AlertBus", function () {
  async function deployFixture() {
    const [deployer, admin, agentSigner1, agentSigner2, agentSigner3, stranger] = await ethers.getSigners();
    
    const OrgRegistry = await ethers.getContractFactory("OrgRegistry");
    const orgRegistry = await OrgRegistry.deploy();
    await orgRegistry.waitForDeployment();
    
    const AttestationRegistry = await ethers.getContractFactory("AttestationRegistry");
    const attestationRegistry = await AttestationRegistry.deploy(await orgRegistry.getAddress());
    await attestationRegistry.waitForDeployment();
    
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
      const approvers = [stranger.address, stranger.address, stranger.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await orgRegistry.registerOrg(orgId, nameHash, org.sector, admin.address, org.agent.address, approvers, threshold, safetyOfficerFlags);
    }
    
    return { 
      orgRegistry, 
      attestationRegistry, 
      alertBus, 
      deployer, 
      admin, 
      agentSigner1, 
      agentSigner2, 
      agentSigner3, 
      stranger,
      orgs
    };
  });

  describe("Publish Alert (BC-ALERT-01)", function () {
    it("BC-ALERT-01: Should allow org agent to publish alert", async function () {
      const { alertBus, orgs, agentSigner1 } = await loadFixture(deployFixture);
      
      const providerOrg = ethers.id("power");
      const providerServiceHash = ethers.id("power-service-1");
      const severity = 2; // High
      const ttiBucket = 1; // Min15To60
      const evidenceCommitment = ethers.id("evidence-1");
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      
      const domain = {
        name: "AlertBus",
        version: "1",
        chainId: 31337,
        verifyingContract: await alertBus.getAddress()
      };
      
      const types = {
        Alert: [
          { name: "providerOrg", type: "bytes32" },
          { name: "providerServiceHash", type: "bytes32" },
          { name: "severity", type: "uint8" },
          { name: "ttiBucket", type: "uint8" },
          { name: "evidenceCommitment", type: "bytes32" },
          { name: "expiry", type: "uint256" }
        ]
      };
      
      const value = { providerOrg, providerServiceHash, severity, ttiBucket, evidenceCommitment, expiry };
      const signature = await agentSigner1.signTypedData(domain, types, value);
      
      const alertId = await alertBus.publish(providerOrg, providerServiceHash, severity, ttiBucket, evidenceCommitment, expiry, signature);
      expect(alertId).to.not.equal(ethers.ZeroHash);
      
      const alert = await alertBus.getAlert(alertId);
      expect(alert.providerOrg).to.equal(providerOrg);
      expect(alert.providerServiceHash).to.equal(providerServiceHash);
      expect(alert.severity).to.equal(severity);
      expect(alert.status).to.equal(0); // Active
    });

    it("BC-ALERT-01: Should revert if non-agent tries to publish", async function () {
      const { alertBus, orgs, stranger } = await loadFixture(deployFixture);
      
      const providerOrg = ethers.id("power");
      const providerServiceHash = ethers.id("power-service-1");
      const severity = 2;
      const ttiBucket = 1;
      const evidenceCommitment = ethers.id("evidence-1");
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      
      const domain = {
        name: "AlertBus",
        version: "1",
        chainId: 31337,
        verifyingContract: await alertBus.getAddress()
      };
      
      const types = {
        Alert: [
          { name: "providerOrg", type: "bytes32" },
          { name: "providerServiceHash", type: "bytes32" },
          { name: "severity", type: "uint8" },
          { name: "ttiBucket", type: "uint8" },
          { name: "evidenceCommitment", type: "bytes32" },
          { name: "expiry", type: "uint256" }
        ]
      };
      
      const value = { providerOrg, providerServiceHash, severity, ttiBucket, evidenceCommitment, expiry };
      const signature = await stranger.signTypedData(domain, types, value);
      
      await expect(alertBus.publish(providerOrg, providerServiceHash, severity, ttiBucket, evidenceCommitment, expiry, signature))
        .to.be.revertedWithCustomError(alertBus, "InvalidSignature");
    });

    it("BC-ALERT-04: Should deduplicate alerts within window", async function () {
      const { alertBus, orgs, agentSigner1 } = await loadFixture(deployFixture);
      
      const providerOrg = ethers.id("power");
      const providerServiceHash = ethers.id("power-service-1");
      const severity = 2;
      const ttiBucket = 1;
      const evidenceCommitment = ethers.id("evidence-1");
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      
      const domain = {
        name: "AlertBus",
        version: "1",
        chainId: 31337,
        verifyingContract: await alertBus.getAddress()
      };
      
      const types = {
        Alert: [
          { name: "providerOrg", type: "bytes32" },
          { name: "providerServiceHash", type: "bytes32" },
          { name: "severity", type: "uint8" },
          { name: "ttiBucket", type: "uint8" },
          { name: "evidenceCommitment", type: "bytes32" },
          { name: "expiry", type: "uint256" }
        ]
      };
      
      const value = { providerOrg, providerServiceHash, severity, ttiBucket, evidenceCommitment, expiry };
      const signature = await agentSigner1.signTypedData(domain, types, value);
      
      // First alert
      await alertBus.publish(providerOrg, providerServiceHash, severity, ttiBucket, evidenceCommitment, expiry, signature);
      
      // Second alert with same provider/service/severity within dedupe window
      await expect(alertBus.publish(providerOrg, providerServiceHash, severity, ttiBucket, evidenceCommitment, expiry, signature))
        .to.be.revertedWithCustomError(alertBus, "DuplicateAlert");
    });
  });

  describe("Acknowledge (BC-ALERT-03)", function () {
    it("BC-ALERT-03: Should allow consumer org to acknowledge alert", async function () {
      const { alertBus, orgs, agentSigner1, agentSigner2 } = await loadFixture(deployFixture);
      
      const providerOrg = ethers.id("power");
      const providerServiceHash = ethers.id("power-service-1");
      const severity = 2;
      const ttiBucket = 1;
      const evidenceCommitment = ethers.id("evidence-1");
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      
      const domain = {
        name: "AlertBus",
        version: "1",
        chainId: 31337,
        verifyingContract: await alertBus.getAddress()
      };
      
      const alertTypes = {
        Alert: [
          { name: "providerOrg", type: "bytes32" },
          { name: "providerServiceHash", type: "bytes32" },
          { name: "severity", type: "uint8" },
          { name: "ttiBucket", type: "uint8" },
          { name: "evidenceCommitment", type: "bytes32" },
          { name: "expiry", type: "uint256" }
        ]
      };
      
      const alertValue = { providerOrg, providerServiceHash, severity, ttiBucket, evidenceCommitment, expiry };
      const alertSig = await agentSigner1.signTypedData(domain, alertTypes, alertValue);
      
      const alertId = await alertBus.publish(providerOrg, providerServiceHash, severity, ttiBucket, evidenceCommitment, expiry, alertSig);
      
      // Acknowledge
      const ackDomain = {
        name: "AlertBus",
        version: "1",
        chainId: 31337,
        verifyingContract: await alertBus.getAddress()
      };
      
      const ackTypes = {
        Acknowledge: [
          { name: "alertId", type: "bytes32" }
        ]
      };
      
      const ackValue = { alertId };
      const ackSig = await agentSigner2.signTypedData(ackDomain, ackTypes, ackValue);
      
      await expect(alertBus.acknowledge(alertId, ackSig))
        .to.emit(alertBus, "AlertAcknowledged");
      
      const alert = await alertBus.getAlert(alertId);
      expect(alert.status).to.equal(1); // Acknowledged
    });
  });

  describe("Resolve (BC-ALERT-05)", function () {
    it("BC-ALERT-05: Should allow provider to resolve alert", async function () {
      const { alertBus, orgs, agentSigner1 } = await loadFixture(deployFixture);
      
      const providerOrg = ethers.id("power");
      const providerServiceHash = ethers.id("power-service-1");
      const severity = 2;
      const ttiBucket = 1;
      const evidenceCommitment = ethers.id("evidence-1");
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      
      const domain = {
        name: "AlertBus",
        version: "1",
        chainId: 31337,
        verifyingContract: await alertBus.getAddress()
      };
      
      const types = {
        Alert: [
          { name: "providerOrg", type: "bytes32" },
          { name: "providerServiceHash", type: "bytes32" },
          { name: "severity", type: "uint8" },
          { name: "ttiBucket", type: "uint8" },
          { name: "evidenceCommitment", type: "bytes32" },
          { name: "expiry", type: "uint256" }
        ]
      };
      
      const value = { providerOrg, providerServiceHash, severity, ttiBucket, evidenceCommitment, expiry };
      const signature = await agentSigner1.signTypedData(domain, types, value);
      
      const alertId = await alertBus.publish(providerOrg, providerServiceHash, severity, ttiBucket, evidenceCommitment, expiry, signature);
      
      // Resolve
      const resolveDomain = {
        name: "AlertBus",
        version: "1",
        chainId: 31337,
        verifyingContract: await alertBus.getAddress()
      };
      
      const resolveTypes = {
        Resolve: [
          { name: "alertId", type: "bytes32" }
        ]
      };
      
      const resolveValue = { alertId };
      const resolveSig = await agentSigner1.signTypedData(resolveDomain, resolveTypes, resolveValue);
      
      await expect(alertBus.resolve(alertId, resolveSig))
        .to.emit(alertBus, "AlertResolved");
      
      const alert = await alertBus.getAlert(alertId);
      expect(alert.status).to.equal(2); // Resolved
    });
  });

  describe("Rate Limiting (BC-ALERT-06)", function () {
    it("BC-ALERT-06: Should enforce rate limit per org", async function () {
      const { alertBus, orgs, agentSigner1 } = await loadFixture(deployFixture);
      
      const providerOrg = ethers.id("power");
      const severity = 2;
      const ttiBucket = 1;
      const expiry = Math.floor(Date.now() / 1000) + 3600;
      
      const domain = {
        name: "AlertBus",
        version: "1",
        chainId: 31337,
        verifyingContract: await alertBus.getAddress()
      };
      
      const types = {
        Alert: [
          { name: "providerOrg", type: "bytes32" },
          { name: "providerServiceHash", type: "bytes32" },
          { name: "severity", type: "uint8" },
          { name: "ttiBucket", type: "uint8" },
          { name: "evidenceCommitment", type: "bytes32" },
          { name: "expiry", type: "uint256" }
        ]
      };
      
      // Publish many alerts (rate limit is 100)
      for (let i = 0; i < 100; i++) {
        const providerServiceHash = ethers.id("power-service-" + i);
        const evidenceCommitment = ethers.id("evidence-" + i);
        
        const value = { providerOrg, providerServiceHash, severity, ttiBucket, evidenceCommitment, expiry };
        const signature = await agentSigner1.signTypedData(domain, types, value);
        
        await alertBus.publish(providerOrg, providerServiceHash, severity, ttiBucket, evidenceCommitment, expiry, signature);
      }
      
      // 101st should fail
      const providerServiceHash = ethers.id("power-service-101");
      const evidenceCommitment = ethers.id("evidence-101");
      const value = { providerOrg, providerServiceHash, severity, ttiBucket, evidenceCommitment, expiry };
      const signature = await agentSigner1.signTypedData(domain, types, value);
      
      await expect(alertBus.publish(providerOrg, providerServiceHash, severity, ttiBucket, evidenceCommitment, expiry, signature))
        .to.be.revertedWithCustomError(alertBus, "RateLimitExceeded");
    });
  });
});