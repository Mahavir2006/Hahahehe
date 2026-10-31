import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { OrgRegistry } from "../typechain-types";

describe("OrgRegistry", function () {
  async function deployOrgRegistryFixture() {
    const [deployer, admin, agentSigner, approver1, approver2, approver3, stranger, stranger1, stranger2, stranger3, agentSigner2, b1, b2, b3] = await ethers.getSigners();
    
    const OrgRegistry = await ethers.getContractFactory("OrgRegistry");
    const orgRegistry = await OrgRegistry.deploy();
    await orgRegistry.waitForDeployment();
    
    return { orgRegistry, deployer, admin, agentSigner, approver1, approver2, approver3, stranger, stranger1, stranger2, stranger3, agentSigner2, b1, b2, b3 };
  }

  describe("Constructor", function () {
    it("BC-ORG-01: Should grant REGISTRY_ADMIN_ROLE to deployer", async function () {
      const { orgRegistry, deployer } = await loadFixture(deployOrgRegistryFixture);
      const REGISTRY_ADMIN_ROLE = await orgRegistry.REGISTRY_ADMIN_ROLE();
      expect(await orgRegistry.hasRole(REGISTRY_ADMIN_ROLE, deployer.address)).to.be.true;
    });
  });

  describe("registerOrg", function () {
    it("BC-ORG-01: Should register org successfully with valid params", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      const tx = await orgRegistry.registerOrg(
        orgId, nameHash, 0, admin.address, agentSigner.address,
        approvers, threshold, safetyOfficerFlags
      );
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt!.blockNumber);
      const timestamp = block?.timestamp || 0;
      
      await expect(tx).to.emit(orgRegistry, "OrgRegistered")
        .withArgs(orgId, nameHash, 0, admin.address, agentSigner.address, timestamp);
      
      const org = await orgRegistry.getOrg(orgId);
      expect(org.orgId).to.equal(orgId);
      expect(org.nameHash).to.equal(nameHash);
      expect(org.sector).to.equal(0);
      expect(org.adminAddress).to.equal(admin.address);
      expect(org.agentSigner).to.equal(agentSigner.address);
      expect(org.threshold).to.equal(threshold);
      expect(org.active).to.be.true;
    });

    it("BC-ORG-01: Should revert if not called by REGISTRY_ADMIN", async function () {
      const { orgRegistry, stranger, admin, agentSigner, approver1, approver2, approver3 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await expect(orgRegistry.connect(stranger).registerOrg(
        orgId, nameHash, 0, admin.address, agentSigner.address,
        approvers, threshold, safetyOfficerFlags
      )).to.be.revertedWithCustomError(orgRegistry, "OnlyRegistryAdmin");
    });

    it("BC-ORG-01: Should revert if org already exists", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await orgRegistry.registerOrg(orgId, nameHash, 0, admin.address, agentSigner.address, approvers, threshold, safetyOfficerFlags);
      
      await expect(orgRegistry.registerOrg(
        orgId, nameHash, 0, admin.address, agentSigner.address,
        approvers, threshold, safetyOfficerFlags
      )).to.be.revertedWithCustomError(orgRegistry, "OrgAlreadyExists");
    });

    it("BC-ORG-01: Should revert with zero address for admin or agentSigner", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await expect(orgRegistry.registerOrg(
        orgId, nameHash, 0, ethers.ZeroAddress, agentSigner.address,
        approvers, threshold, safetyOfficerFlags
      )).to.be.revertedWithCustomError(orgRegistry, "ZeroAddress");
      
      await expect(orgRegistry.registerOrg(
        orgId, nameHash, 0, admin.address, ethers.ZeroAddress,
        approvers, threshold, safetyOfficerFlags
      )).to.be.revertedWithCustomError(orgRegistry, "ZeroAddress");
    });

    it("BC-ORG-01: Should revert with invalid sector", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await expect(orgRegistry.registerOrg(
        orgId, nameHash, 5, admin.address, agentSigner.address,
        approvers, threshold, safetyOfficerFlags
      )).to.be.revertedWithCustomError(orgRegistry, "InvalidSector");
    });

    it("BC-ORG-01: Should revert with less than 3 approvers", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address];
      const safetyOfficerFlags = [true, false];
      const threshold = 1;
      
      await expect(orgRegistry.registerOrg(
        orgId, nameHash, 0, admin.address, agentSigner.address,
        approvers, threshold, safetyOfficerFlags
      )).to.be.revertedWithCustomError(orgRegistry, "InvalidApproverCount");
    });

    it("BC-ORG-01: Should revert with invalid threshold", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      
      // Threshold = 0
      await expect(orgRegistry.registerOrg(
        orgId, nameHash, 0, admin.address, agentSigner.address,
        approvers, 0, safetyOfficerFlags
      )).to.be.revertedWithCustomError(orgRegistry, "InvalidThreshold");
      
      // Threshold > approvers.length
      await expect(orgRegistry.registerOrg(
        orgId, nameHash, 0, admin.address, agentSigner.address,
        approvers, 4, safetyOfficerFlags
      )).to.be.revertedWithCustomError(orgRegistry, "InvalidThreshold");
    });

    it("BC-ORG-01: Should revert if safetyOfficerFlags length mismatch", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false]; // Wrong length
      const threshold = 2;
      
      await expect(orgRegistry.registerOrg(
        orgId, nameHash, 0, admin.address, agentSigner.address,
        approvers, threshold, safetyOfficerFlags
      )).to.be.revertedWithCustomError(orgRegistry, "InvalidApproverCount");
    });

    it("BC-ORG-01: Should revert if agentSigner is in approvers", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [agentSigner.address, approver1.address, approver2.address]; // agentSigner in approvers
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await expect(orgRegistry.registerOrg(
        orgId, nameHash, 0, admin.address, agentSigner.address,
        approvers, threshold, safetyOfficerFlags
      )).to.be.revertedWithCustomError(orgRegistry, "AgentSignerCannotBeApprover");
    });

    it("BC-ORG-01: Should revert if duplicate approvers", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver1.address, approver2.address]; // Duplicate
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await expect(orgRegistry.registerOrg(
        orgId, nameHash, 0, admin.address, agentSigner.address,
        approvers, threshold, safetyOfficerFlags
      )).to.be.revertedWithCustomError(orgRegistry, "DuplicateApprover");
    });

    it("BC-ORG-01: Should revert if no safety officer", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [false, false, false]; // No safety officer
      const threshold = 2;
      
      await expect(orgRegistry.registerOrg(
        orgId, nameHash, 0, admin.address, agentSigner.address,
        approvers, threshold, safetyOfficerFlags
      )).to.be.revertedWithCustomError(orgRegistry, "InvalidApproverCount");
    });

    it("BC-ORG-01: Should store approvers with metadata correctly", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, true]; // Two safety officers
      const threshold = 2;
      
      await orgRegistry.registerOrg(orgId, nameHash, 0, admin.address, agentSigner.address, approvers, threshold, safetyOfficerFlags);
      
      const count = await orgRegistry.getApproverCount(orgId);
      expect(count).to.equal(3);
      
      const [addr0, isSafety0] = await orgRegistry.getApproverAt(orgId, 0);
      const [addr1, isSafety1] = await orgRegistry.getApproverAt(orgId, 1);
      const [addr2, isSafety2] = await orgRegistry.getApproverAt(orgId, 2);
      
      expect(addr0).to.equal(approver1.address);
      expect(isSafety0).to.be.true;
      expect(addr1).to.equal(approver2.address);
      expect(isSafety1).to.be.false;
      expect(addr2).to.equal(approver3.address);
      expect(isSafety2).to.be.true;
    });
  });

  describe("View functions", function () {
    it("BC-ORG-03: Should return correct org info", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await orgRegistry.registerOrg(orgId, nameHash, 0, admin.address, agentSigner.address, approvers, threshold, safetyOfficerFlags);
      
      const org = await orgRegistry.getOrg(orgId);
      expect(org.orgId).to.equal(orgId);
      
      const returnedThreshold = await orgRegistry.getThreshold(orgId);
      expect(returnedThreshold).to.equal(threshold);
      
      const approverCount = await orgRegistry.getApproverCount(orgId);
      expect(approverCount).to.equal(3);
    });

    it("BC-ORG-03: Should correctly identify agent signer", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3, stranger } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await orgRegistry.registerOrg(orgId, nameHash, 0, admin.address, agentSigner.address, approvers, threshold, safetyOfficerFlags);
      
      expect(await orgRegistry.isOrgAgent(orgId, agentSigner.address)).to.be.true;
      expect(await orgRegistry.isOrgAgent(orgId, stranger.address)).to.be.false;
      expect(await orgRegistry.isOrgAgent(orgId, approver1.address)).to.be.false;
    });

    it("BC-ORG-03: Should correctly identify approvers and safety officers", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3, stranger } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await orgRegistry.registerOrg(orgId, nameHash, 0, admin.address, agentSigner.address, approvers, threshold, safetyOfficerFlags);
      
      expect(await orgRegistry.isOrgApprover(orgId, approver1.address)).to.be.true;
      expect(await orgRegistry.isOrgApprover(orgId, approver2.address)).to.be.true;
      expect(await orgRegistry.isOrgApprover(orgId, stranger.address)).to.be.false;
      
      expect(await orgRegistry.isOrgSafetyOfficer(orgId, approver1.address)).to.be.true;
      expect(await orgRegistry.isOrgSafetyOfficer(orgId, approver2.address)).to.be.false;
      expect(await orgRegistry.isOrgSafetyOfficer(orgId, stranger.address)).to.be.false;
    });

    it("BC-ORG-07: Should return all org IDs", async function () {
      const { orgRegistry, admin, agentSigner, agentSigner2, approver1, approver2, approver3, b1, b2, b3 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId1 = ethers.id("power");
      const orgId2 = ethers.id("water");
      const nameHash1 = ethers.id("Grid Utility");
      const nameHash2 = ethers.id("Water Board");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await orgRegistry.registerOrg(orgId1, nameHash1, 0, admin.address, agentSigner.address, approvers, threshold, safetyOfficerFlags);
      await orgRegistry.registerOrg(orgId2, nameHash2, 1, admin.address, agentSigner2.address, [b1.address, b2.address, b3.address], threshold, safetyOfficerFlags);
      
      const allIds = await orgRegistry.getAllOrgIds();
      expect(allIds.length).to.equal(2);
      expect(allIds).to.deep.equal([orgId1, orgId2]);
    });
  });

  describe("setEncryptionKey", function () {
    it("SEC-PRIV-04: org admin publishes and rotates the X25519 key used to seal disclosures to the org", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3, stranger } = await loadFixture(deployOrgRegistryFixture);
      const orgId = ethers.id("power");
      await orgRegistry.registerOrg(orgId, ethers.id("Grid Utility"), 0, admin.address, agentSigner.address,
        [approver1.address, approver2.address, approver3.address], 2, [true, false, false]);

      const k1 = ethers.id("x25519-pub-1");
      await expect(orgRegistry.connect(admin).setEncryptionKey(orgId, k1)).to.emit(orgRegistry, "EncryptionKeySet");
      expect(await orgRegistry.encryptionKeys(orgId)).to.equal(k1);
      const k2 = ethers.id("x25519-pub-2");
      await orgRegistry.connect(admin).setEncryptionKey(orgId, k2);
      expect(await orgRegistry.encryptionKeys(orgId)).to.equal(k2);

      await expect(orgRegistry.connect(stranger).setEncryptionKey(orgId, k1)).to.be.revertedWithCustomError(orgRegistry, "OnlyOrgAdmin");
      await expect(orgRegistry.connect(agentSigner).setEncryptionKey(orgId, k1)).to.be.revertedWithCustomError(orgRegistry, "OnlyOrgAdmin");
      await expect(orgRegistry.connect(admin).setEncryptionKey(orgId, ethers.ZeroHash)).to.be.revertedWithCustomError(orgRegistry, "InvalidEncryptionKey");
      await expect(orgRegistry.connect(admin).setEncryptionKey(ethers.id("nobody"), k1)).to.be.revertedWithCustomError(orgRegistry, "OrgNotFound");
    });
  });

  describe("rotateAgentSigner", function () {
    it("BC-ORG-04: Should allow org admin to rotate agent signer", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3, stranger } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await orgRegistry.registerOrg(orgId, nameHash, 0, admin.address, agentSigner.address, approvers, threshold, safetyOfficerFlags);
      
      const tx = await orgRegistry.connect(admin).rotateAgentSigner(orgId, stranger.address);
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt!.blockNumber);
      const timestamp = block?.timestamp || 0;
      
      await expect(tx).to.emit(orgRegistry, "AgentSignerRotated")
        .withArgs(orgId, agentSigner.address, stranger.address, timestamp);
      
      const org = await orgRegistry.getOrg(orgId);
      expect(org.agentSigner).to.equal(stranger.address);
      expect(await orgRegistry.isOrgAgent(orgId, stranger.address)).to.be.true;
      expect(await orgRegistry.isOrgAgent(orgId, agentSigner.address)).to.be.false;
    });

    it("BC-ORG-04: Should revert if not called by org admin", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3, stranger } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await orgRegistry.registerOrg(orgId, nameHash, 0, admin.address, agentSigner.address, approvers, threshold, safetyOfficerFlags);
      
      await expect(orgRegistry.connect(stranger).rotateAgentSigner(orgId, stranger.address))
        .to.be.revertedWithCustomError(orgRegistry, "OnlyOrgAdmin");
    });

    it("BC-ORG-04: Should revert with zero address", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await orgRegistry.registerOrg(orgId, nameHash, 0, admin.address, agentSigner.address, approvers, threshold, safetyOfficerFlags);
      
      await expect(orgRegistry.connect(admin).rotateAgentSigner(orgId, ethers.ZeroAddress))
        .to.be.revertedWithCustomError(orgRegistry, "ZeroAddress");
    });
  });

  describe("updateApproverSet", function () {
    it("BC-ORG-05: Should allow org admin to update approver set", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3, stranger1, stranger2, stranger3 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await orgRegistry.registerOrg(orgId, nameHash, 0, admin.address, agentSigner.address, approvers, threshold, safetyOfficerFlags);
      
      const newApprovers = [stranger1.address, stranger2.address, stranger3.address];
      const newSafetyOfficerFlags = [false, true, false];
      const newThreshold = 2;
      
      await expect(orgRegistry.connect(admin).updateApproverSet(
        orgId, newApprovers, newThreshold, newSafetyOfficerFlags
      )).to.emit(orgRegistry, "ApproverSetUpdated");
      
      const org = await orgRegistry.getOrg(orgId);
      expect(org.threshold).to.equal(newThreshold);
      // Note: org.approvers is not directly accessible via public getter for dynamic arrays
      // Check via individual getters
      const count = await orgRegistry.getApproverCount(orgId);
      expect(count).to.equal(3);
      
      const [addr0, isSafety0] = await orgRegistry.getApproverAt(orgId, 0);
      const [addr1, isSafety1] = await orgRegistry.getApproverAt(orgId, 1);
      const [addr2, isSafety2] = await orgRegistry.getApproverAt(orgId, 2);
      
      expect(addr0).to.equal(newApprovers[0]);
      expect(isSafety0).to.equal(newSafetyOfficerFlags[0]);
      expect(addr1).to.equal(newApprovers[1]);
      expect(isSafety1).to.equal(newSafetyOfficerFlags[1]);
      expect(addr2).to.equal(newApprovers[2]);
      expect(isSafety2).to.equal(newSafetyOfficerFlags[2]);
    });

    it("BC-ORG-05: Should revert if new threshold invalid", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3, stranger1, stranger2, stranger3 } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await orgRegistry.registerOrg(orgId, nameHash, 0, admin.address, agentSigner.address, approvers, threshold, safetyOfficerFlags);
      
      const newApprovers = [stranger1.address, stranger2.address, stranger3.address];
      const newSafetyOfficerFlags = [true, false, false];
      
      await expect(orgRegistry.connect(admin).updateApproverSet(
        orgId, newApprovers, 4, newSafetyOfficerFlags
      )).to.be.revertedWithCustomError(orgRegistry, "InvalidThreshold");
    });

    it("BC-ORG-05: Should not retroactively change pending requests' snapshot", async function () {
      // This is tested in ApprovalGate tests - the snapshot is taken at request creation
      // OrgRegistry just stores current state
    });
  });

  describe("deactivateOrg / reactivateOrg", function () {
    it("BC-ORG-06: Should allow registry admin to deactivate org", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3, deployer } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await orgRegistry.registerOrg(orgId, nameHash, 0, admin.address, agentSigner.address, approvers, threshold, safetyOfficerFlags);
      
      await expect(orgRegistry.connect(deployer).deactivateOrg(orgId))
        .to.emit(orgRegistry, "OrgDeactivated");
      
      expect(await orgRegistry.isOrgActive(orgId)).to.be.false;
    });

    it("BC-ORG-06: Should allow registry admin to reactivate org", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3, deployer } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await orgRegistry.registerOrg(orgId, nameHash, 0, admin.address, agentSigner.address, approvers, threshold, safetyOfficerFlags);
      await orgRegistry.connect(deployer).deactivateOrg(orgId);
      
      await expect(orgRegistry.connect(deployer).reactivateOrg(orgId))
        .to.emit(orgRegistry, "OrgReactivated");
      
      expect(await orgRegistry.isOrgActive(orgId)).to.be.true;
    });

    it("BC-ORG-06: Should revert if not called by registry admin", async function () {
      const { orgRegistry, admin, agentSigner, approver1, approver2, approver3, stranger } = await loadFixture(deployOrgRegistryFixture);
      
      const orgId = ethers.id("power");
      const nameHash = ethers.id("Grid Utility");
      const approvers = [approver1.address, approver2.address, approver3.address];
      const safetyOfficerFlags = [true, false, false];
      const threshold = 2;
      
      await orgRegistry.registerOrg(orgId, nameHash, 0, admin.address, agentSigner.address, approvers, threshold, safetyOfficerFlags);
      
      await expect(orgRegistry.connect(stranger).deactivateOrg(orgId))
        .to.be.revertedWithCustomError(orgRegistry, "OnlyRegistryAdmin");
    });
  });
});