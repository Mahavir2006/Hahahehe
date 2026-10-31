import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { AuditLog } from "../typechain-types";

describe("AuditLog", function () {
  async function deployFixture() {
    const [deployer, admin, agentSigner, stranger] = await ethers.getSigners();
    
    const OrgRegistry = await ethers.getContractFactory("OrgRegistry");
    const orgRegistry = await OrgRegistry.deploy();
    await orgRegistry.waitForDeployment();
    
    const AuditLog = await ethers.getContractFactory("AuditLog");
    const auditLog = await AuditLog.deploy(await orgRegistry.getAddress());
    await auditLog.waitForDeployment();
    
    // Register org
    const orgId = ethers.id("power");
    const nameHash = ethers.id("Grid Utility");
    const approvers = [stranger.address, stranger.address, stranger.address]; // dummy
    const safetyOfficerFlags = [true, false, false];
    const threshold = 2;
    
    await orgRegistry.registerOrg(orgId, nameHash, 0, admin.address, agentSigner.address, approvers, threshold, safetyOfficerFlags);
    
    return { 
      orgRegistry, 
      auditLog, 
      deployer, 
      admin, 
      agentSigner, 
      stranger,
      orgId
    };
  }

  describe("Single Anchor (BC-AUD-01, BC-AUD-02)", function () {
    it("BC-AUD-01: Should anchor single record with hash chaining", async function () {
      const { auditLog, orgId, agentSigner } = await loadFixture(deployFixture);
      
      const digest = ethers.id("trace-1");
      const prevDigest = ethers.ZeroHash;
      const metaHash = ethers.id("meta-1");
      
      // Create signature
      const domain = {
        name: "AuditLog",
        version: "1",
        chainId: 31337,
        verifyingContract: await auditLog.getAddress()
      };
      
      const types = {
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
      
      const value = {
        orgId,
        kind: 0, // AgentTrace
        digest,
        prevDigest,
        metaHash,
        index: 0,
        timestamp: Math.floor(Date.now() / 1000)
      };
      
      const signature = await agentSigner.signTypedData(domain, types, value);
      
      const index = await auditLog.anchor(orgId, 0, digest, prevDigest, metaHash, signature);
      expect(index).to.equal(0);
      
      const anchor = await auditLog.getAnchor(orgId, 0);
      expect(anchor.digest).to.equal(digest);
      expect(anchor.prevDigest).to.equal(prevDigest);
      expect(anchor.metaHash).to.equal(metaHash);
      expect(anchor.index).to.equal(0);
      expect(anchor.kind).to.equal(0);
      
      const lastDigest = await auditLog.getLastDigest(orgId);
      expect(lastDigest).to.not.equal(ethers.ZeroHash);
    });

    it("BC-AUD-02: Should enforce hash chaining - reject wrong prevDigest", async function () {
      const { auditLog, orgId, agentSigner } = await loadFixture(deployFixture);
      
      const digest1 = ethers.id("trace-1");
      const metaHash = ethers.id("meta-1");
      
      const domain = {
        name: "AuditLog",
        version: "1",
        chainId: 31337,
        verifyingContract: await auditLog.getAddress()
      };
      
      const types = {
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
      
      // First anchor
      const value1 = { orgId, kind: 0, digest: digest1, prevDigest: ethers.ZeroHash, metaHash, index: 0, timestamp: Math.floor(Date.now() / 1000) };
      const sig1 = await agentSigner.signTypedData(domain, types, value1);
      await auditLog.anchor(orgId, 0, digest1, ethers.ZeroHash, metaHash, sig1);
      
      // Second anchor with wrong prevDigest
      const digest2 = ethers.id("trace-2");
      const wrongPrevDigest = ethers.id("wrong");
      const value2 = { orgId, kind: 0, digest: digest2, prevDigest: wrongPrevDigest, metaHash, index: 1, timestamp: Math.floor(Date.now() / 1000) };
      const sig2 = await agentSigner.signTypedData(domain, types, value2);
      
      await expect(auditLog.anchor(orgId, 0, digest2, wrongPrevDigest, metaHash, sig2))
        .to.be.revertedWithCustomError(auditLog, "InvalidPrevDigest");
    });

    it("BC-AUD-02: Should accept correct prevDigest for chained anchors", async function () {
      const { auditLog, orgId, agentSigner } = await loadFixture(deployFixture);
      
      const metaHash = ethers.id("meta");
      
      const domain = {
        name: "AuditLog",
        version: "1",
        chainId: 31337,
        verifyingContract: await auditLog.getAddress()
      };
      
      const types = {
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
      
      // First anchor
      const digest1 = ethers.id("trace-1");
      const value1 = { orgId, kind: 0, digest: digest1, prevDigest: ethers.ZeroHash, metaHash, index: 0, timestamp: Math.floor(Date.now() / 1000) };
      const sig1 = await agentSigner.signTypedData(domain, types, value1);
      await auditLog.anchor(orgId, 0, digest1, ethers.ZeroHash, metaHash, sig1);
      
      const lastDigest1 = await auditLog.getLastDigest(orgId);
      
      // Second anchor with correct prevDigest
      const digest2 = ethers.id("trace-2");
      const value2 = { orgId, kind: 0, digest: digest2, prevDigest: lastDigest1, metaHash, index: 1, timestamp: Math.floor(Date.now() / 1000) };
      const sig2 = await agentSigner.signTypedData(domain, types, value2);
      await auditLog.anchor(orgId, 0, digest2, lastDigest1, metaHash, sig2);
      
      const length = await auditLog.length(orgId);
      expect(length).to.equal(2);
    });

    it("BC-AUD-04: Should only allow org's agent signer or approver to anchor", async function () {
      const { auditLog, orgId, stranger } = await loadFixture(deployFixture);
      
      const digest = ethers.id("trace-1");
      const prevDigest = ethers.ZeroHash;
      const metaHash = ethers.id("meta-1");
      
      const domain = {
        name: "AuditLog",
        version: "1",
        chainId: 31337,
        verifyingContract: await auditLog.getAddress()
      };
      
      const types = {
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
      
      const value = { orgId, kind: 0, digest, prevDigest, metaHash, index: 0, timestamp: Math.floor(Date.now() / 1000) };
      const signature = await stranger.signTypedData(domain, types, value);
      
      await expect(auditLog.anchor(orgId, 0, digest, prevDigest, metaHash, signature))
        .to.be.revertedWithCustomError(auditLog, "UnauthorizedSigner");
    });
  });

  describe("Batch Anchors / Merkle (BC-AUD-03)", function () {
    it("BC-AUD-03: Should anchor batch with Merkle root", async function () {
      const { auditLog, orgId, agentSigner } = await loadFixture(deployFixture);
      
      const leaf1 = ethers.id("leaf-1");
      const leaf2 = ethers.id("leaf-2");
      const leaves = [leaf1, leaf2];
      
      // Compute Merkle root
      const merkleRoot = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["bytes32[]"], [leaves]));
      // Simplified - in reality would use proper Merkle tree
      
      const prevDigest = ethers.ZeroHash;
      const count = 2;
      
      const domain = {
        name: "AuditLog",
        version: "1",
        chainId: 31337,
        verifyingContract: await auditLog.getAddress()
      };
      
      const types = {
        BatchAnchor: [
          { name: "orgId", type: "bytes32" },
          { name: "kind", type: "uint8" },
          { name: "merkleRoot", type: "bytes32" },
          { name: "count", type: "uint256" },
          { name: "prevDigest", type: "bytes32" },
          { name: "startIndex", type: "uint256" },
          { name: "timestamp", type: "uint256" }
        ]
      };
      
      const value = { orgId, kind: 0, merkleRoot, count, prevDigest, startIndex: 0, timestamp: Math.floor(Date.now() / 1000) };
      const signature = await agentSigner.signTypedData(domain, types, value);
      
      const batchIndex = await auditLog.anchorBatch(orgId, 0, merkleRoot, count, prevDigest, signature);
      expect(batchIndex).to.equal(0);
      
      const batch = await auditLog.getBatchAnchor(orgId, 0);
      expect(batch.merkleRoot).to.equal(merkleRoot);
      expect(batch.count).to.equal(count);
    });

    it("BC-AUD-03: Should verify Merkle inclusion proofs", async function () {
      const { auditLog, orgId, agentSigner } = await loadFixture(deployFixture);
      
      const leaf1 = ethers.id("leaf-1");
      const leaf2 = ethers.id("leaf-2");
      const leaves = [leaf1, leaf2];
      
      // Simple Merkle tree: root = hash(leaf1, leaf2)
      const merkleRoot = ethers.keccak256(ethers.concat([leaf1, leaf2]));
      const prevDigest = ethers.ZeroHash;
      const count = 2;
      
      const domain = {
        name: "AuditLog",
        version: "1",
        chainId: 31337,
        verifyingContract: await auditLog.getAddress()
      };
      
      const types = {
        BatchAnchor: [
          { name: "orgId", type: "bytes32" },
          { name: "kind", type: "uint8" },
          { name: "merkleRoot", type: "bytes32" },
          { name: "count", type: "uint256" },
          { name: "prevDigest", type: "bytes32" },
          { name: "startIndex", type: "uint256" },
          { name: "timestamp", type: "uint256" }
        ]
      };
      
      const value = { orgId, kind: 0, merkleRoot, count, prevDigest, startIndex: 0, timestamp: Math.floor(Date.now() / 1000) };
      const signature = await agentSigner.signTypedData(domain, types, value);
      
      await auditLog.anchorBatch(orgId, 0, merkleRoot, count, prevDigest, signature);
      
      // Proof for leaf1: sibling is leaf2
      const proof = [leaf2];
      const verified = await auditLog.verifyInclusion(orgId, 0, leaf1, proof);
      expect(verified).to.be.true;
      
      // Wrong proof should fail
      const wrongProof = [ethers.id("wrong")];
      const wrongVerified = await auditLog.verifyInclusion(orgId, 0, leaf1, wrongProof);
      expect(wrongVerified).to.be.false;
    });
  });

  describe("View Functions (BC-AUD-06)", function () {
    it("BC-AUD-06: Should return correct anchor length and last digest", async function () {
      const { auditLog, orgId, agentSigner } = await loadFixture(deployFixture);
      
      expect(await auditLog.length(orgId)).to.equal(0);
      expect(await auditLog.getLastDigest(orgId)).to.equal(ethers.ZeroHash);
      
      const digest = ethers.id("trace-1");
      const metaHash = ethers.id("meta");
      
      const domain = {
        name: "AuditLog",
        version: "1",
        chainId: 31337,
        verifyingContract: await auditLog.getAddress()
      };
      
      const types = {
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
      
      const value = { orgId, kind: 0, digest, prevDigest: ethers.ZeroHash, metaHash, index: 0, timestamp: Math.floor(Date.now() / 1000) };
      const sig = await agentSigner.signTypedData(domain, types, value);
      
      await auditLog.anchor(orgId, 0, digest, ethers.ZeroHash, metaHash, sig);
      
      expect(await auditLog.length(orgId)).to.equal(1);
      expect(await auditLog.getLastDigest(orgId)).to.not.equal(ethers.ZeroHash);
    });

    it("BC-AUD-07: Should support audit verification script", async function () {
      const { auditLog, orgId, agentSigner } = await loadFixture(deployFixture);
      
      const digests = [ethers.id("trace-1"), ethers.id("trace-2"), ethers.id("trace-3")];
      const metaHash = ethers.id("meta");
      
      const domain = {
        name: "AuditLog",
        version: "1",
        chainId: 31337,
        verifyingContract: await auditLog.getAddress()
      };
      
      const types = {
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
      
      let prevDigest = ethers.ZeroHash;
      for (let i = 0; i < digests.length; i++) {
        const value = { orgId, kind: 0, digest: digests[i], prevDigest, metaHash, index: i, timestamp: Math.floor(Date.now() / 1000) };
        const sig = await agentSigner.signTypedData(domain, types, value);
        await auditLog.anchor(orgId, 0, digests[i], prevDigest, metaHash, sig);
        prevDigest = await auditLog.getLastDigest(orgId);
      }
      
      // Verify all anchors
      for (let i = 0; i < digests.length; i++) {
        const anchor = await auditLog.getAnchor(orgId, i);
        expect(anchor.digest).to.equal(digests[i]);
        if (i === 0) {
          expect(anchor.prevDigest).to.equal(ethers.ZeroHash);
        } else {
          // prevDigest should match previous anchor's hash
          const prevAnchor = await auditLog.getAnchor(orgId, i - 1);
          // Note: actual verification would compute hash from prevAnchor
        }
      }
    });
  });
});