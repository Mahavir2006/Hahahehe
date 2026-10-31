import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { FirmwareRegistry } from "../typechain-types";

describe("FirmwareRegistry", function () {
  async function deployFixture() {
    const [deployer, vendor1, vendor2, stranger] = await ethers.getSigners();
    
    const FirmwareRegistry = await ethers.getContractFactory("FirmwareRegistry");
    const firmwareRegistry = await FirmwareRegistry.deploy();
    await firmwareRegistry.waitForDeployment();
    
    // Grant vendor roles via addVendor (which sets vendorAddressToId)
    const vendorId1 = ethers.id("vendor-1");
    const vendorId2 = ethers.id("vendor-2");
    await firmwareRegistry.addVendor(vendorId1, vendor1.address);
    await firmwareRegistry.addVendor(vendorId2, vendor2.address);
    
    return { 
      firmwareRegistry, 
      deployer, 
      vendor1, 
      vendor2, 
      stranger 
    };
  }

  describe("Vendor Management (BC-FW-01, BC-FW-02)", function () {
    it("BC-FW-02: Should allow registry admin to add vendor", async function () {
      const { firmwareRegistry, deployer, stranger } = await loadFixture(deployFixture);
      
      const vendorId = ethers.id("new-vendor");
      await firmwareRegistry.addVendor(vendorId, stranger.address);
      
      expect(await firmwareRegistry.isVendor(stranger.address)).to.be.true;
    });

    it("BC-FW-02: Should revert if non-admin tries to add vendor", async function () {
      const { firmwareRegistry, vendor1, stranger } = await loadFixture(deployFixture);
      
      const vendorId = ethers.id("new-vendor");
      await expect(firmwareRegistry.connect(vendor1).addVendor(vendorId, stranger.address))
        .to.be.revertedWithCustomError(firmwareRegistry, "OnlyRegistryAdmin");
    });
  });

  describe("Firmware Publishing (BC-FW-01)", function () {
    it("BC-FW-01: Should allow vendor to publish firmware", async function () {
      const { firmwareRegistry, vendor1 } = await loadFixture(deployFixture);
      
      const vendorId = ethers.id("vendor-1");
      const modelHash = ethers.id("model-1");
      const versionHash = ethers.id("v1.0.0");
      const firmwareSha256 = ethers.id("firmware-bytes-1");
      const sbomHash = ethers.id("sbom-1");
      const releaseTimestamp = Math.floor(Date.now() / 1000);
      
      await expect(firmwareRegistry.connect(vendor1).publishFirmware(
        vendorId, modelHash, versionHash, firmwareSha256, sbomHash, releaseTimestamp
      )).to.emit(firmwareRegistry, "FirmwarePublished");
      
      const entry = await firmwareRegistry.getFirmwareEntry(vendorId, modelHash, versionHash);
      expect(entry.vendorId).to.equal(vendorId);
      expect(entry.modelHash).to.equal(modelHash);
      expect(entry.versionHash).to.equal(versionHash);
      expect(entry.firmwareSha256).to.equal(firmwareSha256);
      expect(entry.sbomHash).to.equal(sbomHash);
      expect(entry.revoked).to.be.false;
      expect(entry.publisher).to.equal(vendor1.address);
    });

    it("BC-FW-01: Should revert if vendor publishes for another vendor", async function () {
      const { firmwareRegistry, vendor1, vendor2 } = await loadFixture(deployFixture);
      
      const vendorId1 = ethers.id("vendor-1");
      const vendorId2 = ethers.id("vendor-2");
      const modelHash = ethers.id("model-1");
      const versionHash = ethers.id("v1.0.0");
      const firmwareSha256 = ethers.id("firmware-bytes-1");
      const sbomHash = ethers.id("sbom-1");
      const releaseTimestamp = Math.floor(Date.now() / 1000);
      
      // vendor1 tries to publish for vendorId2
      await expect(firmwareRegistry.connect(vendor1).publishFirmware(
        vendorId2, modelHash, versionHash, firmwareSha256, sbomHash, releaseTimestamp
      )).to.be.revertedWithCustomError(firmwareRegistry, "VendorNotAuthorized");
    });

    it("BC-FW-01: Should revert if firmware already published", async function () {
      const { firmwareRegistry, vendor1 } = await loadFixture(deployFixture);
      
      const vendorId = ethers.id("vendor-1");
      const modelHash = ethers.id("model-1");
      const versionHash = ethers.id("v1.0.0");
      const firmwareSha256 = ethers.id("firmware-bytes-1");
      const sbomHash = ethers.id("sbom-1");
      const releaseTimestamp = Math.floor(Date.now() / 1000);
      
      await firmwareRegistry.connect(vendor1).publishFirmware(
        vendorId, modelHash, versionHash, firmwareSha256, sbomHash, releaseTimestamp
      );
      
      await expect(firmwareRegistry.connect(vendor1).publishFirmware(
        vendorId, modelHash, versionHash, firmwareSha256, sbomHash, releaseTimestamp
      )).to.be.revertedWithCustomError(firmwareRegistry, "FirmwareAlreadyPublished");
    });
  });

  describe("Firmware Revocation (BC-FW-04)", function () {
    it("BC-FW-04: Should allow vendor to revoke firmware", async function () {
      const { firmwareRegistry, vendor1 } = await loadFixture(deployFixture);
      
      const vendorId = ethers.id("vendor-1");
      const modelHash = ethers.id("model-1");
      const versionHash = ethers.id("v1.0.0");
      const firmwareSha256 = ethers.id("firmware-bytes-1");
      const sbomHash = ethers.id("sbom-1");
      const releaseTimestamp = Math.floor(Date.now() / 1000);
      
      await firmwareRegistry.connect(vendor1).publishFirmware(
        vendorId, modelHash, versionHash, firmwareSha256, sbomHash, releaseTimestamp
      );
      
      await expect(firmwareRegistry.connect(vendor1).revokeFirmware(
        vendorId, modelHash, versionHash, 1 // security reason
      )).to.emit(firmwareRegistry, "FirmwareRevoked");
      
      const entry = await firmwareRegistry.getFirmwareEntry(vendorId, modelHash, versionHash);
      expect(entry.revoked).to.be.true;
      expect(entry.revocationReason).to.equal(1);
    });

    it("BC-FW-04: Should revert if non-publisher tries to revoke", async function () {
      const { firmwareRegistry, vendor1, vendor2 } = await loadFixture(deployFixture);
      
      const vendorId = ethers.id("vendor-1");
      const modelHash = ethers.id("model-1");
      const versionHash = ethers.id("v1.0.0");
      const firmwareSha256 = ethers.id("firmware-bytes-1");
      const sbomHash = ethers.id("sbom-1");
      const releaseTimestamp = Math.floor(Date.now() / 1000);
      
      await firmwareRegistry.connect(vendor1).publishFirmware(
        vendorId, modelHash, versionHash, firmwareSha256, sbomHash, releaseTimestamp
      );
      
      await expect(firmwareRegistry.connect(vendor2).revokeFirmware(
        vendorId, modelHash, versionHash, 1
      )).to.be.revertedWithCustomError(firmwareRegistry, "VendorNotAuthorized");
    });
  });

  describe("Verification (BC-FW-03, BC-FW-07)", function () {
    it("BC-FW-03: Should return Match for correct firmware", async function () {
      const { firmwareRegistry, vendor1 } = await loadFixture(deployFixture);
      
      const vendorId = ethers.id("vendor-1");
      const modelHash = ethers.id("model-1");
      const versionHash = ethers.id("v1.0.0");
      const firmwareSha256 = ethers.id("firmware-bytes-1");
      const sbomHash = ethers.id("sbom-1");
      const releaseTimestamp = Math.floor(Date.now() / 1000);
      
      await firmwareRegistry.connect(vendor1).publishFirmware(
        vendorId, modelHash, versionHash, firmwareSha256, sbomHash, releaseTimestamp
      );
      
      const result = await firmwareRegistry.verifyFirmware(vendorId, modelHash, versionHash, firmwareSha256);
      expect(result).to.equal(0); // Match
    });

    it("BC-FW-03: Should return Mismatch for incorrect firmware", async function () {
      const { firmwareRegistry, vendor1 } = await loadFixture(deployFixture);
      
      const vendorId = ethers.id("vendor-1");
      const modelHash = ethers.id("model-1");
      const versionHash = ethers.id("v1.0.0");
      const firmwareSha256 = ethers.id("firmware-bytes-1");
      const sbomHash = ethers.id("sbom-1");
      const releaseTimestamp = Math.floor(Date.now() / 1000);
      
      await firmwareRegistry.connect(vendor1).publishFirmware(
        vendorId, modelHash, versionHash, firmwareSha256, sbomHash, releaseTimestamp
      );
      
      const wrongSha = ethers.id("wrong-firmware");
      const result = await firmwareRegistry.verifyFirmware(vendorId, modelHash, versionHash, wrongSha);
      expect(result).to.equal(1); // Mismatch
    });

    it("BC-FW-03: Should return Unknown for unpublished firmware", async function () {
      const { firmwareRegistry } = await loadFixture(deployFixture);
      
      const result = await firmwareRegistry.verifyFirmware(
        ethers.id("unknown"), ethers.id("unknown"), ethers.id("unknown"), ethers.id("unknown")
      );
      expect(result).to.equal(2); // Unknown
    });

    it("BC-FW-03: Should return Revoked for revoked firmware", async function () {
      const { firmwareRegistry, vendor1 } = await loadFixture(deployFixture);
      
      const vendorId = ethers.id("vendor-1");
      const modelHash = ethers.id("model-1");
      const versionHash = ethers.id("v1.0.0");
      const firmwareSha256 = ethers.id("firmware-bytes-1");
      const sbomHash = ethers.id("sbom-1");
      const releaseTimestamp = Math.floor(Date.now() / 1000);
      
      await firmwareRegistry.connect(vendor1).publishFirmware(
        vendorId, modelHash, versionHash, firmwareSha256, sbomHash, releaseTimestamp
      );
      await firmwareRegistry.connect(vendor1).revokeFirmware(vendorId, modelHash, versionHash, 1);
      
      const result = await firmwareRegistry.verifyFirmware(vendorId, modelHash, versionHash, firmwareSha256);
      expect(result).to.equal(3); // Revoked
    });

    it("BC-FW-07: Should verify multiple firmwares in batch", async function () {
      const { firmwareRegistry, vendor1, vendor2 } = await loadFixture(deployFixture);
      
      const vendorId1 = ethers.id("vendor-1");
      const modelHash1 = ethers.id("model-1");
      const versionHash1 = ethers.id("v1.0.0");
      const firmwareSha1 = ethers.id("firmware-1");
      const sbomHash1 = ethers.id("sbom-1");
      
      const vendorId2 = ethers.id("vendor-2");
      const modelHash2 = ethers.id("model-2");
      const versionHash2 = ethers.id("v2.0.0");
      const firmwareSha2 = ethers.id("firmware-2");
      const sbomHash2 = ethers.id("sbom-2");
      
      const releaseTimestamp = Math.floor(Date.now() / 1000);
      
      await firmwareRegistry.connect(vendor1).publishFirmware(vendorId1, modelHash1, versionHash1, firmwareSha1, sbomHash1, releaseTimestamp);
      await firmwareRegistry.connect(vendor2).publishFirmware(vendorId2, modelHash2, versionHash2, firmwareSha2, sbomHash2, releaseTimestamp);
      
      const results = await firmwareRegistry.verifyMany(
        [vendorId1, vendorId2],
        [modelHash1, modelHash2],
        [versionHash1, versionHash2],
        [firmwareSha1, firmwareSha2]
      );
      
      expect(results.length).to.equal(2);
      expect(results[0]).to.equal(0); // Match
      expect(results[1]).to.equal(0); // Match
    });

    it("BC-FW-07: Should revert on batch size > 100", async function () {
      const { firmwareRegistry } = await loadFixture(deployFixture);
      
      const largeArray = new Array(101).fill(ethers.ZeroHash);
      
      await expect(firmwareRegistry.verifyMany(largeArray, largeArray, largeArray, largeArray))
        .to.be.revertedWithCustomError(firmwareRegistry, "InvalidBatchSize");
    });
  });
});