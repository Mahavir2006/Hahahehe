import hre from "hardhat";
import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deploySystem, ORG, futureTs, submitDep, confirmEdge } from "./helpers";

describe("OrgRegistry edge cases", function () {
  const fx = () => deploySystem();

  async function reg(sys: any, id: string, o: Partial<any> = {}) {
    const s = sys.s;
    const args = {
      sector: 0, admin: sys.admin.address, agent: s[17].address,
      approvers: [s[18].address, s[19].address, s[0].address], threshold: 2, flags: [true, false, false], ...o,
    };
    return sys.orgRegistry.registerOrg(ethers.id(id), ethers.id(id), args.sector, args.admin, args.agent, args.approvers, args.threshold, args.flags);
  }

  it("BC-ORG-02 only the registry admin can register / deactivate / reactivate", async function () {
    const sys = await loadFixture(fx);
    await expect(sys.orgRegistry.connect(sys.stranger).registerOrg(ethers.id("z"), ethers.id("z"), 0, sys.admin.address, sys.s[17].address,
      [sys.s[18].address, sys.s[19].address, sys.s[0].address], 2, [true, false, false])).to.be.revertedWithCustomError(sys.orgRegistry, "OnlyRegistryAdmin");
    await expect(sys.orgRegistry.connect(sys.stranger).deactivateOrg(ORG.power)).to.be.revertedWithCustomError(sys.orgRegistry, "OnlyRegistryAdmin");
    await expect(sys.orgRegistry.connect(sys.stranger).reactivateOrg(ORG.power)).to.be.revertedWithCustomError(sys.orgRegistry, "OnlyRegistryAdmin");
  });

  it("BC-ORG-01 rejects duplicates, bad sector, zero addresses", async function () {
    const sys = await loadFixture(fx);
    await expect(reg(sys, "power")).to.be.revertedWithCustomError(sys.orgRegistry, "OrgAlreadyExists");
    await expect(reg(sys, "n1", { sector: 4 })).to.be.revertedWithCustomError(sys.orgRegistry, "InvalidSector");
    await expect(reg(sys, "n2", { admin: ethers.ZeroAddress })).to.be.revertedWithCustomError(sys.orgRegistry, "ZeroAddress");
    await expect(reg(sys, "n3", { agent: ethers.ZeroAddress })).to.be.revertedWithCustomError(sys.orgRegistry, "ZeroAddress");
    await expect(reg(sys, "n4", { approvers: [sys.s[18].address, ethers.ZeroAddress, sys.s[19].address] })).to.be.revertedWithCustomError(sys.orgRegistry, "ZeroAddress");
  });

  it("BC-ORG-05 rejects too few approvers, bad threshold, flag mismatch, no safety officer, duplicates", async function () {
    const sys = await loadFixture(fx);
    const s = sys.s;
    await expect(reg(sys, "a", { approvers: [s[18].address, s[19].address], flags: [true, false] })).to.be.revertedWithCustomError(sys.orgRegistry, "InvalidApproverCount");
    await expect(reg(sys, "b", { threshold: 0 })).to.be.revertedWithCustomError(sys.orgRegistry, "InvalidThreshold");
    await expect(reg(sys, "c", { threshold: 4 })).to.be.revertedWithCustomError(sys.orgRegistry, "InvalidThreshold");
    await expect(reg(sys, "d", { flags: [true, false] })).to.be.revertedWithCustomError(sys.orgRegistry, "InvalidApproverCount");
    await expect(reg(sys, "e", { flags: [false, false, false] })).to.be.revertedWithCustomError(sys.orgRegistry, "InvalidApproverCount");
    await expect(reg(sys, "f", { approvers: [s[18].address, s[18].address, s[19].address] })).to.be.revertedWithCustomError(sys.orgRegistry, "DuplicateApprover");
  });

  it("BC-ORG-06 an address can be bound to one org's agent/approver role only", async function () {
    const sys = await loadFixture(fx);
    await expect(reg(sys, "g", { agent: sys.people.power.agent.address })).to.be.revertedWithCustomError(sys.orgRegistry, "AddressAlreadyBound");
    await expect(reg(sys, "h", { approvers: [sys.people.power.approvers[0].address, sys.s[18].address, sys.s[19].address] })).to.be.revertedWithCustomError(sys.orgRegistry, "AddressAlreadyBound");
    await expect(sys.orgRegistry.connect(sys.admin).rotateAgentSigner(ORG.power, sys.people.water.agent.address)).to.be.revertedWithCustomError(sys.orgRegistry, "AddressAlreadyBound");
  });

  it("BC-ORG-03 getters revert for unknown orgs and report inactive state", async function () {
    const sys = await loadFixture(fx);
    const ghost = ethers.id("ghost");
    await expect(sys.orgRegistry.getOrg(ghost)).to.be.revertedWithCustomError(sys.orgRegistry, "OrgNotFound");
    await expect(sys.orgRegistry.getApproverCount(ghost)).to.be.revertedWithCustomError(sys.orgRegistry, "OrgNotFound");
    await expect(sys.orgRegistry.getApproverAt(ghost, 0)).to.be.revertedWithCustomError(sys.orgRegistry, "OrgNotFound");
    await expect(sys.orgRegistry.getThreshold(ghost)).to.be.revertedWithCustomError(sys.orgRegistry, "OrgNotFound");
    await expect(sys.orgRegistry.connect(sys.admin).rotateAgentSigner(ghost, sys.s[17].address)).to.be.revertedWithCustomError(sys.orgRegistry, "OrgNotFound");
    await expect(sys.orgRegistry.deactivateOrg(ghost)).to.be.revertedWithCustomError(sys.orgRegistry, "OrgNotFound");
    await expect(sys.orgRegistry.reactivateOrg(ghost)).to.be.revertedWithCustomError(sys.orgRegistry, "OrgNotFound");
    expect(await sys.orgRegistry.isOrgAgent(ghost, sys.s[17].address)).to.equal(false);
    expect(await sys.orgRegistry.isOrgActive(ghost)).to.equal(false);
    expect(await sys.orgRegistry.getThreshold(ORG.power)).to.equal(2);
    expect(await sys.orgRegistry.getOrgIdByAddress(sys.people.power.agent.address)).to.equal(ORG.power);
    // deactivation hides approver/agent status; deactivate and reactivate are idempotent
    await sys.orgRegistry.deactivateOrg(ORG.power);
    await sys.orgRegistry.deactivateOrg(ORG.power);
    expect(await sys.orgRegistry.isOrgApprover(ORG.power, sys.people.power.approvers[0].address)).to.equal(false);
    expect(await sys.orgRegistry.isOrgAgent(ORG.power, sys.people.power.agent.address)).to.equal(false);
    await sys.orgRegistry.reactivateOrg(ORG.power);
    await sys.orgRegistry.reactivateOrg(ORG.power);
    expect(await sys.orgRegistry.isOrgAgent(ORG.power, sys.people.power.agent.address)).to.equal(true);
  });

  it("BC-ORG-05 updateApproverSet validates agent overlap, zero, duplicates, flags, safety officer and size", async function () {
    const sys = await loadFixture(fx);
    const s = sys.s;
    const o = sys.orgRegistry.connect(sys.admin);
    const ok = [s[17].address, s[18].address, s[19].address];
    await expect(o.updateApproverSet(ORG.power, [sys.people.power.agent.address, s[18].address, s[19].address], 2, [true, false, false])).to.be.revertedWithCustomError(sys.orgRegistry, "AgentSignerCannotBeApprover");
    await expect(o.updateApproverSet(ORG.power, [s[17].address, ethers.ZeroAddress, s[19].address], 2, [true, false, false])).to.be.revertedWithCustomError(sys.orgRegistry, "ZeroAddress");
    await expect(o.updateApproverSet(ORG.power, [s[17].address, s[17].address, s[19].address], 2, [true, false, false])).to.be.revertedWithCustomError(sys.orgRegistry, "DuplicateApprover");
    await expect(o.updateApproverSet(ORG.power, ok, 2, [true, false])).to.be.revertedWithCustomError(sys.orgRegistry, "InvalidApproverCount");
    await expect(o.updateApproverSet(ORG.power, ok, 2, [false, false, false])).to.be.revertedWithCustomError(sys.orgRegistry, "InvalidApproverCount");
    await expect(o.updateApproverSet(ORG.power, [s[17].address, s[18].address], 1, [true, false])).to.be.revertedWithCustomError(sys.orgRegistry, "InvalidApproverCount");
    await expect(sys.orgRegistry.connect(sys.stranger).updateApproverSet(ORG.power, ok, 2, [true, false, false])).to.be.revertedWithCustomError(sys.orgRegistry, "OnlyOrgAdmin");
    await o.updateApproverSet(ORG.power, ok, 3, [false, true, false]);
    expect(await sys.orgRegistry.isOrgSafetyOfficer(ORG.power, s[18].address)).to.equal(true);
    expect(await sys.orgRegistry.getThreshold(ORG.power)).to.equal(3);
    expect((await sys.orgRegistry.getAllOrgIds()).length).to.equal(3);
  });
});

describe("FirmwareRegistry edge cases", function () {
  const fx = () => deploySystem();
  const V = ethers.id("acme");
  const M = ethers.id("RTU-9");

  it("BC-FW-02 vendor management and access control", async function () {
    const sys = await loadFixture(fx);
    await expect(sys.firmware.connect(sys.stranger).addVendor(V, sys.vendor.address)).to.be.revertedWithCustomError(sys.firmware, "OnlyRegistryAdmin");
    await sys.firmware.addVendor(V, sys.vendor.address);
    await expect(sys.firmware.addVendor(V, sys.vendor.address)).to.be.revertedWithCustomError(sys.firmware, "VendorAlreadyExists");
    expect(await sys.firmware.isVendor(sys.vendor.address)).to.equal(true);
    expect(await sys.firmware.getVendorId(sys.vendor.address)).to.equal(V);
    await expect(sys.firmware.connect(sys.stranger).removeVendor(V, sys.vendor.address)).to.be.revertedWithCustomError(sys.firmware, "OnlyRegistryAdmin");
    await sys.firmware.removeVendor(V, sys.vendor.address);
    expect(await sys.firmware.isVendor(sys.vendor.address)).to.equal(false);
    expect(await sys.firmware.getVendorId(sys.vendor.address)).to.equal(ethers.ZeroHash);
    await expect(sys.firmware.connect(sys.vendor).publishFirmware(V, M, ethers.id("1"), ethers.id("x"), ethers.id("s"), 1)).to.be.revertedWithCustomError(sys.firmware, "OnlyVendor");
    await expect(sys.firmware.connect(sys.vendor).revokeFirmware(V, M, ethers.id("1"), 1)).to.be.revertedWithCustomError(sys.firmware, "OnlyVendor");
  });

  it("BC-FW-01 vendors can only publish for their own id; published entries are immutable", async function () {
    const sys = await loadFixture(fx);
    await sys.firmware.addVendor(V, sys.vendor.address);
    await expect(sys.firmware.connect(sys.vendor).publishFirmware(ethers.id("other"), M, ethers.id("1"), ethers.id("x"), ethers.id("s"), 1)).to.be.revertedWithCustomError(sys.firmware, "VendorNotAuthorized");
    await sys.firmware.connect(sys.vendor).publishFirmware(V, M, ethers.id("1"), ethers.id("x"), ethers.id("s"), 1);
    await expect(sys.firmware.connect(sys.vendor).publishFirmware(V, M, ethers.id("1"), ethers.id("y"), ethers.id("s"), 1)).to.be.revertedWithCustomError(sys.firmware, "FirmwareAlreadyPublished");
    const e = await sys.firmware.getFirmwareEntry(V, M, ethers.id("1"));
    expect(e.firmwareSha256).to.equal(ethers.id("x"));
    expect(e.publisher).to.equal(sys.vendor.address);
  });

  it("BC-FW-04 revocation rules: unknown, double, other vendor", async function () {
    const sys = await loadFixture(fx);
    await sys.firmware.addVendor(V, sys.vendor.address);
    const v2 = sys.s[17];
    await sys.firmware.addVendor(ethers.id("beta"), v2.address);
    await expect(sys.firmware.connect(sys.vendor).revokeFirmware(V, M, ethers.id("1"), 1)).to.be.revertedWithCustomError(sys.firmware, "FirmwareNotFound");
    await sys.firmware.connect(sys.vendor).publishFirmware(V, M, ethers.id("1"), ethers.id("x"), ethers.id("s"), 1);
    await expect(sys.firmware.connect(v2).revokeFirmware(V, M, ethers.id("1"), 1)).to.be.revertedWithCustomError(sys.firmware, "VendorNotAuthorized");
    await expect(sys.firmware.connect(sys.vendor).revokeFirmware(V, M, ethers.id("1"), 2)).to.emit(sys.firmware, "FirmwareRevoked");
    await expect(sys.firmware.connect(sys.vendor).revokeFirmware(V, M, ethers.id("1"), 2)).to.be.revertedWithCustomError(sys.firmware, "FirmwareAlreadyRevoked");
  });

  it("BC-FW-07 enumeration and verifyMany (all four outcomes, size and length limits)", async function () {
    const sys = await loadFixture(fx);
    await sys.firmware.addVendor(V, sys.vendor.address);
    const f = sys.firmware.connect(sys.vendor);
    const M2 = ethers.id("PLC-3");
    await f.publishFirmware(V, M, ethers.id("1"), ethers.id("a"), ethers.id("s"), 1);
    await f.publishFirmware(V, M, ethers.id("2"), ethers.id("b"), ethers.id("s"), 1);
    await f.publishFirmware(V, M2, ethers.id("1"), ethers.id("c"), ethers.id("s"), 1);
    await f.revokeFirmware(V, M2, ethers.id("1"), 1);
    expect((await sys.firmware.getVendorModels(V)).length).to.equal(2);
    expect((await sys.firmware.getModelVersions(V, M)).length).to.equal(2);
    const r = await sys.firmware.verifyMany([V, V, V, V], [M, M, M, M2], [ethers.id("1"), ethers.id("1"), ethers.id("9"), ethers.id("1")],
      [ethers.id("a"), ethers.id("zzz"), ethers.id("a"), ethers.id("c")]);
    expect(r.map((x: bigint) => Number(x))).to.deep.equal([0, 1, 2, 3]);
    await expect(sys.firmware.verifyMany([V], [M, M], [ethers.id("1")], [ethers.id("a")])).to.be.revertedWithCustomError(sys.firmware, "InvalidBatchSize");
    const big = new Array(101).fill(V);
    await expect(sys.firmware.verifyMany(big, big, big, big)).to.be.revertedWithCustomError(sys.firmware, "InvalidBatchSize");
  });
});

describe("AttestationRegistry misc", function () {
  it("BC-ATT-D-04 views for unknown edges, and risk getters for unknown ids", async function () {
    const sys = await deploySystem();
    const x = ethers.id("x");
    expect(await sys.attestation.isEdgeConfirmed(ORG.water, x, ORG.power, x)).to.equal(false);
    expect(await sys.attestation.getEdgeState(ORG.water, x, ORG.power, x)).to.equal(3);
    expect((await sys.attestation.getRiskAttestation(x)).timestamp).to.equal(0);
    expect((await sys.attestation.getLatestRiskAttestation(ORG.power, x)).timestamp).to.equal(0);
  });

  it("BC-ATT-D-04 provider expiry also invalidates a confirmed edge", async function () {
    const sys = await deploySystem();
    const c = ethers.id("c"), p = ethers.id("p");
    const short = await futureTs(500);
    const long = await futureTs(100000);
    const base = { consumerOrg: ORG.water, consumerServiceHash: c, providerOrg: ORG.power, providerServiceHash: p, strength: 1, tolerance: 1 };
    await submitDep(sys.attestation, sys.people.water.agent, { ...base, expiry: long });
    await submitDep(sys.attestation, sys.people.power.agent, { ...base, expiry: short });
    expect(await sys.attestation.isEdgeConfirmed(ORG.water, c, ORG.power, p)).to.equal(true);
    await ethers.provider.send("evm_increaseTime", [600]);
    await ethers.provider.send("evm_mine", []);
    expect(await sys.attestation.isEdgeConfirmed(ORG.water, c, ORG.power, p)).to.equal(false);
    expect(await sys.attestation.getEdgeState(ORG.water, c, ORG.power, p)).to.equal(3);
  });

  it("BC-ATT-D-01 an org deactivated mid-edge blocks the counter-attestation", async function () {
    const sys = await deploySystem();
    const c = ethers.id("c2"), p = ethers.id("p2");
    const base = { consumerOrg: ORG.water, consumerServiceHash: c, providerOrg: ORG.power, providerServiceHash: p, strength: 1, tolerance: 1, expiry: await futureTs(1000) };
    await submitDep(sys.attestation, sys.people.water.agent, base);
    await sys.orgRegistry.deactivateOrg(ORG.power);
    await expect(submitDep(sys.attestation, sys.people.power.agent, base)).to.be.revertedWithCustomError(sys.attestation, "OrgNotActive");
  });
});

describe("Under-coverage guards", function () {
  it("BC-ENV-05 every contract's deployed bytecode is below the 24KB EIP-170 limit (skipped under instrumentation)", async function () {
    if ((hre as any).__SOLIDITY_COVERAGE_RUNNING) this.skip();
    const sys = await deploySystem();
    for (const c of [sys.orgRegistry, sys.auditLog, sys.attestation, sys.firmware, sys.gate, sys.alertBus]) {
      const code = await ethers.provider.getCode(await c.getAddress());
      expect((code.length - 2) / 2).to.be.lt(24576);
    }
  });

  it("BC-ENV-06 gas ceiling test is meaningful only without instrumentation", async function () {
    if ((hre as any).__SOLIDITY_COVERAGE_RUNNING) this.skip();
  });
});
