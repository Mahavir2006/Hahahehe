import { expect } from "chai";
import { ethers } from "hardhat";
import { deploySystem, ORG, KIND, IMPACT, STATUS, submitRisk, submitFinding, confirmEdge, anchorCritic, futureTs, submitDep, publishAlert, bandCommitment } from "./helpers";

describe("Integration: full CascadeShield flow", function () {
  it("BC-ENV-03 INT-01 register -> bilateral edges -> risk -> alert -> HIGH approval -> execute -> audit verifies -> firmware mismatch", async function () {
    const sys = await deploySystem();
    const P = ethers.id("power-substation-7");
    const W = ethers.id("water-pumping");
    const H = ethers.id("hospital-water");

    // wiring is correct after deployment (BC-ENV-03)
    expect(await sys.gate.orgRegistry()).to.equal(await sys.orgRegistry.getAddress());
    expect(await sys.gate.auditLog()).to.equal(await sys.auditLog.getAddress());
    expect(await sys.alertBus.attestationRegistry()).to.equal(await sys.attestation.getAddress());
    expect(await sys.auditLog.orgRegistry()).to.equal(await sys.orgRegistry.getAddress());

    // 1. bilateral dependency attestations power -> water -> hospital
    await confirmEdge(sys, "water", "power", W, P);
    await confirmEdge(sys, "hospital", "water", H, W);
    expect(await sys.attestation.isEdgeConfirmed(ORG.water, W, ORG.power, P)).to.equal(true);
    expect(await sys.attestation.isEdgeConfirmed(ORG.hospital, H, ORG.water, W)).to.equal(true);
    // 1b. a one-sided edge stays unconfirmed
    await submitDep(sys.attestation, sys.people.hospital.agent, {
      consumerOrg: ORG.hospital, consumerServiceHash: ethers.id("hospital-backup"), providerOrg: ORG.power, providerServiceHash: P,
      strength: 2, tolerance: 0, expiry: await futureTs(100000),
    });
    expect(await sys.attestation.isEdgeConfirmed(ORG.hospital, ethers.id("hospital-backup"), ORG.power, P)).to.equal(false);

    // 2. finding + risk attestation
    await submitFinding(sys.attestation, sys.people.power.agent, ORG.power, ethers.id("ADV-1"), ethers.id("CVE-2024-0001"), await futureTs(0), true);
    await submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P, 3, 3, await futureTs(100000));
    expect((await sys.attestation.getLatestRiskAttestation(ORG.power, P)).bandCommitment).to.equal(bandCommitment(3, 3));

    // 3. cascade alert reaches the downstream orgs through confirmed edges
    await publishAlert(sys.alertBus, sys.people.power.agent, ORG.power, P, 3, 1, await futureTs(3600), ethers.id("evidence"));
    const waterAlerts = await sys.alertBus.affectedBy(ORG.water, W);
    expect(waterAlerts.length).to.equal(1);
    await sys.alertBus.connect(sys.people.water.agent).acknowledge(waterAlerts[0], ORG.water, W);
    await publishAlert(sys.alertBus, sys.people.water.agent, ORG.water, W, 3, 1, await futureTs(3600), ethers.id("evidence2"));
    expect((await sys.alertBus.affectedBy(ORG.hospital, H)).length).to.equal(1);
    // the hospital is not directly affected by the power alert (its backup edge is unconfirmed)
    expect((await sys.alertBus.affectedBy(ORG.hospital, ethers.id("hospital-backup"))).length).to.equal(0);

    // 4. critic verdict anchored, then HIGH approval requested
    const verdict = await anchorCritic(sys, "power", "integration");
    const planHash = ethers.id("plan-integration");
    const tx = await sys.gate.connect(sys.people.power.agent).requestApproval(ORG.power, planHash, ethers.id("steps"), IMPACT.High, await futureTs(3600), verdict);
    const rc = await tx.wait();
    const reqId = rc.logs.map((l: any) => { try { return sys.gate.interface.parseLog(l); } catch { return null; } }).find((e: any) => e?.name === "ApprovalRequested").args.requestId;

    // 4b. the agent cannot approve or execute early
    await expect(sys.gate.connect(sys.people.power.agent).approve(reqId)).to.be.revertedWithCustomError(sys.gate, "AgentCannotVote");
    await expect(sys.gate.connect(sys.people.power.agent).markExecuted(reqId, ethers.id("early"))).to.be.revertedWithCustomError(sys.gate, "InvalidState");

    // 5. humans approve (incl. safety officer), then the agent executes
    await sys.gate.connect(sys.people.power.approvers[0]).approve(reqId);
    await sys.gate.connect(sys.people.power.approvers[1]).approve(reqId);
    expect(await sys.gate.status(reqId)).to.equal(STATUS.Approved);
    expect(await sys.gate.planHashOf(reqId)).to.equal(planHash);
    const execDigest = ethers.id("execution-record");
    await sys.gate.connect(sys.people.power.agent).markExecuted(reqId, execDigest);
    expect(await sys.gate.status(reqId)).to.equal(STATUS.Executed);

    // 6. anchor the execution and verify the whole audit chain
    await sys.auditLog.connect(sys.people.power.agent).anchor(ORG.power, KIND.Execution, execDigest, await sys.auditLog.lastDigest(ORG.power), ethers.ZeroHash);
    expect(await sys.auditLog.verifyChain(ORG.power, 100)).to.equal(true);
    expect(await sys.auditLog.length(ORG.power)).to.equal(2);

    // 7. firmware: a tampered image is detected
    const vendorId = ethers.id("acme");
    await sys.firmware.addVendor(vendorId, sys.vendor.address);
    const model = ethers.id("RTU-9");
    const ver = ethers.id("1.2.0");
    const good = ethers.id("good-image");
    await sys.firmware.connect(sys.vendor).publishFirmware(vendorId, model, ver, good, ethers.id("sbom"), 1700000000);
    expect(await sys.firmware.verifyFirmware(vendorId, model, ver, good)).to.equal(0); // Match
    expect(await sys.firmware.verifyFirmware(vendorId, model, ver, ethers.id("tampered"))).to.equal(1); // Mismatch
    expect(await sys.firmware.verifyFirmware(vendorId, model, ethers.id("9.9"), good)).to.equal(2); // Unknown
    await sys.firmware.connect(sys.vendor).revokeFirmware(vendorId, model, ver, 1);
    expect(await sys.firmware.verifyFirmware(vendorId, model, ver, good)).to.equal(3); // Revoked
  });

  it("BC-SEC-02 INT-01 an attacker holding only the agent key cannot complete a HIGH action", async function () {
    const sys = await deploySystem();
    const verdict = await anchorCritic(sys, "hospital", "x");
    const tx = await sys.gate.connect(sys.people.hospital.agent).requestApproval(ORG.hospital, ethers.id("isolate-icu"), ethers.id("s"), IMPACT.High, await futureTs(3600), verdict);
    const rc = await tx.wait();
    const id = rc.logs.map((l: any) => { try { return sys.gate.interface.parseLog(l); } catch { return null; } }).find((e: any) => e?.name === "ApprovalRequested").args.requestId;
    const g = sys.gate.connect(sys.people.hospital.agent);
    await expect(g.approve(id)).to.be.reverted;
    await expect(g.reject(id)).to.be.reverted;
    await expect(g.markExecuted(id, ethers.id("e"))).to.be.reverted;
    await expect(g.approveWithSigs(id, [sys.people.hospital.agent.address], ["0x" + "00".repeat(65)])).to.be.reverted;
    expect(await sys.gate.status(id)).to.equal(STATUS.Pending);
  });

  it("BC-ENV-06 gas ceiling: key functions stay under 500k gas", async function () {
    const sys = await deploySystem();
    const verdict = await anchorCritic(sys, "power", "gas");
    const tx = await sys.gate.connect(sys.people.power.agent).requestApproval(ORG.power, ethers.id("p"), ethers.id("s"), IMPACT.High, await futureTs(3600), verdict);
    expect((await tx.wait())!.gasUsed).to.be.lt(500000n);
    const t2 = await submitRisk(sys.attestation, sys.people.power.agent, ORG.power, ethers.id("svc"), 3, 3, await futureTs(1000));
    expect((await t2.wait())!.gasUsed).to.be.lt(500000n);
    const t3 = await publishAlert(sys.alertBus, sys.people.power.agent, ORG.power, ethers.id("svc"), 3, 1, await futureTs(1000), ethers.id("e"));
    expect((await t3.wait())!.gasUsed).to.be.lt(500000n);
    const t4 = await sys.auditLog.connect(sys.people.power.agent).anchor(ORG.power, KIND.Plan, ethers.id("d"), await sys.auditLog.lastDigest(ORG.power), ethers.ZeroHash);
    expect((await t4.wait())!.gasUsed).to.be.lt(500000n);
  });
});
