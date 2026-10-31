import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { deploySystem, ORG, futureTs, confirmEdge, submitDep } from "./helpers";

const P_SVC = ethers.id("power-substation-7");
const W_SVC = ethers.id("water-pumping");
const H_SVC = ethers.id("hospital-water");

describe("AlertBus", function () {
  const fx = async () => {
    const sys = await deploySystem();
    // water depends on power (consumer=water, provider=power); hospital depends on water
    await confirmEdge(sys, "water", "power", W_SVC, P_SVC);
    await confirmEdge(sys, "hospital", "water", H_SVC, W_SVC);
    return sys;
  };

  async function publish(sys: any, severity = 3, tti = 1, ttl = 3600, svc = P_SVC, org: "power" | "water" | "hospital" = "power") {
    const tx = await sys.alertBus.connect(sys.people[org].agent).publish(ORG[org], svc, severity, tti, ethers.id("ev"), await futureTs(ttl));
    const rc = await tx.wait();
    const ev = rc.logs.map((l: any) => { try { return sys.alertBus.interface.parseLog(l); } catch { return null; } }).find((e: any) => e && (e.name === "CascadeAlert" || e.name === "AlertDeduplicated"));
    return ev.args.alertId as string;
  }

  describe("publish", function () {
    it("BC-ALERT-01 an org agent can publish an alert and CascadeAlert is emitted", async function () {
      const sys = await loadFixture(fx);
      await expect(sys.alertBus.connect(sys.people.power.agent).publish(ORG.power, P_SVC, 3, 1, ethers.id("ev"), await futureTs(3600)))
        .to.emit(sys.alertBus, "CascadeAlert");
      expect(await sys.alertBus.alertCount()).to.equal(1);
    });

    it("BC-ALERT-01 only that org's agent can publish for it", async function () {
      const sys = await loadFixture(fx);
      for (const who of [sys.stranger, sys.people.water.agent, sys.people.power.approvers[0]]) {
        await expect(sys.alertBus.connect(who).publish(ORG.power, P_SVC, 3, 1, ethers.id("ev"), await futureTs(3600)))
          .to.be.revertedWithCustomError(sys.alertBus, "NotOrgAgent");
      }
    });

    it("BC-ALERT-04 validates severity, tti and expiry", async function () {
      const sys = await loadFixture(fx);
      const a = sys.alertBus.connect(sys.people.power.agent);
      await expect(a.publish(ORG.power, P_SVC, 4, 1, ethers.id("ev"), await futureTs(60))).to.be.revertedWithCustomError(sys.alertBus, "InvalidSeverity");
      await expect(a.publish(ORG.power, P_SVC, 1, 4, ethers.id("ev"), await futureTs(60))).to.be.revertedWithCustomError(sys.alertBus, "InvalidTti");
      await expect(a.publish(ORG.power, P_SVC, 1, 1, ethers.id("ev"), (await futureTs(0)) - 1)).to.be.revertedWithCustomError(sys.alertBus, "InvalidExpiry");
    });

    it("BC-ALERT-04 identical active alerts inside the de-dupe window collapse to one", async function () {
      const sys = await loadFixture(fx);
      const id1 = await publish(sys, 3);
      const id2 = await publish(sys, 3);
      expect(id2).to.equal(id1);
      expect(await sys.alertBus.alertCount()).to.equal(1);
      // different severity is a different alert
      const id3 = await publish(sys, 2);
      expect(id3).to.not.equal(id1);
      expect(await sys.alertBus.alertCount()).to.equal(2);
      // after the window passes, a new alert is created
      await time.increase(301);
      const id4 = await publish(sys, 3);
      expect(id4).to.not.equal(id1);
    });

    it("BC-ALERT-06 rate-limits an org's alert spam, per org", async function () {
      const sys = await loadFixture(fx);
      for (let i = 0; i < 30; i++) await publish(sys, 3, 1, 3600, ethers.id("svc" + i));
      await expect(sys.alertBus.connect(sys.people.power.agent).publish(ORG.power, ethers.id("svc-over"), 3, 1, ethers.id("ev"), await futureTs(3600)))
        .to.be.revertedWithCustomError(sys.alertBus, "RateLimitExceeded");
      // other orgs are unaffected; the window resets after an hour
      await publish(sys, 3, 1, 3600, W_SVC, "water");
      await time.increase(3601);
      await publish(sys, 3, 1, 3600, ethers.id("svc-after"));
    });

    it("BC-ALERT-01 deactivated orgs cannot publish", async function () {
      const sys = await loadFixture(fx);
      await sys.orgRegistry.deactivateOrg(ORG.power);
      await expect(sys.alertBus.connect(sys.people.power.agent).publish(ORG.power, P_SVC, 3, 1, ethers.id("ev"), await futureTs(60)))
        .to.be.revertedWithCustomError(sys.alertBus, "NotOrgAgent");
    });
  });

  describe("affectedBy (BC-ALERT-02)", function () {
    it("BC-ALERT-02 returns alerts only for consumers with a CONFIRMED edge", async function () {
      const sys = await loadFixture(fx);
      const id = await publish(sys);
      const water = await sys.alertBus.affectedBy(ORG.water, W_SVC);
      expect(water).to.deep.equal([id]);
      // hospital depends on water, not on power -> not directly affected by a power alert
      expect(await sys.alertBus.affectedBy(ORG.hospital, H_SVC)).to.deep.equal([]);
      // unrelated service of a related org
      expect(await sys.alertBus.affectedBy(ORG.water, ethers.id("other-svc"))).to.deep.equal([]);
      // power itself is a provider, not a consumer
      expect(await sys.alertBus.affectedBy(ORG.power, P_SVC)).to.deep.equal([]);
    });

    it("BC-ALERT-02 chains: a water alert affects the hospital service", async function () {
      const sys = await loadFixture(fx);
      const id = await publish(sys, 3, 1, 3600, W_SVC, "water");
      expect(await sys.alertBus.affectedBy(ORG.hospital, H_SVC)).to.deep.equal([id]);
    });

    it("BC-ALERT-02 alerts for an UNCONFIRMED edge are stored but never returned", async function () {
      const sys = await loadFixture(fx);
      // hospital attests it depends on power, power never attests back
      const expiry = await futureTs(100000);
      await submitDep(sys.attestation, sys.people.hospital.agent, {
        consumerOrg: ORG.hospital, consumerServiceHash: H_SVC, providerOrg: ORG.power, providerServiceHash: P_SVC, strength: 2, tolerance: 1, expiry,
      });
      await publish(sys);
      expect(await sys.alertBus.affectedBy(ORG.hospital, H_SVC)).to.deep.equal([]);
      expect(await sys.alertBus.alertCount()).to.equal(1);
    });

    it("BC-ALERT-02 excludes resolved and expired alerts and revoked edges", async function () {
      const sys = await loadFixture(fx);
      const id = await publish(sys, 3, 1, 600);
      expect((await sys.alertBus.affectedBy(ORG.water, W_SVC)).length).to.equal(1);
      await sys.alertBus.connect(sys.people.power.agent).resolve(id);
      expect(await sys.alertBus.affectedBy(ORG.water, W_SVC)).to.deep.equal([]);

      const id2 = await publish(sys, 2, 1, 600);
      expect((await sys.alertBus.affectedBy(ORG.water, W_SVC)).length).to.equal(1);
      await time.increase(700);
      expect(await sys.alertBus.affectedBy(ORG.water, W_SVC)).to.deep.equal([]);
      expect(await sys.alertBus.isActive(id2)).to.equal(false);

      await publish(sys, 1, 1, 3600);
      await sys.attestation.connect(sys.people.water.agent).revokeDependencyAttestation(ORG.water, W_SVC, ORG.power, P_SVC);
      expect(await sys.alertBus.affectedBy(ORG.water, W_SVC)).to.deep.equal([]);
    });
  });

  describe("acknowledge", function () {
    it("BC-ALERT-03 an affected consumer acknowledges once; timestamp recorded", async function () {
      const sys = await loadFixture(fx);
      const id = await publish(sys);
      await expect(sys.alertBus.connect(sys.people.water.agent).acknowledge(id, ORG.water, W_SVC)).to.emit(sys.alertBus, "AlertAcknowledged");
      expect(await sys.alertBus.acknowledgedAt(id, ORG.water)).to.be.gt(0);
      await expect(sys.alertBus.connect(sys.people.water.agent).acknowledge(id, ORG.water, W_SVC))
        .to.be.revertedWithCustomError(sys.alertBus, "AlreadyAcknowledged");
    });

    it("BC-ALERT-03 an unrelated org (no confirmed edge) cannot acknowledge", async function () {
      const sys = await loadFixture(fx);
      const id = await publish(sys);
      await expect(sys.alertBus.connect(sys.people.hospital.agent).acknowledge(id, ORG.hospital, H_SVC))
        .to.be.revertedWithCustomError(sys.alertBus, "NotAffected");
    });

    it("BC-ALERT-03 wrong sender, unknown alert, resolved and expired alerts revert", async function () {
      const sys = await loadFixture(fx);
      const id = await publish(sys, 3, 1, 600);
      await expect(sys.alertBus.connect(sys.stranger).acknowledge(id, ORG.water, W_SVC)).to.be.revertedWithCustomError(sys.alertBus, "NotOrgAgent");
      await expect(sys.alertBus.connect(sys.people.power.agent).acknowledge(id, ORG.water, W_SVC)).to.be.revertedWithCustomError(sys.alertBus, "NotOrgAgent");
      await expect(sys.alertBus.connect(sys.people.water.agent).acknowledge(ethers.id("nope"), ORG.water, W_SVC)).to.be.revertedWithCustomError(sys.alertBus, "AlertNotFound");
      await time.increase(700);
      await expect(sys.alertBus.connect(sys.people.water.agent).acknowledge(id, ORG.water, W_SVC)).to.be.revertedWithCustomError(sys.alertBus, "AlertIsExpired");
      const id2 = await publish(sys, 2, 1, 3600);
      await sys.alertBus.connect(sys.people.power.agent).resolve(id2);
      await expect(sys.alertBus.connect(sys.people.water.agent).acknowledge(id2, ORG.water, W_SVC)).to.be.revertedWithCustomError(sys.alertBus, "AlertNotActive");
    });

    it("BC-ALERT-03 several consumers can each acknowledge the same alert", async function () {
      const sys = await loadFixture(fx);
      await confirmEdge(sys, "hospital", "power", ethers.id("hospital-backup-power"), P_SVC);
      const id = await publish(sys);
      await sys.alertBus.connect(sys.people.water.agent).acknowledge(id, ORG.water, W_SVC);
      await sys.alertBus.connect(sys.people.hospital.agent).acknowledge(id, ORG.hospital, ethers.id("hospital-backup-power"));
      expect(await sys.alertBus.acknowledgedAt(id, ORG.hospital)).to.be.gt(0);
    });
  });

  describe("resolve", function () {
    it("BC-ALERT-05 only the provider's agent resolves; once", async function () {
      const sys = await loadFixture(fx);
      const id = await publish(sys);
      await expect(sys.alertBus.connect(sys.people.water.agent).resolve(id)).to.be.revertedWithCustomError(sys.alertBus, "NotAlertOwner");
      await expect(sys.alertBus.connect(sys.stranger).resolve(id)).to.be.revertedWithCustomError(sys.alertBus, "NotAlertOwner");
      await expect(sys.alertBus.connect(sys.people.power.agent).resolve(id)).to.emit(sys.alertBus, "AlertResolved");
      await expect(sys.alertBus.connect(sys.people.power.agent).resolve(id)).to.be.revertedWithCustomError(sys.alertBus, "AlertNotActive");
      await expect(sys.alertBus.connect(sys.people.power.agent).resolve(ethers.id("nope"))).to.be.revertedWithCustomError(sys.alertBus, "AlertNotFound");
      expect((await sys.alertBus.getAlert(id)).status).to.equal(2);
    });
  });

  it("BC-ALERT-01 getAlert reverts for unknown ids; constructor rejects zero addresses", async function () {
    const sys = await loadFixture(fx);
    await expect(sys.alertBus.getAlert(ethers.id("nope"))).to.be.revertedWithCustomError(sys.alertBus, "AlertNotFound");
    const F = await ethers.getContractFactory("AlertBus");
    await expect(F.deploy(ethers.ZeroAddress, ethers.ZeroAddress)).to.be.revertedWithCustomError(F, "ZeroAddress");
  });
});
