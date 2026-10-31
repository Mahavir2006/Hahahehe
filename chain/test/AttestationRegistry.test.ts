import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import {
  deploySystem, ORG, submitDep, submitRisk, submitFinding, futureTs, confirmEdge,
  DepArgs, attDomain, DEP_TYPES, RISK_TYPES,
} from "./helpers";

const C_SVC = ethers.id("water-pumping");
const P_SVC = ethers.id("power-substation-7");

describe("AttestationRegistry", function () {
  const fx = () => deploySystem();

  async function depArgs(overrides: Partial<DepArgs> = {}): Promise<DepArgs> {
    return {
      consumerOrg: ORG.water, consumerServiceHash: C_SVC,
      providerOrg: ORG.power, providerServiceHash: P_SVC,
      strength: 2, tolerance: 1, expiry: await futureTs(100000), ...overrides,
    };
  }

  describe("dependency attestations (bilateral)", function () {
    it("BC-ATT-D-01 one-sided attestation leaves the edge Proposed, not confirmed", async function () {
      const sys = await loadFixture(fx);
      const a = await depArgs();
      await submitDep(sys.attestation, sys.people.water.agent, a);
      expect(await sys.attestation.isEdgeConfirmed(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(false);
      expect(await sys.attestation.getEdgeState(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(0); // Proposed
    });

    it("BC-ATT-D-01 matching attestations from both sides confirm the edge", async function () {
      const sys = await loadFixture(fx);
      const a = await depArgs();
      await submitDep(sys.attestation, sys.people.water.agent, a);
      await expect(submitDep(sys.attestation, sys.people.power.agent, a)).to.emit(sys.attestation, "DependencyEdgeConfirmed");
      expect(await sys.attestation.isEdgeConfirmed(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(true);
      expect(await sys.attestation.getEdgeState(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(1); // Confirmed
    });

    it("BC-ATT-D-01 provider can attest first, consumer second", async function () {
      const sys = await loadFixture(fx);
      const a = await depArgs();
      await submitDep(sys.attestation, sys.people.power.agent, a);
      expect(await sys.attestation.isEdgeConfirmed(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(false);
      await submitDep(sys.attestation, sys.people.water.agent, a);
      expect(await sys.attestation.isEdgeConfirmed(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(true);
    });

    it("BC-ATT-D-01 a third org cannot attest an edge between two others", async function () {
      const sys = await loadFixture(fx);
      const a = await depArgs();
      await expect(submitDep(sys.attestation, sys.people.hospital.agent, a))
        .to.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
    });

    it("BC-ATT-D-01 a stranger key is rejected", async function () {
      const sys = await loadFixture(fx);
      await expect(submitDep(sys.attestation, sys.stranger, await depArgs()))
        .to.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
    });

    it("BC-ATT-D-01 consumer and provider must be different orgs", async function () {
      const sys = await loadFixture(fx);
      await expect(submitDep(sys.attestation, sys.people.water.agent, await depArgs({ providerOrg: ORG.water })))
        .to.be.revertedWithCustomError(sys.attestation, "SameOrg");
    });

    it("BC-ATT-D-03 invalid bucket enums are rejected", async function () {
      const sys = await loadFixture(fx);
      await expect(submitDep(sys.attestation, sys.people.water.agent, await depArgs({ strength: 3 })))
        .to.be.revertedWithCustomError(sys.attestation, "InvalidDependencyStrength");
      await expect(submitDep(sys.attestation, sys.people.water.agent, await depArgs({ tolerance: 4 })))
        .to.be.revertedWithCustomError(sys.attestation, "InvalidToleranceBucket");
    });

    it("BC-ATT-D-04 revoke by either side marks Revoked and isEdgeConfirmed becomes false", async function () {
      const sys = await loadFixture(fx);
      await confirmEdge(sys, "water", "power", C_SVC, P_SVC);
      await expect(sys.attestation.connect(sys.people.power.agent).revokeDependencyAttestation(ORG.water, C_SVC, ORG.power, P_SVC))
        .to.emit(sys.attestation, "DependencyEdgeRevoked");
      expect(await sys.attestation.isEdgeConfirmed(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(false);
      expect(await sys.attestation.getEdgeState(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(2); // Revoked
    });

    it("BC-ATT-D-04 only the two parties can revoke; double revoke and unknown edge revert", async function () {
      const sys = await loadFixture(fx);
      await confirmEdge(sys, "water", "power", C_SVC, P_SVC);
      await expect(sys.attestation.connect(sys.people.hospital.agent).revokeDependencyAttestation(ORG.water, C_SVC, ORG.power, P_SVC))
        .to.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
      await expect(sys.attestation.connect(sys.stranger).revokeDependencyAttestation(ORG.water, C_SVC, ORG.power, P_SVC))
        .to.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
      await sys.attestation.connect(sys.people.water.agent).revokeDependencyAttestation(ORG.water, C_SVC, ORG.power, P_SVC);
      await expect(sys.attestation.connect(sys.people.water.agent).revokeDependencyAttestation(ORG.water, C_SVC, ORG.power, P_SVC))
        .to.be.revertedWithCustomError(sys.attestation, "EdgeAlreadyRevoked");
      await expect(sys.attestation.connect(sys.people.water.agent).revokeDependencyAttestation(ORG.water, ethers.id("nope"), ORG.power, P_SVC))
        .to.be.revertedWithCustomError(sys.attestation, "EdgeNotFound");
    });

    it("BC-ATT-D-04 a revoked edge does NOT return to Confirmed from a single fresh attestation", async function () {
      const sys = await loadFixture(fx);
      const a = await confirmEdge(sys, "water", "power", C_SVC, P_SVC);
      await sys.attestation.connect(sys.people.water.agent).revokeDependencyAttestation(ORG.water, C_SVC, ORG.power, P_SVC);
      await submitDep(sys.attestation, sys.people.water.agent, a);
      expect(await sys.attestation.isEdgeConfirmed(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(false);
      await submitDep(sys.attestation, sys.people.power.agent, a);
      expect(await sys.attestation.isEdgeConfirmed(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(true);
    });

    it("BC-ATT-D-04 confirmed edges expire", async function () {
      const sys = await loadFixture(fx);
      await confirmEdge(sys, "water", "power", C_SVC, P_SVC, 2, 1, 1000);
      expect(await sys.attestation.isEdgeConfirmed(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(true);
      await time.increase(1100);
      expect(await sys.attestation.isEdgeConfirmed(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(false);
      expect(await sys.attestation.getEdgeState(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(3); // Expired
    });

    it("BC-ATT-D-04 an expired edge can be re-confirmed only by two fresh attestations", async function () {
      const sys = await loadFixture(fx);
      await confirmEdge(sys, "water", "power", C_SVC, P_SVC, 2, 1, 1000);
      await time.increase(1100);
      const a = await depArgs();
      await submitDep(sys.attestation, sys.people.water.agent, a);
      expect(await sys.attestation.isEdgeConfirmed(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(false);
      await submitDep(sys.attestation, sys.people.power.agent, a);
      expect(await sys.attestation.isEdgeConfirmed(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(true);
    });

    it("BC-ATT-D-04 attesting with an already-expired expiry is rejected", async function () {
      const sys = await loadFixture(fx);
      await expect(submitDep(sys.attestation, sys.people.water.agent, await depArgs({ expiry: (await futureTs(0)) - 10 })))
        .to.be.revertedWithCustomError(sys.attestation, "AttestationExpired");
    });

    it("BC-ATT-D-04 re-attesting a live confirmed edge reverts", async function () {
      const sys = await loadFixture(fx);
      const a = await confirmEdge(sys, "water", "power", C_SVC, P_SVC);
      await expect(submitDep(sys.attestation, sys.people.water.agent, a))
        .to.be.revertedWithCustomError(sys.attestation, "EdgeAlreadyExists");
    });

    it("BC-ATT-D-05 mismatched buckets mark the edge Disputed; re-attest resolves", async function () {
      const sys = await loadFixture(fx);
      const a = await depArgs();
      await submitDep(sys.attestation, sys.people.water.agent, a);
      await expect(submitDep(sys.attestation, sys.people.power.agent, { ...a, strength: 0 }))
        .to.emit(sys.attestation, "DependencyEdgeDisputed");
      expect(await sys.attestation.getEdgeState(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(4); // Disputed
      expect(await sys.attestation.isEdgeConfirmed(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(false);
      // provider re-attests with the matching tuple
      await submitDep(sys.attestation, sys.people.power.agent, a);
      expect(await sys.attestation.isEdgeConfirmed(ORG.water, C_SVC, ORG.power, P_SVC)).to.equal(true);
    });

    it("BC-ATT-D-06 replayed signature is rejected (nonce)", async function () {
      const sys = await loadFixture(fx);
      const a = await depArgs();
      await submitDep(sys.attestation, sys.people.water.agent, a, 1);
      await expect(submitDep(sys.attestation, sys.people.water.agent, a, 1))
        .to.be.revertedWithCustomError(sys.attestation, "InvalidNonce");
      await expect(submitDep(sys.attestation, sys.people.water.agent, a, 5))
        .to.be.revertedWithCustomError(sys.attestation, "InvalidNonce");
    });

    it("BC-ATT-D-06 a signature for a different chain/contract domain is rejected", async function () {
      const sys = await loadFixture(fx);
      const a = await depArgs();
      const wrongDomain = { ...(await attDomain(sys.attestation)), chainId: 1 };
      const sig = await sys.people.water.agent.signTypedData(wrongDomain, DEP_TYPES, { ...a, nonce: 1 });
      await expect(
        sys.attestation.connect(sys.people.water.agent).submitDependencyAttestation(
          a.consumerOrg, a.consumerServiceHash, a.providerOrg, a.providerServiceHash, a.strength, a.tolerance, 1, a.expiry, sig
        )
      ).to.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
      const otherContract = { ...(await attDomain(sys.attestation)), verifyingContract: sys.stranger.address };
      const sig2 = await sys.people.water.agent.signTypedData(otherContract, DEP_TYPES, { ...a, nonce: 1 });
      await expect(
        sys.attestation.connect(sys.people.water.agent).submitDependencyAttestation(
          a.consumerOrg, a.consumerServiceHash, a.providerOrg, a.providerServiceHash, a.strength, a.tolerance, 1, a.expiry, sig2
        )
      ).to.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
    });

    it("BC-ATT-D-06 a tampered field invalidates the signature", async function () {
      const sys = await loadFixture(fx);
      const a = await depArgs();
      const sig = await sys.people.water.agent.signTypedData(await attDomain(sys.attestation), DEP_TYPES, { ...a, nonce: 1 });
      await expect(
        sys.attestation.connect(sys.people.water.agent).submitDependencyAttestation(
          a.consumerOrg, a.consumerServiceHash, a.providerOrg, a.providerServiceHash, 0 /*tampered*/, a.tolerance, 1, a.expiry, sig
        )
      ).to.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
    });

    it("BC-ATT-D-04 deactivated orgs cannot attest", async function () {
      const sys = await loadFixture(fx);
      await sys.orgRegistry.deactivateOrg(ORG.power);
      await expect(submitDep(sys.attestation, sys.people.water.agent, await depArgs()))
        .to.be.revertedWithCustomError(sys.attestation, "OrgNotActive");
    });

    it("BC-ORG-04 attestations signed by a rotated-out signer are rejected", async function () {
      const sys = await loadFixture(fx);
      const a = await depArgs();
      await sys.orgRegistry.connect(sys.admin).rotateAgentSigner(ORG.water, sys.s[17].address);
      await expect(submitDep(sys.attestation, sys.people.water.agent, a))
        .to.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
      await submitDep(sys.attestation, sys.s[17], a);
    });

    it("BC-ATT-X-04 property: an edge is never Confirmed with only one org's signature", async function () {
      const sys = await loadFixture(fx);
      for (let i = 0; i < 5; i++) {
        const cs = ethers.id("c" + i);
        const ps = ethers.id("p" + i);
        const a = await depArgs({ consumerServiceHash: cs, providerServiceHash: ps });
        await submitDep(sys.attestation, sys.people.water.agent, a);
        expect(await sys.attestation.isEdgeConfirmed(ORG.water, cs, ORG.power, ps)).to.equal(false);
        // consumer cannot double-sign to self-confirm
        await expect(submitDep(sys.attestation, sys.people.water.agent, a)).to.not.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
        expect(await sys.attestation.isEdgeConfirmed(ORG.water, cs, ORG.power, ps)).to.equal(false);
      }
    });
  });

  describe("risk attestations", function () {
    it("BC-ATT-R-01 stores and returns the latest attestation", async function () {
      const sys = await loadFixture(fx);
      const ev = ethers.id("evidence");
      await submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P_SVC, 3, 2, await futureTs(1000), ev);
      const r = await sys.attestation.getLatestRiskAttestation(ORG.power, P_SVC);
      expect(r.riskBand).to.equal(3);
      expect(r.criticalityBucket).to.equal(2);
      expect(r.evidenceCommitment).to.equal(ev);
      expect(r.signer).to.equal(sys.people.power.agent.address);
    });

    it("BC-ATT-R-01 rejects wrong signer, bad enums, expired validity, deactivated org", async function () {
      const sys = await loadFixture(fx);
      await expect(submitRisk(sys.attestation, sys.people.water.agent, ORG.power, P_SVC, 1, 1, await futureTs(1000)))
        .to.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
      await expect(submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P_SVC, 4, 1, await futureTs(1000)))
        .to.be.revertedWithCustomError(sys.attestation, "InvalidRiskBand");
      await expect(submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P_SVC, 1, 4, await futureTs(1000)))
        .to.be.revertedWithCustomError(sys.attestation, "InvalidCriticalityBucket");
      await expect(submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P_SVC, 1, 1, (await futureTs(0)) - 5))
        .to.be.revertedWithCustomError(sys.attestation, "AttestationExpired");
      await sys.orgRegistry.deactivateOrg(ORG.power);
      await expect(submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P_SVC, 1, 1, await futureTs(1000)))
        .to.be.revertedWithCustomError(sys.attestation, "OrgNotActive");
    });

    it("BC-ATT-R-02 keeps full history", async function () {
      const sys = await loadFixture(fx);
      for (let b = 0; b < 3; b++) {
        await submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P_SVC, b, 1, await futureTs(1000));
        await time.increase(2);
      }
      const hist = await sys.attestation.getRiskAttestationHistory(ORG.power, P_SVC);
      expect(hist.length).to.equal(3);
      expect((await sys.attestation.getLatestRiskAttestation(ORG.power, P_SVC)).riskBand).to.equal(2);
    });

    it("BC-ATT-R-03 rate limit per service", async function () {
      const sys = await loadFixture(fx);
      await sys.attestation.setRiskAttestationMinInterval(3600);
      await submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P_SVC, 1, 1, await futureTs(100000));
      await expect(submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P_SVC, 2, 1, await futureTs(100000)))
        .to.be.revertedWithCustomError(sys.attestation, "RateLimited");
      // a different service is not limited
      await submitRisk(sys.attestation, sys.people.power.agent, ORG.power, ethers.id("other"), 2, 1, await futureTs(100000));
      await time.increase(3601);
      await submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P_SVC, 2, 1, await futureTs(100000));
    });

    it("BC-ATT-R-03 only the admin can change the rate limit", async function () {
      const sys = await loadFixture(fx);
      await expect(sys.attestation.connect(sys.stranger).setRiskAttestationMinInterval(5))
        .to.be.revertedWithCustomError(sys.attestation, "OnlyRegistryAdmin");
    });

    it("BC-ATT-R-04 selective disclosure verifies correct salt+assessment and rejects wrong ones", async function () {
      const sys = await loadFixture(fx);
      const salt = ethers.id("salt");
      const assessment = ethers.id("assessment-json");
      const commitment = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32"], [salt, assessment]));
      await submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P_SVC, 2, 1, await futureTs(1000), commitment);
      const id = (await sys.attestation.getRiskAttestationHistory(ORG.power, P_SVC))[0];
      expect(await sys.attestation.verifyRiskDisclosure(ORG.power, P_SVC, id, salt, assessment)).to.equal(true);
      expect(await sys.attestation.verifyRiskDisclosure(ORG.power, P_SVC, id, ethers.id("bad"), assessment)).to.equal(false);
      expect(await sys.attestation.verifyRiskDisclosure(ORG.power, P_SVC, id, salt, ethers.id("bad"))).to.equal(false);
      expect(await sys.attestation.verifyRiskDisclosure(ORG.water, P_SVC, id, salt, assessment)).to.equal(false);
    });

    it("BC-ATT-R-05 attestations expire and are reported invalid", async function () {
      const sys = await loadFixture(fx);
      await submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P_SVC, 2, 1, await futureTs(500));
      expect(await sys.attestation.isRiskAttestationValid(ORG.power, P_SVC)).to.equal(true);
      await time.increase(600);
      expect(await sys.attestation.isRiskAttestationValid(ORG.power, P_SVC)).to.equal(false);
      expect(await sys.attestation.isRiskAttestationValid(ORG.power, ethers.id("never"))).to.equal(false);
    });

    it("BC-ATT-D-06 risk signature replay and nonce gaps are rejected", async function () {
      const sys = await loadFixture(fx);
      await submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P_SVC, 1, 1, await futureTs(1000), ethers.ZeroHash, 1);
      await expect(submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P_SVC, 1, 1, await futureTs(1000), ethers.ZeroHash, 1))
        .to.be.revertedWithCustomError(sys.attestation, "InvalidNonce");
    });
  });

  describe("finding attestations", function () {
    it("BC-ATT-F-01 records that an org processed an advisory without revealing assets", async function () {
      const sys = await loadFixture(fx);
      const adv = ethers.id("advisory-1");
      const ts = await futureTs(0);
      await submitFinding(sys.attestation, sys.people.power.agent, ORG.power, adv, ethers.id("cves"), ts, true);
      const f = await sys.attestation.getFindingAttestation(ORG.power, adv);
      expect(f.matched).to.equal(true);
      expect(f.advisoryContentHash).to.equal(adv);
    });

    it("BC-ATT-F-02 duplicate (org, advisory) is idempotent: first record wins", async function () {
      const sys = await loadFixture(fx);
      const adv = ethers.id("advisory-1");
      await submitFinding(sys.attestation, sys.people.power.agent, ORG.power, adv, ethers.id("cves"), 1, true);
      await submitFinding(sys.attestation, sys.people.power.agent, ORG.power, adv, ethers.id("cves"), 2, false);
      const f = await sys.attestation.getFindingAttestation(ORG.power, adv);
      expect(f.matched).to.equal(true);
      expect(f.processedAt).to.equal(1);
    });

    it("BC-ATT-F-02 unknown finding returns an empty record; wrong signer reverts", async function () {
      const sys = await loadFixture(fx);
      expect((await sys.attestation.getFindingAttestation(ORG.power, ethers.id("x"))).timestamp).to.equal(0);
      await expect(submitFinding(sys.attestation, sys.people.water.agent, ORG.power, ethers.id("x"), ethers.id("c"), 1, true))
        .to.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
      await sys.orgRegistry.deactivateOrg(ORG.power);
      await expect(submitFinding(sys.attestation, sys.people.power.agent, ORG.power, ethers.id("x"), ethers.id("c"), 1, true))
        .to.be.revertedWithCustomError(sys.attestation, "OrgNotActive");
    });
  });

  describe("challenge mechanism (BC-SEC-08)", function () {
    async function withRisk() {
      const sys = await deploySystem();
      await confirmEdge(sys, "water", "power", C_SVC, P_SVC);
      await submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P_SVC, 0, 1, await futureTs(100000));
      const id = (await sys.attestation.getRiskAttestationHistory(ORG.power, P_SVC))[0];
      return { sys, id };
    }

    it("BC-SEC-08 an org with a confirmed edge can challenge; counted once per org", async function () {
      const { sys, id } = await withRisk();
      await expect(sys.attestation.connect(sys.people.water.agent).challengeRiskAttestation(id, ORG.water, ethers.id("proof")))
        .to.emit(sys.attestation, "ChallengeSubmitted");
      expect(await sys.attestation.isChallenged(id)).to.equal(true);
      expect(await sys.attestation.challengeCount(id)).to.equal(1);
      await expect(sys.attestation.connect(sys.people.water.agent).challengeRiskAttestation(id, ORG.water, ethers.id("proof")))
        .to.be.revertedWithCustomError(sys.attestation, "ChallengeNotAllowed");
    });

    it("BC-SEC-08 an org WITHOUT a confirmed edge cannot challenge", async function () {
      const { sys, id } = await withRisk();
      await expect(sys.attestation.connect(sys.people.hospital.agent).challengeRiskAttestation(id, ORG.hospital, ethers.id("p")))
        .to.be.revertedWithCustomError(sys.attestation, "ChallengeNotAllowed");
    });

    it("BC-SEC-08 self-challenge, wrong sender and unknown attestation revert", async function () {
      const { sys, id } = await withRisk();
      await expect(sys.attestation.connect(sys.people.power.agent).challengeRiskAttestation(id, ORG.power, ethers.id("p")))
        .to.be.revertedWithCustomError(sys.attestation, "ChallengeNotAllowed");
      await expect(sys.attestation.connect(sys.stranger).challengeRiskAttestation(id, ORG.water, ethers.id("p")))
        .to.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
      await expect(sys.attestation.connect(sys.people.water.agent).challengeRiskAttestation(ethers.id("nope"), ORG.water, ethers.id("p")))
        .to.be.revertedWithCustomError(sys.attestation, "AttestationNotFound");
    });

    it("BC-SEC-08 a revoked edge no longer authorises challenges", async function () {
      const { sys, id } = await withRisk();
      await sys.attestation.connect(sys.people.water.agent).revokeDependencyAttestation(ORG.water, C_SVC, ORG.power, P_SVC);
      await expect(sys.attestation.connect(sys.people.water.agent).challengeRiskAttestation(id, ORG.water, ethers.id("p")))
        .to.be.revertedWithCustomError(sys.attestation, "ChallengeNotAllowed");
    });
  });

  it("BC-ATT-X-03 no external function takes a free-form string parameter", async function () {
    const sys = await loadFixture(fx);
    for (const c of [sys.attestation, sys.auditLog, sys.gate, sys.alertBus, sys.orgRegistry]) {
      for (const f of c.interface.fragments) {
        if (f.type !== "function") continue;
        for (const inp of (f as any).inputs) {
          expect(inp.type, `${(f as any).name}.${inp.name}`).to.not.equal("string");
        }
      }
    }
  });

  it("BC-ATT-X-01 constructor rejects a zero OrgRegistry", async function () {
    const F = await ethers.getContractFactory("AttestationRegistry");
    await expect(F.deploy(ethers.ZeroAddress)).to.be.revertedWithCustomError(F, "OrgRegistryNotSet");
  });
});
