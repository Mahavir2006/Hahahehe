import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import * as fs from "fs";
import * as path from "path";
import {
  deploySystem, ORG, submitDep, submitRisk, submitFinding, futureTs, confirmEdge,
  DepArgs, attDomain, DEP_TYPES, RISK_TYPES, SEALED, BAND_SALT, FINDING_SALT,
  termsCommitment, bandCommitment, advisoryKey, findingCommitment,
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

    it("BC-ATT-D-03 buckets are committed, never stored in the clear; empty commitment or disclosure is rejected", async function () {
      const sys = await loadFixture(fx);
      const a = await depArgs();
      const tx = await submitDep(sys.attestation, sys.people.water.agent, a);
      const rc = await tx.wait();
      const ev = rc.logs.map((l: any) => { try { return sys.attestation.interface.parseLog(l); } catch { return null; } })
        .find((e: any) => e && e.name === "DependencyAttestationSubmitted");
      expect(ev.args.termsCommitment).to.equal(termsCommitment(a.strength, a.tolerance));
      expect(ev.args.toObject()).to.not.have.property("strength");
      expect(ev.args.toObject()).to.not.have.property("tolerance");
      const nonce = 2;
      const sig = await sys.people.water.agent.signTypedData(await attDomain(sys.attestation), DEP_TYPES, {
        ...a, termsCommitment: ethers.ZeroHash, disclosureHash: ethers.keccak256(SEALED), nonce,
      });
      await expect(sys.attestation.connect(sys.people.water.agent).submitDependencyAttestation(
        a.consumerOrg, a.consumerServiceHash, a.providerOrg, a.providerServiceHash, ethers.ZeroHash, nonce, a.expiry, SEALED, sig
      )).to.be.revertedWithCustomError(sys.attestation, "EmptyCommitment");
      await expect(sys.attestation.connect(sys.people.water.agent).submitDependencyAttestation(
        a.consumerOrg, a.consumerServiceHash, a.providerOrg, a.providerServiceHash, termsCommitment(2, 1), nonce, a.expiry, "0x", sig
      )).to.be.revertedWithCustomError(sys.attestation, "EmptyDisclosure");
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
      const tc = termsCommitment(a.strength, a.tolerance);
      const typed = { ...a, termsCommitment: tc, disclosureHash: ethers.keccak256(SEALED), nonce: 1 };
      const sig = await sys.people.water.agent.signTypedData(wrongDomain, DEP_TYPES, typed);
      await expect(
        sys.attestation.connect(sys.people.water.agent).submitDependencyAttestation(
          a.consumerOrg, a.consumerServiceHash, a.providerOrg, a.providerServiceHash, tc, 1, a.expiry, SEALED, sig
        )
      ).to.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
      const otherContract = { ...(await attDomain(sys.attestation)), verifyingContract: sys.stranger.address };
      const sig2 = await sys.people.water.agent.signTypedData(otherContract, DEP_TYPES, typed);
      await expect(
        sys.attestation.connect(sys.people.water.agent).submitDependencyAttestation(
          a.consumerOrg, a.consumerServiceHash, a.providerOrg, a.providerServiceHash, tc, 1, a.expiry, SEALED, sig2
        )
      ).to.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
    });

    it("BC-ATT-D-06 a tampered field invalidates the signature", async function () {
      const sys = await loadFixture(fx);
      const a = await depArgs();
      const tc = termsCommitment(a.strength, a.tolerance);
      const sig = await sys.people.water.agent.signTypedData(await attDomain(sys.attestation), DEP_TYPES, {
        ...a, termsCommitment: tc, disclosureHash: ethers.keccak256(SEALED), nonce: 1,
      });
      await expect(
        sys.attestation.connect(sys.people.water.agent).submitDependencyAttestation(
          a.consumerOrg, a.consumerServiceHash, a.providerOrg, a.providerServiceHash, termsCommitment(0, a.tolerance) /*tampered*/, 1, a.expiry, SEALED, sig
        )
      ).to.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
      // a relayer cannot swap the sealed ciphertext either: keccak256(sealed) is part of the signed struct
      await expect(
        sys.attestation.connect(sys.stranger).submitDependencyAttestation(
          a.consumerOrg, a.consumerServiceHash, a.providerOrg, a.providerServiceHash, tc, 1, a.expiry, "0xdeadbeef", sig
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
      expect(r.bandCommitment).to.equal(bandCommitment(3, 2));
      expect(r.disclosureHash).to.equal(ethers.keccak256(SEALED));
      expect(r.evidenceCommitment).to.equal(ev);
      expect(r.signer).to.equal(sys.people.power.agent.address);
    });

    it("BC-ATT-R-01 rejects wrong signer, empty disclosure, expired validity, deactivated org", async function () {
      const sys = await loadFixture(fx);
      await expect(submitRisk(sys.attestation, sys.people.water.agent, ORG.power, P_SVC, 1, 1, await futureTs(1000)))
        .to.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
      await expect(submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P_SVC, 1, 1, await futureTs(1000), ethers.ZeroHash, undefined, "0x"))
        .to.be.revertedWithCustomError(sys.attestation, "EmptyDisclosure");
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
      expect((await sys.attestation.getLatestRiskAttestation(ORG.power, P_SVC)).bandCommitment).to.equal(bandCommitment(2, 1));
    });

    it("SEC-PRIV-01 the band is only a commitment on-chain; a recipient verifies the opened value", async function () {
      const sys = await loadFixture(fx);
      const tx = await submitRisk(sys.attestation, sys.people.power.agent, ORG.power, P_SVC, 3, 3, await futureTs(1000));
      const rc = await tx.wait();
      const ev = rc.logs.map((l: any) => { try { return sys.attestation.interface.parseLog(l); } catch { return null; } })
        .find((e: any) => e && e.name === "RiskAttestationSubmitted");
      expect(ev.args.toObject()).to.not.have.property("riskBand");
      expect(ev.args.sealedBand).to.equal(SEALED);
      const id = ev.args.attestationId;
      expect(await sys.attestation.verifyBandDisclosure(id, BAND_SALT, 3, 3)).to.equal(true);
      expect(await sys.attestation.verifyBandDisclosure(id, BAND_SALT, 2, 3)).to.equal(false);
      expect(await sys.attestation.verifyBandDisclosure(id, ethers.id("guess"), 3, 3)).to.equal(false);
      expect(await sys.attestation.verifyBandDisclosure(ethers.id("unknown"), BAND_SALT, 3, 3)).to.equal(false);
      // a relayer cannot replace the ciphertext under the org's signature
      const nonce = Number(await sys.attestation.riskNonces(sys.people.power.agent.address)) + 1;
      await time.increase(2);
      const value = {
        orgId: ORG.power, serviceHash: P_SVC, bandCommitment: bandCommitment(1, 1), disclosureHash: ethers.keccak256(SEALED),
        modelVersionHash: ethers.id("model-v1"), evidenceCommitment: ethers.ZeroHash, validUntil: await futureTs(1000), nonce,
      };
      const sig = await sys.people.power.agent.signTypedData(await attDomain(sys.attestation), RISK_TYPES, value);
      await expect(sys.attestation.connect(sys.stranger).submitRiskAttestation(
        ORG.power, P_SVC, value.bandCommitment, value.modelVersionHash, ethers.ZeroHash, value.validUntil, nonce, "0x1234", sig
      )).to.be.revertedWithCustomError(sys.attestation, "InvalidSigner");
      await expect(sys.attestation.connect(sys.stranger).submitRiskAttestation(
        ORG.power, P_SVC, ethers.ZeroHash, value.modelVersionHash, ethers.ZeroHash, value.validUntil, nonce, SEALED, sig
      )).to.be.revertedWithCustomError(sys.attestation, "EmptyCommitment");
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
      // the public advisory hash cannot be used to look the finding up (the key is blinded with an org secret)
      expect((await sys.attestation.getFindingAttestation(ORG.power, adv)).timestamp).to.equal(0);
      const f = await sys.attestation.getFindingAttestation(ORG.power, advisoryKey(adv));
      expect(f.advisoryKey).to.equal(advisoryKey(adv));
      expect(f.findingCommitment).to.equal(findingCommitment(adv, ethers.id("cves"), true));
      expect(f.toObject()).to.not.have.property("matched");
    });

    it("SEC-PRIV-02 a finding opens only to whoever the org gives the salt (selective disclosure)", async function () {
      const sys = await loadFixture(fx);
      const adv = ethers.id("advisory-1");
      const cves = ethers.id("CVE-2024-0001");
      await submitFinding(sys.attestation, sys.people.power.agent, ORG.power, adv, cves, 1, true);
      const key = advisoryKey(adv);
      expect(await sys.attestation.verifyFindingDisclosure(ORG.power, key, FINDING_SALT, adv, cves, true)).to.equal(true);
      expect(await sys.attestation.verifyFindingDisclosure(ORG.power, key, FINDING_SALT, adv, cves, false)).to.equal(false);
      expect(await sys.attestation.verifyFindingDisclosure(ORG.power, key, ethers.id("guess"), adv, cves, true)).to.equal(false);
      expect(await sys.attestation.verifyFindingDisclosure(ORG.water, key, FINDING_SALT, adv, cves, true)).to.equal(false);
    });

    it("BC-ATT-F-02 duplicate (org, advisory) is idempotent: first record wins", async function () {
      const sys = await loadFixture(fx);
      const adv = ethers.id("advisory-1");
      await submitFinding(sys.attestation, sys.people.power.agent, ORG.power, adv, ethers.id("cves"), 1, true);
      await submitFinding(sys.attestation, sys.people.power.agent, ORG.power, adv, ethers.id("cves"), 2, false);
      const f = await sys.attestation.getFindingAttestation(ORG.power, advisoryKey(adv));
      expect(f.findingCommitment).to.equal(findingCommitment(adv, ethers.id("cves"), true));
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
    const contractNames = ["AttestationRegistry", "AuditLog", "ApprovalGate", "AlertBus", "OrgRegistry"];
    const artifactsDir = path.join(__dirname, "../artifacts/contracts");
    for (const name of contractNames) {
      const abiPath = path.join(artifactsDir, `${name}.sol`, `${name}.json`);
      const art = JSON.parse(fs.readFileSync(abiPath, "utf-8"));
      const abi: any[] = art.abi;
      for (const item of abi) {
        if (item.type !== "function") continue;
        if (item.stateMutability === "view" || item.stateMutability === "pure") continue;
        for (const inp of item.inputs || []) {
          expect(inp.type, `${item.name}.${inp.name}`).to.not.equal("string");
        }
      }
    }
  });

  it("BC-ATT-X-01 constructor rejects a zero OrgRegistry", async function () {
    const F = await ethers.getContractFactory("AttestationRegistry");
    await expect(F.deploy(ethers.ZeroAddress)).to.be.revertedWithCustomError(F, "OrgRegistryNotSet");
  });
});
