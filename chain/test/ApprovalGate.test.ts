import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
import { deploySystem, ORG, KIND, IMPACT, STATUS, anchorCritic, futureTs } from "./helpers";

const PLAN = ethers.id("plan-1");
const STEPS = ethers.id("steps-1");

describe("ApprovalGate", function () {
  const fx = () => deploySystem();

  async function request(sys: any, impact: number, opts: { ttl?: number; org?: "power" | "water" | "hospital"; label?: string; plan?: string } = {}) {
    const org = opts.org ?? "power";
    const verdict = await anchorCritic(sys, org, opts.label ?? "v" + Math.random());
    const expiry = await futureTs(opts.ttl ?? 3600);
    const plan = opts.plan ?? ethers.id("plan" + Math.random());
    const tx = await sys.gate.connect(sys.people[org].agent).requestApproval(ORG[org], plan, STEPS, impact, expiry, verdict);
    const rc = await tx.wait();
    const ev = rc.logs.map((l: any) => { try { return sys.gate.interface.parseLog(l); } catch { return null; } }).find((e: any) => e && e.name === "ApprovalRequested");
    return { id: ev.args.requestId as string, plan, verdict, expiry };
  }

  describe("requestApproval", function () {
    it("BC-GATE-01 creates a request, stores the plan hash and emits ApprovalRequested", async function () {
      const sys = await loadFixture(fx);
      const verdict = await anchorCritic(sys, "power", "a");
      const expiry = await futureTs(3600);
      await expect(sys.gate.connect(sys.people.power.agent).requestApproval(ORG.power, PLAN, STEPS, IMPACT.High, expiry, verdict))
        .to.emit(sys.gate, "ApprovalRequested");
    });

    it("BC-GATE-01 requires an ANCHORED critic verdict for that org", async function () {
      const sys = await loadFixture(fx);
      await expect(sys.gate.connect(sys.people.power.agent).requestApproval(ORG.power, PLAN, STEPS, IMPACT.High, await futureTs(3600), ethers.id("fake")))
        .to.be.revertedWithCustomError(sys.gate, "CriticVerdictNotAnchored");
      // a verdict anchored for ANOTHER org does not count
      const waterVerdict = await anchorCritic(sys, "water", "w");
      await expect(sys.gate.connect(sys.people.power.agent).requestApproval(ORG.power, PLAN, STEPS, IMPACT.High, await futureTs(3600), waterVerdict))
        .to.be.revertedWithCustomError(sys.gate, "CriticVerdictNotAnchored");
      // an anchor of the wrong KIND does not count
      const d = ethers.id("not-critic");
      await sys.auditLog.connect(sys.people.power.agent).anchor(ORG.power, KIND.Plan, d, await sys.auditLog.lastDigest(ORG.power), ethers.ZeroHash);
      await expect(sys.gate.connect(sys.people.power.agent).requestApproval(ORG.power, PLAN, STEPS, IMPACT.High, await futureTs(3600), d))
        .to.be.revertedWithCustomError(sys.gate, "CriticVerdictNotAnchored");
    });

    it("BC-GATE-01 only the org agent can request", async function () {
      const sys = await loadFixture(fx);
      const verdict = await anchorCritic(sys, "power", "a");
      for (const who of [sys.stranger, sys.people.water.agent, sys.people.power.approvers[0]]) {
        await expect(sys.gate.connect(who).requestApproval(ORG.power, PLAN, STEPS, IMPACT.High, await futureTs(3600), verdict))
          .to.be.revertedWithCustomError(sys.gate, "NotOrgAgent");
      }
    });

    it("BC-GATE-05 LOW impact is not requestable; invalid class too", async function () {
      const sys = await loadFixture(fx);
      const verdict = await anchorCritic(sys, "power", "a");
      await expect(sys.gate.connect(sys.people.power.agent).requestApproval(ORG.power, PLAN, STEPS, IMPACT.Low, await futureTs(3600), verdict))
        .to.be.revertedWithCustomError(sys.gate, "LowImpactNeedsNoApproval");
      await expect(sys.gate.connect(sys.people.power.agent).requestApproval(ORG.power, PLAN, STEPS, 3, await futureTs(3600), verdict))
        .to.be.revertedWithCustomError(sys.gate, "LowImpactNeedsNoApproval");
    });

    it("BC-GATE-09 expiry must be in the future; plan hash must be non-zero", async function () {
      const sys = await loadFixture(fx);
      const verdict = await anchorCritic(sys, "power", "a");
      await expect(sys.gate.connect(sys.people.power.agent).requestApproval(ORG.power, PLAN, STEPS, IMPACT.High, (await futureTs(0)) - 1, verdict))
        .to.be.revertedWithCustomError(sys.gate, "InvalidExpiry");
      await expect(sys.gate.connect(sys.people.power.agent).requestApproval(ORG.power, ethers.ZeroHash, STEPS, IMPACT.High, await futureTs(60), verdict))
        .to.be.revertedWithCustomError(sys.gate, "ZeroPlanHash");
    });

    it("BC-GATE-10 caps pending requests per org", async function () {
      const sys = await loadFixture(fx);
      for (let i = 0; i < 20; i++) await request(sys, IMPACT.Medium, { label: "cap" + i });
      const verdict = await anchorCritic(sys, "power", "over");
      await expect(sys.gate.connect(sys.people.power.agent).requestApproval(ORG.power, PLAN, STEPS, IMPACT.Medium, await futureTs(3600), verdict))
        .to.be.revertedWithCustomError(sys.gate, "TooManyPending");
      // another org is unaffected
      await request(sys, IMPACT.Medium, { org: "water" });
    });

    it("BC-GATE-02 the on-chain plan hash is queryable", async function () {
      const sys = await loadFixture(fx);
      const { id, plan } = await request(sys, IMPACT.High);
      expect(await sys.gate.planHashOf(id)).to.equal(plan);
    });
  });

  describe("voting and impact rules", function () {
    it("BC-GATE-05 MEDIUM needs exactly one approver", async function () {
      const sys = await loadFixture(fx);
      const { id } = await request(sys, IMPACT.Medium);
      expect(await sys.gate.status(id)).to.equal(STATUS.Pending);
      await sys.gate.connect(sys.people.power.approvers[1]).approve(id); // non safety officer
      expect(await sys.gate.status(id)).to.equal(STATUS.Approved);
    });

    it("BC-GATE-05 HIGH needs M approvals", async function () {
      const sys = await loadFixture(fx);
      const { id } = await request(sys, IMPACT.High);
      await sys.gate.connect(sys.people.power.approvers[0]).approve(id); // safety officer #1
      expect(await sys.gate.status(id)).to.equal(STATUS.Pending); // 1 of 2
      await sys.gate.connect(sys.people.power.approvers[1]).approve(id);
      expect(await sys.gate.status(id)).to.equal(STATUS.Approved);
    });

    it("BC-GATE-05 HIGH needs a safety-officer approval even when M non-safety approvers approve", async function () {
      const sys = await loadFixture(fx);
      const { id } = await request(sys, IMPACT.High);
      await sys.gate.connect(sys.people.power.approvers[1]).approve(id);
      await sys.gate.connect(sys.people.power.approvers[2]).approve(id);
      // 2 approvals == M, but none is the safety officer
      expect(await sys.gate.status(id)).to.equal(STATUS.Pending);
      await sys.gate.connect(sys.people.power.approvers[0]).approve(id);
      expect(await sys.gate.status(id)).to.equal(STATUS.Approved);
    });

    it("BC-GATE-04 no double voting and no vote switching", async function () {
      const sys = await loadFixture(fx);
      const { id } = await request(sys, IMPACT.High);
      await sys.gate.connect(sys.people.power.approvers[0]).approve(id);
      await expect(sys.gate.connect(sys.people.power.approvers[0]).approve(id)).to.be.revertedWithCustomError(sys.gate, "AlreadyVoted");
      await expect(sys.gate.connect(sys.people.power.approvers[0]).reject(id)).to.be.revertedWithCustomError(sys.gate, "AlreadyVoted");
      expect(await sys.gate.hasVoted(id, sys.people.power.approvers[0].address)).to.equal(true);
    });

    it("BC-GATE-04 only snapshot approvers of that org may vote", async function () {
      const sys = await loadFixture(fx);
      const { id } = await request(sys, IMPACT.High);
      for (const who of [sys.stranger, sys.people.water.approvers[0]]) {
        await expect(sys.gate.connect(who).approve(id)).to.be.revertedWithCustomError(sys.gate, "NotSnapshotApprover");
        await expect(sys.gate.connect(who).reject(id)).to.be.revertedWithCustomError(sys.gate, "NotSnapshotApprover");
      }
    });

    it("BC-GATE-06 the agent signer can never approve or reject", async function () {
      const sys = await loadFixture(fx);
      const { id } = await request(sys, IMPACT.High);
      await expect(sys.gate.connect(sys.people.power.agent).approve(id)).to.be.revertedWithCustomError(sys.gate, "AgentCannotVote");
      await expect(sys.gate.connect(sys.people.power.agent).reject(id)).to.be.revertedWithCustomError(sys.gate, "AgentCannotVote");
    });

    it("BC-GATE-06 the registry refuses an agent that is also an approver (registration and rotation)", async function () {
      const sys = await loadFixture(fx);
      const s = sys.s;
      await expect(
        sys.orgRegistry.registerOrg(ethers.id("x"), ethers.id("x"), 3, sys.admin.address, s[18].address, [s[18].address, s[19].address, s[17].address], 2, [true, false, false])
      ).to.be.revertedWithCustomError(sys.orgRegistry, "AgentSignerCannotBeApprover");
      // rotating the agent to one of its own approvers is refused
      await expect(sys.orgRegistry.connect(sys.admin).rotateAgentSigner(ORG.power, sys.people.power.approvers[0].address))
        .to.be.revertedWithCustomError(sys.orgRegistry, "AgentSignerCannotBeApprover");
    });

    it("BC-GATE-03 snapshot semantics: approver-set changes do not affect pending requests", async function () {
      const sys = await loadFixture(fx);
      const { id } = await request(sys, IMPACT.High);
      const [oldList] = await sys.gate.getSnapshotApprovers(id);
      const newApprovers = [sys.s[17], sys.s[18], sys.s[19]];
      await sys.orgRegistry.connect(sys.admin).updateApproverSet(ORG.power, newApprovers.map((a: any) => a.address), 3, [true, false, false]);
      // the NEW approvers cannot vote on the old request, the OLD ones still can
      await expect(sys.gate.connect(newApprovers[0]).approve(id)).to.be.revertedWithCustomError(sys.gate, "NotSnapshotApprover");
      await sys.gate.connect(sys.people.power.approvers[0]).approve(id);
      await sys.gate.connect(sys.people.power.approvers[1]).approve(id);
      expect(await sys.gate.status(id)).to.equal(STATUS.Approved); // old threshold 2, not the new 3
      expect(oldList.length).to.equal(3);
    });

    it("BC-GATE-07 enough rejections make the threshold unreachable -> Rejected (terminal)", async function () {
      const sys = await loadFixture(fx);
      const { id } = await request(sys, IMPACT.High);
      await sys.gate.connect(sys.people.power.approvers[1]).reject(id);
      expect(await sys.gate.status(id)).to.equal(STATUS.Pending); // 2 of 3 still possible
      await sys.gate.connect(sys.people.power.approvers[2]).reject(id);
      expect(await sys.gate.status(id)).to.equal(STATUS.Rejected);
      await expect(sys.gate.connect(sys.people.power.approvers[0]).approve(id)).to.be.revertedWithCustomError(sys.gate, "InvalidState");
    });

    it("BC-GATE-07 if the only safety officer rejects a HIGH request it is Rejected", async function () {
      const sys = await loadFixture(fx);
      const { id } = await request(sys, IMPACT.High);
      await sys.gate.connect(sys.people.power.approvers[0]).reject(id); // the only safety officer
      expect(await sys.gate.status(id)).to.equal(STATUS.Rejected);
    });

    it("BC-GATE-07 a MEDIUM request is rejected only when all approvers reject", async function () {
      const sys = await loadFixture(fx);
      const { id } = await request(sys, IMPACT.Medium);
      await sys.gate.connect(sys.people.power.approvers[0]).reject(id);
      await sys.gate.connect(sys.people.power.approvers[1]).reject(id);
      expect(await sys.gate.status(id)).to.equal(STATUS.Pending);
      await sys.gate.connect(sys.people.power.approvers[2]).reject(id);
      expect(await sys.gate.status(id)).to.equal(STATUS.Rejected);
    });

    it("BC-GATE-04 approveWithSigs aggregates EIP-712 votes through a relayer", async function () {
      const sys = await loadFixture(fx);
      const { id } = await request(sys, IMPACT.High);
      const digest = await sys.gate.voteDigest(id);
      const domain = { name: "ApprovalGate", version: "1", chainId: 31337, verifyingContract: await sys.gate.getAddress() };
      const types = { Vote: [{ name: "requestId", type: "bytes32" }, { name: "approve", type: "bool" }] };
      const a0 = sys.people.power.approvers[0], a1 = sys.people.power.approvers[1];
      const sig0 = await a0.signTypedData(domain, types, { requestId: id, approve: true });
      const sig1 = await a1.signTypedData(domain, types, { requestId: id, approve: true });
      expect(ethers.verifyTypedData(domain, types, { requestId: id, approve: true }, sig0)).to.equal(a0.address);
      expect(digest).to.equal(ethers.TypedDataEncoder.hash(domain, types, { requestId: id, approve: true }));
      await sys.gate.connect(sys.relayer).approveWithSigs(id, [a0.address, a1.address], [sig0, sig1]);
      expect(await sys.gate.status(id)).to.equal(STATUS.Approved);
    });

    it("BC-GATE-04 approveWithSigs rejects forged, mismatched, replayed and agent-signed votes", async function () {
      const sys = await loadFixture(fx);
      const { id } = await request(sys, IMPACT.High);
      const domain = { name: "ApprovalGate", version: "1", chainId: 31337, verifyingContract: await sys.gate.getAddress() };
      const types = { Vote: [{ name: "requestId", type: "bytes32" }, { name: "approve", type: "bool" }] };
      const a0 = sys.people.power.approvers[0];
      const good = await a0.signTypedData(domain, types, { requestId: id, approve: true });
      await expect(sys.gate.connect(sys.relayer).approveWithSigs(id, [sys.people.power.approvers[1].address], [good]))
        .to.be.revertedWithCustomError(sys.gate, "InvalidSignature");
      await expect(sys.gate.connect(sys.relayer).approveWithSigs(id, [a0.address], []))
        .to.be.revertedWithCustomError(sys.gate, "LengthMismatch");
      const agentSig = await sys.people.power.agent.signTypedData(domain, types, { requestId: id, approve: true });
      await expect(sys.gate.connect(sys.relayer).approveWithSigs(id, [sys.people.power.agent.address], [agentSig]))
        .to.be.revertedWithCustomError(sys.gate, "AgentCannotVote");
      // a signature over a different request id does not authorise this one
      const other = await request(sys, IMPACT.High);
      const sigOther = await a0.signTypedData(domain, types, { requestId: other.id, approve: true });
      await expect(sys.gate.connect(sys.relayer).approveWithSigs(id, [a0.address], [sigOther]))
        .to.be.revertedWithCustomError(sys.gate, "InvalidSignature");
      await sys.gate.connect(sys.relayer).approveWithSigs(id, [a0.address], [good]);
      await expect(sys.gate.connect(sys.relayer).approveWithSigs(id, [a0.address], [good]))
        .to.be.revertedWithCustomError(sys.gate, "AlreadyVoted");
    });
  });

  describe("execution", function () {
    async function approved(sys: any) {
      const r = await request(sys, IMPACT.High);
      await sys.gate.connect(sys.people.power.approvers[0]).approve(r.id);
      await sys.gate.connect(sys.people.power.approvers[1]).approve(r.id);
      return r;
    }

    it("BC-GATE-08 the agent can mark an Approved request executed exactly once", async function () {
      const sys = await loadFixture(fx);
      const { id } = await approved(sys);
      await expect(sys.gate.connect(sys.people.power.agent).markExecuted(id, ethers.id("exec"))).to.emit(sys.gate, "Executed");
      expect(await sys.gate.status(id)).to.equal(STATUS.Executed);
      await expect(sys.gate.connect(sys.people.power.agent).markExecuted(id, ethers.id("exec2")))
        .to.be.revertedWithCustomError(sys.gate, "InvalidState");
    });

    it("BC-GATE-08 cannot execute a Pending, Rejected or Cancelled request (agent cannot bypass the gate)", async function () {
      const sys = await loadFixture(fx);
      const pending = await request(sys, IMPACT.High);
      await expect(sys.gate.connect(sys.people.power.agent).markExecuted(pending.id, ethers.id("e")))
        .to.be.revertedWithCustomError(sys.gate, "InvalidState");
      await sys.gate.connect(sys.people.power.agent).cancel(pending.id);
      await expect(sys.gate.connect(sys.people.power.agent).markExecuted(pending.id, ethers.id("e")))
        .to.be.revertedWithCustomError(sys.gate, "InvalidState");
    });

    it("BC-GATE-08 only the org's agent can execute; strangers, approvers and other orgs cannot", async function () {
      const sys = await loadFixture(fx);
      const { id } = await approved(sys);
      for (const who of [sys.stranger, sys.people.power.approvers[0], sys.people.water.agent]) {
        await expect(sys.gate.connect(who).markExecuted(id, ethers.id("e"))).to.be.revertedWithCustomError(sys.gate, "NotOrgAgent");
      }
    });

    it("BC-GATE-08 unknown request ids revert", async function () {
      const sys = await loadFixture(fx);
      await expect(sys.gate.connect(sys.people.power.agent).markExecuted(ethers.id("nope"), ethers.id("e")))
        .to.be.revertedWithCustomError(sys.gate, "RequestNotFound");
      await expect(sys.gate.connect(sys.people.power.approvers[0]).approve(ethers.id("nope"))).to.be.revertedWithCustomError(sys.gate, "RequestNotFound");
      await expect(sys.gate.getRequest(ethers.id("nope"))).to.be.revertedWithCustomError(sys.gate, "RequestNotFound");
      await expect(sys.gate.cancel(ethers.id("nope"))).to.be.revertedWithCustomError(sys.gate, "RequestNotFound");
      await expect(sys.gate.expire(ethers.id("nope"))).to.be.revertedWithCustomError(sys.gate, "RequestNotFound");
    });

    it("BC-GATE-08 a rotated-out agent signer cannot execute", async function () {
      const sys = await loadFixture(fx);
      const { id } = await approved(sys);
      await sys.orgRegistry.connect(sys.admin).rotateAgentSigner(ORG.power, sys.s[17].address);
      await expect(sys.gate.connect(sys.people.power.agent).markExecuted(id, ethers.id("e"))).to.be.revertedWithCustomError(sys.gate, "NotOrgAgent");
      await sys.gate.connect(sys.s[17]).markExecuted(id, ethers.id("e"));
    });
  });

  describe("expiry and cancellation", function () {
    it("BC-GATE-09 requests past expiry are Expired and can never be approved", async function () {
      const sys = await loadFixture(fx);
      const { id } = await request(sys, IMPACT.High, { ttl: 100 });
      await time.increase(101);
      expect(await sys.gate.status(id)).to.equal(STATUS.Expired);
      await expect(sys.gate.connect(sys.people.power.approvers[0]).approve(id)).to.be.revertedWithCustomError(sys.gate, "RequestIsExpired");
      await expect(sys.gate.connect(sys.people.power.approvers[0]).reject(id)).to.be.revertedWithCustomError(sys.gate, "RequestIsExpired");
    });

    it("BC-GATE-09 boundary: voting at exactly the expiry timestamp still works, one second later fails", async function () {
      const sys = await loadFixture(fx);
      const { id, expiry } = await request(sys, IMPACT.Medium, { ttl: 1000 });
      await time.setNextBlockTimestamp(expiry);
      await sys.gate.connect(sys.people.power.approvers[1]).approve(id);
      expect(await sys.gate.status(id)).to.equal(STATUS.Approved);
      const r2 = await request(sys, IMPACT.Medium, { ttl: 1000 });
      await time.setNextBlockTimestamp(r2.expiry + 1);
      await expect(sys.gate.connect(sys.people.power.approvers[1]).approve(r2.id)).to.be.revertedWithCustomError(sys.gate, "RequestIsExpired");
    });

    it("BC-GATE-09 an Approved request that expires cannot be executed", async function () {
      const sys = await loadFixture(fx);
      const { id } = await request(sys, IMPACT.Medium, { ttl: 200 });
      await sys.gate.connect(sys.people.power.approvers[1]).approve(id);
      await time.increase(300);
      expect(await sys.gate.status(id)).to.equal(STATUS.Expired);
      expect(await sys.gate.isApprovedAndLive(id)).to.equal(false);
      await expect(sys.gate.connect(sys.people.power.agent).markExecuted(id, ethers.id("e"))).to.be.revertedWithCustomError(sys.gate, "RequestIsExpired");
    });

    it("BC-GATE-09 expire() writes the state, frees the pending slot, and is refused too early", async function () {
      const sys = await loadFixture(fx);
      const { id } = await request(sys, IMPACT.Medium, { ttl: 100 });
      expect(await sys.gate.livePending(ORG.power)).to.equal(1);
      await expect(sys.gate.expire(id)).to.be.revertedWithCustomError(sys.gate, "NotExpired");
      await time.increase(200);
      await expect(sys.gate.expire(id)).to.emit(sys.gate, "RequestExpired");
      expect(await sys.gate.livePending(ORG.power)).to.equal(0);
      await expect(sys.gate.expire(id)).to.be.revertedWithCustomError(sys.gate, "InvalidState");
    });

    it("BC-GATE-11 agent or snapshot approver can cancel a Pending request; others cannot", async function () {
      const sys = await loadFixture(fx);
      const r1 = await request(sys, IMPACT.High);
      await expect(sys.gate.connect(sys.stranger).cancel(r1.id)).to.be.revertedWithCustomError(sys.gate, "NotCancellable");
      await expect(sys.gate.connect(sys.people.water.agent).cancel(r1.id)).to.be.revertedWithCustomError(sys.gate, "NotCancellable");
      await expect(sys.gate.connect(sys.people.power.approvers[2]).cancel(r1.id)).to.emit(sys.gate, "Cancelled");
      expect(await sys.gate.status(r1.id)).to.equal(STATUS.Cancelled);
      const r2 = await request(sys, IMPACT.High);
      await sys.gate.connect(sys.people.power.agent).cancel(r2.id);
      expect(await sys.gate.status(r2.id)).to.equal(STATUS.Cancelled);
    });

    it("BC-GATE-11 an Approved request cannot be cancelled", async function () {
      const sys = await loadFixture(fx);
      const { id } = await request(sys, IMPACT.Medium);
      await sys.gate.connect(sys.people.power.approvers[1]).approve(id);
      await expect(sys.gate.connect(sys.people.power.agent).cancel(id)).to.be.revertedWithCustomError(sys.gate, "InvalidState");
    });
  });

  describe("invariants", function () {
    it("BC-GATE-14 terminal states never resurrect (Rejected / Cancelled / Expired / Executed)", async function () {
      const sys = await loadFixture(fx);
      const a = sys.people.power.approvers;
      // Rejected
      const rej = await request(sys, IMPACT.High);
      await sys.gate.connect(a[0]).reject(rej.id);
      // Cancelled
      const can = await request(sys, IMPACT.High);
      await sys.gate.connect(sys.people.power.agent).cancel(can.id);
      // Expired
      const exp = await request(sys, IMPACT.High, { ttl: 50 });
      // Executed
      const ex = await request(sys, IMPACT.Medium);
      await sys.gate.connect(a[1]).approve(ex.id);
      await sys.gate.connect(sys.people.power.agent).markExecuted(ex.id, ethers.id("e"));
      await time.increase(100);

      for (const r of [rej, can, ex]) {
        for (const approver of a) {
          await expect(sys.gate.connect(approver).approve(r.id)).to.be.reverted;
          await expect(sys.gate.connect(approver).reject(r.id)).to.be.reverted;
        }
        await expect(sys.gate.connect(sys.people.power.agent).markExecuted(r.id, ethers.id("again"))).to.be.reverted;
        await expect(sys.gate.connect(sys.people.power.agent).cancel(r.id)).to.be.reverted;
      }
      for (const approver of a) await expect(sys.gate.connect(approver).approve(exp.id)).to.be.reverted;
      expect(await sys.gate.status(rej.id)).to.equal(STATUS.Rejected);
      expect(await sys.gate.status(can.id)).to.equal(STATUS.Cancelled);
      expect(await sys.gate.status(ex.id)).to.equal(STATUS.Executed);
      expect(await sys.gate.status(exp.id)).to.equal(STATUS.Expired);
    });

    it("BC-GATE-14 property: no sequence of votes reaches Approved with fewer than the required distinct approvers", async function () {
      const sys = await loadFixture(fx);
      const a = sys.people.power.approvers;
      // exhaustively try every ordering/subset of vote types over the 3 approvers for a HIGH request
      const choices = [0, 1, 2]; // skip, approve, reject
      for (const c0 of choices) for (const c1 of choices) for (const c2 of choices) {
        const { id } = await request(sys, IMPACT.High);
        const picks = [c0, c1, c2];
        let approvals = 0, safetyOk = false;
        for (let i = 0; i < 3; i++) {
          if (picks[i] === 0) continue;
          const st = Number(await sys.gate.status(id));
          if (st !== STATUS.Pending) break;
          if (picks[i] === 1) { await sys.gate.connect(a[i]).approve(id); approvals++; if (i === 0) safetyOk = true; }
          else await sys.gate.connect(a[i]).reject(id);
        }
        const st = Number(await sys.gate.status(id));
        if (st === STATUS.Approved) {
          expect(approvals).to.be.gte(2);
          expect(safetyOk).to.equal(true);
        }
        // clean up so the pending cap is never hit
        if (st === STATUS.Pending) await sys.gate.connect(sys.people.power.agent).cancel(id);
      }
    });

    it("BC-GATE-12 view getters expose consistent request data", async function () {
      const sys = await loadFixture(fx);
      const { id, plan, verdict } = await request(sys, IMPACT.High);
      const r = await sys.gate.getRequest(id);
      expect(r.orgId).to.equal(ORG.power);
      expect(r.planHash).to.equal(plan);
      expect(r.criticVerdictDigest).to.equal(verdict);
      expect(r.impact).to.equal(IMPACT.High);
      expect(r.required).to.equal(2);
      expect(r.needsSafety).to.equal(true);
      const [addrs, flags] = await sys.gate.getSnapshotApprovers(id);
      expect(addrs.length).to.equal(3);
      expect(flags[0]).to.equal(true);
    });

    it("BC-GATE-13 constructor rejects zero addresses", async function () {
      const F = await ethers.getContractFactory("ApprovalGate");
      await expect(F.deploy(ethers.ZeroAddress, ethers.ZeroAddress)).to.be.revertedWithCustomError(F, "ZeroAddress");
    });

    it("BC-GATE-15 there is no emergency bypass function in the ABI", async function () {
      const sys = await loadFixture(fx);
      const names = sys.gate.interface.fragments.filter((f: any) => f.type === "function").map((f: any) => f.name.toLowerCase());
      for (const n of names) {
        expect(n).to.not.contain("emergency");
        expect(n).to.not.contain("bypass");
        expect(n).to.not.contain("override");
        expect(n).to.not.contain("force");
      }
    });
  });
});
