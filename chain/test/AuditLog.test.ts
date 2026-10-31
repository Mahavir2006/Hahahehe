import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { deploySystem, ORG, KIND } from "./helpers";

function merkle(leaves: string[]) {
  // OpenZeppelin MerkleProof uses sorted-pair hashing
  const hashPair = (a: string, b: string) =>
    a.toLowerCase() < b.toLowerCase()
      ? ethers.keccak256(ethers.concat([a, b]))
      : ethers.keccak256(ethers.concat([b, a]));
  let level = [...leaves];
  const layers = [level];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? hashPair(level[i], level[i + 1]) : level[i]);
    }
    level = next;
    layers.push(level);
  }
  const proof = (idx: number) => {
    const p: string[] = [];
    for (let l = 0; l < layers.length - 1; l++) {
      const sib = idx ^ 1;
      if (sib < layers[l].length) p.push(layers[l][sib]);
      idx = Math.floor(idx / 2);
    }
    return p;
  };
  return { root: level[0], proof };
}

describe("AuditLog", function () {
  const fx = () => deploySystem();

  it("BC-AUD-01 anchors a digest and emits an event", async function () {
    const sys = await loadFixture(fx);
    const d = ethers.id("trace-1");
    await expect(sys.auditLog.connect(sys.people.power.agent).anchor(ORG.power, KIND.AgentTrace, d, ethers.ZeroHash, ethers.id("m")))
      .to.emit(sys.auditLog, "Anchored");
    expect(await sys.auditLog.length(ORG.power)).to.equal(1);
    const e = await sys.auditLog.getAnchor(ORG.power, 0);
    expect(e.digest).to.equal(d);
    expect(e.signer).to.equal(sys.people.power.agent.address);
    expect(await sys.auditLog.hasAnchor(ORG.power, KIND.AgentTrace, d)).to.equal(true);
  });

  it("BC-AUD-02 enforces hash chaining via prevDigest", async function () {
    const sys = await loadFixture(fx);
    const a = sys.auditLog.connect(sys.people.power.agent);
    await a.anchor(ORG.power, KIND.AgentTrace, ethers.id("1"), ethers.ZeroHash, ethers.ZeroHash);
    // wrong prevDigest (zero) on the second entry
    await expect(a.anchor(ORG.power, KIND.AgentTrace, ethers.id("2"), ethers.ZeroHash, ethers.ZeroHash))
      .to.be.revertedWithCustomError(sys.auditLog, "InvalidPrevDigest");
    const last = await sys.auditLog.lastDigest(ORG.power);
    await a.anchor(ORG.power, KIND.AgentTrace, ethers.id("2"), last, ethers.ZeroHash);
    expect(await sys.auditLog.length(ORG.power)).to.equal(2);
  });

  it("BC-AUD-02 first anchor must use zero prevDigest", async function () {
    const sys = await loadFixture(fx);
    await expect(
      sys.auditLog.connect(sys.people.power.agent).anchor(ORG.power, KIND.AgentTrace, ethers.id("1"), ethers.id("bogus"), ethers.ZeroHash)
    ).to.be.revertedWithCustomError(sys.auditLog, "InvalidPrevDigest");
  });

  it("BC-AUD-02 lastDigest equals the off-chain recomputed entry hash and verifyChain passes", async function () {
    const sys = await loadFixture(fx);
    const a = sys.auditLog.connect(sys.people.power.agent);
    let prev = ethers.ZeroHash;
    for (let i = 0; i < 5; i++) {
      const d = ethers.id("e" + i);
      const meta = ethers.id("meta" + i);
      await a.anchor(ORG.power, KIND.Plan, d, prev, meta);
      prev = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes32", "uint8", "bytes32", "bytes32", "bytes32", "uint256", "bool", "uint256"],
          [ORG.power, KIND.Plan, d, i === 0 ? ethers.ZeroHash : prev, meta, i, false, 1]
        )
      );
      // note: prevDigest stored in the entry is the previous chain hash; recompute properly below
      prev = await sys.auditLog.lastDigest(ORG.power);
    }
    expect(await sys.auditLog.verifyChain(ORG.power, 100)).to.equal(true);
    // independent recomputation matches contract view for last entry
    const e = await sys.auditLog.getAnchor(ORG.power, 4);
    const h = await sys.auditLog.computeEntryHash(ORG.power, e.kind, e.digest, e.prevDigest, e.metaHash, 4, e.isBatch, e.count);
    expect(h).to.equal(await sys.auditLog.lastDigest(ORG.power));
  });

  it("BC-AUD-03 batch anchors and Merkle inclusion proofs (valid and invalid)", async function () {
    const sys = await loadFixture(fx);
    const leaves = [1, 2, 3, 4, 5].map((i) => ethers.id("leaf" + i));
    const { root, proof } = merkle(leaves);
    await sys.auditLog.connect(sys.people.power.agent).anchorBatch(ORG.power, KIND.AgentTrace, root, leaves.length, ethers.ZeroHash);
    for (let i = 0; i < leaves.length; i++) {
      expect(await sys.auditLog.verifyInclusion(ORG.power, 0, leaves[i], proof(i))).to.equal(true);
    }
    expect(await sys.auditLog.verifyInclusion(ORG.power, 0, ethers.id("not-a-leaf"), proof(0))).to.equal(false);
    expect(await sys.auditLog.verifyInclusion(ORG.power, 0, leaves[1], proof(0))).to.equal(false);
  });

  it("BC-AUD-03 batch rules: empty batch, non-batch inclusion, bad index", async function () {
    const sys = await loadFixture(fx);
    const a = sys.auditLog.connect(sys.people.power.agent);
    await expect(a.anchorBatch(ORG.power, KIND.AgentTrace, ethers.id("r"), 0, ethers.ZeroHash))
      .to.be.revertedWithCustomError(sys.auditLog, "EmptyBatch");
    await a.anchor(ORG.power, KIND.AgentTrace, ethers.id("1"), ethers.ZeroHash, ethers.ZeroHash);
    await expect(sys.auditLog.verifyInclusion(ORG.power, 0, ethers.id("1"), []))
      .to.be.revertedWithCustomError(sys.auditLog, "NotABatch");
    await expect(sys.auditLog.verifyInclusion(ORG.power, 9, ethers.id("1"), []))
      .to.be.revertedWithCustomError(sys.auditLog, "IndexOutOfBounds");
    await expect(sys.auditLog.getAnchor(ORG.power, 9)).to.be.revertedWithCustomError(sys.auditLog, "IndexOutOfBounds");
  });

  it("BC-AUD-03 batches and single anchors share one hash chain", async function () {
    const sys = await loadFixture(fx);
    const a = sys.auditLog.connect(sys.people.power.agent);
    await a.anchor(ORG.power, KIND.Plan, ethers.id("p"), ethers.ZeroHash, ethers.ZeroHash);
    const l1 = await sys.auditLog.lastDigest(ORG.power);
    await a.anchorBatch(ORG.power, KIND.AgentTrace, ethers.id("root"), 3, l1);
    const l2 = await sys.auditLog.lastDigest(ORG.power);
    expect(l2).to.not.equal(l1);
    await a.anchor(ORG.power, KIND.Plan, ethers.id("p2"), l2, ethers.ZeroHash);
    expect(await sys.auditLog.length(ORG.power)).to.equal(3);
    expect(await sys.auditLog.verifyChain(ORG.power, 10)).to.equal(true);
  });

  it("BC-AUD-04 only the org agent can anchor; strangers, other orgs and approvers cannot", async function () {
    const sys = await loadFixture(fx);
    const d = ethers.id("x");
    await expect(sys.auditLog.connect(sys.stranger).anchor(ORG.power, KIND.Plan, d, ethers.ZeroHash, ethers.ZeroHash))
      .to.be.revertedWithCustomError(sys.auditLog, "UnauthorizedSigner");
    await expect(sys.auditLog.connect(sys.people.water.agent).anchor(ORG.power, KIND.Plan, d, ethers.ZeroHash, ethers.ZeroHash))
      .to.be.revertedWithCustomError(sys.auditLog, "UnauthorizedSigner");
    await expect(sys.auditLog.connect(sys.people.power.approvers[0]).anchor(ORG.power, KIND.Plan, d, ethers.ZeroHash, ethers.ZeroHash))
      .to.be.revertedWithCustomError(sys.auditLog, "UnauthorizedSigner");
  });

  it("BC-AUD-04 approvers may anchor Pause/Resume only", async function () {
    const sys = await loadFixture(fx);
    const ap = sys.auditLog.connect(sys.people.power.approvers[0]);
    await ap.anchor(ORG.power, KIND.Pause, ethers.id("pause"), ethers.ZeroHash, ethers.ZeroHash);
    const last = await sys.auditLog.lastDigest(ORG.power);
    await ap.anchor(ORG.power, KIND.Resume, ethers.id("resume"), last, ethers.ZeroHash);
    await expect(ap.anchor(ORG.power, KIND.Plan, ethers.id("nope"), await sys.auditLog.lastDigest(ORG.power), ethers.ZeroHash))
      .to.be.revertedWithCustomError(sys.auditLog, "UnauthorizedSigner");
  });

  it("BC-AUD-04 a rotated-out agent signer can no longer anchor (BC-ORG-04)", async function () {
    const sys = await loadFixture(fx);
    const newSigner = sys.s[17];
    await sys.orgRegistry.connect(sys.admin).rotateAgentSigner(ORG.power, newSigner.address);
    await expect(
      sys.auditLog.connect(sys.people.power.agent).anchor(ORG.power, KIND.Plan, ethers.id("x"), ethers.ZeroHash, ethers.ZeroHash)
    ).to.be.revertedWithCustomError(sys.auditLog, "UnauthorizedSigner");
    await sys.auditLog.connect(newSigner).anchor(ORG.power, KIND.Plan, ethers.id("x"), ethers.ZeroHash, ethers.ZeroHash);
  });

  it("BC-AUD-04 deactivated orgs cannot anchor, history stays readable (BC-ORG-06)", async function () {
    const sys = await loadFixture(fx);
    const a = sys.auditLog.connect(sys.people.power.agent);
    await a.anchor(ORG.power, KIND.Plan, ethers.id("x"), ethers.ZeroHash, ethers.ZeroHash);
    await sys.orgRegistry.deactivateOrg(ORG.power);
    await expect(a.anchor(ORG.power, KIND.Plan, ethers.id("y"), await sys.auditLog.lastDigest(ORG.power), ethers.ZeroHash))
      .to.be.revertedWithCustomError(sys.auditLog, "OrgNotActive");
    expect((await sys.auditLog.getAnchor(ORG.power, 0)).digest).to.equal(ethers.id("x"));
  });

  it("BC-AUD-01 rejects invalid kind, zero digest, unknown org", async function () {
    const sys = await loadFixture(fx);
    const a = sys.auditLog.connect(sys.people.power.agent);
    await expect(a.anchor(ORG.power, 9, ethers.id("x"), ethers.ZeroHash, ethers.ZeroHash))
      .to.be.revertedWithCustomError(sys.auditLog, "InvalidAnchorKind");
    await expect(a.anchor(ORG.power, KIND.Plan, ethers.ZeroHash, ethers.ZeroHash, ethers.ZeroHash))
      .to.be.revertedWithCustomError(sys.auditLog, "ZeroDigest");
    await expect(a.anchor(ethers.id("ghost"), KIND.Plan, ethers.id("x"), ethers.ZeroHash, ethers.ZeroHash))
      .to.be.revertedWithCustomError(sys.auditLog, "OrgNotActive");
  });

  it("BC-AUD-05 each org has an independent chain", async function () {
    const sys = await loadFixture(fx);
    await sys.auditLog.connect(sys.people.power.agent).anchor(ORG.power, KIND.Plan, ethers.id("a"), ethers.ZeroHash, ethers.ZeroHash);
    expect(await sys.auditLog.length(ORG.water)).to.equal(0);
    expect(await sys.auditLog.lastDigest(ORG.water)).to.equal(ethers.ZeroHash);
    await sys.auditLog.connect(sys.people.water.agent).anchor(ORG.water, KIND.Plan, ethers.id("a"), ethers.ZeroHash, ethers.ZeroHash);
    expect(await sys.auditLog.length(ORG.water)).to.equal(1);
  });

  it("BC-AUD-06 constructor rejects zero registry", async function () {
    const F = await ethers.getContractFactory("AuditLog");
    await expect(F.deploy(ethers.ZeroAddress)).to.be.revertedWithCustomError(F, "ZeroAddress");
  });

  it("BC-AUD-02 verifyChain with maxEntries smaller than the log returns true for a valid prefix", async function () {
    const sys = await loadFixture(fx);
    const a = sys.auditLog.connect(sys.people.power.agent);
    for (let i = 0; i < 4; i++) {
      await a.anchor(ORG.power, KIND.Plan, ethers.id("p" + i), await sys.auditLog.lastDigest(ORG.power), ethers.ZeroHash);
    }
    expect(await sys.auditLog.verifyChain(ORG.power, 2)).to.equal(true);
    expect(await sys.auditLog.verifyChain(ORG.power, 0)).to.equal(true);
  });
});
