import { ethers } from "hardhat";
import { HDNodeWallet } from "ethers";

export const ORG = {
  power: ethers.id("power"),
  water: ethers.id("water"),
  hospital: ethers.id("hospital"),
};

export const KIND = {
  AgentTrace: 0,
  RiskSnapshot: 1,
  Plan: 2,
  CriticVerdict: 3,
  Execution: 4,
  Pause: 5,
  Resume: 6,
  ModelVersion: 7,
  Policy: 8,
};

export const IMPACT = { Low: 0, Medium: 1, High: 2 };
export const STATUS = { None: 0, Pending: 1, Approved: 2, Rejected: 3, Expired: 4, Executed: 5, Cancelled: 6 };

export async function deploySystem() {
  const s = await ethers.getSigners();
  const [deployer, admin] = s;
  const people = {
    power: { agent: s[2], approvers: [s[3], s[4], s[5]] },
    water: { agent: s[6], approvers: [s[7], s[8], s[9]] },
    hospital: { agent: s[10], approvers: [s[11], s[12], s[13]] },
  };
  const vendor = s[14];
  const stranger = s[15];
  const relayer = s[16];

  const orgRegistry = await (await ethers.getContractFactory("OrgRegistry")).deploy();
  const auditLog = await (await ethers.getContractFactory("AuditLog")).deploy(await orgRegistry.getAddress());
  const attestation = await (await ethers.getContractFactory("AttestationRegistry")).deploy(await orgRegistry.getAddress());
  const firmware = await (await ethers.getContractFactory("FirmwareRegistry")).deploy();
  const gate = await (await ethers.getContractFactory("ApprovalGate")).deploy(
    await orgRegistry.getAddress(),
    await auditLog.getAddress()
  );
  const alertBus = await (await ethers.getContractFactory("AlertBus")).deploy(
    await orgRegistry.getAddress(),
    await attestation.getAddress()
  );

  let sector = 0;
  for (const name of ["power", "water", "hospital"] as const) {
    const p = people[name];
    await orgRegistry.registerOrg(
      ORG[name],
      ethers.id(name + "-name"),
      sector++,
      admin.address,
      p.agent.address,
      p.approvers.map((a) => a.address),
      2,
      [true, false, false]
    );
  }

  return { s, deployer, admin, people, vendor, stranger, relayer, orgRegistry, auditLog, attestation, firmware, gate, alertBus };
}

export async function attDomain(attestation: any) {
  return {
    name: "AttestationRegistry",
    version: "1",
    chainId: 31337,
    verifyingContract: await attestation.getAddress(),
  };
}

export const DEP_TYPES = {
  DependencyAttestation: [
    { name: "consumerOrg", type: "bytes32" },
    { name: "consumerServiceHash", type: "bytes32" },
    { name: "providerOrg", type: "bytes32" },
    { name: "providerServiceHash", type: "bytes32" },
    { name: "strength", type: "uint8" },
    { name: "tolerance", type: "uint8" },
    { name: "nonce", type: "uint256" },
    { name: "expiry", type: "uint256" },
  ],
};
export const RISK_TYPES = {
  RiskAttestation: [
    { name: "orgId", type: "bytes32" },
    { name: "serviceHash", type: "bytes32" },
    { name: "riskBand", type: "uint8" },
    { name: "criticalityBucket", type: "uint8" },
    { name: "modelVersionHash", type: "bytes32" },
    { name: "evidenceCommitment", type: "bytes32" },
    { name: "validUntil", type: "uint256" },
    { name: "nonce", type: "uint256" },
  ],
};
export const FINDING_TYPES = {
  FindingAttestation: [
    { name: "orgId", type: "bytes32" },
    { name: "advisoryContentHash", type: "bytes32" },
    { name: "cveSetHash", type: "bytes32" },
    { name: "processedAt", type: "uint256" },
    { name: "matched", type: "bool" },
    { name: "nonce", type: "uint256" },
  ],
};

export interface DepArgs {
  consumerOrg: string;
  consumerServiceHash: string;
  providerOrg: string;
  providerServiceHash: string;
  strength: number;
  tolerance: number;
  expiry: number;
}

export async function submitDep(attestation: any, signer: any, a: DepArgs, nonceOverride?: number) {
  const nonce = nonceOverride ?? Number(await attestation.dependencyNonces(signer.address)) + 1;
  const value = { ...a, nonce };
  const sig = await signer.signTypedData(await attDomain(attestation), DEP_TYPES, value);
  return attestation
    .connect(signer)
    .submitDependencyAttestation(
      a.consumerOrg, a.consumerServiceHash, a.providerOrg, a.providerServiceHash,
      a.strength, a.tolerance, nonce, a.expiry, sig
    );
}

export async function submitRisk(
  attestation: any, signer: any, orgId: string, serviceHash: string, band: number, crit: number,
  validUntil: number, evidence = ethers.ZeroHash, nonceOverride?: number
) {
  const nonce = nonceOverride ?? Number(await attestation.riskNonces(signer.address)) + 1;
  const value = {
    orgId, serviceHash, riskBand: band, criticalityBucket: crit,
    modelVersionHash: ethers.id("model-v1"), evidenceCommitment: evidence, validUntil, nonce,
  };
  const sig = await signer.signTypedData(await attDomain(attestation), RISK_TYPES, value);
  return attestation
    .connect(signer)
    .submitRiskAttestation(
      orgId, serviceHash, band, crit, value.modelVersionHash, evidence, validUntil, nonce, sig
    );
}

export async function submitFinding(
  attestation: any, signer: any, orgId: string, advisoryHash: string, cveHash: string,
  processedAt: number, matched: boolean, nonceOverride?: number
) {
  const nonce = nonceOverride ?? Number(await attestation.findingNonces(signer.address)) + 1;
  const value = { orgId, advisoryContentHash: advisoryHash, cveSetHash: cveHash, processedAt, matched, nonce };
  const sig = await signer.signTypedData(await attDomain(attestation), FINDING_TYPES, value);
  return attestation
    .connect(signer)
    .submitFindingAttestation(orgId, advisoryHash, cveHash, processedAt, matched, nonce, sig);
}

export async function futureTs(seconds: number) {
  const b = await ethers.provider.getBlock("latest");
  return Number(b!.timestamp) + seconds;
}

/** Anchor a critic verdict for `org` and return its digest. */
export async function anchorCritic(sys: any, org: "power" | "water" | "hospital", label: string) {
  const digest = ethers.id("critic-" + label);
  const prev = await sys.auditLog.lastDigest(ORG[org]);
  await sys.auditLog.connect(sys.people[org].agent).anchor(ORG[org], KIND.CriticVerdict, digest, prev, ethers.ZeroHash);
  return digest;
}

/** Confirm a bilateral dependency edge consumer(svc c) -> provider(svc p). */
export async function confirmEdge(
  sys: any, consumer: "power" | "water" | "hospital", provider: "power" | "water" | "hospital",
  cSvc: string, pSvc: string, strength = 2, tolerance = 1, ttl = 100000
) {
  const expiry = await futureTs(ttl);
  const a: DepArgs = {
    consumerOrg: ORG[consumer], consumerServiceHash: cSvc,
    providerOrg: ORG[provider], providerServiceHash: pSvc, strength, tolerance, expiry,
  };
  await submitDep(sys.attestation, sys.people[consumer].agent, a);
  await submitDep(sys.attestation, sys.people[provider].agent, a);
  return a;
}

export function randomWallet(): HDNodeWallet {
  return ethers.Wallet.createRandom();
}
