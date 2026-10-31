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
    { name: "termsCommitment", type: "bytes32" },
    { name: "disclosureHash", type: "bytes32" },
    { name: "nonce", type: "uint256" },
    { name: "expiry", type: "uint256" },
  ],
};
export const RISK_TYPES = {
  RiskAttestation: [
    { name: "orgId", type: "bytes32" },
    { name: "serviceHash", type: "bytes32" },
    { name: "bandCommitment", type: "bytes32" },
    { name: "disclosureHash", type: "bytes32" },
    { name: "modelVersionHash", type: "bytes32" },
    { name: "evidenceCommitment", type: "bytes32" },
    { name: "validUntil", type: "uint256" },
    { name: "nonce", type: "uint256" },
  ],
};
export const FINDING_TYPES = {
  FindingAttestation: [
    { name: "orgId", type: "bytes32" },
    { name: "advisoryKey", type: "bytes32" },
    { name: "findingCommitment", type: "bytes32" },
    { name: "processedAt", type: "uint256" },
    { name: "nonce", type: "uint256" },
  ],
};

// ---------------------------------------------------------------- confidentiality helpers
// The contracts only ever see commitments + opaque ciphertext. Tests use fixed salts and a dummy "sealed"
// blob (the real envelope is built by backend/common/sealed.py); production salts are random.
const coder = ethers.AbiCoder.defaultAbiCoder();
export const TERMS_SALT = ethers.id("terms-salt");
export const BAND_SALT = ethers.id("band-salt");
export const FINDING_SALT = ethers.id("finding-salt");
export const ALERT_SALT = ethers.id("alert-salt");
export const ORG_SECRET = ethers.id("org-secret");
export const SEALED = ethers.hexlify(ethers.toUtf8Bytes("sealed-envelope"));

export const termsCommitment = (strength: number, tolerance: number, salt = TERMS_SALT) =>
  ethers.keccak256(coder.encode(["bytes32", "uint8", "uint8"], [salt, strength, tolerance]));
export const bandCommitment = (band: number, crit: number, salt = BAND_SALT) =>
  ethers.keccak256(coder.encode(["bytes32", "uint8", "uint8"], [salt, band, crit]));
export const advisoryKey = (advisoryHash: string, secret = ORG_SECRET) =>
  ethers.keccak256(coder.encode(["bytes32", "bytes32"], [secret, advisoryHash]));
export const findingCommitment = (advisoryHash: string, cveHash: string, matched: boolean, salt = FINDING_SALT) =>
  ethers.keccak256(coder.encode(["bytes32", "bytes32", "bytes32", "bool"], [salt, advisoryHash, cveHash, matched]));
export const alertCommitment = (severity: number, tti: number, evidence = ethers.id("ev"), salt = ALERT_SALT) =>
  ethers.keccak256(coder.encode(["bytes32", "uint8", "uint8", "bytes32"], [salt, severity, tti, evidence]));
export const dedupeKey = (serviceHash: string, severity: number, secret = ORG_SECRET) =>
  ethers.keccak256(coder.encode(["bytes32", "bytes32", "uint8"], [secret, serviceHash, severity]));

export interface DepArgs {
  consumerOrg: string;
  consumerServiceHash: string;
  providerOrg: string;
  providerServiceHash: string;
  strength: number;
  tolerance: number;
  expiry: number;
}

export async function submitDep(attestation: any, signer: any, a: DepArgs, nonceOverride?: number, sealed = SEALED) {
  const nonce = nonceOverride ?? Number(await attestation.dependencyNonces(signer.address)) + 1;
  const tc = termsCommitment(a.strength, a.tolerance);
  const value = {
    consumerOrg: a.consumerOrg, consumerServiceHash: a.consumerServiceHash, providerOrg: a.providerOrg,
    providerServiceHash: a.providerServiceHash, termsCommitment: tc, disclosureHash: ethers.keccak256(sealed), nonce, expiry: a.expiry,
  };
  const sig = await signer.signTypedData(await attDomain(attestation), DEP_TYPES, value);
  return attestation
    .connect(signer)
    .submitDependencyAttestation(
      a.consumerOrg, a.consumerServiceHash, a.providerOrg, a.providerServiceHash,
      tc, nonce, a.expiry, sealed, sig
    );
}

export async function submitRisk(
  attestation: any, signer: any, orgId: string, serviceHash: string, band: number, crit: number,
  validUntil: number, evidence = ethers.ZeroHash, nonceOverride?: number, sealed = SEALED
) {
  const nonce = nonceOverride ?? Number(await attestation.riskNonces(signer.address)) + 1;
  const bc = bandCommitment(band, crit);
  const value = {
    orgId, serviceHash, bandCommitment: bc, disclosureHash: ethers.keccak256(sealed),
    modelVersionHash: ethers.id("model-v1"), evidenceCommitment: evidence, validUntil, nonce,
  };
  const sig = await signer.signTypedData(await attDomain(attestation), RISK_TYPES, value);
  return attestation
    .connect(signer)
    .submitRiskAttestation(
      orgId, serviceHash, bc, value.modelVersionHash, evidence, validUntil, nonce, sealed, sig
    );
}

/** Latest risk attestation's id, for verifyBandDisclosure. */
export async function latestRiskId(attestation: any, orgId: string, serviceHash: string) {
  return attestation.latestRiskId(orgId, serviceHash);
}

export async function submitFinding(
  attestation: any, signer: any, orgId: string, advisoryHash: string, cveHash: string,
  processedAt: number, matched: boolean, nonceOverride?: number
) {
  const nonce = nonceOverride ?? Number(await attestation.findingNonces(signer.address)) + 1;
  const key = advisoryKey(advisoryHash);
  const fc = findingCommitment(advisoryHash, cveHash, matched);
  const value = { orgId, advisoryKey: key, findingCommitment: fc, processedAt, nonce };
  const sig = await signer.signTypedData(await attDomain(attestation), FINDING_TYPES, value);
  return attestation
    .connect(signer)
    .submitFindingAttestation(orgId, key, fc, processedAt, nonce, sig);
}

/** Publish an alert with committed (not plaintext) severity/tti. */
export async function publishAlert(
  alertBus: any, signer: any, orgId: string, serviceHash: string, severity: number, tti: number, expiry: number,
  evidence = ethers.id("ev")
) {
  return alertBus
    .connect(signer)
    .publish(orgId, serviceHash, alertCommitment(severity, tti, evidence), dedupeKey(serviceHash, severity), expiry, SEALED);
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
