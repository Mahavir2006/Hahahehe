import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

async function main() {
    console.log("Deploying CascadeShield contracts...");

    const [deployer] = await ethers.getSigners();
    console.log("Deploying with account:", deployer.address);

    // Deploy OrgRegistry first
    console.log("\n1. Deploying OrgRegistry...");
    const OrgRegistry = await ethers.getContractFactory("OrgRegistry");
    const orgRegistry = await OrgRegistry.deploy();
    await orgRegistry.waitForDeployment();
    const orgRegistryAddress = await orgRegistry.getAddress();
    console.log("OrgRegistry deployed to:", orgRegistryAddress);

    // Deploy AuditLog
    console.log("\n2. Deploying AuditLog...");
    const AuditLog = await ethers.getContractFactory("AuditLog");
    const auditLog = await AuditLog.deploy(orgRegistryAddress);
    await auditLog.waitForDeployment();
    const auditLogAddress = await auditLog.getAddress();
    console.log("AuditLog deployed to:", auditLogAddress);

    // Deploy AttestationRegistry
    console.log("\n3. Deploying AttestationRegistry...");
    const AttestationRegistry = await ethers.getContractFactory("AttestationRegistry");
    const attestationRegistry = await AttestationRegistry.deploy(orgRegistryAddress);
    await attestationRegistry.waitForDeployment();
    const attestationRegistryAddress = await attestationRegistry.getAddress();
    console.log("AttestationRegistry deployed to:", attestationRegistryAddress);

    // Deploy FirmwareRegistry
    console.log("\n4. Deploying FirmwareRegistry...");
    const FirmwareRegistry = await ethers.getContractFactory("FirmwareRegistry");
    const firmwareRegistry = await FirmwareRegistry.deploy();
    await firmwareRegistry.waitForDeployment();
    const firmwareRegistryAddress = await firmwareRegistry.getAddress();
    console.log("FirmwareRegistry deployed to:", firmwareRegistryAddress);

    // Deploy ApprovalGate
    console.log("\n5. Deploying ApprovalGate...");
    const ApprovalGate = await ethers.getContractFactory("ApprovalGate");
    const approvalGate = await ApprovalGate.deploy(orgRegistryAddress, auditLogAddress);
    await approvalGate.waitForDeployment();
    const approvalGateAddress = await approvalGate.getAddress();
    console.log("ApprovalGate deployed to:", approvalGateAddress);

    // Deploy AlertBus
    console.log("\n6. Deploying AlertBus...");
    const AlertBus = await ethers.getContractFactory("AlertBus");
    const alertBus = await AlertBus.deploy(orgRegistryAddress, attestationRegistryAddress);
    await alertBus.waitForDeployment();
    const alertBusAddress = await alertBus.getAddress();
    console.log("AlertBus deployed to:", alertBusAddress);

    // Save deployment info
    const deployment = {
        network: "localhost",
        chainId: 31337,
        deployer: deployer.address,
        timestamp: new Date().toISOString(),
        contracts: {
            OrgRegistry: orgRegistryAddress,
            AuditLog: auditLogAddress,
            AttestationRegistry: attestationRegistryAddress,
            FirmwareRegistry: firmwareRegistryAddress,
            ApprovalGate: approvalGateAddress,
            AlertBus: alertBusAddress,
        },
    };

    const deploymentsDir = path.join(__dirname, "../deployments");
    if (!fs.existsSync(deploymentsDir)) {
        fs.mkdirSync(deploymentsDir, { recursive: true });
    }

    const deploymentPath = process.env.DEPLOYMENT_FILE || path.join(deploymentsDir, "local.json");
    fs.writeFileSync(deploymentPath, JSON.stringify(deployment, null, 2));
    console.log("\nDeployment saved to:", deploymentPath);

    // Verify all contracts
    console.log("\nVerifying contracts...");
    const contracts = [
        { name: "OrgRegistry", address: orgRegistryAddress },
        { name: "AuditLog", address: auditLogAddress },
        { name: "AttestationRegistry", address: attestationRegistryAddress },
        { name: "FirmwareRegistry", address: firmwareRegistryAddress },
        { name: "ApprovalGate", address: approvalGateAddress },
        { name: "AlertBus", address: alertBusAddress },
    ];

    for (const c of contracts) {
        const code = await ethers.provider.getCode(c.address);
        if (code === "0x") {
            console.error(`ERROR: ${c.name} at ${c.address} has no code!`);
            process.exit(1);
        }
        console.log(`${c.name}: OK`);
    }

    console.log("\n✅ All contracts deployed successfully!");
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});