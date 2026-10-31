import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * Seeds a freshly deployed chain:
 *  - funds the dev keys for every org (admin, agent signer, approvers)
 *  - registers the three orgs (first approver is the safety officer, threshold 2)
 *  - registers one vendor address per firmware vendor and publishes the firmware catalog
 * Any failure aborts the script (no silent catches).
 */
async function setBalance(addr: string, ether: string) {
    await network.provider.send("hardhat_setBalance", [addr, "0x" + ethers.parseEther(ether).toString(16)]);
}

async function main() {
    const deploymentPath = process.env.DEPLOYMENT_FILE || path.join(__dirname, "../deployments/local.json");
    if (!fs.existsSync(deploymentPath)) throw new Error("Deployment file not found. Run deploy first.");
    const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf-8"));
    const dataDir = path.join(__dirname, "../../data");

    const orgRegistry = await ethers.getContractAt("OrgRegistry", deployment.contracts.OrgRegistry);
    const attestationRegistry = await ethers.getContractAt("AttestationRegistry", deployment.contracts.AttestationRegistry);
    const firmwareRegistry = await ethers.getContractAt("FirmwareRegistry", deployment.contracts.FirmwareRegistry);

    const orgs = [
        { id: "power", name: "Grid Utility", sector: 0 },
        { id: "water", name: "Water Board", sector: 1 },
        { id: "hospital", name: "City Hospital", sector: 2 },
    ];

    for (const org of orgs) {
        const keys = JSON.parse(fs.readFileSync(path.join(dataDir, "orgs", org.id, "private_keys.dev.json"), "utf-8"));
        const addrs: string[] = [keys.admin.address, keys.agent_signer.address, ...keys.approvers.map((a: any) => a.address)];
        for (const a of addrs) await setBalance(a, "1000");

        const orgId = ethers.id(org.id);
        const existing = await orgRegistry.isOrgActive(orgId);
        if (existing) {
            console.log(`  ${org.id}: already registered`);
            continue;
        }
        await (
            await orgRegistry.registerOrg(
                orgId,
                ethers.id(org.name),
                org.sector,
                keys.admin.address,
                keys.agent_signer.address,
                keys.approvers.map((a: any) => a.address),
                2,
                keys.approvers.map((_: any, i: number) => i === 0)
            )
        ).wait();
        console.log(`  ${org.id}: registered`);
    }

    // Vendors + firmware catalog
    const catalog = JSON.parse(fs.readFileSync(path.join(dataDir, "firmware_catalog.json"), "utf-8"));
    const vendorWallets: Record<string, any> = {};
    const vendors = Array.from(new Set(catalog.map((e: any) => e.vendor))) as string[];
    for (const v of vendors) {
        const wallet = new ethers.Wallet(ethers.id("vendor-key-" + v), ethers.provider);
        await setBalance(wallet.address, "100");
        await (await firmwareRegistry.addVendor(ethers.id(v), wallet.address)).wait();
        vendorWallets[v] = wallet;
    }
    let published = 0;
    for (const e of catalog) {
        const fw = firmwareRegistry.connect(vendorWallets[e.vendor]) as any;
        await (
            await fw.publishFirmware(
                ethers.id(e.vendor),
                ethers.id(e.model),
                ethers.id(e.version),
                e.firmware_sha256,
                e.sbom_hash,
                Math.floor(new Date(e.release_date).getTime() / 1000)
            )
        ).wait();
        published++;
    }
    console.log(`  firmware: ${vendors.length} vendors, ${published} entries`);

    await (await attestationRegistry.setRiskAttestationMinInterval(1)).wait();
    console.log("Seeding complete");
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
