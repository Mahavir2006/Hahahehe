"""
Chain client for interacting with CascadeShield smart contracts.
"""

import asyncio
import json
import time
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass
from web3 import Web3
from web3.contract import Contract
from web3.types import TxParams, TxReceipt
from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data
from eth_typing import HexStr
import logging

from .config import settings
from .schemas import *

logger = logging.getLogger(__name__)


@dataclass
class ChainError(Exception):
    """Chain interaction error with error code."""
    code: str
    message: str
    tx_hash: Optional[str] = None


class ChainClient:
    """High-level client for interacting with CascadeShield contracts."""
    
    def __init__(self, rpc_url: Optional[str] = None, private_key: Optional[str] = None):
        self.rpc_url = rpc_url or settings.chain_rpc_url
        self.w3 = Web3(Web3.HTTPProvider(
            self.rpc_url,
            request_kwargs={"timeout": settings.chain_request_timeout}
        ))
        
        # Load deployment addresses
        self.deployment = self._load_deployment()
        
        # Initialize contracts
        self._init_contracts()
        
        # Account setup
        self.account = None
        if private_key:
            self.account = Account.from_key(private_key)
        elif settings.anthropic_api_key:  # fallback to env
            pass
        
        # Nonce management
        self._nonce_lock = asyncio.Lock()
        self._pending_nonce: Optional[int] = None
        
    def _load_deployment(self) -> dict:
        import os
        if os.path.exists(settings.deployment_file):
            with open(settings.deployment_file, "r") as f:
                return json.load(f)
        return {}
    
    def _init_contracts(self):
        """Initialize contract instances."""
        contracts_config = self.deployment.get("contracts", {})
        
        # Load ABIs from artifacts
        import os
        artifacts_dir = "chain/artifacts/contracts"
        
        def load_abi(contract_name: str):
            path = os.path.join(artifacts_dir, f"{contract_name}.sol", f"{contract_name}.json")
            if os.path.exists(path):
                with open(path, "r") as f:
                    data = json.load(f)
                    return data["abi"]
            return []
        
        self.org_registry = self.w3.eth.contract(
            address=contracts_config.get("OrgRegistry"),
            abi=load_abi("OrgRegistry")
        )
        
        self.attestation_registry = self.w3.eth.contract(
            address=contracts_config.get("AttestationRegistry"),
            abi=load_abi("AttestationRegistry")
        )
        
        self.audit_log = self.w3.eth.contract(
            address=contracts_config.get("AuditLog"),
            abi=load_abi("AuditLog")
        )
        
        self.approval_gate = self.w3.eth.contract(
            address=contracts_config.get("ApprovalGate"),
            abi=load_abi("ApprovalGate")
        )
        
        self.firmware_registry = self.w3.eth.contract(
            address=contracts_config.get("FirmwareRegistry"),
            abi=load_abi("FirmwareRegistry")
        )
        
        self.alert_bus = self.w3.eth.contract(
            address=contracts_config.get("AlertBus"),
            abi=load_abi("AlertBus")
        )
    
    def set_account(self, private_key: str):
        """Set the signing account."""
        self.account = Account.from_key(private_key)
    
    async def _get_nonce(self) -> int:
        """Get next nonce with thread safety."""
        async with self._nonce_lock:
            if self._pending_nonce is None:
                self._pending_nonce = self.w3.eth.get_transaction_count(self.account.address)
            nonce = self._pending_nonce
            self._pending_nonce += 1
            return nonce
    
    async def _send_transaction(self, tx_params: TxParams) -> TxReceipt:
        """Send transaction with retry logic."""
        if not self.account:
            raise ChainError("NO_ACCOUNT", "No signing account configured")
        
        for attempt in range(settings.chain_max_retries):
            try:
                # Estimate gas
                gas_estimate = self.w3.eth.estimate_gas(tx_params)
                tx_params["gas"] = int(gas_estimate * settings.gas_limit_multiplier)
                
                # Set gas price
                base_fee = self.w3.eth.gas_price
                tx_params["maxFeePerGas"] = int(base_fee * settings.gas_price_multiplier)
                tx_params["maxPriorityFeePerGas"] = int(base_fee * 0.1)
                
                # Sign and send
                signed = self.account.sign_transaction(tx_params)
                tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)
                
                # Wait for receipt
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
                
                if receipt.status != 1:
                    raise ChainError("TX_FAILED", f"Transaction failed: {tx_hash.hex()}", tx_hash.hex())
                
                return receipt
                
            except Exception as e:
                if attempt == settings.chain_max_retries - 1:
                    raise ChainError("TX_ERROR", f"Transaction failed after retries: {str(e)}")
                await asyncio.sleep(settings.chain_retry_backoff_base ** attempt)
        
        raise ChainError("TX_ERROR", "Max retries exceeded")
    
    # =========================================================================
    # OrgRegistry Methods
    # =========================================================================
    
    def is_org_agent(self, org_id: bytes, address: str) -> bool:
        return self.org_registry.functions.isOrgAgent(org_id, address).call()
    
    def is_org_approver(self, org_id: bytes, address: str) -> bool:
        return self.org_registry.functions.isOrgApprover(org_id, address).call()
    
    def get_org(self, org_id: bytes) -> Dict[str, Any]:
        org = self.org_registry.functions.getOrg(org_id).call()
        return {
            "org_id": org[0].hex(),
            "name_hash": org[1].hex(),
            "sector": org[2],
            "admin_address": org[3],
            "agent_signer": org[4],
            "approvers": org[5],
            "threshold": org[6],
            "active": org[7],
            "created_at": org[8],
            "updated_at": org[9],
        }
    
    def get_approvers(self, org_id: bytes) -> List[Dict[str, Any]]:
        approvers = self.org_registry.functions.getApprovers(org_id).call()
        return [{"addr": a[0], "is_safety_officer": a[1]} for a in approvers]
    
    def get_threshold(self, org_id: bytes) -> int:
        return self.org_registry.functions.getThreshold(org_id).call()
    
    # =========================================================================
    # AttestationRegistry Methods
    # =========================================================================
    
    def submit_dependency_attestation(
        self,
        consumer_org: bytes,
        consumer_service_hash: bytes,
        provider_org: bytes,
        provider_service_hash: bytes,
        strength: int,
        tolerance: int,
        nonce: int,
        expiry: int,
        signature: bytes
    ) -> TxReceipt:
        tx = self.attestation_registry.functions.submitDependencyAttestation(
            consumer_org, consumer_service_hash, provider_org, provider_service_hash,
            strength, tolerance, nonce, expiry, signature
        ).build_transaction({"from": self.account.address})
        return asyncio.run(self._send_transaction(tx))
    
    def submit_risk_attestation(
        self,
        org_id: bytes,
        service_hash: bytes,
        risk_band: int,
        criticality_bucket: int,
        model_version_hash: bytes,
        evidence_commitment: bytes,
        valid_until: int,
        nonce: int,
        signature: bytes
    ) -> TxReceipt:
        tx = self.attestation_registry.functions.submitRiskAttestation(
            org_id, service_hash, risk_band, criticality_bucket,
            model_version_hash, evidence_commitment, valid_until, nonce, signature
        ).build_transaction({"from": self.account.address})
        return asyncio.run(self._send_transaction(tx))
    
    def submit_finding_attestation(
        self,
        org_id: bytes,
        advisory_content_hash: bytes,
        cve_set_hash: bytes,
        processed_at: int,
        matched: bool,
        nonce: int,
        signature: bytes
    ) -> TxReceipt:
        tx = self.attestation_registry.functions.submitFindingAttestation(
            org_id, advisory_content_hash, cve_set_hash, processed_at, matched, nonce, signature
        ).build_transaction({"from": self.account.address})
        return asyncio.run(self._send_transaction(tx))
    
    def is_edge_confirmed(
        self,
        consumer_org: bytes,
        consumer_service_hash: bytes,
        provider_org: bytes,
        provider_service_hash: bytes
    ) -> bool:
        return self.attestation_registry.functions.isEdgeConfirmed(
            consumer_org, consumer_service_hash, provider_org, provider_service_hash
        ).call()
    
    def get_latest_risk_attestation(self, org_id: bytes, service_hash: bytes) -> Dict[str, Any]:
        attestation = self.attestation_registry.functions.getLatestRiskAttestation(org_id, service_hash).call()
        return {
            "org_id": attestation[0].hex(),
            "service_hash": attestation[1].hex(),
            "risk_band": attestation[2],
            "criticality_bucket": attestation[3],
            "model_version_hash": attestation[4].hex(),
            "evidence_commitment": attestation[5].hex(),
            "valid_until": attestation[6],
            "nonce": attestation[7],
            "signer": attestation[8],
            "timestamp": attestation[9],
        }
    
    # =========================================================================
    # AuditLog Methods
    # =========================================================================
    
    def anchor(
        self,
        org_id: bytes,
        kind: int,
        digest: bytes,
        prev_digest: bytes,
        meta_hash: bytes,
        signature: bytes
    ) -> TxReceipt:
        tx = self.audit_log.functions.anchor(
            org_id, kind, digest, prev_digest, meta_hash, signature
        ).build_transaction({"from": self.account.address})
        return asyncio.run(self._send_transaction(tx))
    
    def anchor_batch(
        self,
        org_id: bytes,
        kind: int,
        merkle_root: bytes,
        count: int,
        prev_digest: bytes,
        signature: bytes
    ) -> TxReceipt:
        tx = self.audit_log.functions.anchorBatch(
            org_id, kind, merkle_root, count, prev_digest, signature
        ).build_transaction({"from": self.account.address})
        return asyncio.run(self._send_transaction(tx))
    
    def get_anchor(self, org_id: bytes, index: int) -> Dict[str, Any]:
        anchor = self.audit_log.functions.getAnchor(org_id, index).call()
        return {
            "org_id": anchor[0].hex(),
            "kind": anchor[1],
            "digest": anchor[1].hex(),
            "prev_digest": anchor[3].hex(),
            "meta_hash": anchor[4].hex(),
            "index": anchor[5],
            "timestamp": anchor[6],
            "signer": anchor[7],
        }
    
    def get_last_digest(self, org_id: bytes) -> bytes:
        return self.audit_log.functions.getLastDigest(org_id).call()
    
    def verify_inclusion(self, org_id: bytes, batch_index: int, leaf: bytes, proof: List[bytes]) -> bool:
        return self.audit_log.functions.verifyInclusion(org_id, batch_index, leaf, proof).call()
    
    # =========================================================================
    # ApprovalGate Methods
    # =========================================================================
    
    def request_approval(
        self,
        org_id: bytes,
        plan_hash: bytes,
        step_ids: List[int],
        impact_class: int,
        expiry: int,
        critic_verdict_digest: bytes,
        signature: bytes
    ) -> TxReceipt:
        tx = self.approval_gate.functions.requestApproval(
            org_id, plan_hash, step_ids, impact_class, expiry, critic_verdict_digest, signature
        ).build_transaction({"from": self.account.address})
        return asyncio.run(self._send_transaction(tx))
    
    def approve(self, request_id: bytes, signature: bytes) -> TxReceipt:
        tx = self.approval_gate.functions.approve(request_id, signature).build_transaction({"from": self.account.address})
        return asyncio.run(self._send_transaction(tx))
    
    def reject(self, request_id: bytes, signature: bytes) -> TxReceipt:
        tx = self.approval_gate.functions.reject(request_id, signature).build_transaction({"from": self.account.address})
        return asyncio.run(self._send_transaction(tx))
    
    def mark_executed(self, request_id: bytes, execution_digest: bytes, signature: bytes) -> TxReceipt:
        tx = self.approval_gate.functions.markExecuted(request_id, execution_digest, signature).build_transaction({"from": self.account.address})
        return asyncio.run(self._send_transaction(tx))
    
    def get_request(self, request_id: bytes) -> Dict[str, Any]:
        request = self.approval_gate.functions.getRequest(request_id).call()
        return {
            "request_id": request[0].hex(),
            "org_id": request[1].hex(),
            "plan_hash": request[2].hex(),
            "step_ids": request[3],
            "impact_class": request[4],
            "expiry": request[5],
            "critic_verdict_digest": request[6].hex(),
            "state": request[7],
            "created_at": request[8],
            "executed_at": request[9],
        }
    
    def get_request_state(self, request_id: bytes) -> int:
        return self.approval_gate.functions.getRequestState(request_id).call()
    
    # =========================================================================
    # FirmwareRegistry Methods
    # =========================================================================
    
    def verify_firmware(
        self,
        vendor_id: bytes,
        model_hash: bytes,
        version_hash: bytes,
        observed_sha256: bytes
    ) -> int:
        return self.firmware_registry.functions.verifyFirmware(
            vendor_id, model_hash, version_hash, observed_sha256
        ).call()
    
    def verify_many(
        self,
        vendor_ids: List[bytes],
        model_hashes: List[bytes],
        version_hashes: List[bytes],
        observed_sha256s: List[bytes]
    ) -> List[int]:
        return self.firmware_registry.functions.verifyMany(
            vendor_ids, model_hashes, version_hashes, observed_sha256s
        ).call()
    
    # =========================================================================
    # AlertBus Methods
    # =========================================================================
    
    def publish_alert(
        self,
        provider_org: bytes,
        provider_service_hash: bytes,
        severity: int,
        tti_bucket: int,
        evidence_commitment: bytes,
        expiry: int,
        signature: bytes
    ) -> TxReceipt:
        tx = self.alert_bus.functions.publish(
            provider_org, provider_service_hash, severity, tti_bucket, evidence_commitment, expiry, signature
        ).build_transaction({"from": self.account.address})
        return asyncio.run(self._send_transaction(tx))
    
    def acknowledge_alert(self, alert_id: bytes, signature: bytes) -> TxReceipt:
        tx = self.alert_bus.functions.acknowledge(alert_id, signature).build_transaction({"from": self.account.address})
        return asyncio.run(self._send_transaction(tx))
    
    def resolve_alert(self, alert_id: bytes, signature: bytes) -> TxReceipt:
        tx = self.alert_bus.functions.resolve(alert_id, signature).build_transaction({"from": self.account.address})
        return asyncio.run(self._send_transaction(tx))
    
    def get_alert(self, alert_id: bytes) -> Dict[str, Any]:
        alert = self.alert_bus.functions.getAlert(alert_id).call()
        return {
            "alert_id": alert[0].hex(),
            "provider_org": alert[1].hex(),
            "provider_service_hash": alert[2].hex(),
            "severity": alert[3],
            "tti_bucket": alert[4],
            "evidence_commitment": alert[5].hex(),
            "expiry": alert[6],
            "status": alert[7],
            "published_at": alert[7],
            "acknowledged_at": alert[8],
            "resolved_at": alert[9],
        }
    
    # =========================================================================
    # Signature Helpers
    # =========================================================================
    
    def sign_typed_data(self, domain: dict, types: dict, message: dict) -> bytes:
        """Sign EIP-712 typed data."""
        if not self.account:
            raise ChainError("NO_ACCOUNT", "No account for signing")
        
        encoded = encode_typed_data(domain, types, message)
        signed = self.account.sign_message(encoded)
        return signed.signature
    
    def sign_message(self, message: bytes) -> bytes:
        """Sign raw message (EIP-191)."""
        if not self.account:
            raise ChainError("NO_ACCOUNT", "No account for signing")
        
        encoded = encode_defunct(message)
        signed = self.account.sign_message(encoded)
        return signed.signature
    
    def sign_digest(self, digest: bytes) -> bytes:
        """Sign raw 32-byte digest."""
        if not self.account:
            raise ChainError("NO_ACCOUNT", "No account for signing")
        
        signed = self.account.signHash(digest)
        return signed.signature
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def get_block_number(self) -> int:
        return self.w3.eth.block_number
    
    def get_chain_id(self) -> int:
        return self.w3.eth.chain_id
    
    def is_connected(self) -> bool:
        try:
            return self.w3.is_connected()
        except:
            return False
    
    def to_bytes32(self, value: str) -> bytes:
        """Convert hex string or text to bytes32."""
        if value.startswith("0x"):
            return bytes.fromhex(value[2:]).rjust(32, b'\x00')
        return Web3.keccak(text=value)
    
    def from_bytes32(self, value: bytes) -> str:
        """Convert bytes32 to hex string."""
        return "0x" + value.hex()


# Global client instance
_client: Optional[ChainClient] = None


def get_chain_client() -> ChainClient:
    """Get or create global chain client."""
    global _client
    if _client is None:
        _client = ChainClient()
    return _client