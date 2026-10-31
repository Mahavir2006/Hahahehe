"""
AuditAnchorService - Batches traces/snapshots into Merkle trees and anchors on-chain.
"""

import asyncio
import hashlib
import json
import time
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path
import logging

from .chain_client import ChainClient
from .chain_writer import ChainWriter, IdempotencyKeyGenerator
from .config import settings
from .schemas import *

logger = logging.getLogger(__name__)


@dataclass
class BatchItem:
    """Item to be included in a Merkle batch."""
    org_id: str
    kind: str
    digest: str
    meta: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class MerkleBatch:
    """A batch of items with Merkle root."""
    org_id: str
    kind: str
    items: List[BatchItem]
    merkle_root: str
    leaf_hashes: List[str]
    proofs: Dict[str, List[str]]  # leaf -> proof path
    batch_id: str
    created_at: float
    anchored: bool = False
    tx_hash: Optional[str] = None


class AuditAnchorService:
    """
    Batches traces/snapshots into Merkle trees and anchors on-chain.
    Flushes on interval or size threshold, and on shutdown.
    """
    
    def __init__(
        self,
        client: ChainClient,
        writer: ChainWriter,
        batch_interval: float = 30.0,
        batch_size: int = 100,
        flush_on_shutdown: bool = True
    ):
        self.client = client
        self.writer = writer
        self.batch_interval = batch_interval
        self.batch_size = batch_size
        self.flush_on_shutdown = flush_on_shutdown
        
        # Pending items per org/kind
        self._pending: Dict[str, Dict[str, List[BatchItem]]] = defaultdict(lambda: defaultdict(list))
        
        # Batches in progress
        self._batches: Dict[str, MerkleBatch] = {}
        
        # Proofs for lookup
        self._proofs: Dict[str, Dict[str, List[str]]] = defaultdict(dict)
        
        self._running = False
        self._processor_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        
    async def add_item(
        self,
        org_id: str,
        kind: str,
        digest: str,
        meta: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add an item to be batched and anchored.
        Returns the batch ID it will be included in.
        """
        async with self._lock:
            key = f"{org_id}:{kind}"
            item = BatchItem(
                org_id=org_id,
                kind=kind,
                digest=digest,
                meta=meta or {}
            )
            self._pending[org_id][kind].append(item)
            
            # Check if we should flush
            if len(self._pending[org_id][kind]) >= self.batch_size:
                await self._flush_org_kind(org_id, kind)
            
            return f"{org_id}:{kind}:pending"
    
    async def flush_all(self):
        """Flush all pending items."""
        async with self._lock:
            for org_id in list(self._pending.keys()):
                for kind in list(self._pending[org_id].keys()):
                    if self._pending[org_id][kind]:
                        await self._flush_org_kind(org_id, kind)
    
    async def _flush_org_kind(self, org_id: str, kind: str):
        """Flush pending items for a specific org/kind."""
        items = self._pending[org_id].pop(kind, [])
        if not items:
            return
        
        # Create Merkle batch
        batch = await self._create_merkle_batch(org_id, kind, items)
        
        # Anchor on-chain
        await self._anchor_batch(batch)
        
        # Store batch for proof lookup
        self._batches[batch.batch_id] = batch
    
    def _compute_leaf_hash(self, item: BatchItem) -> str:
        """Compute leaf hash for Merkle tree."""
        data = {
            "org_id": item.org_id,
            "kind": item.kind,
            "digest": item.digest,
            "meta": item.meta,
            "timestamp": item.timestamp
        }
        canon = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canon.encode()).hexdigest()
    
    def _build_merkle_tree(self, leaves: List[str]) -> tuple:
        """Build Merkle tree and return (root, proofs)."""
        if not leaves:
            return "0x" + "0" * 64, {}
        
        # Pad to power of 2
        n = len(leaves)
        padded = leaves[:]
        while len(padded) & (len(padded) - 1):
            padded.append(padded[-1])
        
        # Build tree
        tree = [padded]
        while len(tree[-1]) > 1:
            level = tree[-1]
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else level[i]
                combined = hashlib.sha256((left + right).encode()).hexdigest()
                next_level.append(combined)
            tree.append(next_level)
        
        root = tree[-1][0] if tree[-1] else "0x" + "0" * 64
        
        # Generate proofs for original leaves
        proofs = {}
        for i, leaf in enumerate(leaves):
            proof = []
            level_idx = i
            for level in range(len(tree) - 1):
                sibling_idx = level_idx ^ 1
                if sibling_idx < len(tree[level]):
                    proof.append(tree[level][sibling_idx])
                else:
                    proof.append(tree[level][level_idx])
                level_idx //= 2
            proofs[leaf] = proof
        
        return root, proofs
    
    async def _create_merkle_batch(
        self,
        org_id: str,
        kind: str,
        items: List[BatchItem]
    ) -> MerkleBatch:
        """Create a Merkle batch from items."""
        # Compute leaf hashes
        leaves = [self._compute_leaf_hash(item) for item in items]
        
        # Build Merkle tree
        root, proofs = self._build_merkle_tree(leaves)
        
        batch_id = hashlib.sha256(
            f"{org_id}:{kind}:{root}:{time.time()}".encode()
        ).hexdigest()[:32]
        
        batch = MerkleBatch(
            org_id=org_id,
            kind=kind,
            items=items,
            merkle_root="0x" + root,
            leaf_hashes=["0x" + h for h in leaves],
            proofs={("0x" + k): ["0x" + p for p in v] for k, v in proofs.items()},
            batch_id=batch_id,
            created_at=time.time()
        )
        
        # Store proofs for lookup
        for leaf, proof in proofs.items():
            self._proofs[f"{org_id}:{kind}"]["0x" + leaf] = ["0x" + p for p in proof]
        
        return batch
    
    async def _anchor_batch(self, batch: MerkleBatch):
        """Anchor batch on-chain using ChainWriter."""
        org_id_bytes = self.client.to_bytes32(batch.org_id)
        
        # Map kind to AnchorKind enum
        kind_map = {
            "AgentTrace": 0,
            "RiskSnapshot": 1,
            "Plan": 2,
            "CriticVerdict": 3,
            "Execution": 4,
            "Pause": 5,
            "Resume": 6,
            "ModelVersion": 7,
            "Policy": 8,
        }
        kind_enum = kind_map.get(batch.kind, 0)
        
        # Generate idempotency key
        idempotency_key = IdempotencyKeyGenerator.anchor_batch(batch.org_id, batch.merkle_root[2:])
        
        # Get previous digest
        prev_digest = self.client.get_last_digest(self.client.to_bytes32(batch.org_id))
        
        # Prepare signature
        # In production, this would be signed by the org's agent signer
        # For now, use a placeholder
        signature = b"\x00" * 65  # Placeholder
        
        # Anchor batch via ChainWriter
        async def do_anchor():
            return self.client.anchor_batch(
                org_id_bytes,
                kind_enum,
                bytes.fromhex(batch.merkle_root[2:]),
                len(batch.items),
                prev_digest,
                signature
            )
        
        idempotency_key = IdempotencyKeyGenerator.anchor_batch(batch.org_id, batch.merkle_root[2:])
        
        try:
            tx_hash = await self.writer.write(
                idempotency_key,
                do_anchor,
                signer=batch.org_id
            )
            batch.anchored = True
            batch.tx_hash = tx_hash.hex() if hasattr(tx_hash, 'hex') else str(tx_hash)
            logger.info(f"Anchored batch {batch.batch_id} for {batch.org_id}:{batch.kind} in tx {batch.tx_hash}")
        except Exception as e:
            logger.error(f"Failed to anchor batch {batch.batch_id}: {e}")
            raise
    
    def get_proof(
        self,
        org_id: str,
        kind: str,
        leaf_digest: str
    ) -> Optional[List[str]]:
        """Get Merkle proof for a leaf."""
        key = f"{org_id}:{kind}"
        return self._proofs.get(key, {}).get(leaf_digest)
    
    def verify_inclusion(
        self,
        org_id: str,
        kind: str,
        leaf_digest: str,
        proof: List[str],
        root: str
    ) -> bool:
        """Verify a Merkle proof."""
        current = leaf_digest
        for sibling in proof:
            if current < sibling:
                combined = hashlib.sha256((current + sibling).encode()).hexdigest()
            else:
                combined = hashlib.sha256((sibling + current).encode()).hexdigest()
            current = combined
        return current == root[2:] if root.startswith("0x") else current == root
    
    async def start(self):
        """Start the batch processor."""
        self._running = True
        # Periodic flush
        asyncio.create_task(self._periodic_flush())
    
    async def stop(self):
        """Stop and flush all pending."""
        if self.flush_on_shutdown:
            await self.flush_all()
    
    async def _periodic_flush(self):
        """Periodically flush pending batches."""
        while True:
            await asyncio.sleep(self.batch_interval)
            await self.flush_all()
    
    def get_batch_status(self, batch_id: str) -> Optional[MerkleBatch]:
        """Get batch status by ID."""
        return self._batches.get(batch_id)
    
    def get_pending_count(self, org_id: str, kind: str) -> int:
        """Get count of pending items for org/kind."""
        return len(self._pending[org_id].get(kind, []))


# Global instance
_anchor_service: Optional[AuditAnchorService] = None


def get_anchor_service(
    client: Optional[ChainClient] = None,
    writer: Optional[ChainWriter] = None
) -> AuditAnchorService:
    """Get or create global anchor service."""
    global _anchor_service
    if _anchor_service is None:
        if client is None:
            from .chain_client import get_chain_client
            client = get_chain_client()
        if writer is None:
            from .chain_writer import ChainWriter
            writer = ChainWriter(client)
        _anchor_service = AuditAnchorService(client, writer)
    return _anchor_service