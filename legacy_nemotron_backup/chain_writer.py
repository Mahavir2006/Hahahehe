"""
ChainWriter - Handles idempotent chain writes with nonce management and pause support.
"""

import asyncio
import time
import hashlib
import json
from typing import Optional, Dict, Any, Callable, Awaitable
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import logging

from .chain_client import ChainClient, ChainError
from .config import settings

logger = logging.getLogger(__name__)


class WriteStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    DUPLICATE = "duplicate"


@dataclass
class WriteRequest:
    """A pending chain write request."""
    idempotency_key: str
    write_fn: Callable[[], Awaitable[Any]]
    args: tuple
    kwargs: dict
    status: WriteStatus = WriteStatus.PENDING
    tx_hash: Optional[str] = None
    result: Any = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    retries: int = 0
    future: asyncio.Future = field(default_factory=asyncio.Future)


class ChainWriter:
    """
    Manages chain writes with:
    - Idempotency keys (prevents duplicate writes)
    - Per-signer serialized nonce queue
    - Pause/resume support
    - Dry-run mode
    - Automatic retries with backoff
    """
    
    def __init__(self, client: ChainClient):
        self.client = client
        self._pending_writes: Dict[str, WriteRequest] = {}
        self._write_queue: asyncio.Queue = asyncio.Queue()
        self._paused = False
        self._pause_lock = asyncio.Lock()
        self._processor_task: Optional[asyncio.Task] = None
        self._dry_run = False
        self._nonce_locks: Dict[str, asyncio.Lock] = {}
        
    def set_dry_run(self, dry_run: bool):
        """Enable/disable dry-run mode."""
        self._dry_run = dry_run
    
    async def pause(self):
        """Pause all chain writes."""
        async with self._pause_lock:
            self._paused = True
            logger.info("ChainWriter paused")
    
    async def resume(self):
        """Resume chain writes."""
        async with self._pause_lock:
            self._paused = False
            logger.info("ChainWriter resumed")
    
    def is_paused(self) -> bool:
        return self._paused
    
    def _get_nonce_lock(self, signer: str) -> asyncio.Lock:
        """Get or create nonce lock for signer."""
        if signer not in self._nonce_locks:
            self._nonce_locks[signer] = asyncio.Lock()
        return self._nonce_locks[signer]
    
    async def write(
        self,
        idempotency_key: str,
        write_fn: Callable[[], Awaitable[Any]],
        *args,
        signer: Optional[str] = None,
        **kwargs
    ) -> Any:
        """
        Submit a chain write with idempotency.
        
        Args:
            idempotency_key: Unique key for this write (prevents duplicates)
            write_fn: Async function that performs the chain write
            *args, **kwargs: Arguments to pass to write_fn
            signer: Optional signer address for nonce management
            
        Returns:
            Result of the write function, or existing result if duplicate
        """
        # Check for existing write with same key
        if idempotency_key in self._pending_writes:
            existing = self._pending_writes[idempotency_key]
            if existing.status in (WriteStatus.CONFIRMED, WriteStatus.SENT):
                logger.info(f"Duplicate write detected for {idempotency_key}, returning existing result")
                existing.future = asyncio.Future()
                existing.future.set_result(existing.result)
                return await existing.future
            elif existing.status == WriteStatus.PENDING:
                # Wait for existing to complete
                return await existing.future
        
        # Create new write request
        future = asyncio.Future()
        request = WriteRequest(
            idempotency_key=idempotency_key,
            write_fn=write_fn,
            args=args,
            kwargs=kwargs,
            future=future
        )
        self._pending_writes[idempotency_key] = request
        
        # Queue for processing
        await self._write_queue.put(request)
        
        # Ensure processor is running
        if self._processor_task is None or self._processor_task.done():
            self._processor_task = asyncio.create_task(self._process_queue())
        
        return await future
    
    async def _process_queue(self):
        """Process queued writes sequentially per signer."""
        while True:
            try:
                request = await self._write_queue.get()
                
                # Check pause
                async with self._pause_lock:
                    while self._paused:
                        await asyncio.sleep(1)
                
                # Skip if already completed (duplicate)
                if request.status in (WriteStatus.CONFIRMED, WriteStatus.SENT):
                    continue
                
                # Determine signer for nonce locking
                signer = request.kwargs.get("signer", "default")
                nonce_lock = self._get_nonce_lock(signer)
                
                async with nonce_lock:
                    await self._execute_write(request)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing write queue: {e}")
                await asyncio.sleep(1)
    
    async def _execute_write(self, request: WriteRequest):
        """Execute a single write with retries."""
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                if self._dry_run:
                    # Dry run: just simulate
                    logger.info(f"DRY RUN: {request.idempotency_key}")
                    request.result = {"dry_run": True, "idempotency_key": request.idempotency_key}
                    request.status = WriteStatus.CONFIRMED
                    request.future.set_result(request.result)
                    return
                
                # Execute the write function
                request.status = WriteStatus.SENT
                result = await request.write_fn(*request.args, **request.kwargs)
                
                request.result = result
                request.status = WriteStatus.CONFIRMED
                request.future.set_result(result)
                logger.info(f"Write confirmed: {request.idempotency_key}")
                return
                
            except Exception as e:
                request.retries += 1
                request.error = str(e)
                
                if attempt == 2:  # Last attempt
                    request.status = WriteStatus.FAILED
                    request.future.set_exception(e)
                    logger.error(f"Write failed after {max_retries} attempts: {request.idempotency_key} - {e}")
                    return
                
                # Wait before retry with exponential backoff
                await asyncio.sleep(2 ** attempt)
    
    async def flush(self, timeout: float = 30.0) -> Dict[str, Any]:
        """Wait for all pending writes to complete."""
        start = time.time()
        while time.time() - start < timeout:
            pending = [r for r in self._pending_writes.values() 
                      if r.status in (WriteStatus.PENDING, WriteStatus.SENT)]
            if not pending:
                break
            await asyncio.sleep(0.5)
        
        return {
            "total": len(self._pending_writes),
            "confirmed": len([r for r in self._pending_writes.values() if r.status == WriteStatus.CONFIRMED]),
            "failed": len([r for r in self._pending_writes.values() if r.status == WriteStatus.FAILED]),
            "pending": len([r for r in self._pending_writes.values() if r.status in (WriteStatus.PENDING, WriteStatus.SENT)]),
        }
    
    def get_status(self, idempotency_key: str) -> Optional[WriteStatus]:
        """Get status of a write by idempotency key."""
        if idempotency_key in self._pending_writes:
            return self._pending_writes[idempotency_key].status
        return None
    
    def get_result(self, idempotency_key: str) -> Any:
        """Get result of a completed write."""
        if idempotency_key in self._pending_writes:
            return self._pending_writes[idempotency_key].result
        return None
    
    def clear_completed(self, older_than: float = 3600):
        """Clear old completed writes from memory."""
        now = time.time()
        to_remove = []
        for key, request in self._pending_writes.items():
            if request.status in (WriteStatus.CONFIRMED, WriteStatus.FAILED):
                if now - request.created_at > older_than:
                    to_remove.append(key)
        
        for key in to_remove:
            del self._pending_writes[key]


class IdempotencyKeyGenerator:
    """Generate consistent idempotency keys for common operations."""
    
    @staticmethod
    def dependency_attestation(
        consumer_org: str,
        consumer_service: str,
        provider_org: str,
        provider_service: str,
        nonce: int
    ) -> str:
        data = f"dep:{consumer_org}:{consumer_service}:{provider_org}:{provider_service}:{nonce}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    @staticmethod
    def risk_attestation(org: str, service: str, nonce: int) -> str:
        data = f"risk:{org}:{service}:{nonce}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    @staticmethod
    def finding_attestation(org: str, advisory_hash: str, nonce: int) -> str:
        data = f"finding:{org}:{advisory_hash}:{nonce}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    @staticmethod
    def anchor(org: str, kind: str, digest: str) -> str:
        data = f"anchor:{org}:{kind}:{digest}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    @staticmethod
    def anchor_batch(org: str, merkle_root: str) -> str:
        data = f"batch:{org}:{merkle_root}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    @staticmethod
    def approval_request(org: str, plan_hash: str) -> str:
        data = f"approval:{org}:{plan_hash}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    @staticmethod
    def approval_vote(request_id: str, approver: str, approve: bool) -> str:
        data = f"vote:{request_id}:{approver}:{approve}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    @staticmethod
    def alert_publish(provider: str, service: str, severity: int) -> str:
        data = f"alert:{provider}:{service}:{severity}:{int(time.time() // 300)}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    @staticmethod
    def firmware_publish(vendor: str, model: str, version: str) -> str:
        data = f"firmware:{vendor}:{model}:{version}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]