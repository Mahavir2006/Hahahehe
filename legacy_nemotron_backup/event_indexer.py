"""
EventIndexer - Indexes blockchain events for fast querying.
"""

import asyncio
import json
import time
import sqlite3
from typing import Optional, List, Dict, Any, Callable, Awaitable
from dataclasses import dataclass
from pathlib import Path
from contextlib import contextmanager
import logging

from .chain_client import ChainClient
from .config import settings

logger = logging.getLogger(__name__)


@dataclass
class IndexedEvent:
    """An indexed blockchain event."""
    contract: str
    event_name: str
    block_number: int
    transaction_hash: str
    log_index: int
    args: Dict[str, Any]
    timestamp: int


class EventIndexer:
    """
    Tails blockchain events and stores them in a local SQLite index.
    Handles reorg-safe restart from last processed block.
    """
    
    def __init__(self, client: ChainClient, db_path: str = "data/events.db"):
        self.client = client
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._running = False
        self._processor_task: Optional[asyncio.Task] = None
        self._poll_interval = 2  # seconds
        self._batch_size = 100
        self._handlers: Dict[str, List[Callable[[IndexedEvent], Awaitable[None]]]] = {}
        
        self._init_db()
        self._load_state()
    
    def _init_db(self):
        """Initialize SQLite database."""
        with self._db() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    contract TEXT NOT NULL,
                    event_name TEXT NOT NULL,
                    block_number INTEGER NOT NULL,
                    transaction_hash TEXT NOT NULL,
                    log_index INTEGER NOT NULL,
                    args_json TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
                );
                
                CREATE INDEX IF NOT EXISTS idx_events_contract_event 
                    ON events(contract, event_name);
                CREATE INDEX IF NOT EXISTS idx_events_block 
                    ON events(block_number);
                CREATE INDEX IF NOT EXISTS idx_events_tx_hash 
                    ON events(transaction_hash);
                CREATE INDEX IF NOT EXISTS idx_events_args 
                    ON events(contract, event_name, block_number);
                
                CREATE TABLE IF NOT EXISTS indexer_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                
                CREATE TABLE IF NOT EXISTS event_handlers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    contract TEXT NOT NULL,
                    event_name TEXT NOT NULL,
                    handler_name TEXT NOT NULL
                );
            """)
    
    @contextmanager
    def _db(self):
        """Database connection context manager."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def _load_state(self):
        """Load last processed block from database."""
        with self._db() as conn:
            row = conn.execute(
                "SELECT value FROM indexer_state WHERE key = 'last_block'"
            ).fetchone()
            self._last_processed_block = int(row["value"]) if row else 0
            
            # Also load registered handlers
            rows = conn.execute(
                "SELECT contract, event_name, handler_name FROM event_handlers"
            ).fetchall()
            for row in rows:
                key = f"{row['contract']}.{row['event_name']}"
                if key not in self._handlers:
                    self._handlers[key] = []
    
    def _save_state(self, block_number: int):
        """Save last processed block to database."""
        with self._db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO indexer_state (key, value) VALUES ('last_block', ?)",
                (str(block_number),)
            )
    
    def register_handler(
        self, 
        contract: str, 
        event_name: str, 
        handler: Callable[[IndexedEvent], Awaitable[None]]
    ):
        """Register an async handler for specific contract events."""
        key = f"{contract}.{event_name}"
        if key not in self._handlers:
            self._handlers[key] = []
        self._handlers[key].append(handler)
        
        # Persist handler registration
        with self._db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO event_handlers (contract, event_name, handler_name) VALUES (?, ?, ?)",
                (contract, event_name, handler.__name__)
            )
    
    def start(self, from_block: Optional[int] = None):
        """Start the event indexer."""
        if self._running:
            return
        
        if from_block is not None:
            self._last_processed_block = from_block
        
        self._running = True
        self._processor_task = asyncio.create_task(self._process_loop())
        logger.info(f"EventIndexer started from block {self._last_processed_block}")
    
    def stop(self):
        """Stop the event indexer."""
        self._running = False
        if self._processor_task:
            self._processor_task.cancel()
        logger.info("EventIndexer stopped")
    
    async def _process_loop(self):
        """Main event processing loop."""
        while self._running:
            try:
                await self._process_new_blocks()
                await asyncio.sleep(self._poll_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"EventIndexer error: {e}")
                await asyncio.sleep(5)
    
    async def _process_new_blocks(self):
        """Process new blocks since last processed."""
        current_block = self.client.get_block_number()
        
        if current_block <= self._last_processed_block:
            return
        
        # Process in batches
        for start_block in range(self._last_processed_block + 1, current_block + 1, self._batch_size):
            end_block = min(start_block + self._batch_size - 1, current_block)
            
            events = await self._fetch_events(start_block, end_block)
            
            for event in events:
                await self._store_event(event)
                await self._dispatch_handlers(event)
            
            self._last_processed_block = end_block
            self._save_state(end_block)
    
    async def _fetch_events(self, from_block: int, to_block: int) -> List[IndexedEvent]:
        """Fetch events from all contracts in block range."""
        events = []
        
        contracts = [
            ("OrgRegistry", self.client.org_registry),
            ("AttestationRegistry", self.client.attestation_registry),
            ("AuditLog", self.client.audit_log),
            ("ApprovalGate", self.client.approval_gate),
            ("FirmwareRegistry", self.client.firmware_registry),
            ("AlertBus", self.client.alert_bus),
        ]
        
        for contract_name, contract in contracts:
            try:
                # Get all events for this contract
                for event_name in contract.events:
                    event_abi = contract.events[event_name].abi
                    logs = self.client.w3.eth.get_logs({
                        "fromBlock": from_block,
                        "toBlock": to_block,
                        "address": contract.address,
                        "topics": [event_abi["topic"]] if "topic" in event_abi else None
                    })
                    
                    for log in logs:
                        try:
                            decoded = contract.events[event_name].process_log(log)
                            events.append(IndexedEvent(
                                contract=contract_name,
                                event_name=event_name,
                                block_number=log["blockNumber"],
                                transaction_hash=log["transactionHash"].hex(),
                                log_index=log["logIndex"],
                                args=dict(decoded["args"]),
                                timestamp=int(time.time())
                            ))
                        except Exception as e:
                            logger.warning(f"Failed to decode {contract_name}.{event_name}: {e}")
                            
            except Exception as e:
                logger.warning(f"Error fetching events for {contract_name}: {e}")
        
        return events
    
    async def _store_event(self, event: IndexedEvent):
        """Store event in database."""
        with self._db() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO events 
                   (contract, event_name, block_number, transaction_hash, log_index, args_json, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.contract,
                    event.event_name,
                    event.block_number,
                    event.transaction_hash,
                    event.log_index,
                    json.dumps(event.args, default=str),
                    event.timestamp
                )
            )
    
    async def _dispatch_handlers(self, event: IndexedEvent):
        """Dispatch event to registered handlers."""
        key = f"{event.contract}.{event.event_name}"
        handlers = self._handlers.get(key, [])
        
        for handler in handlers:
            try:
                await handler(event)
            except Exception as e:
                logger.error(f"Handler {handler.__name__} failed for {key}: {e}")
    
    # =========================================================================
    # Query Methods
    # =========================================================================
    
    def get_events(
        self,
        contract: Optional[str] = None,
        event_name: Optional[str] = None,
        from_block: Optional[int] = None,
        to_block: Optional[int] = None,
        org_id: Optional[str] = None,
        limit: int = 100
    ) -> List[IndexedEvent]:
        """Query indexed events."""
        query = "SELECT * FROM events WHERE 1=1"
        params = []
        
        if contract:
            query += " AND contract = ?"
            params.append(contract)
        if event_name:
            query += " AND event_name = ?"
            params.append(event_name)
        if from_block:
            query += " AND block_number >= ?"
            params.append(from_block)
        if to_block:
            query += " AND block_number <= ?"
            params.append(to_block)
        
        query += " ORDER BY block_number DESC, log_index DESC LIMIT ?"
        params.append(limit)
        
        with self._db() as conn:
            rows = conn.execute(query, params).fetchall()
        
        events = []
        for row in rows:
            # Filter by org_id if specified (check args_json)
            if org_id:
                args = json.loads(row["args_json"])
                if "orgId" in args and args["orgId"].lower() != org_id.lower():
                    if "consumerOrg" in args and args["consumerOrg"].lower() != org_id.lower():
                        if "providerOrg" in args and args["providerOrg"].lower() != org_id.lower():
                            continue
            
            events.append(IndexedEvent(
                contract=row["contract"],
                event_name=row["event_name"],
                block_number=row["block_number"],
                transaction_hash=row["transaction_hash"],
                log_index=row["log_index"],
                args=json.loads(row["args_json"]),
                timestamp=row["timestamp"]
            ))
        
        return events
    
    def get_last_processed_block(self) -> int:
        """Get last processed block number."""
        return self._last_processed_block
    
    def get_stats(self) -> Dict[str, Any]:
        """Get indexer statistics."""
        with self._db() as conn:
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            contracts = conn.execute(
                "SELECT contract, COUNT(*) as count FROM events GROUP BY contract"
            ).fetchall()
        
        return {
            "total_events": total,
            "last_processed_block": self._last_processed_block,
            "by_contract": {row[0]: row[1] for row in contracts},
            "running": self._running,
        }
    
    def reprocess_from_block(self, block_number: int):
        """Reprocess events from a specific block (for reorg recovery)."""
        logger.info(f"Reprocessing from block {block_number}")
        self._last_processed_block = block_number - 1
        self._save_state(block_number - 1)
        
        # Delete events from this block onwards
        with self._db() as conn:
            conn.execute("DELETE FROM events WHERE block_number >= ?", (block_number,))


class EventIndexerManager:
    """Manages multiple EventIndexers for different chains/orgs."""
    
    def __init__(self):
        self._indexers: Dict[str, EventIndexer] = {}
    
    def add_indexer(self, name: str, indexer: EventIndexer):
        self._indexers[name] = indexer
    
    def get_indexer(self, name: str) -> Optional[EventIndexer]:
        return self._indexers.get(name)
    
    def start_all(self):
        for indexer in self._indexers.values():
            indexer.start()
    
    def stop_all(self):
        for indexer in self._indexers.values():
            indexer.stop()
    
    def get_all_stats(self) -> Dict[str, Any]:
        return {name: idx.get_stats() for name, idx in self._indexers.items()}