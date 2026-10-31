"""
EventIndexer (BC-INT-03): tails logs of all six contracts into SQLite.
Restart-safe: progress is stored in the DB and (tx_hash, log_index) is unique, so replays never duplicate.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from eth_utils import keccak
from web3._utils.events import get_event_data

from backend.common.chain import Chain


def _jsonable(v: Any) -> Any:
    if isinstance(v, (bytes, bytearray)):
        return "0x" + bytes(v).hex()
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    return v if isinstance(v, (int, str, bool)) or v is None else str(v)


class EventIndexer:
    def __init__(self, chain: Chain, db_path: Path | str):
        self.chain = chain
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS events (block INTEGER, tx TEXT, log_index INTEGER, contract TEXT, name TEXT, args TEXT, UNIQUE(tx, log_index))"
            )
            db.execute("CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v INTEGER)")
        self._topics: Dict[str, Dict[bytes, Any]] = {}
        for cname, c in chain.contracts.items():
            m = {}
            for item in c.abi:
                if item.get("type") == "event":
                    sig = f"{item['name']}({','.join(self._canon(i) for i in item['inputs'])})"
                    m[keccak(text=sig)] = item
            self._topics[cname] = m

    @staticmethod
    def _canon(i: dict) -> str:
        if i["type"].startswith("tuple"):
            inner = ",".join(EventIndexer._canon(x) for x in i["components"])
            return f"({inner})" + i["type"][5:]
        return i["type"]

    def _db(self):
        db = sqlite3.connect(self.db_path, timeout=30)
        db.row_factory = sqlite3.Row
        return db

    def last_block(self) -> int:
        with self._db() as db:
            r = db.execute("SELECT v FROM state WHERE k='last_block'").fetchone()
            return r["v"] if r else -1

    def sync(self) -> int:
        """Index new logs; returns the number of newly stored events."""
        latest = self.chain.block_number()
        start = self.last_block() + 1
        if start > latest:
            return 0
        added = 0
        with self._db() as db:
            for cname, c in self.chain.contracts.items():
                logs = self.chain.w3.eth.get_logs({"fromBlock": start, "toBlock": latest, "address": c.address})
                for lg in logs:
                    abi = self._topics[cname].get(bytes(lg["topics"][0]))
                    if not abi:
                        continue
                    ev = get_event_data(self.chain.w3.codec, abi, lg)
                    cur = db.execute(
                        "INSERT OR IGNORE INTO events(block, tx, log_index, contract, name, args) VALUES(?,?,?,?,?,?)",
                        (lg["blockNumber"], "0x" + bytes(lg["transactionHash"]).hex(), lg["logIndex"], cname, abi["name"], json.dumps(_jsonable(dict(ev["args"])))),
                    )
                    added += cur.rowcount
            db.execute("INSERT OR REPLACE INTO state(k, v) VALUES('last_block', ?)", (latest,))
        return added

    def query(self, contract: Optional[str] = None, name: Optional[str] = None, limit: int = 200) -> List[dict]:
        q, p = "SELECT * FROM events WHERE 1=1", []
        if contract:
            q += " AND contract=?"
            p.append(contract)
        if name:
            q += " AND name=?"
            p.append(name)
        q += " ORDER BY block DESC, log_index DESC LIMIT ?"
        p.append(limit)
        with self._db() as db:
            return [{**dict(r), "args": json.loads(r["args"])} for r in db.execute(q, p).fetchall()]

    def count(self) -> int:
        with self._db() as db:
            return db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
