"""
Where twin events come from.

* indexer_events: the node's local SQLite copy of contract events (fast; what the live twin uses).
* chain_events:   a fresh replay straight from the chain over its own RPC connection, decoding every log again.
  It shares nothing with the indexer, so it is the independent check: if someone edits the local copy, the two
  replays produce different fingerprints.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, List, Optional

from eth_utils import keccak
from web3 import Web3
from web3._utils.events import get_event_data

from backend.common.events import EventIndexer, _jsonable


def indexer_events(indexer: EventIndexer, upto_block: Optional[int] = None) -> List[Dict[str, Any]]:
    q = "SELECT block, tx, log_index, contract, name, args FROM events"
    p: list = []
    if upto_block is not None:
        q += " WHERE block <= ?"
        p.append(upto_block)
    q += " ORDER BY block, log_index"
    db = sqlite3.connect(indexer.db_path, timeout=30)
    db.row_factory = sqlite3.Row
    try:
        return [{**dict(r), "args": json.loads(r["args"])} for r in db.execute(q, p).fetchall()]
    finally:
        db.close()


def chain_events(rpc_url: str, contracts: Dict[str, Any], upto_block: Optional[int] = None, w3: Optional[Web3] = None) -> List[Dict[str, Any]]:
    """Decode every log of the given contracts (name -> web3 contract) from block 0, over a separate connection."""
    w3 = w3 or Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
    head = int(w3.eth.block_number) if upto_block is None else upto_block
    out: List[Dict[str, Any]] = []
    for cname, c in contracts.items():
        topics = {}
        for item in c.abi:
            if item.get("type") == "event":
                topics[keccak(text=f"{item['name']}({','.join(EventIndexer._canon(i) for i in item['inputs'])})")] = item
        for lg in w3.eth.get_logs({"fromBlock": 0, "toBlock": head, "address": c.address}):
            abi = topics.get(bytes(lg["topics"][0]))
            if not abi:
                continue
            ev = get_event_data(w3.codec, abi, lg)
            out.append({
                "block": lg["blockNumber"], "tx": "0x" + bytes(lg["transactionHash"]).hex(), "log_index": lg["logIndex"],
                "contract": cname, "name": abi["name"], "args": json.loads(json.dumps(_jsonable(dict(ev["args"])))),
            })
    return sorted(out, key=lambda e: (e["block"], e["log_index"]))
