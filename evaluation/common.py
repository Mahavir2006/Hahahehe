"""Shared helpers for the offline evaluation scripts (never used in production)."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
METRICS = ROOT / "backend" / "risk" / "artifacts" / "metrics.json"


def record(key: str, value: Dict[str, Any]) -> None:
    """Merge one evaluation's results into metrics.json (the single source of every reported number)."""
    m = json.loads(METRICS.read_text(encoding="utf-8")) if METRICS.exists() else {}
    m[key] = value
    METRICS.write_text(json.dumps(m, indent=2) + "\n", encoding="utf-8")


def demo_nodes():
    """The three demo org nodes, offline (no chain)."""
    from backend.agents.org_node import OrgNodeRuntime
    from backend.common.chain import Chain, ChainWriter

    d = Path(tempfile.mkdtemp())
    c = Chain("http://127.0.0.1:9", deployment_file=str(d / "none.json"))
    w = ChainWriter(c, d / "w.db")
    return {o: OrgNodeRuntime(o, c, w, d) for o in ("power", "water", "hospital")}
