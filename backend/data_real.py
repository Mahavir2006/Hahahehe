"""
Loaders for the checksummed snapshot of real public data in data/real/ (DATA-REAL-01..04).

Every loader verifies the file it reads against data/real/MANIFEST.json and raises
SnapshotIntegrityError if the file is missing, modified, or has the wrong row count.
Checksums are taken over the file bytes with CRLF normalised to LF, so a Windows
checkout with core.autocrlf still verifies while any content change is caught.

EPSS scores are current-day scores (time_matched=false): load_epss refuses any as-of
date earlier than the snapshot's epss_asof_date, so a back-test cannot see the future.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

ROOT = Path(__file__).resolve().parents[1]
REAL_DIR = ROOT / "data" / "real"
MANIFEST = "MANIFEST.json"
SIZE_CAP_BYTES = 5_000_000


class SnapshotIntegrityError(Exception):
    pass


class EpssLookAheadError(ValueError):
    pass


def content_sha256(data: bytes) -> str:
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def count_rows(data: bytes) -> int:
    return sum(1 for line in data.replace(b"\r\n", b"\n").split(b"\n") if line.strip())


def dir_size_bytes(root: Optional[Path] = None) -> int:
    return sum(p.stat().st_size for p in Path(root or REAL_DIR).rglob("*") if p.is_file())


def load_manifest(root: Optional[Path] = None) -> Dict[str, Any]:
    path = Path(root or REAL_DIR) / MANIFEST
    if not path.exists():
        raise SnapshotIntegrityError(f"missing manifest: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def verify_file(name: str, root: Optional[Path] = None, manifest: Optional[Dict[str, Any]] = None) -> bytes:
    root = Path(root or REAL_DIR)
    manifest = manifest or load_manifest(root)
    entry = manifest.get("files", {}).get(name)
    if entry is None:
        raise SnapshotIntegrityError(f"{name} is not listed in {MANIFEST}")
    path = root / name
    if not path.exists():
        raise SnapshotIntegrityError(f"missing file: {path}")
    data = path.read_bytes()
    if content_sha256(data) != entry["sha256"]:
        raise SnapshotIntegrityError(f"checksum mismatch: {name}")
    if count_rows(data) != entry["rows"]:
        raise SnapshotIntegrityError(f"row count mismatch: {name}")
    return data


def verify_all(root: Optional[Path] = None) -> Dict[str, Any]:
    manifest = load_manifest(root)
    for name in manifest.get("files", {}):
        verify_file(name, root, manifest)
    return manifest


def _jsonl(name: str, root: Optional[Path]) -> List[Dict[str, Any]]:
    data = verify_file(name, root)
    return [json.loads(line) for line in data.decode("utf-8").splitlines() if line.strip()]


def load_vulns(root: Optional[Path] = None) -> List[Dict[str, Any]]:
    return _jsonl("vuln_snapshot.jsonl", root)


def load_kev(root: Optional[Path] = None) -> List[Dict[str, Any]]:
    return _jsonl("kev.jsonl", root)


def _as_date(d: Union[date, str]) -> date:
    return d if isinstance(d, date) else date.fromisoformat(str(d)[:10])


def load_epss(as_of: Union[date, str], root: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    """EPSS rows keyed by CVE. Refuses as_of dates before the scores' as-of date (no look-ahead)."""
    rows = _jsonl("epss.jsonl", root)
    as_of_d = _as_date(as_of)
    earliest = min((_as_date(r["epss_asof_date"]) for r in rows), default=None)
    if earliest is not None and as_of_d < earliest:
        raise EpssLookAheadError(
            f"EPSS scores are as of {earliest.isoformat()} and not time-matched; refusing as_of={as_of_d.isoformat()}"
        )
    return {r["cve"]: r for r in rows if _as_date(r["epss_asof_date"]) <= as_of_d}


# ---------------------------------------------------------------------------
# Version ranges
# ---------------------------------------------------------------------------
# Handled: vers:all/*, vers:intdot/<constraints>, bare comparators (<X, <=X, <VX.Y, >=A | <B, ...)
# and plain versions. A version is digits and dots with an optional leading V. Anything else
# keeps its raw string with parse_failed=True; nothing is guessed.

_VERSION = r"\d+(?:\.\d+)*"
_CONSTRAINT = re.compile(rf"^(<=|>=|<|>|=)?\s*[Vv]?({_VERSION})$")


def _vtuple(v: str) -> tuple:
    return tuple(int(p) for p in v.split("."))


def _failed(raw: str) -> Dict[str, Any]:
    return {"raw": raw, "format": "unparsed", "parse_failed": True,
            "min": None, "max": None, "min_inclusive": None, "max_inclusive": None, "all": False}


def parse_version_range(raw: Optional[str]) -> Dict[str, Any]:
    if raw is None:
        return _failed(raw)  # type: ignore[arg-type]
    s = raw.strip()
    out = {"raw": raw, "format": "", "parse_failed": False,
           "min": None, "max": None, "min_inclusive": None, "max_inclusive": None, "all": False}
    if s == "vers:all/*":
        out.update(format="vers:all/*", all=True)
        return out
    prefix = ""
    if s.startswith("vers:"):
        if not s.startswith("vers:intdot/"):
            return _failed(raw)
        prefix, s = "vers:intdot/", s[len("vers:intdot/"):]
    parts = [p.strip() for p in s.split("|")]
    if not parts or any(not p for p in parts):
        return _failed(raw)
    ops = []
    for p in parts:
        m = _CONSTRAINT.match(p)
        if not m:
            return _failed(raw)
        op, ver = m.group(1) or "", m.group(2)
        ops.append(op or "=")
        if op in ("", "="):
            if len(parts) != 1:
                return _failed(raw)
            out.update(min=ver, max=ver, min_inclusive=True, max_inclusive=True)
        elif op in (">", ">="):
            if out["min"] is not None:
                return _failed(raw)
            out.update(min=ver, min_inclusive=(op == ">="))
        else:
            if out["max"] is not None:
                return _failed(raw)
            out.update(max=ver, max_inclusive=(op == "<="))
    if out["min"] is not None and out["max"] is not None and _vtuple(out["min"]) > _vtuple(out["max"]):
        return _failed(raw)
    if not prefix and ops == ["="] and not _CONSTRAINT.match(s).group(1):  # type: ignore[union-attr]
        out["format"] = "plain"
    else:
        out["format"] = prefix + "|".join(ops)
    return out
