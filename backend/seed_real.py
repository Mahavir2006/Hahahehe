"""
PS-03 WP2: attach REAL vulnerability context (data/real, via backend.data_real which verifies checksums) to the
demo assets, in memory only. Enabled by PS03_SEED_REAL=1. Nothing is written to data/real or inventory.json.

Matching, most specific first:
  model           the asset's model string appears in an advisory product name of the same vendor
  vendor          the advisory vendor's first word equals the asset vendor's first word
  sector_fallback no vendor match: CVEs from advisories of the org's sector
At most MAX_PER_ASSET CVEs, chosen deterministically by sha256(asset_id + cve). KEV status from the real KEV
file; EPSS from the real FIRST file (current-day, epss_time_matched=false). A CVE without an EPSS score gets the
median real EPSS of its CVSS bucket and epss_missing=true.
"""

from __future__ import annotations

import hashlib
import statistics
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from backend import data_real

MAX_PER_ASSET = 3
ORG_SECTOR = {"power": "Energy", "water": "Water and Wastewater", "hospital": "Healthcare and Public Health"}


def _key(v: Optional[str]) -> str:
    return (v or "").casefold().split()[0] if (v or "").strip() else ""


def _intdot(v: str) -> Optional[Tuple[int, ...]]:
    try:
        return tuple(int(p) for p in str(v).lstrip("Vv").split("."))
    except ValueError:
        return None


def version_status(fw: str, entries: List[Dict[str, Any]], model: str) -> str:
    """Affected-version check for model-level matches only: in_range | out_of_range | unparsed | not_checked."""
    rel = [e for e in entries if model and model.casefold() in str(e.get("product") or "").casefold()]
    if not rel:
        return "not_checked"
    v = _intdot(fw)
    for e in rel:
        r = e.get("range") or {}
        if r.get("parse_failed") or v is None:
            return "unparsed"
        if r.get("all"):
            return "in_range"
        lo, hi = _intdot(r["min"]) if r.get("min") else None, _intdot(r["max"]) if r.get("max") else None
        ok = (lo is None or (v > lo or (r.get("min_inclusive") and v == lo))) and (hi is None or (v < hi or (r.get("max_inclusive") and v == hi)))
        if ok:
            return "in_range"
    return "out_of_range"


class RealContext:
    def __init__(self) -> None:
        self.rows = data_real.load_vulns()
        self.kev = {r["cveID"] for r in data_real.load_kev()}
        all_epss = data_real.load_epss(date.max)
        self.epss_asof = max(r["epss_asof_date"] for r in all_epss.values())
        self.epss = {c: float(r["epss"]) for c, r in data_real.load_epss(self.epss_asof).items()}
        by_bucket: Dict[int, List[float]] = {}
        for r in self.rows:
            if r["cve"] in self.epss and r["cvss_base"] is not None:
                by_bucket.setdefault(min(int(r["cvss_base"]), 9), []).append(self.epss[r["cve"]])
        self.epss_fallback = {b: statistics.median(v) for b, v in by_bucket.items()}
        self.by_vendor: Dict[str, List[Dict[str, Any]]] = {}
        self.by_sector: Dict[str, List[Dict[str, Any]]] = {}
        for r in self.rows:
            self.by_vendor.setdefault(_key(r["vendor"]), []).append(r)
            self.by_sector.setdefault(r["assigned_sector"], []).append(r)
        self.manifest = data_real.load_manifest()

    def vuln(self, r: Dict[str, Any], match: str, inv: Dict[str, Any]) -> Dict[str, Any]:
        e = self.epss.get(r["cve"])
        missing = e is None
        if missing:
            e = self.epss_fallback.get(min(int(r["cvss_base"] or 0), 9), 0.0)
        return {
            "cve": r["cve"], "cvss": r["cvss_base"], "epss": round(float(e), 5), "exploited": r["cve"] in self.kev,
            "source": "real_snapshot", "match": match, "epss_time_matched": False, "epss_missing": missing,
            "epss_asof": self.epss_asof, "advisory_id": r["advisory_id"], "advisory_vendor": r["vendor"],
            "cwe": r.get("cwe_id"), "kev": r["cve"] in self.kev,
            "version_match": version_status(inv.get("firmware_version", ""), r.get("known_affected", []), inv.get("model", "")) if match == "model" else "not_checked",
        }

    def for_asset(self, org: str, inv: Dict[str, Any]) -> List[Dict[str, Any]]:
        cands = self.by_vendor.get(_key(inv.get("vendor")), [])
        model = (inv.get("model") or "").casefold()
        model_rows = [r for r in cands if model and any(model in p.casefold() for p in r["product_names"])]
        if model_rows:
            pool, match = model_rows, "model"
        elif cands:
            pool, match = cands, "vendor"
        else:
            pool, match = self.by_sector.get(ORG_SECTOR[org], []), "sector_fallback"
        uniq = {r["cve"]: r for r in pool}
        order = sorted(uniq, key=lambda c: hashlib.sha256(f"{inv['asset_id']}|{c}".encode()).hexdigest())
        return [self.vuln(uniq[c], match, inv) for c in order[:MAX_PER_ASSET]]


def seed_node(node: Any, ctx: Optional[RealContext] = None) -> Dict[str, Any]:
    ctx = ctx or RealContext()
    counts = {"model": 0, "vendor": 0, "sector_fallback": 0}
    seeded = 0
    for aid, a in node.assets.items():
        inv = node.inventory[aid]
        vs = ctx.for_asset(node.org, inv)
        have = {v["cve"] for v in a.vulns}
        add = [v for v in vs if v["cve"] not in have]
        a.vulns.extend(add)
        seeded += len(add)
        if vs:
            counts[vs[0]["match"]] += 1
    return {"org": node.org, "assets": len(node.assets), "vulns_seeded": seeded, "assets_by_match": counts,
            "epss_asof": ctx.epss_asof, "epss_time_matched": False}
