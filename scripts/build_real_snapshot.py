#!/usr/bin/env python3
"""
Build data/real/: a small, checksummed snapshot of real public data (DATA-REAL-01..04).

Sources (clones live OUTSIDE this repo and are never committed):
  - CISA CSAF OT advisories 2022-2026  (git clone --depth 1 --filter=blob:none --sparse
        https://github.com/cisagov/CSAF ; sparse-checkout csaf_files/OT/white/2022..2026)
  - CISA KEV                            (git clone --depth 1 https://github.com/cisagov/kev-data)
  - FIRST EPSS API                      (https://api.first.org/data/v1/epss, only the snapshot's CVEs)

Usage:
  python scripts/build_real_snapshot.py --csaf <csaf clone> --kev <kev clone> [--no-epss]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.data_real import SIZE_CAP_BYTES, content_sha256, count_rows, dir_size_bytes, parse_version_range  # noqa: E402

SEED = 42
YEARS = range(2022, 2027)
SECTORS = ["Energy", "Water and Wastewater", "Healthcare and Public Health"]
PER_SECTOR = 100
MAX_CVES = 50
CSAF_URL = "https://github.com/cisagov/CSAF"
KEV_URL = "https://github.com/cisagov/kev-data"
EPSS_API = "https://api.first.org/data/v1/epss"


def git_info(repo: Path) -> Dict[str, str]:
    def g(*a: str) -> str:
        return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, check=True).stdout.strip()
    return {"commit": g("rev-parse", "HEAD"), "commit_date": g("log", "-1", "--format=%cI")}


def note(doc: Dict[str, Any], title: str) -> Optional[str]:
    for n in doc.get("notes", []):
        if (n.get("title") or "").strip().lower() == title.lower():
            return n.get("text")
    return None


def split_list(text: Optional[str]) -> List[str]:
    return [p.strip() for p in (text or "").split(",") if p.strip()]


def assign_sector(sectors: List[str]) -> Optional[str]:
    for s in sectors:
        for target in SECTORS:
            if target in s:
                return target
    return None


def walk_products(branches: List[Dict[str, Any]], ctx: Dict[str, Any], out: Dict[str, Dict[str, Any]]) -> None:
    for b in branches:
        c = dict(ctx)
        cat, name = b.get("category"), b.get("name")
        if cat == "vendor":
            c["vendor"] = name
        elif cat == "product_family":
            c["product_family"] = name
        elif cat == "product_name":
            c["product_name"] = name
        elif cat in ("product_version", "product_version_range"):
            c["version_raw"] = name
        p = b.get("product")
        if p:
            out[p["product_id"]] = {
                "vendor": c.get("vendor"), "product_family": c.get("product_family"),
                "product_name": c.get("product_name") or p.get("name"), "full_name": p.get("name"),
                "version_raw": c.get("version_raw"),
            }
        walk_products(b.get("branches", []), c, out)


def products_of(tree: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    walk_products(tree.get("branches", []), {}, out)
    for p in tree.get("full_product_names", []):
        out.setdefault(p["product_id"], {"vendor": None, "product_family": None, "product_name": p.get("name"),
                                         "full_name": p.get("name"), "version_raw": None})
    return out


AV_CODES = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}


def attack_vector(explicit: Optional[str], vector: Optional[str]) -> Optional[str]:
    """The explicit field when CSAF gives it, else the AV: metric of the vector string; None if neither."""
    if explicit:
        return explicit
    for part in (vector or "").split("/"):
        if part.startswith("AV:"):
            return AV_CODES.get(part[3:])
    return None


def pick_score(v: Dict[str, Any]) -> Dict[str, Any]:
    v3 = [s["cvss_v3"] for s in v.get("scores", []) if s.get("cvss_v3")]
    v2 = [s["cvss_v2"] for s in v.get("scores", []) if s.get("cvss_v2")]
    if v3:
        s = v3[0]
        return {"cvss_version": s.get("version"), "cvss_base": s.get("baseScore"), "cvss_vector": s.get("vectorString"),
                "attack_vector": attack_vector(s.get("attackVector"), s.get("vectorString")), "cvss_v2_also_present": bool(v2),
                "cvss_multiple_scores": len({x.get("baseScore") for x in v3}) > 1}
    if v2:
        s = v2[0]
        return {"cvss_version": s.get("version") or "2.0", "cvss_base": s.get("baseScore"), "cvss_vector": s.get("vectorString"),
                "attack_vector": attack_vector(s.get("accessVector"), s.get("vectorString")), "cvss_v2_also_present": True,
                "cvss_multiple_scores": len({x.get("baseScore") for x in v2}) > 1}
    return {"cvss_version": None, "cvss_base": None, "cvss_vector": None, "attack_vector": None,
            "cvss_v2_also_present": False, "cvss_multiple_scores": False}


def affected_entries(ids: List[str], products: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen, out = set(), []
    for pid in ids:
        p = products.get(pid, {"product_name": None, "version_raw": None})
        key = (p.get("product_name"), p.get("version_raw"))
        if key in seen:
            continue
        seen.add(key)
        out.append({"product": p.get("product_name"), "version_raw": p.get("version_raw"),
                    "range": parse_version_range(p["version_raw"]) if p.get("version_raw") is not None else None})
    return out


def read_advisories(csaf: Path) -> Dict[str, Any]:
    """Every OT/white 2022-2026 advisory with its assigned sector; checks each .sha512 sidecar."""
    advs: Dict[str, Dict[str, Any]] = {}
    sidecar_bad: List[str] = []
    sidecar_missing = 0
    for y in YEARS:
        for f in sorted((csaf / "csaf_files" / "OT" / "white" / str(y)).glob("*.json")):
            raw = f.read_bytes().replace(b"\r\n", b"\n")  # undo core.autocrlf so hashes match upstream
            side = f.with_name(f.name + ".sha512")
            if side.exists():
                if hashlib.sha512(raw).hexdigest() != side.read_text(encoding="utf-8").split()[0].lower():
                    sidecar_bad.append(f.name)
                    continue
            else:
                sidecar_missing += 1
            d = json.loads(raw)
            doc = d["document"]
            sectors = split_list(note(doc, "Critical infrastructure sectors"))
            vendors = [b.get("name") for b in d.get("product_tree", {}).get("branches", []) if b.get("category") == "vendor"]
            adv = {"id": doc["tracking"]["id"], "path": f.relative_to(csaf).as_posix(), "sha256": hashlib.sha256(raw).hexdigest(),
                   "year": y, "sectors": sectors, "sector": assign_sector(sectors),
                   "vendor": (vendors[0] if vendors else None), "doc": d}
            prev = advs.get(adv["id"])
            if prev is None or doc["tracking"].get("current_release_date", "") > prev["doc"]["document"]["tracking"].get("current_release_date", ""):
                advs[adv["id"]] = adv
    return {"advisories": advs, "sidecar_bad": sidecar_bad, "sidecar_missing": sidecar_missing}


def round_robin(pool: List[Dict[str, Any]], rng: random.Random) -> List[Dict[str, Any]]:
    """Order a sector's advisories so vendors take turns (vendor order and within-vendor order seeded)."""
    by_vendor: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for a in sorted(pool, key=lambda a: a["id"]):
        by_vendor[(a["vendor"] or "").strip().casefold()].append(a)
    vendors = sorted(by_vendor)
    rng.shuffle(vendors)
    for v in vendors:
        rng.shuffle(by_vendor[v])
    order: List[Dict[str, Any]] = []
    while any(by_vendor[v] for v in vendors):
        for v in vendors:
            if by_vendor[v]:
                order.append(by_vendor[v].pop(0))
    return order


def select(advs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    rng = random.Random(SEED)
    queues = {s: round_robin([a for a in advs.values() if a["sector"] == s], rng) for s in SECTORS}
    available = {s: len(q) for s, q in queues.items()}
    picked: Dict[str, List[Dict[str, Any]]] = {s: queues[s][:PER_SECTOR] for s in SECTORS}
    rest = {s: queues[s][PER_SECTOR:] for s in SECTORS}
    fills: Dict[str, Dict[str, int]] = {}
    for s in SECTORS:
        short = PER_SECTOR - len(picked[s])
        donors = [o for o in SECTORS if o != s]
        while short > 0 and any(rest[o] for o in donors):
            for o in donors:
                if short > 0 and rest[o]:
                    a = rest[o].pop(0)
                    a["fill_for"] = s
                    picked[s].append(a)
                    fills.setdefault(s, Counter())[o] += 1
                    short -= 1
    return {"picked": picked, "available": available, "fills": {s: dict(c) for s, c in fills.items()}}


def rows_for(adv: Dict[str, Any], slot: str) -> List[Dict[str, Any]]:
    d = adv["doc"]
    doc = d["document"]
    products = products_of(d.get("product_tree", {}))
    vulns = [v for v in d.get("vulnerabilities", []) if v.get("cve")]
    total = len(vulns)
    rows = []
    for v in vulns[:MAX_CVES]:
        status = v.get("product_status", {})
        ka_ids = status.get("known_affected", []) or []
        affected = [products.get(i, {}) for i in ka_ids]
        vendor = next((p["vendor"] for p in affected if p.get("vendor")), adv["vendor"])
        family = next((p["product_family"] for p in affected if p.get("product_family")), None)
        summary = next((n.get("text") for n in v.get("notes", []) if n.get("category") == "summary"), None) \
            or next((n.get("text") for n in v.get("notes", []) if n.get("category") == "description"), None)
        mitig, seen = [], set()
        for r in v.get("remediations", []):
            t = (r.get("details") or "").strip()
            if t and t not in seen:
                seen.add(t)
                mitig.append(f"[{r.get('category')}] {t}")
        cwe = v.get("cwe") or {}
        row = {
            "advisory_id": doc["tracking"]["id"], "title": doc.get("title"),
            "initial_release_date": doc["tracking"].get("initial_release_date"),
            "sectors": adv["sectors"], "assigned_sector": adv["sector"], "selected_for_sector": slot,
            "countries": split_list(note(doc, "Countries/areas deployed")),
            "vendor": vendor, "product_family": family,
            "product_names": sorted({p["product_name"] for p in affected if p.get("product_name")}),
            "raw_version_strings": sorted({p["version_raw"] for p in affected if p.get("version_raw") is not None}),
            "known_affected": affected_entries(ka_ids, products),
            "fixed": affected_entries(status.get("fixed", []) or [], products),
            "cve": v["cve"], **pick_score(v), "cwe_id": cwe.get("id"),
            "summary": summary, "mitigation_text": "\n".join(mitig) or None,
            "cves_in_advisory": total, "cves_capped": total > MAX_CVES,
            "source_path": adv["path"], "source_sha256": adv["sha256"],
        }
        rows.append(row)
    return rows


def fetch_epss(cves: List[str]) -> Dict[str, Any]:
    rows, batches, batch = [], [], []
    for c in cves:
        if batch and (len(",".join(batch + [c])) > 1900 or len(batch) >= 100):
            batches.append(batch)
            batch = []
        batch.append(c)
    if batch:
        batches.append(batch)
    for b in batches:
        url = EPSS_API + "?" + urllib.parse.urlencode({"cve": ",".join(b)})
        req = urllib.request.Request(url, headers={"User-Agent": "CascadeShield-snapshot/1.0"})
        with urllib.request.urlopen(req, timeout=60) as r:
            body = json.loads(r.read().decode("utf-8"))
        if body.get("status-code") != 200:
            raise RuntimeError(f"EPSS API status {body.get('status-code')}: {body.get('status')}")
        if int(body.get("total", 0)) != len(body["data"]):
            raise RuntimeError(f"EPSS API paginated unexpectedly: total={body.get('total')} got={len(body['data'])}")
        for d in body["data"]:
            rows.append({"cve": d["cve"], "epss": float(d["epss"]), "percentile": float(d["percentile"]),
                         "epss_asof_date": d["date"], "time_matched": False})
        time.sleep(1)
    return {"rows": rows, "batches": len(batches)}


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csaf", required=True, type=Path)
    ap.add_argument("--kev", required=True, type=Path)
    ap.add_argument("--out", default=ROOT / "data" / "real", type=Path)
    ap.add_argument("--no-epss", action="store_true")
    a = ap.parse_args()
    out: Path = a.out
    out.mkdir(parents=True, exist_ok=True)
    fetched = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    read = read_advisories(a.csaf)
    advs = read["advisories"]
    sel = select(advs)
    vuln_rows: List[Dict[str, Any]] = []
    for s in SECTORS:
        for adv in sel["picked"][s]:
            vuln_rows.extend(rows_for(adv, s))
    write_jsonl(out / "vuln_snapshot.jsonl", vuln_rows)

    kev_doc = json.loads((a.kev / "known_exploited_vulnerabilities.json").read_text(encoding="utf-8"))
    kev_rows = [{k: v.get(k) for k in ("cveID", "vendorProject", "product", "dateAdded", "knownRansomwareCampaignUse")}
                for v in kev_doc["vulnerabilities"]]
    write_jsonl(out / "kev.jsonl", kev_rows)

    epss_info: Dict[str, Any] = {"fetched": False}
    cves = sorted({r["cve"] for r in vuln_rows})
    if not a.no_epss:
        e = fetch_epss(cves)
        write_jsonl(out / "epss.jsonl", sorted(e["rows"], key=lambda r: r["cve"]))
        dates = sorted({r["epss_asof_date"] for r in e["rows"]})
        epss_info = {"fetched": True, "url": EPSS_API, "asof_dates": dates, "batches": e["batches"],
                     "cves_requested": len(cves), "cves_returned": len(e["rows"]), "fetched_at": fetched}

    files = {}
    for name in ("vuln_snapshot.jsonl", "kev.jsonl", "epss.jsonl"):
        p = out / name
        if p.exists():
            b = p.read_bytes()
            files[name] = {"sha256": content_sha256(b), "rows": count_rows(b), "bytes": len(b)}
    manifest = {
        "generated_by": "scripts/build_real_snapshot.py", "fetch_date": fetched, "seed": SEED,
        "checksum": "sha256 over file bytes with CRLF normalised to LF",
        "files": files,
        "sources": {
            "csaf": {"url": CSAF_URL, **git_info(a.csaf), "paths": [f"csaf_files/OT/white/{y}/*.json" for y in YEARS],
                     "advisories_read": len(advs), "sidecar_sha512_mismatch": read["sidecar_bad"],
                     "sidecar_sha512_missing": read["sidecar_missing"]},
            "kev": {"url": KEV_URL, **git_info(a.kev), "catalogVersion": kev_doc.get("catalogVersion"),
                    "dateReleased": kev_doc.get("dateReleased"), "count": kev_doc.get("count")},
            "epss": epss_info,
        },
        "selection": {"per_sector_target": PER_SECTOR, "eligible_per_sector": sel["available"],
                      "picked_per_sector": {s: len(sel["picked"][s]) for s in SECTORS}, "fills": sel["fills"],
                      "max_cves_per_advisory": MAX_CVES},
    }
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")

    size = dir_size_bytes(out)
    print(json.dumps({"files": files, "selection": manifest["selection"], "epss": epss_info,
                      "sidecar_bad": len(read["sidecar_bad"]), "size_bytes": size}, indent=1))
    if size >= SIZE_CAP_BYTES:
        print(f"FAIL: data/real is {size} bytes, cap is {SIZE_CAP_BYTES}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
