"""
Fetch CVSS and publication dates for every CVE in the CISA KEV snapshot from the NVD API, so known-exploited
CVEs can enter the M1 CVE pool (data/real/kev.jsonl has no CVSS).

    python scripts/fetch_nvd_kev.py          # writes data/real_extra/{nvd_kev.jsonl, MANIFEST.json}

Source: https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev  (NVD data is a US-government work; this product
uses data from the NVD API but is not endorsed or certified by the NVD). Only derived fields are stored.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "real_extra"
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev&resultsPerPage=500&startIndex={}"


def cvss(metrics: dict):
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV40", "4.0"), ("cvssMetricV2", "2.0")):
        for m in metrics.get(key, []):
            if m.get("type") == "Primary" or len(metrics[key]) == 1:
                d = m["cvssData"]
                return float(d["baseScore"]), ver, d.get("attackVector") or d.get("accessVector")
    return None, None, None


def main() -> int:
    kev = {json.loads(l)["cveID"]: json.loads(l) for l in (ROOT / "data" / "real" / "kev.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()}
    rows, start, total = [], 0, None
    while total is None or start < total:
        # curl, not urllib: NVD drops urllib's connections on this platform while curl is served normally
        for attempt in range(5):
            r = subprocess.run(["curl", "-s", "-f", "-m", "180", "-A", "CascadeShield-research/1.0 (hackathon dataset build)", URL.format(start)],
                               capture_output=True)
            if r.returncode == 0:
                page = json.loads(r.stdout)
                break
            print(f"page {start}: attempt {attempt + 1} failed (curl exit {r.returncode}); retrying", flush=True)
            time.sleep(10 * (attempt + 1))
        else:
            raise RuntimeError(f"NVD page {start} failed 5 times")
        total = page["totalResults"]
        for v in page["vulnerabilities"]:
            c = v["cve"]
            if c["id"] not in kev:
                continue
            score, ver, av = cvss(c.get("metrics", {}))
            k = kev[c["id"]]
            rows.append({"cve": c["id"], "published": c["published"][:10], "cvss_base": score, "cvss_version": ver, "attack_vector": av,
                         "vendor": k["vendorProject"], "product": k["product"], "kev_date_added": k["dateAdded"]})
        start += page["resultsPerPage"]
        time.sleep(6)  # NVD public rate limit
    rows.sort(key=lambda r: r["cve"])
    OUT.mkdir(parents=True, exist_ok=True)
    body = "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)
    (OUT / "nvd_kev.jsonl").write_text(body, encoding="utf-8", newline="\n")
    manifest = {"source": URL.format(0), "fetched_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "nvd_total_results": total, "rows": len(rows), "rows_without_cvss": sum(r["cvss_base"] is None for r in rows),
                "sha256": hashlib.sha256(body.encode()).hexdigest(),
                "notice": "This product uses data from the NVD API but is not endorsed or certified by the NVD."}
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
