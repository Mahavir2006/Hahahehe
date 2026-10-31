# data/real_extra — sources

`nvd_kev.jsonl`: CVSS base score, CVSS version, attack vector and publication date from the NVD CVE API 2.0 for
every CVE in the CISA KEV snapshot (`data/real/kev.jsonl`), joined with KEV's vendor, product and dateAdded.

- Source: https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev (fetch time and sha256 in `MANIFEST.json`).
- Rebuild: `python scripts/fetch_nvd_kev.py`.
- Licence: NVD data is a work of the US government and not subject to copyright in the US.
- Notice requested by NVD's terms of use: "This product uses data from the NVD API but is not endorsed or certified by the NVD."
- CVSS is as published at fetch time; for windows in 2024-2025 it is assumed unchanged since then. Publication date
  and KEV dateAdded are used for time-matching, so a CVE exists for an asset only after it was published and counts
  as known-exploited only after it was added to KEV.
