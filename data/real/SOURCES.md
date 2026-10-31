# data/real — sources

Real public data, snapshotted by `scripts/build_real_snapshot.py` on **2026-10-31** (fetch_date 2026-10-31T12:52:01Z).
Commit hashes, row counts and checksums are in `MANIFEST.json`; `backend/data_real.py` verifies them on every load.
No clone or raw download is committed: only the derived files listed in the manifest.

## 1. CISA CSAF OT advisories → `vuln_snapshot.jsonl`

- URL: https://github.com/cisagov/CSAF
- Commit: `3c2594d3dfa2ae5e36146f934b5e231ffbdb3d06` (2026-10-29T14:31:19-06:00)
- Fetched: shallow, blob-filtered, sparse clone of `csaf_files/OT/white/2022` … `2026` only (2,153 advisories).
  Each file's `.sha512` sidecar was checked (0 mismatches).
- Licence: **licence not found**. The repository has no licence file at its root. The only licence file
  in it is `tools/csaf2md/LICENSE.md`, which covers a conversion tool, not the advisory data.
- Distribution marking found in all 300 selected advisories: `"tlp": {"label": "WHITE"}`,
  `"text": "Disclosure is not limited"`.
- Legal notes found in the selected advisories (verbatim):
  - 172 advisories, "Legal Notice": "All information products included in https://us-cert.cisa.gov/ics are provided
    "as is" for informational purposes only. The Department of Homeland Security (DHS) does not provide any warranties
    of any kind regarding any information contained within. DHS does not endorse any commercial product or service,
    referenced in this product or otherwise. Further dissemination of this product is governed by the Traffic Light
    Protocol (TLP) marking in the header. For more information about TLP, see https://us-cert.cisa.gov/tlp/."
  - 128 advisories, "Legal Notice and Terms of Use": "This product is provided subject to this Notification
    (https://www.cisa.gov/notification) and this Privacy & Use policy (https://www.cisa.gov/privacy-policy)."

## 2. CISA Known Exploited Vulnerabilities → `kev.jsonl`

- URL: https://github.com/cisagov/kev-data
- Commit: `7ccba8e1223ccec82d12c7736bf3fae11e5bee86` (2026-10-30T20:27:53Z)
- catalogVersion: `2026.10.30` (dateReleased 2026-10-30T17:02:45.3665Z, count 1766)
- Fields kept: cveID, vendorProject, product, dateAdded, knownRansomwareCampaignUse (all 1,766 entries).
- Licence text found (`LICENSE`, first paragraph verbatim, followed in the file by the full
  "Creative Commons Legal Code / CC0 1.0 Universal" text):
  "The KEV database is distributed under the Creative Commons 0 1.0 License. You may use this data in any legal
  manner but note that information provided at any 3rd party links included in the KEV database are bound by the
  policies and licenses of those 3rd party websites. Use of the information does not authorize you to use the CISA
  Logo or DHS Seal, nor should such use be interpreted as an endorsement by CISA or DHS."

## 3. FIRST EPSS → `epss.jsonl`

- URL: https://api.first.org/data/v1/epss (official FIRST API; documented at https://api.first.org/epss/ and
  https://www.first.org/epss/data). Queried only for the 811 CVEs in `vuln_snapshot.jsonl`, in 9 requests; 801 returned.
- Scores are as of **2026-10-30** and are **not time-matched** to advisory dates (`time_matched: false`).
  `load_epss()` refuses any as-of date earlier than that.
- Licence: no licence for the EPSS scores was found on the EPSS pages. Terms found:
  - https://www.first.org/epss/faq: "EPSS scores are published freely via CSV download and API with no registration
    required." and "Attribution is requested when EPSS data is used in publications or products."
  - https://www.first.org/about/policies/terms (FIRST Services Terms of Use): "FIRST grants you a nonexclusive,
    nontransferable, revocable, limited license to view, copy, print, and distribute Content … only for vulnerability
    disclosure, cybersecurity incident response, or preventative cybersecurity uses … provided that you do not remove,
    alter, or obscure any copyright notice"; other uses need FIRST's prior written permission.
  - Copyright notice on the EPSS pages, kept here as the terms require:
    "Copyright © 2015—2026 by Forum of Incident Response and Security Teams, Inc. All Rights Reserved."
- Attribution: EPSS scores from FIRST, https://www.first.org/epss/ .
  Use of `epss.jsonl` is limited to preventative cybersecurity uses under the terms above.
