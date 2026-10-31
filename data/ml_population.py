"""
Simulated asset population for training M1 (one row = one asset in one 90-day window).

What is real and what is simulated:
* REAL: the CVE context. Each vulnerable asset draws its CVEs from the CISA CSAF OT advisory snapshot in
  data/real (sector-matched, product-keyword-matched where possible), with real CVSS scores, real release dates
  and real KEV membership, all time-matched to the window start t.
* SIMULATED: the assets themselves, their configuration, patch history and network exposure.
* PROXY: EPSS. The real EPSS file in data/real is not time-matched, so the exploit-probability feature is the
  documented proxy `estimate_epss(cvss, known_exploited_at_t)` (epss_source = "proxy").

Features are drawn with realistic correlations (exposure depends on zone, default credentials on firmware age,
patch age on zone), not as independent uniform draws. Labels are NOT made here: see data/label_process.py.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend import data_real  # noqa: E402
from backend.agents.advisory_parser import estimate_epss  # noqa: E402

WINDOW_DAYS = 90
TELEMETRY_DAYS = 30
FIRST_WINDOW = date(2024, 1, 1)
N_WINDOWS = 8
SECTOR_OF = {"energy": "Energy", "water": "Water and Wastewater", "healthcare": "Healthcare and Public Health"}
ZONES = ["IT", "DMZ", "OT", "SAFETY"]
ZONE_ORD = {"IT": 0, "DMZ": 1, "OT": 2, "SAFETY": 3}
MGMT_PORTS = {22, 23, 80, 443, 3389, 5900, 8080, 8443, 5000}

# type: (sector or "any", zone probabilities, criticality range, P(safety-critical), mgmt-port rate, P(remote access), product keywords)
TYPES: Dict[str, tuple] = {
    "substation gateway": ("energy", {"DMZ": .5, "OT": .5}, (4, 5), .10, 2.0, .50, ["gateway", "substation", "sicam"]),
    "RTU": ("energy", {"OT": .8, "SAFETY": .2}, (4, 5), .30, 1.0, .20, ["rtu", "remote terminal"]),
    "smart meter": ("energy", {"OT": .6, "DMZ": .4}, (2, 3), .00, 0.5, .30, ["meter", "metering"]),
    "SCADA server": ("any", {"OT": .7, "DMZ": .3}, (4, 5), .20, 2.5, .40, ["scada"]),
    "historian": ("any", {"DMZ": .5, "IT": .3, "OT": .2}, (3, 4), .00, 2.0, .40, ["historian"]),
    "SCADA historian": ("any", {"DMZ": .5, "OT": .5}, (3, 4), .00, 2.0, .40, ["historian", "scada"]),
    "HMI": ("any", {"OT": .9, "SAFETY": .1}, (3, 5), .30, 1.5, .30, ["hmi", "panel", "visualiz"]),
    "PLC": ("any", {"OT": .6, "SAFETY": .4}, (4, 5), .50, 0.8, .10, ["plc", "logix", "simatic", "modicon", "programmable"]),
    "pump controller": ("water", {"OT": .7, "SAFETY": .3}, (4, 5), .40, 0.8, .20, ["pump", "drive"]),
    "chlorination controller": ("water", {"SAFETY": .7, "OT": .3}, (5, 5), .90, 0.6, .10, ["dosing", "analyzer", "controller"]),
    "firewall": ("any", {"DMZ": .8, "IT": .2}, (4, 5), .00, 2.0, .70, ["firewall", "router"]),
    "jump host": ("any", {"DMZ": .9, "IT": .1}, (3, 4), .00, 3.0, .95, ["remote access", "vpn"]),
    "IoT sensor": ("any", {"OT": .6, "IT": .4}, (1, 3), .00, 0.6, .20, ["sensor", "transmitter", "iot"]),
    "building management system": ("healthcare", {"IT": .5, "OT": .5}, (2, 4), .10, 1.5, .40, ["building", "hvac", "bms"]),
    "PACS server": ("healthcare", {"IT": .9, "DMZ": .1}, (3, 4), .00, 2.0, .30, ["pacs", "imaging", "dicom"]),
    "EHR server": ("healthcare", {"IT": .9, "DMZ": .1}, (4, 5), .00, 2.0, .30, ["clinical", "patient", "record"]),
    "medical device gateway": ("healthcare", {"OT": .5, "IT": .5}, (4, 5), .60, 1.0, .30, ["infusion", "monitor", "medical", "patient"]),
    "hospital network switch": ("healthcare", {"IT": .8, "DMZ": .2}, (3, 4), .00, 1.5, .20, ["switch", "network"]),
}
ASSET_TYPES = sorted(TYPES) + ["unknown"]          # "unknown" is an explicit level, also used for unseen types
ASSET_TYPE_CODE = {t: i for i, t in enumerate(ASSET_TYPES)}
EXPOSE_P = {"IT": .20, "DMZ": .45, "OT": .05, "SAFETY": .02}
PATCH_INTERVAL = {"IT": (45, 200), "DMZ": (60, 260), "OT": (180, 720), "SAFETY": (300, 1100)}


def window_start(w: int) -> date:
    return FIRST_WINDOW + timedelta(days=WINDOW_DAYS * w)


@dataclass
class Asset:
    asset_id: str
    sector: str
    asset_type: str
    zone: str
    criticality: int
    safety_critical: int
    num_dependents: int
    internet_exposed: int
    default_credentials: int
    open_mgmt_ports: int
    remote_access_enabled: int
    firmware_known: int
    supply_chain_flag: int
    firmware_age_years: float
    patch_interval_days: float
    vuln_proneness: float
    last_patch: date = FIRST_WINDOW
    cves: List[Dict[str, Any]] = field(default_factory=list)


class CvePool:
    """Real advisories grouped by sector and asset-type keyword, with KEV dates for time-matching."""

    def __init__(self):
        self.rows = []
        kev = {k["cveID"]: date.fromisoformat(k["dateAdded"]) for k in data_real.load_kev()}
        for v in data_real.load_vulns():
            self.rows.append({
                "cve": v["cve"], "cvss": float(v["cvss_base"]), "sector": v["assigned_sector"],
                "released": date.fromisoformat(v["initial_release_date"][:10]),
                "kev_added": kev.get(v["cve"]),
                "text": " ".join([v.get("title") or "", " ".join(v.get("product_names") or [])]).lower(),
            })
        self.by_sector = {s: [r for r in self.rows if r["sector"] == s] for s in SECTOR_OF.values()}
        self._typed: Dict[tuple, List[dict]] = {}

    def candidates(self, sector: str, asset_type: str) -> tuple:
        key = (sector, asset_type)
        if key not in self._typed:
            kws = TYPES.get(asset_type, ("", {}, (1, 1), 0, 0, 0, []))[6]
            pool = [r for r in self.by_sector[SECTOR_OF[sector]] if any(k in r["text"] for k in kws)]
            self._typed[key] = pool
        typed = self._typed[key]
        return (typed, True) if len(typed) >= 5 else (self.by_sector[SECTOR_OF[sector]], False)


def make_assets(n: int, rng: np.random.Generator, prefix: str) -> List[Asset]:
    names = sorted(TYPES)
    out = []
    for i in range(n):
        unknown = rng.random() < 0.03
        t = names[rng.integers(len(names))]
        sector_s, zone_p, crit_rng, p_safe, port_rate, p_remote, _ = TYPES[t]
        sector = sector_s if sector_s != "any" else ["energy", "water", "healthcare"][rng.integers(3)]
        zone = rng.choice(list(zone_p), p=list(zone_p.values()))
        age = float(min(rng.gamma(2.0, 1.6), 14.0))
        fw_known = int(rng.random() > 0.03 + 0.015 * age)
        exposed = int(rng.random() < EXPOSE_P[zone] * (1.6 if t in ("jump host", "firewall") else 1.0))
        dc = int(rng.random() < 1 / (1 + np.exp(-(-3.2 + 0.35 * age + (0.5 if zone in ("OT", "SAFETY") else 0.0)))))
        ports = int(min(rng.poisson(port_rate * (1.4 if exposed else 1.0)), 8))
        lo, hi = PATCH_INTERVAL[zone]
        a = Asset(
            asset_id=f"{prefix}-{i:05d}", sector=sector, asset_type="unknown" if unknown else t, zone=zone,
            criticality=int(rng.integers(crit_rng[0], crit_rng[1] + 1)), safety_critical=int(rng.random() < p_safe),
            num_dependents=int(min(rng.poisson(1.2 + 2.0 * (crit_rng[1] >= 5)), 12)), internet_exposed=exposed,
            default_credentials=dc, open_mgmt_ports=ports, remote_access_enabled=int(rng.random() < p_remote),
            firmware_known=fw_known, supply_chain_flag=int(rng.random() < 0.02 + 0.10 * (1 - fw_known) + 0.006 * age),
            firmware_age_years=round(age, 2), patch_interval_days=float(rng.uniform(lo, hi)),
            vuln_proneness=float(rng.gamma(1.2, 0.9)),
        )
        a.last_patch = FIRST_WINDOW - timedelta(days=int(rng.uniform(0, a.patch_interval_days)))
        out.append(a)
    return out


def advance(a: Asset, t: date, rng: np.random.Generator) -> None:
    """Patch events up to t (Poisson process at the asset's own rate). A patch clears CVEs released before it."""
    day = a.last_patch
    while True:
        nxt = day + timedelta(days=max(1, int(rng.exponential(a.patch_interval_days))))
        if nxt >= t:
            break
        day = nxt
    if day > a.last_patch:
        a.last_patch = day
        a.cves = [c for c in a.cves if c["released"] > day]


def cve_context(a: Asset, t: date, pool: CvePool, rng: np.random.Generator, stats: Dict[str, int]) -> Dict[str, Any]:
    """Draw new CVEs released in (last_patch, t] at the asset's proneness; aggregate everything known at t."""
    cands, typed = pool.candidates(a.sector, a.asset_type)
    fresh = [r for r in cands if a.last_patch < r["released"] <= t and r["cve"] not in {c["cve"] for c in a.cves}]
    lam = a.vuln_proneness * min((t - a.last_patch).days, 1500) / 365.0 * 0.55
    k = min(int(rng.poisson(lam)), len(fresh), 6 - len(a.cves))
    if k > 0:
        for j in rng.choice(len(fresh), size=k, replace=False):
            a.cves.append(fresh[int(j)])
        stats["typed" if typed else "sector_fallback"] += k
    known = [c for c in a.cves if c["released"] <= t]
    if not known:
        return {"has_vulnerability": 0, "cve_count": 0, "max_cvss": 0.0, "max_epss": 0.0, "any_known_exploited": 0,
                "vuln_age_days": 0, "missing_cvss": 0, "missing_epss": 0, "max_source_date": None, "cve_ids": ""}
    kev = [bool(c["kev_added"] and c["kev_added"] <= t) for c in known]
    rec = {
        "has_vulnerability": 1, "cve_count": len(known), "max_cvss": max(c["cvss"] for c in known),
        "max_epss": max(estimate_epss(c["cvss"], e) for c, e in zip(known, kev)), "any_known_exploited": int(any(kev)),
        "vuln_age_days": (t - min(c["released"] for c in known)).days, "missing_cvss": 0, "missing_epss": 0,
        "max_source_date": max([c["released"] for c in known] + [c["kev_added"] for c, e in zip(known, kev) if e]).isoformat(),
        "cve_ids": ";".join(sorted(c["cve"] for c in known)),
    }
    # simulated feed gaps, so the fallback path is exercised: value -> documented fallback 0.0, flag set
    if rng.random() < 0.08:
        rec["max_epss"], rec["missing_epss"] = 0.0, 1
    if rng.random() < 0.03:
        rec["max_cvss"], rec["missing_cvss"] = 0.0, 1
    return rec


def static_record(a: Asset) -> Dict[str, Any]:
    return {
        "asset_id": a.asset_id, "sector": a.sector, "asset_type": a.asset_type, "asset_type_code": ASSET_TYPE_CODE[a.asset_type],
        "zone": a.zone, "zone_ord": ZONE_ORD[a.zone], "criticality": a.criticality, "safety_critical": a.safety_critical,
        "num_dependents": a.num_dependents, "supply_chain_flag": a.supply_chain_flag, "internet_exposed": a.internet_exposed,
        "default_credentials": a.default_credentials, "open_mgmt_ports": a.open_mgmt_ports,
        "remote_access_enabled": a.remote_access_enabled, "firmware_known": a.firmware_known,
    }


def build_population(n_assets: int, seed: int, prefix: str, pool: Optional[CvePool] = None) -> tuple:
    """Return (assets, rows) where rows are the observable, time-matched records per asset-window (no label)."""
    rng = np.random.default_rng(seed)
    pool = pool or CvePool()
    assets = make_assets(n_assets, rng, prefix)
    rows, stats = [], {"typed": 0, "sector_fallback": 0}
    for w in range(N_WINDOWS):
        t = window_start(w)
        for a in assets:
            advance(a, t, rng)
            r = static_record(a)
            r.update({"window": w, "window_start": t.isoformat(), "days_since_patch": (t - a.last_patch).days})
            r.update(cve_context(a, t, pool, rng, stats))
            rows.append(r)
    return assets, rows, stats
