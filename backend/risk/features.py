"""
M1 feature schema: the single source of truth for training, inference and data/schema.json.

Every feature is computed "as of" the window start t from information available at or before t; telemetry
features use the 30 days before t. Inference clips every value to its schema range and reports what it clipped.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Tuple

from data.ml_population import ASSET_TYPE_CODE, ZONE_ORD  # noqa: F401  (re-exported for callers)

# name: (dtype, min, max, group, source, real_or_simulated, description)
SCHEMA: Dict[str, tuple] = {
    "asset_type_code": ("categorical", 0, len(ASSET_TYPE_CODE) - 1, "asset", "inventory", "simulated", "asset type code (ordinal; explicit 'unknown' level)"),
    "zone_ord": ("int", 0, 3, "asset", "inventory", "simulated", "IT=0, DMZ=1, OT=2, SAFETY=3"),
    "criticality": ("int", 1, 5, "asset", "inventory", "simulated", "operator-assigned criticality"),
    "safety_critical": ("binary", 0, 1, "asset", "inventory", "simulated", "safety-instrumented asset"),
    "num_dependents": ("int", 0, 20, "asset", "dependency graph", "simulated", "assets that DIRECTLY depend on this one"),
    "supply_chain_flag": ("binary", 0, 1, "asset", "FirmwareRegistry check", "simulated", "firmware mismatch, unknown or revoked"),
    "internet_exposed": ("binary", 0, 1, "asset", "inventory", "simulated", "reachable from the internet"),
    "default_credentials": ("binary", 0, 1, "asset", "inventory", "simulated", "vendor default credentials in use"),
    "open_mgmt_ports": ("int", 0, 10, "asset", "inventory", "simulated", "count of open management ports"),
    "remote_access_enabled": ("binary", 0, 1, "asset", "inventory", "simulated", "vendor/remote access path enabled"),
    "firmware_known": ("binary", 0, 1, "asset", "inventory", "simulated", "firmware version is known"),
    "days_since_patch": ("int", 0, 2000, "asset", "inventory", "simulated", "days from last patch to t"),
    "has_vulnerability": ("binary", 0, 1, "vulnerability", "CISA CSAF advisories", "real CVE context", "any known CVE affects the asset at t"),
    "cve_count": ("int", 0, 20, "vulnerability", "CISA CSAF advisories", "real CVE context", "CVEs affecting the asset at t"),
    "max_cvss": ("float", 0.0, 10.0, "vulnerability", "CISA CSAF advisories", "real", "max CVSS base score; 0 with has_vulnerability=0 or missing_cvss=1"),
    "max_epss": ("float", 0.0, 1.0, "vulnerability", "proxy from CVSS + KEV", "proxy (EPSS not time-matched)", "max exploit-probability proxy"),
    "any_known_exploited": ("binary", 0, 1, "vulnerability", "CISA KEV", "real", "a CVE was in KEV at t"),
    "vuln_age_days": ("int", 0, 4000, "vulnerability", "CISA CSAF advisories", "real dates", "age of the oldest unpatched CVE at t"),
    "missing_cvss": ("binary", 0, 1, "vulnerability", "feed status", "simulated gaps", "CVSS unavailable; max_cvss set to fallback 0"),
    "missing_epss": ("binary", 0, 1, "vulnerability", "feed status", "simulated gaps", "EPSS unavailable; max_epss set to fallback 0"),
    "failed_auth_count": ("int", 0, 5000, "telemetry", "detection rules D", "simulated telemetry", "failed logins over the 30 days before t"),
    "new_remote_session_flag": ("binary", 0, 1, "telemetry", "detection rules D", "simulated telemetry", "rule D2 fired in the 30 days before t"),
    "rule_hit_count": ("int", 0, 200, "telemetry", "detection rules D", "simulated telemetry", "active-attack rule hits in the 30 days before t"),
    "high_severity_rule_hit": ("binary", 0, 1, "telemetry", "detection rules D", "simulated telemetry", "a high-severity rule fired"),
}
FEATURES: List[str] = list(SCHEMA)
# Asset type is passed to the trees as an ordinal code, not as a native categorical feature: shap's TreeExplainer
# does not reproduce HistGradientBoosting's categorical splits, so SHAP values would not add up (found in testing).
CATEGORICAL: List[str] = []
# a higher value of these must never lower predicted likelihood (enforced by the monotonic variant, checked by tests)
MONOTONE_INCREASING = ["internet_exposed", "default_credentials", "any_known_exploited", "days_since_patch", "max_cvss",
                       "max_epss", "supply_chain_flag", "open_mgmt_ports"]
LABELS = {
    "asset_type_code": "Asset type", "zone_ord": "Network zone sensitivity", "criticality": "Asset criticality",
    "safety_critical": "Safety-critical asset", "num_dependents": "Number of dependent assets",
    "supply_chain_flag": "Unattested / tampered firmware", "internet_exposed": "Internet-exposed",
    "default_credentials": "Default credentials in use", "open_mgmt_ports": "Open management ports",
    "remote_access_enabled": "Remote access enabled", "firmware_known": "Firmware version known",
    "days_since_patch": "Days since last patch", "has_vulnerability": "Has a known vulnerability",
    "cve_count": "Number of CVEs", "max_cvss": "Vulnerability severity (CVSS)", "max_epss": "Exploit likelihood (EPSS proxy)",
    "any_known_exploited": "Known exploited (CISA KEV)", "vuln_age_days": "Age of oldest open CVE",
    "missing_cvss": "CVSS missing", "missing_epss": "EPSS missing", "failed_auth_count": "Failed logins (30 days)",
    "new_remote_session_flag": "New remote-access source", "rule_hit_count": "Detection-rule hits (30 days)",
    "high_severity_rule_hit": "High-severity detection",
}


def clip(features: Dict[str, Any]) -> Tuple[Dict[str, float], List[str]]:
    """Coerce to the schema: missing/NaN/inf -> documented fallback (range minimum), out-of-range -> clipped.
    Returns (clean record, names of features that were missing or clipped)."""
    out, notes = {}, []
    for f, (dtype, lo, hi, *_rest) in SCHEMA.items():
        v = features.get(f)
        try:
            v = float(v)
        except (TypeError, ValueError):
            v = float("nan")
        if math.isnan(v) or math.isinf(v):
            out[f] = float(lo)
            notes.append(f"{f}:missing")
            continue
        if v < lo or v > hi:
            notes.append(f"{f}:clipped")
            v = min(max(v, lo), hi)
        out[f] = float(int(round(v))) if dtype in ("int", "binary", "categorical") else v
    return out, notes


def schema_json() -> Dict[str, Any]:
    return {f: {"type": s[0], "min": s[1], "max": s[2], "group": s[3], "source": s[4], "real_or_simulated": s[5],
                "description": s[6], "monotone_increasing": f in MONOTONE_INCREASING} for f, s in SCHEMA.items()}
