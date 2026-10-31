"""
Detection rules D: deterministic rules over simulated daily telemetry. Not machine learning.

Each rule turns telemetry into finding records; findings are either "active_attack" (telemetry) or "exposure"
(asset configuration), never mixed. The aggregated telemetry features feed M1 (backend/risk/features.py).
Thresholds are hand-set and documented here; their precision/recall on the injected episodes is in
docs/ML_REPORT.md.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pandas as pd

# rule id: (episode type it targets, condition on a daily row, severity, description). Days on the maintenance
# calendar are excluded where scheduled work legitimately produces the same signal.
RULES = {
    "D1": ("auth_bruteforce", lambda r: r.failed_auth >= 20, "high", "20+ failed logins in one day"),
    "D2": ("unexpected_remote", lambda r: (r.new_remote_source > 0) & (r.maintenance == 0), "medium", "remote session from a new source outside maintenance"),
    "D3": ("lateral_movement", lambda r: r.lateral_new_peers >= 5, "high", "5+ new internal peers in one day"),
    "D4": ("abnormal_ot", lambda r: (r.ot_write_anomalies >= 2) & (r.maintenance == 0), "high", "abnormal OT protocol writes outside maintenance"),
    "D5": ("unexpected_config", lambda r: (r.config_changes > 0) & (r.maintenance == 0), "medium", "configuration change outside maintenance"),
    "D6": ("exploit_indicator", lambda r: r.exploit_sig > 0, "high", "IDS known-exploit signature"),
}
TELEMETRY_FEATURES = ["failed_auth_count", "new_remote_session_flag", "rule_hit_count", "high_severity_rule_hit"]


def run(daily: pd.DataFrame, window_start: Optional[str] = None, related_cve: Optional[Dict[str, str]] = None) -> pd.DataFrame:
    """All active-attack findings for the given daily telemetry (one row per rule hit per day)."""
    out = []
    for rid, (etype, cond, sev, desc) in RULES.items():
        hits = daily[cond(daily)]
        if hits.empty:
            continue
        f = hits[["asset_id", "window", "day"]].copy()
        f["rule"] = rid
        f["detection_method"] = f"rule:{rid}"
        f["finding_type"] = "active_attack"
        f["episode_type"] = etype
        f["severity"] = sev
        f["confidence"] = 0.9 if sev == "high" else 0.6
        f["evidence"] = desc
        f["source"] = "telemetry"
        f["related_cve"] = f["asset_id"].map(related_cve or {}).fillna("") if etype == "exploit_indicator" else ""
        if window_start is not None:
            f["event_time"] = (pd.Timestamp(window_start) - pd.Timedelta(days=30) + pd.to_timedelta(f["day"], unit="D")).dt.date.astype(str)
        out.append(f)
    if not out:
        return pd.DataFrame(columns=["asset_id", "window", "day", "rule", "detection_method", "finding_type", "episode_type", "severity", "confidence", "evidence", "source", "related_cve"])
    return pd.concat(out, ignore_index=True)


def exposure_findings(asset: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Configuration findings (finding_type "exposure"): kept separate from active-attack findings."""
    out = []
    if asset.get("internet_exposed") and (asset.get("default_credentials") or asset.get("open_mgmt_ports", 0) >= 2):
        out.append({"asset_id": asset["asset_id"], "rule": "X1", "finding_type": "exposure", "severity": "high", "confidence": 1.0,
                    "evidence": "internet-exposed with default credentials or 2+ management ports", "source": "simulated",
                    "detection_method": "rule:X1"})
    return out


def aggregate(daily: pd.DataFrame, findings: pd.DataFrame) -> pd.DataFrame:
    """Per (asset_id, window) telemetry features for M1, computed from the 30 days before the window start only."""
    base = daily.groupby(["asset_id", "window"], sort=False).agg(failed_auth_count=("failed_auth", "sum")).reset_index()
    if len(findings):
        g = findings.groupby(["asset_id", "window"])
        agg = pd.DataFrame({
            "rule_hit_count": g.size(),
            "high_severity_rule_hit": g["severity"].apply(lambda s: int((s == "high").any())),
            "new_remote_session_flag": g["rule"].apply(lambda s: int((s == "D2").any())),
        }).reset_index()
        base = base.merge(agg, on=["asset_id", "window"], how="left")
    for c in ("rule_hit_count", "high_severity_rule_hit", "new_remote_session_flag"):
        if c not in base:
            base[c] = 0
        base[c] = base[c].fillna(0).astype(int)
    return base


def evaluate(findings: pd.DataFrame, episodes: pd.DataFrame, windows: pd.DataFrame) -> Dict[str, Any]:
    """Per-rule precision/recall at the asset-window level against injected ATTACK episodes; false positives on
    windows whose only matching signal was benign off-calendar activity are reported separately."""
    res = {}
    keys = windows[["asset_id", "window"]].drop_duplicates()
    for rid, (etype, *_rest) in RULES.items():
        fired = set(map(tuple, findings.loc[findings["rule"] == rid, ["asset_id", "window"]].drop_duplicates().values))
        att = set(map(tuple, episodes.loc[(episodes["kind"] == "attack") & (episodes["episode_type"] == etype), ["asset_id", "window"]].drop_duplicates().values))
        benign = set(map(tuple, episodes.loc[(episodes["kind"] != "attack") & (episodes["episode_type"].isin([etype, "maintenance"])), ["asset_id", "window"]].drop_duplicates().values))
        tp, fp, fn = len(fired & att), len(fired - att), len(att - fired)
        fp_benign = len((fired - att) & benign)
        res[rid] = {
            "targets": etype, "windows": int(len(keys)), "attack_windows": len(att), "fired_windows": len(fired),
            "true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "precision": round(tp / (tp + fp), 4) if tp + fp else "metric undefined",
            "recall": round(tp / (tp + fn), 4) if tp + fn else "metric undefined",
            "false_positives_from_benign_anomalies": fp_benign,
        }
    return res
