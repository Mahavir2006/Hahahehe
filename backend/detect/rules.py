"""
Deterministic detection rules over simulated telemetry (PS-03 WP3). These are RULES with fixed thresholds,
not a trained detector. Confidence values are documented heuristics, not calibrated probabilities.

Each rule: fn(record, ctx) -> Optional[dict(rule_id, detection_method, severity, confidence, evidence, related_cve)]
ctx = {"zone", "seen_remote_sources" (set over the previous 30 days)}.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

BRUTE_FORCE_MIN_FAILURES = 20          # baseline is Poisson(1.5) on IT/DMZ: 20 in a day is far outside it
LATERAL_MIN_NEW_PEERS = 8
LATERAL_MIN_ADMIN_TARGETS = 3
OT_WRITE_MAX_OUTSIDE_MAINT = 25        # baseline Poisson(3) writes/day; maintenance adds 20-60
CONFIG_CHANGE_OUTSIDE_MAINT = 1

Rule = Callable[[Dict[str, Any], Dict[str, Any]], Optional[Dict[str, Any]]]


def r1_brute_force(rec: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    n = rec["auth_failures"]
    if n < BRUTE_FORCE_MIN_FAILURES:
        return None
    return {"rule_id": "R1_REPEATED_AUTH_FAILURES", "episode_type": "brute_force", "detection_method": "threshold",
            "severity": "high" if n >= 50 else "medium", "confidence": 0.8 if n >= 50 else 0.6,
            "evidence": [f"auth_failures={n} (threshold {BRUTE_FORCE_MIN_FAILURES}/day)"], "related_cve": None}


def r2_unexpected_remote(rec: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if rec["maintenance"]:
        return None
    new = [s for s in rec["remote_sessions"] if s["src"] not in ctx["seen_remote_sources"]]
    if not new:
        return None
    admin = any(s["admin"] for s in new)
    return {"rule_id": "R2_UNEXPECTED_REMOTE_ACCESS", "episode_type": "unexpected_remote_access", "detection_method": "new-source outside maintenance",
            "severity": "high" if admin else "medium", "confidence": 0.75 if admin else 0.55,
            "evidence": [f"remote session from unseen source {s['src']} (admin={s['admin']})" for s in new], "related_cve": None}


def r3_lateral(rec: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if rec["new_peers"] < LATERAL_MIN_NEW_PEERS or rec["internal_admin_targets"] < LATERAL_MIN_ADMIN_TARGETS:
        return None
    return {"rule_id": "R3_LATERAL_MOVEMENT", "episode_type": "lateral_movement", "detection_method": "fan-out threshold",
            "severity": "critical", "confidence": 0.7,
            "evidence": [f"new_peers={rec['new_peers']} (>= {LATERAL_MIN_NEW_PEERS})", f"internal_admin_targets={rec['internal_admin_targets']} (>= {LATERAL_MIN_ADMIN_TARGETS})"],
            "related_cve": None}


def r4_abnormal_ot(rec: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if ctx["zone"] not in ("OT", "SAFETY") or rec["maintenance"] or rec["ot_write_cmds"] <= OT_WRITE_MAX_OUTSIDE_MAINT:
        return None
    return {"rule_id": "R4_ABNORMAL_OT_PROTOCOL", "episode_type": "abnormal_ot_protocol", "detection_method": "OT write-command threshold outside maintenance",
            "severity": "critical" if ctx["zone"] == "SAFETY" else "high", "confidence": 0.75,
            "evidence": [f"ot_write_cmds={rec['ot_write_cmds']} (> {OT_WRITE_MAX_OUTSIDE_MAINT}) outside maintenance window"], "related_cve": None}


def r5_config_change(rec: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if rec["maintenance"] or rec["config_changes"] < CONFIG_CHANGE_OUTSIDE_MAINT:
        return None
    return {"rule_id": "R5_UNEXPECTED_CONFIG_CHANGE", "episode_type": "unexpected_config_change", "detection_method": "change outside maintenance",
            "severity": "medium", "confidence": 0.6, "evidence": [f"config_changes={rec['config_changes']} outside maintenance window"], "related_cve": None}


def r6_exploit_indicator(rec: Dict[str, Any], ctx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not rec["exploit_signature_hits"]:
        return None
    cve = rec["exploit_signature_hits"][0]
    return {"rule_id": "R6_KNOWN_EXPLOIT_INDICATOR", "episode_type": "known_exploit_indicator", "detection_method": "signature match",
            "severity": "critical", "confidence": 0.85, "evidence": [f"exploit signature for {c}" for c in rec["exploit_signature_hits"]], "related_cve": cve}


RULES: List[Rule] = [r1_brute_force, r2_unexpected_remote, r3_lateral, r4_abnormal_ot, r5_config_change, r6_exploit_indicator]
SEVERITY_ORDER = ["low", "medium", "high", "critical"]
