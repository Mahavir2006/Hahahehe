"""
Simulated daily telemetry per asset (PS-03 WP3). SIMULATION ONLY: no real network is observed.

Each record is what a defender could see for one asset on one simulated day:
  auth_failures, remote_sessions [{src, admin}], bytes_in, bytes_out, new_peers, internal_admin_targets,
  ot_write_cmds (Modbus/DNP3-style write function codes; OT/SAFETY zones only), config_changes,
  exploit_signature_hits [cve], maintenance (bool, from the asset's maintenance_window).

Labelled injected episodes (EPISODE_TYPES) are kept OUT of the telemetry record: they are returned
separately so only rule evaluation can read them. Maintenance days are benign look-alikes (vendor remote
sessions, config changes, OT writes, extra peers).

Deterministic: every draw comes from an RNG seeded by sha256(seed, org, asset, day).
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

EPISODE_TYPES = ["brute_force", "unexpected_remote_access", "lateral_movement", "abnormal_ot_protocol",
                 "unexpected_config_change", "known_exploit_indicator"]
EPISODE_RATE = 0.004            # per asset per day, background (simulated) episode start probability
OT_ZONES = ("OT", "SAFETY")
DOW = {"0": 6, "1": 0, "2": 1, "3": 2, "4": 3, "5": 4, "6": 5, "7": 6}   # cron day-of-week -> Python weekday


def rng_for(seed: int, *parts: Any) -> np.random.Generator:
    h = hashlib.sha256("|".join(str(p) for p in (seed,) + parts).encode()).digest()
    return np.random.default_rng(int.from_bytes(h[:8], "big"))


def maintenance_day(window: str, weekday: int) -> bool:
    """window is a 5-field cron string ('0 2 * * 0') or 'none'. Only the day-of-week field is used."""
    parts = (window or "none").split()
    if len(parts) != 5:
        return False
    dow = parts[4]
    if dow == "*":
        return True
    return any(DOW.get(d) == weekday for d in dow.split(","))


class TelemetryGenerator:
    def __init__(self, seed: int = 42, episode_rate: float = EPISODE_RATE):
        self.seed = seed
        self.episode_rate = episode_rate
        self.injected: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}    # (org, asset) -> scripted episodes

    def inject(self, org: str, asset_id: str, kind: str, start_day: int, days: int = 1, cve: Optional[str] = None) -> None:
        if kind not in EPISODE_TYPES:
            raise ValueError(f"unknown episode type {kind}")
        self.injected.setdefault((org, asset_id), []).append({"kind": kind, "start": start_day, "days": days, "cve": cve, "scripted": True})

    def episodes(self, org: str, asset: Dict[str, Any], day: int, kev_cves: List[str]) -> List[Dict[str, Any]]:
        out = [dict(e) for e in self.injected.get((org, asset["asset_id"]), []) if e["start"] <= day < e["start"] + e["days"]]
        r = rng_for(self.seed, "episode", org, asset["asset_id"], day)
        if r.random() < self.episode_rate:
            kinds = [k for k in EPISODE_TYPES if (k != "abnormal_ot_protocol" or asset["zone"] in OT_ZONES) and (k != "known_exploit_indicator" or kev_cves)]
            k = kinds[int(r.integers(0, len(kinds)))]
            out.append({"kind": k, "start": day, "days": 1, "cve": kev_cves[0] if k == "known_exploit_indicator" else None, "scripted": False})
        return out

    def day(self, org: str, asset: Dict[str, Any], day: int, weekday: int, kev_cves: List[str]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Returns (telemetry record, episode labels). The record never contains the labels."""
        r = rng_for(self.seed, "tele", org, asset["asset_id"], day)
        ot = asset["zone"] in OT_ZONES
        maint = maintenance_day(asset.get("maintenance_window", "none"), weekday)
        rec: Dict[str, Any] = {
            "org": org, "asset_id": asset["asset_id"], "sim_day": day, "maintenance": maint,
            "auth_failures": int(r.poisson(1.5 if asset["zone"] in ("IT", "DMZ") else 0.4)),
            "remote_sessions": [], "bytes_in": float(r.lognormal(15 if not ot else 12, 0.3)),
            "bytes_out": float(r.lognormal(14.5 if not ot else 12, 0.3)), "new_peers": int(r.poisson(0.6)),
            "internal_admin_targets": int(r.poisson(0.2)), "ot_write_cmds": int(r.poisson(3)) if ot else 0,
            "config_changes": 0, "exploit_signature_hits": [],
        }
        if r.random() < (0.15 if asset["zone"] in ("IT", "DMZ") else 0.02):
            rec["remote_sessions"].append({"src": f"corp-admin-{int(r.integers(0, 3))}", "admin": True})
        if maint:  # benign look-alikes
            rec["remote_sessions"].append({"src": f"vendor-{asset.get('vendor', 'x')}-{int(r.integers(0, 4))}", "admin": True})
            rec["config_changes"] += int(r.integers(1, 4))
            rec["new_peers"] += int(r.integers(1, 5))
            rec["auth_failures"] += int(r.integers(0, 4))
            if ot:
                rec["ot_write_cmds"] += int(r.integers(20, 60))
        eps = self.episodes(org, asset, day, kev_cves)
        for e in eps:
            k = e["kind"]
            if k == "brute_force":
                rec["auth_failures"] += int(r.integers(25, 200))
            elif k == "unexpected_remote_access":
                rec["remote_sessions"].append({"src": f"ext-{int(r.integers(1000, 9999))}", "admin": bool(r.random() < 0.7)})
            elif k == "lateral_movement":
                rec["new_peers"] += int(r.integers(8, 30))
                rec["internal_admin_targets"] += int(r.integers(3, 12))
            elif k == "abnormal_ot_protocol":
                rec["ot_write_cmds"] += int(r.integers(40, 300))
            elif k == "unexpected_config_change":
                rec["config_changes"] += int(r.integers(1, 3))
            elif k == "known_exploit_indicator":
                rec["exploit_signature_hits"].append(e["cve"] or (kev_cves[0] if kev_cves else "unknown"))
        return rec, eps
