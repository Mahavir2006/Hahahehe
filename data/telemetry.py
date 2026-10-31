"""
Simulated network/OT telemetry: one record per asset per day for the 30 days before each window start.

Benign background traffic for every asset, scheduled maintenance days (observable calendar), benign anomalies
(off-calendar vendor sessions, account lock-out bursts, emergency config changes, IDS false positives) and the
attack precursors scheduled by data/label_process.py. Every injected episode, benign or attack, is listed in the
episodes table, which is used only to evaluate the detection rules (backend/risk/rules.py), never as a feature.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd

DAYS = 30
FIELDS = ["failed_auth", "remote_sessions", "new_remote_source", "lateral_new_peers", "ot_write_anomalies",
          "config_changes", "exploit_sig", "maintenance"]


def generate(rows: List[Dict[str, Any]], attack_episodes: List[Dict[str, Any]], seed: int) -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
    rng = np.random.default_rng(seed)
    n = len(rows)
    t = {f: np.zeros((n, DAYS), dtype=np.int64) for f in FIELDS}
    remote = np.array([r["remote_access_enabled"] for r in rows], dtype=float)
    ot = np.array([r["zone_ord"] >= 2 for r in rows])
    t["failed_auth"] = rng.poisson(np.repeat(rng.uniform(0.2, 3.0, n)[:, None], DAYS, axis=1))
    t["remote_sessions"] = rng.poisson(np.repeat((0.15 + 1.2 * remote)[:, None], DAYS, axis=1))
    t["lateral_new_peers"] = rng.poisson(0.25, (n, DAYS))
    episodes: List[Dict[str, Any]] = []

    def ep(i, day, kind, etype):
        episodes.append({"asset_id": rows[i]["asset_id"], "window": int(rows[i]["window"]), "day": int(day), "episode_type": etype, "kind": kind})

    for i in range(n):
        # scheduled maintenance (on the change calendar, so rules can exclude it)
        for day in rng.choice(DAYS, size=int(rng.integers(0, 3)), replace=False):
            t["maintenance"][i, day] = 1
            t["config_changes"][i, day] += int(rng.integers(1, 4))
            t["new_remote_source"][i, day] += int(rng.random() < 0.7)
            t["remote_sessions"][i, day] += int(rng.integers(1, 3))
            if ot[i]:
                t["ot_write_anomalies"][i, day] += int(rng.integers(2, 8))
            ep(i, day, "benign_maintenance", "maintenance")
        # benign anomalies OFF the calendar: the realistic source of false positives
        if rng.random() < 0.04:
            d = int(rng.integers(DAYS))
            t["new_remote_source"][i, d] += 1
            ep(i, d, "benign_unscheduled", "unexpected_remote")
        if rng.random() < 0.03:
            d = int(rng.integers(DAYS))
            t["failed_auth"][i, d] += int(rng.integers(12, 32))
            ep(i, d, "benign_unscheduled", "auth_bruteforce")
        if rng.random() < 0.02:
            d = int(rng.integers(DAYS))
            t["config_changes"][i, d] += 1
            ep(i, d, "benign_unscheduled", "unexpected_config")
        if rng.random() < 0.006:
            d = int(rng.integers(DAYS))
            t["exploit_sig"][i, d] += 1
            ep(i, d, "benign_unscheduled", "exploit_indicator")

    index = {(r["asset_id"], int(r["window"])): i for i, r in enumerate(rows)}
    for e in attack_episodes:
        i, d = index[(e["asset_id"], e["window"])], e["day"]
        k = e["episode_type"]
        if k == "auth_bruteforce":
            t["failed_auth"][i, d] += int(rng.integers(18, 90))
        elif k == "unexpected_remote":
            t["new_remote_source"][i, d] += int(rng.integers(1, 3))
            t["remote_sessions"][i, d] += int(rng.integers(1, 4))
        elif k == "lateral_movement":
            t["lateral_new_peers"][i, d] += int(rng.integers(4, 16))
        elif k == "abnormal_ot":
            t["ot_write_anomalies"][i, d] += int(rng.integers(2, 11))
        elif k == "unexpected_config":
            t["config_changes"][i, d] += int(rng.integers(1, 4))
        elif k == "exploit_indicator":
            t["exploit_sig"][i, d] += int(rng.integers(1, 4)) if rng.random() < 0.85 else 0  # IDS misses some
        episodes.append(dict(e))

    ids = np.repeat([r["asset_id"] for r in rows], DAYS)
    win = np.repeat([int(r["window"]) for r in rows], DAYS)
    df = pd.DataFrame({"asset_id": ids, "window": win, "day": np.tile(np.arange(DAYS), n)})
    for f in FIELDS:
        df[f] = t[f].reshape(-1)
    return df, episodes


def demo_telemetry(asset_id: str, remote_access: bool, ot_zone: bool, seed: int = 42) -> pd.DataFrame:
    """Benign-only telemetry for one demo asset (deterministic per asset id), so demo features are in-distribution."""
    s = seed + sum(ord(ch) for ch in asset_id)
    row = {"asset_id": asset_id, "window": 0, "remote_access_enabled": int(remote_access), "zone_ord": 2 if ot_zone else 0}
    df, _ = generate([row], [], s)
    return df
