"""
Evaluate the detection rules on SIMULATED telemetry with labelled injected episodes (PS-03 WP3).

  python -m backend.detect.evaluate_rules [--days 365] [--rate 0.01]

Per rule: an asset-day counts as positive for the rule's episode type if an episode of that type is active
on it. Precision/recall are per asset-day. False positives on maintenance days (benign look-alikes) are
reported separately from other false positives. Writes backend/risk/artifacts/rules_metrics.json.
These are rules, not a trained detector; the numbers describe the rules on this simulator only.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.detect.rules import RULES  # noqa: E402
from backend.detect.telemetry import TelemetryGenerator  # noqa: E402

OUT = ROOT / "backend" / "risk" / "artifacts" / "rules_metrics.json"
START = date(2026, 10, 31)


def evaluate(days: int = 365, rate: float = 0.01, seed: int = 7) -> Dict[str, Any]:
    gen = TelemetryGenerator(seed, episode_rate=rate)
    inv = {o: json.loads((ROOT / "data" / "orgs" / o / "inventory.json").read_text(encoding="utf-8")) for o in ("power", "water", "hospital")}
    stats = {r.__name__: {"tp": 0, "fp_maintenance": 0, "fp_other": 0, "fn": 0} for r in RULES}
    kinds = {}
    n_days = 0
    for org, assets in inv.items():
        for a in assets:
            seen: Dict[str, int] = {}
            kev = ["CVE-SIM-KEV"]   # a KEV-listed CVE so known_exploit_indicator episodes can occur
            for d in range(-30, days):
                wd = (START + timedelta(days=d)).weekday()
                rec, eps = gen.day(org, a, d, wd, kev)
                if d >= 0:
                    n_days += 1
                    active = {e["kind"] for e in eps}
                    ctx = {"zone": a["zone"], "seen_remote_sources": {s for s, x in seen.items() if d - x <= 30}}
                    for rule in RULES:
                        h = rule(rec, ctx)
                        st = stats[rule.__name__]
                        kind = None
                        if h is not None:
                            kind = h["episode_type"]
                            kinds[rule.__name__] = kind
                            if kind in active:
                                st["tp"] += 1
                            elif rec["maintenance"]:
                                st["fp_maintenance"] += 1
                            else:
                                st["fp_other"] += 1
                        k = kinds.get(rule.__name__)
                        if k and k in active and h is None:
                            st["fn"] += 1
                for s in rec["remote_sessions"]:
                    seen[s["src"]] = d
    out: Dict[str, Any] = {"note": "rules evaluated on SIMULATED telemetry with injected labelled episodes; not real detection",
                           "asset_days": n_days, "days": days, "episode_rate_per_asset_day": rate, "seed": seed, "rules": {}}
    for name, st in stats.items():
        fp = st["fp_maintenance"] + st["fp_other"]
        out["rules"][name] = {**st, "episode_type": kinds.get(name),
                              "precision": round(st["tp"] / (st["tp"] + fp), 4) if st["tp"] + fp else None,
                              "precision_excluding_maintenance_fp": round(st["tp"] / (st["tp"] + st["fp_other"]), 4) if st["tp"] + st["fp_other"] else None,
                              "recall": round(st["tp"] / (st["tp"] + st["fn"]), 4) if st["tp"] + st["fn"] else None}
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=365)
    ap.add_argument("--rate", type=float, default=0.01)
    a = ap.parse_args()
    res = evaluate(a.days, a.rate)
    OUT.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(res, indent=1))
