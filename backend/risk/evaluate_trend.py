"""
Back-test the trend estimator on SYNTHETIC risk histories (PS-03 WP4).

  python -m backend.risk.evaluate_trend

Each history: a start level, a constant drift (bp/day) and Gaussian noise. For every history that crosses
the next band boundary within the horizon, compare the estimated days-to-crossing after 7 observed days with
the true crossing day. Baseline: the naive last-value forecaster, which predicts no change and therefore never
predicts a crossing (its error is the full true time to cross, capped at the horizon). Statistical, not ML.
Writes backend/risk/artifacts/trend_metrics.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.risk.trend import band_edges_bp, trend  # noqa: E402

OUT = ROOT / "backend" / "risk" / "artifacts" / "trend_metrics.json"
OBS_DAYS, HORIZON, N, SEED = 7, 60, 2000, 11


def run() -> dict:
    rng = np.random.default_rng(SEED)
    edges = band_edges_bp()
    err_holt, err_naive, missed, false_alarm, n_cross, n_flat = [], [], 0, 0, 0, 0
    for _ in range(N):
        start = rng.uniform(500, 7000)
        drift = rng.choice([0.0, rng.uniform(5, 80)], p=[0.3, 0.7])
        noise = rng.uniform(0, 60)
        days = np.arange(OBS_DAYS + HORIZON)
        xs = start + drift * days + rng.normal(0, noise, len(days))
        nxt = next((e for e in edges if start <= e), None)
        obs = trend(list(days[:OBS_DAYS]), list(xs[:OBS_DAYS]))
        est = obs["est_days_to_next_band"]
        true_cross = None
        if nxt is not None:
            after = np.where(xs[OBS_DAYS:] > nxt)[0]
            true_cross = int(after[0]) + 1 if len(after) else None
        if true_cross is None:
            n_flat += 1
            if est is not None and est <= HORIZON:
                false_alarm += 1
            continue
        n_cross += 1
        if est is None:
            missed += 1
            err_holt.append(min(true_cross, HORIZON))
        else:
            err_holt.append(abs(min(est, HORIZON) - true_cross))
        err_naive.append(min(true_cross, HORIZON))
    return {
        "note": "SYNTHETIC histories (linear drift + noise); statistical trend, not ML",
        "histories": N, "observed_days": OBS_DAYS, "horizon_days": HORIZON, "seed": SEED,
        "histories_crossing_within_horizon": n_cross, "histories_not_crossing": n_flat,
        "mae_days_holt": round(float(np.mean(err_holt)), 3) if err_holt else None,
        "mae_days_naive_last_value": round(float(np.mean(err_naive)), 3) if err_naive else None,
        "holt_missed_crossings": missed, "holt_false_alarms_on_non_crossing": false_alarm,
    }


if __name__ == "__main__":
    res = run()
    OUT.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(res, indent=1))
