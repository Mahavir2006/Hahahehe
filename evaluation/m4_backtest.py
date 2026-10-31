"""
M4 backtest: on synthetic risk histories, how well does the Holt trend predict when the next band boundary is
crossed, compared with a naive 'last value' forecaster (which never predicts a crossing)?

    python evaluation/m4_backtest.py
"""

from __future__ import annotations

import numpy as np

from common import record
from backend.risk import trend


def synthetic_history(rng, n=60):
    """Piecewise-linear drift (rising, falling or flat) plus noise, clipped to 0-100."""
    start = rng.uniform(5, 95)
    drift = rng.choice([-1, 0, 1]) * rng.uniform(0.1, 1.2)
    noise = rng.uniform(0.5, 3.0)
    t = np.arange(n, dtype=float)
    return t, np.clip(start + drift * t + rng.normal(0, noise, n), 0, 100)


def first_crossing(values, k, level_at_k):
    """Actual days after k until the score crosses a band boundary away from its level at k."""
    for j in range(k + 1, len(values)):
        for b in trend.boundaries():
            if (level_at_k <= b < values[j]) or (level_at_k > b >= values[j]):
                return j - k
    return None


def main(runs: int = 2000, seed: int = 42, k: int = 30):
    rng = np.random.default_rng(seed)
    cap = 30  # remaining days in each history
    err_m4, err_naive, hits, crossings = [], [], 0, 0
    for _ in range(runs):
        t, v = synthetic_history(rng)
        actual = first_crossing(v, k - 1, v[k - 1])
        f = trend.forecast(t[:k], v[:k])
        pred = f["days_to_next_band"]
        a = actual if actual is not None else cap
        p = min(pred, cap) if pred is not None else cap
        err_m4.append(abs(p - a))
        err_naive.append(abs(cap - a))   # naive never predicts a crossing
        if actual is not None:
            crossings += 1
            hits += int(pred is not None)
    out = {"method": "Holt linear trend (statistical, not ML)", "runs": runs, "history_days": 60, "forecast_from_day": k,
           "horizon_cap_days": cap, "histories_with_a_crossing": crossings,
           "mae_days_m4": round(float(np.mean(err_m4)), 3), "mae_days_naive_last_value": round(float(np.mean(err_naive)), 3),
           "crossings_anticipated_by_m4": hits,
           "note": "synthetic risk histories; no-crossing cases count as the horizon cap for both forecasters"}
    record("m4_trend_backtest", out)
    print(out)


if __name__ == "__main__":
    main()
