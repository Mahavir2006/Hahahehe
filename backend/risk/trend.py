"""
Risk trend per asset (PS-03 WP4). STATISTICAL, not ML: EWMA level and Holt's linear trend over the
risk_bp series in the reassessment log, with a naive estimate of days until the next band boundary.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from backend.common.config import settings

ALPHA = 0.5             # level smoothing (EWMA and Holt)
BETA = 0.3              # Holt trend smoothing
FLAT_BP_PER_DAY = 5     # |slope| below this (0.05 risk points/day) counts as flat


def band_edges_bp() -> List[int]:
    """Upper inclusive edge of low/medium/high in basis points (risk 25 -> 2500 ...)."""
    return [int(settings.risk_band_low_max * 100), int(settings.risk_band_medium_max * 100), int(settings.risk_band_high_max * 100)]


def ewma(xs: List[float], alpha: float = ALPHA) -> float:
    lvl = xs[0]
    for x in xs[1:]:
        lvl = alpha * x + (1 - alpha) * lvl
    return lvl


def holt(days: List[int], xs: List[float], alpha: float = ALPHA, beta: float = BETA) -> Tuple[float, float]:
    """Holt's linear method on an irregular daily index; returns (level, slope per day)."""
    lvl, slope = xs[0], 0.0
    for i in range(1, len(xs)):
        gap = max(days[i] - days[i - 1], 1)
        prev = lvl
        lvl = alpha * xs[i] + (1 - alpha) * (lvl + slope * gap)
        slope = beta * (lvl - prev) / gap + (1 - beta) * slope
    return lvl, slope


def days_to_next_band(level: float, slope: float) -> Optional[float]:
    if slope <= FLAT_BP_PER_DAY:
        return None
    nxt = next((e for e in band_edges_bp() if level <= e), None)
    if nxt is None:
        return None
    return round((nxt + 1 - level) / slope, 2)


def trend(days: List[int], xs: List[float]) -> Dict[str, Any]:
    if not xs:
        return {"points": 0, "direction": "flat", "slope_per_day": 0.0, "est_days_to_next_band": None}
    if len(xs) == 1:
        return {"points": 1, "direction": "flat", "slope_per_day": 0.0, "level_bp": xs[0], "ewma_bp": xs[0], "est_days_to_next_band": None}
    lvl, slope = holt(days, xs)
    direction = "rising" if slope > FLAT_BP_PER_DAY else "falling" if slope < -FLAT_BP_PER_DAY else "flat"
    return {"points": len(xs), "direction": direction, "slope_per_day": round(slope, 3), "level_bp": round(lvl, 2),
            "ewma_bp": round(ewma(xs), 2), "est_days_to_next_band": days_to_next_band(lvl, slope),
            "method": "Holt linear trend (alpha=%.2f, beta=%.2f) + EWMA; statistical, not ML" % (ALPHA, BETA)}


def org_trends(risk_log: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    series: Dict[str, Tuple[List[int], List[float]]] = {}
    for e in risk_log:
        for aid, a in e["assets"].items():
            d, x = series.setdefault(aid, ([], []))
            d.append(e["sim_day"])
            x.append(float(a["risk_bp"]))
    out = {}
    for aid, (d, x) in series.items():
        # one value per day: keep the last reassessment of each day
        last: Dict[int, float] = {}
        for di, xi in zip(d, x):
            last[di] = xi
        ds = sorted(last)
        out[aid] = trend(ds, [last[k] for k in ds])
    return out
