"""
M4: trend and band-crossing forecast on an asset's stored risk snapshots. Statistical (EWMA + Holt linear
trend), not machine learning. Reads the Risk Agent's snapshot history (node.history).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from backend.common.config import settings

FLAT_SLOPE = 0.05     # risk points per day below which the trend is called flat
HORIZON = 90          # days; crossings further out are reported as "none within horizon"


def ewma(values: Sequence[float], alpha: float = 0.3) -> float:
    level = float(values[0])
    for v in values[1:]:
        level = alpha * float(v) + (1 - alpha) * level
    return level


def holt(times: Sequence[float], values: Sequence[float], alpha: float = 0.5, beta: float = 0.3) -> tuple:
    """Holt linear trend on possibly irregular times; returns (level, slope per day) at the last point."""
    level, slope = float(values[0]), 0.0
    for i in range(1, len(values)):
        dt = max(float(times[i] - times[i - 1]), 1e-9)
        prev = level
        level = alpha * float(values[i]) + (1 - alpha) * (level + slope * dt)
        slope = beta * (level - prev) / dt + (1 - beta) * slope
    return level, slope


def boundaries() -> List[float]:
    return [settings.risk_band_low_max, settings.risk_band_medium_max, settings.risk_band_high_max]


def forecast(times: Sequence[float], values: Sequence[float]) -> Dict[str, Any]:
    if len(values) < 3:
        return {"direction": "insufficient history", "slope_per_day": None, "days_to_next_band": None, "method": "holt"}
    level, slope = holt(times, values)
    direction = "flat" if abs(slope) < FLAT_SLOPE else ("rising" if slope > 0 else "falling")
    days = None
    if direction != "flat":
        ahead = [b for b in boundaries() if (b > level if slope > 0 else b < level)]
        if ahead:
            target = min(ahead) if slope > 0 else max(ahead)
            d = (target - level) / slope
            days = round(d, 1) if 0 <= d <= HORIZON else None
    return {"level": round(level, 3), "ewma": round(ewma(values), 3), "slope_per_day": round(slope, 4), "direction": direction,
            "days_to_next_band": days, "method": "Holt linear trend (statistical)"}


def asset_trend(history: List[Dict[str, Any]], asset_id: str) -> Dict[str, Any]:
    """Trend for one asset from the Risk Agent's snapshots ({"ts": seconds, "assets": {asset_id: risk}})."""
    pts = [(h["ts"] / 86400.0, h["assets"][asset_id]) for h in history if asset_id in h.get("assets", {})]
    if not pts:
        return {"direction": "no history"}
    return {"asset_id": asset_id, "points": len(pts), **forecast([p[0] for p in pts], [p[1] for p in pts])}


def naive_forecast(times: Sequence[float], values: Sequence[float]) -> Optional[float]:
    """'Last value' forecaster: the score never moves, so it never predicts a crossing."""
    return None
