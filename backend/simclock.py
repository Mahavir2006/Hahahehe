"""
Simulated clock (PS-03 WP4). Advancing moves backend.risk.model.REFERENCE_DATE forward so patch age grows;
model.py itself is not edited. reset() restores the original date.
"""

from __future__ import annotations

from datetime import date, timedelta

from backend.risk import model as risk

ORIGINAL_DATE: date = risk.REFERENCE_DATE
_day = 0


def now_day() -> int:
    return _day


def now_date() -> date:
    return ORIGINAL_DATE + timedelta(days=_day)


def advance(days: int = 1) -> int:
    global _day
    if days < 0:
        raise ValueError("the simulated clock only moves forward (use reset())")
    _day += int(days)
    risk.REFERENCE_DATE = now_date()
    return _day


def reset() -> None:
    global _day
    _day = 0
    risk.REFERENCE_DATE = ORIGINAL_DATE
