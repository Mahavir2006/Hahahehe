"""
Synthetic compromise process: the ONLY place labels are made. Training code must never import this file
(backend/tests/test_ml.py checks that).

A row's compromise probability comes from a latent logit over the observed features AND hidden factors that are
deliberately absent from every feature file, plus noise; the label is a Bernoulli draw, then a share of labels is
flipped (recording error). For a fraction of compromises, attack precursors are scheduled in the 30 days before the
window start, so telemetry is informative but imperfect.

Two generators with different functional forms, interactions, hidden factors and noise:
* A: mostly additive, with one exposure x severity interaction. Used for training and held-out testing.
* B: saturating patch age, multiplicative exposure and remote-access terms, a different hidden-factor set and more
  noise. Used only as an out-of-distribution test.
Real asset-level compromise labels do not exist publicly; these labels are synthetic.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

import numpy as np

EPISODE_TYPES = ["auth_bruteforce", "unexpected_remote", "lateral_movement", "abnormal_ot", "unexpected_config", "exploit_indicator"]


def _sigmoid(z):
    return 1.0 / (1.0 + np.exp(-z))


def _cols(rows: List[Dict[str, Any]]) -> Dict[str, np.ndarray]:
    keys = ["internet_exposed", "default_credentials", "open_mgmt_ports", "remote_access_enabled", "supply_chain_flag",
            "firmware_known", "days_since_patch", "has_vulnerability", "max_cvss", "max_epss", "any_known_exploited",
            "cve_count", "zone_ord", "criticality", "window"]
    return {k: np.array([float(r[k]) for r in rows]) for k in keys}


def _hidden(rows, rng, names) -> Dict[str, np.ndarray]:
    """Per-asset hidden factors (constant across windows) plus a per-sector, per-window campaign factor."""
    ids = sorted({r["asset_id"] for r in rows})
    h = {n: dict(zip(ids, rng.normal(0, 1, len(ids)))) for n in names}
    out = {n: np.array([h[n][r["asset_id"]] for r in rows]) for n in names}
    camp = {(s, w): rng.normal(0, 0.45) for s in ("energy", "water", "healthcare") for w in range(64)}
    out["campaign"] = np.array([camp[(r["sector"], r["window"])] for r in rows])
    return out


def _logit_a(c, h, rng):
    ot = (c["zone_ord"] >= 2).astype(float)
    it = (c["zone_ord"] <= 1).astype(float)
    z = (1.1 * c["internet_exposed"] + 0.9 * c["default_credentials"] + 0.22 * c["open_mgmt_ports"]
         + 0.45 * c["remote_access_enabled"] + 0.9 * c["supply_chain_flag"] + 0.35 * (1 - c["firmware_known"])
         + 0.0016 * np.minimum(c["days_since_patch"], 1200)
         + c["has_vulnerability"] * (0.5 + 0.16 * (c["max_cvss"] - 5.0) + 1.4 * c["max_epss"] + 0.15 * np.log1p(c["cve_count"]))
         + 1.3 * c["any_known_exploited"] + 0.25 * ot + 0.1 * (c["criticality"] - 3)
         + 0.7 * c["internet_exposed"] * c["has_vulnerability"] * (c["max_cvss"] >= 7)
         # hidden factors (never in the feature table)
         + 0.70 * h["insider_access"] + 0.60 * h["phishing_exposure"] * it + 0.55 * h["vendor_remote_hygiene"] * c["remote_access_enabled"]
         + h["campaign"] + rng.normal(0, 0.45, len(c["window"])))
    return z


def _logit_b(c, h, rng):
    exposure = c["internet_exposed"] * np.where(c["open_mgmt_ports"] >= 2, 1.0, 0.45)
    z = (1.7 * exposure + 1.3 * c["default_credentials"] * (0.4 + 0.6 * c["remote_access_enabled"])
         + 1.3 * np.tanh(c["days_since_patch"] / 365.0) + 0.5 * c["supply_chain_flag"]
         + c["has_vulnerability"] * (0.3 + 2.0 * np.sqrt(np.clip(c["max_epss"], 0, 1)) + 0.05 * c["max_cvss"])
         + 2.0 * c["any_known_exploited"] + 0.5 * (c["zone_ord"] == 1) - 0.15 * (c["zone_ord"] == 3)
         # a different hidden-factor set
         + 0.85 * h["supplier_compromise"] + 0.50 * h["insider_access"] + 0.80 * h["targeted_actor"] * (c["criticality"] >= 4)
         + 1.2 * h["campaign"] + rng.normal(0, 0.75, len(c["window"])))
    return z


SPEC = {
    "A": {"hidden": ["insider_access", "phishing_exposure", "vendor_remote_hygiene"], "logit": _logit_a,
          "base_rate": 0.12, "flip": 0.06, "precursor_p": 0.50},
    "B": {"hidden": ["supplier_compromise", "insider_access", "targeted_actor"], "logit": _logit_b,
          "base_rate": 0.12, "flip": 0.07, "precursor_p": 0.35},
}


def _intercept(z: np.ndarray, target: float) -> float:
    lo, hi = -30.0, 30.0
    for _ in range(80):
        mid = (lo + hi) / 2
        if _sigmoid(z + mid).mean() > target:
            hi = mid
        else:
            lo = mid
    return (lo + hi) / 2


def make_labels(rows: List[Dict[str, Any]], generator: str, seed: int) -> Tuple[np.ndarray, List[Dict[str, Any]]]:
    """Return (label per row, scheduled attack-precursor episodes). Episodes are evaluation-only ground truth for D."""
    spec = SPEC[generator]
    rng = np.random.default_rng(seed)
    c = _cols(rows)
    h = _hidden(rows, rng, spec["hidden"])
    z = spec["logit"](c, h, rng)
    p = _sigmoid(z + _intercept(z, spec["base_rate"]))
    compromised = rng.random(len(p)) < p
    flip = rng.random(len(p)) < spec["flip"]
    label = np.where(flip, ~compromised, compromised).astype(int)

    episodes = []
    for i in np.flatnonzero(compromised):
        if rng.random() >= spec["precursor_p"]:
            continue
        r = rows[i]
        w = np.array([1.0, 1.0, 0.8, 1.2 if r["zone_ord"] >= 2 else 0.0, 0.8, 1.5 if (r["any_known_exploited"] or r["max_cvss"] >= 8) else 0.4])
        for _ in range(1 + int(rng.random() < 0.4)):
            kind = EPISODE_TYPES[int(rng.choice(len(w), p=w / w.sum()))]
            episodes.append({"asset_id": r["asset_id"], "window": int(r["window"]), "day": int(rng.integers(0, 30)),
                             "episode_type": kind, "kind": "attack"})
    return label, episodes
