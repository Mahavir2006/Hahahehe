"""
Derive risk-band thresholds from M1's output, by the rule declared in docs/ML_DECISIONS.md section 3:
50th / 80th / 95th percentile of risk over the held-out grouped test split of generator A.

    python evaluation/band_thresholds.py
"""

from __future__ import annotations

import numpy as np

from common import record
from backend.risk import model as M
from backend.risk import train_model as T
from backend.risk.features import FEATURES
from backend.risk.inference import M1

SERVICE_FROM_CRIT = {5: "life_critical", 4: "high", 3: "medium", 2: "low", 1: "low"}


def main():
    test = T.split(T.load("a"))["test"]
    m = M1.get()
    lik = m.calibrated.predict_proba(test[FEATURES])[:, 1]
    risks = []
    for p, (_, r) in zip(lik, test.iterrows()):
        a = M.AssetCtx(asset_id=r["asset_id"], org="population", criticality=int(r["criticality"]), safety_critical=bool(r["safety_critical"]),
                       num_dependents=int(r["num_dependents"]), service_crit=SERVICE_FROM_CRIT[int(r["criticality"])])
        lik_bp = int(np.floor(p * 10000 + 0.5))
        risks.append(M.risk_bp_of(lik_bp, M.to_bp(M.impact_of(a))) / 100)
    risks = np.array(risks)
    q = {k: round(float(np.percentile(risks, v)), 2) for k, v in (("low_max", 50), ("medium_max", 80), ("high_max", 95))}
    out = {"rule": "50th / 80th / 95th percentile of M1 risk on the held-out grouped test split of generator A (docs/ML_DECISIONS.md section 3)",
           "rows": int(len(risks)), "risk_band_low_max": q["low_max"], "risk_band_medium_max": q["medium_max"],
           "risk_band_high_max": q["high_max"], "previous": {"low_max": 25, "medium_max": 50, "high_max": 75},
           "risk_min": round(float(risks.min()), 2), "risk_max": round(float(risks.max()), 2)}
    record("band_thresholds", out)
    print(out)


if __name__ == "__main__":
    main()
