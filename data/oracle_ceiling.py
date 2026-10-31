"""
Accuracy ceiling for generator A: how good can ANY model be on this data?

Oracles (evaluated on the same held-out grouped test split as M1):
  O1 observable-logit oracle   the generator's exact formula for everything a model can see; no telemetry
  O2 O1 + telemetry            a flexible model given O1's score plus the telemetry features (precursors carry
                               information beyond the formula)
  O3 true-probability oracle   knows the hidden factors and noise too; only the 6% label flips remain unexplained
M1 is compared with O2, the best a model limited to the observed features could plausibly reach. O3 is out of reach
for any real model by construction.

    python data/oracle_ceiling.py      # writes "accuracy_ceiling" into backend/risk/artifacts/metrics.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.risk import train_model as T  # noqa: E402
from backend.risk.features import FEATURES  # noqa: E402
from backend.risk.inference import M1  # noqa: E402
from backend.risk.rules import TELEMETRY_FEATURES  # noqa: E402
from data import label_process  # noqa: E402

METRICS = ROOT / "backend" / "risk" / "artifacts" / "metrics.json"


def main():
    df = T.load("a")
    lat = label_process.latent(df.to_dict("records"), "A", 43)   # gen A labels were drawn with seed 42 + 1
    df["oracle_obs"] = lat["logit_observable"]
    df["oracle_true"] = lat["p_true"]
    s = T.split(df)
    tr, te = s["train"], s["test"]
    y = te["label"].values
    o2 = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.05, max_depth=3, random_state=42).fit(
        tr[["oracle_obs"] + TELEMETRY_FEATURES], tr["label"])
    p_o2 = o2.predict_proba(te[["oracle_obs"] + TELEMETRY_FEATURES])[:, 1]
    p_m1 = M1.get().calibrated.predict_proba(te[FEATURES])[:, 1]

    def score(p):
        return {"roc_auc": round(float(roc_auc_score(y, p)), 4), "pr_auc": round(float(average_precision_score(y, p)), 4)}

    out = {
        "test_rows": int(len(te)),
        "O1_observable_logit_oracle_no_telemetry": score(te["oracle_obs"].values),
        "O2_observable_oracle_plus_telemetry": score(p_o2),
        "O3_true_probability_oracle": score(te["oracle_true"].values),
        "M1": score(p_m1),
    }
    out["M1_share_of_O2_roc_auc_above_chance"] = round((out["M1"]["roc_auc"] - 0.5) / (out["O2_observable_oracle_plus_telemetry"]["roc_auc"] - 0.5), 4)
    out["note"] = "O3 needs the hidden factors, which no model can observe; the reachable ceiling is about O2"
    m = json.loads(METRICS.read_text(encoding="utf-8"))
    m["accuracy_ceiling"] = out
    METRICS.write_text(json.dumps(m, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
