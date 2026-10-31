"""
Build the M1 training/evaluation datasets (generators A and B) from the simulated population, the real CVE
snapshot, the synthetic label process and simulated telemetry run through detection rules D.

    python data/build_ml_dataset.py            # from the repo root; writes data/ml/

Outputs (data/ml/): gen_a.csv, gen_b.csv (features + label + meta), episodes_{a,b}.csv (evaluation-only ground
truth for D), telemetry_{a,b}.csv.gz (daily), rules_eval.json, MANIFEST.json (sha256, row counts, positive
rates, CVE matching stats, leakage audit). data/schema.json is written from backend/risk/features.py.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import date, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.risk import rules  # noqa: E402
from backend.risk.features import FEATURES, schema_json  # noqa: E402
from data import label_process, telemetry  # noqa: E402
from data.ml_population import CvePool, build_population  # noqa: E402

OUT = ROOT / "data" / "ml"
META = ["asset_id", "sector", "asset_type", "zone", "window", "window_start", "max_source_date", "cve_ids"]
SEED = 42


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def leakage_audit(df: pd.DataFrame, daily: pd.DataFrame) -> dict:
    """Hard gate: no feature may be a deterministic function of the label, and nothing may come from after t."""
    problems = []
    y = df["label"]
    for f in FEATURES:
        if df.groupby("label")[f].nunique().max() <= 1 and df[f].nunique() > 1:
            problems.append(f"{f} is constant within each label class")
        a = df.loc[y == 1, f]
        b = df.loc[y == 0, f]
        if len(set(a) & set(b)) == 0:
            problems.append(f"{f} separates the classes perfectly")
    src = pd.to_datetime(df["max_source_date"])
    late = (src.notna() & (src > pd.to_datetime(df["window_start"]))).sum()
    if late:
        problems.append(f"{late} rows use CVE/KEV information dated after the window start")
    if daily["day"].max() >= telemetry.DAYS or daily["day"].min() < 0:
        problems.append("telemetry outside the 30 days before t")
    return {"passed": not problems, "problems": problems,
            "checks": ["feature constant within a label class", "feature perfectly separates classes",
                       "CVE release / KEV date-added after t", "telemetry day outside [t-30, t)"]}


def build(gen: str, n_assets: int, seed: int, pool: CvePool) -> tuple:
    assets, rows, stats = build_population(n_assets, seed, f"{gen.lower()}", pool)
    label, attacks = label_process.make_labels(rows, gen, seed + 1)
    daily, episodes = telemetry.generate(rows, attacks, seed + 2)
    findings = rules.run(daily)
    tel = rules.aggregate(daily, findings)
    df = pd.DataFrame(rows).merge(tel, on=["asset_id", "window"], how="left")
    df["label"] = label
    df = df[META + FEATURES + ["label"]]
    return df, daily, pd.DataFrame(episodes), findings, stats


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    (ROOT / "data" / "schema.json").write_text(json.dumps(schema_json(), indent=2) + "\n", encoding="utf-8")
    pool = CvePool()
    manifest = {"seed": SEED, "row_definition": "one asset in one 90-day window; features as of the window start t",
                "epss_source": "proxy", "files": {}, "generators": {}}
    rules_eval = {}
    for gen, n, seed in (("A", 2000, SEED), ("B", 800, SEED + 1000)):
        df, daily, episodes, findings, stats = build(gen, n, seed, pool)
        audit = leakage_audit(df, daily)
        if not audit["passed"]:
            print(f"LEAKAGE AUDIT FAILED for {gen}: {audit['problems']}")
            return 1
        rules_eval[gen] = rules.evaluate(findings, episodes, df)
        g = gen.lower()
        df.to_csv(OUT / f"gen_{g}.csv", index=False, lineterminator="\n")
        episodes.to_csv(OUT / f"episodes_{g}.csv", index=False, lineterminator="\n")
        daily.to_csv(OUT / f"telemetry_{g}.csv.gz", index=False, compression={"method": "gzip", "mtime": 0})
        manifest["generators"][gen] = {
            "assets": n, "rows": int(len(df)), "positive_rate": round(float(df["label"].mean()), 4),
            "cves_drawn_from_type_matched_advisories": stats["typed"], "cves_drawn_from_sector_fallback": stats["sector_fallback"],
            "cves_drawn_from_kev_enrichment": stats["kev_enrichment"],
            "rows_with_vulnerability": int(df["has_vulnerability"].sum()), "rows_known_exploited": int(df["any_known_exploited"].sum()),
            "attack_episodes": int((episodes["kind"] == "attack").sum()) if len(episodes) else 0, "leakage_audit": audit,
        }
        print(f"{gen}: {len(df)} rows, positive rate {df['label'].mean():.4f}, CVEs typed={stats['typed']} fallback={stats['sector_fallback']}")
    (OUT / "rules_eval.json").write_text(json.dumps(rules_eval, indent=2) + "\n", encoding="utf-8")
    for p in sorted(OUT.glob("*")):
        if p.name != "MANIFEST.json":
            manifest["files"][p.name] = {"sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
