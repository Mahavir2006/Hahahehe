"""Print the markdown tables used in docs/ML_REPORT.md, straight from metrics.json and data/ml/MANIFEST.json."""

from __future__ import annotations

import json

from common import METRICS, ROOT

m = json.loads(METRICS.read_text(encoding="utf-8"))
man = json.loads((ROOT / "data" / "ml" / "MANIFEST.json").read_text(encoding="utf-8"))


def fmt(v):
    return v if isinstance(v, str) else f"{v}"


print("### M1 versus baselines\n")
cols = ["roc_auc", "pr_auc", "brier", "ece", "precision_at_threshold", "recall_at_threshold", "top5_precision", "top10_precision"]
print("| Evaluation | Model | " + " | ".join(cols) + " |")
print("|---|---|" + "---|" * len(cols))
for ev, models in m["evaluations"].items():
    for name, r in models.items():
        cells = []
        for c in cols:
            v = r.get(c, "")
            cells.append("n/a" if isinstance(v, str) and v.startswith("not applicable") else fmt(v))
        print(f"| {ev} (n={r['n']}, positives={r['positives']}) | {name} | " + " | ".join(cells) + " |")

d = m["two_generator_drop"]
print(f"\n### Two-generator drop\n\n| | Generator A (held-out) | Generator B | Drop |\n|---|---|---|---|\n| ROC-AUC | {d['roc_auc_A']} | {d['roc_auc_B']} | {d['roc_auc_drop']} |\n| PR-AUC | {d['pr_auc_A']} | {d['pr_auc_B']} | {round(d['pr_auc_A'] - d['pr_auc_B'], 4)} |")

c = m["calibration"]
print(f"\n### Calibration ({c['method']}, grouped test split)\n\n| | Before | After |\n|---|---|---|\n| Brier | {c['brier_before']} | {c['brier_after']} |\n| ECE | {c['ece_before']} | {c['ece_after']} |")
print("\n| Bin | n before | predicted before | observed before | n after | predicted after | observed after |\n|---|---|---|---|---|---|---|")
for b, a in zip(c["reliability_before"], c["reliability_after"]):
    print(f"| {b['bin']} | {b['n']} | {b['mean_predicted']} | {b['observed_rate']} | {a['n']} | {a['mean_predicted']} | {a['observed_rate']} |")

ab = m["ablations"]
print(f"\n### Ablations (uncalibrated, grouped test split; full model PR-AUC {ab['full_model_uncalibrated']['pr_auc']}, ROC-AUC {ab['full_model_uncalibrated']['roc_auc']})\n")
print("| Dropped | PR-AUC | change | ROC-AUC | change |\n|---|---|---|---|---|")
for k, v in ab.items():
    if k != "full_model_uncalibrated":
        print(f"| {k} | {v['pr_auc']} | {v['pr_auc_change']} | {v['roc_auc']} | {v['roc_auc_change']} |")
ln = m["label_noise"]
print(f"\nLabel noise (+{ln['extra_flip_rate']:.0%} flipped training labels): ROC-AUC {ln['roc_auc_clean']} -> {ln['roc_auc_noisy']} ({ln['roc_auc_change']}).")
print("\nMonotonicity (shipped model, 300 test rows): " + ", ".join(f"{k} {v['violations']}/{v['points_checked']}" for k, v in m["monotonicity"].items()) + " violations.")
dt = m["determinism"]
print(f"\nDeterminism: same model_version {dt['same_model_version']}, same artifact sha256 {dt['same_artifact_sha256']}, identical predictions {dt['identical_predictions']} (version {dt['model_version']}).")

print("\n### Detection rules D (asset-window level)\n\n| Gen | Rule | Targets | Precision | Recall | TP | FP | FN | FP from benign anomalies |\n|---|---|---|---|---|---|---|---|---|")
for g, rules in m["detection_rules_D"].items():
    for rid, r in rules.items():
        print(f"| {g} | {rid} | {r['targets']} | {r['precision']} | {r['recall']} | {r['true_positives']} | {r['false_positives']} | {r['false_negatives']} | {r['false_positives_from_benign_anomalies']} |")

t = m["m4_trend_backtest"]
print(f"\n### M4 trend backtest\n\n{t['runs']} synthetic histories, forecast from day {t['forecast_from_day']}, horizon {t['horizon_cap_days']} days, {t['histories_with_a_crossing']} with a real crossing. MAE of crossing time: M4 {t['mae_days_m4']} days, naive last value {t['mae_days_naive_last_value']} days. M4 anticipated {t['crossings_anticipated_by_m4']} of {t['histories_with_a_crossing']} crossings.")

a = m["m3_leakage_adversary"]
print(f"\n### M3 leakage adversary ({a['runs']} runs, mean ± std)\n\n| Attack | Adversary | Chance |\n|---|---|---|")
print(f"| T1 which service a hash is (top-1) | {a['T1_service_identity_top1']['mean']} ± {a['T1_service_identity_top1']['std']} | {a['T1_chance']['mean']} ± {a['T1_chance']['std']} |")
print(f"| T2 named edges recovered | {a['T2_named_edges_recovered']['mean']} ± {a['T2_named_edges_recovered']['std']} | {a['T2_chance']['mean']} ± {a['T2_chance']['std']} |")
print(f"| T3 service currently high/critical, from timing only | {a['T3_hot_band_from_timing']['mean']} ± {a['T3_hot_band_from_timing']['std']} | {a['T3_majority_baseline']['mean']} ± {a['T3_majority_baseline']['std']} (majority) |")
print(f"\nAnonymity set (services in the same org with identical public observables): mean {a['anonymity_set_mean']['mean']}, minimum {a['anonymity_set_min']['mean']}. Edge existence between hashes: {a['edge_existence_between_hashes']}.")

s = m["constant_sensitivity"]["results"]
print("\n### Sensitivity of hand-set constants (x0.8 / x1.2)\n\n| Constant | Kendall tau (top 10) | Top-10 overlap |\n|---|---|---|")
for k, v in s.items():
    print(f"| {k} | {v['kendall_tau_top10']} | {v['top10_overlap']} |")

print("\n### Data\n")
for g, v in man["generators"].items():
    print(f"- Generator {g}: {v['assets']} assets, {v['rows']} rows, positive rate {v['positive_rate']}, rows with a vulnerability {v['rows_with_vulnerability']}, rows known-exploited {v['rows_known_exploited']}, CVEs from type-matched advisories {v['cves_drawn_from_type_matched_advisories']}, from sector fallback {v['cves_drawn_from_sector_fallback']}, attack episodes {v['attack_episodes']}, leakage audit passed {v['leakage_audit']['passed']}.")
