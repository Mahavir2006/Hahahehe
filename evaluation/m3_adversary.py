"""
M3 leakage adversary (evaluation only, never in production).

What an outsider sees on-chain after SEC-PRIV (backend/common/sealed.py, read only): org ids (keccak of public
names), salted service hashes, which hashed services have a dependency edge (both sides attest), the timestamps
and counts of risk attestations, alerts and acknowledgements. Bands, dependency terms, alert severity and finding
outcomes are sealed or committed. Plausible outsider knowledge: each org's public service catalogue (roles) and
priors such as "a primary supply service has more downstream consumers".

Attacks, each against chance, over 20 random consortia (mean and spread):
  T1 which named service (role) a hash is         chance = 1 / services in that org
  T2 which named edges exist                      edges between hashes are public; naming them needs T1
  T3 whether a service is currently high/critical from public timing only   chance = majority class
Anonymity set = services in the same org with an identical public observable vector.

    python evaluation/m3_adversary.py
"""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from common import record

ROLES = ["primary_supply", "secondary_supply", "control", "metering", "internal"]
SUPPLY_W = {"primary_supply": 3.0, "secondary_supply": 1.5, "control": 0.8, "metering": 0.4, "internal": 0.2}


def consortium(rng):
    """3 orgs, 3-5 services each with distinct roles; edges by role prior; activity partly driven by the hidden band."""
    svcs = []
    for o in range(3):
        k = int(rng.integers(3, 6))
        for r in rng.permutation(ROLES)[:k]:
            hot = rng.random() < 0.3                                   # hidden: band high/critical
            svcs.append({"org": o, "role": str(r), "hot": hot})
    edges = set()
    for i, c in enumerate(svcs):
        for j, p in enumerate(svcs):
            if c["org"] != p["org"] and rng.random() < 0.08 * SUPPLY_W[p["role"]]:
                edges.add((i, j))                                      # consumer i depends on provider j
    for i, s in enumerate(svcs):
        s["in_deg"] = sum(1 for (_, p) in edges if p == i)
        s["out_deg"] = sum(1 for (c, _) in edges if c == i)
        s["attestations"] = int(rng.poisson(2 + 3 * s["hot"]))        # re-attested when the band moves
        s["alerts"] = int(rng.poisson(0.2 + 1.5 * s["hot"] * (s["in_deg"] > 0)))
        s["acks"] = int(rng.poisson(s["alerts"] * min(s["in_deg"], 3) * 0.8))
        s["org_size"] = sum(1 for t in svcs if t["org"] == s["org"])
    return svcs, edges


def obs(s):
    return [s["org"], s["org_size"], s["in_deg"], s["out_deg"], s["attestations"], s["alerts"], s["acks"]]


def run(seed):
    rng = np.random.default_rng(seed)
    train = [consortium(rng) for _ in range(300)]                     # the attacker's own simulations from priors
    X = [obs(s) for svcs, _ in train for s in svcs]
    role = [s["role"] for svcs, _ in train for s in svcs]
    hot = [int(s["hot"]) for svcs, _ in train for s in svcs]
    t1 = RandomForestClassifier(n_estimators=150, max_depth=6, random_state=seed, n_jobs=1).fit(X, role)
    t3 = RandomForestClassifier(n_estimators=150, max_depth=6, random_state=seed, n_jobs=1).fit([x[2:] for x in X], hot)
    svcs, edges = consortium(rng)                                     # the real consortium under attack
    Xt = [obs(s) for s in svcs]
    pred_role = t1.predict(Xt)
    t1_acc = float(np.mean([p == s["role"] for p, s in zip(pred_role, svcs)]))
    t1_chance = float(np.mean([1 / s["org_size"] for s in svcs]))
    named_ok = [pred_role[c] == svcs[c]["role"] and pred_role[p] == svcs[p]["role"] for c, p in edges]
    t2 = float(np.mean(named_ok)) if edges else float("nan")
    t2_chance = float(np.mean([1 / (svcs[c]["org_size"] * svcs[p]["org_size"]) for c, p in edges])) if edges else float("nan")
    y3 = np.array([int(s["hot"]) for s in svcs])
    t3_acc = float(np.mean(t3.predict([x[2:] for x in Xt]) == y3))
    t3_chance = float(max(y3.mean(), 1 - y3.mean()))
    anon = []
    for s in svcs:
        anon.append(sum(1 for t in svcs if t["org"] == s["org"] and obs(t) == obs(s)))
    return {"t1": t1_acc, "t1_chance": t1_chance, "t2": t2, "t2_chance": t2_chance, "t3": t3_acc, "t3_chance": t3_chance,
            "anon_mean": float(np.mean(anon)), "anon_min": int(min(anon)), "edge_existence_between_hashes": 1.0}


def main(runs: int = 20):
    rs = [run(42 + i) for i in range(runs)]

    def ms(k):
        v = np.array([r[k] for r in rs], dtype=float)
        v = v[~np.isnan(v)]
        return {"mean": round(float(v.mean()), 4), "std": round(float(v.std()), 4)}

    out = {
        "runs": runs, "public_inputs": "org ids, salted service hashes, edge existence between hashes, counts/timestamps of attestations, alerts and acks",
        "T1_service_identity_top1": ms("t1"), "T1_chance": ms("t1_chance"),
        "T2_named_edges_recovered": ms("t2"), "T2_chance": ms("t2_chance"),
        "T3_hot_band_from_timing": ms("t3"), "T3_majority_baseline": ms("t3_chance"),
        "anonymity_set_mean": ms("anon_mean"), "anonymity_set_min": ms("anon_min"),
        "edge_existence_between_hashes": "fully public (accepted residual, docs/THREAT_MODEL.md)",
        "note": "simulated consortia from outsider priors; evaluation only",
    }
    record("m3_leakage_adversary", out)
    print(out)


if __name__ == "__main__":
    main()
