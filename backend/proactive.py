"""
Proactive reassessment (PS-03 WP4): simulated clock -> scenario events -> telemetry/rules -> score every asset ->
risk log + the EXISTING hashed snapshot -> what changed -> band attestation through the EXISTING agent path.

Loop breakers:
  * only TRIGGERS are accepted; attestation / alert / snapshot events can never start a reassessment;
  * at most one reassessment per (trigger, sim_day, key);
  * timer-triggered runs at most once per MIN_TIMER_INTERVAL_DAYS;
  * advance() steps at most MAX_STEPS days per call;
  * a second advance() while one is running is rejected (ReassessRejected("busy")).
Everything is simulated; nothing is sent to real equipment.
"""

from __future__ import annotations

import json
import threading
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend import simclock
from backend.detect.findings import Detector
from backend.detect.telemetry import TelemetryGenerator
from backend.risk import adapter
from backend.risk.inference import M1
from backend.risk import explain as X
from backend.risk import model as risk

ROOT = Path(__file__).resolve().parents[1]
TRIGGERS = {"timer", "advisory", "asset_change", "dependency_change", "scenario"}
FORBIDDEN_TRIGGERS = {"attestation", "alert", "snapshot"}
MIN_TIMER_INTERVAL_DAYS = 1
MAX_STEPS = 30
SETTABLE_FIELDS = {"internet_exposed", "default_credentials", "supply_chain_flag", "zone"}


class ReassessRejected(RuntimeError):
    pass


def load_scenario(name_or_path: str) -> Dict[str, Any]:
    p = Path(name_or_path)
    if not p.exists():
        p = ROOT / "data" / "scenarios" / f"{name_or_path}.json"
    return json.loads(p.read_text(encoding="utf-8"))


def aggregate_bp(risks: List[int]) -> int:
    """RISK-07 (0.6 * max + 0.4 * mean) in integer basis points, round half up."""
    if not risks:
        return 0
    n = len(risks)
    return X.round_half_up_div(6 * max(risks) * n + 4 * sum(risks), 10 * n)


class Reassessor:
    def __init__(self, nodes: Dict[str, Any], orch: Optional[Dict[str, Any]] = None, seed: int = 42, chain_ops: bool = True,
                 labels_path: Optional[Path] = None, real_ctx: Any = None):
        self.nodes, self.orch, self.seed, self.chain_ops = nodes, orch or {}, seed, chain_ops
        self.labels_path, self.real_ctx = labels_path, real_ctx
        self._lock = threading.Lock()
        self.baseline = {org: deepcopy(n.assets) for org, n in nodes.items()}
        self.events_log: List[Dict[str, Any]] = []
        self.changes: List[Dict[str, Any]] = []
        self.rejected: List[Dict[str, Any]] = []
        self._init_state()

    def _init_state(self) -> None:
        self.gen = TelemetryGenerator(self.seed)
        self.detectors = {org: Detector(org, n.inventory, simclock.ORIGINAL_DATE, self.seed, self.labels_path, self.gen) for org, n in self.nodes.items()}
        self.processed: set = set()
        self.last_timer_day: Optional[int] = None
        for org, n in self.nodes.items():
            n.risk_log = []
            self.detectors[org]._exposures(simclock.now_day(), simclock.now_date().isoformat(), n.assets)  # day-0 exposure findings

    # ------------------------------------------------------------------ scoring
    def _entry(self, org: str, trigger: str, key: Optional[str]) -> Dict[str, Any]:
        n, det, day = self.nodes[org], self.detectors[org], simclock.now_day()
        m = M1.get()
        assets = {}
        for aid, a in n.assets.items():
            if det.last_day is not None:  # once the simulated clock runs, telemetry features come from the PS-03 detector
                a.telemetry.update({k: int(v) for k, v in det.aggregate(aid, day).items()})
            s = X.score_asset_v2(a, m)
            assets[aid] = {"likelihood_bp": s["likelihood_bp"], "impact_bp": s["impact_bp"], "risk_bp": s["risk_bp"], "band": s["band_bp"],
                           "features": s["features"], "shap": s["factors_shap"]["all"], "likelihood_mult": a.likelihood_mult,
                           "findings": [h["finding_id"] for h in det.hits[aid] if day - h["sim_day"] < 30]}
        return {"org": org, "sim_day": day, "date": simclock.now_date().isoformat(), "trigger": trigger, "trigger_key": key,
                "model_version": m.version, "model_source": adapter.model_source(m),
                "aggregate_bp": aggregate_bp([v["risk_bp"] for v in assets.values()]), "assets": assets}

    def _chain(self, org: str, trigger: str) -> Dict[str, Any]:
        o = self.orch.get(org)
        if not self.chain_ops or o is None:
            return {"snapshot": "skipped (chain_ops off)", "attested": []}
        from backend.agents.framework import Trace

        tr = Trace(org, f"ps03-reassess-{trigger}-day{simclock.now_day()}")
        o.risk.bind(tr)
        snap = o.risk.call("record_snapshot", note=f"ps03:{trigger}:day{simclock.now_day()}")
        att = o.risk.call("attest_service_risk", force=False)
        self.nodes[org].audit.save_trace(tr.to_dict())
        return {"snapshot": snap.model_dump(), "attested": att.attested}

    def reassess_all(self, trigger: str, key: Optional[str] = None) -> Dict[str, Any]:
        if trigger in FORBIDDEN_TRIGGERS or trigger not in TRIGGERS:
            self.rejected.append({"trigger": trigger, "key": key, "sim_day": simclock.now_day()})
            raise ReassessRejected(f"trigger '{trigger}' may not start a reassessment")
        day = simclock.now_day()
        tk = (trigger, day, key)
        if tk in self.processed:
            return {"skipped": "already reassessed for this trigger", "trigger": trigger, "sim_day": day}
        if trigger == "timer" and self.last_timer_day is not None and day - self.last_timer_day < MIN_TIMER_INTERVAL_DAYS:
            return {"skipped": f"timer runs at most once per {MIN_TIMER_INTERVAL_DAYS} simulated day", "trigger": trigger, "sim_day": day}
        self.processed.add(tk)
        if trigger == "timer":
            self.last_timer_day = day
        out: Dict[str, Any] = {"trigger": trigger, "sim_day": day, "orgs": {}}
        for org, n in self.nodes.items():
            prev = n.risk_log[-1] if n.risk_log else None
            cur = self._entry(org, trigger, key)
            n.risk_log.append(cur)
            changed = [c for c in (X.explain_change(prev, cur, aid) for aid in cur["assets"]) if c] if prev else []
            for c in changed:
                c["org"] = org
            self.changes += changed
            out["orgs"][org] = {"aggregate_bp": cur["aggregate_bp"], "changed": changed, **self._chain(org, trigger)}
        return out

    # ------------------------------------------------------------------ events
    def _apply_event(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        n = self.nodes[ev["org"]]
        a = n.assets[ev["asset_id"]]
        t = ev["type"]
        if t == "add_vuln":
            row = next((r for r in (self.real_ctx.rows if self.real_ctx else []) if r["cve"] == ev["cve"]), None)
            if row is None:
                raise ValueError(f"CVE {ev['cve']} is not in the real snapshot")
            v = self.real_ctx.vuln(row, "scenario", n.inventory[ev["asset_id"]])
            if not any(x["cve"] == v["cve"] for x in a.vulns):
                a.vulns.append(v)
        elif t == "set_field":
            if ev["field"] not in SETTABLE_FIELDS:
                raise ValueError(f"field {ev['field']} cannot be set by a scenario")
            setattr(a, ev["field"], ev["value"])
        elif t == "episode":
            self.gen.inject(ev["org"], ev["asset_id"], ev["kind"], simclock.now_day(), ev.get("days", 1))
        elif t == "action":
            risk.apply_action(a, ev["action"])
        else:
            raise ValueError(f"unknown scenario event type {t}")
        rec = {**ev, "applied_on_sim_day": simclock.now_day()}
        self.events_log.append(rec)
        return rec

    def advance(self, days: int, scenario: Optional[str] = None) -> Dict[str, Any]:
        if not self._lock.acquire(blocking=False):
            raise ReassessRejected("busy: another advance is running")
        try:
            want = int(days)
            if want < 1:
                raise ValueError("days must be >= 1")
            steps = min(want, MAX_STEPS)
            sc = load_scenario(scenario) if scenario else None
            start = simclock.now_day()
            applied, runs, before = [], [], len(self.changes)
            for _ in range(steps):
                day = simclock.advance(1)
                evs = [e for e in (sc or {}).get("events", []) if e["day"] == day] if sc else []
                applied += [self._apply_event(e) for e in evs]
                for org, det in self.detectors.items():
                    det.step(day, self.nodes[org].assets)
                runs.append(self.reassess_all("scenario" if evs else "timer", key=f"{scenario}:{day}" if evs else None))
            return {"from_day": start, "to_day": simclock.now_day(), "requested_days": want, "steps": steps, "capped": want > steps,
                    "events_applied": applied, "changes": self.changes[before:], "reassessments": len(runs)}
        finally:
            self._lock.release()

    def reset(self) -> Dict[str, Any]:
        """Clock to day 0, assets to their startup state, risk log / findings / scenario state cleared.
        On-chain attestations and the audit chain are append-only and are NOT rewound."""
        if not self._lock.acquire(blocking=False):
            raise ReassessRejected("busy: an advance is running")
        try:
            simclock.reset()
            for org, n in self.nodes.items():
                n.assets = deepcopy(self.baseline[org])
            self.events_log, self.changes, self.rejected = [], [], []
            self._init_state()
            return {"sim_day": 0, "note": "on-chain attestations and audit anchors are append-only and were not rewound"}
        finally:
            self._lock.release()

    # ------------------------------------------------------------------ reads
    def history(self, org: str) -> Dict[str, Any]:
        log = self.nodes[org].risk_log
        per: Dict[str, List[Tuple[int, int, str]]] = {}
        for e in log:
            for aid, a in e["assets"].items():
                per.setdefault(aid, []).append({"sim_day": e["sim_day"], "risk_bp": a["risk_bp"], "band": a["band"], "trigger": e["trigger"]})
        return {"org": org, "aggregate": [{"sim_day": e["sim_day"], "aggregate_bp": e["aggregate_bp"], "trigger": e["trigger"], "model_version": e["model_version"]} for e in log],
                "assets": per}

    def days_at_high(self, org: str, aid: str) -> int:
        k = 0
        last_day = None
        for e in reversed(self.nodes[org].risk_log):
            if e["sim_day"] == last_day:
                continue
            last_day = e["sim_day"]
            if e["assets"][aid]["band"] in ("high", "critical"):
                k += 1
            else:
                break
        return k
