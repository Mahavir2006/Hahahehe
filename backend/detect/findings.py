"""
Findings from simulated telemetry and asset state (PS-03 WP3).

Finding record:
  {finding_id, org, asset_id, event_time, finding_type: "exposure"|"active_attack", detection_method, rule_id,
   evidence: [..], severity: low|medium|high|critical, confidence: 0..1 (rule heuristic), related_cve|null,
   source: "telemetry"|"advisory"|"simulated", sim_day}

active_attack findings come from rules over telemetry (source "telemetry"); exposure findings come from asset
state: seeded real CVEs (source "advisory") or simulated inventory facts (source "simulated").
The Detector learns remote-access sources over a WARMUP_DAYS baseline before it raises findings.
Episode labels from the generator are written to a separate file and never read here.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from backend.detect.rules import RULES, SEVERITY_ORDER
from backend.detect.telemetry import TelemetryGenerator

LOOKBACK_DAYS = 30
WARMUP_DAYS = 30
MGMT_PORTS = {22, 23, 3389, 5900, 102, 502, 44818, 2404}


def finding_id(*parts: Any) -> str:
    return "F-" + hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


class Detector:
    def __init__(self, org: str, inventory: Dict[str, Dict[str, Any]], start: date, seed: int = 42,
                 labels_path: Optional[Path] = None, gen: Optional[TelemetryGenerator] = None):
        self.org, self.inventory, self.start = org, inventory, start
        self.gen = gen or TelemetryGenerator(seed)
        self.labels_path = labels_path
        self.records: Dict[str, Deque[Dict[str, Any]]] = {a: deque(maxlen=LOOKBACK_DAYS) for a in inventory}
        self.seen: Dict[str, Dict[str, int]] = {a: {} for a in inventory}      # asset -> remote src -> last seen day
        self.findings: Dict[str, Dict[str, Any]] = {}
        self.hits: Dict[str, Deque[Dict[str, Any]]] = {a: deque() for a in inventory}
        self.last_day: Optional[int] = None
        for d in range(-WARMUP_DAYS, 0):           # baseline learning: no findings, no labels kept
            for aid, inv in inventory.items():
                rec, _ = self.gen.day(org, inv, d, (start + timedelta(days=d)).weekday(), [])
                self._learn(aid, rec)

    def _learn(self, aid: str, rec: Dict[str, Any]) -> None:
        for s in rec["remote_sessions"]:
            self.seen[aid][s["src"]] = rec["sim_day"]
        self.records[aid].append(rec)

    def _seen_sources(self, aid: str, day: int) -> set:
        return {s for s, d in self.seen[aid].items() if day - d <= LOOKBACK_DAYS}

    def step(self, day: int, assets: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate one simulated day for every asset, run the rules, refresh exposure findings."""
        if self.last_day is not None and day <= self.last_day:
            return []
        self.last_day = day
        when = (self.start + timedelta(days=day)).isoformat()
        new: List[Dict[str, Any]] = []
        labels = []
        for aid, inv in self.inventory.items():
            a = assets.get(aid)
            kev = [v["cve"] for v in (a.vulns if a is not None else []) if v.get("exploited")]
            rec, eps = self.gen.day(self.org, {**inv, "zone": getattr(a, "zone", inv["zone"])}, day, (self.start + timedelta(days=day)).weekday(), kev)
            labels += [{"org": self.org, "asset_id": aid, "sim_day": day, **e} for e in eps]
            if a is not None and getattr(a, "isolated", False):
                rec = {**rec, "remote_sessions": [], "new_peers": 0, "internal_admin_targets": 0}  # quarantined: no traffic
            ctx = {"zone": inv["zone"], "seen_remote_sources": self._seen_sources(aid, day)}
            for rule in RULES:
                h = rule(rec, ctx)
                if h is None:
                    continue
                f = {"finding_id": finding_id(self.org, aid, h["rule_id"], day), "org": self.org, "asset_id": aid, "event_time": when,
                     "finding_type": "active_attack", "detection_method": h["detection_method"], "rule_id": h["rule_id"],
                     "evidence": h["evidence"], "severity": h["severity"], "confidence": h["confidence"], "related_cve": h["related_cve"],
                     "source": "telemetry", "sim_day": day}
                self.findings[f["finding_id"]] = f
                self.hits[aid].append(f)
                new.append(f)
            self._learn(aid, rec)
            while self.hits[aid] and day - self.hits[aid][0]["sim_day"] >= LOOKBACK_DAYS:
                self.hits[aid].popleft()
        new += self._exposures(day, when, assets)
        if self.labels_path is not None and labels:
            self.labels_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.labels_path, "a", encoding="utf-8") as fh:
                for lb in labels:
                    fh.write(json.dumps(lb, sort_keys=True) + "\n")
        return new

    def _exposures(self, day: int, when: str, assets: Dict[str, Any]) -> List[Dict[str, Any]]:
        new = []
        for aid, a in assets.items():
            inv = self.inventory[aid]
            items = []
            for v in a.vulns:
                if v.get("exploited"):
                    items.append(("kev", "high" if a.internet_exposed else "medium", [f"{v['cve']} is on CISA KEV", f"internet_exposed={a.internet_exposed}"], v["cve"], v.get("source", "advisory")))
                elif (v.get("cvss") or 0) >= 9.0:
                    items.append(("critical_cvss", "medium", [f"{v['cve']} CVSS {v['cvss']}"], v["cve"], v.get("source", "advisory")))
            if a.default_credentials:
                items.append(("default_credentials", "high" if a.internet_exposed else "medium", ["default credentials in use (inventory)"], None, "simulated"))
            mg = sorted(set(inv.get("open_ports", [])) & MGMT_PORTS)
            if a.internet_exposed and mg:
                items.append(("exposed_mgmt_ports", "high", [f"internet-exposed with management ports {mg}"], None, "simulated"))
            for kind, sev, ev, cve, src in items:
                fid = finding_id(self.org, aid, "exposure", kind, cve)
                if fid in self.findings:
                    continue
                f = {"finding_id": fid, "org": self.org, "asset_id": aid, "event_time": when, "finding_type": "exposure",
                     "detection_method": "asset state check", "rule_id": f"EXP_{kind.upper()}", "evidence": ev, "severity": sev,
                     "confidence": 1.0, "related_cve": cve, "source": "advisory" if src == "real_snapshot" else src, "sim_day": day}
                self.findings[fid] = f
                new.append(f)
        return new

    def aggregate(self, aid: str, day: int) -> Dict[str, float]:
        """30-day look-back telemetry features (same names as the M1 telemetry features) for AssetCtx.telemetry."""
        recs = [r for r in self.records[aid] if day - r["sim_day"] < LOOKBACK_DAYS and r["sim_day"] >= 0]
        hits = [h for h in self.hits[aid] if day - h["sim_day"] < LOOKBACK_DAYS]
        return {
            "failed_auth_count": float(sum(r["auth_failures"] for r in recs)),
            "new_remote_session_flag": float(any(h["rule_id"] == "R2_UNEXPECTED_REMOTE_ACCESS" for h in hits)),
            "rule_hit_count": float(len(hits)),
            "high_severity_rule_hit": float(any(SEVERITY_ORDER.index(h["severity"]) >= 2 for h in hits)),
        }

    def list(self, asset_id: Optional[str] = None) -> List[Dict[str, Any]]:
        out = [f for f in self.findings.values() if asset_id is None or f["asset_id"] == asset_id]
        return sorted(out, key=lambda f: (-f["sim_day"], f["finding_type"], f["asset_id"], f["rule_id"]))
