"""
IntakeAgent (AG-INT-*): raw advisory text -> structured, inventory-matched finding.
The advisory is DATA. Output is schema-constrained, tools are allow-listed, and injection is flagged.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from backend.agents import advisory_parser as P
from backend.agents.framework import BaseAgent, SideEffect, agent_tool


class ExtractIn(BaseModel):
    text: str
    source: str = "unknown"


class ExtractOut(BaseModel):
    extraction: Dict[str, Any]
    injection_signals: List[str] = Field(default_factory=list)
    llm_fallback: bool = False


class MatchIn(BaseModel):
    finding: Dict[str, Any]


class MatchOut(BaseModel):
    matches: List[Dict[str, Any]]


class AttestIn(BaseModel):
    content_hash: str
    cve_ids: List[str]
    matched: bool


class AttestOut(BaseModel):
    status: str
    tx_hash: Optional[str] = None


MAX_BYTES = 200_000


class IntakeAgent(BaseAgent):
    NAME = "intake"

    @agent_tool("extract_advisory", ExtractIn, ExtractOut, SideEffect.none)
    def _extract(self, i: ExtractIn) -> ExtractOut:
        text, flags = P.sanitize(i.text)
        sig = P.injection_signals(i.text)
        ex, fb = self.node.llm.extract_advisory(text)
        ex["flags"] = sorted(set(ex.get("flags", []) + flags))
        return ExtractOut(extraction=ex, injection_signals=sig, llm_fallback=fb)

    @agent_tool("match_inventory", MatchIn, MatchOut, SideEffect.none)
    def _match(self, i: MatchIn) -> MatchOut:
        # Only THIS org's own inventory is visible to the node (AG-INT-04).
        return MatchOut(matches=P.match_inventory(i.finding, list(self.node.inventory.values())))

    @agent_tool("attest_finding", AttestIn, AttestOut, SideEffect.write_chain)
    def _attest(self, i: AttestIn) -> AttestOut:
        r = self.node.attest_finding(i.content_hash, i.cve_ids, i.matched)
        return AttestOut(status=r.status, tx_hash=r.tx_hash)

    def process(self, text: str, source: str = "feed") -> Dict[str, Any]:
        if not text or not text.strip():
            raise ValueError("empty advisory rejected")
        raw_len = len(text.encode("utf-8", "replace"))
        content_hash = P.content_hash(text)
        self.log("observation", content_hash=content_hash[:16], bytes=raw_len, source=source)

        # AG-INT-05: dedupe by content hash and by CVE set
        if content_hash in {f["content_hash"] for f in self.node.findings.values()}:
            existing = next(f for f in self.node.findings.values() if f["content_hash"] == content_hash)
            self.log("decision", note="duplicate advisory (content hash)", advisory_id=existing["advisory_id"])
            return {**existing, "duplicate": True}

        ext = self.call("extract_advisory", text=text, source=source)
        e = ext.extraction
        injection = bool(ext.injection_signals)
        if injection:
            self.log("decision", note="prompt-injection suspected; advisory treated as data only", signals=ext.injection_signals[:4])
            if self.trace:
                self.trace.flags["injection_suspected"] = True

        cves = e.get("cve_ids", [])
        if cves:
            cve_key = ",".join(sorted(cves))
            for f in self.node.findings.values():
                if ",".join(sorted(f["cve_ids"])) == cve_key and not injection and f["status"] != "injection":
                    self.log("decision", note="duplicate advisory (CVE set)", advisory_id=f["advisory_id"])
                    return {**f, "duplicate": True}

        confidence = 0.9
        confidence -= 0.35 if injection else 0.0
        confidence -= 0.2 if not cves else 0.0
        confidence -= 0.1 if not e.get("products") else 0.0
        confidence -= 0.1 if ext.llm_fallback else 0.0
        if raw_len > MAX_BYTES:
            confidence -= 0.05

        finding = {
            "advisory_id": "ADV-" + content_hash[:10],
            "content_hash": content_hash,
            "source": source,
            "cve_ids": cves,
            "title": e.get("title", ""),
            "vendor": e.get("vendor", "Unknown"),
            "products": e.get("products", []),
            "affected_version_ranges": e.get("affected_version_ranges", []),
            "product_ranges": e.get("product_ranges", []),
            "cvss_base": e.get("cvss_base"),
            "exploited_in_wild": e.get("exploited_in_wild"),
            "epss_like": P.estimate_epss(e.get("cvss_base"), e.get("exploited_in_wild")),
            "extraction_confidence": round(max(confidence, 0.05), 2),
            "llm_fallback": ext.llm_fallback,
            "injection_suspected": injection,
            "injection_signals": ext.injection_signals,
            "flags": e.get("flags", []),
            "duplicate": False,
        }

        matches: List[Dict[str, Any]] = []
        if not injection:  # an injected advisory never drives remediation
            matches = self.call("match_inventory", finding=finding).matches
        finding["matches"] = matches
        finding["status"] = "injection" if injection else ("matched" if matches else "no_match")
        if finding["status"] == "no_match":
            self.log("decision", note="no inventory match (recorded, not an error)")

        self.node.findings[finding["advisory_id"]] = finding
        if cves or injection:
            att = self.call("attest_finding", content_hash=content_hash, cve_ids=cves or ["none"], matched=bool(matches))
            finding["attestation"] = att.model_dump()
        return finding
