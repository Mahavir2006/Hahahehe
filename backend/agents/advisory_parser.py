"""
Deterministic advisory parsing, injection heuristics and inventory matching.

This is the offline implementation of everything the Intake agent asks an LLM to do (AG-LLM-02).
Advisory text is always treated as DATA (AG-INT-02).
"""

from __future__ import annotations

import base64
import hashlib
import re
import unicodedata
from typing import Dict, List, Optional, Tuple

VENDOR_ALIASES: List[Tuple[str, str]] = [
    (r"siemens healthineers", "Siemens Healthineers"),
    (r"siemens", "Siemens"),
    (r"rockwell automation|rockwell", "Rockwell Automation"),
    (r"schneider electric|schneider", "Schneider Electric"),
    (r"philips healthcare|philips", "Philips Healthcare"),
    (r"ge healthcare", "GE Healthcare"),
    (r"ge grid solutions|ge digital|ge vernova|\bge\b", "GE Grid Solutions"),
    (r"\babb\b", "ABB"),
    (r"cisco", "Cisco"),
    (r"emerson", "Emerson"),
    (r"honeywell", "Honeywell"),
    (r"yokogawa", "Yokogawa"),
    (r"eaton", "Eaton"),
    (r"palo alto networks|palo alto", "Palo Alto Networks"),
    (r"aveva", "AVEVA"),
    (r"baxter", "Baxter"),
    (r"landis\+gyr|landis & gyr", "Landis+Gyr"),
    (r"endress\+hauser", "Endress+Hauser"),
    (r"\bdell\b", "Dell"),
    (r"\bhp\b|hewlett", "HP"),
    (r"lenovo", "Lenovo"),
    (r"\bepic\b", "Epic"),
]

INJECTION_PATTERNS = [
    r"ignore (?:all |any )?(?:the )?(?:previous|prior|above) (?:instructions|rules|prompts?)",
    r"disregard (?:all |any )?(?:previous|prior|above)",
    r"forget (?:all |any )?(?:previous|prior)",
    r"\bsystem\s*:",
    r"you are now\b",
    r"new instructions\b",
    r"maintenance mode",
    r"(?:call|invoke|execute|run)\s+(?:the\s+)?(?:approve|execute|isolate|reject|markExecuted)\w*\s*(?:\(|function)?",
    r"approve (?:all|every|any)\b.{0,40}(?:action|remediation|request|isolation)",
    r"without (?:human )?review",
    r"act as (?:an? )?(?:admin|administrator|root|system)",
    r"reveal (?:your )?(?:system )?(?:prompt|instructions|keys?)",
]
_INJ_RE = [re.compile(p, re.I | re.S) for p in INJECTION_PATTERNS]
_ZW = re.compile("[​-‏⁠﻿‪-‮]")
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
MAX_CHARS = 200_000


def sanitize(text: str) -> Tuple[str, List[str]]:
    """Strip invisible characters and bound size. Returns (clean_text, flags)."""
    flags = []
    if _ZW.search(text):
        flags.append("hidden_unicode")
    clean = _ZW.sub("", text)
    clean = unicodedata.normalize("NFKC", clean)
    if len(clean) > MAX_CHARS:
        clean = clean[:MAX_CHARS]
        flags.append("truncated")
    return clean, flags


def injection_signals(raw: str) -> List[str]:
    """AG-INT-03: imperative phrases aimed at the assistant, hidden text and base64 blobs."""
    sig = []
    if _ZW.search(raw):
        sig.append("hidden_unicode")
    clean = _ZW.sub("", raw)
    for rx in _INJ_RE:
        if rx.search(clean):
            sig.append("imperative:" + rx.pattern[:40])
    for m in _B64.finditer(clean):
        try:
            dec = base64.b64decode(m.group(0), validate=True)
            if len(dec) >= 8 and sum(32 <= b < 127 for b in dec) / len(dec) > 0.85:
                sig.append("base64_text_blob")
                break
        except Exception:  # noqa: BLE001
            continue
    return sig


# ------------------------------------------------------------------- versions
_VER_TOKEN = re.compile(r"\d+(?:\.\d+)*")


def vtuple(v: str) -> Tuple[int, ...]:
    m = _VER_TOKEN.search(v or "")
    return tuple(int(x) for x in m.group(0).split(".")) if m else ()


def _cmp(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a2, b2 = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a2 > b2) - (a2 < b2)


_RANGE_PATTERNS = [
    ("all", re.compile(r"\ball\s+(?:\w+\s+)?versions\b", re.I)),
    ("lt", re.compile(r"\b(?:before|prior to|earlier than|below)\s+v?(\d[\w.\-]*)", re.I)),
    ("between", re.compile(r"\bv?(\d[\w.\-]*)\s+(?:through|thru|to)\s+v?(\d[\w.\-]*)", re.I)),
    ("le", re.compile(r"\bv?(\d[\w.\-]*(?:\s+R\d+)?)\s+and\s+(?:earlier|below|prior|older)", re.I)),
    ("le", re.compile(r"\b(?:up to and including|through)\s+v?(\d[\w.\-]*)", re.I)),
    ("exact", re.compile(r"\bversions?\s+v?(\d[\w.\-]*)\b(?!\s+(?:and|through|to))", re.I)),
]


def find_ranges(s: str) -> List[Tuple[str, str]]:
    """Return [(normalized_text, kind)] for version ranges stated in a line."""
    out: List[Tuple[str, str]] = []
    taken: List[Tuple[int, int]] = []
    for kind, rx in _RANGE_PATTERNS:
        for m in rx.finditer(s):
            if any(m.start() < e and m.end() > b for b, e in taken):
                continue
            taken.append((m.start(), m.end()))
            if kind == "all":
                out.append(("all versions", kind))
            elif kind == "lt":
                out.append((f"before {m.group(1).rstrip('.,;')}", kind))
            elif kind == "between":
                out.append((f"{m.group(1)} through {m.group(2).rstrip('.,;')}", kind))
            elif kind == "le":
                out.append((f"{m.group(1).strip().rstrip('.,;')} and earlier", kind))
            else:
                out.append((m.group(1).rstrip(".,;"), kind))
    return out


def version_in_range(version: str, rng: str) -> bool:
    v = vtuple(version)
    r = rng.strip().lower()
    if r == "all versions":
        return True
    if not v:
        return False
    if r.startswith("before "):
        return _cmp(v, vtuple(r[7:])) < 0
    if " through " in r:
        a, b = r.split(" through ")
        return _cmp(v, vtuple(a)) >= 0 and _cmp(v, vtuple(b)) <= 0
    if r.endswith(" and earlier"):
        return _cmp(v, vtuple(r[: -len(" and earlier")])) <= 0
    return _cmp(v, vtuple(r)) == 0


# ------------------------------------------------------------------ extraction
def canonical_vendor(s: str) -> Optional[str]:
    for pat, name in VENDOR_ALIASES:
        if re.search(pat, s, re.I):
            return name
    return None


def vendor_key(v: str) -> str:
    return (canonical_vendor(v) or v).strip().lower()


_CVE = re.compile(r"CVE-\d{4}-[0-9A-Za-z]{3,}")
_CVSS = re.compile(r"CVSS[^\n]{0,40}?(?:Base Score|Score)?[:\s]*([0-9]{1,2}\.[0-9])", re.I)
_NOISE_WORDS = re.compile(
    r"\b(?:firmware|software|versions?|series|switches|controllers?|drives?|products?|units?|patient monitors?|"
    r"monitors?|chlorination|gateways?|scada|systems?|corp|inc|ltd)\b",
    re.I,
)


def _clean_product(s: str, vendor: Optional[str]) -> str:
    s = re.sub(r"^[\-\*•\d.\s]+", "", s).strip()
    s = re.split(r"\s*(?::|\(|—|–|\bfirmware\b|\bversions?\b|\bbefore\b|\bprior\b)", s, maxsplit=1, flags=re.I)[0]
    if vendor:
        for pat, name in VENDOR_ALIASES:
            if name == vendor:
                s = re.sub(pat, "", s, flags=re.I).strip()
    s = _NOISE_WORDS.sub("", s)
    return re.sub(r"\s+", " ", s).strip(" -:,")


def extract(text: str) -> Dict:
    clean, flags = sanitize(text)
    lines = [l.rstrip() for l in clean.split("\n")]
    head = "\n".join(lines[:6])
    cves = list(dict.fromkeys(_CVE.findall(clean)))

    vendor: Optional[str] = None
    if re.search(r"multiple vendors", clean, re.I):
        vendor = "Multiple"
    else:
        for l in lines[:4]:
            v = canonical_vendor(l)
            if v:
                vendor = v
                break
        if not vendor:
            vendor = canonical_vendor(head) or canonical_vendor(clean[:1500])
    if not vendor:
        m = re.search(r"vulnerabilit\w+ in (?:a )?(?:product )?([A-Z][\w+]*(?: [A-Z][\w+]*)*?)(?: Product| [A-Z]+-\d+)", head)
        if m:
            vendor = m.group(1).strip()
        else:
            m = re.match(r"\W*([A-Z][\w+]*(?: Corp| Inc| Ltd)?)\s+(?:Security|Product|Advisory)", head)
            vendor = m.group(1) if m else "Unknown"

    pairs: List[Tuple[str, str]] = []
    mvp = re.search(r"vulnerabilit\w+ in (.+?) Product ([A-Z0-9][\w\-]*)", head, re.I)
    if mvp and (not vendor or vendor == "Unknown"):
        vendor = mvp.group(1).strip()
        pairs.append((mvp.group(2), "all versions" if re.search(r"all versions", clean, re.I) else ""))
    block_open = False
    prev_product: Optional[str] = None
    for i, l in enumerate(lines):
        low = l.strip().lower()
        if re.match(r"^(affected|affected products|affected versions)\b", low):
            block_open = True
            rest = l.split(":", 1)[1].strip() if ":" in l else ""
            if rest and not pairs:
                mo = re.search(r"all (?:\w+ )?versions of ([A-Za-z0-9][\w\-+ ]*)", rest, re.I)
                if mo:
                    pairs.append((_clean_product(mo.group(1), vendor), "all versions"))
                    continue
                rngs = find_ranges(rest)
                prod = _clean_product(rest, vendor) if not re.match(r"^(firmware|software)\b", rest, re.I) else ""
                prod = re.sub(r"\b(?:all|\d[\w.]*|v?\d.*)$", "", prod).strip() if prod else prod
                pairs.extend((prod, r) for r, _ in rngs)
                if rngs:
                    # "Affected: Firmware versions before X" -> product comes from the title/description
                    pass
            continue
        if block_open and not l.strip():
            block_open = False
            prev_product = None
            continue
        if block_open and l.strip().startswith(("-", "*", "•")):
            rngs = find_ranges(l)
            if rngs:
                prod = _clean_product(l, vendor) or (prev_product or "")
                pairs.extend((prod, r) for r, _ in rngs)
            else:
                prev_product = _clean_product(l, vendor)

    if not pairs:
        mv = re.search(r"([A-Z][\w+]*(?: [A-Z][\w+.]*){0,3}) version (\d[\w.]*) (?:has|is|contains|allows)", clean)
        if mv:
            prod = _clean_product(mv.group(1), vendor)
            for w in (vendor or "").split():
                prod = re.sub(r"\b" + re.escape(w) + r"\b", "", prod).strip()
            pairs.append((re.sub(r"\s+", " ", prod), mv.group(2)))
    # fall back to sentence-level patterns
    if not pairs:
        for l in lines:
            rngs = find_ranges(l)
            if rngs and re.search(r"\b(versions?|firmware|all)\b", l, re.I):
                m = re.search(r"(?:of|in|affecting)\s+([A-Z][\w\-]*(?:\s+[A-Za-z0-9][\w\-]*){0,3}?)\s+(?:versions?|firmware|remote|controllers?|\()", l)
                prod = _clean_product(m.group(1), vendor) if m else ""
                pairs.extend((prod, r) for r, _ in rngs)
                break

    # products missing: infer from title / first sentence
    products = [p for p, _ in pairs if p]
    if not products:
        title = "\n".join(lines[:3])
        for m in re.finditer(r"\b([A-Z][A-Za-z0-9+]*(?:[ -][A-Z0-9][A-Za-z0-9.+-]*){0,3})\b", title):
            cand = _clean_product(m.group(1), vendor)
            if cand and cand.lower() not in {"cert in advisory", "ics cert advisory"} and not _CVE.match(cand) and not re.match(r"^(?:CERT|ICS|Security|Critical|Buffer|SQL|Path|Multiple|Vulnerab)", cand):
                products.append(cand)
                break
    if pairs and any(not p for p, _ in pairs):
        fallback = products[0] if products else ""
        pairs = [(p or fallback, r) for p, r in pairs]
    products = list(dict.fromkeys(p for p, _ in pairs if p) or products)
    ranges = list(dict.fromkeys(r for _, r in pairs)) or (["all versions"] if re.search(r"all (?:\w+ )?versions", clean, re.I) else [])

    cvss = None
    body = "\n".join(l for l in clean.split("\n") if "CVSS:3" not in l and "CVSS:2" not in l)  # drop vector strings
    body = re.sub(r"CVSS\s*(?:v|version\s*)?[34]\.[01]", "CVSS", body, flags=re.I)  # drop the spec version number
    found = [float(x) for x in re.findall(r"base score[:\s]*([0-9]{1,2}\.[0-9])", body, re.I)]
    found += [float(x) for x in re.findall(r"CVSS[^\n]{0,30}?[:\s]([0-9]{1,2}\.[0-9])\b", body, re.I)]
    found = [x for x in found if 0.0 <= x <= 10.0]
    if found:
        cvss = max(found)  # worst case when an advisory lists several CVEs
    low = clean.lower()
    exploited: Optional[bool] = None
    if re.search(r"(actively exploited|exploited in the wild|confirmed exploitation|exploited:\s*yes|poc available|known exploit)", low):
        exploited = True
    elif re.search(r"(no known exploitation|not (?:been )?exploited|no evidence of exploitation)", low):
        exploited = False

    title = next((l.strip() for l in lines if l.strip()), "")[:200]
    return {
        "cve_ids": cves,
        "title": title,
        "vendor": vendor,
        "products": products,
        "affected_version_ranges": ranges,
        "product_ranges": [{"product": p, "range": r} for p, r in pairs],
        "cvss_base": cvss,
        "exploited_in_wild": exploited,
        "flags": flags,
    }


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def estimate_epss(cvss: Optional[float], exploited: Optional[bool]) -> float:
    """Documented fallback when an advisory states no exploit-probability: monotone in CVSS and exploitation."""
    c = (cvss if cvss is not None else 5.0) / 10.0
    return round(min(0.97, 0.05 + 0.55 * c + (0.3 if exploited else 0.0)), 3)


# ------------------------------------------------------------------- matching
def _tokens(s: str) -> List[str]:
    return [t for t in re.split(r"[^a-z0-9+\-.]+", s.lower()) if t]


def match_inventory(finding: Dict, inventory: List[Dict]) -> List[Dict]:
    """AG-INT-04: vendor alias + product-token containment + version range. Own-org inventory only."""
    out = []
    fv = vendor_key(finding.get("vendor") or "")
    if fv in ("multiple", "unknown", ""):
        return out
    pr = finding.get("product_ranges") or [{"product": p, "range": r} for p in finding.get("products", []) for r in finding.get("affected_version_ranges", [])]
    for a in inventory:
        if vendor_key(a["vendor"]) != fv:
            continue
        mtoks = set(_tokens(a["model"]))
        for item in pr:
            ptoks = set(_tokens(item["product"]))
            if not ptoks or not ptoks <= mtoks:
                continue
            if version_in_range(a["firmware_version"], item["range"]):
                out.append(
                    {
                        "asset_id": a["asset_id"],
                        "match_reason": f"vendor={a['vendor']}, model has '{item['product']}', firmware {a['firmware_version']} in '{item['range']}'",
                        "match_confidence": 0.95 if item["range"] != "all versions" else 0.85,
                    }
                )
                break
    return out
