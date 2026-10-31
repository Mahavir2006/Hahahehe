"""Generate cross-language canonical-JSON test vectors (consumed by chain/test/Canonical.test.ts)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.common.crypto import canonical_hash, canonical_json  # noqa: E402

CASES = [
    {"a": 1, "b": 2},
    {"b": {"z": 1, "a": 2}, "a": 3},
    [3, 1, 2],
    {"items": [{"id": 2}, {"id": 1}], "count": 2},
    {"int": 42, "float": 3.14, "sci": 1000, "neg": -7},
    {},
    [],
    {"msg": "hello \u00e9 world with  spaces"},
    {"text": "line one\nline two\ttabbed", "quote": 'she said "hi"'},
    {"nested": {"list": [1, {"x": "y z"}, None, True, False]}, "empty": ""},
    {"plan": {"steps": [{"action": "PATCH", "target": "power-asset-001", "delta": -18.6528}], "org": "power"}},
]


def build():
    return [{"value": c, "canonical": canonical_json(c), "sha256": canonical_hash(c)} for c in CASES]


if __name__ == "__main__":
    out = ROOT / "shared" / "canonical_vectors.json"
    out.write_text(json.dumps(build(), indent=2, ensure_ascii=False), encoding="utf-8")
    print("wrote", out)
