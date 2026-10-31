import shutil
from datetime import date, timedelta

import pytest

from backend.data_real import (
    REAL_DIR,
    SIZE_CAP_BYTES,
    EpssLookAheadError,
    SnapshotIntegrityError,
    dir_size_bytes,
    load_epss,
    load_kev,
    load_manifest,
    load_vulns,
    parse_version_range,
    verify_all,
)


@pytest.fixture()
def snapshot(tmp_path):
    dst = tmp_path / "real"
    shutil.copytree(REAL_DIR, dst)
    return dst


@pytest.mark.req("DATA-REAL-01")
def test_manifest_verifies_and_detects_tampering(snapshot):
    manifest = verify_all(snapshot)
    assert set(manifest["files"]) >= {"vuln_snapshot.jsonl", "kev.jsonl"}
    assert len(load_vulns(snapshot)) == manifest["files"]["vuln_snapshot.jsonl"]["rows"]
    assert len(load_kev(snapshot)) == manifest["files"]["kev.jsonl"]["rows"]

    p = snapshot / "kev.jsonl"
    data = p.read_bytes()
    p.write_bytes(data.replace(b'"Microsoft"', b'"Micr0soft"', 1))
    with pytest.raises(SnapshotIntegrityError, match="checksum"):
        load_kev(snapshot)
    p.write_bytes(data)
    load_kev(snapshot)

    (snapshot / "vuln_snapshot.jsonl").unlink()
    with pytest.raises(SnapshotIntegrityError, match="missing"):
        load_vulns(snapshot)
    with pytest.raises(SnapshotIntegrityError, match="missing"):
        verify_all(snapshot)


@pytest.mark.req("DATA-REAL-01")
def test_crlf_checkout_still_verifies_but_missing_manifest_raises(snapshot):
    p = snapshot / "kev.jsonl"
    p.write_bytes(p.read_bytes().replace(b"\n", b"\r\n"))
    load_kev(snapshot)
    (snapshot / "MANIFEST.json").unlink()
    with pytest.raises(SnapshotIntegrityError, match="manifest"):
        load_kev(snapshot)


@pytest.mark.req("DATA-REAL-02")
def test_epss_refuses_dates_before_asof():
    if "epss.jsonl" not in load_manifest()["files"]:
        pytest.skip("EPSS not in this snapshot (see docs/DEVIATIONS.md)")
    rows = load_epss(date(2100, 1, 1))
    assert rows and all(r["time_matched"] is False for r in rows.values())
    asof = min(date.fromisoformat(r["epss_asof_date"]) for r in rows.values())
    assert load_epss(asof)
    assert load_epss(asof.isoformat())
    with pytest.raises(EpssLookAheadError):
        load_epss(asof - timedelta(days=1))
    with pytest.raises(EpssLookAheadError):
        load_epss("2023-01-01")


def _r(raw):
    r = parse_version_range(raw)
    return (r["min"], r["max"], r["min_inclusive"], r["max_inclusive"], r["all"], r["parse_failed"])


@pytest.mark.req("DATA-REAL-03")
@pytest.mark.parametrize("raw,expected", [
    ("vers:all/*", (None, None, None, None, True, False)),
    ("vers:intdot/<4.3.8", (None, "4.3.8", None, False, False, False)),
    ("vers:intdot/<=2.1", (None, "2.1", None, True, False, False)),
    ("vers:intdot/>=1.2|<3.0", ("1.2", "3.0", True, False, False, False)),
    ("vers:intdot/2.2.0", ("2.2.0", "2.2.0", True, True, False, False)),
    ("<= 4.60", (None, "4.60", None, True, False, False)),
    ("<V16.20", (None, "16.20", None, False, False, False)),
    ("< 3.1", (None, "3.1", None, False, False, False)),
    (">= 5.4.1 | <= 5.7.1", ("5.4.1", "5.7.1", True, True, False, False)),
    ("> 8.0.4", ("8.0.4", None, False, None, False, False)),
    ("2.2.0", ("2.2.0", "2.2.0", True, True, False, False)),
    ("V1.10.1", ("1.10.1", "1.10.1", True, True, False, False)),
])
def test_version_range_parses(raw, expected):
    assert _r(raw) == expected


@pytest.mark.req("DATA-REAL-03")
@pytest.mark.parametrize("raw", [
    "vers:generic/<2.0",
    "vers:semver/<1.0.0",
    "All_versions_only_if_web_components_are_used",
    "4.1.1.7662 (and possibly prior versions)",
    " < 15.1 HF001  (including former Unity Pro)",
    "3.3 SP2 (part of SPR1 2023.0)",
    "5.1.0-x | 5.1.1-x | >= 6.0.0-1 | <= 6.0.0-3",
    "15|15.1|16|17",
    ">=V10.3.3.3_only_if_web_components_are_used",
    "<=<1.0",
    "vers:intdot/>=3.0|<2.0",
    "vers:intdot/>=1.0|>=2.0",
    "",
    None,
])
def test_version_range_parse_failed_keeps_raw(raw):
    r = parse_version_range(raw)
    assert r["parse_failed"] is True and r["raw"] == raw
    assert r["min"] is None and r["max"] is None and r["all"] is False


@pytest.mark.req("DATA-REAL-03")
def test_snapshot_ranges_match_parser():
    for row in load_vulns():
        for e in row["known_affected"] + row["fixed"]:
            if e["version_raw"] is not None:
                assert e["range"] == parse_version_range(e["version_raw"])


@pytest.mark.req("DATA-REAL-04")
def test_real_dir_under_size_cap():
    size = dir_size_bytes()
    assert 0 < size < SIZE_CAP_BYTES, f"data/real is {size} bytes (cap {SIZE_CAP_BYTES})"
