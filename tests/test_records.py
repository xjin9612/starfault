"""CVE JSON 5 的解析。tests/fixtures/cvelist/ 是 cvelistV5 delta 的真實紀錄節錄。"""

from __future__ import annotations

import json

import pytest

from starfault.records import (
    TITLE_MAX,
    RecordError,
    first_sentence,
    parse_record,
    record_from_json,
    record_to_json,
    severity,
)
from tests.builders import FIXTURES, cve, fixture_record


def test_cna_v40_is_preferred_over_v31() -> None:
    r = parse_record(fixture_record("CVE-2025-71472"))
    assert r.cvss is not None
    assert (r.cvss.score, r.cvss.version, r.cvss.source, r.cvss.sev) == (
        6.8,
        "4.0",
        "vendor",
        "medium",
    )
    assert r.cvss.vector.startswith("CVSS:4.0/")
    assert r.title == "littlefs 2.8.0 through 2.11.3 Divide by Zero in lfs_mount_()"
    assert r.cwe == (("CWE-369", "Divide By Zero"),)
    assert r.affected[0].versions == "2.8.0 – 2.11.3"


def test_cisa_adp_score_is_used_when_cna_has_none() -> None:
    r = parse_record(fixture_record("CVE-2026-114023"))
    assert r.cvss is not None
    assert (r.cvss.score, r.cvss.version, r.cvss.source) == (8.8, "3.1", "cisa-adp")
    # CNA 沒有 CWE 時改用 CISA ADP 的。
    assert r.cwe[0][0] == "CWE-22"
    assert r.title is None
    assert r.display_title() == "A path handling issue was addressed with improved validation."
    assert r.display_title("Apple macOS Path Traversal") == "Apple macOS Path Traversal"
    a = r.affected[0]
    assert (a.vendor, a.product) == ("Apple", "macOS")
    assert a.versions == "< 15.8.2, < 26.7.2, < 27.2"
    assert a.fixed == "15.8.2, 26.7.2, 27.2"


def test_cvss_v30_is_used_when_no_newer_version() -> None:
    r = parse_record(fixture_record("CVE-2024-7409"))
    assert r.cvss is not None and (r.cvss.score, r.cvss.version) == (7.5, "3.0")


def test_record_without_any_score() -> None:
    r = parse_record(fixture_record("CVE-2026-124851"))
    assert r.cvss is None
    assert r.vendor_product() == ("Facebook", "Zstandard")


def test_rejected_record() -> None:
    r = parse_record(fixture_record("CVE-2026-12401"))
    assert r.rejected
    assert r.published is None and r.cvss is None


def test_git_versions_are_skipped_and_package_name_fills_product() -> None:
    r = parse_record(fixture_record("CVE-2024-4693"))
    qemu = r.affected[0]
    assert (qemu.vendor, qemu.product, qemu.versions, qemu.fixed) == ("", "qemu", "", None)
    # 顯示用的廠商與產品略過沒有廠商的項目。
    assert r.vendor_product() == ("Red Hat", "Red Hat Enterprise Linux 6")
    # CPE 2.2 格式。
    assert ("redhat", "rhel_els") in r.affected[1].cpes


def test_cisa_adp_affected_and_cpe23() -> None:
    r = parse_record(fixture_record("CVE-2024-2467"))
    assert r.adp_affected[0].cpes == (("redhat", "openssl"),)


def test_cpe_escapes_are_decoded() -> None:
    r = parse_record(
        cve(
            "CVE-2026-90001",
            cpes=[
                r"cpe:2.3:a:lantern\:labs:lantern\\cms:*:*:*:*:*:*:*:*",
                "cpe:/a:harbor%3aprint:harbor%2bprint:2.0",
            ],
        )
    )
    assert r.affected[0].cpes == (
        ("lantern:labs", "lantern\\cms"),
        ("harbor:print", "harbor+print"),
    )


def test_less_than_or_equal_ranges() -> None:
    r = parse_record(fixture_record("CVE-2024-11079"))
    assert r.affected[0].versions == "≤ 2.18.0"


@pytest.mark.parametrize(
    "path", sorted((FIXTURES / "cvelist").glob("*.json")), ids=lambda p: p.stem
)
def test_json_round_trip(path: object) -> None:
    r = parse_record(json.loads(path.read_text()))  # type: ignore[attr-defined]
    assert record_from_json(json.loads(json.dumps(record_to_json(r)))) == r


def test_missing_optional_fields_do_not_fail() -> None:
    data = cve("CVE-2026-90001", title=None, cwe=None, score=None)
    del data["containers"]["cna"]["affected"]
    del data["containers"]["cna"]["references"]
    r = parse_record(data)
    assert r.affected == () and r.references == () and r.cwe == ()
    assert r.vendor_product() == ("", "")


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"cveMetadata": {"cveId": "nope", "state": "PUBLISHED"}},
        {"cveMetadata": {"cveId": "CVE-2026-90001", "state": "RESERVED"}},
        {"cveMetadata": {"cveId": "CVE-2026-90001", "state": "PUBLISHED"}, "containers": {}},
    ],
)
def test_invalid_records_raise(data: dict[str, object]) -> None:
    with pytest.raises(RecordError):
        parse_record(data)


def test_published_record_without_date_raises() -> None:
    data = cve("CVE-2026-90001")
    del data["cveMetadata"]["datePublished"]
    with pytest.raises(RecordError, match="datePublished"):
        parse_record(data)


def test_out_of_range_score_is_ignored() -> None:
    r = parse_record(cve("CVE-2026-90001", score=11.0, adp_score=6.1))
    assert r.cvss is not None and (r.cvss.score, r.cvss.source) == (6.1, "cisa-adp")


@pytest.mark.parametrize(
    ("score", "sev"),
    [
        (10.0, "critical"),
        (9.0, "critical"),
        (8.9, "high"),
        (7.0, "high"),
        (6.9, "medium"),
        (4.0, "medium"),
        (3.9, "low"),
        (0.1, "low"),
        (0.0, "none"),
        (None, "none"),
    ],
)
def test_severity_boundaries(score: float | None, sev: str) -> None:
    assert severity(score) == sev


def test_first_sentence() -> None:
    assert first_sentence("One thing.  Two things.") == "One thing."
    long = "x" * 200
    assert len(first_sentence(long)) == TITLE_MAX and first_sentence(long).endswith("…")
