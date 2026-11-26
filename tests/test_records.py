"""CVE JSON 5 的解析。tests/fixtures/cvelist/ 是 cvelistV5 delta 的真實紀錄節錄。"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from starfault.records import (
    REFERENCES_MAX,
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
    r = parse_record(fixture_record("CVE-2026-131914"))
    assert r.affected[0].versions == "≤ 0.9.1.0, ≤ 0.9.1 Beta"


def test_real_version_ranges_and_fixed_versions() -> None:
    juniper = parse_record(fixture_record("CVE-2026-103406")).affected[0]
    assert juniper.versions == "< 7.0.5, 7.1.0 – < 7.1.7, 7.2.0 – < 7.2.3"
    assert juniper.fixed == "7.0.5, 7.1.7, 7.2.3"
    # 從某版起不受影響（lessThan "*"）與單一的不受影響版本，都列為修補版本。
    red_hat = parse_record(fixture_record("CVE-2023-5380")).affected[0]
    assert (red_hat.versions, red_hat.fixed) == ("", "0:1.8.0-26.el7_9")
    amd = parse_record(fixture_record("CVE-2025-61963")).affected[0]
    assert (amd.versions, amd.fixed) == ("", "GenoaPI 1.0.0.G")


def _versions(*versions: dict[str, Any]) -> tuple[str, str | None]:
    a = parse_record(cve("CVE-2026-90001", versions=versions)).affected[0]
    return a.versions, a.fixed


def test_open_ended_affected_range() -> None:
    assert _versions({"version": "2.0", "lessThan": "*", "status": "affected"}) == ("≥ 2.0", None)
    assert _versions({"version": "2.0", "lessThanOrEqual": "*", "status": "affected"}) == (
        "≥ 2.0",
        None,
    )


def test_unaffected_range_is_not_a_fixed_version() -> None:
    assert _versions(
        {"version": "3.0", "status": "affected"},
        {"version": "1.0", "lessThan": "2.0", "status": "unaffected"},
    ) == ("3.0", None)


def test_version_list_limits() -> None:
    many = [{"version": f"1.{i}", "status": "affected"} for i in range(6)]
    assert _versions(*many)[0] == "1.0, 1.1, 1.2, 1.3…"
    long = "pkg:generic/example@" + "1" * 30
    assert _versions({"version": long, "status": "affected"})[0] == ""


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
    assert first_sentence("Fixed in 1.2. A flaw (CVE-2026-1) exists.") == "Fixed in 1.2."
    assert (
        first_sentence("A flaw in Foo Inc. Widget (e.g. The admin panel) allows RCE. More.")
        == "A flaw in Foo Inc. Widget (e.g. The admin panel) allows RCE."
    )
    assert first_sentence("Upgrade to v2.1.3 or later. See notes.") == "Upgrade to v2.1.3 or later."
    assert first_sentence("Path traversal. sentence-case follows.") == (
        "Path traversal. sentence-case follows."
    )
    long = "x" * 200
    assert len(first_sentence(long)) == TITLE_MAX and first_sentence(long).endswith("…")


def _metrics(*items: tuple[str, float]) -> list[dict[str, object]]:
    return [{key: {"baseScore": score, "vectorString": "CVSS:x/AV:N"}} for key, score in items]


def test_cna_version_order_does_not_depend_on_list_order() -> None:
    data = cve("CVE-2026-90001", score=None)
    data["containers"]["cna"]["metrics"] = _metrics(("cvssV3_1", 7.5), ("cvssV4_0", 8.7))
    r = parse_record(data)
    assert r.cvss is not None and (r.cvss.version, r.cvss.score) == ("4.0", 8.7)


def test_cna_score_wins_over_cisa_adp() -> None:
    r = parse_record(cve("CVE-2026-90001", score=7.5, adp_score=9.9))
    assert r.cvss is not None and (r.cvss.score, r.cvss.source) == (7.5, "vendor")


def test_scores_from_other_adps_are_ignored() -> None:
    data = cve("CVE-2026-90001", score=None)
    data["containers"]["adp"] = [
        {"providerMetadata": {"shortName": "Other-ADP"}, "metrics": _metrics(("cvssV3_1", 9.1))}
    ]
    assert parse_record(data).cvss is None


def test_english_description_is_preferred() -> None:
    data = cve("CVE-2026-90001")
    data["containers"]["cna"]["descriptions"] = [
        {"lang": "es", "value": "Una falla."},
        {"lang": "en-US", "value": "A flaw."},
    ]
    assert parse_record(data).desc == "A flaw."
    data["containers"]["cna"]["descriptions"] = [{"lang": "es", "value": "Una falla."}]
    assert parse_record(data).desc == "Una falla."


def test_cna_title_wins_over_kev_name() -> None:
    r = parse_record(cve("CVE-2026-90001", title="CNA title"))
    assert r.display_title("KEV name") == "CNA title"


def test_references_keep_http_urls_only_and_are_capped() -> None:
    data = cve("CVE-2026-90001")
    refs = [{"url": "ftp://example.test/a"}, {"url": "javascript:alert(1)"}]
    refs += [{"url": f"https://example.test/{i}"} for i in range(REFERENCES_MAX + 5)]
    data["containers"]["cna"]["references"] = refs
    urls = [url for url, _ in parse_record(data).references]
    assert len(urls) == REFERENCES_MAX and all(u.startswith("https://") for u in urls)


def test_wildcard_cpe_product_is_dropped() -> None:
    r = parse_record(cve("CVE-2026-90001", cpes=["cpe:2.3:a:acme:*:*:*:*:*:*:*:*:*"]))
    assert r.affected[0].cpes == ()


def test_cwe_name_prefix_is_removed() -> None:
    data = cve("CVE-2026-90001")
    data["containers"]["cna"]["problemTypes"] = [
        {"descriptions": [{"cweId": "CWE-79", "description": "CWE-79: Cross-site Scripting"}]}
    ]
    assert parse_record(data).cwe == (("CWE-79", "Cross-site Scripting"),)


def test_time_without_zone_is_utc() -> None:
    r = parse_record(cve("CVE-2026-90001", published="2026-11-24T03:00:00"))
    assert r.published == datetime(2026, 11, 24, 3, tzinfo=UTC)
