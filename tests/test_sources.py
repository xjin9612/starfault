"""KEV、EPSS、cvelistV5 的讀取。fixtures 是真實資料的節錄。"""

from __future__ import annotations

import gzip
import json
import logging
from datetime import UTC, date, datetime

import httpx
import pytest

from starfault import cvelist, epss, kev
from starfault.epss import EpssFormatError
from starfault.http import FetchError, Http, NotFoundError
from starfault.kev import KevFormatError
from tests.builders import FIXTURES, cve, delta_zip, kev_feed, kev_item
from tests.fakes import FakeSources


def test_kev_real_feed_fields() -> None:
    catalog = kev.parse_catalog((FIXTURES / "kev" / "kev.json").read_bytes())
    assert catalog.version == "2026.11.25"
    e = catalog.entries["CVE-2026-103406"]
    assert e.added == date(2026, 11, 25) and e.due == date(2026, 11, 28)
    assert e.triage is True and e.ransomware is False
    assert e.cwes == ("CWE-78",)
    assert e.vendor == "Hewlett Packard Enterprise (HPE)"
    # BOD 26-04 以前列入的項目 forensicTriage 是 "No"。
    old = catalog.entries["CVE-2021-40539"]
    assert old.triage is False and old.ransomware is True
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-103406" in e.note_urls()


def test_kev_missing_triage_defaults_to_false_with_one_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    feed = kev_feed(
        [kev_item("CVE-2026-90001", triage=None), kev_item("CVE-2026-90002", triage=None)]
    )
    with caplog.at_level(logging.WARNING):
        catalog = kev.parse_catalog(feed)
    assert not catalog.entries["CVE-2026-90001"].triage
    assert [r.message for r in caplog.records] == [
        "KEV：2 筆沒有可辨識的 forensicTriage，當作不需鑑識"
    ]


def test_kev_boolean_triage_and_unknown_fields_are_accepted() -> None:
    item = kev_item("CVE-2026-90001", triage=True) | {"someNewField": 1}
    assert kev.parse_catalog(kev_feed([item])).entries["CVE-2026-90001"].triage


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("catalogVersion"),
        lambda d: d.pop("vulnerabilities"),
        lambda d: d["vulnerabilities"][0].pop("cveID"),
        lambda d: d["vulnerabilities"][0].pop("dateAdded"),
        lambda d: d["vulnerabilities"][0].update(dueDate="soon"),
    ],
)
def test_kev_missing_required_fields_raise(mutate: object) -> None:
    data = json.loads(kev_feed([kev_item("CVE-2026-90001")]))
    mutate(data)  # type: ignore[operator]
    with pytest.raises(KevFormatError):
        kev.parse_catalog(json.dumps(data).encode())


def test_kev_not_json_raises() -> None:
    with pytest.raises(KevFormatError):
        kev.parse_catalog(b"<html>maintenance</html>")


def test_epss_real_file_header_and_filter() -> None:
    raw = (FIXTURES / "epss" / "epss_scores-2026-11-25.csv.gz").read_bytes()
    data = epss.parse_csv(raw, {"CVE-2021-40539", "CVE-2014-3566"}.__contains__)
    assert data.model == "v2026.06.15"
    assert data.score_date == "2026-11-25T12:00:23Z"
    assert data.date == date(2026, 11, 25)
    assert data.scores == {"CVE-2021-40539": (0.9896, 0.9996), "CVE-2014-3566": (0.99999, 1.0)}


def test_epss_rows_outside_unit_range_are_skipped() -> None:
    raw = gzip.compress(
        b"#model_version:v1,score_date:2026-11-25T00:00:00Z\n"
        b"cve,epss,percentile\n"
        b"CVE-2026-90001,nan,0.5\n"
        b"CVE-2026-90002,inf,0.5\n"
        b"CVE-2026-90003,0.2,1.5\n"
        b"CVE-2026-90004,-0.1,0.5\n"
        b"CVE-2026-90005,0.2,0.7\n"
    )
    assert epss.parse_csv(raw).scores == {"CVE-2026-90005": (0.2, 0.7)}


@pytest.mark.parametrize(
    "raw",
    [
        b"not gzip",
        gzip.compress(b"cve,epss,percentile\nCVE-2026-90001,0.1,0.5\n"),
        gzip.compress(b"#model_version:v1,score_date:soon\ncve,epss,percentile\n"),
        gzip.compress(b"#model_version:v1,score_date:2026-11-25T00:00:00Z\ncve,score\n"),
        gzip.compress(b"#model_version:v1,score_date:2026-11-25T00:00:00Z\ncve,epss,percentile\n"),
    ],
)
def test_epss_bad_files_raise(raw: bytes) -> None:
    with pytest.raises(EpssFormatError):
        epss.parse_csv(raw)


def test_cvelist_zip_skips_invalid_records_and_counts_rejected() -> None:
    raw = delta_zip(
        [
            cve("CVE-2026-90001"),
            cve("CVE-2026-90002", state="REJECTED"),
            {"cveMetadata": {"cveId": "bad"}},
        ]
    )
    batch = cvelist.parse_zip(raw)
    assert set(batch.records) == {"CVE-2026-90001", "CVE-2026-90002"}
    assert batch.invalid == 1 and batch.rejected == 1


def test_cvelist_urls() -> None:
    assert cvelist.eod_url(date(2026, 11, 24)) == (
        "https://github.com/CVEProject/cvelistV5/releases/download/"
        "cve_2026-11-24_at_end_of_day/2026-11-24_delta_CVEs_at_end_of_day.zip"
    )
    assert cvelist.hourly_url(date(2026, 11, 25), 7).endswith(
        "cve_2026-11-25_0700Z/2026-11-25_delta_CVEs_at_0700Z.zip"
    )
    assert cvelist.record_url("CVE-2021-44228").endswith("/cves/2021/44xxx/CVE-2021-44228.json")
    assert cvelist.record_url("CVE-2002-0367").endswith("/cves/2002/0xxx/CVE-2002-0367.json")


def test_latest_hourly_walks_back_to_the_newest_release() -> None:
    day = date(2026, 11, 25)
    fake = FakeSources(hourly={(day, 5): [cve("CVE-2026-90001")]})
    with Http(transport=fake.transport()) as http:
        batch = cvelist.fetch_latest_hourly(http, datetime(2026, 11, 25, 7, 30, tzinfo=UTC))
    assert batch is not None and list(batch.records) == ["CVE-2026-90001"]
    assert [u.rsplit("_", 1)[1] for u in fake.requested] == ["0700Z.zip", "0600Z.zip", "0500Z.zip"]


def test_utc_days_use_end_of_day_then_latest_hourly() -> None:
    old = cve("CVE-2026-90001", score=5.0)
    newer = cve("CVE-2026-90001", score=9.1)
    fake = FakeSources(
        eod={date(2026, 11, 24): [old]},
        hourly={
            (date(2026, 11, 25), 1): [newer],
            (date(2026, 11, 23), 23): [cve("CVE-2026-90002")],
        },
    )
    now = datetime(2026, 11, 25, 2, tzinfo=UTC)
    with Http(transport=fake.transport()) as http:
        batch = cvelist.fetch_utc_days(
            http, [date(2026, 11, 25), date(2026, 11, 24), date(2026, 11, 23)], now
        )
    # 後讀到的版本取代先讀到的；end_of_day 還沒發布時改讀最後的 hourly。
    cvss = batch.records["CVE-2026-90001"].cvss
    assert cvss is not None and cvss.score == 9.1
    assert "CVE-2026-90002" in batch.records


def test_fetch_record_missing_returns_none() -> None:
    with Http(transport=FakeSources().transport()) as http:
        assert cvelist.fetch_record(http, "CVE-2026-90001") is None


def test_http_retries_server_errors_then_fails() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(503)

    sleeps: list[float] = []
    transport = httpx.MockTransport(handler)
    with (
        Http(transport=transport, sleep=sleeps.append) as http,
        pytest.raises(FetchError, match="503"),
    ):
        http.get("https://example.test/x")
    assert len(calls) == 3 and sleeps == [2, 4]


def test_http_not_found_is_not_retried() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(404)

    with Http(transport=httpx.MockTransport(handler)) as http, pytest.raises(NotFoundError):
        http.get("https://example.test/x")
    assert len(calls) == 1
