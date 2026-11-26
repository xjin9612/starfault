"""網站產生器：data/*.json 的形狀與內容、index.html 的填入。"""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from starfault import translate
from starfault.records import parse_record
from starfault.site_page import detect_repo, fill_index
from starfault.state import Daily, Row, State, Watch
from tests.builders import (
    REPO_ROOT,
    SITE_URL,
    config_text,
    cve,
    epss_csv,
    kev_feed,
    kev_item,
    make_config,
)
from tests.conftest import Run
from tests.fakes import FakeSources

EARLY = datetime(2026, 11, 25, 1, 0, tzinfo=UTC)
NOW = datetime(2026, 11, 25, 22, 30, tzinfo=UTC)

CRIT = cve(
    "CVE-2026-93001",
    published="2026-11-25T02:00:00Z",
    score=9.8,
    version="4.0",
    title="Critical one",
)
HOT = cve("CVE-2026-93002", published="2026-11-25T03:00:00Z", score=None, title="Hot one")
PLAIN = cve("CVE-2026-93003", published="2026-11-25T04:00:00Z", score=5.0)
KEV_OLD = kev_item(
    "CVE-2020-0001", added="2021-11-03", due="2021-11-17", triage="No", ransomware="Known"
)
KEV_NEW = kev_item("CVE-2026-93004", added="2026-11-25", due="2026-11-28")


def _build(run: Run, fake: FakeSources, workdir: Path) -> Path:
    fake.kev = kev_feed([KEV_OLD], "2026.11.24")
    fake.records["CVE-2026-93004"] = cve(
        "CVE-2026-93004", published="2026-11-20T00:00:00Z", score=8.1
    )
    fake.eod[date(2026, 11, 24)] = []
    for r in (CRIT, HOT, PLAIN):
        fake.records[r["cveMetadata"]["cveId"]] = r
    fake.hourly[(date(2026, 11, 25), 0)] = [CRIT, HOT, PLAIN]
    fake.hourly[(date(2026, 11, 25), 22)] = [CRIT, HOT, PLAIN]
    fake.epss = epss_csv(
        {
            "CVE-2026-93002": (0.42, 0.98),
            "CVE-2026-93004": (0.9, 0.99999),
            "CVE-2020-0001": (0.5, 0.99),
        },
        "2026-11-25",
    )
    assert run("kev", now=EARLY) == 0
    assert run("cve", now=EARLY) == 0
    fake.kev = kev_feed([KEV_OLD, KEV_NEW], "2026.11.25")
    assert run("kev", now=NOW) == 0
    assert run("cve", now=NOW) == 0
    assert run("epss", now=NOW) == 0
    out = workdir / "site"
    assert run("site", "--out", str(out), "--web", "web", "--assets", "assets", now=NOW) == 0
    return out


def _load(out: Path, name: str) -> Any:
    return json.loads((out / "data" / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture
def site(run: Run, fake: FakeSources, workdir: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    return _build(run, fake, workdir)


def test_meta(site: Path) -> None:
    meta = _load(site, "meta")
    assert meta["today"] == "2026-11-26"
    assert meta["timezone"] == "Asia/Taipei" and meta["locale"] == "zh-TW"
    assert meta["translation"] == "zh-TW"
    assert meta["thresholds"] == {
        "epss": 0.1,
        "cvss": 9.0,
        "epss_window_days": 30,
        "stack_cvss": 7.0,
        "calibrating_until": "2026-12-02",
    }
    assert meta["sources"]["kev"] | {"at": None} == {
        "at": None,
        "ok": True,
        "version": "2026.11.25",
        "count": 2,
    }
    assert meta["sources"]["epss"]["date"] == "2026-11-25"
    assert "counts" not in meta


def test_cves_items(site: Path) -> None:
    items = {i["id"]: i for i in _load(site, "cves")["items"]}
    # 只收錄符合規則的 CVE；KEV_OLD 列入超過 90 天，只在 KEV 頁。
    assert set(items) == {"CVE-2026-93001", "CVE-2026-93002", "CVE-2026-93004"}
    crit = items["CVE-2026-93001"]
    assert set(crit) == {
        "id",
        "title",
        "vendor",
        "product",
        "published",
        "cvss",
        "epss",
        "epss_cross",
        "kev",
        "reasons",
    }
    assert crit["cvss"] == {"score": 9.8, "version": "4.0", "sev": "critical", "source": "vendor"}
    assert crit["reasons"] == ["critical"] and crit["epss"] is None
    hot = items["CVE-2026-93002"]
    assert hot["reasons"] == ["epss"] and hot["epss_cross"] == "2026-11-25"
    assert hot["epss"] == {"s": 0.42, "p": 0.98, "date": "2026-11-25"} and hot["cvss"] is None
    kev = items["CVE-2026-93004"]
    assert kev["kev"] == {
        "added": "2026-11-25",
        "due": "2026-11-28",
        "ransomware": False,
        "triage": True,
    }
    # 發布日早於開始收集的日子，不在 EPSS 規則的候選裡。
    assert kev["reasons"] == ["kev"]


def test_kev_items_newest_first(site: Path) -> None:
    items = _load(site, "kev")["items"]
    assert [i["id"] for i in items] == ["CVE-2026-93004", "CVE-2020-0001"]
    assert set(items[0]) == {
        "id",
        "title",
        "vendor",
        "product",
        "cvss",
        "epss",
        "added",
        "due",
        "ransomware",
        "triage",
    }
    assert items[1]["ransomware"] is True and items[1]["triage"] is False


def test_detail_files(site: Path) -> None:
    files = {p.stem for p in (site / "data" / "cve").glob("*.json")}
    assert files == {"CVE-2026-93001", "CVE-2026-93002", "CVE-2026-93004", "CVE-2020-0001"}
    d = _load(site, "cve/CVE-2026-93004")
    assert set(d) == {
        "id",
        "desc",
        "cvss",
        "cwe",
        "affected",
        "references",
        "epss_hist",
        "kev",
        "timeline",
    }
    assert d["cvss"]["vector"].startswith("CVSS:3.1/")
    assert d["kev"]["action"] == "Apply mitigations per vendor instructions."
    assert d["references"][-1] == {
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "tags": ["kev"],
    }
    assert d["epss_hist"] == [{"d": "2026-11-25", "s": 0.9, "p": 0.99999}]
    # 發布日早於保存的 EPSS 第一天，不知道第一次有分數的日子。
    assert [e["type"] for e in d["timeline"]] == ["published", "kev"]
    # 因 EPSS 跨過才開始保存分數，不知道更早有沒有分數。
    hot = _load(site, "cve/CVE-2026-93002")
    assert [e["type"] for e in hot["timeline"]] == ["published", "epss_cross"]
    # 沒有完整紀錄的 KEV：用 KEV 目錄的內容。
    old = _load(site, "cve/CVE-2020-0001")
    assert old["desc"] == "Halden Networks EdgeGate VPN contains a vulnerability."
    assert old["affected"] == [
        {"vendor": "Halden Networks", "product": "EdgeGate VPN", "versions": "", "fixed": None}
    ]
    assert old["cwe"] == [{"id": "CWE-287", "name": ""}]
    assert old["references"][0] == {"url": "https://example.com/CVE-2020-0001", "tags": []}


def test_daily_and_stats(site: Path) -> None:
    days = _load(site, "daily")["days"]
    assert days == [
        {
            "date": "2026-11-25",
            "total": 3,
            "sev": {"critical": 1, "high": 0, "medium": 1, "low": 0, "none": 1},
        },
        {
            "date": "2026-11-26",
            "total": 0,
            "sev": {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0},
        },
    ]
    stats = _load(site, "stats")
    assert stats["window"] == {"from": "2026-11-19", "to": "2026-11-25", "days": 1, "new_cves": 3}
    assert {x["t"]: x["per_day"] for x in stats["epss"]} == {
        0.01: 1.0,
        0.05: 1.0,
        0.1: 1.0,
        0.2: 1.0,
        0.5: 0.0,
    }
    assert {x["t"]: x["per_day"] for x in stats["cvss"]} == {9.0: 1.0, 9.5: 1.0, 10.0: 0.0}
    assert stats["kev_per_day"] == 0.1


def test_index_html_is_filled(site: Path) -> None:
    html = (site / "index.html").read_text(encoding="utf-8")
    assert '<html lang="zh-Hant">' in html
    assert f'<meta property="og:url" content="{SITE_URL}">' in html
    assert "<!-- site:meta -->" not in html
    assert "site:repo-link" not in html
    assert (site / "icon.svg").is_file() and (site / "social-preview.png").is_file()


def test_fill_index_repo_link() -> None:
    text = (REPO_ROOT / "web" / "index.html").read_text(encoding="utf-8")
    cfg = make_config()
    linked = fill_index(text, cfg, "owner/name")
    assert 'href="https://github.com/owner/name"' in linked and ">owner/name<" in linked
    assert "site:repo-link" not in linked and "__REPO" not in linked
    plain = fill_index(text, cfg, None)
    assert "github.com" not in plain and "site:repo-link" not in plain and "__REPO" not in plain


def test_detect_repo(tmp_path: Path) -> None:
    assert detect_repo({"GITHUB_REPOSITORY": "owner/name"}, tmp_path) == "owner/name"
    assert detect_repo({"GITHUB_REPOSITORY": "not a repo"}, tmp_path) is None
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for remote, repo in [
        ("git@github.com:owner/name.git", "owner/name"),
        ("https://github.com/owner/name", "owner/name"),
        ("https://gitlab.example/owner/name.git", None),
    ]:
        subprocess.run(["git", "-C", str(tmp_path), "remote", "remove", "origin"], check=False)
        subprocess.run(["git", "-C", str(tmp_path), "remote", "add", "origin", remote], check=True)
        assert detect_repo({}, tmp_path) == repo, remote


SITE_TODAY = date(2026, 11, 26)


def _days_ago(n: int) -> date:
    return SITE_TODAY - timedelta(days=n)


def _site_from_state(run: Run, workdir: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    out = workdir / "site"
    assert run("site", "--out", str(out), "--web", "web", "--assets", "assets", now=NOW) == 0
    return out


def test_window_boundaries(run: Run, workdir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = State(workdir / "state")
    old = "2026-07-01T00:00:00Z"
    for cve_id, cross in [
        ("CVE-2026-93101", _days_ago(89)),
        ("CVE-2026-93102", _days_ago(90)),
        ("CVE-2026-93103", _days_ago(6)),
        ("CVE-2026-93104", _days_ago(7)),
    ]:
        state.save_watch(Watch(parse_record(cve(cve_id, published=old)), epss_cross=cross))
    for age in (30, 29):
        state.save_daily(Daily(_days_ago(age)))
    site = _site_from_state(run, workdir, monkeypatch)
    # 關注 CVE 收錄最後事件在近 90 天內的；圖表 30 天含今天。
    ids = {i["id"] for i in _load(site, "cves")["items"]}
    assert ids == {"CVE-2026-93101", "CVE-2026-93103", "CVE-2026-93104"}
    days = _load(site, "daily")["days"]
    assert days[0]["date"] == _days_ago(29).isoformat() and len(days) == 30


def test_rescored_cves_count_once_in_calibration(
    run: Run, workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = State(workdir / "state")
    # 11-20 發布時沒有分數，11-22 補上 9.8：只算在 11-22。
    state.save_daily(Daily(_days_ago(6), new={"CVE-2026-93201": Row(9.8, "critical")}))
    state.save_daily(Daily(_days_ago(4), rescored={"CVE-2026-93201": (9.8, "critical")}))
    stats = _load(_site_from_state(run, workdir, monkeypatch), "stats")
    assert stats["window"]["days"] == 2
    assert {x["t"]: x["per_day"] for x in stats["cvss"]}[9.0] == 0.5


def test_first_epss_after_tracking_starts(
    run: Run, fake: FakeSources, workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Critical 規則先開始保存分數，之後第一次出現的分數才是第一次有 EPSS。"""
    state = State(workdir / "state")
    record = parse_record(cve("CVE-2026-93301", published="2026-11-24T02:00:00Z", score=9.8))
    state.save_watch(Watch(record, critical=date(2026, 11, 24)))
    state.save_epss_day(date(2026, 11, 24), {})
    state.save_epss_day(date(2026, 11, 25), {"CVE-2026-93301": (0.02, 0.5)})
    detail = _load(_site_from_state(run, workdir, monkeypatch), "cve/CVE-2026-93301")
    assert {"date": "2026-11-25", "type": "epss_first"} in detail["timeline"]


def test_translations_add_tr_fields(
    run: Run, fake: FakeSources, workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    state = State(workdir / "state")
    translate.save(state.root, "zh-TW", {translate.text_key("Critical one"): "嚴重的那個"})
    translate.save(state.root, "ja", {translate.text_key("Hot one"): "ホット"})
    site = _build(run, fake, workdir)
    items = {i["id"]: i for i in _load(site, "cves")["items"]}
    assert items["CVE-2026-93001"]["title_tr"] == "嚴重的那個"
    assert "title_tr" not in items["CVE-2026-93002"]
    (workdir / "config.toml").write_text(config_text(target=""))
    assert run("site", "--out", str(site), "--web", "web", "--assets", "assets", now=NOW) == 0
    assert "title_tr" not in json.dumps(_load(site, "cves"))
