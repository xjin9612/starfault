"""daily 的流程：CVE delta、EPSS、每日摘要（含技術棧段落）。

時區是 Asia/Taipei。NOW 是台灣 11-26 06:30，摘要處理的「昨天」是 11-25，
涵蓋 UTC 11-24 16:00 到 11-25 16:00。
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from starfault.state import State
from tests.builders import FIXTURES, SITE_URL, config_text, cve, epss_csv
from tests.conftest import Run
from tests.fakes import FakeSources

# 前一次 hourly：只讀到 R1 還沒有分數的版本。
EARLY = datetime(2026, 11, 25, 1, 0, tzinfo=UTC)
NOW = datetime(2026, 11, 25, 22, 30, tzinfo=UTC)
NEXT_DAY = datetime(2026, 11, 26, 22, 30, tzinfo=UTC)
WATCHLIST = FIXTURES / "watchlist.toml"

N1 = cve(
    "CVE-2026-91001",
    published="2026-11-25T02:00:00Z",
    score=9.8,
    title="Pellmar CivicForms hard-coded credentials",
)
N2 = cve(
    "CVE-2026-91002",
    published="2026-11-25T03:00:00Z",
    score=6.0,
    title="Nimbra agent authentication bypass",
)
N3 = cve(
    "CVE-2026-91003",
    published="2026-11-25T04:00:00Z",
    score=7.5,
    title="Memory corruption in replication",
    vendor="Quillstore",
    product="Quillstore",
    versions=[{"version": "7.0", "lessThan": "7.2.4", "status": "affected"}],
)
N4 = cve(
    "CVE-2026-91004",
    published="2026-11-25T05:00:00Z",
    score=5.0,
    vendor="Quillstore",
    product="Quillstore",
)
N5 = cve(
    "CVE-2026-91005",
    published="2026-11-25T06:00:00Z",
    score=None,
    title="Network component validation bypass",
    vendor="Tidewater",
    product="HPS",
    versions=[
        {"version": "4.2.0", "status": "affected"},
        {"version": "5.1.1", "status": "affected"},
    ],
)
N6 = cve(
    "CVE-2026-91006",
    published="2026-11-25T07:00:00Z",
    score=9.0,
    title="Acme cache flaw",
    vendor="Acme",
    product="Quillstore",
)
R1_OLD = cve(
    "CVE-2026-91007",
    published="2026-11-24T20:00:00Z",
    score=None,
    title="Management plugin path traversal",
    vendor="Gullwing Networks",
    product="Gullwing Router",
)
R1 = cve(
    "CVE-2026-91007",
    published="2026-11-24T20:00:00Z",
    updated="2026-11-25T10:00:00Z",
    score=None,
    adp_score=9.1,
    title="Management plugin path traversal",
    vendor="Gullwing Networks",
    product="Gullwing Router",
)


def _sources(fake: FakeSources) -> None:
    fake.eod[date(2026, 11, 24)] = [R1_OLD]
    fake.hourly[(date(2026, 11, 25), 0)] = [N1, N2, N3, N4, N5, N6]
    fake.hourly[(date(2026, 11, 25), 22)] = [N1, N2, N3, N4, N5, N6, R1]
    fake.eod[date(2026, 11, 25)] = [N1, N2, N3, N4, N5, N6, R1]
    fake.epss = epss_csv(
        {"CVE-2026-91002": (0.25, 0.97), "CVE-2026-91003": (0.004, 0.3)}, "2026-11-25"
    )
    for r in (N1, N2, N3, N4, N5, N6, R1):
        fake.records[r["cveMetadata"]["cveId"]] = r


def _daily(run: Run, now: datetime = NOW, **kw: Any) -> list[int]:
    if now == NOW:
        assert run("cve", now=EARLY, **kw) == 0
    return [
        run("cve", now=now, **kw),
        run("epss", now=now, **kw),
        run("digest", now=now, watchlist=WATCHLIST),
    ]


def test_cve_and_epss_update_state(run: Run, fake: FakeSources, workdir: Path) -> None:
    _sources(fake)
    # 第一次執行時從前一個 UTC 日的 end_of_day 開始讀。
    assert run("cve", now=EARLY) == 0
    assert run("cve", now=NOW) == 0
    state = State(workdir / "state")
    daily = state.load_daily(date(2026, 11, 25))
    assert set(daily.new) == {f"CVE-2026-9100{i}" for i in range(1, 8)}
    assert daily.new["CVE-2026-91007"].score == 9.1
    assert daily.rescored == {"CVE-2026-91007": (9.1, "critical")}
    # Critical 規則：發布 7 天內、CVSS ≥ 9。
    assert set(state.load_watch()) == {"CVE-2026-91001", "CVE-2026-91006", "CVE-2026-91007"}
    assert run("epss", now=NOW) == 0
    watch = state.load_watch()
    assert watch["CVE-2026-91002"].epss_cross == date(2026, 11, 25)
    assert state.load_daily(date(2026, 11, 25)).new["CVE-2026-91002"].cross == {
        "0.01": "2026-11-25",
        "0.05": "2026-11-25",
        "0.1": "2026-11-25",
        "0.2": "2026-11-25",
    }
    meta = state.load_epss_meta()
    assert meta is not None and meta.model == "v2026.06.15"


def test_digest_sections(run: Run, fake: FakeSources, telegram: None) -> None:
    _sources(fake)
    assert _daily(run) == [0, 0, 0]
    assert len(fake.sent) == 1
    msg = fake.sent[0]

    def link(cve_id: str) -> str:
        return f'<a href="{SITE_URL}#/cve/{cve_id}">{cve_id}</a>'

    assert msg.text.splitlines() == [
        "<b>starfault 每日摘要 2026-11-26</b>",
        "",
        "<b>你的技術棧（3）</b>",
        link("CVE-2026-91007") + "  Gullwing Router：Management plugin path traversal  9.1",
        "  受影響 &lt; 2.4.1・修補 2.4.1（分店路由器）",
        'CVE-2026-91003 <a href="https://www.cve.org/CVERecord?id=CVE-2026-91003">CVE.org</a>・'
        '<a href="https://nvd.nist.gov/vuln/detail/CVE-2026-91003">NVD</a>'
        "  Quillstore：Memory corruption in replication  7.5",
        "  受影響 7.0 – &lt; 7.2.4・修補 7.2.4（文件庫）",
        'CVE-2026-91005 <a href="https://www.cve.org/CVERecord?id=CVE-2026-91005">CVE.org</a>・'
        '<a href="https://nvd.nist.gov/vuln/detail/CVE-2026-91005">NVD</a>'
        "  Harbor Print：Network component validation bypass  未評分",
        "  受影響 4.2.0, 5.1.1・修補版本不明（辦公室印表機）",
        "",
        "<b>EPSS 跨過 10%（1）</b>",
        link("CVE-2026-91002") + "  Nimbra agent authentication bypass  25%",
        "",
        "<b>CVSS ≥ 9.0 且還沒有 EPSS（3）</b>",
        link("CVE-2026-91001") + "  Pellmar CivicForms hard-coded credentials  9.8",
        link("CVE-2026-91007") + "  Management plugin path traversal  9.1",
        link("CVE-2026-91006") + "  Acme cache flaw  9.0",
    ]
    # 有技術棧段落時有通知音。
    assert msg.silent is False
    assert msg.buttons == [{"text": "今日", "url": SITE_URL}]


def test_rerun_does_not_resend(run: Run, fake: FakeSources, telegram: None) -> None:
    _sources(fake)
    _daily(run)
    assert _daily(run) == [0, 0, 0]
    assert len(fake.sent) == 1


def test_digest_without_stack_is_silent(
    run: Run, fake: FakeSources, workdir: Path, telegram: None
) -> None:
    _sources(fake)
    run("cve", now=EARLY)
    run("cve", now=NOW)
    run("epss", now=NOW)
    assert run("digest", now=NOW, watchlist=workdir / "none.toml") == 0
    assert fake.sent[0].silent is True
    assert "你的技術棧" not in fake.sent[0].text


def test_missed_day_is_caught_up_once(
    run: Run, fake: FakeSources, workdir: Path, monkeypatch: pytest.MonkeyPatch, telegram: None
) -> None:
    _sources(fake)
    assert _daily(run) == [0, 0, 0]
    assert len(fake.sent) == 1
    # 11-26 發布的新 CVE；11-27 早上的執行沒有設定 Telegram，摘要略過、進度不前進。
    n7 = cve(
        "CVE-2026-91008",
        published="2026-11-26T03:00:00Z",
        score=8.0,
        title="Quillstore scripting sandbox escape",
        vendor="Quillstore",
        product="Quillstore",
    )
    fake.hourly[(NEXT_DAY.date(), 22)] = [n7]
    fake.eod[NEXT_DAY.date()] = [n7]
    fake.epss = epss_csv({"CVE-2026-91002": (0.25, 0.97)}, "2026-11-26")
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN")
    assert _daily(run, NEXT_DAY) == [0, 0, 0]
    assert len(fake.sent) == 1
    assert State(workdir / "state").load_digest_day() == date(2026, 11, 25)
    # 11-28 早上補上 11-26 與 11-27，已發過的 11-25 不再出現。
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    third = datetime(2026, 11, 27, 22, 30, tzinfo=UTC)
    fake.hourly[(third.date(), 22)] = []
    fake.epss = epss_csv({"CVE-2026-91002": (0.25, 0.97)}, "2026-11-27")
    assert _daily(run, third) == [0, 0, 0]
    text = fake.sent[1].text
    assert "<b>你的技術棧（1）</b>" in text and "CVE-2026-91008" in text
    assert "CVE-2026-91003" not in text
    assert State(workdir / "state").load_digest_day() == date(2026, 11, 27)
    assert _daily(run, third) == [0, 0, 0]
    assert len(fake.sent) == 2


def test_epss_drop_and_recross_is_not_resent(
    run: Run, fake: FakeSources, workdir: Path, telegram: None
) -> None:
    _sources(fake)
    _daily(run)
    later = [
        (NEXT_DAY, "2026-11-26", 0.05),
        (datetime(2026, 11, 27, 22, 30, tzinfo=UTC), "2026-11-27", 0.30),
    ]
    for now, day, score in later:
        fake.hourly[(now.date(), 22)] = []
        fake.epss = epss_csv({"CVE-2026-91002": (score, 0.9)}, day)
        assert _daily(run, now) == [0, 0, 0]
    # 跌回再跨過不算新的跨過：之後兩天都沒有內容，不發摘要。
    assert len(fake.sent) == 1
    assert State(workdir / "state").load_watch()["CVE-2026-91002"].epss_cross == date(2026, 11, 25)


def test_critical_rule_stops_once_epss_exists(run: Run, fake: FakeSources, telegram: None) -> None:
    _sources(fake)
    fake.epss = epss_csv({"CVE-2026-91001": (0.002, 0.1)}, "2026-11-25")
    _daily(run)
    assert "CVE-2026-91001" not in fake.sent[0].text


def test_failed_send_writes_nothing(
    run: Run, fake: FakeSources, workdir: Path, telegram: None
) -> None:
    _sources(fake)
    run("cve", now=EARLY)
    run("cve", now=NOW)
    run("epss", now=NOW)
    state = State(workdir / "state")
    # 發送當下還沒有寫入：job 在發送途中被終止時，下次整份重發。
    at_send: list[object] = []
    fake.on_telegram = lambda: at_send.append((state.load_notified(), state.load_digest_day()))
    fake.telegram_fail = True
    assert run("digest", now=NOW, watchlist=WATCHLIST) == 1
    assert state.load_notified() == {} and state.load_digest_day() is None
    fake.telegram_fail = False
    assert run("digest", now=NOW, watchlist=WATCHLIST) == 0
    assert "你的技術棧（3）" in fake.sent[0].text
    assert at_send and all(a == ({}, None) for a in at_send)
    assert state.load_digest_day() == date(2026, 11, 25)


def test_stack_records_failure_still_sends_public_sections(
    run: Run, fake: FakeSources, workdir: Path, telegram: None
) -> None:
    from starfault import cvelist

    _sources(fake)
    run("cve", now=EARLY)
    run("cve", now=NOW)
    run("epss", now=NOW)
    fake.status[cvelist.eod_url(date(2026, 11, 24))] = 500
    assert run("digest", now=NOW, watchlist=WATCHLIST) == 1
    text = fake.sent[0].text
    assert "<b>EPSS 跨過 10%（1）</b>" in text and "你的技術棧" not in text
    state = State(workdir / "state")
    assert state.load_digest_day() is None
    assert "epss" in state.load_notified()["CVE-2026-91002"]
    # 下一次重新處理技術棧段落，已發送的段落不重發。
    fake.status.clear()
    assert run("digest", now=NOW, watchlist=WATCHLIST) == 0
    assert "你的技術棧（3）" in fake.sent[1].text and "EPSS" not in fake.sent[1].text
    assert state.load_digest_day() == date(2026, 11, 25)


def test_thresholds_in_digest_follow_config(
    run: Run, fake: FakeSources, workdir: Path, telegram: None
) -> None:
    (workdir / "config.toml").write_text(config_text(thresholds__epss=0.2, thresholds__cvss=9.5))
    _sources(fake)
    _daily(run)
    text = fake.sent[0].text
    assert "<b>EPSS 跨過 20%（1）</b>" in text
    assert "<b>CVSS ≥ 9.5 且還沒有 EPSS（1）</b>" in text


def test_empty_digest_is_not_sent_but_progress_moves(
    run: Run, fake: FakeSources, workdir: Path, telegram: None
) -> None:
    fake.eod[date(2026, 11, 24)] = []
    fake.epss = epss_csv({"CVE-2026-99999": (0.5, 0.99)}, "2026-11-25")
    assert _daily(run) == [0, 0, 0]
    assert fake.sent == []
    assert State(workdir / "state").load_digest_day() == date(2026, 11, 25)


def test_stale_epss_is_noted(run: Run, fake: FakeSources, telegram: None) -> None:
    _sources(fake)
    fake.epss = epss_csv({"CVE-2026-91002": (0.25, 0.97)}, "2026-11-23")
    _daily(run)
    assert fake.sent[0].text.splitlines()[-1] == "EPSS 資料日期 2026-11-23，還沒有更新的分數。"


def test_epss_failure_fails_and_marks_source(run: Run, fake: FakeSources, workdir: Path) -> None:
    fake.epss = b"broken"
    assert run("epss", now=NOW) == 1
    assert State(workdir / "state").load_sources()["epss"]["ok"] is False


def test_cve_failure_fails_and_marks_source(run: Run, fake: FakeSources, workdir: Path) -> None:
    from starfault import cvelist

    fake.status[cvelist.eod_url(date(2026, 11, 24))] = 500
    assert run("cve", now=NOW) == 1
    assert State(workdir / "state").load_sources()["cve"]["ok"] is False


def test_english_digest(run: Run, fake: FakeSources, workdir: Path, telegram: None) -> None:
    (workdir / "config.toml").write_text(config_text(locale="en", target=""))
    _sources(fake)
    _daily(run)
    lines = fake.sent[0].text.splitlines()
    assert lines[0] == "<b>starfault daily digest 2026-11-26</b>"
    assert "<b>Your stack (3)</b>" in lines
    assert "  affected 4.2.0, 5.1.1 · fixed version unknown (辦公室印表機)" in lines


@pytest.mark.parametrize("days", ["0", "91", "-1"])
def test_backfill_days_out_of_range(run: Run, days: str) -> None:
    assert run("cve", "--backfill-days", days, now=NOW) == 2


def test_backfill_reads_past_days(run: Run, fake: FakeSources, workdir: Path) -> None:
    fake.eod[date(2026, 11, 22)] = [cve("CVE-2026-91100", published="2026-11-22T20:00:00Z")]
    fake.eod[date(2026, 11, 23)] = []
    fake.eod[date(2026, 11, 24)] = []
    assert run("cve", "--backfill-days", "3", now=NOW) == 0
    state = State(workdir / "state")
    # 第一個讀取的 UTC 日之後才是完整的日子；台灣 11-23 04:00 屬於 11-23。
    assert state.load_cvelist() == (date(2026, 11, 24), date(2026, 11, 23))
    assert "CVE-2026-91100" in state.load_daily(date(2026, 11, 23)).new
