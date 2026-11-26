"""狀態更新的細節：保留期間、REJECTED、EPSS 取不到紀錄時延後。"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

from starfault.epss import EpssData
from starfault.http import Http
from starfault.kev import parse_catalog
from starfault.records import parse_record
from starfault.state import Row, State, Watch
from starfault.track import (
    apply_epss,
    apply_records,
    fill_records,
    prune,
    update_kev,
)
from tests.builders import cve, kev_feed, kev_item, make_config
from tests.fakes import FakeSources

CFG = make_config()
TODAY = date(2026, 11, 26)
SINCE = date(2026, 11, 1)


def test_critical_window_boundaries(tmp_path: Path) -> None:
    state = State(tmp_path)
    records = [
        parse_record(
            cve("CVE-2026-94001", published="2026-11-19T17:00:00Z", score=9.0)
        ),  # 台灣 11-20，第 7 天
        parse_record(
            cve("CVE-2026-94002", published="2026-11-19T15:00:00Z", score=9.9)
        ),  # 台灣 11-19，第 8 天
        parse_record(cve("CVE-2026-94003", published="2026-11-25T00:00:00Z", score=8.9)),
    ]
    apply_records(state, records, CFG, TODAY, set(), SINCE)
    assert set(state.load_watch()) == {"CVE-2026-94001"}
    assert state.load_watch()["CVE-2026-94001"].critical == TODAY


def test_rejected_record_is_removed(tmp_path: Path) -> None:
    state = State(tmp_path)
    apply_records(
        state,
        [parse_record(cve("CVE-2026-94001", published="2026-11-25T00:00:00Z", score=9.8))],
        CFG,
        TODAY,
        set(),
        SINCE,
    )
    rejected = parse_record(cve("CVE-2026-94001", state="REJECTED"))
    result = apply_records(state, [rejected], CFG, TODAY, set(), SINCE)
    assert result.rejected == 1
    assert state.load_watch() == {}
    assert state.load_daily(date(2026, 11, 25)).new == {}


def test_rejected_record_is_removed_from_rescored(tmp_path: Path) -> None:
    state = State(tmp_path)
    pub = "2026-11-24T00:00:00Z"
    for score in (None, 9.8):
        record = parse_record(cve("CVE-2026-94001", published=pub, updated=pub, score=score))
        apply_records(state, [record], CFG, TODAY, set(), SINCE)
    assert state.load_daily(date(2026, 11, 24)).rescored
    apply_records(
        state, [parse_record(cve("CVE-2026-94001", state="REJECTED"))], CFG, TODAY, set(), SINCE
    )
    assert state.load_daily(date(2026, 11, 24)).to_json()["rescored"] == []


def test_changed_publish_date_moves_the_row(tmp_path: Path) -> None:
    state = State(tmp_path)
    first = parse_record(cve("CVE-2026-94001", published="2026-11-23T00:00:00Z"))
    apply_records(state, [first], CFG, TODAY, set(), SINCE)
    moved = parse_record(cve("CVE-2026-94001", published="2026-11-25T00:00:00Z", score=8.0))
    result = apply_records(state, [moved], CFG, TODAY, set(), SINCE)
    assert result.new == 0
    assert state.load_daily(date(2026, 11, 23)).new == {}
    assert state.load_daily(date(2026, 11, 25)).new == {"CVE-2026-94001": Row(8.0, "high")}
    # 搬到 since 之前的日子時只移除。
    early = parse_record(cve("CVE-2026-94001", published="2026-10-01T00:00:00Z"))
    apply_records(state, [early], CFG, TODAY, set(), SINCE)
    assert state.load_daily(date(2026, 11, 25)).new == {}


def test_late_rows_are_an_epss_baseline(tmp_path: Path) -> None:
    """晚於隔天才寫入的列，第一次 EPSS 只記錄，不算首次跨過。"""
    state = State(tmp_path)
    late = cve("CVE-2026-94001", published="2026-11-20T00:00:00Z", score=5.0)
    fresh = cve("CVE-2026-94002", published="2026-11-25T00:00:00Z", score=5.0)
    apply_records(state, [parse_record(late), parse_record(fresh)], CFG, TODAY, set(), SINCE)
    assert state.load_daily(date(2026, 11, 20)).baseline == {"CVE-2026-94001"}
    assert state.load_daily(date(2026, 11, 25)).baseline == set()
    data = EpssData(
        "v1", "2026-11-25T12:00:00Z", {"CVE-2026-94001": (0.3, 0.9), "CVE-2026-94002": (0.3, 0.9)}
    )
    fake = FakeSources(records={"CVE-2026-94001": late, "CVE-2026-94002": fresh})
    with Http(transport=fake.transport()) as http:
        apply_epss(state, http, data, CFG, TODAY, set())
    # 兩筆都進關注清單；舊的那筆記為已通知，不進每日摘要，也不算進門檻校準。
    watch = state.load_watch()
    assert watch["CVE-2026-94001"].epss_cross == watch["CVE-2026-94002"].epss_cross
    assert set(state.load_notified()) == {"CVE-2026-94001"}
    old_row = state.load_daily(date(2026, 11, 20)).new["CVE-2026-94001"]
    assert set(old_row.cross.values()) == {""}
    assert state.load_daily(date(2026, 11, 20)).baseline == set()
    assert set(state.load_daily(date(2026, 11, 25)).new["CVE-2026-94002"].cross.values()) == {
        "2026-11-25"
    }


def test_days_before_since_are_not_recorded(tmp_path: Path) -> None:
    state = State(tmp_path)
    old = parse_record(cve("CVE-2026-94001", published="2026-10-20T00:00:00Z"))
    apply_records(state, [old], CFG, TODAY, set(), SINCE)
    assert state.daily_days() == []


def test_rescored_is_recorded_once(tmp_path: Path) -> None:
    state = State(tmp_path)
    pub = "2026-11-24T00:00:00Z"
    apply_records(
        state,
        [parse_record(cve("CVE-2026-94001", published=pub, score=None))],
        CFG,
        TODAY,
        set(),
        SINCE,
    )
    scored = parse_record(
        cve(
            "CVE-2026-94001",
            published=pub,
            updated="2026-11-25T02:00:00Z",
            score=None,
            adp_score=7.1,
        )
    )
    apply_records(state, [scored], CFG, TODAY, set(), SINCE)
    changed = parse_record(
        cve("CVE-2026-94001", published=pub, updated="2026-11-26T02:00:00Z", score=8.0)
    )
    apply_records(state, [changed], CFG, TODAY, set(), SINCE)
    assert state.load_daily(date(2026, 11, 25)).rescored == {"CVE-2026-94001": (7.1, "high")}
    assert state.load_daily(date(2026, 11, 26)).rescored == {}
    assert state.load_daily(date(2026, 11, 24)).new["CVE-2026-94001"] == Row(8.0, "high")


def test_prune_keeps_kev_and_recent_events(tmp_path: Path) -> None:
    state = State(tmp_path)
    old = date(2026, 8, 1)
    for cve_id in ("CVE-2026-94001", "CVE-2026-94002", "CVE-2026-94003"):
        state.save_watch(
            Watch(parse_record(cve(cve_id, published="2026-07-01T00:00:00Z")), critical=old)
        )
    w = state.load_watch()["CVE-2026-94003"]
    w.epss_cross = TODAY - timedelta(days=90)
    state.save_watch(w)
    w = Watch(parse_record(cve("CVE-2026-94004", published="2026-07-01T00:00:00Z")))
    w.epss_cross = TODAY - timedelta(days=91)
    state.save_watch(w)
    state.save_daily(state.load_daily(TODAY - timedelta(days=90)))
    state.save_daily(state.load_daily(TODAY - timedelta(days=89)))
    removed = prune(state, CFG, TODAY, {"CVE-2026-94002"})
    assert removed == 2
    assert set(state.load_watch()) == {"CVE-2026-94002", "CVE-2026-94003"}
    assert state.daily_days() == [TODAY - timedelta(days=89)]


def test_prune_epss_keeps_thirty_days(tmp_path: Path) -> None:
    state = State(tmp_path)
    for age in (29, 30):
        state.save_epss_day(TODAY - timedelta(days=age), {"CVE-2026-94001": (0.1, 0.5)})
    state.prune_epss(TODAY)
    assert state.epss_days() == [TODAY - timedelta(days=29)]


def test_kev_update_detects_new_and_removed(tmp_path: Path) -> None:
    state = State(tmp_path)
    a, b = kev_item("CVE-2026-94001"), kev_item("CVE-2026-94002", added="2026-11-25")
    assert update_kev(state, parse_catalog(kev_feed([a])), TODAY).baseline
    update = update_kev(state, parse_catalog(kev_feed([a, b], "2026.11.25")), TODAY)
    assert update.new == ["CVE-2026-94002"] and update.changed
    # CISA 移除的項目不再推播。
    update = update_kev(state, parse_catalog(kev_feed([a], "2026.11.26")), TODAY)
    assert update.kev.pending == {}
    unchanged = update_kev(state, parse_catalog(kev_feed([a], "2026.11.26")), TODAY)
    assert not unchanged.changed


def test_fill_records_respects_budget_and_stops_on_failures(tmp_path: Path) -> None:
    state = State(tmp_path)
    fake = FakeSources(records={f"CVE-2026-9400{i}": cve(f"CVE-2026-9400{i}") for i in range(5)})
    with Http(transport=fake.transport()) as http:
        assert fill_records(
            state, http, [f"CVE-2026-9400{i}" for i in range(5)], CFG, TODAY, 3
        ) == (3, 0)
    ids = ["CVE-2026-94100", "CVE-2026-94101", "CVE-2026-94102", "CVE-2026-94103"]
    from starfault import cvelist

    fake.status = {cvelist.record_url(i): 500 for i in ids}
    with Http(transport=fake.transport(), sleep=lambda _: None) as http:
        assert fill_records(state, http, ids, CFG, TODAY, 10) == (0, 3)


def test_fill_records_counts_missing_records_and_skips_bad_ones(tmp_path: Path) -> None:
    state = State(tmp_path)
    fake = FakeSources()
    with Http(transport=fake.transport()) as http:
        assert fill_records(
            state, http, [f"CVE-2026-9410{i}" for i in range(5)], CFG, TODAY, 2
        ) == (
            0,
            0,
        )
    assert len(fake.requested) == 2
    # 格式錯誤的紀錄是個別問題，不會讓後面的紀錄停止抓取。
    bad = {f"CVE-2026-9420{i}": cve(f"CVE-2026-9420{i}", state="RESERVED") for i in range(4)}
    fake = FakeSources(records=bad | {"CVE-2026-94210": cve("CVE-2026-94210")})
    with Http(transport=fake.transport()) as http:
        assert fill_records(state, http, [*bad, "CVE-2026-94210"], CFG, TODAY, 10) == (1, 4)


def test_epss_cross_is_deferred_when_record_is_missing(tmp_path: Path) -> None:
    state = State(tmp_path)
    apply_records(
        state,
        [parse_record(cve("CVE-2026-94001", published="2026-11-25T00:00:00Z", score=5.0))],
        CFG,
        TODAY,
        set(),
        SINCE,
    )
    data = EpssData("v1", "2026-11-25T12:00:00Z", {"CVE-2026-94001": (0.3, 0.99)})
    fake = FakeSources()
    with Http(transport=fake.transport()) as http:
        result = apply_epss(state, http, data, CFG, TODAY, set())
    assert result.crossed == [] and result.deferred == 1
    fake.records["CVE-2026-94001"] = cve(
        "CVE-2026-94001", published="2026-11-25T00:00:00Z", score=5.0
    )
    with Http(transport=fake.transport()) as http:
        result = apply_epss(state, http, data, CFG, TODAY, set())
    assert result.crossed == ["CVE-2026-94001"]


def test_epss_window_boundary(tmp_path: Path) -> None:
    state = State(tmp_path)
    # EPSS 日期 11-25，30 天內是台灣 10-27 到 11-25。
    for cve_id, pub in [
        ("CVE-2026-94001", "2026-10-26T16:00:00Z"),
        ("CVE-2026-94002", "2026-10-26T15:59:00Z"),
    ]:
        record = parse_record(cve(cve_id, published=pub, score=5.0))
        apply_records(state, [record], CFG, date(2026, 10, 27), set(), date(2026, 10, 1))
    data = EpssData(
        "v1", "2026-11-25T12:00:00Z", {"CVE-2026-94001": (0.1, 0.9), "CVE-2026-94002": (0.5, 0.99)}
    )
    fake = FakeSources(
        records={
            "CVE-2026-94001": cve("CVE-2026-94001", published="2026-10-26T16:00:00Z", score=5.0),
            "CVE-2026-94002": cve("CVE-2026-94002", published="2026-10-26T15:59:00Z", score=5.0),
        }
    )
    with Http(transport=fake.transport()) as http:
        result = apply_epss(state, http, data, CFG, TODAY, set())
    # 門檻含等號；發布超過 epss_window_days 天的不看。
    assert result.crossed == ["CVE-2026-94001"]
