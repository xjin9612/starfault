"""hourly 的 KEV 流程：快照、待推播、即時推播。"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from starfault import kev as kev_source
from starfault.state import State
from tests.builders import FIXTURES, SITE_URL, config_text, cve, kev_feed, kev_item
from tests.conftest import Run
from tests.fakes import FakeSources

NOW = datetime(2026, 11, 25, 1, 30, tzinfo=UTC)
A = kev_item("CVE-2026-90001", added="2026-11-20", due="2026-11-23")
B = kev_item("CVE-2026-90002", added="2026-11-21", due="2026-12-05", triage="No")
C = kev_item(
    "CVE-2026-90003",
    added="2026-11-25",
    due="2026-11-28",
    ransomware="Known",
    vendor="Sorell",
    product="Sorell Hypervisor",
    name="Sorell Hypervisor Server-Side Request Forgery Vulnerability",
)


def _setup(fake: FakeSources) -> None:
    fake.kev = kev_feed([A, B], version="2026.11.24")
    for item in (A, B, C):
        fake.records[item["cveID"]] = cve(item["cveID"], score=8.6, title=None)


def _add_c(fake: FakeSources) -> None:
    fake.kev = kev_feed([A, B, C], version="2026.11.25")


def _state(workdir: Path) -> State:
    return State(workdir / "state")


def test_first_run_is_a_baseline_without_alerts(
    run: Run, fake: FakeSources, workdir: Path, telegram: None
) -> None:
    _setup(fake)
    assert run("kev", now=NOW) == 0
    assert run("push", now=NOW) == 0
    assert fake.sent == []
    kev = _state(workdir).load_kev()
    assert kev is not None and set(kev.entries) == {"CVE-2026-90001", "CVE-2026-90002"}
    assert kev.pending == {}
    # KEV 的完整紀錄一併抓取，給詳細頁用。
    assert set(_state(workdir).load_watch()) == {"CVE-2026-90001", "CVE-2026-90002"}


def test_new_kev_is_alerted_once(
    run: Run, fake: FakeSources, workdir: Path, telegram: None
) -> None:
    _setup(fake)
    run("kev", now=NOW)
    _add_c(fake)
    assert run("kev", now=NOW) == 0
    assert run("push", now=NOW) == 0
    assert len(fake.sent) == 1
    msg = fake.sent[0]
    assert msg.silent is False
    assert msg.text.splitlines() == [
        "<b>KEV 新增：CVE-2026-90003</b>",
        "Sorell Hypervisor Server-Side Request Forgery Vulnerability",
        "CVSS 8.6（High）・尚無 EPSS",
        "期限 2026-11-28（3 天）・需鑑識・勒索軟體",
    ]
    assert msg.buttons == [
        {"text": "詳細頁", "url": f"{SITE_URL}#/cve/CVE-2026-90003"},
        {"text": "CISA KEV", "url": kev_source.CATALOG_URL},
    ]
    assert msg.thread is None
    # 同一次的資料重跑兩個指令都不會再發。
    assert run("kev", now=NOW) == 0
    assert run("push", now=NOW) == 0
    assert len(fake.sent) == 1
    notified = _state(workdir).load_notified()
    assert list(notified) == ["CVE-2026-90003"] and "kev" in notified["CVE-2026-90003"]


def test_workflow_rerun_from_older_checkout_does_not_resend(
    run: Run, fake: FakeSources, workdir: Path, telegram: None
) -> None:
    """重跑時快照還是舊的（例如 commit 失敗），已通知清單仍擋下重複發送。"""
    _setup(fake)
    run("kev", now=NOW)
    old_kev = (workdir / "state" / "kev.json").read_text()
    _add_c(fake)
    run("kev", now=NOW)
    run("push", now=NOW)
    (workdir / "state" / "kev.json").write_text(old_kev)
    run("kev", now=NOW)
    run("push", now=NOW)
    assert len(fake.sent) == 1


def test_without_telegram_alerts_are_kept_for_later(
    run: Run, fake: FakeSources, workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup(fake)
    run("kev", now=NOW)
    _add_c(fake)
    run("kev", now=NOW)
    assert run("push", now=NOW) == 0
    assert fake.sent == []
    kev = _state(workdir).load_kev()
    assert kev is not None and list(kev.pending) == ["CVE-2026-90003"]
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "1")
    assert run("push", now=NOW) == 0
    assert len(fake.sent) == 1


def test_send_failure_keeps_the_alert_pending(
    run: Run, fake: FakeSources, workdir: Path, telegram: None
) -> None:
    _setup(fake)
    run("kev", now=NOW)
    _add_c(fake)
    run("kev", now=NOW)
    # 發送當下還沒有記為已通知：job 在發送途中被終止時，下次照樣重發。
    at_send: list[object] = []
    fake.on_telegram = lambda: at_send.append(_state(workdir).load_notified())
    fake.telegram_fail = True
    assert run("push", now=NOW) == 1
    assert _state(workdir).load_notified() == {}
    kev = _state(workdir).load_kev()
    assert kev is not None and list(kev.pending) == ["CVE-2026-90003"]
    fake.telegram_fail = False
    assert run("push", now=NOW) == 0
    assert len(fake.sent) == 1
    assert at_send and all(n == {} for n in at_send)
    assert "kev" in _state(workdir).load_notified()["CVE-2026-90003"]


def test_pending_alerts_expire_after_a_week(
    run: Run, fake: FakeSources, workdir: Path, telegram: None
) -> None:
    _setup(fake)
    run("kev", now=NOW)
    _add_c(fake)
    run("kev", now=NOW)
    later = datetime(2026, 12, 2, 1, 30, tzinfo=UTC)
    assert run("kev", now=later) == 0
    assert run("push", now=later) == 0
    assert fake.sent == []


def test_feed_failure_fails_the_job_and_marks_source(
    run: Run, fake: FakeSources, workdir: Path
) -> None:
    fake.status[kev_source.FEED_URL] = 500
    assert run("kev", now=NOW) == 1
    assert _state(workdir).load_sources()["kev"] == {"at": None, "ok": False}
    fake.status.clear()
    fake.kev = b"{}"
    assert run("kev", now=NOW) == 1


def test_thread_id_is_sent(
    run: Run, fake: FakeSources, telegram: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup(fake)
    run("kev", now=NOW)
    _add_c(fake)
    run("kev", now=NOW)
    monkeypatch.setenv("TELEGRAM_THREAD_ID", " 7 ")
    assert run("push", now=NOW) == 0
    assert fake.sent[0].thread == 7


@pytest.mark.parametrize("value", ["abc", "0", "-3", "7.0"])
def test_invalid_thread_id_sends_nothing(
    run: Run, fake: FakeSources, telegram: None, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    _setup(fake)
    run("kev", now=NOW)
    _add_c(fake)
    run("kev", now=NOW)
    monkeypatch.setenv("TELEGRAM_THREAD_ID", value)
    assert run("push", now=NOW) == 2
    assert run("digest", now=NOW) == 2
    assert fake.sent == []


@pytest.mark.parametrize(
    ("locale", "line"),
    [
        ("zh-TW", "命中你的技術棧：Quillstore（文件庫）、Quill Mirror"),
        ("en", "Matches your stack: Quillstore (文件庫), Quill Mirror"),
    ],
)
def test_stack_hit_is_added_to_kev_alert(
    run: Run, fake: FakeSources, workdir: Path, telegram: None, locale: str, line: str
) -> None:
    (workdir / "config.toml").write_text(config_text(locale=locale))
    _setup(fake)
    run("kev", now=NOW)
    hit = kev_item("CVE-2026-90009", added="2026-11-25", vendor="Quillstore", product="Quillstore")
    fake.kev = kev_feed([A, B, hit], version="2026.11.25")
    fake.records["CVE-2026-90009"] = cve(
        "CVE-2026-90009", vendor="Quillstore", product="Quillstore"
    )
    run("kev", now=NOW)
    watchlist = workdir / "watchlist.toml"
    watchlist.write_text(
        (FIXTURES / "watchlist.toml").read_text(encoding="utf-8")
        + '[[product]]\nname = "Quill Mirror"\nmatch = ["quillstore"]\n',
        encoding="utf-8",
    )
    assert run("push", now=NOW, watchlist=watchlist) == 0
    assert fake.sent[0].text.splitlines()[-1] == line
    # 狀態檔不記技術棧。
    state_text = "".join(p.read_text() for p in (workdir / "state").rglob("*.json"))
    assert "文件庫" not in state_text
    assert json.loads((workdir / "state" / "notified.json").read_text()) == {
        "CVE-2026-90009": {"kev": "2026-11-25T01:30:00Z"}
    }
