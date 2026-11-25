"""技術棧清單不留下公開痕跡：log、state/、網站與 commit 的內容都不能出現清單或比對結果。

用 tests/fixtures/watchlist.toml 的虛構清單跑完 hourly 與 daily 的全部指令，再拿另一份
一個都不會命中的清單跑一次。兩次的公開輸出（log、state/、網站）必須完全相同，Telegram 訊息除外。
"""

from __future__ import annotations

import logging
import tomllib
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from starfault.cli import main
from tests.builders import BOT_TOKEN, FIXTURES, config_text, cve, epss_csv, kev_feed, kev_item
from tests.fakes import FakeSources

WATCHLIST = FIXTURES / "watchlist.toml"
NO_HITS = """
[[product]]
name = "Nothing Matches"
match = ["zzzz nothing"]
note = "不會命中"
"""
EARLY = datetime(2026, 11, 25, 1, 0, tzinfo=UTC)
NOW = datetime(2026, 11, 25, 22, 30, tzinfo=UTC)

# 只因技術棧命中的 CVE：分數普通、不在 KEV，網站不收錄。
STACK_ONLY = [
    cve(
        "CVE-2026-92001",
        published="2026-11-25T03:00:00Z",
        score=7.2,
        vendor="Quillstore",
        product="Quillstore",
    ),
    cve(
        "CVE-2026-92002",
        published="2026-11-25T04:00:00Z",
        score=None,
        vendor="Tidewater",
        product="HPS",
    ),
    cve(
        "CVE-2026-92003",
        published="2026-11-25T05:00:00Z",
        score=8.1,
        vendor="n/a",
        product="n/a",
        cpes=["cpe:2.3:a:gullwing:gullwing_router:*:*:*:*:*:*:*:*"],
    ),
]
# 公開規則也會收錄的命中：KEV 與 EPSS。
KEV_HIT = kev_item(
    "CVE-2026-92004", added="2026-11-25", vendor="Lantern Labs", product="Lantern CMS"
)
EPSS_HIT = cve(
    "CVE-2026-92005",
    published="2026-11-25T00:30:00Z",
    score=6.5,
    vendor="Quillstore",
    product="Quillstore",
)
OTHER = cve(
    "CVE-2026-92006",
    published="2026-11-25T06:00:00Z",
    score=9.8,
    vendor="Pellmar",
    product="CivicForms",
)


def _sources() -> FakeSources:
    fake = FakeSources()
    fake.kev = kev_feed([kev_item("CVE-2026-92010", added="2026-11-01")], version="2026.11.24")
    fake.eod[date(2026, 11, 24)] = []
    fake.hourly[(date(2026, 11, 25), 0)] = [*STACK_ONLY, OTHER, EPSS_HIT]
    fake.hourly[(date(2026, 11, 25), 22)] = [*STACK_ONLY, OTHER, EPSS_HIT]
    fake.eod[date(2026, 11, 25)] = [*STACK_ONLY, OTHER, EPSS_HIT]
    fake.epss = epss_csv({"CVE-2026-92005": (0.4, 0.99)}, "2026-11-25")
    fake.records["CVE-2026-92010"] = cve("CVE-2026-92010", published="2026-10-01T00:00:00Z")
    fake.records["CVE-2026-92004"] = cve(
        "CVE-2026-92004", vendor="Lantern Labs", product="Lantern CMS"
    )
    fake.records["CVE-2026-92005"] = EPSS_HIT
    return fake


def _run_all(
    root: Path, watchlist: str, caplog: pytest.LogCaptureFixture
) -> tuple[str, FakeSources]:
    root.mkdir()
    (root / "config.toml").write_text(config_text())
    (root / "watchlist.toml").write_text(watchlist, encoding="utf-8")
    fake = _sources()
    base = ["--config", str(root / "config.toml"), "--state", str(root / "state")]
    base += ["--watchlist", str(root / "watchlist.toml")]
    steps = [
        (EARLY, ["kev"]),
        (EARLY, ["cve"]),
        (NOW, ["cve"]),
        (NOW, ["epss"]),
        (NOW, ["kev"]),
        (NOW, ["push"]),
        (NOW, ["translate"]),
        (NOW, ["digest"]),
        (NOW, ["site", "--out", str(root / "site")]),
    ]
    caplog.clear()
    for now, args in steps:
        if args == ["kev"] and now == NOW:
            fake.kev = kev_feed(
                [kev_item("CVE-2026-92010", added="2026-11-01"), KEV_HIT], version="2026.11.25"
            )
        with caplog.at_level(logging.DEBUG):
            assert main([*base, *args], transport=fake.transport(), now=now) == 0, args
    return caplog.text, fake


def _public_files(root: Path) -> dict[str, str]:
    out = {}
    for base in ("state", "site"):
        for path in sorted((root / base).rglob("*")):
            if path.is_file() and path.suffix in (".json", ".jsonl", ".html", ".js"):
                out[str(path.relative_to(root))] = path.read_text(encoding="utf-8")
    return out


def _secrets() -> list[str]:
    """清單裡所有會洩漏技術棧的字串：名稱、寫法、廠商、備註。"""
    data = tomllib.loads(WATCHLIST.read_text(encoding="utf-8"))
    values: list[str] = []
    for p in data["product"]:
        values += [p["name"], p["note"], *p["match"], *p["vendors"]]
    return values


@pytest.fixture
def telegram_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", BOT_TOKEN)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100")


def test_public_outputs_do_not_depend_on_the_watchlist(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, telegram_env: None
) -> None:
    hit_log, hit_fake = _run_all(tmp_path / "hit", WATCHLIST.read_text(encoding="utf-8"), caplog)
    miss_log, miss_fake = _run_all(tmp_path / "miss", NO_HITS, caplog)
    # Telegram 訊息確實不同：命中的那次有技術棧段落與 KEV 加註。
    hit_text = "\n".join(s.text for s in hit_fake.sent)
    assert "你的技術棧（3）" in hit_text
    assert "命中你的技術棧：Lantern CMS（對外網站）" in hit_text
    assert "命中：Quillstore" in hit_text
    assert "你的技術棧" not in "\n".join(s.text for s in miss_fake.sent)
    # 公開輸出完全相同。
    assert hit_log.replace(str(tmp_path / "hit"), "") == miss_log.replace(
        str(tmp_path / "miss"), ""
    )
    hit_files = _public_files(tmp_path / "hit")
    miss_files = _public_files(tmp_path / "miss")
    assert hit_files.keys() == miss_files.keys()
    for name, text in hit_files.items():
        if name.endswith("sources.json") or name.endswith("meta.json"):
            continue
        assert text == miss_files[name], name


def test_public_outputs_contain_no_watchlist_content(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, telegram_env: None
) -> None:
    log_text, _ = _run_all(tmp_path / "hit", WATCHLIST.read_text(encoding="utf-8"), caplog)
    files = _public_files(tmp_path / "hit")
    # 只因技術棧命中的 CVE 不出現在任何公開輸出。
    stack_only = [r["cveMetadata"]["cveId"] for r in STACK_ONLY]
    public = {name: text for name, text in files.items() if not name.startswith("state/daily/")}
    for cve_id in stack_only:
        assert cve_id not in log_text
        assert not [name for name, text in public.items() if cve_id in text], cve_id
    # 備註與只因技術棧命中的產品名稱：不出現在 log、狀態檔與網站。其他產品與廠商名稱可能本來就在
    # 公開的 CVE 資料裡，例如命中 KEV 的 Lantern CMS，因此只檢查 log。
    notes_and_names = [
        "對外網站",
        "辦公室印表機",
        "文件庫",
        "分店路由器",
        "Harbor Print",
        "Gullwing",
    ]
    for value in notes_and_names:
        assert value not in log_text, value
        assert not [name for name, text in files.items() if value in text], value
    for value in _secrets():
        assert value.lower() not in log_text.lower(), value
    assert "技術棧" not in log_text
