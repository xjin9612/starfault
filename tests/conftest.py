from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import pytest

from starfault.cli import main
from tests.builders import BOT_TOKEN, config_text
from tests.fakes import FakeSources

Run = Callable[..., int]


@pytest.fixture
def fake() -> FakeSources:
    return FakeSources()


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    (tmp_path / "config.toml").write_text(config_text(), encoding="utf-8")
    return tmp_path


@pytest.fixture
def telegram(monkeypatch: pytest.MonkeyPatch) -> None:
    """設定 Telegram 的環境變數；沒有用這個 fixture 的測試視為未設定。"""
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", BOT_TOKEN)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100")
    monkeypatch.delenv("TELEGRAM_THREAD_ID", raising=False)


@pytest.fixture(autouse=True)
def _no_ambient_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_ID",
        "TELEGRAM_THREAD_ID",
        "STARFAULT_WATCHLIST",
        "GEMINI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GITHUB_REPOSITORY",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def run(workdir: Path, fake: FakeSources) -> Run:
    """以 workdir 的設定與 state/ 執行 starfault 指令。"""

    def call(*args: str, now: datetime) -> int:
        argv = ["--config", str(workdir / "config.toml"), "--state", str(workdir / "state"), *args]
        return main(argv, transport=fake.transport(), now=now)

    return call
