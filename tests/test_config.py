from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from starfault.config import ConfigError, load_config, parse_config
from tests.builders import REPO_ROOT, config_text


def test_repo_config_loads() -> None:
    cfg = load_config(REPO_ROOT / "config.toml")
    assert cfg.thresholds.epss == 0.10
    assert cfg.thresholds.cvss == 9.0
    assert cfg.thresholds.epss_window_days == 30
    assert cfg.thresholds.calibrating_until == date(2026, 12, 2)
    assert cfg.translation.target == "zh-TW"
    assert cfg.translation.models == ("gemini-3.5-flash-lite", "gemini-3.5-flash")
    assert cfg.watchlist.cvss == 7.0
    assert cfg.site.timezone.key == "Asia/Taipei"


def test_site_url_gets_trailing_slash() -> None:
    cfg = parse_config(config_text(url="https://example.test/sf"))
    assert cfg.site.url == "https://example.test/sf/"


def test_calibrating_until_is_optional() -> None:
    text = "\n".join(
        line for line in config_text().splitlines() if not line.startswith("calibrating_until")
    )
    assert parse_config(text).thresholds.calibrating_until is None


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"thresholds__epss": 1.5}, "thresholds.epss"),
        ({"thresholds__cvss": 0.0}, "thresholds.cvss"),
        ({"watchlist__cvss": 11.0}, "watchlist.cvss"),
        ({"epss_window_days": 0}, "thresholds.epss_window_days"),
        ({"calibrating_until": "12/02"}, "thresholds.calibrating_until"),
        ({"locale": "ja"}, "site.locale"),
        ({"timezone": "Mars/Base"}, "site.timezone"),
        ({"url": "http://example.test/"}, "site.url"),
        ({"target": "繁中"}, "translation.target"),
        ({"provider": "openai"}, "translation.provider"),
        ({"model": "Gemini Pro"}, "translation.model"),
        ({"provider": "anthropic"}, "translation.fallback_models"),
        ({"max_per_run": -1}, "translation.max_per_run"),
    ],
)
def test_invalid_values_are_rejected(values: dict[str, object], message: str) -> None:
    with pytest.raises(ConfigError, match=message.replace(".", r"\.")):
        parse_config(config_text(**values))


def test_unknown_keys_and_sections_are_rejected() -> None:
    with pytest.raises(ConfigError, match=r"\[site\]: 未知的設定 extra"):
        parse_config(config_text() + "\n[site.extra]\n")
    with pytest.raises(ConfigError, match="未知的區段 other"):
        parse_config(config_text() + "\n[other]\nx = 1\n")


def test_missing_file_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="無法讀取設定檔"):
        load_config(tmp_path / "missing.toml")
