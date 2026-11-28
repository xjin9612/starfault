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
    assert cfg.thresholds.calibrating_until == date(2026, 12, 4)
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


@pytest.mark.parametrize(
    ("key", "inside", "outside"),
    [
        ("thresholds__epss", [0.0001, 1.0], [0.0, 1.0001]),
        ("thresholds__cvss", [0.1, 10.0], [0.09, 10.1]),
        ("epss_window_days", [1, 90], [0, 91]),
        ("watchlist__cvss", [0.0, 10.0], [-0.1, 10.1]),
        ("batch_size", [1, 100], [0, 101]),
        ("max_per_run", [0, 5000], [-1, 5001]),
        ("request_interval_seconds", [0.0], [-0.1, float("inf"), 10**400]),
    ],
)
def test_range_boundaries(key: str, inside: list[object], outside: list[object]) -> None:
    for value in inside:
        parse_config(config_text(**{key: value}))
    for value in outside:
        with pytest.raises(ConfigError, match=key.rpartition("__")[2]):
            parse_config(config_text(**{key: value}))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("calibrating_until", "20261202"),
        ("calibrating_until", "2026-W49-3"),
        ("url", "https://"),
        ("url", "https:///path"),
    ],
)
def test_loose_formats_are_rejected(key: str, value: str) -> None:
    with pytest.raises(ConfigError, match=key):
        parse_config(config_text(**{key: value}))


def test_unknown_keys_and_sections_are_rejected() -> None:
    with pytest.raises(ConfigError, match=r"\[site\]: 未知的設定 extra"):
        parse_config(config_text() + "\n[site.extra]\n")
    with pytest.raises(ConfigError, match="未知的區段 other"):
        parse_config(config_text() + "\n[other]\nx = 1\n")


def test_missing_file_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="無法讀取設定檔"):
        load_config(tmp_path / "missing.toml")
