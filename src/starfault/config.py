"""讀取並驗證 config.toml。"""

from __future__ import annotations

import math
import re
import tomllib
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from starfault.gemini import MODEL_PATTERN

LOCALES = ("zh-TW", "en")
TRANSLATION_PROVIDERS = ("gemini", "anthropic")

# BCP 47 語言代碼的常見形式：語言加上選用的文字、地區等子標籤，例如 ja、zh-TW、zh-Hant-TW。
_LANGUAGE_TAG = re.compile(r"[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*")


class ConfigError(ValueError):
    """設定檔內容不合法。訊息包含出錯的鍵路徑。"""


@dataclass(frozen=True)
class Thresholds:
    epss: float
    cvss: float
    epss_window_days: int
    # None 表示門檻已定案。
    calibrating_until: date | None


@dataclass(frozen=True)
class TranslationConfig:
    # 譯文的 BCP 47 語言代碼；空字串表示不翻譯。
    target: str
    provider: str
    model: str
    # 只用於 gemini：model 重試後仍無法使用時依序改用。
    fallback_models: tuple[str, ...]
    batch_size: int
    # 0 表示不翻譯。
    max_per_run: int
    request_interval_seconds: float

    @property
    def models(self) -> tuple[str, ...]:
        return (self.model, *self.fallback_models)


@dataclass(frozen=True)
class WatchlistConfig:
    cvss: float


@dataclass(frozen=True)
class SiteConfig:
    locale: str
    timezone: ZoneInfo
    # 空字串表示訊息與分享標籤不附網站連結；否則以 / 結尾。
    url: str


@dataclass(frozen=True)
class Config:
    thresholds: Thresholds
    translation: TranslationConfig
    watchlist: WatchlistConfig
    site: SiteConfig


class _Section:
    """逐鍵讀取一個 TOML 表，結束時拒絕未讀取的鍵。"""

    def __init__(self, root: dict[str, Any], name: str) -> None:
        if name not in root:
            raise ConfigError(f"[{name}]: 缺少此區段")
        value = root[name]
        if not isinstance(value, dict):
            raise ConfigError(f"[{name}]: 必須是表格")
        self._data: dict[str, Any] = value
        self._name = name
        self._read: set[str] = set()

    def has(self, key: str) -> bool:
        return key in self._data

    def _get(self, key: str) -> Any:
        if key not in self._data:
            raise ConfigError(f"{self._name}.{key}: 缺少此設定")
        self._read.add(key)
        return self._data[key]

    def error(self, key: str, message: str) -> ConfigError:
        return ConfigError(f"{self._name}.{key}: {message}")

    def get_int(self, key: str, *, minimum: int, maximum: int | None = None) -> int:
        value = self._get(key)
        # bool 是 int 的子類別，必須另外排除。
        if isinstance(value, bool) or not isinstance(value, int):
            raise self.error(key, "必須是整數")
        if value < minimum or (maximum is not None and value > maximum):
            bound = f"{minimum} 以上" if maximum is None else f"{minimum} 到 {maximum}"
            raise self.error(key, f"必須是 {bound}，目前是 {value}")
        return value

    def get_float(self, key: str, *, minimum: float, maximum: float | None = None) -> float:
        value = self._get(key)
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise self.error(key, "必須是數字")
        try:
            finite = math.isfinite(value)
        except OverflowError:
            finite = False
        if not finite:
            raise self.error(key, "必須是有限的數字")
        if value < minimum or (maximum is not None and value > maximum):
            bound = f"{minimum} 以上" if maximum is None else f"{minimum} 到 {maximum}"
            raise self.error(key, f"必須是 {bound}，目前是 {value}")
        return float(value)

    def get_str(self, key: str) -> str:
        value = self._get(key)
        if not isinstance(value, str) or not value:
            raise self.error(key, "必須是非空字串")
        return value

    def get_optional_str(self, key: str) -> str:
        """可為空字串的字串設定。"""
        value = self._get(key)
        if not isinstance(value, str):
            raise self.error(key, "必須是字串")
        return value

    def get_str_list(self, key: str) -> tuple[str, ...]:
        value = self._get(key)
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            raise self.error(key, "必須是非空字串組成的陣列")
        if len(set(value)) != len(value):
            raise self.error(key, "不可有重複項目")
        return tuple(value)

    def finish(self) -> None:
        unknown = sorted(set(self._data) - self._read)
        if unknown:
            raise ConfigError(f"[{self._name}]: 未知的設定 {', '.join(unknown)}")


def _thresholds(root: dict[str, Any]) -> Thresholds:
    s = _Section(root, "thresholds")
    until: date | None = None
    if s.has("calibrating_until"):
        raw = s.get_str("calibrating_until")
        try:
            # fromisoformat 也接受 20261202 與 2026-W49-3，這裡只收 YYYY-MM-DD。
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
                raise ValueError(raw)
            until = date.fromisoformat(raw)
        except ValueError as e:
            raise s.error("calibrating_until", f"必須是 YYYY-MM-DD，目前是 {raw!r}") from e
    cfg = Thresholds(
        epss=s.get_float("epss", minimum=0.0001, maximum=1.0),
        cvss=s.get_float("cvss", minimum=0.1, maximum=10.0),
        epss_window_days=s.get_int("epss_window_days", minimum=1, maximum=90),
        calibrating_until=until,
    )
    s.finish()
    return cfg


def _translation(root: dict[str, Any]) -> TranslationConfig:
    s = _Section(root, "translation")
    target = s.get_optional_str("target")
    if target and not _LANGUAGE_TAG.fullmatch(target):
        raise ConfigError(f"translation.target: 無效的語言代碼 {target!r}，例如 zh-TW、ja")
    provider = s.get_str("provider")
    if provider not in TRANSLATION_PROVIDERS:
        raise s.error(
            "provider", f"無效的值 {provider!r}，可用值為 {', '.join(TRANSLATION_PROVIDERS)}"
        )
    model = s.get_str("model")
    if not MODEL_PATTERN.fullmatch(model):
        raise s.error("model", f"只能包含小寫英數字、點與連字號，目前是 {model!r}")
    fallback_models = s.get_str_list("fallback_models")
    for name in fallback_models:
        if not MODEL_PATTERN.fullmatch(name):
            raise s.error("fallback_models", f"只能包含小寫英數字、點與連字號，目前是 {name!r}")
    if model in fallback_models:
        raise s.error("fallback_models", "不可包含 translation.model")
    if fallback_models and provider != "gemini":
        raise s.error("fallback_models", "只能用於 gemini，anthropic 請設為 []")
    cfg = TranslationConfig(
        target=target,
        provider=provider,
        model=model,
        fallback_models=fallback_models,
        batch_size=s.get_int("batch_size", minimum=1, maximum=100),
        max_per_run=s.get_int("max_per_run", minimum=0, maximum=5_000),
        request_interval_seconds=s.get_float("request_interval_seconds", minimum=0.0),
    )
    s.finish()
    return cfg


def _watchlist(root: dict[str, Any]) -> WatchlistConfig:
    s = _Section(root, "watchlist")
    cfg = WatchlistConfig(cvss=s.get_float("cvss", minimum=0.0, maximum=10.0))
    s.finish()
    return cfg


def _site(root: dict[str, Any]) -> SiteConfig:
    s = _Section(root, "site")
    locale = s.get_str("locale")
    if locale not in LOCALES:
        raise s.error("locale", f"無效的值 {locale!r}，可用值為 {', '.join(LOCALES)}")
    name = s.get_str("timezone")
    try:
        tz = ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as e:
        raise s.error("timezone", f"無效的時區 {name!r}") from e
    url = s.get_optional_str("url")
    if url and (not url.startswith("https://") or not urlsplit(url).hostname):
        raise s.error("url", "必須是空字串或 https:// 開頭、含主機名稱的網址")
    if url and not url.endswith("/"):
        url += "/"
    s.finish()
    return SiteConfig(locale=locale, timezone=tz, url=url)


_SECTIONS = ("thresholds", "translation", "watchlist", "site")


def parse_config(text: str) -> Config:
    """解析設定內容；任何不合法的值都會丟出 ConfigError。"""
    try:
        root = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"TOML 格式錯誤：{e}") from e
    unknown = sorted(set(root) - set(_SECTIONS))
    if unknown:
        raise ConfigError(f"未知的區段 {', '.join(unknown)}")
    return Config(
        thresholds=_thresholds(root),
        translation=_translation(root),
        watchlist=_watchlist(root),
        site=_site(root),
    )


def load_config(path: Path) -> Config:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"無法讀取設定檔 {path}：{e.strerror}") from e
    return parse_config(text)
