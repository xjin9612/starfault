"""技術棧清單：讀取與產品比對。

清單只用於 Telegram 推播。任何會寫進 log、狀態檔或網站的內容都不能包含清單的值或比對結果；
錯誤訊息只寫位置，不寫內容。
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from starfault.kev import KevEntry
from starfault.records import CveRecord

ENV_VAR = "STARFAULT_WATCHLIST"
_PUNCT = re.compile(r"[^\w]+|_")


class WatchlistError(ValueError):
    """清單格式錯誤。訊息只含行號或項目序號，不含清單內容。"""


def normalize(text: str) -> tuple[str, ...]:
    """小寫、標點與底線換成空白後切成詞。"""
    return tuple(_PUNCT.sub(" ", text.lower()).split())


def _contains(words: tuple[str, ...], term: tuple[str, ...]) -> bool:
    n = len(term)
    return any(words[i : i + n] == term for i in range(len(words) - n + 1))


@dataclass(frozen=True)
class Product:
    name: str
    match: tuple[tuple[str, ...], ...]
    vendors: tuple[tuple[str, ...], ...]
    note: str

    def matches(self, vendor: str, product: str) -> bool:
        """product 以完整詞包含任一 match；有 vendors 時 vendor 也要以完整詞包含其中之一。"""
        words = normalize(product)
        if not any(_contains(words, m) for m in self.match):
            return False
        if not self.vendors:
            return True
        vendor_words = normalize(vendor)
        return any(_contains(vendor_words, v) for v in self.vendors)

    def label(self) -> str:
        return f"{self.name}（{self.note}）" if self.note else self.name


@dataclass(frozen=True)
class Watchlist:
    products: tuple[Product, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.products)

    def match_pairs(self, pairs: Iterable[tuple[str, str]]) -> list[Product]:
        """依清單順序回傳命中的產品，每個產品只列一次。"""
        pairs = list(pairs)
        return [p for p in self.products if any(p.matches(v, n) for v, n in pairs)]


def record_pairs(record: CveRecord) -> list[tuple[str, str]]:
    """CNA 與 CISA ADP 的受影響產品與 CPE 的 (vendor, product)。"""
    out: list[tuple[str, str]] = []
    for a in (*record.affected, *record.adp_affected):
        out.append((a.vendor, a.product))
        out.extend(a.cpes)
    return out


def kev_pairs(entry: KevEntry) -> list[tuple[str, str]]:
    return [(entry.vendor, entry.product)]


def _location(e: tomllib.TOMLDecodeError) -> str:
    line = getattr(e, "lineno", None)
    col = getattr(e, "colno", None)
    return f"第 {line} 行第 {col} 欄" if line else "位置不明"


def _terms(item: dict[str, object], key: str, index: int, *, required: bool) -> tuple[str, ...]:
    value = item.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise WatchlistError(f"第 {index} 個 product：{key} 必須是字串陣列")
    if required and not value:
        raise WatchlistError(f"第 {index} 個 product：{key} 至少要有一個值")
    return tuple(value)


def parse(text: str) -> Watchlist:
    try:
        root = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise WatchlistError(f"TOML 格式錯誤（{_location(e)}）") from None
    unknown = set(root) - {"product"}
    if unknown:
        raise WatchlistError(f"未知的區段 {len(unknown)} 個；只允許 [[product]]")
    items = root.get("product", [])
    if not isinstance(items, list):
        raise WatchlistError("product 必須寫成 [[product]]")
    products: list[Product] = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            raise WatchlistError(f"第 {index} 個 product 必須是表格")
        extra = set(item) - {"name", "match", "vendors", "note"}
        if extra:
            raise WatchlistError(f"第 {index} 個 product：有 {len(extra)} 個未知的鍵")
        name = item.get("name")
        note = item.get("note", "")
        if not isinstance(name, str) or not name.strip():
            raise WatchlistError(f"第 {index} 個 product：name 必須是非空字串")
        if not isinstance(note, str):
            raise WatchlistError(f"第 {index} 個 product：note 必須是字串")
        match = tuple(normalize(m) for m in _terms(item, "match", index, required=True))
        vendors = tuple(normalize(v) for v in _terms(item, "vendors", index, required=False))
        if not all(match) or not all(vendors):
            raise WatchlistError(f"第 {index} 個 product：match 與 vendors 不可只有標點或空白")
        products.append(Product(name.strip(), match, vendors, note.strip()))
    return Watchlist(tuple(products))


def load(environ: Mapping[str, str] | None, path: Path) -> Watchlist:
    """環境變數 STARFAULT_WATCHLIST 有值時用它，否則讀 path；都沒有時是空清單。"""
    text = (environ or {}).get(ENV_VAR, "")
    if text.strip():
        return parse(text)
    if path.is_file():
        return parse(path.read_text(encoding="utf-8"))
    return Watchlist()
