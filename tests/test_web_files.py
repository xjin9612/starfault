"""web/ 的靜態檢查：語言檔兩種語言一致、程式用到的 key 都存在，與後端共用的格式一致。"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from starfault.view import pct_text

WEB = Path(__file__).resolve().parent.parent / "web"
_ENTRY = re.compile(r"^\s*'([\w.-]+)':\s*'((?:[^'\\]|\\.)*)',?\s*$")


def _dicts() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in (WEB / "i18n.js").read_text(encoding="utf-8").splitlines():
        head = re.match(r"^\s*'?(zh-TW|en)'?:\s*\{\s*$", line)
        if head:
            current = out.setdefault(head.group(1), {})
            continue
        m = _ENTRY.match(line)
        if m and current is not None:
            current[m.group(1)] = m.group(2)
        elif current is not None and line.strip().startswith("'"):
            pytest.fail(f"無法解析的語言檔行：{line}")
    return out


def test_languages_have_same_keys_and_variables() -> None:
    dicts = _dicts()
    zh, en = dicts["zh-TW"], dicts["en"]
    assert len(zh) > 200
    assert set(zh) == set(en)
    variables = {k: set(re.findall(r"\{(\w+)\}", v)) for k, v in zh.items()}
    assert {k: set(re.findall(r"\{(\w+)\}", v)) for k, v in en.items()} == variables


def test_keys_used_by_the_page_exist() -> None:
    app = (WEB / "app.js").read_text(encoding="utf-8")
    html = (WEB / "index.html").read_text(encoding="utf-8")
    used = set(re.findall(r"\bt\('([\w.-]+)'[,)]", app))
    used |= set(re.findall(r"data-i18n(?:-aria|-placeholder)?=\"([\w.-]+)\"", html))
    assert len(used) > 50, "沒有找到足夠的 key，檢查規則可能失效"
    assert sorted(used - set(_dicts()["zh-TW"])) == []


def test_english_has_no_cjk() -> None:
    cjk = re.compile(r"[㐀-鿿＀-￯　-〿]")
    assert {k: v for k, v in _dicts()["en"].items() if cjk.search(v)} == {}


@pytest.mark.parametrize(
    ("score", "text"),
    [
        (0.0004, "<0.1%"),
        (0.001, "0.1%"),
        (0.0123, "1.23%"),
        (0.05, "5%"),
        (0.1, "10%"),
        (0.881, "88.1%"),
    ],
)
def test_pct_text_matches_frontend(score: float, text: str) -> None:
    assert pct_text(score) == text


def test_frontend_formats_match_backend() -> None:
    app = (WEB / "app.js").read_text(encoding="utf-8")
    pct = (
        "const pctText = s => s == null ? '' : s < 0.001 ? '<0.1%' : "
        "(s * 100).toFixed(s >= 0.1 ? 1 : 2).replace(/\\.?0+$/, '') + '%';"
    )
    assert pct in app
    assert "const cveHref = id => '#/cve/' + encodeURIComponent(id);" in app
