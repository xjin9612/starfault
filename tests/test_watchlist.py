"""技術棧清單的讀取與比對。清單是 tests/fixtures/watchlist.toml 的虛構產品。"""

from __future__ import annotations

from pathlib import Path

import pytest

from starfault.records import parse_record
from starfault.watchlist import (
    ENV_VAR,
    WatchlistError,
    load,
    normalize,
    parse,
    record_pairs,
)
from tests.builders import FIXTURES, cve

WATCHLIST = FIXTURES / "watchlist.toml"


def _hits(vendor: str, product: str) -> list[str]:
    return [p.name for p in load({}, WATCHLIST).match_pairs([(vendor, product)])]


def test_normalize() -> None:
    assert normalize("Gullwing-Router_3.x (Lite)") == ("gullwing", "router", "3", "x", "lite")


@pytest.mark.parametrize(
    ("vendor", "product", "expected"),
    [
        # 每個產品的命中
        ("Lantern Labs", "Lantern CMS", ["Lantern CMS"]),
        ("lantern_labs", "lanterncms", ["Lantern CMS"]),
        ("Tidewater", "Harbor Print Server Suite", ["Harbor Print"]),
        ("Tidewater Inc.", "HPS", ["Harbor Print"]),
        ("Mooring Systems", "Build of HarborPrint", ["Harbor Print"]),
        ("Quillstore Ltd", "Quillstore", ["Quillstore"]),
        ("gullwing", "gullwing_router", ["Gullwing Router"]),
        ("Gullwing Networks", "GullwingOS", ["Gullwing Router"]),
        # 同名排除：廠商不符
        ("Gridworks", "Lantern CMS", []),
        ("Heliport Services", "HPS", []),
        ("Acme", "Quillstore", []),
        ("Fan Project", "Gullwing Router Dashboard", []),
        # 只比對完整詞
        ("Quillstore", "Quillstoreson", []),
        ("Tidewater", "HPSX Studio", []),
        ("Lantern Labs", "Lantern", []),
    ],
)
def test_matching(vendor: str, product: str, expected: list[str]) -> None:
    assert _hits(vendor, product) == expected


def test_record_pairs_include_cpes_and_cisa_adp() -> None:
    data = cve(
        "CVE-2026-90001",
        vendor="n/a",
        product="n/a",
        cpes=["cpe:2.3:a:gullwing:gullwing_router:*:*:*:*:*:*:*:*"],
    )
    assert ("gullwing", "gullwing_router") in record_pairs(parse_record(data))
    adp = cve(
        "CVE-2026-90002",
        adp_affected=[{"vendor": "quillstore", "product": "quillstore", "cpes": []}],
    )
    assert ("quillstore", "quillstore") in record_pairs(parse_record(adp))


def test_env_var_takes_precedence(tmp_path: Path) -> None:
    env = {ENV_VAR: '[[product]]\nname = "Solo"\nmatch = ["solo"]\n'}
    assert [p.name for p in load(env, WATCHLIST).products] == ["Solo"]
    assert len(load({ENV_VAR: "  "}, WATCHLIST).products) == 4
    assert not load({}, tmp_path / "missing.toml")


SECRET = "Zephyrine Secret Value"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (f'[[product]]\nname = "{SECRET}\n', "第 2 行"),
        (f'[[product]]\nname = "{SECRET}"\n', "match 至少要有一個值"),
        (f'[[product]]\nname = "x"\nmatch = ["{SECRET}"]\nextra = 1\n', "未知的鍵"),
        (f'[[product]]\nname = ""\nmatch = ["{SECRET}"]\n', "name 必須是非空字串"),
        (f'[[product]]\nname = "x"\nmatch = "{SECRET}"\n', "match 必須是字串陣列"),
        (f'[[product]]\nname = "x"\nmatch = ["..."]\nnote = "{SECRET}"\n', "不可只有標點"),
        (f'[other]\nname = "{SECRET}"\n', "未知的區段"),
    ],
)
def test_errors_never_include_list_content(text: str, message: str) -> None:
    with pytest.raises(WatchlistError) as info:
        parse(text)
    assert message in str(info.value)
    assert "Zephyrine" not in str(info.value) and "Secret" not in str(info.value)
    assert info.value.__cause__ is None


def test_example_file_is_valid() -> None:
    from tests.builders import REPO_ROOT

    example = load({}, REPO_ROOT / "watchlist.example.toml")
    assert [p.name for p in example.products] == ["Example Proxy", "Sample Runtime"]
