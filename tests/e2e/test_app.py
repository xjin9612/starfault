"""網站（web/）的瀏覽器測試。資料見 fixture_data.py。

由原型的 133 項檢查改寫：每一項檢查對應一個 assert；英文介面的 6 個頁面，以及
6 種寬度 × 2 種主題 × 5 個頁面，是參數化的檢查。
原型用網址參數模擬的狀態（empty、loading、error、stale）改由攔截 data/*.json 呈現。
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from playwright.sync_api import Page, Route, expect

from tests.e2e.conftest import OpenPage, PageErrors, patch_json
from tests.e2e.fixture_data import FOCUS

pytestmark = pytest.mark.e2e

# 關注 CVE：近 90 天的 KEV 17 筆、EPSS 10 筆、Critical 9 筆。
CVES = 36
KEV_CVES = 17
KEV_TOTAL = 26
KEV_30D = 10
CJK = re.compile(r"[㐀-鿿＀-￯　-〿]")
# 英文介面：畫面文字、aria-label、title、placeholder 與頁面標題都不能有中文。
UI_TEXT_JS = """() => {
  const names = ['aria-label', 'title', 'placeholder'];
  const attrs = [...document.querySelectorAll('[aria-label],[title],[placeholder]')]
    .map(e => names.map(n => e.getAttribute(n)).join(' '));
  return document.body.innerText + ' ' + attrs.join(' ') + ' ' + document.title;
}"""
ROUTES = ["", "#/cves", "#/kev", f"#/cve/{FOCUS}", "#/rules"]


def _ready(pg: Page) -> None:
    """等目前網址的頁面繪製完成：app.js 繪製後把網址寫在 #view 的 data-hash。"""
    pg.wait_for_function(
        "() => { const v = document.querySelector('#view');"
        " return v.dataset.hash === location.hash && !v.hasAttribute('aria-busy'); }"
    )


def _go(pg: Page, url: str) -> None:
    pg.goto(url)
    _ready(pg)


def _rows(pg: Page) -> int:
    return pg.locator("#view .rows > li").count()


def _click(pg: Page, selector: str, url: str) -> None:
    pg.click(selector)
    expect(pg).to_have_url(re.compile(re.escape(url) + "$"))
    _ready(pg)


# ===== 語言檔 =====


def test_i18n_keys_match(open_page: OpenPage, base_url: str) -> None:
    pg = open_page()
    _go(pg, base_url)
    diff = pg.evaluate(
        "(() => { const a=Object.keys(I18N['zh-TW']), b=Object.keys(I18N.en);"
        " return [a.filter(k=>!b.includes(k)), b.filter(k=>!a.includes(k))]; })()"
    )
    assert diff == [[], []]


# ===== 今日 =====


def test_today(open_page: OpenPage, base_url: str) -> None:
    pg = open_page()
    _go(pg, base_url)
    kpi = pg.inner_text(".kpis")
    assert "KEV 新增" in kpi and "4" in kpi and "61" in kpi, kpi
    assert "2026-11-25 11:20" in pg.inner_text("#hdrInfo")
    assert pg.locator(".sec").count() == 3
    assert (
        pg.locator("#sec-kev").count() == 1
        and pg.locator(".sec:nth-child(1) .rows > li").count() == 4
    )
    assert pg.locator(".sec:nth-child(3) .rows > li").count() == 5
    assert "查看全部 9 筆" in pg.inner_text(".sec:nth-child(3) .sec-head")
    # 原型的示意資料提示只在範例模式出現；正式網站沒有，來源正常時也沒有停更提醒。
    assert pg.locator(".demo-note").count() == 0 and pg.locator(".notice").count() == 0
    due = pg.inner_text(".sec:nth-child(1)")
    assert "剩 3 天" in due and "（今天）" in due


def test_today_chart(open_page: OpenPage, base_url: str) -> None:
    pg = open_page()
    _go(pg, base_url)
    assert pg.locator("#chart .bar").count() == 30
    pg.focus("#chart")
    expect(pg.locator("#chartTip")).to_be_visible()
    tip = pg.inner_text("#chartTip")
    assert "2026-11-25" in tip and "尚未結束" in tip
    pg.keyboard.press("ArrowLeft")
    expect(pg.locator("#chartTip")).to_contain_text("2026-11-24")
    pg.keyboard.press("Home")
    expect(pg.locator("#chartTip")).to_contain_text("2026-10-27")
    pg.hover('#chart .bar[data-i="10"] .hit')
    expect(pg.locator("#chartTip")).to_contain_text("2026-11-06")
    pg.click(".tbl-toggle summary")
    assert pg.locator(".tbl-toggle tbody tr").count() == 30
    sums = pg.evaluate(
        "[...document.querySelectorAll('.tbl-toggle tbody tr')].every(tr => {"
        " const n=[...tr.cells].slice(1).map(c=>+c.textContent.replace(/,/g,''));"
        " return n.slice(0,5).reduce((a,b)=>a+b,0)===n[5]; })"
    )
    assert sums
    _click(pg, ".sec:nth-child(3) .sec-head a", "#/cves?reason=critical")
    assert _rows(pg) == 9


# ===== 關注 CVE =====


def test_cves_filters(open_page: OpenPage, base_url: str) -> None:
    pg = open_page()
    _go(pg, base_url + "#/cves")
    assert _rows(pg) == CVES
    _click(pg, '[data-f="reason"][data-v="kev"]', "#/cves?reason=kev")
    n_kev = _rows(pg)
    assert n_kev == KEV_CVES and pg.locator("#view .row .flag.kev").count() == n_kev
    assert "KEV・共" in pg.inner_text(".summary-line")
    _click(pg, '[data-f="sev"][data-v="critical"]', "#/cves?reason=kev&sev=critical")
    sev = pg.evaluate(
        "[...document.querySelectorAll('#view .row .r-top .sev')].map(e=>e.className)"
    )
    assert sev and all("critical" in s for s in sev) and "reason=kev&sev=critical" in pg.url
    assert pg.evaluate("document.activeElement.dataset.v") == "critical"
    _click(pg, "[data-clear]", "#/cves")
    assert _rows(pg) == CVES


def test_cves_sorting_and_empty(open_page: OpenPage, base_url: str) -> None:
    pg = open_page()
    _go(pg, base_url + "#/cves")
    _click(pg, '[data-f="sort"][data-v="epss"]', "#/cves?sort=epss")
    ep = pg.evaluate(
        "[...document.querySelectorAll('#view .row')].map(r => {"
        " const b=r.querySelector('.epss b');"
        " return b ? parseFloat(b.textContent.replace('<','')) : -1; })"
    )
    assert ep == sorted(ep, reverse=True), ep[:4]
    _click(pg, '[data-f="sort"][data-v="cvss"]', "#/cves?sort=cvss")
    cv = pg.evaluate(
        "[...document.querySelectorAll('#view .row .r-top .sev')].map(e => {"
        " const b=e.querySelector('b'); return b ? +b.textContent : -1; })"
    )
    assert cv == sorted(cv, reverse=True), cv[:4]
    _go(pg, base_url + "#/cves?reason=epss&sev=low")
    assert _rows(pg) == 0 and pg.locator(".empty").count() == 1
    _click(pg, ".empty [data-clear]", "#/cves")
    assert _rows(pg) == CVES
    _go(pg, base_url + "#/cves?reason=bad&sev=nope&sort=x")
    assert _rows(pg) == CVES


# ===== KEV =====


def test_kev(open_page: OpenPage, base_url: str) -> None:
    pg = open_page()
    _go(pg, base_url + "#/kev")
    assert _rows(pg) == KEV_30D
    _click(pg, '[data-f="range"][data-v="all"]', "#/kev?range=all")
    assert _rows(pg) == KEV_TOTAL and "range=all" in pg.url
    _click(pg, '[data-f="flag"][data-v="ransomware"]', "#/kev?range=all&flag=ransomware")
    n = _rows(pg)
    assert n > 0 and pg.locator("#view .row .flag.ransom").count() == n
    _click(pg, '[data-f="flag"][data-v="all"]', "#/kev?range=all")
    _click(pg, '[data-f="sort"][data-v="due"]', "#/kev?range=all&sort=due")
    meta = pg.evaluate("[...document.querySelectorAll('#view .r-meta')].map(m=>m.innerText)")
    first_past = next((i for i, m in enumerate(meta) if "期限已過" in m), len(meta))
    assert all("期限已過" in m for m in meta[first_past:]) and first_past > 0
    assert "剩 1 天" in meta[1] or "今天" in meta[0]


# ===== 詳細頁與返回還原 =====


def test_detail_and_back(open_page: OpenPage, base_url: str) -> None:
    pg = open_page(1440, 700)
    _go(pg, base_url + "#/cves")
    target = pg.locator("#view .row .r-title a").nth(10)
    target.scroll_into_view_if_needed()
    pg.wait_for_function("window.scrollY > 0")
    y0 = pg.evaluate("window.scrollY")
    href = target.get_attribute("href")
    assert href
    target.click()
    expect(pg).to_have_url(re.compile(re.escape(href) + "$"))
    _ready(pg)
    assert pg.url.endswith(href) and pg.locator(".d-head h2").count() == 1
    assert pg.evaluate("document.activeElement.tagName") == "H2"
    assert "返回關注 CVE" in pg.inner_text(".back")
    pg.click(".back")
    expect(pg).to_have_url(re.compile(r"#/cves$"))
    _ready(pg)
    pg.wait_for_function(f"Math.abs(window.scrollY - {y0}) < 5")
    y = pg.evaluate("window.scrollY")
    assert y0 > 0 and abs(y - y0) < 5, (y0, y)
    assert pg.evaluate("document.activeElement.getAttribute('href')") == href


def test_detail_content(open_page: OpenPage, base_url: str) -> None:
    pg = open_page()
    _go(pg, base_url + "#/cve/" + FOCUS.lower())
    assert pg.inner_text(".d-head .cve-id") == FOCUS
    body = pg.inner_text("#view")
    assert "列入 CISA KEV" in body and "修補前先確認" in body and "機器翻譯" in body
    assert "前往今日" in pg.inner_text(".back")
    assert "100.0" not in pg.inner_text(".d-side")
    assert pg.locator(".spark").count() == 1 and pg.locator(".timeline li").count() >= 2
    ext = pg.evaluate(
        "[...document.querySelectorAll('#view a[href^=\"http\"]')]"
        ".every(a => a.target==='_blank' && a.rel.includes('noopener'))"
    )
    assert ext
    pg.click(".orig summary")
    assert pg.locator('.orig p[lang="en"]').is_visible()
    no_epss = pg.evaluate(
        "fetch('data/cves.json').then(r=>r.json()).then(d=>d.items.find(x=>!x.epss).id)"
    )
    _go(pg, base_url + "#/cve/" + no_epss)
    assert "還沒有 EPSS" in pg.inner_text(".d-side")
    _go(pg, base_url + "#/cve/CVE-1999-0001")
    assert pg.locator(".empty").count() == 1 and "找不到" in pg.inner_text(".empty")


# ===== 搜尋 =====


def test_search(open_page: OpenPage, base_url: str) -> None:
    pg = open_page()
    _go(pg, base_url)
    pg.keyboard.press("/")
    assert pg.evaluate("document.activeElement.id") == "q"
    pg.keyboard.type("94440")
    expect(pg.locator("#qList .dd-item").first).to_be_visible()
    assert FOCUS in pg.inner_text("#qList .dd-item >> nth=0")
    pg.keyboard.press("Enter")
    expect(pg).to_have_url(re.compile(re.escape(f"#/cve/{FOCUS}") + "$"))
    assert pg.url.endswith(f"#/cve/{FOCUS}")
    _ready(pg)
    pg.fill("#q", "sorell")
    expect(pg.locator("#qFoot")).to_contain_text("共")
    n = pg.locator("#qList .dd-item").count()
    assert n > 0 and "共" in pg.inner_text("#qFoot")
    pg.keyboard.press("ArrowDown")
    assert pg.get_attribute("#q", "aria-activedescendant") == "opt1"
    pg.keyboard.press("Escape")
    expect(pg.locator("#qPanel")).to_be_hidden()
    assert pg.locator("#qPanel").is_hidden()
    pg.fill("#q", "zzzz")
    expect(pg.locator("#qFoot")).to_contain_text("找不到")
    assert "找不到" in pg.inner_text("#qFoot")


# ===== 狀態 =====


def _empty(pg: Page) -> None:
    patch_json(pg, "meta", lambda m: m | {"counts": dict.fromkeys(m["counts"], 0)})
    patch_json(pg, "cves", lambda d: {"items": []})
    patch_json(pg, "kev", lambda d: {"items": []})
    patch_json(pg, "daily", lambda d: {"days": []})


def _stale(meta: dict[str, Any]) -> dict[str, Any]:
    """KEV 連續 5 小時讀取失敗；EPSS 停在 3 天前。"""
    meta["sources"]["kev"] |= {"at": "2026-11-24T23:02:00Z", "ok": False}
    meta["sources"]["epss"] |= {"date": "2026-11-22"}
    return meta


def test_empty_state(open_page: OpenPage, base_url: str) -> None:
    pg = open_page()
    _empty(pg)
    _go(pg, base_url)
    assert "還沒有資料" in pg.inner_text(".empty")
    _go(pg, base_url + "#/kev")
    assert pg.locator(".empty").count() == 1


def test_loading_skeleton(open_page: OpenPage, base_url: str) -> None:
    pg = open_page()
    pg.route("**/data/*.json", lambda route: None)
    pg.goto(base_url)
    expect(pg.locator(".sk").first).to_be_attached()
    assert pg.locator(".sk").count() > 0 and pg.get_attribute("#view", "aria-busy") == "true"


def test_error_and_retry(open_page: OpenPage, base_url: str, errors: PageErrors) -> None:
    pg = open_page()
    failing = {"on": True}

    def handler(route: Route) -> None:
        if failing["on"]:
            route.abort()
        else:
            route.fallback()

    pg.route("**/data/*.json", handler)
    pg.goto(base_url)
    expect(pg.locator(".empty")).to_be_visible()
    assert "讀取資料失敗" in pg.inner_text(".empty") and pg.locator("[data-retry]").count() == 1
    # 讀取失敗時 app.js 以 console.error 記下原因，這是預期的錯誤。
    assert errors.errors and all("Failed to fetch" in e for e in errors.errors)
    errors.errors.clear()
    failing["on"] = False
    pg.click("[data-retry]")
    _ready(pg)
    expect(pg.locator(".kpis")).to_be_visible()


def test_stale_sources(open_page: OpenPage, base_url: str) -> None:
    pg = open_page()
    patch_json(pg, "meta", _stale)
    _go(pg, base_url)
    note = pg.inner_text(".notice")
    assert "KEV 在 2026-11-25 07:02" in note and "EPSS 停在 2026-11-22" in note, note
    _go(pg, base_url + "#/rules")
    assert pg.locator(".st-bad").count() == 2


# ===== 規則 =====


def test_rules(open_page: OpenPage, base_url: str) -> None:
    pg = open_page()
    _go(pg, base_url + "#/rules")
    assert pg.locator(".rule").count() == 4
    assert pg.locator(".tbl tr.cur").count() == 2
    assert "暫定值" in pg.inner_text("#calT + p")


# ===== 主題 =====


def test_theme(open_page: OpenPage, base_url: str) -> None:
    pg = open_page()
    _go(pg, base_url)
    pg.click("#themeBtn")
    assert pg.get_attribute("html", "data-theme") == "light"
    pg.click("#themeBtn")
    pg.reload()
    _ready(pg)
    assert pg.get_attribute("html", "data-theme") == "dark"


# ===== 英文介面 =====


@pytest.mark.parametrize("route", [*ROUTES[:3], ROUTES[4], ROUTES[3], "#/cve/CVE-1999-0001"])
def test_english_has_no_chinese(open_page: OpenPage, base_url_en: str, route: str) -> None:
    pg = open_page()
    _go(pg, base_url_en + route)
    text = pg.evaluate(UI_TEXT_JS)
    assert not CJK.search(text), CJK.findall(text)[:5]


def test_english_stale_and_translation_note(open_page: OpenPage, base_url_en: str) -> None:
    pg = open_page()
    patch_json(pg, "meta", _stale)
    _go(pg, base_url_en)
    assert not CJK.search(pg.evaluate(UI_TEXT_JS))
    pg.unroute("**/data/meta.json")
    _go(pg, base_url_en + f"#/cve/{FOCUS}")
    assert pg.locator(".tr-note").count() == 0


# ===== 寬度 =====


@pytest.mark.parametrize("scheme", ["light", "dark"])
@pytest.mark.parametrize("width", [360, 390, 768, 1100, 1440, 2560])
def test_no_horizontal_scroll(open_page: OpenPage, base_url: str, width: int, scheme: str) -> None:
    pg = open_page(width, 900, scheme)
    overflow = {}
    for route in ROUTES:
        _go(pg, base_url + route)
        overflow[route or "#/"] = pg.evaluate(
            "document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
    for route, over in overflow.items():
        assert over <= 0, f"{width}px {scheme} {route}：{over}"
