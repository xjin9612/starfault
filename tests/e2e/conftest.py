"""瀏覽器測試的共用環境：以 fixture 狀態檔產生網站，在本機起 HTTP server，用 Playwright 開啟。

同一份狀態檔產生 zh-TW 與 en 兩個網站，分別放在 server 根目錄的 zh/ 與 en/。
en 網站不設定翻譯，CVE 內容維持英文原文。
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Iterator
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import Browser, Page, Route, sync_playwright

from starfault.cli import main
from tests.builders import REPO_ROOT, config_text
from tests.e2e.fixture_data import GENERATED_AT, NOW, write_state

GITHUB_REPO = "me/starfault"


def _build(work: Path, state: Path, out: Path, **values: str) -> None:
    config = work / f"config-{values['locale']}.toml"
    config.write_text(config_text(**values), encoding="utf-8")
    argv = ["--config", str(config), "--state", str(state), "site", "--out", str(out)]
    argv += ["--web", str(REPO_ROOT / "web"), "--assets", str(REPO_ROOT / "assets")]
    with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": GITHUB_REPO}):
        assert main(argv, now=GENERATED_AT) == 0


@pytest.fixture(scope="session")
def site_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    work = tmp_path_factory.mktemp("e2e")
    state = work / "state"
    write_state(state)
    root = work / "site"
    _build(work, state, root / "zh", locale="zh-TW", target="zh-TW")
    _build(work, state, root / "en", locale="en", target="")
    return root


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass


@pytest.fixture(scope="session")
def server_url(site_root: Path) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(_QuietHandler, directory=str(site_root)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="session")
def base_url(server_url: str) -> str:
    return server_url + "zh/"


@pytest.fixture(scope="session")
def base_url_en(server_url: str) -> str:
    return server_url + "en/"


@pytest.fixture(scope="session")
def browser() -> Iterator[Browser]:
    with sync_playwright() as p:
        b = p.chromium.launch()
        try:
            yield b
        finally:
            b.close()


class PageErrors:
    """JS 錯誤與失敗的請求。預期會出錯的測試，檢查後自行清空。"""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.failed: list[str] = []
        self.outside: list[str] = []


@pytest.fixture
def errors() -> PageErrors:
    return PageErrors()


OpenPage = Callable[..., Page]


@pytest.fixture
def open_page(browser: Browser, server_url: str, errors: PageErrors) -> Iterator[OpenPage]:
    """開新的 context 與頁面，瀏覽器時鐘固定在 NOW。

    測試結束時不能有 JS 錯誤、失敗的請求，也不能連到本機以外的網址。
    """
    contexts = []
    host = urlsplit(server_url).netloc

    def guard(route: Route) -> None:
        if urlsplit(route.request.url).netloc == host:
            route.fallback()
        else:
            errors.outside.append(route.request.url)
            route.abort()

    def make(width: int = 1440, height: int = 900, scheme: str = "light") -> Page:
        context = browser.new_context(
            viewport={"width": width, "height": height},
            color_scheme=scheme,  # type: ignore[arg-type]
        )
        context.set_default_timeout(5000)
        contexts.append(context)
        pg = context.new_page()
        pg.clock.set_fixed_time(NOW)
        pg.on("pageerror", lambda e: errors.errors.append(str(e)))
        pg.on(
            "console",
            lambda m: (
                errors.errors.append(m.text)
                if m.type == "error" and not m.text.startswith("Failed to load resource")
                else None
            ),
        )
        pg.on("response", lambda r: errors.failed.append(r.url) if r.status >= 400 else None)
        pg.route("**/*", guard)
        return pg

    try:
        yield make
    finally:
        for c in contexts:
            c.close()
    assert errors.errors == []
    assert errors.failed == []
    assert errors.outside == []


Patch = Callable[[Page, str, Callable[[Any], Any]], None]


def patch_json(page: Page, name: str, change: Callable[[Any], Any]) -> None:
    """改寫 data/<name>.json 的內容，用來呈現網站資料以外的狀態。"""

    def handler(route: Route) -> None:
        body = route.fetch().json()
        route.fulfill(json=change(body))

    page.route(f"**/data/{name}.json", handler)
