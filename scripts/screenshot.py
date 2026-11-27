"""產生 README 用的網站截圖。

用瀏覽器測試的虛構資料（tests/e2e/fixture_data.py）建置繁中與英文兩個網站，在本機起
HTTP server，以 Playwright 截取今日頁與 CVE 詳細頁。瀏覽器時鐘固定在 fixture 的 NOW，
截圖不會出現來源停更的提示。

    uv run python scripts/screenshot.py [--out docs/screenshots]
"""

from __future__ import annotations

import argparse
import os
import tempfile
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock

from playwright.sync_api import Page, sync_playwright

from starfault.cli import main as starfault
from tests.builders import REPO_ROOT, config_text
from tests.e2e.fixture_data import FOCUS, GENERATED_AT, NOW, write_state

WIDTH, HEIGHT = 1440, 900
# (語言目錄, site.locale, translation.target)
LOCALES = [("zh-TW", "zh-TW", "zh-TW"), ("en", "en", "")]
PAGES = [("today", ""), ("detail", f"#/cve/{FOCUS}")]


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass


def build(work: Path, state: Path, name: str, locale: str, target: str) -> None:
    config = work / f"config-{name}.toml"
    config.write_text(config_text(locale=locale, target=target), encoding="utf-8")
    argv = ["--config", str(config), "--state", str(state), "site", "--out", str(work / name)]
    argv += ["--web", str(REPO_ROOT / "web"), "--assets", str(REPO_ROOT / "assets")]
    # 頁尾的 repo 連結用佔位名稱，不依賴本機的 git remote。
    with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/starfault"}):
        if starfault(argv, now=GENERATED_AT) != 0:
            raise SystemExit(f"{name} 網站產生失敗")


def _ready(page: Page) -> None:
    page.wait_for_function(
        "() => { const v = document.querySelector('#view');"
        " return v.dataset.hash === location.hash && !v.hasAttribute('aria-busy'); }"
    )
    page.wait_for_load_state("networkidle")


def capture(root: Path, out: Path) -> list[Path]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(_QuietHandler, directory=str(root)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}/"
    written = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            for name, _, _ in LOCALES:
                page = browser.new_page(
                    viewport={"width": WIDTH, "height": HEIGHT}, color_scheme="light"
                )
                page.clock.set_fixed_time(NOW)
                for shot, route in PAGES:
                    page.goto(f"{base}{name}/{route}")
                    _ready(page)
                    # 換頁後焦點在標題上，截圖不需要焦點框。
                    page.evaluate("document.activeElement.blur()")
                    path = out / name / f"{shot}.png"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    page.screenshot(path=str(path))
                    written.append(path)
                page.close()
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, default=Path("docs/screenshots"))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        state = work / "state"
        write_state(state)
        for name, locale, target in LOCALES:
            build(work, state, name, locale, target)
        for path in capture(work, args.out):
            print(f"已寫入 {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
