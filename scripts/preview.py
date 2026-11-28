"""用瀏覽器測試的虛構資料建置網站，在本機起 HTTP server 檢視。

繁中與英文網站分別在 /zh-TW/ 與 /en/。資料是 tests/e2e/fixture_data.py 寫入的狀態檔，
「今天」固定在 fixture 的日期，用目前時間開啟時會看到來源停更的提示。

    uv run python -m scripts.preview [--port 8000]
"""

from __future__ import annotations

import argparse
import tempfile
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from scripts.screenshot import LOCALES, build
from tests.e2e.fixture_data import write_state


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        state = work / "state"
        write_state(state)
        for name, locale, target in LOCALES:
            build(work, state, name, locale, target)
        server = ThreadingHTTPServer(
            ("127.0.0.1", args.port), partial(SimpleHTTPRequestHandler, directory=str(work))
        )
        print(
            f"http://localhost:{args.port}/zh-TW/  http://localhost:{args.port}/en/（Ctrl+C 結束）"
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
