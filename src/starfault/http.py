"""抓取資料來源的共用 HTTP client：逾時、重試與錯誤訊息。"""

from __future__ import annotations

import time
from collections.abc import Callable

import httpx

USER_AGENT = "starfault"
# 每個請求最多嘗試次數。5xx 與連線錯誤的重試間隔依序為 2、4 秒。
MAX_ATTEMPTS = 3
TIMEOUT = 60.0


class FetchError(Exception):
    """沒有取得資料。訊息只含網址與原因。"""


class NotFoundError(FetchError):
    """伺服器回應 404。"""


class Http:
    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._client = httpx.Client(
            timeout=TIMEOUT,
            transport=transport,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        self._sleep = sleep

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Http:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def get(self, url: str) -> bytes:
        """回傳回應內容。404 丟出 NotFoundError，其他失敗丟出 FetchError。

        只重試連線錯誤與 5xx；429 等其他狀態碼直接失敗，留給下一次排程。
        """
        for attempt in range(MAX_ATTEMPTS):
            last = attempt + 1 == MAX_ATTEMPTS
            try:
                response = self._client.get(url)
            except httpx.TransportError as e:
                if last:
                    raise FetchError(f"{url}：連線失敗（{type(e).__name__}）") from None
                self._sleep(2 ** (attempt + 1))
                continue
            except httpx.HTTPError as e:
                raise FetchError(f"{url}：{type(e).__name__}") from None
            status = response.status_code
            if status == 404:
                raise NotFoundError(f"{url}：回應 404")
            if status >= 500 and not last:
                self._sleep(2 ** (attempt + 1))
                continue
            if status != 200:
                raise FetchError(f"{url}：回應 {status}")
            return response.content
        raise AssertionError("unreachable")
