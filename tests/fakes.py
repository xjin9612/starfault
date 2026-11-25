"""模擬三個資料來源與 Telegram 的 transport。"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from typing import Any

import httpx

from starfault import cvelist, epss, kev
from tests.builders import delta_zip


@dataclass
class Sent:
    text: str
    silent: bool
    buttons: list[dict[str, str]]
    thread: int | None


@dataclass
class FakeSources:
    """模擬 KEV、EPSS、cvelistV5 與 Telegram。沒有設定的網址回應 404。"""

    kev: bytes | None = None
    epss: bytes | None = None
    eod: dict[date, list[dict[str, Any]]] = field(default_factory=dict)
    hourly: dict[tuple[date, int], list[dict[str, Any]]] = field(default_factory=dict)
    records: dict[str, dict[str, Any]] = field(default_factory=dict)
    status: dict[str, int] = field(default_factory=dict)
    telegram_fail: bool = False
    sent: list[Sent] = field(default_factory=list)
    requested: list[str] = field(default_factory=list)

    def _routes(self) -> dict[str, bytes]:
        routes: dict[str, bytes] = {}
        if self.kev is not None:
            routes[kev.FEED_URL] = self.kev
        if self.epss is not None:
            routes[epss.CSV_URL] = self.epss
        for day, recs in self.eod.items():
            routes[cvelist.eod_url(day)] = delta_zip(recs)
        for (day, hour), recs in self.hourly.items():
            routes[cvelist.hourly_url(day, hour)] = delta_zip(recs)
        for cve_id, rec in self.records.items():
            routes[cvelist.record_url(cve_id)] = json.dumps(rec).encode()
        return routes

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.requested.append(url)
        if request.url.host == "api.telegram.org":
            if self.telegram_fail:
                return httpx.Response(400, json={"ok": False, "description": "Bad Request"})
            body = json.loads(request.content)
            markup = body.get("reply_markup", {}).get("inline_keyboard", [[]])[0]
            self.sent.append(
                Sent(
                    body["text"],
                    body["disable_notification"],
                    markup,
                    body.get("message_thread_id"),
                )
            )
            return httpx.Response(200, json={"ok": True})
        if url in self.status:
            return httpx.Response(self.status[url])
        body_bytes = self._routes().get(url)
        if body_bytes is None:
            return httpx.Response(404)
        return httpx.Response(200, content=body_bytes)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)
