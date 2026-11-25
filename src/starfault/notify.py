"""Telegram 推播：KEV 新增的即時推播。

技術棧的比對結果只出現在訊息裡：不寫進 log、狀態檔或網站。
"""

from __future__ import annotations

import html
import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import quote

from starfault.config import Config
from starfault.kev import CATALOG_URL, KevEntry
from starfault.messages import Messages
from starfault.state import State, iso_now
from starfault.telegram import Button
from starfault.track import local_date
from starfault.translate import lookup
from starfault.view import Entry, SiteView, build_view, pct_text
from starfault.watchlist import Product, Watchlist, kev_pairs, record_pairs

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Message:
    text: str
    silent: bool
    buttons: tuple[Button, ...] = ()


# 發送失敗時丟出 TelegramError。
Send = Callable[[Message], None]


def detail_url(site_url: str, cve_id: str) -> str:
    """與 web/app.js 的 cveHref 一致。"""
    return f"{site_url}#/cve/{quote(cve_id, safe='')}"


def cve_org_url(cve_id: str) -> str:
    return f"https://www.cve.org/CVERecord?id={quote(cve_id, safe='')}"


def nvd_url(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{quote(cve_id, safe='')}"


def _e(text: str) -> str:
    return html.escape(text, quote=False)


def _a(url: str, text: str) -> str:
    return f'<a href="{html.escape(url)}">{_e(text)}</a>'


@dataclass
class Context:
    cfg: Config
    messages: Messages
    view: SiteView
    translations: Mapping[str, str]
    watchlist: Watchlist

    def title(self, text: str) -> str:
        """有譯文時用譯文。"""
        if self.cfg.translation.target:
            return lookup(self.translations, text) or text
        return text

    def cve_link(self, cve_id: str) -> str:
        """網站有收錄就連詳細頁；沒有時連 CVE.org 與 NVD。"""
        url = self.cfg.site.url
        if cve_id in self.view.ids():
            return _a(detail_url(url, cve_id), cve_id) if url else _e(cve_id)
        sep = self.messages.sep
        return f"{_e(cve_id)} {_a(cve_org_url(cve_id), 'CVE.org')}{sep}{_a(nvd_url(cve_id), 'NVD')}"


# ---------------------------------------------------------------- KEV


def kev_message(ctx: Context, entry: Entry, kev: KevEntry, hits: Sequence[Product]) -> Message:
    m = ctx.messages
    cvss = entry.cvss
    score = m.cvss.format(score=f"{cvss.score:.1f}", sev=cvss.sev.capitalize()) if cvss else None
    epss = m.epss.format(pct=pct_text(entry.epss.s)) if entry.epss else m.epss_none
    lines = [
        f"<b>{_e(m.kev_head.format(id=entry.id))}</b>",
        _e(ctx.title(entry.title)),
        _e((score or m.cvss_none) + m.sep + epss),
    ]
    due = [m.due.format(date=kev.due.isoformat(), days=(kev.due - kev.added).days)]
    if kev.triage:
        due.append(m.triage)
    if kev.ransomware:
        due.append(m.ransomware)
    lines.append(_e(m.sep.join(due)))
    if hits:
        lines.append(_e(m.stack_hit.format(labels=m.list_sep.join(p.label() for p in hits))))
    buttons = []
    if ctx.cfg.site.url:
        buttons.append(Button(m.btn_detail, detail_url(ctx.cfg.site.url, entry.id)))
    buttons.append(Button(m.btn_kev, CATALOG_URL))
    return Message("\n".join(lines), silent=False, buttons=tuple(buttons))


@dataclass
class KevPushResult:
    sent: int = 0
    # 未設定 Telegram 而略過的筆數。
    skipped: int = 0


def push_kev(
    state: State,
    cfg: Config,
    messages: Messages,
    translations: Mapping[str, str],
    watchlist: Watchlist,
    send: Send | None,
    *,
    now: datetime,
) -> KevPushResult:
    """推播待推播清單裡的 KEV 新增，一則一個 CVE。

    發送前寫入 notified.json；發送失敗時回滾該筆並丟出 TelegramError，下次重試。
    send 為 None（未設定 Telegram）時不發送，待推播清單保留。
    """
    today = local_date(now, cfg.site.timezone)
    kev_state = state.load_kev()
    result = KevPushResult()
    if kev_state is None or not kev_state.pending:
        return result
    view = build_view(state, cfg, today)
    ctx = Context(cfg, messages, view, translations, watchlist)
    notified = state.load_notified()
    order = sorted(kev_state.pending, key=lambda i: (kev_state.entries[i].added, i))
    for cve_id in order:
        if notified.get(cve_id, {}).get("kev"):
            del kev_state.pending[cve_id]
            state.save_kev(kev_state)
            continue
        if send is None:
            result.skipped += 1
            continue
        kev = kev_state.entries[cve_id]
        entry = view.get(cve_id)
        assert entry is not None
        pairs = kev_pairs(kev) + (record_pairs(entry.record) if entry.record else [])
        message = kev_message(ctx, entry, kev, watchlist.match_pairs(pairs))
        notified.setdefault(cve_id, {})["kev"] = iso_now(now)
        state.save_notified(notified)
        try:
            send(message)
        except Exception:
            del notified[cve_id]["kev"]
            if not notified[cve_id]:
                del notified[cve_id]
            state.save_notified(notified)
            raise
        del kev_state.pending[cve_id]
        state.save_kev(kev_state)
        result.sent += 1
    return result
