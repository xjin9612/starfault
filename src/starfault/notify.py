"""Telegram 推播：KEV 新增的即時推播與每日摘要。

技術棧的比對結果只出現在訊息裡：不寫進 log、狀態檔或網站。
已通知清單（notified.json）只記公開規則的原因；每日摘要的技術棧段落靠 digest.json 的
last_day 避免漏發與重發。
"""

from __future__ import annotations

import html
import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from urllib.parse import quote

from starfault.config import Config
from starfault.http import FetchError
from starfault.kev import CATALOG_URL, KevEntry
from starfault.messages import Messages
from starfault.records import CveRecord
from starfault.state import State, iso_now
from starfault.telegram import Button
from starfault.track import CRITICAL_DAYS, local_date
from starfault.translate import lookup
from starfault.view import Entry, SiteView, build_view, pct_text
from starfault.watchlist import Product, Watchlist, kev_pairs, record_pairs

log = logging.getLogger(__name__)

# 每日摘要的技術棧段落最多回溯的天數；漏跑更久時，更早的日子不再補發。
DIGEST_MAX_DAYS = 7


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


# ---------------------------------------------------------------- 每日摘要

# UTC 日 → 該日新增或更新的紀錄。digest 用它取得技術棧比對所需的完整紀錄。
LoadRecords = Callable[[list[date]], Mapping[str, CveRecord]]


def utc_days(days: Sequence[date], cfg: Config) -> list[date]:
    """涵蓋 site.timezone 的 days 所需的 UTC 日。"""
    tz = cfg.site.timezone
    out: set[date] = set()
    for day in days:
        start = datetime.combine(day, time.min, tz)
        end = start + timedelta(days=1) - timedelta(microseconds=1)
        d = start.astimezone(UTC).date()
        while d <= end.astimezone(UTC).date():
            out.add(d)
            d += timedelta(days=1)
    return sorted(out)


@dataclass
class Digest:
    message: Message | None
    # (CVE, 原因)：發送前寫入 notified.json。
    marks: list[tuple[str, str]] = field(default_factory=list)
    # 技術棧段落處理到的日子；讀取 CVE 紀錄失敗時為 None，下次重新處理。
    last_day: date | None = None
    # 統計，寫進 log；不含技術棧。
    epss: int = 0
    critical: int = 0
    # 技術棧段落讀取 CVE 紀錄失敗；其他段落照常發送。
    stack_error: FetchError | None = None


def _stack_section(
    ctx: Context,
    state: State,
    days: Sequence[date],
    load_records: LoadRecords,
) -> list[str]:
    cfg, m = ctx.cfg, ctx.messages
    candidates: dict[str, float | None] = {}
    for day in days:
        daily = state.load_daily(day)
        for cve_id, row in daily.new.items():
            candidates[cve_id] = row.score
        for cve_id, (rescore, _) in daily.rescored.items():
            candidates[cve_id] = rescore
    records = dict(load_records(utc_days(days, cfg)))
    kev = ctx.view.kev_state.entries if ctx.view.kev_state else {}
    lines: list[tuple[float, str, str]] = []
    for cve_id in sorted(candidates):
        score = candidates[cve_id]
        if score is not None and score < cfg.watchlist.cvss:
            continue
        record = records.get(cve_id)
        if record is None:
            entry = ctx.view.get(cve_id)
            record = entry.record if entry else None
        if record is None or record.rejected:
            continue
        pairs = record_pairs(record) + (kev_pairs(kev[cve_id]) if cve_id in kev else [])
        hits = ctx.watchlist.match_pairs(pairs)
        if not hits:
            continue
        lines.append((score if score is not None else -1.0, cve_id, _stack_line(ctx, record, hits)))
    lines.sort(key=lambda x: (-x[0], x[1]))
    if not lines:
        return []
    return [f"<b>{_e(m.stack_section.format(n=len(lines)))}</b>", *(line for _, _, line in lines)]


def _stack_line(ctx: Context, record: CveRecord, hits: Sequence[Product]) -> str:
    m = ctx.messages
    kev = ctx.view.kev_state.entries.get(record.id) if ctx.view.kev_state else None
    title = ctx.title(record.display_title(kev.name if kev else None))
    score = f"{record.cvss.score:.1f}" if record.cvss else m.unscored
    names = m.list_sep.join(p.name for p in hits)
    affected = [
        a
        for a in (*record.affected, *record.adp_affected)
        if any(p.matches(a.vendor, a.product) or any(p.matches(*c) for c in a.cpes) for p in hits)
    ]
    versions = ", ".join(dict.fromkeys(a.versions for a in affected if a.versions))
    fixed = ", ".join(dict.fromkeys(a.fixed for a in affected if a.fixed))
    detail = m.sep.join(
        [
            m.affected.format(v=versions) if versions else m.affected_unknown,
            m.fixed.format(v=fixed) if fixed else m.fixed_unknown,
        ]
    )
    notes = m.list_sep.join(p.note for p in hits if p.note)
    if notes:
        detail += f"（{notes}）" if ctx.cfg.site.locale == "zh-TW" else f" ({notes})"
    head = f"{ctx.cve_link(record.id)}  {_e(names + m.title_sep + title)}  {_e(score)}"
    return f"{head}\n  {_e(detail)}"


def _epss_section(
    ctx: Context, state: State, notified: Mapping[str, Mapping[str, str]]
) -> tuple[list[str], list[str]]:
    m, th = ctx.messages, ctx.cfg.thresholds.epss
    items = [e for e in ctx.view.cves if e.epss_cross and not notified.get(e.id, {}).get("epss")]
    items.sort(key=lambda e: (-(e.epss.s if e.epss else 0), e.id))
    lines = []
    kev = ctx.view.kev_state.entries if ctx.view.kev_state else {}
    for e in items:
        pct = pct_text(e.epss.s) if e.epss else ""
        line = f"{ctx.cve_link(e.id)}  {_e(ctx.title(e.title))}  {_e(pct)}"
        pairs = (record_pairs(e.record) if e.record else []) + (
            kev_pairs(kev[e.id]) if e.id in kev else []
        )
        hits = ctx.watchlist.match_pairs(pairs)
        if hits:
            line += _e(m.sep + m.epss_hit.format(names=m.list_sep.join(p.name for p in hits)))
        lines.append(line)
    if not lines:
        return [], []
    head = f"<b>{_e(m.epss_section.format(th=pct_text(th), n=len(lines)))}</b>"
    return [head, *lines], [e.id for e in items]


def _critical_section(
    ctx: Context, notified: Mapping[str, Mapping[str, str]], today: date
) -> tuple[list[str], list[str]]:
    m, th = ctx.messages, ctx.cfg.thresholds.cvss
    since = today - timedelta(days=CRITICAL_DAYS - 1)
    items = [
        e
        for e in ctx.view.cves
        if "critical" in e.reasons(ctx.cfg)
        and e.published is not None
        and e.published >= since
        and e.epss is None
        and not notified.get(e.id, {}).get("critical")
    ]
    items.sort(key=lambda e: (-(e.cvss.score if e.cvss else 0), e.id))
    lines = [
        f"{ctx.cve_link(e.id)}  {_e(ctx.title(e.title))}  {e.cvss.score:.1f}"
        for e in items
        if e.cvss
    ]
    if not lines:
        return [], []
    head = f"<b>{_e(m.critical_section.format(th=f'{th:.1f}', n=len(lines)))}</b>"
    return [head, *lines], [e.id for e in items]


def build_digest(
    state: State,
    cfg: Config,
    messages: Messages,
    translations: Mapping[str, str],
    watchlist: Watchlist,
    load_records: LoadRecords,
    *,
    now: datetime,
) -> Digest:
    """組出每日摘要。三類都沒有時 message 為 None，但 last_day 照常前進。

    技術棧段落處理 digest.last_day 之後到昨天（最多 DIGEST_MAX_DAYS 天）的新 CVE 與補上分數的 CVE；
    沒有 last_day 時只處理昨天。
    """
    today = local_date(now, cfg.site.timezone)
    yesterday = today - timedelta(days=1)
    last = state.load_digest_day() or yesterday - timedelta(days=1)
    first = max(last + timedelta(days=1), yesterday - timedelta(days=DIGEST_MAX_DAYS - 1))
    days = [first + timedelta(days=i) for i in range((yesterday - first).days + 1)]
    view = build_view(state, cfg, today)
    ctx = Context(cfg, messages, view, translations, watchlist)
    notified = state.load_notified()
    epss_lines, epss_ids = _epss_section(ctx, state, notified)
    critical_lines, critical_ids = _critical_section(ctx, notified, today)
    marks = [(i, "epss") for i in epss_ids] + [(i, "critical") for i in critical_ids]
    digest = Digest(None, marks, yesterday, len(epss_ids), len(critical_ids))
    stack: list[str] = []
    if watchlist and days:
        try:
            stack = _stack_section(ctx, state, days, load_records)
        except FetchError as e:
            digest.stack_error = e
            digest.last_day = None
    sections = [s for s in (stack, epss_lines, critical_lines) if s]
    if not sections:
        return digest
    body = [f"<b>{_e(messages.digest_head.format(date=today.isoformat()))}</b>"]
    for section in sections:
        body += ["", *section]
    meta = state.load_epss_meta()
    if meta and (today - meta.date).days > 1:
        body += ["", _e(messages.epss_date.format(date=meta.date.isoformat()))]
    buttons = (Button(messages.btn_today, cfg.site.url),) if cfg.site.url else ()
    digest.message = Message("\n".join(body), silent=not stack, buttons=buttons)
    return digest


def send_digest(state: State, digest: Digest, send: Send, *, now: datetime) -> None:
    """寫入已通知與 last_day 後發送；發送失敗時回滾並丟出 TelegramError。

    只有技術棧段落時，發送失敗不回滾也不丟出：回滾與失敗的結束碼會透露有命中。
    """
    notified = state.load_notified()
    before = {k: dict(v) for k, v in notified.items()}
    previous_day = state.load_digest_day()
    stamp = iso_now(now)
    for cve_id, reason in digest.marks:
        notified.setdefault(cve_id, {})[reason] = stamp
    state.save_notified(notified)
    if digest.last_day:
        state.save_digest_day(digest.last_day)
    if digest.message is None:
        return
    try:
        send(digest.message)
    except Exception:
        if not digest.marks:
            return
        state.save_notified(before)
        if previous_day:
            state.save_digest_day(previous_day)
        else:
            (state.root / "digest.json").unlink(missing_ok=True)
        raise
