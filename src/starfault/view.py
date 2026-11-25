"""網站收錄的 CVE：關注清單與 KEV 合併後的顯示欄位與收錄原因。網站產生器與推播共用。"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from starfault.config import Config
from starfault.kev import KevEntry
from starfault.records import CveRecord, Cvss, first_sentence
from starfault.state import KevState, State, Watch
from starfault.track import local_date

# 關注 CVE 頁收錄最後一個事件在幾天內的 CVE。
LIST_DAYS = 90


@dataclass(frozen=True)
class Epss:
    s: float
    p: float
    date: date


@dataclass(frozen=True)
class Entry:
    id: str
    record: CveRecord | None
    kev: KevEntry | None
    watch: Watch | None
    published: date | None
    epss: Epss | None

    @property
    def title(self) -> str:
        kev_name = self.kev.name if self.kev else None
        if self.record:
            return self.record.display_title(kev_name)
        return kev_name or first_sentence(self.desc)

    @property
    def desc(self) -> str:
        if self.record and self.record.desc:
            return self.record.desc
        return self.kev.desc if self.kev else ""

    @property
    def vendor(self) -> str:
        return self.kev.vendor if self.kev else self.record_vendor_product()[0]

    @property
    def product(self) -> str:
        return self.kev.product if self.kev else self.record_vendor_product()[1]

    def record_vendor_product(self) -> tuple[str, str]:
        return self.record.vendor_product() if self.record else ("", "")

    @property
    def cvss(self) -> Cvss | None:
        return self.record.cvss if self.record else None

    @property
    def epss_cross(self) -> date | None:
        return self.watch.epss_cross if self.watch else None

    def reasons(self, cfg: Config) -> list[str]:
        out = []
        if self.kev:
            out.append("kev")
        if self.epss_cross:
            out.append("epss")
        if (
            self.watch
            and self.watch.critical
            and self.cvss
            and self.cvss.score >= cfg.thresholds.cvss
        ):
            out.append("critical")
        return out

    def last_event(self) -> date | None:
        events = [d for d in (self.published, self.epss_cross) if d]
        if self.kev:
            events.append(self.kev.added)
        return max(events) if events else None


@dataclass(frozen=True)
class SiteView:
    # 關注 CVE 頁：近 LIST_DAYS 天有事件、符合任一規則的 CVE，最新事件在前。
    cves: list[Entry]
    # KEV 頁：整份目錄，列入日期新的在前。
    kev: list[Entry]
    kev_state: KevState | None

    def ids(self) -> set[str]:
        """網站有詳細頁的 CVE。"""
        return {e.id for e in self.cves} | {e.id for e in self.kev}

    def get(self, cve_id: str) -> Entry | None:
        return next((e for e in (*self.cves, *self.kev) if e.id == cve_id), None)


def latest_epss(state: State) -> dict[str, Epss]:
    days = state.epss_days()
    if not days:
        return {}
    return {i: Epss(s, p, days[-1]) for i, (s, p) in state.load_epss_day(days[-1]).items()}


def build_view(state: State, cfg: Config, today: date) -> SiteView:
    tz = cfg.site.timezone
    kev_state = state.load_kev()
    kev = kev_state.entries if kev_state else {}
    watch = state.load_watch()
    epss = latest_epss(state)

    def entry(cve_id: str) -> Entry:
        w = watch.get(cve_id)
        record = w.record if w else None
        published = local_date(record.published, tz) if record and record.published else None
        return Entry(cve_id, record, kev.get(cve_id), w, published, epss.get(cve_id))

    since = today - timedelta(days=LIST_DAYS - 1)
    cves = []
    for cve_id in sorted(set(watch) | set(kev)):
        e = entry(cve_id)
        last = e.last_event()
        if e.reasons(cfg) and last and last >= since:
            cves.append(e)
    cves.sort(key=lambda e: (e.last_event() or date.min, e.id), reverse=True)
    kev_list = sorted((entry(i) for i in kev), key=lambda e: (kev[e.id].added, e.id), reverse=True)
    return SiteView(cves, kev_list, kev_state)


def pct_text(s: float) -> str:
    """與 web/app.js 的 pctText 相同：<0.1%、10% 以上小數一位、其他小數兩位，去掉尾端的 0。"""
    if s < 0.001:
        return "<0.1%"
    text = f"{s * 100:.{1 if s >= 0.1 else 2}f}"
    return (text.rstrip("0").rstrip(".") if "." in text else text) + "%"
