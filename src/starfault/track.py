"""把 CVE、KEV、EPSS 的新資料套用到狀態檔：每日新 CVE、關注清單、KEV 快照。"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from starfault import cvelist
from starfault.config import Config
from starfault.epss import EpssData
from starfault.http import FetchError, Http
from starfault.kev import Catalog
from starfault.records import CveRecord, RecordError, severity
from starfault.state import (
    DAILY_KEEP_DAYS,
    WATCH_KEEP_DAYS,
    Daily,
    EpssMeta,
    KevState,
    Row,
    State,
    Watch,
    level_key,
)

log = logging.getLogger(__name__)

# Critical 規則只看發布幾天內的 CVE（含當天）。
CRITICAL_DAYS = 7
# 推播失敗或未設定 Telegram 而累積的 KEV 新增，超過這個天數不再嘗試推播。
KEV_PENDING_DAYS = 7
# 門檻校準表列出的 EPSS 門檻；設定的門檻不在其中時另外加入。
EPSS_LEVELS = (0.01, 0.05, 0.10, 0.20, 0.50)
# 單筆紀錄連續失敗這麼多次時停止抓取，通常代表服務暫時無法使用。
MAX_CONSECUTIVE_FAILURES = 3


def local_date(value: datetime, tz: ZoneInfo) -> date:
    return value.astimezone(tz).date()


def epss_levels(cfg: Config) -> tuple[float, ...]:
    return tuple(sorted({*EPSS_LEVELS, cfg.thresholds.epss}))


def qualifies_critical(record: CveRecord, cfg: Config, today: date) -> bool:
    if record.cvss is None or record.published is None:
        return False
    age = (today - local_date(record.published, cfg.site.timezone)).days
    return record.cvss.score >= cfg.thresholds.cvss and 0 <= age < CRITICAL_DAYS


@dataclass
class CveResult:
    records: int = 0
    new: int = 0
    rescored: int = 0
    rejected: int = 0
    watch_added: int = 0
    watch_updated: int = 0


class _Dailies:
    """保留期間內的每日紀錄，只寫回有變動的日子。"""

    def __init__(self, state: State, today: date) -> None:
        self.state = state
        self.first = today - timedelta(days=DAILY_KEEP_DAYS - 1)
        self.today = today
        self.days = {d: state.load_daily(d) for d in state.daily_days() if d >= self.first}
        self.changed: set[date] = set()
        self.where = {i: d for d, daily in self.days.items() for i in daily.new}
        self.rescored = {i for daily in self.days.values() for i in daily.rescored}

    def get(self, day: date) -> Daily:
        if day not in self.days:
            self.days[day] = Daily(day)
        return self.days[day]

    def remove(self, cve_id: str) -> None:
        """從 new 與 rescored 移除。"""
        day = self.where.pop(cve_id, None)
        if day is not None:
            self.days[day].new.pop(cve_id, None)
            self.days[day].baseline.discard(cve_id)
            self.changed.add(day)
        for d, daily in self.days.items():
            if daily.rescored.pop(cve_id, None) is not None:
                self.changed.add(d)
        self.rescored.discard(cve_id)

    def move(self, cve_id: str, old: date, new: date | None) -> None:
        """datePublished 改變時把列搬到新的日子；new 為 None 時只移除。"""
        row = self.days[old].new.pop(cve_id)
        base = cve_id in self.days[old].baseline
        self.days[old].baseline.discard(cve_id)
        self.changed.add(old)
        del self.where[cve_id]
        if new is None:
            return
        self.get(new).new[cve_id] = row
        if base:
            self.days[new].baseline.add(cve_id)
        self.where[cve_id] = new
        self.changed.add(new)

    def save(self) -> None:
        for day in sorted(self.changed):
            self.state.save_daily(self.days[day])


def apply_records(
    state: State,
    records: Iterable[CveRecord],
    cfg: Config,
    today: date,
    kev_ids: set[str],
    since: date,
) -> CveResult:
    """更新每日新 CVE 紀錄與關注清單。規則見 docs/DEVELOPMENT.md「狀態檔」。

    since 是開始讀 delta 後第一個完整的日子，更早的日子不寫入 new。同一次讀到的多個版本
    只看最後一個，所以只有前一次執行記下的未評分紀錄才會成為 rescored。
    """
    tz = cfg.site.timezone
    dailies = _Dailies(state, today)
    watch = state.load_watch()
    result = CveResult()
    for r in records:
        result.records += 1
        if r.rejected:
            result.rejected += 1
            dailies.remove(r.id)
            if r.id in watch and r.id not in kev_ids:
                del watch[r.id]
                state.delete_watch(r.id)
            continue
        assert r.published is not None
        pub = local_date(r.published, tz)
        score = r.cvss.score if r.cvss else None
        sev = severity(score)
        in_range = max(dailies.first, since) <= pub <= today
        old = dailies.where.get(r.id)
        if old is not None and old != pub:
            dailies.move(r.id, old, pub if in_range else None)
        if in_range:
            row = dailies.get(pub).new.get(r.id)
            if row is None:
                dailies.days[pub].new[r.id] = Row(score, sev)
                # 晚於隔天才寫入的列（backfill 或停跑後補讀）沒有之前的 EPSS 可比。
                if pub < today - timedelta(days=1):
                    dailies.days[pub].baseline.add(r.id)
                dailies.where[r.id] = pub
                result.new += 1
                dailies.changed.add(pub)
            elif (row.score, row.sev) != (score, sev):
                if row.score is None and score is not None and r.id not in dailies.rescored:
                    updated = local_date(r.updated or r.published, tz)
                    rday = min(max(updated, pub), today)
                    dailies.get(rday).rescored[r.id] = (score, sev)
                    dailies.rescored.add(r.id)
                    dailies.changed.add(rday)
                    result.rescored += 1
                row.score, row.sev = score, sev
                dailies.changed.add(pub)
        critical = qualifies_critical(r, cfg, today)
        w = watch.get(r.id)
        if w is not None:
            w.record = r
            if critical and w.critical is None:
                w.critical = today
            state.save_watch(w)
            result.watch_updated += 1
        elif critical or r.id in kev_ids:
            w = Watch(r, critical=today if critical else None)
            watch[r.id] = w
            state.save_watch(w)
            result.watch_added += 1
    dailies.save()
    return result


def last_event(w: Watch, tz: ZoneInfo) -> date:
    events = [d for d in (w.epss_cross, w.critical) if d]
    if w.record.published:
        events.append(local_date(w.record.published, tz))
    return max(events)


def prune(state: State, cfg: Config, today: date, kev_ids: set[str]) -> int:
    """刪除過期的每日紀錄，以及最後事件超過保留期間、不在 KEV 的關注清單。回傳刪除的 CVE 數。"""
    state.prune_daily(today)
    removed = 0
    for cve_id, w in state.load_watch().items():
        if cve_id in kev_ids:
            continue
        if (today - last_event(w, cfg.site.timezone)).days > WATCH_KEEP_DAYS:
            state.delete_watch(cve_id)
            removed += 1
    return removed


@dataclass
class KevUpdate:
    kev: KevState
    new: list[str] = field(default_factory=list)
    # 第一次執行：建立快照，不推播。
    baseline: bool = False
    # 快照或待推播清單有變動。
    changed: bool = False
    # 超過 KEV_PENDING_DAYS 而放棄推播的筆數。
    expired: int = 0


def update_kev(state: State, catalog: Catalog, today: date) -> KevUpdate:
    """比對前一次快照，把新增的 CVE 加入待推播清單並寫回快照。"""
    prev = state.load_kev()
    if prev is None:
        kev = KevState(catalog.version, catalog.released, catalog.entries)
        state.save_kev(kev)
        return KevUpdate(kev, baseline=True, changed=True)
    new = sorted(
        (i for i in catalog.entries if i not in prev.entries),
        key=lambda i: (catalog.entries[i].added, i),
    )
    pending = {
        i: d for i, d in (prev.pending | dict.fromkeys(new, today)).items() if i in catalog.entries
    }
    fresh = {i: d for i, d in pending.items() if (today - d).days < KEV_PENDING_DAYS}
    kev = KevState(catalog.version, catalog.released, catalog.entries, fresh)
    changed = kev.to_json() != prev.to_json()
    if changed:
        state.save_kev(kev)
    return KevUpdate(kev, new, changed=changed, expired=len(pending) - len(fresh))


def fill_records(
    state: State, http: Http, ids: Iterable[str], cfg: Config, today: date, budget: int
) -> tuple[int, int]:
    """為還沒有完整紀錄的 KEV 或關注 CVE 抓取單筆紀錄，最多請求 budget 筆。

    回傳 (取得筆數, 失敗筆數)。cvelistV5 沒有或 REJECTED 的 CVE 不算失敗，但計入 budget。
    """
    watch = state.load_watch()
    requested = fetched = failed = consecutive = 0
    for cve_id in ids:
        if requested >= budget or consecutive >= MAX_CONSECUTIVE_FAILURES:
            break
        if cve_id in watch:
            continue
        requested += 1
        try:
            record = cvelist.fetch_record(http, cve_id)
        except FetchError as e:
            failed += 1
            consecutive += 1
            log.warning("無法取得 %s：%s", cve_id, e)
            continue
        except RecordError as e:
            failed += 1
            consecutive = 0
            log.warning("無法解析 %s：%s", cve_id, e)
            continue
        consecutive = 0
        if record is None or record.rejected:
            continue
        w = Watch(record, critical=today if qualifies_critical(record, cfg, today) else None)
        watch[cve_id] = w
        state.save_watch(w)
        fetched += 1
    return fetched, failed


@dataclass
class EpssResult:
    meta: EpssMeta
    # 這次首次跨過 thresholds.epss 的 CVE。
    crossed: list[str]
    # 跨過門檻但取不到紀錄、下次再試的 CVE 數。
    deferred: int


def epss_candidates(
    state: State, cfg: Config, epss_date: date, *, extra_days: int = 0
) -> dict[str, date]:
    """EPSS 規則要看的 CVE（以 EPSS 資料日期為準，發布 epss_window_days 天內，含當天）→ 發布日。"""
    first = epss_date - timedelta(days=cfg.thresholds.epss_window_days - 1 + extra_days)
    out: dict[str, date] = {}
    for day in state.daily_days():
        if first <= day <= epss_date:
            out.update(dict.fromkeys(state.load_daily(day).new, day))
    return out


def apply_epss(
    state: State, http: Http, data: EpssData, cfg: Config, today: date, kev_ids: set[str]
) -> EpssResult:
    """記錄當天分數、各校準門檻的首次跨過日，並把首次跨過 thresholds.epss 的 CVE 加入關注清單。"""
    epss_date = data.date
    day_key = epss_date.isoformat()
    levels = epss_levels(cfg)
    candidates = epss_candidates(state, cfg, epss_date)
    changed: dict[date, Daily] = {}
    baseline: set[str] = set()
    for cve_id, pub in candidates.items():
        daily = changed.get(pub) or state.load_daily(pub)
        if cve_id in daily.baseline:
            daily.baseline.discard(cve_id)
            baseline.add(cve_id)
            changed[pub] = daily
        score = data.scores.get(cve_id)
        if score is None:
            continue
        row = daily.new[cve_id]
        for t in levels:
            key = level_key(t)
            if score[0] >= t and key not in row.cross:
                # 第一次比對的列不知道何時跨過，日期留空，不算進門檻校準。
                row.cross[key] = "" if cve_id in baseline else day_key
                changed[pub] = daily
    for daily in changed.values():
        state.save_daily(daily)

    watch = state.load_watch()
    crossing = sorted(
        i
        for i in candidates
        if i in data.scores
        and data.scores[i][0] >= cfg.thresholds.epss
        and (i not in watch or watch[i].epss_cross is None)
    )
    missing = [i for i in crossing if i not in watch]
    fill_records(state, http, missing, cfg, today, budget=len(missing))
    watch = state.load_watch()
    crossed: list[str] = []
    notified = state.load_notified()
    for cve_id in crossing:
        w = watch.get(cve_id)
        if w is None:
            continue
        w.epss_cross = epss_date
        state.save_watch(w)
        crossed.append(cve_id)
        if cve_id in baseline:
            notified.setdefault(cve_id, {})["epss"] = f"{day_key}T00:00:00Z"
    if baseline & set(crossed):
        state.save_notified(notified)
    keep = set(watch) | kev_ids
    state.save_epss_day(epss_date, {i: v for i, v in data.scores.items() if i in keep})
    state.prune_epss(epss_date)
    meta = EpssMeta(epss_date, data.model, data.score_date)
    state.save_epss_meta(meta)
    return EpssResult(meta, crossed, len(crossing) - len(crossed))


def wanted_for_epss(state: State, cfg: Config, today: date, kev_ids: set[str]) -> set[str]:
    """解析 EPSS CSV 時要保留的 CVE。EPSS 日期最晚是 today，用 today 估算候選範圍。"""
    # EPSS 停更時檔案日期比 today 早，多保留 7 天的候選。
    window = epss_candidates(state, cfg, today, extra_days=7)
    return set(window) | set(state.load_watch()) | kev_ids
