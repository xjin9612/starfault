"""從狀態檔產生網站：複製 web/、填入 index.html，寫出 data/*.json。

格式見 docs/DEVELOPMENT.md「網站資料」。網站是公開的：只輸出公開規則收錄的 CVE，不讀技術棧清單。
"""

from __future__ import annotations

import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from starfault.config import Config
from starfault.jsonio import write_compact
from starfault.kev import CATALOG_URL
from starfault.records import SEVERITIES
from starfault.site_page import SOCIAL_PREVIEW, fill_index
from starfault.state import State, iso_now, level_key
from starfault.track import epss_levels, local_date
from starfault.translate import lookup
from starfault.view import Entry, SiteView, build_view

# 今日頁圖表的天數。
CHART_DAYS = 30
# 門檻校準表看最近幾個完整的日子。
CALIBRATION_DAYS = 7
# 門檻校準表列出的 CVSS 門檻；設定的門檻不在其中時另外加入。
CVSS_LEVELS = (9.0, 9.5, 10.0)


@dataclass(frozen=True)
class SiteStats:
    cves: int
    kev: int
    details: int


class _Text:
    def __init__(self, cfg: Config, translations: Mapping[str, str]) -> None:
        self.enabled = bool(cfg.translation.target)
        self.translations = translations

    def tr(self, text: str) -> str | None:
        return lookup(self.translations, text) if self.enabled else None


def _cvss(e: Entry, with_vector: bool = False) -> dict[str, Any] | None:
    if e.cvss is None:
        return None
    out = e.cvss.to_json()
    if not with_vector:
        del out["vector"]
    return out


def _epss(e: Entry) -> dict[str, Any] | None:
    if e.epss is None:
        return None
    return {"s": e.epss.s, "p": e.epss.p, "date": e.epss.date.isoformat()}


def _kev(e: Entry) -> dict[str, Any] | None:
    if e.kev is None:
        return None
    k = e.kev
    return {
        "added": k.added.isoformat(),
        "due": k.due.isoformat(),
        "ransomware": k.ransomware,
        "triage": k.triage,
    }


def _with_tr(item: dict[str, Any], key: str, text: str, tx: _Text) -> dict[str, Any]:
    found = tx.tr(text)
    if found:
        item[f"{key}_tr"] = found
    return item


def _cve_item(e: Entry, cfg: Config, tx: _Text) -> dict[str, Any]:
    item = {
        "id": e.id,
        "title": e.title,
        "vendor": e.vendor,
        "product": e.product,
        "published": e.published.isoformat() if e.published else None,
        "cvss": _cvss(e),
        "epss": _epss(e),
        "epss_cross": e.epss_cross.isoformat() if e.epss_cross else None,
        "kev": _kev(e),
        "reasons": e.reasons(cfg),
    }
    return _with_tr(item, "title", e.title, tx)


def _kev_item(e: Entry, tx: _Text) -> dict[str, Any]:
    assert e.kev is not None
    item = {
        "id": e.id,
        "title": e.title,
        "vendor": e.vendor,
        "product": e.product,
        "cvss": _cvss(e),
        "epss": _epss(e),
        "added": e.kev.added.isoformat(),
        "due": e.kev.due.isoformat(),
        "ransomware": e.kev.ransomware,
        "triage": e.kev.triage,
    }
    return _with_tr(item, "title", e.title, tx)


def _detail(
    e: Entry, epss_hist: list[dict[str, Any]], first_epss: date | None, tx: _Text
) -> dict[str, Any]:
    r, k = e.record, e.kev
    if r is not None:
        cwe = [{"id": c, "name": n} for c, n in r.cwe]
        affected = [a.to_json() for a in r.affected if a.vendor or a.product]
        refs = [{"url": u, "tags": list(t)} for u, t in r.references]
    else:
        cwe = [{"id": c, "name": ""} for c in (k.cwes if k else ())]
        affected = [{"vendor": e.vendor, "product": e.product, "versions": "", "fixed": None}]
        refs = [{"url": u, "tags": []} for u in (k.note_urls() if k else [])]
    if k is not None:
        refs.append({"url": CATALOG_URL, "tags": ["kev"]})
    timeline = []
    if e.published:
        timeline.append({"date": e.published.isoformat(), "type": "published"})
    if first_epss:
        timeline.append({"date": first_epss.isoformat(), "type": "epss_first"})
    if e.epss_cross:
        timeline.append({"date": e.epss_cross.isoformat(), "type": "epss_cross"})
    if k:
        timeline.append({"date": k.added.isoformat(), "type": "kev"})
    order = ["published", "epss_first", "epss_cross", "kev"]
    timeline.sort(key=lambda x: (x["date"], order.index(x["type"])))
    detail: dict[str, Any] = {
        "id": e.id,
        "desc": e.desc,
        "cvss": _cvss(e, with_vector=True),
        "cwe": cwe,
        "affected": affected,
        "references": refs,
        "epss_hist": epss_hist,
        "kev": (_kev(e) or {}) | {"action": k.action, "notes": k.notes} if k else None,
        "timeline": timeline,
    }
    return _with_tr(detail, "desc", e.desc, tx)


def _epss_history(state: State) -> tuple[dict[str, list[dict[str, Any]]], date | None]:
    """CVE → 近 EPSS_KEEP_DAYS 天的分數，以及保存的第一天。"""
    hist: dict[str, list[dict[str, Any]]] = {}
    days = state.epss_days()
    for day in days:
        for cve_id, (s, p) in state.load_epss_day(day).items():
            hist.setdefault(cve_id, []).append({"d": day.isoformat(), "s": s, "p": p})
    return hist, (days[0] if days else None)


def _tracked_since(e: Entry) -> date | None:
    """因 Critical 或 KEV 開始保存 EPSS 分數的日子。

    epss/ 只保存已在關注清單或 KEV 的 CVE。開始保存之後才第一次有分數，走勢的第一天
    才是第一次有 EPSS 的日子；因 EPSS 跨過才加入的 CVE 不知道更早的分數。
    """
    days = [d for d in (e.watch.critical if e.watch else None, e.kev.added if e.kev else None) if d]
    return min(days) if days else None


def _daily(state: State, today: date) -> list[dict[str, Any]]:
    """近 CHART_DAYS 天每日新 CVE 數；第一筆紀錄之前的日子不列。"""
    days = state.daily_days()
    if not days:
        return []
    first = max(days[0], today - timedelta(days=CHART_DAYS - 1))
    out = []
    for i in range((today - first).days + 1):
        day = first + timedelta(days=i)
        daily = state.load_daily(day)
        sev = dict.fromkeys(SEVERITIES, 0)
        for row in daily.new.values():
            sev[row.sev] += 1
        out.append({"date": day.isoformat(), "total": len(daily.new), "sev": sev})
    return out


def _stats(state: State, cfg: Config, view: SiteView, today: date) -> dict[str, Any]:
    """門檻校準：最近 CALIBRATION_DAYS 個完整的日子，各門檻每天平均會推播幾則。

    計算方式見 docs/DEVELOPMENT.md「門檻校準」。平均以期間內有每日紀錄的天數為分母。
    """
    end = today - timedelta(days=1)
    start = end - timedelta(days=CALIBRATION_DAYS - 1)
    recorded = set(state.daily_days())
    window = [start + timedelta(days=i) for i in range(CALIBRATION_DAYS)]
    have = [d for d in window if d in recorded]
    epss_counts = dict.fromkeys(epss_levels(cfg), 0)
    cvss_levels = sorted({*CVSS_LEVELS, cfg.thresholds.cvss})
    cvss_counts = dict.fromkeys(cvss_levels, 0)
    new_cves = 0
    look_back = start - timedelta(days=cfg.thresholds.epss_window_days - 1)
    dailies = [state.load_daily(d) for d in sorted(recorded) if look_back <= d <= end]
    # 補上分數的 CVE 只算在補上分數那天。
    rescored = {i for daily in dailies for i in daily.rescored}
    for daily in dailies:
        for row in daily.new.values():
            for t in epss_counts:
                crossed = row.cross.get(level_key(t))
                if crossed and start.isoformat() <= crossed <= end.isoformat():
                    epss_counts[t] += 1
        if daily.day < start:
            continue
        new_cves += len(daily.new)
        scores = [r.score for i, r in daily.new.items() if i not in rescored]
        scores += [s for s, _ in daily.rescored.values()]
        for t in cvss_levels:
            cvss_counts[t] += sum(1 for s in scores if s is not None and s >= t)
    n = len(have)
    kev_added = sum(1 for e in view.kev if e.kev and start <= e.kev.added <= end)

    def per_day(count: int) -> float:
        return round(count / n, 1) if n else 0.0

    return {
        "window": {
            "from": start.isoformat(),
            "to": end.isoformat(),
            "days": n,
            "new_cves": new_cves,
        },
        "epss": [{"t": t, "per_day": per_day(c)} for t, c in epss_counts.items()],
        "cvss": [{"t": t, "per_day": per_day(c)} for t, c in cvss_counts.items()],
        "kev_per_day": round(kev_added / CALIBRATION_DAYS, 1),
    }


def _meta(
    state: State,
    cfg: Config,
    view: SiteView,
    today: date,
    now: datetime,
) -> dict[str, Any]:
    sources = state.load_sources()
    kev_state = view.kev_state
    epss_meta = state.load_epss_meta()
    th = cfg.thresholds
    return {
        "generated_at": iso_now(now),
        "locale": cfg.site.locale,
        "timezone": cfg.site.timezone.key,
        "today": today.isoformat(),
        "translation": cfg.translation.target,
        "thresholds": {
            "epss": th.epss,
            "cvss": th.cvss,
            "epss_window_days": th.epss_window_days,
            "stack_cvss": cfg.watchlist.cvss,
            "calibrating_until": th.calibrating_until.isoformat() if th.calibrating_until else None,
        },
        "sources": {
            "cve": sources["cve"],
            "kev": sources["kev"]
            | {
                "version": kev_state.version if kev_state else None,
                "count": len(kev_state.entries) if kev_state else 0,
            },
            "epss": sources["epss"] | {"date": epss_meta.date.isoformat() if epss_meta else None},
        },
    }


def build_site(
    state: State,
    cfg: Config,
    out_dir: Path,
    web_dir: Path,
    assets_dir: Path,
    now: datetime,
    translations: Mapping[str, str],
    github_repo: str | None,
) -> SiteStats:
    """清空 out_dir 後重新產生整個網站。translations 是 translation.target 的譯文。"""
    today = local_date(now, cfg.site.timezone)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    shutil.copytree(web_dir, out_dir)
    for name in ("icon.svg", SOCIAL_PREVIEW):
        shutil.copyfile(assets_dir / name, out_dir / name)
    index = out_dir / "index.html"
    index.write_text(fill_index(index.read_text(encoding="utf-8"), cfg, github_repo), "utf-8")

    data = out_dir / "data"
    tx = _Text(cfg, translations)
    view = build_view(state, cfg, today)
    daily = _daily(state, today)
    write_compact(data / "meta.json", _meta(state, cfg, view, today, now))
    write_compact(data / "cves.json", {"items": [_cve_item(e, cfg, tx) for e in view.cves]})
    write_compact(data / "kev.json", {"items": [_kev_item(e, tx) for e in view.kev]})
    write_compact(data / "daily.json", {"days": daily})
    write_compact(data / "stats.json", _stats(state, cfg, view, today))
    hist, first_day = _epss_history(state)
    details = {e.id: e for e in (*view.cves, *view.kev)}
    for cve_id, e in details.items():
        h = hist.get(cve_id, [])
        first = None
        tracked = _tracked_since(e)
        if h and first_day and tracked and first_day <= tracked < date.fromisoformat(h[0]["d"]):
            first = date.fromisoformat(h[0]["d"])
        write_compact(data / "cve" / f"{cve_id}.json", _detail(e, h, first, tx))
    return SiteStats(len(view.cves), len(view.kev), len(details))
