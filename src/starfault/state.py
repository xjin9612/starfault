"""state/ 底下的狀態檔。格式見 docs/DEVELOPMENT.md「狀態檔」。

狀態檔會 commit 進公開的 repo，不得寫入任何技術棧清單的內容或比對結果。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

from starfault.jsonio import read_json, write_json
from starfault.kev import KevEntry
from starfault.records import CveRecord, record_from_json, record_to_json

# 每日新 CVE 紀錄保留天數。
DAILY_KEEP_DAYS = 90
# EPSS 每日分數保留天數，詳細頁的走勢圖用。
EPSS_KEEP_DAYS = 30
# 關注清單在最後一個事件後保留的天數；KEV 項目不受限。
WATCH_KEEP_DAYS = 90
SOURCES = ("cve", "kev", "epss")


@dataclass
class Row:
    """一筆新 CVE 的精簡紀錄。"""

    score: float | None
    sev: str
    # 校準門檻（見 level_key）→ EPSS 首次達到該門檻的日期。
    cross: dict[str, str] = field(default_factory=dict)


@dataclass
class Daily:
    """某一天（site.timezone）發布的新 CVE，以及當天第一次有 CVSS 的 CVE。"""

    day: date
    new: dict[str, Row] = field(default_factory=dict)
    # CVE → (分數, 嚴重度)
    rescored: dict[str, tuple[float, str]] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "date": self.day.isoformat(),
            "new": [[i, r.score, r.sev, r.cross or None] for i, r in sorted(self.new.items())],
            "rescored": [[i, s, sev] for i, (s, sev) in sorted(self.rescored.items())],
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> Daily:
        return cls(
            day=date.fromisoformat(d["date"]),
            new={i: Row(s, sev, dict(x or {})) for i, s, sev, x in d["new"]},
            rescored={i: (s, sev) for i, s, sev in d["rescored"]},
        )


@dataclass
class Watch:
    """關注清單的一筆 CVE。"""

    record: CveRecord
    # EPSS 首次跨過 thresholds.epss 的 EPSS 資料日期。
    epss_cross: date | None = None
    # 第一次符合 Critical 規則（發布 7 天內且 CVSS ≥ thresholds.cvss）的日期。
    critical: date | None = None

    @property
    def id(self) -> str:
        return self.record.id

    def to_json(self) -> dict[str, Any]:
        return record_to_json(self.record) | {
            "epss_cross": self.epss_cross.isoformat() if self.epss_cross else None,
            "critical": self.critical.isoformat() if self.critical else None,
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> Watch:
        return cls(
            record=record_from_json(d),
            epss_cross=date.fromisoformat(d["epss_cross"]) if d["epss_cross"] else None,
            critical=date.fromisoformat(d["critical"]) if d["critical"] else None,
        )


@dataclass
class KevState:
    version: str
    released: str
    entries: dict[str, KevEntry]
    # 偵測到新增、還沒推播成功的 CVE → 偵測日期。
    pending: dict[str, date] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "catalogVersion": self.version,
            "dateReleased": self.released,
            "count": len(self.entries),
            "items": {i: e.to_json() for i, e in self.entries.items()},
            "pending": {i: d.isoformat() for i, d in self.pending.items()},
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> KevState:
        return cls(
            version=d["catalogVersion"],
            released=d["dateReleased"],
            entries={i: KevEntry.from_json(i, e) for i, e in d["items"].items()},
            pending={i: date.fromisoformat(v) for i, v in d["pending"].items()},
        )


@dataclass(frozen=True)
class EpssMeta:
    date: date
    model: str
    score_date: str


def level_key(threshold: float) -> str:
    """校準門檻的鍵，例如 0.1 → "0.1"。"""
    return f"{threshold:g}"


def iso_now(now: datetime) -> str:
    return now.isoformat(timespec="seconds").replace("+00:00", "Z")


class State:
    def __init__(self, root: Path) -> None:
        self.root = root

    # ---- KEV ----
    @property
    def _kev_path(self) -> Path:
        return self.root / "kev.json"

    def load_kev(self) -> KevState | None:
        return KevState.from_json(read_json(self._kev_path)) if self._kev_path.is_file() else None

    def save_kev(self, kev: KevState) -> None:
        write_json(self._kev_path, kev.to_json())

    # ---- 已通知 ----
    def load_notified(self) -> dict[str, dict[str, str]]:
        path = self.root / "notified.json"
        loaded: dict[str, dict[str, str]] = read_json(path) if path.is_file() else {}
        return loaded

    def save_notified(self, notified: dict[str, dict[str, str]]) -> None:
        write_json(self.root / "notified.json", notified)

    # ---- 每日摘要進度 ----
    def load_digest_day(self) -> date | None:
        path = self.root / "digest.json"
        return date.fromisoformat(read_json(path)["last_day"]) if path.is_file() else None

    def save_digest_day(self, day: date) -> None:
        write_json(self.root / "digest.json", {"last_day": day.isoformat()})

    # ---- 資料來源狀態 ----
    def load_sources(self) -> dict[str, dict[str, Any]]:
        path = self.root / "sources.json"
        loaded: dict[str, dict[str, Any]] = read_json(path) if path.is_file() else {}
        return {k: loaded.get(k, {"at": None, "ok": False}) for k in SOURCES}

    def mark_source(self, name: str, ok: bool, now: datetime) -> None:
        """記錄一次讀取結果；失敗時保留上次成功的時間。"""
        sources = self.load_sources()
        previous = sources[name]
        sources[name] = {"at": iso_now(now) if ok else previous["at"], "ok": ok}
        write_json(self.root / "sources.json", sources)

    # ---- cvelist 進度 ----
    def load_cvelist(self) -> tuple[date | None, date | None]:
        """(已讀過 end_of_day delta 的最後一個 UTC 日, 每日紀錄完整的第一天)。"""
        path = self.root / "cvelist.json"
        if not path.is_file():
            return None, None
        d = read_json(path)
        return date.fromisoformat(d["eod_through"]), date.fromisoformat(d["since"])

    def save_cvelist(self, eod_through: date, since: date) -> None:
        write_json(
            self.root / "cvelist.json",
            {"eod_through": eod_through.isoformat(), "since": since.isoformat()},
        )

    # ---- 關注清單 ----
    @property
    def _watch_dir(self) -> Path:
        return self.root / "watch"

    def load_watch(self) -> dict[str, Watch]:
        if not self._watch_dir.is_dir():
            return {}
        out: dict[str, Watch] = {}
        for path in sorted(self._watch_dir.glob("CVE-*.json")):
            w = Watch.from_json(read_json(path))
            out[w.id] = w
        return out

    def save_watch(self, w: Watch) -> None:
        write_json(self._watch_dir / f"{w.id}.json", w.to_json())

    def delete_watch(self, cve_id: str) -> None:
        (self._watch_dir / f"{cve_id}.json").unlink(missing_ok=True)

    # ---- 每日新 CVE ----
    @property
    def _daily_dir(self) -> Path:
        return self.root / "daily"

    def daily_days(self) -> list[date]:
        if not self._daily_dir.is_dir():
            return []
        return sorted(date.fromisoformat(p.stem) for p in self._daily_dir.glob("*.json"))

    def load_daily(self, day: date) -> Daily:
        path = self._daily_dir / f"{day.isoformat()}.json"
        return Daily.from_json(read_json(path)) if path.is_file() else Daily(day)

    def save_daily(self, daily: Daily) -> None:
        write_json(self._daily_dir / f"{daily.day.isoformat()}.json", daily.to_json())

    def prune_daily(self, today: date) -> None:
        for day in self.daily_days():
            if (today - day).days >= DAILY_KEEP_DAYS:
                (self._daily_dir / f"{day.isoformat()}.json").unlink()

    # ---- EPSS ----
    def load_epss_meta(self) -> EpssMeta | None:
        path = self.root / "epss.json"
        if not path.is_file():
            return None
        d = read_json(path)
        return EpssMeta(date.fromisoformat(d["date"]), d["model"], d["score_date"])

    def save_epss_meta(self, meta: EpssMeta) -> None:
        write_json(
            self.root / "epss.json",
            {"date": meta.date.isoformat(), "model": meta.model, "score_date": meta.score_date},
        )

    @property
    def _epss_dir(self) -> Path:
        return self.root / "epss"

    def epss_days(self) -> list[date]:
        if not self._epss_dir.is_dir():
            return []
        return sorted(date.fromisoformat(p.stem) for p in self._epss_dir.glob("*.json"))

    def load_epss_day(self, day: date) -> dict[str, tuple[float, float]]:
        path = self._epss_dir / f"{day.isoformat()}.json"
        if not path.is_file():
            return {}
        return {i: (s, p) for i, (s, p) in read_json(path)["scores"].items()}

    def save_epss_day(self, day: date, scores: dict[str, tuple[float, float]]) -> None:
        write_json(
            self._epss_dir / f"{day.isoformat()}.json",
            {"date": day.isoformat(), "scores": {i: list(v) for i, v in scores.items()}},
        )

    def prune_epss(self, latest: date) -> None:
        for day in self.epss_days():
            if (latest - day).days >= EPSS_KEEP_DAYS:
                (self._epss_dir / f"{day.isoformat()}.json").unlink()
