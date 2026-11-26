"""從 CVEProject/cvelistV5 取得 CVE 紀錄：每小時與每日的 delta release，以及單筆紀錄。

hourly delta 包含當天 UTC 0 時以來新增或更新的全部紀錄；end_of_day delta 包含整個 UTC 日的。
"""

from __future__ import annotations

import io
import json
import logging
import zipfile
import zlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, datetime

from starfault.http import FetchError, Http, NotFoundError
from starfault.records import CveRecord, RecordError, parse_record

log = logging.getLogger(__name__)

RELEASES = "https://github.com/CVEProject/cvelistV5/releases/download"
RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
# 單一紀錄超過這個大小視為異常，不解壓縮。
MAX_MEMBER_BYTES = 5 * 1024 * 1024


def eod_url(day: date) -> str:
    d = day.isoformat()
    return f"{RELEASES}/cve_{d}_at_end_of_day/{d}_delta_CVEs_at_end_of_day.zip"


def hourly_url(day: date, hour: int) -> str:
    d, h = day.isoformat(), f"{hour:02d}00Z"
    return f"{RELEASES}/cve_{d}_{h}/{d}_delta_CVEs_at_{h}.zip"


def record_url(cve_id: str) -> str:
    _, year, number = cve_id.split("-")
    return f"{RAW}/{year}/{int(number) // 1000}xxx/{cve_id}.json"


class DeltaFormatError(ValueError):
    """delta 不是有效的 zip。"""


@dataclass
class Batch:
    """一或多個 delta 解析後的紀錄；同一個 CVE 只留最後讀到的版本。"""

    records: dict[str, CveRecord] = field(default_factory=dict)
    # 無法解析而略過的紀錄數。
    invalid: int = 0

    def add(self, other: Batch) -> None:
        self.records.update(other.records)
        self.invalid += other.invalid

    @property
    def rejected(self) -> int:
        return sum(1 for r in self.records.values() if r.rejected)


def parse_zip(raw: bytes) -> Batch:
    """解析 delta zip。不是 zip 時丟出 DeltaFormatError；個別紀錄損毀時計入 invalid。"""
    batch = Batch()
    try:
        z = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as e:
        raise DeltaFormatError(f"不是 zip：{e}") from None
    with z:
        for info in z.infolist():
            if info.is_dir() or not info.filename.endswith(".json"):
                continue
            if info.file_size > MAX_MEMBER_BYTES:
                batch.invalid += 1
                continue
            try:
                record = parse_record(json.loads(z.read(info)))
            except ValueError, zipfile.BadZipFile, zlib.error, EOFError:
                batch.invalid += 1
                continue
            batch.records[record.id] = record
    return batch


def _fetch_zip(http: Http, url: str) -> Batch:
    try:
        return parse_zip(http.get(url))
    except DeltaFormatError as e:
        raise FetchError(f"{url}：{e}") from None


def fetch_eod(http: Http, day: date) -> Batch | None:
    """UTC 日 day 的 end_of_day delta；還沒發布時回傳 None。"""
    try:
        return _fetch_zip(http, eod_url(day))
    except NotFoundError:
        return None


def fetch_latest_hourly(http: Http, now: datetime) -> Batch | None:
    """now 所在 UTC 日最新的 hourly delta；當天還沒有任何 release 時回傳 None。"""
    for hour in range(now.hour, -1, -1):
        try:
            batch = _fetch_zip(http, hourly_url(now.date(), hour))
        except NotFoundError:
            continue
        log.info("CVE delta：%s %02d00Z", now.date().isoformat(), hour)
        return batch
    return None


def fetch_record(http: Http, cve_id: str) -> CveRecord | None:
    """單筆紀錄；cvelistV5 沒有這筆時回傳 None。格式錯誤時丟出 RecordError。"""
    try:
        raw = http.get(record_url(cve_id))
    except NotFoundError:
        return None
    try:
        data = json.loads(raw)
    except ValueError as e:
        raise RecordError(f"{cve_id}：不是 JSON：{e}") from e
    return parse_record(data)


def fetch_utc_days(http: Http, days: Iterable[date], now: datetime) -> Batch:
    """依序讀取 UTC 日 days 的 delta：過去的日子讀 end_of_day，now 當天讀最新的 hourly。

    end_of_day 還沒發布的日子改讀那天最後一個 hourly delta。
    """
    batch = Batch()
    today = now.date()
    for day in sorted(set(days)):
        if day > today:
            continue
        if day == today:
            part = fetch_latest_hourly(http, now)
        else:
            part = fetch_eod(http, day)
            if part is None:
                log.info("CVE：%s 的 end_of_day 還沒發布，改讀當天最後的 hourly", day)
                part = fetch_latest_hourly(http, datetime.combine(day, datetime.max.time()))
        if part is not None:
            batch.add(part)
    return batch
