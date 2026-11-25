"""抓取並解析 CISA KEV 目錄。"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import date
from typing import Any

from starfault.http import Http

log = logging.getLogger(__name__)

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
_URL = re.compile(r"https?://[^\s;]+")


class KevFormatError(ValueError):
    """KEV 目錄缺少必要欄位。"""


@dataclass(frozen=True)
class KevEntry:
    id: str
    vendor: str
    product: str
    name: str
    desc: str
    added: date
    due: date
    ransomware: bool
    triage: bool
    action: str
    notes: str
    cwes: tuple[str, ...]

    def note_urls(self) -> list[str]:
        """notes 欄位裡的網址，依出現順序、不重複。"""
        return list(dict.fromkeys(u.rstrip(".,)") for u in _URL.findall(self.notes)))

    def to_json(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "product": self.product,
            "name": self.name,
            "desc": self.desc,
            "added": self.added.isoformat(),
            "due": self.due.isoformat(),
            "ransomware": self.ransomware,
            "triage": self.triage,
            "action": self.action,
            "notes": self.notes,
            "cwes": list(self.cwes),
        }

    @classmethod
    def from_json(cls, cve_id: str, d: dict[str, Any]) -> KevEntry:
        return cls(
            id=cve_id,
            vendor=d["vendor"],
            product=d["product"],
            name=d["name"],
            desc=d["desc"],
            added=date.fromisoformat(d["added"]),
            due=date.fromisoformat(d["due"]),
            ransomware=d["ransomware"],
            triage=d["triage"],
            action=d["action"],
            notes=d["notes"],
            cwes=tuple(d["cwes"]),
        )


@dataclass(frozen=True)
class Catalog:
    version: str
    released: str
    entries: dict[str, KevEntry]


def _text(entry: dict[str, Any], key: str) -> str:
    value = entry.get(key)
    return " ".join(value.split()) if isinstance(value, str) else ""


def _date(entry: dict[str, Any], key: str, cve_id: str) -> date:
    value = entry.get(key)
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError:
            pass
    raise KevFormatError(f"{cve_id}.{key} 不是日期：{value!r}")


def _flag(value: object, yes: str) -> bool | None:
    """KEV 的 Yes/No、Known/Unknown 欄位；值無法辨識時回傳 None。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v == yes:
            return True
        if v in ("no", "unknown"):
            return False
    return None


def parse_catalog(raw: bytes) -> Catalog:
    """解析 KEV JSON。

    必要欄位（catalogVersion、vulnerabilities、各筆的 cveID、dateAdded、dueDate）缺漏時丟出
    KevFormatError。forensicTriage 缺漏或無法辨識時當作 false，並記一行警告。
    """
    try:
        data = json.loads(raw)
    except ValueError as e:
        raise KevFormatError(f"不是 JSON：{e}") from e
    if not isinstance(data, dict):
        raise KevFormatError("最外層不是物件")
    version = data.get("catalogVersion")
    items = data.get("vulnerabilities")
    if not isinstance(version, str) or not version:
        raise KevFormatError("缺少 catalogVersion")
    if not isinstance(items, list):
        raise KevFormatError("缺少 vulnerabilities")
    entries: dict[str, KevEntry] = {}
    no_triage = 0
    for item in items:
        if not isinstance(item, dict):
            raise KevFormatError("vulnerabilities 的項目不是物件")
        cve_id = _text(item, "cveID").upper()
        if not _CVE_ID.fullmatch(cve_id):
            raise KevFormatError(f"cveID 格式錯誤：{cve_id!r}")
        if "dateAdded" not in item or "dueDate" not in item:
            raise KevFormatError(f"{cve_id} 缺少 dateAdded 或 dueDate")
        triage = _flag(item.get("forensicTriage"), "yes")
        if triage is None:
            no_triage += 1
        cwes = item.get("cwes")
        entries[cve_id] = KevEntry(
            id=cve_id,
            vendor=_text(item, "vendorProject"),
            product=_text(item, "product"),
            name=_text(item, "vulnerabilityName"),
            desc=_text(item, "shortDescription"),
            added=_date(item, "dateAdded", cve_id),
            due=_date(item, "dueDate", cve_id),
            ransomware=bool(_flag(item.get("knownRansomwareCampaignUse"), "known")),
            triage=bool(triage),
            action=_text(item, "requiredAction"),
            notes=_text(item, "notes"),
            cwes=tuple(c for c in cwes if isinstance(c, str)) if isinstance(cwes, list) else (),
        )
    if no_triage:
        log.warning("KEV：%d 筆沒有可辨識的 forensicTriage，當作不需鑑識", no_triage)
    released = data.get("dateReleased")
    return Catalog(version, released if isinstance(released, str) else "", entries)


def fetch_catalog(http: Http) -> Catalog:
    return parse_catalog(http.get(FEED_URL))
