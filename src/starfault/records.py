"""解析 CVE JSON 5 紀錄，取出網站、規則與技術棧比對用的欄位。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

SEVERITIES = ("critical", "high", "medium", "low", "none")
CISA_ADP = "CISA-ADP"
# CNA 的分數依此順序選用，都沒有時改用 CISA ADP 的 v3.1。
_CNA_METRICS = (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"))
TITLE_MAX = 120
# 受影響版本與修補版本最多列出幾個，其餘以「…」表示。
VERSIONS_MAX = 4
# 超過這個長度的版本字串（例如 purl）不列出。
VERSION_MAX_LEN = 40
REFERENCES_MAX = 30
_NO_VALUE = frozenset({"", "n/a", "unknown", "-", "*"})
_SENTENCE_END = re.compile(r"(?<=[.!?])\s")


class RecordError(ValueError):
    """紀錄缺少必要欄位或格式錯誤。"""


def severity(score: float | None) -> str:
    """CVSS v3.x 與 v4.0 共用的嚴重度區間。"""
    if score is None or score <= 0:
        return "none"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


@dataclass(frozen=True)
class Cvss:
    score: float
    version: str
    # vendor（CNA）或 cisa-adp。
    source: str
    vector: str

    @property
    def sev(self) -> str:
        return severity(self.score)

    def to_json(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "version": self.version,
            "sev": self.sev,
            "source": self.source,
            "vector": self.vector,
        }


@dataclass(frozen=True)
class Affected:
    vendor: str
    product: str
    # 顯示用的受影響版本摘要；不明時為空字串。
    versions: str
    # 顯示用的修補版本；不明時為 None。
    fixed: str | None
    # CPE 的 (vendor, product)，給技術棧比對用。
    cpes: tuple[tuple[str, str], ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "product": self.product,
            "versions": self.versions,
            "fixed": self.fixed,
        }


@dataclass(frozen=True)
class CveRecord:
    id: str
    # REJECTED 的紀錄只有 id、state、updated。
    state: str
    published: datetime | None
    updated: datetime | None
    title: str | None
    desc: str
    cvss: Cvss | None
    cwe: tuple[tuple[str, str], ...] = ()
    affected: tuple[Affected, ...] = ()
    references: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # CISA ADP 補上的受影響產品，只用於技術棧比對。
    adp_affected: tuple[Affected, ...] = field(default=())

    @property
    def rejected(self) -> bool:
        return self.state != "PUBLISHED"

    def vendor_product(self) -> tuple[str, str]:
        """顯示用的廠商與產品：第一個兩者都有值的受影響項目。"""
        for a in (*self.affected, *self.adp_affected):
            if a.vendor.lower() not in _NO_VALUE and a.product.lower() not in _NO_VALUE:
                return a.vendor, a.product
        return "", ""

    def display_title(self, kev_name: str | None = None) -> str:
        """CNA 的標題；沒有時用 KEV 的名稱；再沒有時取描述第一句。"""
        if self.title:
            return self.title
        if kev_name:
            return kev_name
        return first_sentence(self.desc)


def first_sentence(text: str) -> str:
    text = " ".join(text.split())
    sentence = _SENTENCE_END.split(text, maxsplit=1)[0]
    if len(sentence) <= TITLE_MAX:
        return sentence
    return sentence[: TITLE_MAX - 1].rstrip() + "…"


def parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _str(value: object) -> str:
    return " ".join(value.split()) if isinstance(value, str) else ""


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _description(cna: dict[str, Any]) -> str:
    items = [_dict(d) for d in _list(cna.get("descriptions"))]
    for d in items:
        if _str(d.get("lang")).lower().startswith("en") and _str(d.get("value")):
            return _str(d.get("value"))
    return next((_str(d.get("value")) for d in items if _str(d.get("value"))), "")


def _metric(metrics: list[Any], key: str, version: str, source: str) -> Cvss | None:
    for m in metrics:
        data = _dict(_dict(m).get(key))
        score = data.get("baseScore")
        if isinstance(score, bool) or not isinstance(score, int | float):
            continue
        if not 0 <= score <= 10:
            continue
        return Cvss(float(score), version, source, _str(data.get("vectorString")))
    return None


def _cvss(cna: dict[str, Any], cisa: list[dict[str, Any]]) -> Cvss | None:
    metrics = _list(cna.get("metrics"))
    for key, version in _CNA_METRICS:
        found = _metric(metrics, key, version, "vendor")
        if found:
            return found
    for adp in cisa:
        found = _metric(_list(adp.get("metrics")), "cvssV3_1", "3.1", "cisa-adp")
        if found:
            return found
    return None


def _cwes(container: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for pt in _list(container.get("problemTypes")):
        for d in _list(_dict(pt).get("descriptions")):
            cwe = _str(_dict(d).get("cweId"))
            if not re.fullmatch(r"CWE-\d+", cwe) or any(c == cwe for c, _ in out):
                continue
            name = _str(_dict(d).get("description"))
            name = re.sub(rf"^{cwe}:?\s*", "", name)
            out.append((cwe, name))
    return out


def _cpe(value: str) -> tuple[str, str] | None:
    """cpe:2.3:a:vendor:product:... 或 cpe:/a:vendor:product:... 的 (vendor, product)。

    跳脫規則依 NISTIR 7695：2.3 以反斜線跳脫，2.2 以百分比編碼。
    https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
    """
    if value.startswith("cpe:2.3:"):
        parts = _split_cpe23(value)
        return (parts[3], parts[4]) if len(parts) > 4 else None
    if value.startswith("cpe:/"):
        parts = [unquote(p) for p in value[5:].split(":")]
        return (parts[1], parts[2]) if len(parts) > 2 else None
    return None


def _split_cpe23(value: str) -> list[str]:
    fields: list[str] = []
    current: list[str] = []
    chars = iter(value)
    for ch in chars:
        if ch == "\\":
            current.append(next(chars, ""))
        elif ch == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(ch)
    fields.append("".join(current))
    return fields


def _usable_version(version: dict[str, Any], key: str) -> str | None:
    value = _str(version.get(key))
    if (
        value.lower() in _NO_VALUE
        or value == "0"
        or len(value) > VERSION_MAX_LEN
        or version.get("versionType") == "git"
    ):
        return None
    return value


def _join(values: list[str]) -> str:
    unique = list(dict.fromkeys(values))
    if len(unique) > VERSIONS_MAX:
        return ", ".join(unique[:VERSIONS_MAX]) + "…"
    return ", ".join(unique)


def _affected(entry: dict[str, Any]) -> Affected:
    vendor = _str(entry.get("vendor"))
    product = _str(entry.get("product")) or _str(entry.get("packageName"))
    ranges: list[str] = []
    fixed: list[str] = []
    for v in (_dict(x) for x in _list(entry.get("versions"))):
        if v.get("versionType") == "git":
            continue
        start = _usable_version(v, "version")
        less = _usable_version(v, "lessThan")
        less_eq = _usable_version(v, "lessThanOrEqual")
        if v.get("status") == "unaffected":
            if start and not less and not less_eq:
                fixed.append(start)
            continue
        if v.get("status") != "affected":
            continue
        if less:
            ranges.append(f"{start} – < {less}" if start else f"< {less}")
            fixed.append(less)
        elif less_eq:
            ranges.append(f"{start} – {less_eq}" if start else f"≤ {less_eq}")
        elif start:
            ranges.append(start)
    cpes = tuple(
        dict.fromkeys(
            pair
            for pair in (_cpe(_str(c)) for c in _list(entry.get("cpes")))
            if pair is not None and pair[1] not in _NO_VALUE
        )
    )
    return Affected(vendor, product, _join(ranges), _join(fixed) or None, cpes)


def _references(
    cna: dict[str, Any], adps: list[dict[str, Any]]
) -> list[tuple[str, tuple[str, ...]]]:
    out: dict[str, tuple[str, ...]] = {}
    for container in (cna, *adps):
        for ref in (_dict(r) for r in _list(container.get("references"))):
            url = _str(ref.get("url"))
            if not url.startswith(("https://", "http://")) or url in out:
                continue
            tags = tuple(t for t in (_str(x) for x in _list(ref.get("tags"))) if t)
            out[url] = tags
    return list(out.items())[:REFERENCES_MAX]


def parse_record(data: object) -> CveRecord:
    """解析一筆 CVE JSON 5 紀錄。缺少 cveId 或 state 時丟出 RecordError。"""
    root = _dict(data)
    meta = _dict(root.get("cveMetadata"))
    cve_id = _str(meta.get("cveId")).upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        raise RecordError(f"cveMetadata.cveId 格式錯誤：{cve_id!r}")
    state = _str(meta.get("state"))
    if state not in ("PUBLISHED", "REJECTED"):
        raise RecordError(f"{cve_id}：未知的 state {state!r}")
    updated = parse_time(meta.get("dateUpdated"))
    if state == "REJECTED":
        return CveRecord(cve_id, state, None, updated, None, "", None)
    containers = _dict(root.get("containers"))
    cna = _dict(containers.get("cna"))
    if not cna:
        raise RecordError(f"{cve_id}：缺少 containers.cna")
    adps = [_dict(a) for a in _list(containers.get("adp"))]
    cisa = [a for a in adps if _dict(a.get("providerMetadata")).get("shortName") == CISA_ADP]
    published = parse_time(meta.get("datePublished"))
    if published is None:
        raise RecordError(f"{cve_id}：缺少 datePublished")
    cwes = _cwes(cna) or [c for a in cisa for c in _cwes(a)]
    return CveRecord(
        id=cve_id,
        state=state,
        published=published,
        updated=updated or published,
        title=_str(cna.get("title")) or None,
        desc=_description(cna),
        cvss=_cvss(cna, cisa),
        cwe=tuple(dict.fromkeys(cwes)),
        affected=tuple(_affected(_dict(a)) for a in _list(cna.get("affected"))),
        references=tuple(_references(cna, adps)),
        adp_affected=tuple(_affected(_dict(x)) for a in cisa for x in _list(a.get("affected"))),
    )


def _affected_json(a: Affected) -> dict[str, Any]:
    return a.to_json() | {"cpes": [list(p) for p in a.cpes]}


def _affected_from(d: dict[str, Any]) -> Affected:
    return Affected(
        vendor=d["vendor"],
        product=d["product"],
        versions=d["versions"],
        fixed=d["fixed"],
        cpes=tuple((v, p) for v, p in d.get("cpes", [])),
    )


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value else None


def record_to_json(r: CveRecord) -> dict[str, Any]:
    """關注清單（state/watch）保存的紀錄欄位，可由 record_from_json 還原。"""
    return {
        "id": r.id,
        "state": r.state,
        "published": _iso(r.published),
        "updated": _iso(r.updated),
        "title": r.title,
        "desc": r.desc,
        "cvss": r.cvss.to_json() if r.cvss else None,
        "cwe": [{"id": c, "name": n} for c, n in r.cwe],
        "affected": [_affected_json(a) for a in r.affected],
        "adp_affected": [_affected_json(a) for a in r.adp_affected],
        "references": [{"url": u, "tags": list(t)} for u, t in r.references],
    }


def record_from_json(d: dict[str, Any]) -> CveRecord:
    c = d["cvss"]
    return CveRecord(
        id=d["id"],
        state=d["state"],
        published=parse_time(d["published"]),
        updated=parse_time(d["updated"]),
        title=d["title"],
        desc=d["desc"],
        cvss=Cvss(c["score"], c["version"], c["source"], c["vector"]) if c else None,
        cwe=tuple((x["id"], x["name"]) for x in d["cwe"]),
        affected=tuple(_affected_from(a) for a in d["affected"]),
        adp_affected=tuple(_affected_from(a) for a in d["adp_affected"]),
        references=tuple((x["url"], tuple(x["tags"])) for x in d["references"]),
    )
