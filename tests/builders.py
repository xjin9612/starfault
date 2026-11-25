"""測試資料：設定檔，以及虛構的 CVE 紀錄、KEV 目錄、EPSS CSV。

廠商、產品與 CVE 編號都是虛構的。
"""

from __future__ import annotations

import gzip
import io
import json
import re
import zipfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from starfault.config import Config, parse_config

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SITE_URL = "https://example.test/starfault/"
BOT_TOKEN = "123456:TEST-TOKEN"


def config_text(**values: Any) -> str:
    """repo 的 config.toml 換上指定的值，網址固定為 SITE_URL。

    鍵名在檔案裡重複時，寫成「區段__鍵」，例如 watchlist__cvss。
    """
    text = (REPO_ROOT / "config.toml").read_text(encoding="utf-8")
    values = {"url": SITE_URL} | values
    for name, value in values.items():
        section, _, key = name.rpartition("__")
        literal = repr(value) if isinstance(value, float) else json.dumps(value, ensure_ascii=False)
        start = text.index(f"[{section}]") if section else 0
        head, body = text[:start], text[start:]
        line = f"{key} = {literal}".replace("\\", "\\\\")
        body, count = re.subn(rf"(?m)^{key} = .*$", line, body, count=1)
        assert count == 1, name
        text = head + body
    return text


def make_config(**values: Any) -> Config:
    return parse_config(config_text(**values))


def cve(
    cve_id: str,
    *,
    published: str = "2026-11-24T03:00:00Z",
    updated: str | None = None,
    title: str | None = "Example flaw",
    desc: str = "An example vulnerability allows remote attackers to do harm.",
    score: float | None = 7.5,
    version: str = "3.1",
    adp_score: float | None = None,
    affected: Sequence[dict[str, Any]] = (),
    vendor: str = "Quarrel Labs",
    product: str = "Harbor SSO",
    versions: Sequence[dict[str, Any]] = (
        {"version": "0", "lessThan": "2.4.1", "status": "affected"},
    ),
    cpes: Sequence[str] = (),
    adp_affected: Sequence[dict[str, Any]] = (),
    cwe: str | None = "CWE-287",
    state: str = "PUBLISHED",
) -> dict[str, Any]:
    """CVE JSON 5 紀錄。score 是 CNA 的分數，adp_score 是 CISA ADP 的 v3.1 分數。"""
    meta = {
        "cveId": cve_id,
        "state": state,
        "datePublished": published,
        "dateUpdated": updated or published,
    }
    if state == "REJECTED":
        del meta["datePublished"]
        return {"dataType": "CVE_RECORD", "cveMetadata": meta, "containers": {"cna": {}}}
    metrics = []
    if score is not None:
        key = {"4.0": "cvssV4_0", "3.1": "cvssV3_1", "3.0": "cvssV3_0"}[version]
        metrics.append(
            {key: {"baseScore": score, "vectorString": f"CVSS:{version}/AV:N", "version": version}}
        )
    cna: dict[str, Any] = {
        "descriptions": [{"lang": "en", "value": desc}],
        "metrics": metrics,
        "affected": list(affected)
        or [{"vendor": vendor, "product": product, "versions": list(versions), "cpes": list(cpes)}],
        "references": [{"url": f"https://example.com/advisories/{cve_id}", "tags": ["patch"]}],
        "problemTypes": (
            [{"descriptions": [{"cweId": cwe, "description": f"{cwe} Example", "lang": "en"}]}]
            if cwe
            else []
        ),
    }
    if title:
        cna["title"] = title
    containers: dict[str, Any] = {"cna": cna}
    adp: dict[str, Any] = {"providerMetadata": {"shortName": "CISA-ADP"}}
    if adp_score is not None:
        adp["metrics"] = [{"cvssV3_1": {"baseScore": adp_score, "vectorString": "CVSS:3.1/AV:N"}}]
    if adp_affected:
        adp["affected"] = list(adp_affected)
    if len(adp) > 1:
        containers["adp"] = [adp]
    return {"dataType": "CVE_RECORD", "cveMetadata": meta, "containers": containers}


def kev_item(
    cve_id: str,
    *,
    added: str = "2026-11-24",
    due: str = "2026-11-27",
    vendor: str = "Halden Networks",
    product: str = "EdgeGate VPN",
    name: str = "Halden Networks EdgeGate VPN Authentication Bypass Vulnerability",
    triage: Any = "Yes",
    ransomware: str = "Unknown",
) -> dict[str, Any]:
    item = {
        "cveID": cve_id,
        "vendorProject": vendor,
        "product": product,
        "vulnerabilityName": name,
        "dateAdded": added,
        "shortDescription": f"{vendor} {product} contains a vulnerability.",
        "requiredAction": "Apply mitigations per vendor instructions.",
        "dueDate": due,
        "knownRansomwareCampaignUse": ransomware,
        "notes": f"https://example.com/{cve_id} ; https://nvd.nist.gov/vuln/detail/{cve_id}",
        "cwes": ["CWE-287"],
    }
    if triage is not None:
        item["forensicTriage"] = triage
    return item


def kev_feed(items: Sequence[dict[str, Any]], version: str = "2026.11.24") -> bytes:
    data = {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": version,
        "dateReleased": f"{version.replace('.', '-')}T14:00:00.000Z",
        "count": len(items),
        "vulnerabilities": list(items),
    }
    return json.dumps(data).encode()


def epss_csv(scores: dict[str, tuple[float, float]], score_date: str = "2026-11-24") -> bytes:
    lines = [f"#model_version:v2026.06.15,score_date:{score_date}T12:00:00Z", "cve,epss,percentile"]
    lines += [f"{i},{s},{p}" for i, (s, p) in sorted(scores.items())]
    return gzip.compress(("\n".join(lines) + "\n").encode())


def delta_zip(records: Sequence[dict[str, Any]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for r in records:
            z.writestr(f"deltaCves/{r['cveMetadata']['cveId']}.json", json.dumps(r))
    return buf.getvalue()


def fixture_record(cve_id: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / "cvelist" / f"{cve_id}.json").read_text())
    return data
