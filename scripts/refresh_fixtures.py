"""重新下載 tests/fixtures/ 的真實資料節錄：KEV、EPSS、cvelistV5 的 CVE 紀錄。

只保留測試用到的 CVE，檔案維持在幾十 KB。更新後跑一次 pytest，依實際值調整斷言。
用法：uv run python scripts/refresh_fixtures.py [UTC 日期，預設昨天]
"""

from __future__ import annotations

import gzip
import io
import json
import sys
import zipfile
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from starfault import cvelist, epss, kev
from starfault.http import Http

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
# 測試涵蓋的紀錄類型；換日期後挑出同類型的紀錄時，要一併改測試。
CVE_IDS = sorted(p.stem for p in (FIXTURES / "cvelist").glob("CVE-*.json"))
# EPSS 另外保留百分位為 1.0 的紀錄，測試百分位的顯示。
EPSS_EXTRA = {"CVE-1999-0001", "CVE-2014-3566"}


def _kev(http: Http) -> set[str]:
    data = json.loads(http.get(kev.FEED_URL))
    keep = {p.stem for p in (FIXTURES / "cvelist").glob("CVE-*.json")}
    old = json.loads((FIXTURES / "kev" / "kev.json").read_text(encoding="utf-8"))
    keep |= {v["cveID"] for v in old["vulnerabilities"]}
    items = [v for v in data["vulnerabilities"] if v["cveID"] in keep]
    data["vulnerabilities"] = items
    data["count"] = len(items)
    path = FIXTURES / "kev" / "kev.json"
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"kev.json：{len(items)} 筆，版本 {data['catalogVersion']}")
    return {v["cveID"] for v in items}


def _epss(http: Http, ids: set[str]) -> None:
    raw = http.get(epss.CSV_URL)
    lines = gzip.decompress(raw).decode().splitlines(keepends=True)
    out = lines[:2] + [line for line in lines[2:] if line.split(",")[0] in ids]
    score_date = epss.parse_csv(raw).date
    for old in (FIXTURES / "epss").glob("*.csv.gz"):
        old.unlink()
    path = FIXTURES / "epss" / f"epss_scores-{score_date}.csv.gz"
    path.write_bytes(gzip.compress("".join(out).encode(), mtime=0))
    print(f"{path.name}：{len(out) - 2} 筆")


def _records(http: Http, day: date) -> None:
    raw = http.get(cvelist.eod_url(day))
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        names = {Path(n).stem: n for n in z.namelist()}
        for cve_id in CVE_IDS:
            if cve_id in names:
                (FIXTURES / "cvelist" / f"{cve_id}.json").write_bytes(z.read(names[cve_id]))
            else:
                # 不在當天 delta 的紀錄改抓 cvelistV5 的最新版本。
                (FIXTURES / "cvelist" / f"{cve_id}.json").write_bytes(
                    http.get(cvelist.record_url(cve_id))
                )
    print(f"cvelist：{len(CVE_IDS)} 筆")


def main() -> None:
    day = (
        date.fromisoformat(sys.argv[1])
        if len(sys.argv) > 1
        else datetime.now(UTC).date() - timedelta(days=1)
    )
    with Http() as http:
        ids = _kev(http) | set(CVE_IDS)
        _epss(http, ids | EPSS_EXTRA)
        _records(http, day)


if __name__ == "__main__":
    main()
