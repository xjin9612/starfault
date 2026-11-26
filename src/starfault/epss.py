"""抓取並解析 FIRST EPSS 每日 CSV。"""

from __future__ import annotations

import gzip
import io
import re
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date

from starfault.http import Http

CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
_HEADER = re.compile(r"#model_version:(?P<model>[^,]*),score_date:(?P<date>\S+)")


class EpssFormatError(ValueError):
    """EPSS 檔案格式不符。"""


@dataclass(frozen=True)
class EpssData:
    model: str
    # 檔頭的 score_date，ISO 8601。
    score_date: str
    # (epss, percentile)，只含 parse_csv 的 wanted 篩選後的 CVE。
    scores: dict[str, tuple[float, float]]

    @property
    def date(self) -> date:
        return date.fromisoformat(self.score_date[:10])


def parse_csv(raw: bytes, wanted: Callable[[str], bool] = lambda _: True) -> EpssData:
    """解析 gzip 壓縮的 EPSS CSV。

    第一行是 `#model_version:…,score_date:…` 註解，第二行是 `cve,epss,percentile` 欄名。
    分數或百分位數不是 0 到 1 之間數字的列略過。
    格式不符或沒有任何分數時丟出 EpssFormatError。
    """
    try:
        text = gzip.decompress(raw).decode("utf-8")
    except (OSError, EOFError, UnicodeDecodeError, zlib.error) as e:
        raise EpssFormatError(f"無法解壓縮：{e}") from e
    lines = io.StringIO(text)
    header = _HEADER.match(lines.readline().strip())
    if not header:
        raise EpssFormatError("第一行不是 model_version 與 score_date 註解")
    try:
        date.fromisoformat(header["date"][:10])
    except ValueError as e:
        raise EpssFormatError(f"score_date 不是日期：{header['date']!r}") from e
    columns = lines.readline().strip().split(",")
    if columns[:3] != ["cve", "epss", "percentile"]:
        raise EpssFormatError(f"欄名不符：{columns!r}")
    scores: dict[str, tuple[float, float]] = {}
    total = 0
    for line in lines:
        parts = line.strip().split(",")
        if len(parts) < 3:
            continue
        total += 1
        cve_id = parts[0].upper()
        if not wanted(cve_id):
            continue
        try:
            score, percentile = float(parts[1]), float(parts[2])
        except ValueError:
            continue
        # 這個比較也排除 nan。
        if 0 <= score <= 1 and 0 <= percentile <= 1:
            scores[cve_id] = (score, percentile)
    if not total:
        raise EpssFormatError("沒有任何分數")
    return EpssData(header["model"], header["date"], scores)


def fetch(http: Http, wanted: Callable[[str], bool]) -> EpssData:
    return parse_csv(http.get(CSV_URL), wanted)
