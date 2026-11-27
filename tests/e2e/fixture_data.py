"""瀏覽器測試用的狀態檔：直接寫入 state/，再由 starfault site 產生網站。

CVE 編號、廠商、產品都是虛構的。今天是台灣 2026-11-25，資料涵蓋各頁面需要的情況：

- KEV 26 筆：近 7 天 4 筆、近 30 天 10 筆、近 90 天 17 筆；CVE-2026-94440 今天到期、需鑑識、有翻譯。
  兩筆舊的 KEV 沒有完整紀錄，詳細頁改用 KEV 目錄的內容。
- EPSS 跨過門檻 10 筆，其中近 7 天 5 筆；沒有 Low 嚴重度。
- Critical 9 筆，都在近 7 天發布，大多還沒有 EPSS。
- 每日新 CVE：2026-10-27 到今天，共 30 天；今天 61 筆。
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from starfault import translate
from starfault.jsonio import write_json
from starfault.kev import KevEntry
from starfault.records import parse_record, severity
from starfault.state import Daily, EpssMeta, KevState, Row, State, Watch
from tests.builders import cve

TODAY = date(2026, 11, 25)
GENERATED_AT = datetime(2026, 11, 25, 3, 20, tzinfo=UTC)
# 瀏覽器時鐘：台灣 2026-11-25 12:00。
NOW = datetime(2026, 11, 25, 4, 0, tzinfo=UTC)
KEV_VERSION = "2026.11.24"
FOCUS = "CVE-2026-94440"

PRODUCTS = [
    ("Halden Networks", "EdgeGate VPN"),
    ("Corvane", "FileRelay MFT"),
    ("Kestrel", "Kestrel CMS"),
    ("Ostrava Systems", "OrbitDesk"),
    ("Mireo", "Ledger Print Server"),
    ("Bluefen", "TernDB"),
    ("Talvik", "PulseRouter"),
    ("Pellmar", "CivicForms"),
    ("Vantor", "StreamVault NAS"),
    ("Lumio", "Lumio Mail Gateway"),
    ("Ardent", "Ardent Backup"),
    ("Nimbra", "Nimbra Kubernetes Agent"),
]
FLAWS = [
    ("Authentication Bypass", "驗證繞過"),
    ("Remote Code Execution", "遠端程式碼執行"),
    ("SQL Injection", "SQL 注入"),
    ("Path Traversal", "路徑穿越"),
    ("Server-Side Request Forgery", "伺服器端請求偽造"),
    ("Heap Buffer Overflow", "堆積緩衝區溢位"),
]
ACTION = "Apply mitigations per vendor instructions, or discontinue use of the product."

# (列入 KEV 距今天數, 期限天數, 勒索軟體, 需鑑識, CVSS)
KEV_ROWS = [
    (0, 3, False, True, 9.8),
    (1, 14, False, False, 8.8),
    (3, 3, False, True, 8.6),  # FOCUS：今天到期
    (5, 3, True, True, None),
    (9, 14, False, False, 7.5),
    (12, 14, True, False, 9.1),
    (15, 3, False, True, 8.1),
    (20, 14, False, False, 7.2),
    (25, 3, False, True, 9.8),
    (28, 14, False, False, 6.5),
    (35, 14, False, False, 8.8),
    (40, 3, False, True, 7.8),
    (50, 14, False, False, 9.8),
    (60, 21, True, False, 8.1),
    (70, 21, False, False, 7.5),
    (80, 21, False, False, 9.8),
    (85, 21, False, False, 7.8),
    (100, 21, False, False, 8.8),
    (150, 21, False, False, 9.8),
    (200, 21, False, False, 7.5),
    (300, 21, False, False, 8.1),
    (400, 21, True, False, 9.8),
    (500, 21, False, False, 7.8),
    (700, 14, False, False, 8.8),
    (900, 14, False, False, 9.8),
    (1200, 14, False, False, 7.5),
]
# 沒有完整紀錄的 KEV（KEV_ROWS 的索引）。
KEV_WITHOUT_RECORD = {23, 25}
# (發布距今天數, EPSS 跨過距今天數, CVSS)
EPSS_ROWS = [
    (3, 1, 8.8),
    (4, 1, 7.5),
    (8, 1, 6.5),
    (6, 3, 5.3),
    (9, 5, None),
    (12, 10, 9.8),
    (18, 14, 8.8),
    (20, 18, 6.5),
    (25, 22, 5.3),
    (29, 26, 7.5),
]
# (發布距今天數, CVSS, 是否已有 EPSS)
CRITICAL_ROWS = [
    (0, 9.8, False),
    (0, 9.0, False),
    (1, 9.4, False),
    (1, 10.0, False),
    (2, 9.1, True),
    (3, 9.8, False),
    (4, 9.8, True),
    (5, 9.1, False),
    (6, 9.4, False),
]


def _iso(day: date, hour: int = 2) -> str:
    return (
        datetime(day.year, day.month, day.day, hour, tzinfo=UTC).isoformat().replace("+00:00", "Z")
    )


class _Ids:
    def __init__(self) -> None:
        self.n = 90000

    def next(self) -> str:
        self.n += 37
        if self.n == 94440:
            self.n += 1
        return f"CVE-2026-{self.n}"


def write_state(root: Path) -> None:
    state = State(root)
    ids = _Ids()
    translations: dict[str, str] = {}
    watch: list[Watch] = []
    kev_entries: dict[str, KevEntry] = {}
    epss_scores: dict[str, float] = {}

    def record(cve_id: str, i: int, published: date, score: float | None) -> Watch:
        vendor, product = (
            ("Sorell", "Sorell Hypervisor") if i % 7 == 0 else PRODUCTS[i % len(PRODUCTS)]
        )
        flaw, flaw_tr = FLAWS[i % len(FLAWS)]
        title = f"{product} {flaw}"
        article = "An" if flaw[0] in "AEIOU" else "A"
        desc = (
            f"{article} {flaw.lower()} in {product} allows a remote attacker"
            " to compromise the service."
        )
        translations[translate.text_key(title)] = f"{product} {flaw_tr}"
        translations[translate.text_key(desc)] = (
            f"{product} 的{flaw_tr}漏洞，遠端攻擊者可以入侵服務。"
        )
        data = cve(
            cve_id,
            published=_iso(published),
            title=title,
            desc=desc,
            score=score,
            vendor=vendor,
            product=product,
            versions=[{"version": "0", "lessThan": f"{i % 9 + 1}.{i % 5}.2", "status": "affected"}],
        )
        return Watch(parse_record(data))

    for i, (age, due_days, ransomware, triage, score) in enumerate(KEV_ROWS):
        cve_id = FOCUS if i == 2 else ids.next()
        added = TODAY - timedelta(days=age)
        published = added - timedelta(days=1 + i % 4)
        w = record(cve_id, 0 if i == 2 else i, published, score)
        vendor, product = w.record.vendor_product()
        kev_entries[cve_id] = KevEntry(
            id=cve_id,
            vendor=vendor,
            product=product,
            name=f"{vendor} {product} Vulnerability",
            desc=f"{vendor} {product} contains a vulnerability that is being exploited.",
            added=added,
            due=added + timedelta(days=due_days),
            ransomware=ransomware,
            triage=triage,
            action=ACTION,
            notes=f"https://example.com/{cve_id} ; https://nvd.nist.gov/vuln/detail/{cve_id}",
            cwes=("CWE-287",),
        )
        epss_scores[cve_id] = 0.88113 if cve_id == FOCUS else round(0.2 + (i % 7) / 10, 5)
        if i not in KEV_WITHOUT_RECORD:
            watch.append(w)
    for i, (age, cross_age, score) in enumerate(EPSS_ROWS):
        cve_id = ids.next()
        w = record(cve_id, i + 3, TODAY - timedelta(days=age), score)
        w.epss_cross = TODAY - timedelta(days=cross_age)
        epss_scores[cve_id] = round(0.11 + i * 0.05, 5)
        watch.append(w)
    for i, (age, score, has_epss) in enumerate(CRITICAL_ROWS):
        cve_id = ids.next()
        w = record(cve_id, i + 5, TODAY - timedelta(days=age), score)
        w.critical = TODAY - timedelta(days=age)
        if has_epss:
            epss_scores[cve_id] = 0.004
        watch.append(w)

    for w in watch:
        state.save_watch(w)
    state.save_kev(KevState(KEV_VERSION, "2026-11-24T14:00:00Z", kev_entries))

    # EPSS：近 29 天，最新是昨天。CVE 發布後隔天才有分數。
    published_on = {w.id: w.record.published.date() for w in watch if w.record.published}
    first = TODAY - timedelta(days=29)
    for n in range(29):
        day = first + timedelta(days=n)
        scores = {}
        for cve_id, final in epss_scores.items():
            pub = published_on.get(cve_id, date(2020, 1, 1))
            if day <= pub:
                continue
            factor = 0.3 + 0.7 * n / 28
            scores[cve_id] = (
                round(min(0.97, final * factor), 5),
                0.99999 if cve_id == FOCUS else 0.95,
            )
        state.save_epss_day(day, scores)
    yesterday = TODAY - timedelta(days=1)
    state.save_epss_meta(EpssMeta(yesterday, "v2026.06.15", f"{yesterday}T12:00:00Z"))

    # 每日新 CVE：平日多、週末少；今天還沒過完。
    for n in range(30):
        day = TODAY - timedelta(days=29 - n)
        total = 61 if day == TODAY else (150 if day.weekday() < 5 else 55) + (n * 7) % 23
        daily = Daily(day)
        for k in range(total):
            bucket = k % 20
            score = (
                9.4
                if bucket == 0
                else 8.1
                if bucket < 6
                else 5.5
                if bucket < 12
                else 2.1
                if bucket == 12
                else None
            )
            cross = {"0.01": day.isoformat()} if k % 9 == 0 else {}
            daily.new[f"CVE-2026-{100000 + n * 300 + k}"] = Row(score, severity(score), cross)
        state.save_daily(daily)

    write_json(
        root / "sources.json",
        {
            "cve": {"at": "2026-11-25T03:05:00Z", "ok": True},
            "kev": {"at": "2026-11-25T03:02:00Z", "ok": True},
            "epss": {"at": "2026-11-25T01:15:00Z", "ok": True},
        },
    )
    translate.save(root, "zh-TW", translations)
