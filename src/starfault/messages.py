"""Telegram 訊息的文字，依 site.locale 選用。"""

from __future__ import annotations

from dataclasses import dataclass

HTML_LANG = {"zh-TW": "zh-Hant", "en": "en"}


@dataclass(frozen=True)
class Messages:
    kev_head: str
    cvss: str
    cvss_none: str
    epss: str
    epss_none: str
    due: str
    triage: str
    ransomware: str
    stack_hit: str
    sep: str
    btn_detail: str
    btn_kev: str
    btn_today: str
    digest_head: str
    stack_section: str
    epss_section: str
    critical_section: str
    unscored: str
    affected: str
    affected_unknown: str
    fixed: str
    fixed_unknown: str
    epss_hit: str
    epss_date: str
    title_sep: str
    list_sep: str
    # 名稱後加註，例如技術棧的 note。
    note: str


ZH_TW = Messages(
    kev_head="KEV 新增：{id}",
    cvss="CVSS {score}（{sev}）",
    cvss_none="CVSS 未評分",
    epss="EPSS {pct}",
    epss_none="尚無 EPSS",
    due="期限 {date}（{days} 天）",
    triage="需鑑識",
    ransomware="勒索軟體",
    stack_hit="命中你的技術棧：{labels}",
    sep="・",
    btn_detail="詳細頁",
    btn_kev="CISA KEV",
    btn_today="今日",
    digest_head="starfault 每日摘要 {date}",
    stack_section="你的技術棧（{n}）",
    epss_section="EPSS 跨過 {th}（{n}）",
    critical_section="CVSS ≥ {th} 且還沒有 EPSS（{n}）",
    unscored="未評分",
    affected="受影響 {v}",
    affected_unknown="受影響版本不明",
    fixed="修補 {v}",
    fixed_unknown="修補版本不明",
    epss_hit="命中：{names}",
    epss_date="EPSS 資料日期 {date}，還沒有更新的分數。",
    title_sep="：",
    list_sep="、",
    note="{text}（{note}）",
)

EN = Messages(
    kev_head="Added to KEV: {id}",
    cvss="CVSS {score} ({sev})",
    cvss_none="CVSS not scored",
    epss="EPSS {pct}",
    epss_none="no EPSS yet",
    due="Due {date} ({days} days)",
    triage="forensic triage required",
    ransomware="ransomware",
    stack_hit="Matches your stack: {labels}",
    sep=" · ",
    btn_detail="Details",
    btn_kev="CISA KEV",
    btn_today="Today",
    digest_head="starfault daily digest {date}",
    stack_section="Your stack ({n})",
    epss_section="EPSS crossed {th} ({n})",
    critical_section="CVSS ≥ {th} with no EPSS yet ({n})",
    unscored="not scored",
    affected="affected {v}",
    affected_unknown="affected versions unknown",
    fixed="fixed {v}",
    fixed_unknown="fixed version unknown",
    epss_hit="matches: {names}",
    epss_date="EPSS data is from {date}; no newer scores yet.",
    title_sep=": ",
    list_sep=", ",
    note="{text} ({note})",
)

MESSAGES = {"zh-TW": ZH_TW, "en": EN}
