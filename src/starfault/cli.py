"""命令列入口。指令說明見 docs/DEVELOPMENT.md「命令列」。

log 會出現在公開 repo 的 Actions 頁面：不得印出技術棧清單的內容、命中的 CVE 或命中數。
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from collections.abc import Sequence
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx

from starfault import cvelist, epss, kev, notify, track, translate, watchlist
from starfault.config import Config, ConfigError, load_config
from starfault.epss import EpssFormatError
from starfault.http import FetchError, Http
from starfault.kev import KevFormatError
from starfault.messages import MESSAGES
from starfault.site import build_site
from starfault.site_page import detect_repo
from starfault.state import State
from starfault.telegram import TelegramError, TelegramSender
from starfault.view import pct_text

log = logging.getLogger("starfault")

# 資料來源或發送失敗；已取得的資料照常寫入。
EXIT_FAILED = 1
# 設定錯誤或缺少必要的環境變數，沒有執行任何工作。
EXIT_USAGE = 2
# 每次執行最多為 KEV 與關注清單抓取幾筆單筆紀錄。
RECORD_BUDGET = 100
# cve 指令最多補讀幾個 UTC 日的 end_of_day delta。
MAX_EOD_DAYS = 7
# --backfill-days 的上限，與每日紀錄的保留天數相同。
MAX_BACKFILL_DAYS = 90

_THREAD_ID = re.compile(r"[0-9]+")


class UsageError(Exception):
    pass


class _Env:
    """測試時替換的外部相依：HTTP transport 與目前時間。"""

    def __init__(self, transport: httpx.BaseTransport | None, now: datetime | None) -> None:
        self.transport = transport
        self._now = now

    def now(self) -> datetime:
        return self._now or datetime.now(UTC)

    def http(self) -> Http:
        return Http(transport=self.transport)


def thread_id(value: str) -> int | None:
    """解析 TELEGRAM_THREAD_ID：空白回傳 None，不是正整數時丟出 UsageError。"""
    value = value.strip()
    if not value:
        return None
    if not _THREAD_ID.fullmatch(value) or int(value) < 1:
        raise UsageError(f"TELEGRAM_THREAD_ID 必須是正整數：{value!r}")
    return int(value)


def _telegram(env: _Env) -> TelegramSender | None:
    """未設定 bot token 或 chat ID 時回傳 None。"""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    thread = thread_id(os.environ.get("TELEGRAM_THREAD_ID", ""))
    if not token or not chat_id:
        return None
    if thread is not None:
        log.info("發送到群組主題 %d", thread)
    return TelegramSender(token, chat_id, thread_id=thread, transport=env.transport)


def _watchlist(args: argparse.Namespace) -> watchlist.Watchlist:
    try:
        return watchlist.load(os.environ, args.watchlist)
    except watchlist.WatchlistError as e:
        raise UsageError(f"技術棧清單格式錯誤：{e}") from None


def _translations(state: State, cfg: Config) -> dict[str, str]:
    target = cfg.translation.target
    return translate.load(state.root, target) if target else {}


def _today(cfg: Config, now: datetime) -> date:
    return track.local_date(now, cfg.site.timezone)


def _kev_ids(state: State) -> set[str]:
    k = state.load_kev()
    return set(k.entries) if k else set()


def cmd_kev(args: argparse.Namespace, cfg: Config, env: _Env) -> int:
    state = State(args.state)
    now = env.now()
    today = _today(cfg, now)
    with env.http() as http:
        try:
            catalog = kev.fetch_catalog(http)
        except (FetchError, KevFormatError) as e:
            log.error("KEV 讀取失敗：%s", e)
            state.mark_source("kev", False, now)
            return EXIT_FAILED
        update = track.update_kev(state, catalog, today)
        state.mark_source("kev", True, now)
        if update.baseline:
            log.info(
                "KEV %s：第一次執行，建立 %d 筆的快照，不推播",
                catalog.version,
                len(catalog.entries),
            )
        else:
            log.info(
                "KEV %s：%d 筆，新增 %s",
                catalog.version,
                len(catalog.entries),
                ", ".join(update.new) or "無",
            )
        if update.expired:
            log.warning(
                "KEV：%d 筆新增超過 %d 天仍未推播，不再嘗試", update.expired, track.KEV_PENDING_DAYS
            )
        order = list(update.kev.pending) + [
            e.id
            for e in sorted(catalog.entries.values(), key=lambda e: (e.added, e.id), reverse=True)
        ]
        fetched, failed = track.fill_records(
            state, http, dict.fromkeys(order), cfg, today, RECORD_BUDGET
        )
    missing = len(set(catalog.entries) - set(state.load_watch()))
    log.info("KEV 紀錄：取得 %d 筆、失敗 %d 筆，還有 %d 筆沒有完整紀錄", fetched, failed, missing)
    return 0


def cmd_push(args: argparse.Namespace, cfg: Config, env: _Env) -> int:
    state = State(args.state)
    stack = _watchlist(args)
    sender = _telegram(env)
    if sender is None:
        log.info("未設定 TELEGRAM_BOT_TOKEN 或 TELEGRAM_CHAT_ID，略過推播")
    try:
        result = notify.push_kev(
            state,
            cfg,
            MESSAGES[cfg.site.locale],
            _translations(state, cfg),
            stack,
            (lambda m: sender.send(m.text, silent=m.silent, buttons=m.buttons)) if sender else None,
            now=env.now(),
        )
    except TelegramError as e:
        log.error("Telegram 發送失敗：%s", e)
        return EXIT_FAILED
    finally:
        if sender:
            sender.close()
    log.info("KEV 推播：發送 %d 則，略過 %d 則", result.sent, result.skipped)
    return 0


def _eod_days(state: State, utc_today: date, backfill_days: int | None) -> list[date]:
    yesterday = utc_today - timedelta(days=1)
    if backfill_days:
        first = utc_today - timedelta(days=backfill_days)
    else:
        through, _ = state.load_cvelist()
        first = through + timedelta(days=1) if through else yesterday
        first = max(first, utc_today - timedelta(days=MAX_EOD_DAYS))
    return [first + timedelta(days=i) for i in range((yesterday - first).days + 1)]


def cmd_cve(args: argparse.Namespace, cfg: Config, env: _Env) -> int:
    """讀取還沒處理的 end_of_day delta 與今天最新的 hourly delta。"""
    if args.backfill_days is not None and not 1 <= args.backfill_days <= MAX_BACKFILL_DAYS:
        raise UsageError(f"--backfill-days 必須是 1 到 {MAX_BACKFILL_DAYS}")
    state = State(args.state)
    now = env.now()
    utc_now = now.astimezone(UTC)
    today = _today(cfg, now)
    days = _eod_days(state, utc_now.date(), args.backfill_days)
    batch = cvelist.Batch()
    processed: date | None = None
    with env.http() as http:
        try:
            for day in days:
                part = cvelist.fetch_eod(http, day)
                if part is None:
                    log.info("CVE：%s 的 end_of_day 還沒發布", day)
                    break
                batch.add(part)
                processed = day
            hourly = cvelist.fetch_latest_hourly(http, utc_now)
            if hourly is not None:
                batch.add(hourly)
        except (FetchError, ValueError) as e:
            log.error("CVE delta 讀取失敗：%s", e)
            state.mark_source("cve", False, now)
            return EXIT_FAILED
    kev_ids = _kev_ids(state)
    through, since = state.load_cvelist()
    if since is None or args.backfill_days:
        # 第一個讀取的 UTC 日在任何時區都涵蓋下一個日子的全部。
        since = (days[0] if days else utc_now.date()) + timedelta(days=1)
    result = track.apply_records(state, batch.records.values(), cfg, today, kev_ids, since)
    removed = track.prune(state, cfg, today, kev_ids)
    first_day = days[0] if days else utc_now.date()
    state.save_cvelist(processed or through or first_day - timedelta(days=1), since)
    state.mark_source("cve", True, now)
    log.info(
        "CVE：%d 筆紀錄（略過格式錯誤 %d、REJECTED %d），新 CVE %d、補上分數 %d、"
        "關注清單新增 %d、更新 %d、移除 %d",
        result.records,
        batch.invalid,
        result.rejected,
        result.new,
        result.rescored,
        result.watch_added,
        result.watch_updated,
        removed,
    )
    return 0


def cmd_epss(args: argparse.Namespace, cfg: Config, env: _Env) -> int:
    state = State(args.state)
    now = env.now()
    today = _today(cfg, now)
    kev_ids = _kev_ids(state)
    wanted = track.wanted_for_epss(state, cfg, today, kev_ids)
    with env.http() as http:
        try:
            data = epss.fetch(http, wanted.__contains__)
        except (FetchError, EpssFormatError) as e:
            log.error("EPSS 讀取失敗：%s", e)
            state.mark_source("epss", False, now)
            return EXIT_FAILED
        result = track.apply_epss(state, http, data, cfg, today, kev_ids)
    state.mark_source("epss", True, now)
    log.info(
        "EPSS %s（模型 %s）：首次跨過 %s 的 CVE %d 筆%s",
        data.date,
        data.model,
        pct_text(cfg.thresholds.epss),
        len(result.crossed),
        f"，{result.deferred} 筆取不到紀錄、下次再試" if result.deferred else "",
    )
    return 0


def cmd_site(args: argparse.Namespace, cfg: Config, env: _Env) -> int:
    state = State(args.state)
    stats = build_site(
        state,
        cfg,
        args.out,
        args.web,
        args.assets,
        env.now(),
        _translations(state, cfg),
        detect_repo(os.environ, Path.cwd()),
    )
    log.info("網站：關注 CVE %d 筆、KEV %d 筆、詳細頁 %d 頁", stats.cves, stats.kev, stats.details)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="starfault", description="每日 CVE 儀表板")
    parser.add_argument("--config", type=Path, default=Path("config.toml"), help="設定檔")
    parser.add_argument("--state", type=Path, default=Path("state"), help="狀態檔目錄")
    parser.add_argument(
        "--watchlist",
        type=Path,
        default=Path("watchlist.toml"),
        help="技術棧清單；環境變數 STARFAULT_WATCHLIST 有值時改用它",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("kev", help="讀取 KEV，更新快照與待推播清單，補抓 KEV 的 CVE 紀錄")
    sub.add_parser("push", help="推播 KEV 新增（需要 TELEGRAM_BOT_TOKEN、TELEGRAM_CHAT_ID）")
    p_cve = sub.add_parser("cve", help="讀取 cvelistV5 的 delta，更新每日新 CVE 與關注清單")
    p_cve.add_argument(
        "--backfill-days", type=int, metavar="N", help="改為重新讀取今天以前 N 個 UTC 日的 delta"
    )
    sub.add_parser("epss", help="讀取 EPSS，記錄分數與首次跨過門檻的 CVE")
    p_site = sub.add_parser("site", help="產生網站")
    p_site.add_argument("--out", type=Path, default=Path("_site"), help="輸出目錄，會先清空")
    p_site.add_argument("--web", type=Path, default=Path("web"), help="前端靜態檔目錄")
    p_site.add_argument("--assets", type=Path, default=Path("assets"), help="icon 與分享圖目錄")
    return parser


_COMMANDS = {
    "kev": cmd_kev,
    "push": cmd_push,
    "cve": cmd_cve,
    "epss": cmd_epss,
    "site": cmd_site,
}


def main(
    argv: Sequence[str] | None = None,
    *,
    transport: httpx.BaseTransport | None = None,
    now: datetime | None = None,
) -> int:
    """transport 與 now 只給測試替換外部連線與時間。"""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    # httpx 在 INFO 會記錄完整請求網址，Telegram 的網址含 bot token。
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)
    args = build_parser().parse_args(argv)
    try:
        cfg = load_config(args.config)
        return _COMMANDS[args.command](args, cfg, _Env(transport, now))
    except (ConfigError, UsageError) as e:
        log.error("%s", e)
        return EXIT_USAGE
