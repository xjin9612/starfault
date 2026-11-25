# starfault

每日 CVE 儀表板：追蹤 CISA KEV、EPSS 與 Critical 漏洞，以 Telegram 推播。

動手前先讀 `docs/DEVELOPMENT.md` 的「開發環境」「狀態檔」「技術棧特別關注」「測試規則」，提交前跑完其中的四項檢查；改了 `web/` 或網站資料時另外跑瀏覽器測試。

- 技術棧清單只存在 secret `STARFAULT_WATCHLIST` 與本機的 `watchlist.toml`。程式、測試、fixture、文件、commit 訊息只用虛構的產品；log、`state/`、網站不得出現清單內容與比對結果，`tests/test_privacy.py` 會檢查。
- 使用者文件是 `README.md`（英文）與 `README.zh-TW.md`（繁體中文），改一份時同步另一份。
- `docs/` 底下只寫繁體中文。
- 共用的前端元件、Telegram 發送與翻譯以 starstrata 為準，改的時候兩邊一起看。
