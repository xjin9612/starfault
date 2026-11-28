# 設計規則

starfault 是每日 CVE 儀表板。它和 starstrata、starcore 是同一個家族，共用「地層儀表」的版面與元件；主色換成**橘紅**，icon 是被斷層錯開的地層。

**閱讀順序：**
1. 本頁的規則。
2. 頁面規格與驗收清單：[pages.md](pages.md)。
3. 建置、網站資料與測試：[DEVELOPMENT.md](DEVELOPMENT.md)。

視覺來自 Claude Design 的設計系統「地層儀表」，`web/` 是唯一的實作。

## 和家族的關係

- 相同：頁首（夜空底、四條地層線）、搜尋下拉、主題按鈕、分頁列、數字列、分段按鈕、空狀態、骨架、頁尾、返回還原、i18n 做法、無障礙要求、系統字型、灰階與間距 token。
- 不同：
  - `accent` 換成橘紅；頁首地層線與 icon 用 `brand-ember-*` 四色。
  - 列表元件是「CVE 卡片」（CveRow），不是 repo 卡片或文章卡片。
  - 新增嚴重度徽章、EPSS 量表、KEV／勒索軟體／需鑑識旗標、堆疊長條圖、EPSS 走勢線。
- 改共用元件時，先在 starstrata 改，再同步到這裡。

## 技術限制

- 靜態網站，部署在 GitHub Pages；只用 HTML、CSS、原生 JavaScript，不用框架、不載入外部字型或 CDN。
- 主題預設跟隨 `prefers-color-scheme`，頁首按鈕可以固定成淺色或深色，存在 `localStorage['starfault-theme']`。
- 寬度支援 360px 到 2560px。介面語言在建置時決定（`zh-TW` 或 `en`），畫面上不提供切換。
- 設計 token 在 `web/style.css` 開頭的 `:root`，淺色與深色主題各一組。

## 色彩

| token | 淺色 | 深色 | 用途 |
|---|---|---|---|
| `accent` | `#c2410c`（對白 5.2:1） | `#fb923c` | 選取狀態、EPSS 量表、High 徽章外框、目前分頁 |
| `warn` | `#b91c1c`（對白 6.5:1） | `#f87171` | Critical 徽章、KEV 數字、期限 3 天內、停更提醒、勒索軟體 |
| `ink` 反白 | `#0f172a` 底 | `#e6edf7` 底 | KEV 旗標（不靠色相，深淺主題都最醒目） |

- 嚴重度徽章靠「分數＋文字＋樣式」三者區分，不只靠顏色：

| 嚴重度 | 樣式 |
|---|---|
| Critical | `warn` 實心 |
| High | `accent` 外框、`accent-soft` 底 |
| Medium | `control-border` 外框 |
| Low | `control-border` 虛線外框、`muted` 文字 |
| 未評分 | `control-border` 點線外框、`muted` 文字 |

- 嚴重度用英文（Critical、High、Medium、Low），這是 CVSS 的正式名稱；「未評分」依介面語言。

## 圖表

- 近 30 天每日新 CVE：堆疊長條，由下到上 Critical、High、Medium、Low、未評分。
- 嚴重度是有順序的量，用單一色相（橘紅）由淺到深的順序色階：淺色主題 Low `#fdba74` → Critical `#7c2d12`；深色主題反過來，Critical 最亮（`#fed7aa`）。「未評分」用灰色斜線紋理，不佔色階。
- 色階對背景的對比不到 3:1 的部分，以圖例文字、滑鼠／鍵盤逐日提示、「以表格檢視」補足。
- 互動：滑鼠移到長條顯示當天各嚴重度數字；圖表可聚焦，←→ 逐日、Home／End 到頭尾。
- EPSS 走勢線（詳細頁）：近 30 天，虛線標出目前門檻。

## 版面

- 內容最寬 1680px（`--content-max`），寬螢幕時置中、左右留白；頁首與頁尾的底色仍然滿版。這個寬度與 starstrata、starcore 相同。
- 資料型頁面（今日、關注 CVE、KEV、規則）用滿內容寬度；閱讀型頁面（CVE 詳細頁）收窄到內文＋右欄並置中。三個專案共用這條規則。
- 今日頁：三個清單在 1400px 以上排三欄，860–1400px 排兩欄（KEV 佔滿第一列），以下單欄。
- CVE 卡片格線 `repeat(auto-fill, minmax(360px, 1fr))`；手機單欄。
- 詳細頁：左欄最寬 `read-max`（76ch），右欄 260–320px 放 CVSS、EPSS、外部連結，桌面吸頂；1100px 以下改單欄，右欄移到標題區之後。整個詳細頁（返回按鈕與兩欄）的寬度上限是內文＋欄距＋右欄，在頁面中置中，寬螢幕的空白平均分在兩側。
- 詳細頁的標題捲到分頁列底下後，分頁列下方出現一行固定列（返回按鈕＋標題，太長時截斷），只在 721px 以上出現，不佔版面。

## 內容原則

- 介面文字全部放在 `i18n.js`，兩種語言的 key 必須完全一致。
- CVE 標題與描述是內容：有翻譯時顯示翻譯，描述下方標「機器翻譯，以原文為準」並可展開原文；沒有翻譯時顯示原文並標 `lang="en"`。
- KEV 的期限是美國聯邦機關的期限，畫面上寫明「可當作急迫程度的參考」，不寫成使用者的義務。
- 日期 `YYYY-MM-DD`；時間依 `meta.timezone` 換算；EPSS 以百分比顯示，百分位無條件捨去到小數一位（避免顯示 100.0）。
- 介面不用 emoji。

## 圖示與品牌

- `assets/icon.svg`：夜空、橘紅四層地層被斷層錯開，斷層縫透出亮光，左上一顆星。頁首 32×32，favicon 同檔。
- `assets/social-preview.*`：1280×640。
- `assets/bot-avatar.*`：「地質學家」bot 頭像，三專案共用（地層由上到下是 starstrata 青綠、starcore 金黃、starfault 橘紅）。
