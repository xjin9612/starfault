/* starfault dashboard。純 HTML/CSS/JS，不需要建置。
 * 資料格式見 docs/DEVELOPMENT.md「網站資料」；介面文字在 i18n.js。
 * 路由、返回還原、主題、搜尋的做法與 starstrata、starcore 相同。 */
'use strict';

/* =====================================================================
 * 設定與語言
 * ===================================================================== */
const DATA_BASE = 'data/';
const SKELETON_DELAY = 150;   // 載入超過這個毫秒數才顯示骨架，避免閃爍
const RECENT_DAYS = 7;        // 今日頁的三個清單看近 7 天
const SECTION_MAX = 5;        // 今日頁每個清單最多幾筆
const MAX_RESULTS = 8;        // 搜尋下拉最多幾筆
const STALE = { cve: 3, kev: 3 };  // 超過幾小時沒更新算「停更」
const EPSS_STALE_DAYS = 2;    // EPSS 資料日期比今天早超過幾天算「停更」（正常是昨天）

// 語言由產生器依 site.locale 寫入的 <html lang> 決定
const LOCALE = document.documentElement.lang.toLowerCase().startsWith('en') ? 'en' : 'zh-TW';
const DICT = window.I18N[LOCALE];
const t = (key, vars = {}) => (DICT[key] ?? key).replace(/\{(\w+)\}/g, (_, n) => (vars[n] ?? ''));

function applyStaticText() {
  document.documentElement.lang = t('html.lang');
  document.querySelectorAll('[data-i18n]').forEach(e => { e.textContent = t(e.dataset.i18n); });
  document.querySelectorAll('[data-i18n-aria]').forEach(e => e.setAttribute('aria-label', t(e.dataset.i18nAria)));
  document.querySelectorAll('[data-i18n-placeholder]').forEach(e => e.setAttribute('placeholder', t(e.dataset.i18nPlaceholder)));
}

/* =====================================================================
 * 資料讀取
 * ===================================================================== */
class NotFound extends Error {}
const cache = new Map();
const DATA_TTL = 10 * 60000;  // 分頁開著超過這個毫秒數，換頁時重新讀取資料
let cacheTime = 0;
function getData(path) {
  if (Date.now() - cacheTime > DATA_TTL) { cache.clear(); cacheTime = Date.now(); }
  if (cache.has(path)) return cache.get(path);
  const url = DATA_BASE + path.split('/').map(encodeURIComponent).join('/') + '.json';
  const p = fetch(url, { cache: 'no-cache' }).then(r => {
    if (r.status === 404) throw new NotFound(path);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  });
  cache.set(path, p);
  p.catch(() => cache.delete(path)); // 失敗不快取，重試時重新讀取
  return p;
}
// 每一頁都需要的資料
const loadBase = () => Promise.all([getData('meta'), getData('cves'), getData('kev')]);

/* =====================================================================
 * 工具
 * ===================================================================== */
const $ = (s, r = document) => r.querySelector(s);
const fmt = n => Number(n).toLocaleString('en-US');
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const DAY = 86400000;
const toMs = d => Date.UTC(+d.slice(0, 4), +d.slice(5, 7) - 1, +d.slice(8, 10));
const addDays = (d, n) => new Date(toMs(d) + n * DAY).toISOString().slice(0, 10);
const daysFrom = (a, b) => Math.round((toMs(b) - toMs(a)) / DAY);  // b - a
const cveHref = id => '#/cve/' + encodeURIComponent(id);
const sep = () => t('summary.sep');
function tzParts(ms, tz) {
  return Object.fromEntries(new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' })
    .formatToParts(new Date(ms)).map(x => [x.type, x.value]));
}
const fmtTime = (iso, tz) => { const p = tzParts(Date.parse(iso), tz); return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}`; };
// 來源從未成功讀取時沒有時間
const fmtAt = (iso, tz) => iso ? fmtTime(iso, tz) : '—';
let TODAY = null;   // 依 meta.timezone 換算的今天（YYYY-MM-DD）
const setToday = tz => { const p = tzParts(Date.now(), tz); TODAY = `${p.year}-${p.month}-${p.day}`; };
const pctText = s => s == null ? '' : s < 0.001 ? '<0.1%' : (s * 100).toFixed(s >= 0.1 ? 1 : 2).replace(/\.?0+$/, '') + '%';
const short = d => d.slice(5);  // MM-DD
// 百分位無條件捨去到小數一位，避免 0.99999 顯示成 100.0
const pctile = p => (Math.floor(p * 1000) / 10).toFixed(1);

const ICON = {
  back: '<svg class="icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>',
  warn: '<svg class="icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17.5v.01"/></svg>',
  bolt: '<svg class="icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" aria-hidden="true"><path d="M13 2 4 14h7l-1 8 9-12h-7z"/></svg>',
  auto: '<svg class="icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" stroke="none"/></svg>',
  light: '<svg class="icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
  dark: '<svg class="icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" aria-hidden="true"><path d="M20.5 14.5A8.5 8.5 0 1 1 9.5 3.5a7 7 0 0 0 11 11z"/></svg>'
};

/* ===== 內容：翻譯 ===== */
let META = null;
const TR = () => !!META?.translation;
const titleOf = r => (TR() && r.title_tr) || r.title;
// 顯示原文（英文）時標上 lang，螢幕閱讀器才會用正確的發音
const titleHtml = r => (TR() && r.title_tr) ? esc(r.title_tr) : `<span lang="en">${esc(r.title)}</span>`;

/* ===== 徽章 ===== */
const SEVS = ['critical', 'high', 'medium', 'low', 'none'];
function sevHtml(cvss, withScore = true) {
  const sev = cvss?.sev || 'none';
  if (sev === 'none') return `<span class="sev none" title="${esc(t('sev.noneTitle'))}">${t('sev.none')}</span>`;
  return `<span class="sev ${esc(sev)}" title="${esc(t('sev.title', { v: cvss.version, src: t('src.' + (cvss.source || 'vendor')) }))}">${withScore ? `<b>${cvss.score.toFixed(1)}</b>` : ''}${t('sev.' + sev)}<span class="sr">${esc(t('sev.sr', { score: cvss.score.toFixed(1), sev: t('sev.' + sev) }))}</span></span>`;
}
function epssHtml(e) {
  if (!e) return `<span class="epss none">${t('epss.none')}</span>`;
  const w = Math.max(2, Math.round(e.s * 100));
  return `<span class="epss" title="${esc(t('epss.title', { p: pctile(e.p), date: e.date }))}"><span aria-hidden="true">EPSS</span><span class="meter" aria-hidden="true"><i style="width:${w}%"></i></span><b aria-hidden="true">${esc(pctText(e.s))}</b><span class="sr">${esc(t('epss.sr', { s: pctText(e.s), p: pctile(e.p) }))}</span></span>`;
}
function flagsHtml(r) {
  const k = r.kev;
  if (!k) return '';
  return [`<span class="flag kev" title="${esc(t('flag.kevTitle', { date: k.added }))}">KEV</span>`,
    k.ransomware ? `<span class="flag ransom" title="${esc(t('flag.ransomTitle'))}">${t('flag.ransom')}</span>` : '',
    k.triage ? `<span class="flag triage" title="${esc(t('flag.triageTitle'))}">${t('flag.triage')}</span>` : ''].join('');
}
function dueHtml(due) {
  const n = daysFrom(TODAY, due);
  if (n < 0) return `<span class="past">${esc(t('due.past', { date: due }))}</span>`;
  if (n === 0) return `<span class="due-soon">${esc(t('due.today', { date: due }))}</span>`;
  return `<span class="${n <= 3 ? 'due-soon' : ''}">${esc(t('due.left', { date: due, n }))}</span>`;
}

/* ===== CVE 列 ===== */
// KEV 清單的項目攤平成和 cves.json 一樣的形狀
const fromKev = k => ({ id: k.id, title: k.title, title_tr: k.title_tr, vendor: k.vendor, product: k.product, cvss: k.cvss, epss: k.epss,
  kev: { added: k.added, due: k.due, ransomware: k.ransomware, triage: k.triage } });
// 最新事件日：發布、列入 KEV、EPSS 跨過門檻，取最晚的
const lastEvent = r => [r.published, r.kev?.added, r.epss_cross].filter(Boolean).sort().pop() || '';

function rowHtml(r, focus = 'all') {
  const meta = [];
  if (r.published && focus !== 'kev') meta.push(esc(t('row.published', { date: r.published })));
  if (r.kev) { meta.push(esc(t('row.kevAdded', { date: r.kev.added }))); meta.push(dueHtml(r.kev.due)); }
  if (r.epss_cross && focus !== 'kev') meta.push(esc(t('row.epssCross', { date: r.epss_cross, th: pctText(META.thresholds.epss) })));
  return `<li><article class="row">
    <div class="r-top">${sevHtml(r.cvss)}${epssHtml(r.epss)}${r.kev ? `<span class="r-flags">${flagsHtml(r)}</span>` : ''}</div>
    <h3 class="r-title"><a href="${cveHref(r.id)}">${titleHtml(r)}</a></h3>
    <div class="r-sub"><span class="cve-id">${esc(r.id)}</span><span>${esc(r.vendor)} · ${esc(r.product)}</span></div>
    ${meta.length ? `<div class="r-meta">${meta.map(m => `<span>${m}</span>`).join('')}</div>` : ''}
  </article></li>`;
}

function emptyHtml(kind, title, text, action = '') {
  // 插圖：error 是錯開的地層（斷層）；其他是平整的地層，上方一顆星（starfault 的 icon 語彙）
  const G = ['#fed7aa', '#fb923c', '#ea580c', '#9a3412'];
  const layers = (dx, dy) => G.map((c, i) => `<path d="M${dx} ${50 + i * 8 + dy} L${dx + 58} ${48 + i * 8 + dy} L${dx + 58} ${56 + i * 8 + dy} L${dx} ${58 + i * 8 + dy} Z" fill="${c}"/>`).join('');
  const art = kind === 'error'
    ? layers(0, 0) + layers(62, -10) + `<path d="M0 82 V82" /><path d="M60 30 L57 52 L63 60 L59 80" stroke="#fef3c7" stroke-width="2" fill="none"/>`
    : `<path d="M0 54 L120 50 L120 80 L0 80 Z" fill="${G[1]}"/><path d="M0 62 L120 58 L120 80 L0 80 Z" fill="${G[2]}"/><path d="M0 70 L120 67 L120 80 L0 80 Z" fill="${G[3]}"/>`
      + '<polygon points="96,10 98.6,17 106,17.4 100.2,22 102.2,29.2 96,25 89.8,29.2 91.8,22 86,17.4 93.4,17" fill="#fdba74"/>';
  return `<div class="empty" role="status">
    <svg width="120" height="80" viewBox="0 0 120 80" aria-hidden="true"><rect width="120" height="80" rx="10" fill="#0f172a"/>${art}</svg>
    <h3>${title}</h3><p>${text}</p>${action}</div>`;
}
const errorHtml = () => emptyHtml('error', t('error.title'), t('error.text'), `<button type="button" class="btn" data-retry>${t('error.retry')}</button>`);

/* ===== 載入骨架 ===== */
const skRows = n => `<ol class="rows" aria-hidden="true">${Array.from({ length: n }, () => `<li><div class="row sk-card">
  <span class="sk w50 h24"></span><span class="sk w70"></span><span class="sk w30"></span></div></li>`).join('')}</ol>`;
function skeletonHtml(route) {
  if (route.name === 'cve') return `<div class="sk-article" aria-hidden="true"><span class="sk h28 w50"></span><span class="sk w70"></span><span class="sk w90"></span><span class="sk w90"></span></div>`;
  return `<div class="kpis" aria-hidden="true">${'<div class="kpi"><span class="sk w50"></span><span class="sk h24 w30"></span></div>'.repeat(4)}</div><div class="sk-gap"></div>${skRows(5)}`;
}

/* =====================================================================
 * 路由與歷史紀錄
 * history.state 存 { id, from }；捲動位置與點過的連結存在 entryStore[id]，並寫進 sessionStorage。
 * ===================================================================== */
if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
const STORE_KEY = 'starfault-entries';
let entryStore = {};
try { entryStore = JSON.parse(sessionStorage.getItem(STORE_KEY) || '{}'); } catch (e) {}
const saveStore = () => { try { sessionStorage.setItem(STORE_KEY, JSON.stringify(entryStore)); } catch (e) {} };
const newId = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
const entry = () => (entryStore[history.state?.id] ||= {});
let lastScrollY = 0, currentRoute = null, prevEntryId = null;

// 每個列表的篩選：第一個值是預設值，預設值不寫進網址
const FILTERS = {
  cves: { reason: ['all', 'kev', 'epss', 'critical'], range: ['90', '7'], sev: ['all', ...SEVS], sort: ['new', 'epss', 'cvss'] },
  kev: { range: ['30', '7', '90', 'all'], flag: ['all', 'ransomware', 'triage'], sort: ['added', 'due'] }
};
function parseRoute(hash = location.hash) {
  const raw = hash.replace(/^#\/?/, '');
  const qi = raw.indexOf('?');
  const path = qi < 0 ? raw : raw.slice(0, qi);
  const q = new URLSearchParams(qi < 0 ? '' : raw.slice(qi + 1));
  if (path.startsWith('cve/')) {
    let id; try { id = decodeURIComponent(path.slice(4)); } catch (e) { id = path.slice(4); }
    return { name: 'cve', id, hash };
  }
  if (path === 'rules') return { name: 'rules', hash };
  if (FILTERS[path]) {
    const r = { name: path, hash };
    for (const [k, vals] of Object.entries(FILTERS[path])) r[k] = vals.includes(q.get(k)) ? q.get(k) : vals[0];
    return r;
  }
  return { name: 'today', hash };
}
function listHash(r) {
  const q = new URLSearchParams();
  for (const [k, vals] of Object.entries(FILTERS[r.name])) if (r[k] !== vals[0]) q.set(k, r[k]);
  const s = q.toString();
  return `#/${r.name}` + (s ? '?' + s : '');
}
function listConditions(r) {
  if (!FILTERS[r.name]) return [];
  return Object.keys(FILTERS[r.name]).filter(k => k !== 'sort' && r[k] !== FILTERS[r.name][k][0]).map(k => t(`f.${r.name}.${k}.${r[k]}`));
}
function routeLabel(r) {
  if (r.name === 'cve') return r.id.toUpperCase();
  const parts = listConditions(r);
  if (parts.length) return LOCALE === 'en' ? `${t('route.' + r.name)} (${parts.join(' · ')})` : `${t('route.' + r.name)}（${parts.join('・')}）`;
  return t('route.' + r.name);
}

/* =====================================================================
 * 共用區塊
 * ===================================================================== */
function renderHeader(meta) {
  const time = fmtTime(meta.generated_at, meta.timezone);
  $('#hdrInfo').innerHTML = esc(t('hdr.info', { time: '\u0000' })).replace('\u0000', `<time datetime="${esc(meta.generated_at)}">${esc(time)}</time>`);
}
function renderTabs(route, meta) {
  const cur = route.name === 'cve' ? null : route.name;
  const badge = { cves: meta ? META_COUNTS.cves : 0, kev: meta ? META_COUNTS.kev : 0 };
  $('#tabs').innerHTML = ['today', 'cves', 'kev', 'rules'].map(k => {
    const b = badge[k] ? `<span class="badge" aria-hidden="true">${fmt(badge[k])}</span><span class="sr">${esc(t('tab.badge.' + k, { n: badge[k] }))}</span>` : '';
    return `<a class="tab" href="${k === 'today' ? '#/' : '#/' + k}"${k === cur ? ' aria-current="page"' : ''}>${t('route.' + k)}${b}</a>`;
  }).join('');
}
const META_COUNTS = { cves: 0, kev: 0 };

// 資料來源是否停更：回傳停更的來源清單
function staleSources(meta) {
  const out = [];
  const hours = iso => (Date.now() - Date.parse(iso)) / 3600000;
  for (const k of ['cve', 'kev']) {
    const s = meta.sources[k];
    if (!s.ok || !s.at || hours(s.at) > STALE[k]) out.push({ key: k, at: fmtAt(s.at, meta.timezone) });
  }
  const e = meta.sources.epss;
  if (!e.ok || !e.date || daysFrom(e.date, TODAY) > EPSS_STALE_DAYS) out.push({ key: 'epss', at: e.date || '—' });
  return out;
}
function staleHtml(meta) {
  const s = staleSources(meta);
  if (!s.length) return '';
  return `<div class="notice" role="note">${ICON.warn}<p>${s.map(x => esc(t('stale.' + x.key, { at: x.at }))).join(' ')}${esc(t('stale.tail'))}</p></div>`;
}

/* =====================================================================
 * 頁面：今日
 * ===================================================================== */
// 依瀏覽器換算的 TODAY 計算，跨過午夜後不必等網站重新產生
function countsFor(cves, kev, daily) {
  const since = addDays(TODAY, -(RECENT_DAYS - 1));
  return {
    kev_7d: kev.filter(k => k.added >= since).length,
    epss_7d: cves.filter(r => r.epss_cross && r.epss_cross >= since).length,
    critical_7d: cves.filter(r => r.reasons.includes('critical') && r.published >= since).length,
    new_today: daily ? daily.days.find(d => d.date === TODAY)?.total ?? 0 : 0
  };
}
function kpisHtml(meta, c) {
  return `<dl class="kpis" aria-label="${t('kpis.label')}">
    <div class="kpi"><dt>${t('kpi.kev')}</dt><dd class="${c.kev_7d ? 'warn' : ''}">${fmt(c.kev_7d)}</dd></div>
    <div class="kpi"><dt>${esc(t('kpi.epss', { th: pctText(meta.thresholds.epss) }))}</dt><dd class="${c.epss_7d ? 'acc' : ''}">${fmt(c.epss_7d)}</dd></div>
    <div class="kpi"><dt>${esc(t('kpi.critical', { th: meta.thresholds.cvss.toFixed(1) }))}</dt><dd>${fmt(c.critical_7d)}</dd></div>
    <div class="kpi"><dt>${t('kpi.today')}</dt><dd>${fmt(c.new_today)}</dd></div>
  </dl>`;
}
function sectionHtml(key, items, more, focus) {
  const th = { th: pctText(META.thresholds.epss), cvss: META.thresholds.cvss.toFixed(1), days: META.thresholds.epss_window_days };
  const list = items.length
    ? `<ol class="rows">${items.slice(0, SECTION_MAX).map(r => rowHtml(r, focus)).join('')}</ol>`
    : `<p class="sec-empty">${esc(t(`sec.${key}.empty`, th))}</p>`;
  const link = items.length ? `<a href="${more}">${esc(t('sec.more', { n: fmt(items.length) }))}</a>` : '';
  return `<section class="sec" aria-labelledby="sec-${key}"><div class="sec-head"><h3 id="sec-${key}">${esc(t(`sec.${key}`, th))}</h3>${link}</div>
    <p>${esc(t(`sec.${key}.desc`, th))}</p>${list}</section>`;
}
async function viewToday(route, meta, cves, kevAll) {
  const since = addDays(TODAY, -(RECENT_DAYS - 1));
  const kev = cves.filter(r => r.kev && r.kev.added >= since).sort((a, b) => b.kev.added.localeCompare(a.kev.added) || a.id.localeCompare(b.id));
  const epss = cves.filter(r => r.epss_cross && r.epss_cross >= since).sort((a, b) => b.epss_cross.localeCompare(a.epss_cross) || (b.epss?.s ?? -1) - (a.epss?.s ?? -1));
  const crit = cves.filter(r => r.reasons.includes('critical') && r.published >= since).sort((a, b) => b.published.localeCompare(a.published) || b.cvss.score - a.cvss.score);
  const daily = await getData('daily');
  const kpis = kpisHtml(meta, countsFor(cves, kevAll, daily));
  const head = `<div class="view-head"><h2 tabindex="-1">${t('today.title')}</h2><p>${esc(t('today.desc', { date: TODAY }))}</p></div>`;
  if (!cves.length && !daily.days.length) return staleHtml(meta) + kpis + head + emptyHtml('quiet', t('empty.zero'), t('empty.zeroText'));
  return staleHtml(meta) + kpis + head + `<div class="sections">
      ${sectionHtml('kev', kev, '#/kev?range=7', 'kev')}
      ${sectionHtml('epss', epss, '#/cves?reason=epss&range=7', 'all')}
      ${sectionHtml('critical', crit, '#/cves?reason=critical&range=7', 'all')}
    </div>${chartPanelHtml(daily.days)}`;
}

/* ===== 圖表：近 30 天每日新 CVE，依嚴重度堆疊 ===== */
const STACK = ['critical', 'high', 'medium', 'low', 'none'];  // 由下到上
let CHART_DAYS = [];
function chartPanelHtml(days) {
  CHART_DAYS = days;
  if (!days.length) return '';
  const legend = STACK.map(k => `<li><i class="sw c-${k}" aria-hidden="true"></i>${t('sev.' + k)}</li>`).join('');
  const total = days.reduce((s, d) => s + d.total, 0);
  const rows = [...days].reverse().map(d => `<tr><td class="mono">${d.date}</td>${STACK.map(k => `<td>${fmt(d.sev[k])}</td>`).join('')}<td>${fmt(d.total)}</td></tr>`).join('');
  return `<section class="chart-panel" aria-labelledby="chartT">
    <h3 id="chartT">${t('chart.title')}</h3>
    <p>${esc(t('chart.desc', { n: fmt(total), avg: fmt(Math.round(total / days.length)) }))}</p>
    <ul class="legend" aria-label="${t('chart.legend')}">${legend}</ul>
    <div class="chart-wrap" id="chartWrap"><div class="tip" id="chartTip" role="status" hidden></div></div>
    <details class="tbl-toggle"><summary>${t('chart.table')}</summary><div class="tbl-wrap"><table class="tbl">
      <thead><tr><th scope="col">${t('chart.date')}</th>${STACK.map(k => `<th scope="col">${t('sev.' + k)}</th>`).join('')}<th scope="col">${t('chart.total')}</th></tr></thead>
      <tbody>${rows}</tbody></table></div></details>
  </section>`;
}
let chartSel = -1;
function drawChart() {
  const wrap = $('#chartWrap');
  if (!wrap || !CHART_DAYS.length) return;
  const days = CHART_DAYS;
  const W = wrap.clientWidth, H = matchMedia('(max-width: 720px)').matches ? 180 : 220;
  const padL = 36, padB = 22, padT = 6;
  const max = Math.max(...days.map(d => d.total));
  const step = max > 300 ? 100 : 50;
  const top = Math.max(step, Math.ceil(max / step) * step);
  const cw = (W - padL) / days.length;
  const bw = Math.max(3, Math.min(22, cw - 3));
  const y = v => padT + (H - padT - padB) * (1 - v / top);
  let g = '';
  for (let v = 0; v <= top; v += step) g += `<line class="grid-line" x1="${padL}" x2="${W}" y1="${y(v)}" y2="${y(v)}"/><text class="axis" x="${padL - 6}" y="${y(v) + 4}" text-anchor="end">${v}</text>`;
  const labelEvery = cw < 18 ? 7 : cw < 30 ? 3 : 1;
  const bars = days.map((d, i) => {
    const x = padL + i * cw + (cw - bw) / 2;
    let acc = 0, segs = '';
    STACK.forEach((k, si) => {
      const v = d.sev[k];
      if (!v) return;
      const y0 = y(acc), y1 = y(acc + v);
      // 只有最上面一段加 2px 圓角
      segs += `<rect class="c-${k}" x="${x}" y="${y1}" width="${bw}" height="${Math.max(0, y0 - y1)}"${si === STACK.length - 1 || STACK.slice(si + 1).every(n => !d.sev[n]) ? ' rx="2"' : ''}/>`;
      acc += v;
    });
    const lab = (days.length - 1 - i) % labelEvery === 0 ? `<text class="axis" x="${x + bw / 2}" y="${H - 6}" text-anchor="middle">${short(d.date)}</text>` : '';
    return `<g class="bar${i === chartSel ? ' on' : ''}" data-i="${i}">${segs}<rect class="hit" x="${padL + i * cw}" y="${padT}" width="${cw}" height="${H - padT - padB}"/>${lab}</g>`;
  }).join('');
  const svg = `<svg class="chart" id="chart" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" tabindex="0" role="img" aria-label="${esc(t('chart.aria', { n: days.length }))}" aria-describedby="chartTip">
    <defs><pattern id="hatch" width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="4" height="4" fill="var(--surface)"/><rect width="2" height="4" fill="var(--chart-none)"/></pattern></defs>
    ${g}${bars}</svg>`;
  const tip = $('#chartTip');
  wrap.innerHTML = svg;
  wrap.appendChild(tip);
}
function showTip(i) {
  const wrap = $('#chartWrap'), tip = $('#chartTip');
  if (!wrap || i < 0) { if (tip) tip.hidden = true; return; }
  chartSel = i;
  wrap.querySelectorAll('.bar').forEach(b => b.classList.toggle('on', +b.dataset.i === i));
  const d = CHART_DAYS[i];
  tip.innerHTML = `<b>${d.date}${d.date === TODAY ? esc(t('chart.partial')) : ''}</b><dl>${STACK.map(k => `<dt>${t('sev.' + k)}</dt><dd>${fmt(d.sev[k])}</dd>`).join('')}<dt>${t('chart.total')}</dt><dd>${fmt(d.total)}</dd></dl>`;
  tip.hidden = false;
  const bar = wrap.querySelector(`.bar[data-i="${i}"] .hit`).getBBox();
  const left = bar.x + bar.width / 2 + 12;
  tip.style.left = Math.min(left, wrap.clientWidth - tip.offsetWidth - 4) + 'px';
  if (left + tip.offsetWidth > wrap.clientWidth) tip.style.left = Math.max(0, bar.x - tip.offsetWidth - 12) + 'px';
  tip.style.top = '8px';
}
document.addEventListener('pointermove', e => {
  const g = e.target.closest?.('#chart .bar');
  if (g) showTip(+g.dataset.i);
  else if (!e.target.closest?.('#chartWrap') && $('#chartTip') && !$('#chartTip').hidden && document.activeElement?.id !== 'chart') { $('#chartTip').hidden = true; chartSel = -1; $('#chartWrap')?.querySelectorAll('.bar.on').forEach(b => b.classList.remove('on')); }
});
document.addEventListener('keydown', e => {
  if (document.activeElement?.id !== 'chart') return;
  const n = CHART_DAYS.length;
  if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') { showTip(chartSel < 0 ? n - 1 : Math.max(0, Math.min(n - 1, chartSel + (e.key === 'ArrowRight' ? 1 : -1)))); e.preventDefault(); }
  else if (e.key === 'Home') { showTip(0); e.preventDefault(); }
  else if (e.key === 'End') { showTip(n - 1); e.preventDefault(); }
  else if (e.key === 'Escape') { $('#chartTip').hidden = true; }
});
document.addEventListener('focusin', e => { if (e.target.id === 'chart') showTip(chartSel < 0 ? CHART_DAYS.length - 1 : chartSel); });
document.addEventListener('focusout', e => { if (e.target.id === 'chart') { $('#chartTip').hidden = true; } });

/* =====================================================================
 * 頁面：關注 CVE、KEV
 * ===================================================================== */
function segHtml(route, key) {
  const vals = FILTERS[route.name][key];
  const id = `f-${key}`;
  return `<div class="f-group"><span class="f-label" id="${id}">${t(`f.${route.name}.${key}`)}</span><div class="seg" role="group" aria-labelledby="${id}">${vals.map(v =>
    `<button type="button" data-f="${key}" data-v="${v}" aria-pressed="${route[key] === v}">${t(`f.${route.name}.${key}.${v}`)}</button>`).join('')}</div></div>`;
}
function filtersHtml(route, keys) {
  const cond = listConditions(route).length ? `<button type="button" class="link-btn" data-clear>${t('filter.clear')}</button>` : '';
  return `<div class="filters" id="filters">${keys.map(k => segHtml(route, k)).join('')}${cond}<div class="f-right">${segHtml(route, 'sort')}</div></div>`;
}
function summaryHtml(route, n) {
  const cond = listConditions(route);
  return `<p class="summary-line">${esc(t('summary', { cond: cond.length ? cond.join(sep()) + sep() : '', n: fmt(n) }))}</p>`;
}
async function viewCves(route, meta, cves) {
  const head = `<div class="view-head"><h2 tabindex="-1">${t('cves.title')}</h2><p>${esc(t('cves.desc', { th: pctText(meta.thresholds.epss), cvss: meta.thresholds.cvss.toFixed(1) }))}</p></div>`;
  if (!cves.length) return head + emptyHtml('quiet', t('empty.zero'), t('empty.zeroText'));
  // 近 7 天依篩選的原因看對應的日期：今日頁的清單與這裡的筆數一致
  const since = route.range === '7' ? addDays(TODAY, -(RECENT_DAYS - 1)) : '';
  const when = r => ({ kev: r.kev?.added, epss: r.epss_cross, critical: r.published }[route.reason] ?? lastEvent(r)) || '';
  let list = cves.filter(r => (route.reason === 'all' || r.reasons.includes(route.reason)) && (route.sev === 'all' || (r.cvss?.sev || 'none') === route.sev) && when(r) >= since);
  const byNew = (a, b) => lastEvent(b).localeCompare(lastEvent(a)) || a.id.localeCompare(b.id);
  if (route.sort === 'epss') list.sort((a, b) => (b.epss?.s ?? -1) - (a.epss?.s ?? -1) || byNew(a, b));
  else if (route.sort === 'cvss') list.sort((a, b) => (b.cvss?.score ?? -1) - (a.cvss?.score ?? -1) || byNew(a, b));
  else list.sort(byNew);
  const body = list.length ? `<ol class="rows" aria-label="${t('cves.label')}">${list.map(r => rowHtml(r)).join('')}</ol>`
    : emptyHtml('filter', t('empty.none'), t('empty.noneText'), `<button type="button" class="btn" data-clear>${t('filter.clear')}</button>`);
  return head + filtersHtml(route, ['reason', 'range', 'sev']) + summaryHtml(route, list.length) + body;
}
async function viewKev(route, meta, cves, kev) {
  const head = `<div class="view-head"><h2 tabindex="-1">${t('kev.title')}</h2><p>${esc(t(meta.sources.kev.version ? 'kev.desc' : 'kev.descNoVersion', { n: fmt(meta.sources.kev.count), v: meta.sources.kev.version }))}</p></div>`;
  if (!kev.length) return head + emptyHtml('quiet', t('empty.zero'), t('empty.zeroText'));
  const since = route.range === 'all' ? '' : addDays(TODAY, -(+route.range - 1));
  let list = kev.filter(k => k.added >= since && (route.flag === 'all' || (route.flag === 'ransomware' ? k.ransomware : k.triage))).map(fromKev);
  if (route.sort === 'due') {
    // 期限：還沒到期的依期限由近到遠，過期的排在最後
    const pastLast = r => r.kev.due < TODAY ? 1 : 0;
    list.sort((a, b) => pastLast(a) - pastLast(b) || (pastLast(a) ? b.kev.due.localeCompare(a.kev.due) : a.kev.due.localeCompare(b.kev.due)) || a.id.localeCompare(b.id));
  } else list.sort((a, b) => b.kev.added.localeCompare(a.kev.added) || a.id.localeCompare(b.id));
  const body = list.length ? `<ol class="rows" aria-label="${t('kev.label')}">${list.map(r => rowHtml(r, 'kev')).join('')}</ol>`
    : emptyHtml('filter', t('empty.none'), t('empty.noneText'), `<button type="button" class="btn" data-clear>${t('filter.clear')}</button>`);
  return head + filtersHtml(route, ['range', 'flag']) + summaryHtml(route, list.length) + body;
}

/* =====================================================================
 * 頁面：CVE 詳細
 * ===================================================================== */
// cls：頁面上的返回按鈕用 back；固定列裡的那一份用 d-mini-back，兩者行為相同
function backHtml(cls = 'back') {
  const from = history.state?.from;
  if (from) {
    const s = LOCALE === 'en' || /^[A-Za-z0-9]/.test(from.label) ? ' ' : '';
    return `<button type="button" class="btn ${cls}" data-back>${ICON.back}<span>${esc(t('detail.back', { sep: s, label: from.label }))}</span></button>`;
  }
  return `<a class="btn ${cls}" href="#/">${ICON.back}<span>${t('detail.toToday')}</span></a>`;
}
function sparkHtml(hist, th) {
  if (hist.length < 2) return '';
  const W = 280, H = 64, pad = 4;
  const top = Math.max(th * 1.6, ...hist.map(h => h.s)) * 1.05;
  const x = i => pad + (W - pad * 2) * i / (hist.length - 1);
  const y = v => pad + (H - pad * 2) * (1 - v / top);
  const pts = hist.map((h, i) => `${x(i).toFixed(1)},${y(h.s).toFixed(1)}`).join(' ');
  const last = hist[hist.length - 1];
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="${esc(t('detail.sparkAria', { from: hist[0].d, to: last.d, a: pctText(hist[0].s), b: pctText(last.s) }))}">
    <line class="thr" x1="${pad}" x2="${W - pad}" y1="${y(th)}" y2="${y(th)}"/><text class="thr-label" x="${pad}" y="${y(th) - 3}">${esc(pctText(th))}</text>
    <polyline class="line" points="${pts}"/><circle class="end" cx="${x(hist.length - 1)}" cy="${y(last.s)}" r="3.5"/></svg>`;
}
async function viewCve(route, meta, cves, kev) {
  const id = route.id.toUpperCase();
  const base = cves.find(r => r.id === id) || (kev.find(k => k.id === id) && fromKev(kev.find(k => k.id === id)));
  let d = null;
  if (base) { try { d = await getData('cve/' + id); } catch (e) { if (!(e instanceof NotFound)) throw e; } }
  if (!base || !d) return `<div class="d-page">` + backHtml() + emptyHtml('quiet', t('detail.notFound'), t('detail.notFoundText', { id: `<b class="mono">${esc(route.id)}</b>` }), `<a class="btn" href="#/cves">${t('detail.toCves')}</a>`) + '</div>';
  route.id = id;
  const r = base, k = d.kev, th = meta.thresholds.epss;
  const ext = (href, text) => `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer">${text}<span class="sr">${t('newTab')}</span></a>`;
  const trDesc = TR() && d.desc_tr;
  const desc = trDesc
    ? `<p class="desc">${esc(d.desc_tr)}</p><p class="tr-note">${esc(t('detail.machine', { lang: meta.translation }))}</p><details class="orig"><summary>${t('detail.original')}</summary><p lang="en">${esc(d.desc)}</p></details>`
    : `<p class="desc" lang="en">${esc(d.desc)}</p>`;
  const kevBox = k ? `<div class="kev-box" role="note"><h3>${ICON.warn}${esc(t('detail.kevHead', { date: k.added }))}</h3>
      <p>${dueHtml(k.due)}${k.triage ? esc(t('detail.triage')) : ''}${k.ransomware ? esc(t('detail.ransom')) : ''}</p>
      <p class="action"><span>${t('detail.action')}</span><span lang="en">${esc(k.action)}</span></p></div>` : '';
  const affected = d.affected.length ? `<section aria-labelledby="dAff"><h3 id="dAff">${t('detail.affected')}</h3><div class="tbl-wrap"><table class="tbl">
      <thead><tr><th scope="col">${t('detail.vendor')}</th><th scope="col">${t('detail.product')}</th><th scope="col">${t('detail.versions')}</th><th scope="col">${t('detail.fixed')}</th></tr></thead>
      <tbody>${d.affected.map(a => `<tr><td>${esc(a.vendor)}</td><td>${esc(a.product)}</td><td class="mono">${esc(a.versions)}</td><td class="mono">${a.fixed ? esc(a.fixed) : `<span class="unk">${t('detail.unknown')}</span>`}</td></tr>`).join('')}</tbody></table></div></section>` : '';
  const cwe = d.cwe.length ? `<section aria-labelledby="dCwe"><h3 id="dCwe">${t('detail.cwe')}</h3><ul class="refs">${d.cwe.map(c => `<li>${ext(`https://cwe.mitre.org/data/definitions/${c.id.replace('CWE-', '')}.html`, esc(c.id))} <span lang="en">${esc(c.name)}</span></li>`).join('')}</ul></section>` : '';
  const refs = `<section aria-labelledby="dRef"><h3 id="dRef">${t('detail.refs')}</h3><ul class="refs">${d.references.map(x => `<li>${ext(x.url, esc(x.url.replace(/^https:\/\//, '')))}${x.tags.length ? `<span class="rt">${x.tags.map(tg => esc(DICT['ref.' + tg] ?? tg)).join(sep())}</span>` : ''}</li>`).join('')}</ul></section>`;
  const tl = `<section aria-labelledby="dTl"><h3 id="dTl">${t('detail.timeline')}</h3><ol class="timeline">${d.timeline.map(e => `<li class="${esc(e.type)}"><time datetime="${esc(e.date)}">${esc(e.date)}</time>${esc(t('tl.' + e.type, { th: pctText(th) }))}</li>`).join('')}</ol></section>`;
  const c = d.cvss;
  const cvssPanel = `<section class="panel" aria-labelledby="pCvss"><h3 id="pCvss">CVSS</h3>${c
    ? `<div class="score-big"><span class="num">${c.score.toFixed(1)}</span>${sevHtml(c, false)}</div><dl class="kv"><dt>${t('detail.version')}</dt><dd>${esc(c.version)}</dd><dt>${t('detail.scoredBy')}</dt><dd>${t('src.' + c.source)}</dd><dt>${t('detail.vector')}</dt><dd class="mono">${esc(c.vector)}</dd></dl>`
    : `<p class="muted">${t('detail.noCvss')}</p>`}</section>`;
  const e = r.epss;
  const epssPanel = `<section class="panel" aria-labelledby="pEpss"><h3 id="pEpss">EPSS</h3>${e
    ? `<div class="score-big"><span class="num">${esc(pctText(e.s))}</span><span class="muted">${esc(t('detail.pct', { p: pctile(e.p) }))}</span></div>${sparkHtml(d.epss_hist, th)}<dl class="kv"><dt>${t('detail.epssDate')}</dt><dd>${esc(e.date)}</dd>${r.epss_cross ? `<dt>${esc(t('detail.crossed', { th: pctText(th) }))}</dt><dd>${esc(r.epss_cross)}</dd>` : ''}</dl>`
    : `<p class="muted">${t('detail.noEpss')}</p>`}</section>`;
  const links = `<nav class="panel" aria-labelledby="pLinks"><h3 id="pLinks">${t('detail.links')}</h3><ul class="links">
      <li>${ext(`https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`, 'CVE.org')}</li>
      <li>${ext(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`, 'NVD')}</li>
      ${k ? `<li>${ext('https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'CISA KEV')}</li>` : ''}</ul></nav>`;
  return `<div class="d-page">${backHtml()}
    <div class="d-mini" hidden><div class="d-mini-in">${backHtml('d-mini-back')}<span class="d-mini-title">${titleHtml(r)}</span></div></div>
    <div class="d-layout">
      <header class="d-head">
        <div class="cve-id">${esc(id)}</div>
        <h2 tabindex="-1">${titleHtml(r)}</h2>
        <p class="d-sub">${esc(r.vendor)} · ${esc(r.product)}${r.published ? sep() + esc(t('row.published', { date: r.published })) : ''}</p>
        <div class="d-badges">${sevHtml(r.cvss)}${flagsHtml(r)}</div>
        ${kevBox}
      </header>
      <aside class="d-side">${cvssPanel}${epssPanel}${links}</aside>
      <div class="d-body">
        <section aria-labelledby="dDesc"><h3 id="dDesc">${t('detail.desc')}</h3>${desc}</section>
        ${affected}${cwe}${tl}${refs}
      </div>
    </div></div>`;
}

/* =====================================================================
 * 頁面：規則
 * ===================================================================== */
async function viewRules(route, meta) {
  const stats = await getData('stats');
  const th = meta.thresholds;
  const vars = { th: pctText(th.epss), cvss: th.cvss.toFixed(1), days: th.epss_window_days, stack: th.stack_cvss.toFixed(1) };
  const calibrating = TODAY <= th.calibrating_until;
  const rules = ['kev', 'epss', 'critical', 'stack'].map(k => `<li class="rule"><h4>${k === 'kev' ? ICON.bolt : ''}${esc(t(`rule.${k}`, vars))}</h4><p>${esc(t(`rule.${k}.text`, vars))}</p><p class="when">${esc(t(`rule.${k}.when`, vars))}</p></li>`).join('');
  const epssRows = stats.epss.map(x => `<tr class="${x.t === th.epss ? 'cur' : ''}"><td>EPSS ≥ ${esc(pctText(x.t))}${x.t === th.epss ? esc(t('cal.current')) : ''}</td><td>${x.per_day.toFixed(1)}</td></tr>`).join('');
  const cvssRows = stats.cvss.map(x => `<tr class="${x.t === th.cvss ? 'cur' : ''}"><td>CVSS ≥ ${x.t.toFixed(1)}${x.t === th.cvss ? esc(t('cal.current')) : ''}</td><td>${x.per_day.toFixed(1)}</td></tr>`).join('');
  const stale = new Set(staleSources(meta).map(s => s.key));
  const src = meta.sources;
  const srcRow = (k, at) => `<tr><td>${t('srcname.' + k)}</td><td>${t('freq.' + k)}</td><td class="mono">${esc(at)}</td><td class="${stale.has(k) ? 'st-bad' : 'st-ok'}">${stale.has(k) ? t('status.stale') : t('status.ok')}</td></tr>`;
  return `<div class="view-head"><h2 tabindex="-1">${t('rules.title')}</h2><p>${t('rules.desc')}</p></div>
    <ul class="rule-cards">${rules}</ul>
    <section class="r-sec" aria-labelledby="calT"><h3 id="calT">${t('cal.title')}</h3>
      <p>${esc(t(calibrating ? 'cal.descOn' : 'cal.descOff', { from: stats.window.from, to: stats.window.to, n: fmt(stats.window.new_cves), until: th.calibrating_until }))}</p>
      <div class="tbl-wrap"><table class="tbl"><thead><tr><th scope="col">${t('cal.rule')}</th><th scope="col">${t('cal.perDay')}</th></tr></thead>
      <tbody>${epssRows}${cvssRows}<tr><td>${t('cal.kev')}</td><td>${stats.kev_per_day.toFixed(1)}</td></tr></tbody></table></div></section>
    <section class="r-sec" aria-labelledby="srcT"><h3 id="srcT">${t('src.title')}</h3><p>${t('src.desc')}</p>
      <div class="tbl-wrap"><table class="tbl left"><thead><tr><th scope="col">${t('src.name')}</th><th scope="col">${t('src.freq')}</th><th scope="col">${t('src.last')}</th><th scope="col">${t('src.status')}</th></tr></thead>
      <tbody>${srcRow('cve', fmtAt(src.cve.at, meta.timezone))}${srcRow('kev', fmtAt(src.kev.at, meta.timezone) + (src.kev.version ? ' · ' + src.kev.version : ''))}${srcRow('epss', src.epss.date || '—')}</tbody></table></div></section>
    <section class="r-sec" aria-labelledby="crT"><h3 id="crT">${t('credit.title')}</h3><ul class="credits">
      <li>${t('credit.cve')}</li><li>${t('credit.kev')}</li><li>${t('credit.epss')}</li></ul></section>`;
}

/* =====================================================================
 * 繪製流程
 * mode：'new' 新頁面｜'restore' 返回｜'update' 同一頁更新｜'init' 第一次載入
 * ===================================================================== */
let renderToken = 0;
async function render(mode = 'update') {
  const token = ++renderToken;
  const route = parseRoute();
  currentRoute = route;
  const view = $('#view');
  renderTabs(route, META);
  let skeletonShown = false;
  const skTimer = setTimeout(() => {
    if (token !== renderToken) return;
    skeletonShown = true;
    view.innerHTML = skeletonHtml(route);
    view.setAttribute('aria-busy', 'true');
    $('#live').textContent = t('live.loading');
    afterPaint(mode, true);
  }, SKELETON_DELAY);
  try {
    const [meta, cves, kev] = await loadBase();
    if (token !== renderToken) return;
    META = meta;
    setToday(meta.timezone);
    META_COUNTS.cves = cves.items.length;
    META_COUNTS.kev = countsFor([], kev.items, null).kev_7d;
    const fn = { today: viewToday, cves: viewCves, kev: viewKev, cve: viewCve, rules: viewRules }[route.name];
    const html = await fn(route, meta, cves.items, kev.items);
    if (token !== renderToken) return;
    clearTimeout(skTimer);
    renderHeader(meta);
    renderTabs(route, meta);
    view.innerHTML = html;
    view.removeAttribute('aria-busy');
    if (skeletonShown) $('#live').textContent = t('live.loaded');
  } catch (e) {
    if (token !== renderToken) return;
    clearTimeout(skTimer);
    console.error(e);
    view.innerHTML = errorHtml();
    view.removeAttribute('aria-busy');
    $('#live').textContent = t('live.failed');
  }
  document.title = routeLabel(route) + t('title.suffix');
  // 繪製完成的網址；瀏覽器測試用它等待換頁完成。
  view.dataset.hash = location.hash;
  measureSticky();
  drawChart();
  afterPaint(mode, false);
}
function afterPaint(mode, isSkeleton) {
  const view = $('#view');
  if (mode === 'restore') {
    if (isSkeleton) return;
    const st = entry();
    window.scrollTo(0, st.scrollY || 0);
    const target = st.focusHref && [...view.querySelectorAll('a[href]')].find(a => a.getAttribute('href') === st.focusHref);
    if (target) target.focus({ preventScroll: true });
    requestAnimationFrame(() => window.scrollTo(0, st.scrollY || 0));
  } else if (mode === 'new') {
    window.scrollTo(0, 0);
    if (!isSkeleton) view.querySelector('h2')?.focus({ preventScroll: true });
  } else if (mode === 'init' && !isSkeleton && entry().scrollY) {
    window.scrollTo(0, entry().scrollY);
  }
}

/* ===== 吸頂高度 ===== */
function measureSticky() {
  const subH = $('#subnav').offsetHeight;
  const filters = $('#filters');
  const desktop = matchMedia('(min-width: 721px)').matches;
  const root = document.documentElement;
  // 詳細頁的固定列是 fixed，不佔版面；捲動定位仍要讓出它的高度
  const miniH = $('.d-mini') && desktop ? parseFloat(getComputedStyle(root).getPropertyValue('--mini-h')) : 0;
  root.style.setProperty('--tabs-h', subH + 'px');
  root.style.setProperty('--sticky-h', (subH + (filters && desktop ? filters.offsetHeight : 0) + miniH + 8) + 'px');
  updateStuck();
}
function updateStuck() {
  // 詳細頁：標題捲到分頁列底下之後才顯示固定列
  const mini = $('.d-mini');
  if (mini) mini.hidden = !(matchMedia('(min-width: 721px)').matches && $('.d-head h2').getBoundingClientRect().bottom <= $('#subnav').offsetHeight);
  const f = $('#filters');
  if (!f) return;
  const top = parseFloat(getComputedStyle(f).top) || 0;
  f.classList.toggle('is-stuck', getComputedStyle(f).position === 'sticky' && f.getBoundingClientRect().top <= top + 0.5 && window.scrollY > 0);
}
let resizeTimer = 0;
window.addEventListener('resize', () => { measureSticky(); clearTimeout(resizeTimer); resizeTimer = setTimeout(drawChart, 100); });

/* =====================================================================
 * 導覽事件
 * ===================================================================== */
document.addEventListener('click', e => {
  const a = e.target.closest('a[href^="#/"]');
  if (a && !e.defaultPrevented && !e.metaKey && !e.ctrlKey && !e.shiftKey && e.button === 0) entry().focusHref = a.getAttribute('href');
}, true);
let scrollTick = false;
window.addEventListener('scroll', () => {
  lastScrollY = window.scrollY;
  if (!scrollTick) { scrollTick = true; requestAnimationFrame(() => { scrollTick = false; updateStuck(); }); }
}, { passive: true });
// 跳到主要內容：不改網址，否則 hash 路由會把 #main 當成今日頁
document.querySelector('.skip').addEventListener('click', e => { e.preventDefault(); $('#main').focus(); });
window.addEventListener('hashchange', e => {
  if (prevEntryId) (entryStore[prevEntryId] ||= {}).scrollY = lastScrollY;
  const prevRoute = parseRoute(new URL(e.oldURL).hash);
  if (!history.state?.id) {
    history.replaceState({ id: newId(), from: { hash: prevRoute.hash, label: routeLabel(prevRoute) } }, '');
    prevEntryId = history.state.id;
    saveStore();
    render('new');
  } else {
    prevEntryId = history.state.id;
    render('restore');
  }
});
window.addEventListener('pagehide', () => { entry().scrollY = window.scrollY; saveStore(); });
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') { entry().scrollY = window.scrollY; saveStore(); } });

function updateList(change, focusSel) {
  // 篩選寫進網址但不新增歷史紀錄
  const r = { ...currentRoute };
  change(r);
  history.replaceState(history.state, '', listHash(r));
  render('update').then(() => focusSel && $(focusSel)?.focus({ preventScroll: true }));
}
document.addEventListener('click', e => {
  const b = e.target.closest('button');
  if (!b || b.disabled) return;
  if (b.dataset.f) {
    updateList(r => { r[b.dataset.f] = b.dataset.v; }, `[data-f="${b.dataset.f}"][data-v="${CSS.escape(b.dataset.v)}"]`);
  } else if (b.hasAttribute('data-clear')) {
    const first = Object.keys(FILTERS[currentRoute.name])[0];
    updateList(r => { for (const [k, vals] of Object.entries(FILTERS[r.name])) if (k !== 'sort') r[k] = vals[0]; }, `[data-f="${first}"][data-v="${FILTERS[currentRoute.name][first][0]}"]`);
  } else if (b.hasAttribute('data-back')) {
    history.back();
  } else if (b.hasAttribute('data-retry')) {
    render('update');
  }
});

/* =====================================================================
 * 主題：跟隨系統 → 淺色 → 深色
 * ===================================================================== */
const THEMES = ['auto', 'light', 'dark'];
let theme = 'auto';
try { const v = localStorage.getItem('starfault-theme'); if (THEMES.includes(v)) theme = v; } catch (e) {}
function applyTheme() {
  if (theme === 'auto') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', theme);
  const name = t('theme.' + theme);
  const btn = $('#themeBtn');
  btn.innerHTML = ICON[theme] + `<span class="sr">${esc(t('theme.label', { name }))}</span>`;
  btn.title = t('theme.title', { name });
}
$('#themeBtn').addEventListener('click', () => {
  document.documentElement.classList.add('no-transition');
  requestAnimationFrame(() => requestAnimationFrame(() => document.documentElement.classList.remove('no-transition')));
  theme = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
  try { theme === 'auto' ? localStorage.removeItem('starfault-theme') : localStorage.setItem('starfault-theme', theme); } catch (e) {}
  applyTheme();
  $('#live').textContent = t('theme.label', { name: t('theme.' + theme) });
});

/* =====================================================================
 * 搜尋：比對 CVE 編號、廠商、產品、標題（原文與翻譯）
 * 範圍是 cves.json 與 kev.json，不含其他 CVE。
 * ===================================================================== */
const q = $('#q'), panel = $('#qPanel'), listEl = $('#qList'), foot = $('#qFoot');
let idxState = 'idle', idxRows = null, results = [], active = -1;
function loadIndex() {
  if (idxState === 'loading' || idxState === 'ready') return;
  idxState = 'loading';
  loadBase().then(([meta, cves, kev]) => {
    META ||= meta;
    const seen = new Map();
    for (const r of [...cves.items, ...kev.items.map(fromKev)]) if (!seen.has(r.id)) seen.set(r.id, r);
    idxRows = [...seen.values()].map(r => ({ r, id: r.id.toLowerCase(), vp: `${r.vendor} ${r.product}`.toLowerCase(), title: `${r.title} ${r.title_tr || ''}`.toLowerCase() }));
    idxState = 'ready';
    if (q.value.trim()) updateSearch();
  }, () => { idxState = 'error'; if (q.value.trim()) updateSearch(); });
}
function markText(text, term) {
  const i = text.toLowerCase().indexOf(term);
  if (i < 0) return esc(text);
  return esc(text.slice(0, i)) + '<mark>' + esc(text.slice(i, i + term.length)) + '</mark>' + esc(text.slice(i + term.length));
}
function openPanel() { panel.hidden = false; q.setAttribute('aria-expanded', 'true'); }
function updateSearch() {
  const raw = q.value.trim(), term = raw.toLowerCase();
  if (!term) { closeSearch(); return; }
  results = []; active = -1;
  if (idxState !== 'ready') {
    listEl.innerHTML = '';
    foot.innerHTML = `<div class="dd-empty">${idxState === 'error' ? t('search.failed') : t('search.loading')}</div>`;
    if (idxState === 'idle' || idxState === 'error') { idxState = 'idle'; loadIndex(); }
    openPanel(); syncActive();
    return;
  }
  // 排序：編號開頭 > 編號包含 > 廠商或產品包含 > 標題包含；同級依最新事件日
  const scored = [];
  const bare = term.replace(/^cve-?/, '');
  for (const x of idxRows) {
    let score = -1;
    if (x.id.startsWith(term) || x.id.slice(4).startsWith(bare) && bare) score = 0;
    else if (bare.length >= 3 && x.id.includes(bare)) score = 1;
    else if (x.vp.includes(term)) score = 2;
    else if (term.length >= 2 && x.title.includes(term)) score = 3;
    if (score >= 0) scored.push({ x, score });
  }
  scored.sort((a, b) => a.score - b.score || lastEvent(b.x.r).localeCompare(lastEvent(a.x.r)) || a.x.id.localeCompare(b.x.id));
  results = scored.slice(0, MAX_RESULTS);
  active = results.length ? 0 : -1;
  listEl.innerHTML = results.map(({ x }, i) => `<li class="dd-item" role="option" id="opt${i}" aria-selected="${i === active}" data-id="${esc(x.r.id)}">
      <span class="dd-name mono">${markText(x.r.id, bare && x.id.includes(bare) ? bare : term)}</span>${sevHtml(x.r.cvss)}
      <span class="dd-repo">${markText(titleOf(x.r), term)}</span><span class="dd-snip">${markText(`${x.r.vendor} · ${x.r.product}`, term)}</span></li>`).join('');
  foot.innerHTML = !results.length
    ? `<div class="dd-empty">${esc(t('search.none', { q: raw }))}</div>`
    : `<div class="dd-foot">${t('search.count', { n: fmt(scored.length) })}${scored.length > MAX_RESULTS ? t('search.first', { m: MAX_RESULTS }) : ''}${t('search.hint')}</div>`;
  openPanel(); syncActive();
  $('#live').textContent = results.length ? t('search.live', { n: scored.length }) : t('search.liveNone');
}
function syncActive() {
  listEl.querySelectorAll('.dd-item').forEach((li, i) => li.setAttribute('aria-selected', i === active));
  if (active >= 0) { q.setAttribute('aria-activedescendant', 'opt' + active); $('#opt' + active).scrollIntoView({ block: 'nearest' }); }
  else q.removeAttribute('aria-activedescendant');
}
function closeSearch() { panel.hidden = true; q.setAttribute('aria-expanded', 'false'); q.removeAttribute('aria-activedescendant'); active = -1; }
function openCve(id) { closeSearch(); q.value = ''; q.blur(); location.hash = cveHref(id); }
q.addEventListener('focus', () => { loadIndex(); if (q.value.trim()) updateSearch(); });
q.addEventListener('input', updateSearch);
q.addEventListener('keydown', e => {
  if (e.key === 'ArrowDown' && results.length) { active = (active + 1) % results.length; syncActive(); e.preventDefault(); }
  else if (e.key === 'ArrowUp' && results.length) { active = (active - 1 + results.length) % results.length; syncActive(); e.preventDefault(); }
  else if (e.key === 'Enter' && active >= 0) { openCve(results[active].x.r.id); e.preventDefault(); }
  else if (e.key === 'Escape') { if (!panel.hidden) closeSearch(); else { q.value = ''; q.blur(); } }
});
panel.addEventListener('mousedown', e => { const li = e.target.closest('.dd-item'); if (li) { e.preventDefault(); openCve(li.dataset.id); } });
listEl.addEventListener('mousemove', e => { const li = e.target.closest('.dd-item'); if (li) { active = [...listEl.children].indexOf(li); syncActive(); } });
document.addEventListener('mousedown', e => { if (!e.target.closest('.search')) closeSearch(); });
document.addEventListener('keydown', e => {
  if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName) && !document.activeElement.isContentEditable) { e.preventDefault(); q.focus(); }
});

/* =====================================================================
 * 啟動
 * ===================================================================== */
applyStaticText();
applyTheme();
if (!history.state?.id) history.replaceState({ id: newId(), from: null }, '');
prevEntryId = history.state.id;
render('init');
