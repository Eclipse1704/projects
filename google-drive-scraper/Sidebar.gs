// The scraper window (a sidebar next to the sheet): paste links, press start, watch progress, open folders.

function openScraper() {
  ensureOwnCopy();
  setup();
  ensureAutoOpen();
  SpreadsheetApp.getUi().showSidebar(HtmlService.createHtmlOutput(SIDEBAR_HTML).setTitle('סורק מוצרים'));
}

// After the first (authorized) use, the window opens by itself whenever the spreadsheet is opened.
function ensureAutoOpen() {
  var has = ScriptApp.getProjectTriggers().some(function (t) { return t.getHandlerFunction() === 'autoOpenScraper'; });
  if (!has) ScriptApp.newTrigger('autoOpenScraper').forSpreadsheet(SpreadsheetApp.getActive()).onOpen().create();
}

function autoOpenScraper() {
  try { openScraper(); } catch (e) {}
}

// ---------- called from the window ----------

// Built on use: STATUS lives in Main.gs, and Apps Script may load the files in any order.
function steps() {
  return [
  [STATUS.queued, 'ממתין להתחלה', 5, 'working'],
  [STATUS.research, 'מחפש את היצרן והאתר הרשמי', 25, 'working'],
  [STATUS.official, 'קורא את אתר היצרן', 45, 'working'],
  [STATUS.write, 'כותב בעברית', 65, 'working'],
  [STATUS.save, 'שומר תמונות וקבצים בדרייב', 85, 'working'],
  [STATUS.doneNotes, 'מוכן, חסר משהו', 100, 'warn'],
  [STATUS.done, 'מוכן', 100, 'done'],
  [STATUS.error, 'נכשל', 100, 'error'],
  [STATUS.stopped, 'נעצר', 0, 'stopped'],
  ];
}

function sidebarState() {
  ensureOwnCopy();
  var sheet = SpreadsheetApp.getActive().getSheetByName(SHEET_PRODUCTS);
  var items = [];
  var n = sheet ? sheet.getLastRow() - 1 : 0;
  if (n > 0) {
    var first = Math.max(2, n + 2 - 40);   // the last 40 rows
    var count = n + 2 - first;
    var values = sheet.getRange(first, 1, count, HEADERS.length).getValues();
    var formulas = sheet.getRange(first, COL.FOLDER, count, 1).getFormulas();
    values.forEach(function (r, i) {
      var link = String(r[COL.LINK - 1]).trim();
      if (!/^https?:\/\//i.test(link)) return;
      var status = String(r[COL.STATUS - 1]);
      var step = steps().filter(function (s) { return status.indexOf(s[0]) === 0; })[0] || ['', status ? status : 'עוד לא התחיל', 0, status ? 'working' : 'idle'];
      var folder = (String(formulas[i][0]).match(/HYPERLINK\("([^"]+)"/) || [])[1] || '';
      items.push({
        link: link, name: String(r[COL.NAME - 1]).replace(/^'/, ''), manufacturer: String(r[COL.MANUFACTURER - 1]).replace(/^'/, ''),
        step: step[1], pct: step[2], state: step[3], folderUrl: folder, notes: String(r[COL.NOTES - 1]).replace(/^'/, ''),
      });
    });
  }
  return { hasKey: !!readSettings().apiKey, items: items.reverse() };
}

function sidebarStart(text) {
  ensureOwnCopy();
  setup();
  if (!readSettings().apiKey) return { ok: false, needKey: true, message: 'קודם מדביקים את מפתח ה-API למעלה.' };
  var seen = {};
  var links = (String(text || '').match(/https?:\/\/[^\s"'<>]+/gi) || [])
    .map(function (l) { return l.replace(/[),.;:!?]+$/, ''); })
    .filter(function (l) { if (seen[l]) return false; seen[l] = true; return true; });
  if (!links.length) return { ok: false, message: 'לא מצאתי קישורים. מדביקים קישורים שמתחילים ב-https://' };
  var sheet = SpreadsheetApp.getActive().getSheetByName(SHEET_PRODUCTS);
  sheet.getRange(sheet.getLastRow() + 1, COL.LINK, links.length, 1).setValues(links.map(function (l) { return [l]; }));
  var added = queueSheetRows() || 0;
  return { ok: true, message: added === 1 ? 'מוצר אחד התחיל. אפשר לסגור הכל - העבודה ממשיכה ברקע.' : added + ' מוצרים התחילו. אפשר לסגור הכל - העבודה ממשיכה ברקע.' };
}

function sidebarSaveKey(key) {
  ensureOwnCopy();
  key = String(key || '').trim();
  if (!/^sk-ant-/.test(key)) return { ok: false, message: 'המפתח מתחיל ב-sk-ant-. מעתיקים אותו שוב מ-console.anthropic.com' };
  var settings = readSettings();
  try {   // a free request, just to check the key
    var r = UrlFetchApp.fetch(settings.apiBase + '/v1/models', { muteHttpExceptions: true, headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01' } });
    if (r.getResponseCode() === 401 || r.getResponseCode() === 403) return { ok: false, message: 'המפתח לא תקין. מעתיקים אותו שוב מ-console.anthropic.com' };
  } catch (e) {}
  PropertiesService.getScriptProperties().setProperty('ANTHROPIC_API_KEY', key);
  SETTINGS_MEMO = null;
  return { ok: true, message: 'המפתח נשמר ✓' };
}

function sidebarStop() {
  stopRun();
  return sidebarState();
}

function sidebarOpenSettings() {
  var ss = SpreadsheetApp.getActive();
  ss.setActiveSheet(ss.getSheetByName(SHEET_SETTINGS));
}

var SIDEBAR_HTML = `<!doctype html>
<html lang="he" dir="rtl">
<head>
<meta charset="utf-8">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Heebo:wght@400;500;700;800&display=swap">
<style>
  :root {
    --red:#c8102e; --red-dark:#a00d24; --red-soft:#fbe9ec;
    --ink:#1f2326; --ink-2:#4a5055; --muted:#80868b; --line:#e3e4e6; --bg:#f4f4f5; --card:#ffffff;
    --ok:#1f8a4c; --ok-soft:#e7f4ec; --warn:#b26a00; --warn-soft:#fdf2e0;
    --shadow:0 1px 2px rgba(31,35,38,.06), 0 2px 8px rgba(31,35,38,.05);
  }
  * { box-sizing:border-box; }
  [hidden] { display:none !important; }
  html, body { overflow-x:hidden; }
  body { margin:0; padding:0 0 16px; font:14px/1.5 "Heebo", "Segoe UI", Arial, sans-serif; color:var(--ink); background:var(--bg); }
  .brand { height:4px; background:linear-gradient(90deg, var(--red) 0 70%, var(--ink) 70% 100%); }
  .wrap { padding:14px 12px 0; display:grid; gap:12px; }
  .card { background:var(--card); border-radius:12px; box-shadow:var(--shadow); padding:14px; display:grid; gap:10px; }
  .label { font-weight:700; font-size:15px; margin:0; }
  .hint { font-size:12px; color:var(--muted); margin:-6px 0 0; }
  textarea, input { width:100%; font:13px/1.45 Arial, sans-serif; direction:ltr; text-align:left; color:var(--ink);
    border:1px solid var(--line); border-radius:8px; padding:9px 10px; background:#fbfbfb; transition:border-color .15s, box-shadow .15s; }
  textarea { min-height:92px; resize:vertical; }
  textarea::placeholder, input::placeholder { color:#a3a8ac; }
  textarea:focus, input:focus { outline:none; border-color:var(--red); box-shadow:0 0 0 3px var(--red-soft); background:#fff; }
  .primary { font:700 15px "Heebo", Arial, sans-serif; border:0; border-radius:8px; padding:11px; cursor:pointer; width:100%;
    background:var(--red); color:#fff; display:flex; align-items:center; justify-content:center; gap:8px; transition:background .15s; }
  .primary:hover { background:var(--red-dark); }
  .primary:disabled { opacity:.6; cursor:default; }
  .primary svg { width:13px; height:13px; fill:currentColor; }
  button:focus-visible, a:focus-visible { outline:3px solid var(--red-soft); outline-offset:2px; }
  .msg { font-size:12.5px; min-height:0; margin:0; }
  .msg:empty { display:none; }
  .msg.bad { color:var(--red); } .msg.good { color:var(--ok); }
  .key { box-shadow:inset -4px 0 0 var(--red), var(--shadow); }
  .key p { margin:0; font-size:13px; color:var(--ink-2); }
  .key a { color:var(--red); font-weight:500; }

  .summary { display:flex; gap:6px; flex-wrap:wrap; font-size:12px; padding:2px 2px 0; }
  .chip { border-radius:999px; padding:2px 10px; background:#e9eaec; color:var(--ink-2); font-weight:500; font-variant-numeric:tabular-nums; }
  .chip.ok { background:var(--ok-soft); color:var(--ok); } .chip.run { background:var(--red-soft); color:var(--red); }

  .list { display:grid; gap:10px; }
  .item { background:var(--card); border-radius:12px; box-shadow:var(--shadow); padding:12px; display:grid; gap:9px; }
  .head { display:grid; grid-template-columns:28px minmax(0, 1fr); gap:10px; align-items:start; }
  .head > div { min-width:0; }
  .dot { width:28px; height:28px; border-radius:50%; display:grid; place-items:center; font-weight:800; font-size:14px; }
  .working .dot { border:3px solid var(--red-soft); border-top-color:var(--red); animation:spin .9s linear infinite; }
  .idle .dot, .stopped .dot { background:#e9eaec; color:var(--muted); }
  .done .dot { background:var(--ok); color:#fff; } .warn .dot { background:var(--warn); color:#fff; } .error .dot { background:var(--red); color:#fff; }
  @keyframes spin { to { transform:rotate(360deg); } }
  .name { font-weight:700; font-size:14px; line-height:1.35; overflow-wrap:anywhere; }
  .meta { font-size:11.5px; color:var(--muted); direction:ltr; text-align:right; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; margin-top:2px; }
  .steps { display:grid; grid-template-columns:repeat(4, 1fr); gap:4px; }
  .steps span { font-size:10.5px; color:var(--muted); text-align:center; padding-top:7px; position:relative; }
  .steps span::before { content:""; position:absolute; top:0; right:0; left:0; height:4px; border-radius:2px; background:#e6e7e9; }
  .steps .on { color:var(--ink-2); } .steps .on::before { background:var(--red); }
  .steps .now { color:var(--red); font-weight:700; }
  .steps .now::before { background:linear-gradient(90deg, var(--red) 0 50%, #e37a8b 50% 100%); background-size:16px 4px; animation:flow .8s linear infinite; }
  @keyframes flow { to { background-position:-16px 0; } }
  .done .steps span::before, .warn .steps span::before { background:var(--ok); } .done .steps span, .warn .steps span { color:var(--ok); }
  .state { font-size:13px; font-weight:500; color:var(--ink-2); }
  .done .state { color:var(--ok); } .warn .state { color:var(--warn); } .error .state { color:var(--red); }
  .actions { display:flex; gap:8px; align-items:center; justify-content:space-between; }
  .state { min-width:0; }
  .open { white-space:nowrap; flex:none; display:inline-flex; align-items:center; gap:6px; text-decoration:none; font-weight:700; font-size:13px; color:var(--ink);
    border:1.5px solid var(--ink); border-radius:8px; padding:6px 12px; transition:background .15s, color .15s; }
  .open:hover { background:var(--ink); color:#fff; }
  .open svg { width:14px; height:14px; fill:none; stroke:currentColor; stroke-width:2; }
  details { font-size:12px; color:var(--ink-2); } summary { cursor:pointer; color:var(--muted); font-weight:500; }
  details[open] summary { margin-bottom:4px; }
  .empty { text-align:center; color:var(--muted); font-size:13px; padding:18px 8px; border:1.5px dashed #d4d6d9; border-radius:12px; }
  .foot { display:flex; justify-content:space-between; padding:14px 14px 0; }
  .link { background:none; border:0; padding:0; cursor:pointer; font:500 12.5px "Heebo", Arial, sans-serif; color:var(--muted); }
  .link:hover { color:var(--ink); }
  .link.danger { color:var(--red); }
  @media (prefers-reduced-motion: reduce) { .working .dot, .steps .now::before { animation:none; } }
</style>
</head>
<body>
  <div class="brand"></div>
  <div class="wrap">
    <section id="keyCard" class="card key" hidden>
      <p class="label">צעד אחד לפני שמתחילים</p>
      <p>מדביקים מפתח API של Claude. יוצרים אותו ב-<a href="https://console.anthropic.com/settings/keys" target="_blank" rel="noopener">console.anthropic.com</a> ← Create Key.</p>
      <input id="key" type="password" placeholder="sk-ant-..." autocomplete="off">
      <button id="saveKey" class="primary" type="button">שמור מפתח</button>
      <p id="keyMsg" class="msg" role="status"></p>
    </section>

    <section class="card">
      <p class="label">קישורים למוצרים</p>
      <p class="hint">אחד או הרבה, מכל אתר</p>
      <textarea id="links" placeholder="https://..."></textarea>
      <button id="start" class="primary" type="button"><svg viewBox="0 0 10 10" aria-hidden="true"><path d="M1 0l8 5-8 5z"/></svg>התחל</button>
      <p id="msg" class="msg" role="status"></p>
    </section>

    <div id="summary" class="summary"></div>
    <div id="list" class="list" aria-live="polite"></div>
  </div>

  <div class="foot">
    <button id="settings" class="link" type="button">הגדרות</button>
    <button id="stop" class="link danger" type="button">עצור הכל</button>
  </div>

<script>
  var $ = function (id) { return document.getElementById(id); };
  var timer = null;
  var stopArmed = false;
  var STEP_NAMES = ['יצרן', 'אתר', 'עברית', 'דרייב'];
  var FOLDER_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>';

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function shortLink(url) { return url.replace(/^https?:\\/\\/(www\\.)?/, '').replace(/\\/$/, ''); }
  // Until the product has a name: the last part of its link, readable ("mse-100-with-shp-9x" -> "mse 100 with shp 9x").
  function guessName(url) {
    var last = url.split(/[?#]/)[0].replace(/\\/+$/, '').split('/').pop() || url;
    try { last = decodeURIComponent(last); } catch (e) {}
    return last.replace(/\\.(html?|php|aspx?)$/i, '').replace(/[-_+]+/g, ' ');
  }

  // Which of the 4 steps is running (pct 25/45/65/85 -> step 0..3); finished items fill all 4.
  function stepsHtml(it) {
    var now = { 25: 0, 45: 1, 65: 2, 85: 3 }[it.pct];
    var finished = it.pct === 100 && (it.state === 'done' || it.state === 'warn');
    return '<div class="steps">' + STEP_NAMES.map(function (n, i) {
      var cls = finished || (now !== undefined && i < now) ? 'on' : (i === now ? 'now' : '');
      return '<span class="' + cls + '">' + n + '</span>';
    }).join('') + '</div>';
  }

  function dotHtml(state) {
    return '<div class="dot" aria-hidden="true">' + ({ done: '✓', warn: '!', error: '×' }[state] || '') + '</div>';
  }

  function render(state) {
    $('keyCard').hidden = state.hasKey;
    var items = state.items || [];
    var n = { done: 0, working: 0, other: 0 };
    items.forEach(function (it) { if (it.state === 'done' || it.state === 'warn') n.done++; else if (it.state === 'working') n.working++; else n.other++; });
    $('summary').innerHTML = items.length
      ? (n.working ? '<span class="chip run">' + n.working + ' בעבודה</span>' : '') + (n.done ? '<span class="chip ok">' + n.done + ' מוכנים</span>' : '') + (n.other ? '<span class="chip">' + n.other + ' אחרים</span>' : '')
      : '';
    if (!items.length) {
      $('list').innerHTML = '<div class="empty">עוד אין מוצרים.<br>מדביקים קישורים ולוחצים "התחל".</div>';
    } else {
      $('list').innerHTML = items.map(function (it) {
        return '<article class="item ' + it.state + '">' +
          '<div class="head">' + dotHtml(it.state) + '<div>' +
            '<div class="name">' + esc(it.name || guessName(it.link)) + '</div>' +
            '<div class="meta" title="' + esc(it.link) + '">' + esc(it.manufacturer ? it.manufacturer + ' · ' + shortLink(it.link) : shortLink(it.link)) + '</div>' +
          '</div></div>' +
          (it.state === 'working' || it.state === 'done' || it.state === 'warn' ? stepsHtml(it) : '') +
          '<div class="actions"><span class="state">' + esc(it.step) + '</span>' +
            (it.folderUrl ? '<a class="open" href="' + esc(it.folderUrl) + '" target="_blank" rel="noopener">' + FOLDER_ICON + 'פתח תיקייה</a>' : '') +
          '</div>' +
          (it.notes ? '<details><summary>' + (it.state === 'error' ? 'מה קרה?' : 'מה חסר?') + '</summary>' + esc(it.notes) + '</details>' : '') +
          '</article>';
      }).join('');
    }
    clearTimeout(timer);
    timer = setTimeout(refresh, n.working ? 5000 : 30000);
  }

  function refresh() {
    google.script.run.withSuccessHandler(render).withFailureHandler(function () { timer = setTimeout(refresh, 15000); }).sidebarState();
  }

  function say(el, text, good) { el.textContent = text || ''; el.className = 'msg ' + (good ? 'good' : 'bad'); }

  $('start').addEventListener('click', function () {
    var text = $('links').value;
    if (!text.trim()) { say($('msg'), 'מדביקים קודם קישורים בתיבה.'); return; }
    $('start').disabled = true;
    say($('msg'), 'מתחיל…', true);
    google.script.run.withSuccessHandler(function (r) {
      $('start').disabled = false;
      say($('msg'), r.message, r.ok);
      if (r.ok) $('links').value = '';
      if (r.needKey) $('keyCard').hidden = false;
      refresh();
    }).withFailureHandler(function (e) {
      $('start').disabled = false;
      say($('msg'), 'משהו השתבש: ' + (e && e.message || e));
    }).sidebarStart(text);
  });

  $('saveKey').addEventListener('click', function () {
    $('saveKey').disabled = true;
    say($('keyMsg'), 'בודק את המפתח…', true);
    google.script.run.withSuccessHandler(function (r) {
      $('saveKey').disabled = false;
      say($('keyMsg'), r.message, r.ok);
      if (r.ok) { $('key').value = ''; setTimeout(refresh, 800); }
    }).withFailureHandler(function (e) {
      $('saveKey').disabled = false;
      say($('keyMsg'), 'משהו השתבש: ' + (e && e.message || e));
    }).sidebarSaveKey($('key').value);
  });

  $('stop').addEventListener('click', function () {
    if (!stopArmed) {
      stopArmed = true;
      $('stop').textContent = 'בטוח? לחצו שוב לעצירה';
      setTimeout(function () { stopArmed = false; $('stop').textContent = 'עצור הכל'; }, 4000);
      return;
    }
    stopArmed = false;
    $('stop').textContent = 'עצור הכל';
    google.script.run.withSuccessHandler(render).sidebarStop();
  });

  $('settings').addEventListener('click', function () { google.script.run.sidebarOpenSettings(); });

  refresh();
</script>
</body>
</html>`;
