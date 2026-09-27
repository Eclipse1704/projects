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
  [STATUS.doneNotes, 'מוכן (חסרים כמה פריטים)', 100, 'warn'],
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
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Assistant:wght@400;600;700&display=swap">
<style>
  :root { --ink:#17252a; --muted:#5b6b70; --line:#dde6e3; --soft:#f3f7f5; --accent:#137a4b; --accent-soft:#e3f2ea; --warn:#9a6200; --warn-soft:#fff3dc; --err:#b3261e; --err-soft:#fdecea; }
  * { box-sizing:border-box; }
  [hidden] { display:none !important; }
  body { margin:0; padding:14px; font:15px/1.5 "Assistant", Arial, sans-serif; color:var(--ink); background:#fff; }
  h2 { font-size:15px; margin:0 0 6px; }
  .card { border:1px solid var(--line); border-radius:10px; padding:12px; display:grid; gap:8px; }
  .key { background:var(--warn-soft); border-color:#f0d49a; }
  textarea { width:100%; min-height:96px; resize:vertical; font:13px/1.4 Arial, sans-serif; direction:ltr; text-align:left; border:1px solid var(--line); border-radius:8px; padding:8px; }
  textarea::placeholder { direction:rtl; text-align:right; font-family:"Assistant", Arial, sans-serif; font-size:14px; }
  input { width:100%; font:13px Arial, sans-serif; direction:ltr; border:1px solid var(--line); border-radius:8px; padding:8px; }
  button { font:700 16px "Assistant", Arial, sans-serif; border:0; border-radius:8px; padding:11px; cursor:pointer; background:var(--accent); color:#fff; width:100%; }
  button:disabled { opacity:.55; cursor:default; }
  button:focus-visible, a:focus-visible, textarea:focus-visible, input:focus-visible { outline:3px solid #7cc4a0; outline-offset:1px; }
  .msg { font-size:13px; min-height:1.2em; margin:0; }
  .msg.bad { color:var(--err); } .msg.good { color:var(--accent); }
  .list { display:grid; gap:10px; margin-top:16px; }
  .item { border:1px solid var(--line); border-radius:10px; padding:10px; display:grid; gap:6px; }
  .name { font-weight:700; font-size:14px; overflow-wrap:anywhere; }
  .sub { font-size:12px; color:var(--muted); direction:ltr; text-align:right; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .bar { height:6px; border-radius:3px; background:var(--soft); overflow:hidden; }
  .bar i { display:block; height:100%; background:var(--accent); transition:width .6s; }
  .item.working .bar i { background-image:linear-gradient(90deg, var(--accent) 0 50%, #2fa36c 50% 100%); background-size:24px 6px; animation:move 1s linear infinite; }
  @keyframes move { to { background-position:24px 0; } }
  @media (prefers-reduced-motion: reduce) { .item.working .bar i { animation:none; } }
  .step { font-size:13px; font-weight:600; }
  .done .step { color:var(--accent); } .warn .step { color:var(--warn); } .error .step { color:var(--err); } .error .bar i { background:var(--err); }
  .open { display:block; text-align:center; text-decoration:none; background:var(--accent-soft); color:var(--accent); font-weight:700; border-radius:8px; padding:8px; }
  details { font-size:12px; color:var(--muted); } summary { cursor:pointer; }
  .foot { display:flex; justify-content:space-between; margin-top:18px; font-size:13px; }
  .link { background:none; color:var(--muted); width:auto; padding:0; font:600 13px "Assistant", Arial, sans-serif; text-decoration:underline; }
  .link.danger { color:var(--err); }
  .empty { color:var(--muted); font-size:13px; text-align:center; padding:12px 0; }
</style>
</head>
<body>
  <section id="keyCard" class="card key" hidden>
    <h2>צעד אחד לפני שמתחילים</h2>
    <div style="font-size:13px">מדביקים מפתח API של Claude. יוצרים אותו ב-<a href="https://console.anthropic.com/settings/keys" target="_blank" rel="noopener">console.anthropic.com</a> ← Create Key.</div>
    <input id="key" type="password" placeholder="sk-ant-..." autocomplete="off">
    <button id="saveKey" type="button">שמור מפתח</button>
    <p id="keyMsg" class="msg" role="status"></p>
  </section>

  <section class="card" style="margin-top:12px">
    <h2>קישורים למוצרים</h2>
    <textarea id="links" placeholder="מדביקים כאן קישורים למוצרים - אחד או הרבה, מכל אתר"></textarea>
    <button id="start" type="button">▶ התחל</button>
    <p id="msg" class="msg" role="status"></p>
  </section>

  <div id="list" class="list" aria-live="polite"></div>

  <div class="foot">
    <button id="settings" class="link" type="button">הגדרות</button>
    <button id="stop" class="link danger" type="button">עצור הכל</button>
  </div>

<script>
  var $ = function (id) { return document.getElementById(id); };
  var timer = null;
  var stopArmed = false;

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function shortLink(url) { return url.replace(/^https?:\\/\\/(www\\.)?/, '').replace(/\\/$/, ''); }
  // Until the product has a name: the last part of its link, readable ("mse-100-with-shp-9x" -> "mse 100 with shp 9x").
  function guessName(url) {
    var last = url.split(/[?#]/)[0].replace(/\\/+$/, '').split('/').pop() || url;
    try { last = decodeURIComponent(last); } catch (e) {}
    return last.replace(/\\.(html?|php|aspx?)$/i, '').replace(/[-_+]+/g, ' ');
  }

  function render(state) {
    $('keyCard').hidden = state.hasKey;
    var items = state.items || [];
    if (!items.length) {
      $('list').innerHTML = '<div class="empty">עוד אין מוצרים. מדביקים קישורים ולוחצים "התחל".</div>';
    } else {
      $('list').innerHTML = items.map(function (it) {
        return '<div class="item ' + it.state + '">' +
          '<div class="name">' + esc(it.name || guessName(it.link)) + '</div>' +
          '<div class="sub" title="' + esc(it.link) + '">' + esc(it.manufacturer ? it.manufacturer + ' · ' + shortLink(it.link) : shortLink(it.link)) + '</div>' +
          '<div class="bar"><i style="width:' + it.pct + '%"></i></div>' +
          '<div class="step">' + esc(it.step) + '</div>' +
          (it.folderUrl ? '<a class="open" href="' + esc(it.folderUrl) + '" target="_blank" rel="noopener">📁 פתח תיקייה</a>' : '') +
          (it.notes ? '<details><summary>' + (it.state === 'error' ? 'מה קרה?' : 'מה חסר?') + '</summary>' + esc(it.notes) + '</details>' : '') +
          '</div>';
      }).join('');
    }
    var busy = items.some(function (it) { return it.state === 'working'; });
    clearTimeout(timer);
    timer = setTimeout(refresh, busy ? 5000 : 30000);
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
