// The app: a web page (Deploy -> Web app) where you paste links, press start, watch progress, open folders
// and change the settings. No spreadsheet needed; everything is saved in the script and in Google Drive.

function doGet() {
  ensureOwnCopy();
  return HtmlService.createHtmlOutput(APP_HTML)
    .setTitle('סורק מוצרים')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1');
}

// ---------- called from the page ----------

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

function appState() {
  ensureOwnCopy();
  var items = getItems().slice(-60).reverse().map(function (it) {
    var status = String(it.status || '');
    var step = steps().filter(function (s) { return status.indexOf(s[0]) === 0; })[0] || ['', status || 'עוד לא התחיל', 0, status ? 'working' : 'idle'];
    return { link: it.link, name: it.name, manufacturer: it.manufacturer, step: step[1], pct: step[2], state: step[3], folderUrl: it.folderUrl, notes: it.notes };
  });
  return { hasKey: !!readSettings().apiKey, items: items, worker: workerStatus() };
}

function appStart(text) {
  ensureOwnCopy();
  if (!readSettings().apiKey) return { ok: false, needKey: true, message: 'קודם מדביקים את מפתח ה-API למעלה.' };
  var seen = {};
  var links = (String(text || '').match(/https?:\/\/[^\s"'<>]+/gi) || [])
    .map(function (l) { return l.replace(/[),.;:!?]+$/, ''); })
    .filter(function (l) { if (seen[l]) return false; seen[l] = true; return true; });
  if (!links.length) return { ok: false, message: 'לא מצאתי קישורים. מדביקים קישורים שמתחילים ב-https://' };
  PropertiesService.getScriptProperties().deleteProperty('LAST_ERROR');
  var added = queueLinks(links);
  return { ok: true, message: added === 1 ? 'מוצר אחד התחיל. אפשר לסגור את הדף - העבודה ממשיכה ברקע.' : added + ' מוצרים התחילו. אפשר לסגור את הדף - העבודה ממשיכה ברקע.' };
}

function appSaveKey(key) {
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

function appStop() {
  stopRun();
  return appState();
}

// Removes finished products from the list (their Drive folders stay).
function appClearFinished() {
  var lock = LockService.getScriptLock();
  lock.waitLock(60000);
  try {
    var active = getStages();
    ITEMS_MEMO = getItems().filter(function (it) { return active[it.id]; });
    flushItems();
  } finally {
    lock.releaseLock();
  }
  return appState();
}

function appGetSettings() {
  ensureOwnCopy();
  var key = readSettings().apiKey;
  return { values: settingsMap(), hasKey: !!key, keyEnd: key ? key.slice(-4) : '' };
}

function appSaveSettings(values) {
  saveSettings(values || {});
  return appGetSettings();
}

function appResetSettings() {
  setBig('SETTINGS', '');
  SETTINGS_MEMO = null;
  return appGetSettings();
}

var APP_HTML = `<!doctype html>
<html lang="he" dir="rtl">
<head>
<meta charset="utf-8">
<title>סורק מוצרים</title>
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
  body { margin:0; padding:0 0 32px; font:14px/1.5 "Heebo", "Segoe UI", Arial, sans-serif; color:var(--ink); background:var(--bg); }
  .brand { height:4px; background:var(--red); }
  .wrap { max-width:760px; margin:0 auto; padding:18px 16px 0; display:grid; gap:14px; }
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
  .foot { max-width:760px; margin:0 auto; display:flex; justify-content:flex-end; padding:16px 18px 0; }
  .link { background:none; border:0; padding:0; cursor:pointer; font:500 12.5px "Heebo", Arial, sans-serif; color:var(--muted); }
  .link:hover { color:var(--ink); }
  .link.danger { color:var(--red); }
  @media (prefers-reduced-motion: reduce) { .working .dot, .steps .now::before { animation:none; } }

  .top { background:var(--ink); color:#fff; }
  .top .in { max-width:760px; margin:0 auto; padding:14px 16px; display:flex; align-items:center; justify-content:space-between; gap:12px; }
  .title { margin:0; font:800 19px "Heebo", Arial, sans-serif; letter-spacing:.2px; display:flex; align-items:center; gap:10px; }
  .title i { width:10px; height:22px; background:var(--red); border-radius:2px; display:inline-block; }
  .tab { background:none; border:1.5px solid rgba(255,255,255,.35); color:#fff; border-radius:8px; padding:6px 12px; cursor:pointer;
    font:500 13px "Heebo", Arial, sans-serif; display:inline-flex; align-items:center; gap:6px; transition:border-color .15s, background .15s; }
  .tab:hover { border-color:#fff; background:rgba(255,255,255,.08); }
  .tab svg { width:15px; height:15px; fill:none; stroke:currentColor; stroke-width:2; }
  .worker { font-size:12px; color:var(--muted); display:flex; align-items:center; gap:6px; padding:0 2px; }
  .worker:empty { display:none; }
  .worker b { width:8px; height:8px; border-radius:50%; background:var(--ok); display:inline-block; flex:none; }
  .worker.bad { color:var(--red); } .worker.bad b { background:var(--red); }
  .field { display:grid; gap:6px; }
  .field label { font-weight:700; font-size:14px; }
  .field .hint { margin:0; }
  .field textarea.rtl, .field input.rtl { direction:rtl; text-align:right; font-family:"Heebo", Arial, sans-serif; }
  .field textarea.tall { min-height:160px; }
  .seg { display:grid; grid-template-columns:1fr 1fr; gap:6px; }
  .seg button { font:500 13px "Heebo", Arial, sans-serif; border:1.5px solid var(--line); background:#fbfbfb; color:var(--ink-2);
    border-radius:8px; padding:9px 8px; cursor:pointer; text-align:center; line-height:1.3; }
  .seg button small { display:block; font-size:11px; color:var(--muted); font-weight:400; }
  .seg button.sel { border-color:var(--red); background:var(--red-soft); color:var(--red); font-weight:700; }
  .grid2 { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
  @media (max-width:560px) { .grid2 { grid-template-columns:1fr; } .top .in { padding:12px 16px; } .title { font-size:17px; } }
  .ghost { font:700 14px "Heebo", Arial, sans-serif; border:1.5px solid var(--line); border-radius:8px; padding:10px; cursor:pointer; background:#fff; color:var(--ink-2); width:100%; }
  .ghost:hover { border-color:var(--ink); color:var(--ink); }
  .row { display:flex; gap:10px; } .row > * { flex:1; }
  .sub { font-size:12px; color:var(--muted); margin:0; }
</style>
</head>
<body>
  <header class="top"><div class="in">
    <h1 class="title"><i aria-hidden="true"></i>סורק מוצרים</h1>
    <button id="tab" class="tab" type="button"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg><span>הגדרות</span></button>
  </div></header>
  <div class="brand"></div>

  <main id="home" class="wrap">
    <section id="keyCard" class="card key" hidden>
      <p class="label">צעד אחד לפני שמתחילים</p>
      <p>מדביקים מפתח API של Claude. יוצרים אותו ב-<a href="https://console.anthropic.com/settings/keys" target="_blank" rel="noopener">console.anthropic.com</a> ← Create Key.</p>
      <input id="key" type="password" placeholder="sk-ant-..." autocomplete="off">
      <button id="saveKey" class="primary" type="button">שמור מפתח</button>
      <p id="keyMsg" class="msg" role="status"></p>
    </section>

    <section class="card">
      <p class="label">קישורים למוצרים</p>
      <p class="hint">אחד או הרבה, מכל אתר. כל מוצר מקבל תיקייה משלו ב-Google Drive.</p>
      <textarea id="links" placeholder="https://..."></textarea>
      <button id="start" class="primary" type="button"><svg viewBox="0 0 10 10" aria-hidden="true"><path d="M1 0l8 5-8 5z"/></svg>התחל</button>
      <p id="msg" class="msg" role="status"></p>
    </section>

    <div id="worker" class="worker"></div>
    <div id="summary" class="summary"></div>
    <div id="list" class="list" aria-live="polite"></div>
    <div class="foot" style="padding:0; gap:18px">
      <button id="clear" class="link" type="button" hidden>נקה מוצרים שהסתיימו מהרשימה</button>
      <button id="stop" class="link danger" type="button" hidden>עצור הכל</button>
    </div>
  </main>

  <main id="settingsView" class="wrap" hidden>
    <section class="card">
      <div class="grid2">
        <div class="field">
          <label>מהירות</label>
          <div class="seg" data-key="מצב מהיר">
            <button type="button" data-v="כן">מהיר<small>מוכן תוך דקות · כ-0.4$ למוצר</small></button>
            <button type="button" data-v="לא">חסכוני<small>עד שעה · כ-0.2$ למוצר</small></button>
          </div>
        </div>
        <div class="field">
          <label>מודל</label>
          <div class="seg" data-key="מודל">
            <button type="button" data-v="claude-sonnet-5">Sonnet<small>מומלץ</small></button>
            <button type="button" data-v="claude-opus-5">Opus<small>חזק יותר · פי 2.5 במחיר</small></button>
          </div>
        </div>
        <div class="field">
          <label for="s-folder">תיקייה בדרייב</label>
          <input id="s-folder" class="rtl" data-key="תיקייה בדרייב">
        </div>
        <div class="field">
          <label>מייל כשהסריקה מסתיימת</label>
          <div class="seg" data-key="שליחת מייל בסיום">
            <button type="button" data-v="כן">כן</button>
            <button type="button" data-v="לא">לא</button>
          </div>
        </div>
      </div>
    </section>

    <section class="card">
      <div class="field">
        <label for="s-glossary">מילון מונחים</label>
        <p class="hint">שורה לכל מונח: אנגלית = איך אומרים אצלנו. מילה שיצאה לא טוב? מוסיפים אותה כאן.</p>
        <textarea id="s-glossary" class="tall" data-key="מילון מונחים"></textarea>
      </div>
      <div class="field">
        <label for="s-avoid">מילים שלא משתמשים בהן</label>
        <p class="hint">מילה או ביטוי בכל שורה. אם Claude משתמש באחד מהם, הטקסט חוזר אליו לתיקון.</p>
        <textarea id="s-avoid" class="rtl" data-key="מילים שלא משתמשים בהן"></textarea>
      </div>
      <div class="field">
        <label for="s-style">דפי דוגמה לסגנון</label>
        <p class="hint">דפי מוצר מהאתר שלכם, כתובת בכל שורה. Claude כותב באותו סגנון.</p>
        <textarea id="s-style" data-key="דפי דוגמה לסגנון"></textarea>
      </div>
    </section>

    <div class="row">
      <button id="saveSettings" class="primary" type="button">שמור הגדרות</button>
      <button id="back" class="ghost" type="button">חזרה</button>
    </div>
    <p id="setMsg" class="msg" role="status"></p>

    <section class="card">
      <p class="label">מפתח API של Claude</p>
      <p id="keyState" class="sub"></p>
      <input id="key2" type="password" placeholder="sk-ant-... (מפתח חדש)" autocomplete="off">
      <button id="saveKey2" class="ghost" type="button">החלף מפתח</button>
      <p id="keyMsg2" class="msg" role="status"></p>
    </section>
    <button id="reset" class="link" type="button" style="justify-self:start">החזר הגדרות ברירת מחדל</button>
  </main>

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
    var w = state.worker || {};
    $('worker').className = 'worker' + (w.lastError ? ' bad' : '');
    $('worker').innerHTML = w.lastError ? '<b></b>תקלה בהרצה ברקע, המערכת מנסה שוב: ' + esc(w.lastError)
      : w.running ? '<b></b>עובד ברקע. אפשר לסגור את הדף.' : '';
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
    $('stop').hidden = !n.working;
    $('clear').hidden = !(items.length - n.working);
    clearTimeout(timer);
    timer = setTimeout(refresh, n.working ? 5000 : 30000);
  }

  function refresh() {
    google.script.run.withSuccessHandler(render).withFailureHandler(function () { timer = setTimeout(refresh, 15000); }).appState();
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
      $('clear').addEventListener('click', function () { google.script.run.withSuccessHandler(render).appClearFinished(); });

  // ---------- settings ----------
  var values = {};
  function showSettings(show) {
    $('home').hidden = show; $('settingsView').hidden = !show;
    $('tab').querySelector('span').textContent = show ? 'חזרה' : 'הגדרות';
    say($('setMsg'), ''); say($('keyMsg2'), '');
    if (show) google.script.run.withSuccessHandler(fillSettings).appGetSettings();
    window.scrollTo(0, 0);
  }
  function fillSettings(r) {
    values = r.values;
    document.querySelectorAll('#settingsView [data-key]').forEach(function (el) {
      var v = values[el.getAttribute('data-key')] || '';
      if (el.classList.contains('seg')) el.querySelectorAll('button').forEach(function (b) { b.classList.toggle('sel', b.getAttribute('data-v') === v); });
      else el.value = v;
    });
    $('keyState').textContent = r.hasKey ? 'שמור מפתח שמסתיים ב-' + r.keyEnd : 'עוד לא נשמר מפתח.';
  }
  document.querySelectorAll('.seg button').forEach(function (b) {
    b.addEventListener('click', function () {
      b.parentNode.querySelectorAll('button').forEach(function (x) { x.classList.toggle('sel', x === b); });
    });
  });
  function collect() {
    var out = {};
    document.querySelectorAll('#settingsView [data-key]').forEach(function (el) {
      if (el.classList.contains('seg')) { var s = el.querySelector('.sel'); if (s) out[el.getAttribute('data-key')] = s.getAttribute('data-v'); }
      else out[el.getAttribute('data-key')] = el.value;
    });
    return out;
  }
  $('tab').addEventListener('click', function () { showSettings($('settingsView').hidden); });
  $('back').addEventListener('click', function () { showSettings(false); });
  $('saveSettings').addEventListener('click', function () {
    $('saveSettings').disabled = true;
    google.script.run.withSuccessHandler(function (r) {
      $('saveSettings').disabled = false; fillSettings(r); say($('setMsg'), 'ההגדרות נשמרו ✓. הן ישמשו מהסריקה הבאה.', true);
    }).withFailureHandler(function (e) { $('saveSettings').disabled = false; say($('setMsg'), 'משהו השתבש: ' + (e && e.message || e)); }).appSaveSettings(collect());
  });
  $('reset').addEventListener('click', function () {
    google.script.run.withSuccessHandler(function (r) { fillSettings(r); say($('setMsg'), 'חזרנו להגדרות ברירת המחדל ✓', true); }).appResetSettings();
  });
  $('saveKey2').addEventListener('click', function () {
    $('saveKey2').disabled = true;
    say($('keyMsg2'), 'בודק את המפתח…', true);
    google.script.run.withSuccessHandler(function (r) {
      $('saveKey2').disabled = false; say($('keyMsg2'), r.message, r.ok);
      if (r.ok) { $('key2').value = ''; google.script.run.withSuccessHandler(fillSettings).appGetSettings(); }
    }).withFailureHandler(function (e) { $('saveKey2').disabled = false; say($('keyMsg2'), 'משהו השתבש: ' + (e && e.message || e)); }).appSaveKey($('key2').value);
  });

  refresh();
    }).withFailureHandler(function (e) {
      $('start').disabled = false;
      say($('msg'), 'משהו השתבש: ' + (e && e.message || e));
    }).appStart(text);
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
    }).appSaveKey($('key').value);
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
    google.script.run.withSuccessHandler(render).appStop();
  });


  $('clear').addEventListener('click', function () { google.script.run.withSuccessHandler(render).appClearFinished(); });

  // ---------- settings ----------
  var values = {};
  function showSettings(show) {
    $('home').hidden = show; $('settingsView').hidden = !show;
    $('tab').querySelector('span').textContent = show ? 'חזרה' : 'הגדרות';
    say($('setMsg'), ''); say($('keyMsg2'), '');
    if (show) google.script.run.withSuccessHandler(fillSettings).appGetSettings();
    window.scrollTo(0, 0);
  }
  function fillSettings(r) {
    values = r.values;
    document.querySelectorAll('#settingsView [data-key]').forEach(function (el) {
      var v = values[el.getAttribute('data-key')] || '';
      if (el.classList.contains('seg')) el.querySelectorAll('button').forEach(function (b) { b.classList.toggle('sel', b.getAttribute('data-v') === v); });
      else el.value = v;
    });
    $('keyState').textContent = r.hasKey ? 'שמור מפתח שמסתיים ב-' + r.keyEnd : 'עוד לא נשמר מפתח.';
  }
  document.querySelectorAll('.seg button').forEach(function (b) {
    b.addEventListener('click', function () {
      b.parentNode.querySelectorAll('button').forEach(function (x) { x.classList.toggle('sel', x === b); });
    });
  });
  function collect() {
    var out = {};
    document.querySelectorAll('#settingsView [data-key]').forEach(function (el) {
      if (el.classList.contains('seg')) { var s = el.querySelector('.sel'); if (s) out[el.getAttribute('data-key')] = s.getAttribute('data-v'); }
      else out[el.getAttribute('data-key')] = el.value;
    });
    return out;
  }
  $('tab').addEventListener('click', function () { showSettings($('settingsView').hidden); });
  $('back').addEventListener('click', function () { showSettings(false); });
  $('saveSettings').addEventListener('click', function () {
    $('saveSettings').disabled = true;
    google.script.run.withSuccessHandler(function (r) {
      $('saveSettings').disabled = false; fillSettings(r); say($('setMsg'), 'ההגדרות נשמרו ✓. הן ישמשו מהסריקה הבאה.', true);
    }).withFailureHandler(function (e) { $('saveSettings').disabled = false; say($('setMsg'), 'משהו השתבש: ' + (e && e.message || e)); }).appSaveSettings(collect());
  });
  $('reset').addEventListener('click', function () {
    google.script.run.withSuccessHandler(function (r) { fillSettings(r); say($('setMsg'), 'חזרנו להגדרות ברירת המחדל ✓', true); }).appResetSettings();
  });
  $('saveKey2').addEventListener('click', function () {
    $('saveKey2').disabled = true;
    say($('keyMsg2'), 'בודק את המפתח…', true);
    google.script.run.withSuccessHandler(function (r) {
      $('saveKey2').disabled = false; say($('keyMsg2'), r.message, r.ok);
      if (r.ok) { $('key2').value = ''; google.script.run.withSuccessHandler(fillSettings).appGetSettings(); }
    }).withFailureHandler(function (e) { $('saveKey2').disabled = false; say($('keyMsg2'), 'משהו השתבש: ' + (e && e.message || e)); }).appSaveKey($('key2').value);
  });

  refresh();
</script>
</body>
</html>`;
