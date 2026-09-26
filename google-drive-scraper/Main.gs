// Product scraper -> Google Drive.
// Paste product links in the "מוצרים" sheet, choose "סורק מוצרים ▸ הרץ". A 1-minute trigger then moves
// every product through these steps until its Drive folder is ready:
//   new -> research (Claude batch: manufacturer + official site) -> official (read official pages)
//       -> write (Claude batch: Hebrew text + choose images/PDFs/videos) -> save (Drive folder) -> done

var TICK_BUDGET_MS = 4.5 * 60 * 1000;   // Apps Script stops a run after 6 minutes
var MAX_BATCH_BYTES = 30 * 1024 * 1024;  // UrlFetchApp payload limit is 50MB
var MAX_PDF_FOR_CLAUDE = 10 * 1024 * 1024;
var MAX_WRITE_ATTEMPTS = 3;

var STATUS = {
  queued: 'ממתין בתור',
  research: 'Claude מחפש את היצרן והאתר הרשמי…',
  official: 'קורא את אתר היצרן…',
  write: 'Claude כותב בעברית…',
  save: 'שומר בדרייב…',
  done: '✓ הושלם',
  doneNotes: '✓ הושלם, עם הערות',
  error: '✗ שגיאה',
  stopped: 'נעצר',
};

// ---------------- Menu & setup ----------------

function onOpen() {
  SpreadsheetApp.getUi().createMenu('סורק מוצרים')
    .addItem('▶ הרץ על הקישורים', 'startRun')
    .addItem('הגדרת מפתח API של Claude', 'setApiKey')
    .addSeparator()
    .addItem('■ עצור', 'stopRun')
    .addToUi();
}

function setup() {
  var ss = SpreadsheetApp.getActive();
  var products = ss.getSheetByName(SHEET_PRODUCTS) || ss.insertSheet(SHEET_PRODUCTS, 0);
  if (products.getLastRow() === 0) {
    products.getRange(1, 1, 1, HEADERS.length).setValues([HEADERS]).setFontWeight('bold');
    products.setFrozenRows(1);
    products.setRightToLeft(true);
    products.setColumnWidth(COL.LINK, 360);
    products.setColumnWidth(COL.STATUS, 220);
    products.setColumnWidth(COL.NAME, 320);
    products.setColumnWidth(COL.FOLDER, 200);
    products.setColumnWidth(COL.NOTES, 360);
    products.hideColumns(COL.ID);
  }
  var settings = ss.getSheetByName(SHEET_SETTINGS) || ss.insertSheet(SHEET_SETTINGS);
  if (settings.getLastRow() === 0) {
    settings.getRange(1, 1, 1, 3).setValues([['הגדרה', 'ערך', 'הסבר']]).setFontWeight('bold');
    settings.getRange(2, 1, DEFAULT_SETTINGS.length, 3).setValues(DEFAULT_SETTINGS).setWrap(true).setVerticalAlignment('top');
    settings.setRightToLeft(true);
    settings.setColumnWidth(1, 160);
    settings.setColumnWidth(2, 520);
    settings.setColumnWidth(3, 320);
  }
}

function setApiKey() {
  var ui = SpreadsheetApp.getUi();
  var r = ui.prompt('מפתח API של Claude', 'הדביקו את המפתח מ-console.anthropic.com (נשמר רק בחשבון שלכם):', ui.ButtonSet.OK_CANCEL);
  if (r.getSelectedButton() !== ui.Button.OK) return;
  var key = r.getResponseText().trim();
  if (key) {
    PropertiesService.getUserProperties().setProperty('ANTHROPIC_API_KEY', key);
    SETTINGS_MEMO = null;
    ui.alert('המפתח נשמר ✓');
  }
}

function startRun() {
  setup();
  var settings = readSettings();
  if (!settings.apiKey) {
    setApiKey();
    settings = readSettings();
    if (!settings.apiKey) return;
  }
  var sheet = SpreadsheetApp.getActive().getSheetByName(SHEET_PRODUCTS);
  var n = sheet.getLastRow() - 1;
  if (n < 1) {
    SpreadsheetApp.getUi().alert('הדביקו קישורים למוצרים בעמודה "קישור למוצר" (קישור בכל שורה) ואז הריצו שוב.');
    return;
  }
  var rows = sheet.getRange(2, 1, n, HEADERS.length).getValues();
  var active = getActive();
  var added = 0;
  rows.forEach(function (r, i) {
    var link = String(r[COL.LINK - 1]).trim();
    var status = String(r[COL.STATUS - 1]).trim();
    if (!/^https?:\/\//i.test(link) || (status && status !== STATUS.stopped && status.indexOf(STATUS.error) !== 0)) return;
    var id = 'p' + Date.now().toString(36) + i;
    sheet.getRange(i + 2, COL.ID).setValue(id);
    saveState({ id: id, link: link, stage: 'new', writeAttempts: 0, researchAttempts: 0, warnings: [] });
    active.push(id);
    setRowStatus(id, STATUS.queued, { notes: '' });
    added++;
  });
  setActive(active);
  if (!added && !active.length) {
    SpreadsheetApp.getUi().alert('אין קישורים חדשים להרצה. (שורות שכבר הושלמו לא רצות שוב; כדי להריץ שוב מוחקים את הסטטוס.)');
    return;
  }
  ensureTrigger();
  SpreadsheetApp.getActive().toast(added + ' מוצרים נכנסו לתור. אפשר לסגור את הגיליון, העבודה ממשיכה ברקע.', 'סורק מוצרים', 10);
  tick();
}

function stopRun() {
  ScriptApp.getProjectTriggers().forEach(function (t) { if (t.getHandlerFunction() === 'tick') ScriptApp.deleteTrigger(t); });
  getActive().forEach(function (id) { setRowStatus(id, STATUS.stopped); });
  setActive([]);
  PropertiesService.getScriptProperties().deleteProperty('BATCHES');
}

function ensureTrigger() {
  var has = ScriptApp.getProjectTriggers().some(function (t) { return t.getHandlerFunction() === 'tick'; });
  if (!has) ScriptApp.newTrigger('tick').timeBased().everyMinutes(1).create();
}

// ---------------- State ----------------

function getActive() { return JSON.parse(PropertiesService.getScriptProperties().getProperty('ACTIVE') || '[]'); }
function setActive(a) { PropertiesService.getScriptProperties().setProperty('ACTIVE', JSON.stringify(a)); }
function getBatches() { return JSON.parse(PropertiesService.getScriptProperties().getProperty('BATCHES') || '[]'); }
function setBatches(b) { PropertiesService.getScriptProperties().setProperty('BATCHES', JSON.stringify(b)); }

function loadState(id) {
  var it = stateFolder(readSettings()).getFilesByName(id + '.json');
  return it.hasNext() ? JSON.parse(it.next().getBlob().getDataAsString('UTF-8')) : null;
}

function saveState(p) {
  replaceFile(stateFolder(readSettings()), p.id + '.json', Utilities.newBlob(JSON.stringify(p), 'application/json'));
}

function findRow(id) {
  var sheet = SpreadsheetApp.getActive().getSheetByName(SHEET_PRODUCTS);
  var n = sheet.getLastRow() - 1;
  if (n < 1) return 0;
  var ids = sheet.getRange(2, COL.ID, n, 1).getValues();
  for (var i = 0; i < ids.length; i++) if (ids[i][0] === id) return i + 2;
  return 0;
}

function setRowStatus(id, status, extra) {
  var row = findRow(id);
  if (!row) return;
  var sheet = SpreadsheetApp.getActive().getSheetByName(SHEET_PRODUCTS);
  sheet.getRange(row, COL.STATUS).setValue(status);
  extra = extra || {};
  if (extra.name !== undefined) sheet.getRange(row, COL.NAME).setValue(extra.name);
  if (extra.manufacturer !== undefined) sheet.getRange(row, COL.MANUFACTURER).setValue(extra.manufacturer);
  if (extra.folderUrl) sheet.getRange(row, COL.FOLDER).setFormula('=HYPERLINK("' + extra.folderUrl + '","פתח תיקייה")');
  if (extra.notes !== undefined) sheet.getRange(row, COL.NOTES).setValue(extra.notes);
}

// ---------------- The worker (runs every minute until everything is done) ----------------

function tick() {
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(1000)) return;
  var started = Date.now();
  try {
    var settings = readSettings();
    pollBatches(settings);
    var active = getActive();
    // Local steps (fetching pages, saving files) - as many as fit in this run.
    for (var i = 0; i < active.length && Date.now() - started < TICK_BUDGET_MS; i++) {
      var p = loadState(active[i]);
      if (!p || ['new', 'official', 'save'].indexOf(p.stage) < 0) continue;
      runLocalStep(settings, p);
    }
    submitBatches(settings, 'research');
    if (Date.now() - started < TICK_BUDGET_MS) submitBatches(settings, 'write');
    finishIfDone(settings);
  } finally {
    lock.releaseLock();
  }
}

function runLocalStep(settings, p) {
  try {
    if (p.stage === 'new') stepSupplier(p);
    else if (p.stage === 'official') stepOfficial(p);
    else if (p.stage === 'save') stepSave(settings, p);
  } catch (e) {
    fail(p, e);
    return;
  }
  saveState(p);
}

function fail(p, e) {
  p.stage = 'error';
  p.error = String(e && e.message || e);
  saveState(p);
  setRowStatus(p.id, STATUS.error, { notes: p.error });
  setActive(getActive().filter(function (x) { return x !== p.id; }));
}

// 1. Read the page the user linked to.
function stepSupplier(p) {
  var page = fetchPage(p.link);
  if (page) {
    p.supplier = { title: page.title, text: page.text.slice(0, 15000), links: page.links.slice(0, 600) };
  } else {
    p.supplier = null;
    p.warnings.push('לא הצלחתי לפתוח את הקישור ישירות; Claude קרא אותו בעצמו');
  }
  p.stage = 'research_pending';
  setRowStatus(p.id, STATUS.research, { name: page ? page.title : '' });
}

// 3. Read the manufacturer's official pages and collect images / PDFs / YouTube links from them only.
function stepOfficial(p) {
  var r = p.research;
  var domains = r.official_domains.slice();
  var linkHost = hostOf(p.link).replace(/^www\./, '');
  if (r.site_is_manufacturer && domains.indexOf(linkHost) < 0) domains.push(linkHost);
  if (!r.site_is_manufacturer) domains = domains.filter(function (d) { return d !== linkHost; });
  r.official_domains = domains;

  var key = String(r.model || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  var urls = [];
  if (r.site_is_manufacturer) urls.push(p.link);
  if (r.official_product_url && isOfficial(r.official_product_url, domains)) urls.push(r.official_product_url);
  ((p.supplier && p.supplier.links) || []).forEach(function (l) {
    var seg = l.url.replace(/[?#].*$/, '').replace(/\/+$/, '').split('/').pop().toLowerCase().replace(/[^a-z0-9]/g, '');
    if (key.length >= 3 && isOfficial(l.url, domains) && seg.indexOf(key) >= 0 && !/\.pdf/i.test(l.url)) urls.push(l.url);
  });
  urls = urls.filter(function (u, i) { return urls.indexOf(u) === i; }).slice(0, 3);

  var off = { pages: [], images: [], pdfs: [], videos: [] };
  var addAll = function (list, items) { items.forEach(function (x) { if (!list.some(function (y) { return y.url === x.url; })) list.push(x); }); };
  urls.forEach(function (u) {
    var page = fetchPage(u);
    if (!page) return;
    off.pages.push({ url: u, text: page.text.slice(0, 15000) });
    addAll(off.images, page.images);
    addAll(off.pdfs, page.pdfs);
    addAll(off.videos, page.videos);
  });
  if (r.official_downloads_url && isOfficial(r.official_downloads_url, domains) && urls.indexOf(r.official_downloads_url) < 0) {
    var dl = fetchPage(r.official_downloads_url);
    if (dl) {
      var forProduct = key.length >= 3 && r.official_downloads_url.toLowerCase().replace(/[^a-z0-9]/g, '').indexOf(key) >= 0;
      addAll(off.pdfs, dl.pdfs.filter(function (d) {
        return forProduct || (key.length >= 3 && (d.label + d.url).toLowerCase().replace(/[^a-z0-9]/g, '').indexOf(key) >= 0);
      }).slice(0, 20));
    }
  }
  off.images = off.images.slice(0, 40);
  p.official = off;
  p.productPages = [{ url: p.link, official: !!r.site_is_manufacturer }]
    .concat(off.pages.filter(function (pg) { return pg.url !== p.link; }).map(function (pg) { return { url: pg.url, official: true }; }));
  if (!domains.length) p.warnings.push('לא נמצא אתר רשמי של היצרן');
  else if (!off.pages.length) p.warnings.push('לא הצלחתי לקרוא את דף המוצר באתר היצרן');
  p.stage = 'write_pending';
  setRowStatus(p.id, STATUS.write, { manufacturer: r.manufacturer });
}

// 5. Create the product's Drive folder: images, brochure, manual, HTML page, Google Doc.
function stepSave(settings, p) {
  var c = p.content;
  var off = p.official;
  var stem = fileStem(p.research.manufacturer, p.research.model || (p.supplier && p.supplier.title) || 'product');
  var root = rootFolder(settings);
  var folder = null;
  var it = root.getFolders();   // re-running a product updates its existing folder
  while (it.hasNext() && !folder) {
    var f = it.next();
    if (f.getName() === stem || f.getName().indexOf(stem + ' - ') === 0) folder = f;
  }
  folder = folder || root.createFolder(stem);

  var saved = { images: [], docs: [], videos: [] };
  var hashes = {};
  uniqueIndexes(c.image_indexes, off.images.length).forEach(function (i) {
    if (saved.images.length >= 5) return;
    var im = off.images[i];
    var r = fetchUrl(im.url) || (im.fallback ? fetchUrl(im.fallback) : null);
    if (!r) return;
    var blob = r.getBlob();
    var type = String(blob.getContentType() || '').split(';')[0];
    var ext = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' }[type];
    if (!ext || blob.getBytes().length < 8000) return;
    var hash = Utilities.base64Encode(Utilities.computeDigest(Utilities.DigestAlgorithm.MD5, blob.getBytes()));
    if (hashes[hash]) return;
    hashes[hash] = true;
    var name = stem + '-' + ('00' + (saved.images.length + 1)).slice(-3) + '.' + ext;
    replaceFile(folder, name, blob);
    saved.images.push({ file: name, url: im.url });
  });
  [['brochure', c.brochure_index], ['manual', c.manual_index]].forEach(function (pair) {
    var d = off.pdfs[pair[1]];
    if (!d) return;
    var r = fetchUrl(d.url);
    if (!r) return;
    var blob = r.getBlob();
    if (Utilities.newBlob(blob.getBytes().slice(0, 5)).getDataAsString() !== '%PDF-') return;
    var name = stem + '-' + pair[0].toUpperCase() + '.pdf';
    replaceFile(folder, name, blob.setContentType('application/pdf'));
    saved.docs.push({ kind: pair[0], file: name, url: d.url });
  });
  uniqueIndexes(c.video_indexes, off.videos.length).forEach(function (i) { saved.videos.push(off.videos[i]); });
  p.saved = saved;

  if (saved.images.length < 3) p.warnings.push('נמצאו ' + saved.images.length + ' תמונות באתר היצרן (המטרה 3-5)');
  if (!saved.docs.some(function (d) { return d.kind === 'brochure'; })) p.warnings.push('לא נמצא ברושור באתר היצרן');
  if (!saved.docs.some(function (d) { return d.kind === 'manual'; })) p.warnings.push('לא נמצא מדריך למשתמש באתר היצרן');
  if (!saved.videos.length) p.warnings.push('לא נמצא סרטון YouTube באתר היצרן');

  replaceFile(folder, stem + '.html', Utilities.newBlob(productHtml(p, false), 'text/html', stem + '.html'));
  saveAsGoogleDoc(folder, stem + ' - תיאור', productHtml(p, true));
  folder.setName(stem + ' - ' + c.name);

  p.stage = 'done';
  p.folderUrl = folder.getUrl();
  setRowStatus(p.id, p.warnings.length ? STATUS.doneNotes : STATUS.done, {
    name: c.name, manufacturer: p.research.manufacturer, folderUrl: p.folderUrl, notes: p.warnings.join(' · '),
  });
  setActive(getActive().filter(function (x) { return x !== p.id; }));
}

function uniqueIndexes(list, n) {
  var out = [];
  (list || []).forEach(function (i) { if (i >= 0 && i < n && out.indexOf(i) < 0) out.push(i); });
  return out;
}

// ---------------- Claude batches ----------------

function submitBatches(settings, kind) {
  var pending = getActive().map(loadState).filter(function (p) { return p && p.stage === kind + '_pending'; });
  if (!pending.length) return;
  var style = kind === 'write' ? styleExamples(settings) : null;
  var requests = [];
  var size = 0;
  var members = [];
  var flush = function () {
    if (!requests.length) return;
    var id = submitBatch(settings, requests);
    setBatches(getBatches().concat([{ id: id, kind: kind }]));
    members.forEach(function (p) { p.stage = kind + '_wait'; p.batchId = id; saveState(p); });
    requests = []; size = 0; members = [];
  };
  pending.forEach(function (p) {
    var params;
    try {
      if (kind === 'research') {
        params = researchParams(settings, p);
        if (p.researchContinuation) params.messages = params.messages.concat(p.researchContinuation);
      } else {
        params = writeParams(settings, p, style, brochureForClaude(p), p.writeFeedback);
      }
    } catch (e) {
      fail(p, e);
      return;
    }
    var req = { custom_id: p.id + '_' + kind + '_' + (kind === 'research' ? p.researchAttempts : p.writeAttempts), params: params };
    var bytes = JSON.stringify(req).length;
    if (size + bytes > MAX_BATCH_BYTES) flush();
    requests.push(req);
    members.push(p);
    size += bytes;
  });
  flush();
}

function brochureForClaude(p) {
  var pdfs = (p.official && p.official.pdfs) || [];
  var d = pdfs.filter(function (x) { return x.kind === 'brochure'; })[0];
  if (!d) return null;
  var r = fetchUrl(d.url);
  if (!r) return null;
  var bytes = r.getBlob().getBytes();
  if (bytes.length > MAX_PDF_FOR_CLAUDE || Utilities.newBlob(bytes.slice(0, 5)).getDataAsString() !== '%PDF-') return null;
  return Utilities.base64Encode(bytes);
}

function styleExamples(settings) {
  var cache = CacheService.getScriptCache();
  var key = 'style_' + Utilities.base64Encode(Utilities.computeDigest(Utilities.DigestAlgorithm.MD5, settings.styleUrls.join(' ')));
  var hit = cache.get(key);
  if (hit) return JSON.parse(hit);
  var out = [];
  settings.styleUrls.forEach(function (u) {
    var page = fetchPage(u);
    if (page) out.push({ url: u, text: page.text.slice(0, 3500) });
  });
  cache.put(key, JSON.stringify(out), 21600);
  return out;
}

function pollBatches(settings) {
  var batches = getBatches();
  if (!batches.length) return;
  var remaining = [];
  batches.forEach(function (b) {
    var batch;
    try {
      batch = getBatch(settings, b.id);
    } catch (e) {
      remaining.push(b);
      return;
    }
    if (batch.processing_status !== 'ended') { remaining.push(b); return; }
    var byId = {};
    batchResults(settings, batch).forEach(function (line) { byId[line.custom_id.split('_')[0]] = line.result; });
    getActive().forEach(function (id) {
      var p = loadState(id);
      if (!p || p.batchId !== b.id) return;
      try {
        if (b.kind === 'research') applyResearch(p, byId[p.id]);
        else applyWrite(p, byId[p.id]);
        saveState(p);
      } catch (e) {
        fail(p, e);
      }
    });
  });
  setBatches(remaining);
}

function resultError(result) {
  if (!result) return 'no result';
  if (result.type === 'errored') return (result.error && result.error.error && result.error.error.message) || 'errored';
  return result.type;
}

function applyResearch(p, result) {
  p.researchAttempts++;
  if (!result || result.type !== 'succeeded') {
    if (p.researchAttempts < 3) { p.stage = 'research_pending'; return; }
    throw new Error('Claude: ' + resultError(result));
  }
  var msg = result.message;
  if (msg.stop_reason === 'pause_turn' && p.researchAttempts < 4) {
    p.researchContinuation = (p.researchContinuation || []).concat([{ role: 'assistant', content: msg.content }]);
    p.stage = 'research_pending';
    return;
  }
  var r = parseResearch(msg);
  if (!r && p.researchAttempts < 3) {
    p.researchContinuation = null;
    p.stage = 'research_pending';
    return;
  }
  p.research = r || { manufacturer: '', model: '', official_domains: [], official_product_url: '', official_downloads_url: '', site_is_manufacturer: false };
  p.researchContinuation = null;
  p.stage = 'official';
  setRowStatus(p.id, STATUS.official, { manufacturer: p.research.manufacturer });
}

function applyWrite(p, result) {
  p.writeAttempts++;
  if (!result || result.type !== 'succeeded' || result.message.stop_reason === 'refusal') {
    if (p.writeAttempts < MAX_WRITE_ATTEMPTS) { p.stage = 'write_pending'; return; }
    throw new Error('Claude: ' + (result && result.type === 'succeeded' ? 'refusal' : resultError(result)));
  }
  var content;
  try {
    content = JSON.parse(messageText(result.message));
  } catch (e) {
    if (p.writeAttempts < MAX_WRITE_ATTEMPTS) { p.stage = 'write_pending'; return; }
    throw new Error('Claude returned invalid JSON');
  }
  var problems = validateContent(content);
  if (problems.length && p.writeAttempts < MAX_WRITE_ATTEMPTS) {
    p.writeFeedback = '\n\nבטיוטה הקודמת היו הבעיות הבאות - תקן/י:\n- ' + problems.join('\n- ') + '\nהטיוטה הקודמת:\n' + JSON.stringify(content);
    p.stage = 'write_pending';
    return;
  }
  p.warnings = p.warnings.concat(problems);
  p.content = content;
  p.stage = 'save';
  setRowStatus(p.id, STATUS.save, { name: content.name });
}

function finishIfDone(settings) {
  if (getActive().length || getBatches().length) return;
  var had = ScriptApp.getProjectTriggers().filter(function (t) { return t.getHandlerFunction() === 'tick'; });
  had.forEach(function (t) { ScriptApp.deleteTrigger(t); });
  stateFolder(settings).setTrashed(true);
  FOLDER_MEMO.state = null;
  if (!had.length || !settings.email) return;
  var ss = SpreadsheetApp.getActive();
  try {
    MailApp.sendEmail(Session.getEffectiveUser().getEmail(), 'סורק מוצרים: הסריקה הסתיימה',
      'כל המוצרים עובדו. הסטטוסים והקישורים לתיקיות בגיליון:\n' + ss.getUrl() + '\n\nהתיקייה בדרייב: ' + rootFolder(settings).getUrl());
  } catch (e) {
    console.warn('email not sent: ' + e.message);
  }
}
