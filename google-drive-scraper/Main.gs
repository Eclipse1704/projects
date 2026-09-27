// Product scraper -> Google Drive (a Google Apps Script web app).
// Links pasted in the app (App.gs) are queued here; a 1-minute trigger then moves every product
// through these steps until its Drive folder is ready:
//   new -> research (Claude batch: manufacturer + official site) -> official (read official pages)
//       -> write (Claude batch: Hebrew text + choose images/PDFs/videos) -> save (Drive folder) -> done

var TICK_BUDGET_MS = 4.5 * 60 * 1000;   // Apps Script stops a run after 6 minutes
var STEP_MIN_MS = 100 * 1000;          // don't start a page/download step with less time than this left
var MAX_STEP_TRIES = 3;               // a step cut off this many times fails with a message
var MAX_BATCH_BYTES = 30 * 1024 * 1024;  // UrlFetchApp payload limit is 50MB
var MAX_BATCH_REQUESTS = 20;             // research results include fetched pages: keep the results file well under 50MB
var MAX_PDF_FOR_CLAUDE = 10 * 1024 * 1024;
var MAX_WRITE_ATTEMPTS = 3;
var MIN_IMAGE_SIDE = 800;   // px on the long side; smaller images count as low resolution
var IMAGES_FOLDER = 'תמונות';

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

// ---------------- Setup ----------------

// Copying the script ("make a copy") also copies its saved properties.
// A copy must not use the original's API key or work queue: start clean.
function ensureOwnCopy() {
  var props = PropertiesService.getUserProperties();
  var id = ScriptApp.getScriptId();
  var owner = props.getProperty('SCRIPT_ID');
  if (owner === id) return;
  if (owner) props.deleteAllProperties();
  props.setProperty('SCRIPT_ID', id);
}

// Queues links and starts the background worker. Returns how many were added.
function queueLinks(links) {
  var lock = LockService.getUserLock();
  lock.waitLock(60000);   // the worker may be running right now
  try {
    var list = getItems();
    var stages = getStages();
    var stamp = Date.now().toString(36);
    links.forEach(function (link, i) {
      var id = 'p' + stamp + 'n' + i;
      list.push({ id: id, link: link, status: STATUS.queued, name: '', manufacturer: '', folderUrl: '', notes: '', added: new Date().toISOString() });
      saveState({ id: id, link: link, stage: 'new', writeAttempts: 0, researchAttempts: 0, researchPauses: 0, stepTries: {}, warnings: [] }, stages);
    });
    setStages(stages);
    flushItems();
  } finally {
    lock.releaseLock();
  }
  if (links.length) setTriggerEvery(1);
  return links.length;
}

function stopRun() {
  var lock = LockService.getUserLock();
  lock.waitLock(60000);
  try {
    deleteTriggers();
    var settings = readSettings();
    getBatches().forEach(function (b) {   // stop paying for work that's no longer wanted
      try { claudeRequest(settings, 'post', '/v1/messages/batches/' + b.id + '/cancel'); } catch (e) {}
    });
    Object.keys(getStages()).forEach(function (id) { setRowStatus(id, STATUS.stopped); });
    flushItems();
    setStages({});
    setBatches([]);
    stateFolder(settings).setTrashed(true);
    FOLDER_MEMO.state = null;
  } finally {
    lock.releaseLock();
  }
}

function deleteTriggers() {
  ScriptApp.getProjectTriggers().forEach(function (t) { if (t.getHandlerFunction() === 'tick') ScriptApp.deleteTrigger(t); });
  PropertiesService.getUserProperties().deleteProperty('TRIGGER_EVERY');
}

// Every minute while there is work to do here; every 5 minutes while only waiting for Claude
// (saves the daily trigger-time quota).
function setTriggerEvery(minutes) {
  var props = PropertiesService.getUserProperties();
  var has = ScriptApp.getProjectTriggers().some(function (t) { return t.getHandlerFunction() === 'tick'; });
  if (has && props.getProperty('TRIGGER_EVERY') === String(minutes)) return;
  deleteTriggers();
  ScriptApp.newTrigger('tick').timeBased().everyMinutes(minutes).create();
  props.setProperty('TRIGGER_EVERY', String(minutes));
}

function ensureTrigger() { setTriggerEvery(1); }

// ---------------- State ----------------

// Where each active product is ({id: stage}), kept in User Properties so a run can see what needs
// work without opening every product's state file.
function getStages() { return JSON.parse(getBig('STAGES') || '{}'); }
function setStages(m) { setBig('STAGES', JSON.stringify(m)); }
function getBatches() { return JSON.parse(getBig('BATCHES') || '[]'); }
function setBatches(b) { setBig('BATCHES', JSON.stringify(b)); }

// User Properties hold at most 9KB per value: long values are split into numbered parts.
var PART_CHARS = 2500;   // Hebrew/UTF-8 safe: 2500 chars <= 9KB
// The parts this execution last read or wrote, so unchanged parts aren't written again
// (Properties have a daily read/write quota). Every writer holds the user's lock.
var BIG_SEEN = {};
function getBig(key) {
  var props = PropertiesService.getUserProperties();
  var n = parseInt(props.getProperty(key + '_parts') || '0', 10);
  var parts = [];
  for (var i = 0; i < n; i++) parts.push(props.getProperty(key + '_' + i) || '');
  BIG_SEEN[key] = parts;
  return parts.join('');
}
function setBig(key, value) {
  var props = PropertiesService.getUserProperties();
  var seen = BIG_SEEN[key];
  var old = seen ? seen.length : parseInt(props.getProperty(key + '_parts') || '0', 10);
  var parts = [];
  for (var i = 0; i * PART_CHARS < value.length; i++) parts.push(value.slice(i * PART_CHARS, (i + 1) * PART_CHARS));
  parts.forEach(function (part, i) { if (!seen || seen[i] !== part) props.setProperty(key + '_' + i, part); });
  for (var j = parts.length; j < old; j++) props.deleteProperty(key + '_' + j);
  if (!seen || seen.length !== parts.length) props.setProperty(key + '_parts', String(parts.length));
  BIG_SEEN[key] = parts;
}

function loadState(id) {
  var f = firstLive(stateFolder(readSettings()).getFilesByName(id + '.json'));
  return f ? JSON.parse(f.getBlob().getDataAsString('UTF-8')) : null;
}

// Saves the product's state file and its stage. Pass `stages` to batch the property write.
function saveState(p, stages) {
  var folder = stateFolder(readSettings());
  var file = firstLive(folder.getFilesByName(p.id + '.json'));
  var json = JSON.stringify(p);
  if (file) file.setContent(json);
  else folder.createFile(p.id + '.json', json, 'application/json');
  var m = stages || getStages();
  if (p.stage === 'done' || p.stage === 'error') delete m[p.id];
  else m[p.id] = p.stage;
  if (!stages) setStages(m);
}

// The list the app shows: one entry per link ever queued (newest last). Kept in memory during a run
// and written once at the end (User Properties have a daily write quota).
var MAX_ITEMS = 200;
var ITEMS_MEMO = null;
var ITEMS_DIRTY = false;

function getItems() {
  if (!ITEMS_MEMO) ITEMS_MEMO = JSON.parse(getBig('ITEMS') || '[]');
  return ITEMS_MEMO;
}

function flushItems() {
  if (!ITEMS_MEMO) return;
  var list = ITEMS_MEMO;
  if (list.length > MAX_ITEMS) {   // forget the oldest finished products
    var active = getStages();
    var extra = list.length - MAX_ITEMS;
    list = list.filter(function (it) { if (extra > 0 && !active[it.id]) { extra--; return false; } return true; });
    ITEMS_MEMO = list;
  }
  setBig('ITEMS', JSON.stringify(list));
  ITEMS_DIRTY = false;
}

function setRowStatus(id, status, extra) {
  var it = getItems().filter(function (x) { return x.id === id; })[0];
  if (!it) return;
  it.status = status;
  extra = extra || {};
  ['name', 'manufacturer', 'folderUrl', 'notes'].forEach(function (k) { if (extra[k] !== undefined) it[k] = String(extra[k]).slice(0, 600); });
  ITEMS_DIRTY = true;
}

// ---------------- The worker (runs every minute until everything is done) ----------------

var DEADLINE = 0;
function timeLeft() { return DEADLINE - Date.now(); }

function tick() {
  var lock = LockService.getUserLock();
  if (!lock.tryLock(1000)) return;
  DEADLINE = Date.now() + TICK_BUDGET_MS;
  PropertiesService.getUserProperties().setProperty('LAST_RUN', new Date().toISOString());
  try {
    work();
  } catch (e) {
    reportCrash(e);
  } finally {
    try { if (ITEMS_DIRTY) flushItems(); } finally { lock.releaseLock(); }
  }
}

// A background run that crashes would otherwise fail silently: show it on the products and in the app.
function reportCrash(e) {
  var msg = String(e && e.message || e);
  PropertiesService.getUserProperties().setProperty('LAST_ERROR', new Date().toISOString() + ' ' + msg);
  try {
    Object.keys(getStages()).forEach(function (id) { setRowStatus(id, STATUS.queued, { notes: 'תקלה בהרצה ברקע (מנסה שוב כל דקה): ' + msg }); });
  } catch (e2) {}
}

// For the app: is the background worker running, when did it last run, what went wrong.
function workerStatus() {
  var props = PropertiesService.getUserProperties();
  var lastError = props.getProperty('LAST_ERROR') || '';
  return {
    running: ScriptApp.getProjectTriggers().some(function (t) { return t.getHandlerFunction() === 'tick'; }),
    lastRun: props.getProperty('LAST_RUN') || '',
    lastError: lastError ? lastError.slice(lastError.indexOf(' ') + 1) : '',
    lastErrorAt: lastError ? lastError.split(' ')[0] : '',
  };
}

// Everything one background run does.
function work() {
  {
    var settings = readSettings();
    pollBatches(settings);
    recoverLostWaits();
    // Take every product as far as it can go in this run - all products together, stage after stage.
    for (var round = 0; round < 10 && timeLeft() > 45000; round++) {
      // After each stage the list is saved, so the app shows progress while this run goes on.
      var moved = runLocalStage(settings, 'new');
      if (settings.fast) moved = runClaudeNow(settings, 'research') || moved;
      if (ITEMS_DIRTY) flushItems();
      moved = runLocalStage(settings, 'official') || moved;
      if (settings.fast) moved = runClaudeNow(settings, 'write') || moved;
      if (ITEMS_DIRTY) flushItems();
      moved = runLocalStage(settings, 'save') || moved;
      if (ITEMS_DIRTY) flushItems();
      if (!moved) break;
    }
    submitBatches(settings, 'research');
    submitBatches(settings, 'write');
    var left = getStages();
    var busy = Object.keys(left).some(function (id) { return !/_wait$/.test(left[id]); });
    if (Object.keys(left).length) setTriggerEvery(busy ? 1 : 5);
    finishIfDone(settings);
  }
}

// Runs one local stage for all products in it: their pages/files are downloaded in parallel first.
var LOCAL_GROUP = { new: 10, official: 5, save: 3 };

function runLocalStage(settings, stage) {
  var stages = getStages();
  var ids = Object.keys(stages).filter(function (id) { return stages[id] === stage; });
  var moved = false;
  for (var i = 0; i < ids.length && timeLeft() >= STEP_MIN_MS; i += LOCAL_GROUP[stage]) {
    var group = [];
    ids.slice(i, i + LOCAL_GROUP[stage]).forEach(function (id) {
      var p = loadState(id);
      if (p) group.push(p);
      else forget(id);
    });
    prefetchFor(stage, group);
    group.forEach(function (p) {
      if (timeLeft() < STEP_MIN_MS) return;
      runLocalStep(settings, p);
      moved = true;
    });
    clearPrefetch();
  }
  return moved;
}

function prefetchFor(stage, group) {
  var noRedirect = { followRedirects: false };
  if (stage === 'new') {
    prefetch(group.map(function (p) { return p.link; }), noRedirect);
  } else if (stage === 'official') {
    var pages = [];
    group.forEach(function (p) {
      var r = p.research || {};
      if (r.site_is_manufacturer) pages.push(p.link);
      pages.push(r.official_product_url, r.official_downloads_url);
    });
    prefetch(pages, noRedirect);
  } else if (stage === 'save') {
    var files = [];
    group.forEach(function (p) {
      var c = p.content || {};
      var off = p.official || { images: [], pdfs: [] };
      uniqueIndexes(c.image_indexes, off.images.length).slice(0, 8).forEach(function (i) { files.push(off.images[i].url, off.images[i].fallback); });
      [c.brochure_index, c.manual_index].forEach(function (i) { if (off.pdfs[i]) files.push(off.pdfs[i].url); });
    });
    prefetch(files);
  }
}

// Fast mode: ask Claude directly (several products at the same time) instead of a batch job.
var NOW_GROUP = 5;
var NOW_MIN_MS = 75 * 1000;   // a direct call can take up to ~60s

function runClaudeNow(settings, kind) {
  var stages = getStages();
  var ids = Object.keys(stages).filter(function (id) { return stages[id] === kind + '_pending'; });
  if (!ids.length) return false;
  var style = kind === 'write' ? styleExamples(settings) : null;
  var moved = false;
  var queue = ids.slice();
  while (queue.length && timeLeft() > NOW_MIN_MS) {
    var group = [];
    var params = [];
    while (queue.length && group.length < NOW_GROUP) {
      var id = queue.shift();
      var p = loadState(id);
      if (!p) { forget(id); continue; }
      if (p.useBatch && p.useBatch[kind]) continue;   // didn't fit in the time limit before: batch job
      try {
        params.push(claudeParams(settings, p, kind, style));
        group.push(p);
      } catch (e) {
        fail(p, e);
      }
    }
    if (!group.length) continue;
    var answers = claudeNow(settings, params);
    var m = getStages();
    group.forEach(function (p, i) {
      var a = answers[i];
      if (a.timeout) {
        p.useBatch = p.useBatch || {};
        p.useBatch[kind] = true;
        saveState(p, m);
        return;
      }
      if (a.status === 401 || a.status === 403) {
        fail(p, new Error(a.message));
        m = getStages();
        return;
      }
      if (a.status === 408 || a.status === 429 || a.status >= 500) {   // busy: try again, then as a batch job
        p.nowErrors = (p.nowErrors || 0) + 1;
        if (p.nowErrors >= 3) { p.useBatch = p.useBatch || {}; p.useBatch[kind] = true; }
        saveState(p, m);
        return;
      }
      try {
        if (kind === 'research') applyResearch(p, a.result);
        else applyWrite(p, a.result);
        saveState(p, m);
        moved = true;
      } catch (e) {
        fail(p, e);
        m = getStages();
      }
    });
    setStages(m);
  }
  return moved;
}

// The request for one product, used by both the direct calls and the batch jobs.
function claudeParams(settings, p, kind, style) {
  if (kind === 'research') {
    var params = researchParams(settings, p);
    if (p.researchContinuation) params.messages = params.messages.concat([p.researchContinuation]);
    return params;
  }
  var brochure = p.skipBrochure ? null : brochureForClaude(p);
  p.lastWriteHadBrochure = !!brochure;
  return writeParams(settings, p, style, brochure, p.writeFeedback);
}

function runLocalStep(settings, p) {
  p.stepTries = p.stepTries || {};
  p.stepTries[p.stage] = (p.stepTries[p.stage] || 0) + 1;
  if (p.stepTries[p.stage] > MAX_STEP_TRIES) {
    fail(p, new Error('השלב נקטע שוב ושוב (האתר איטי מדי או הקבצים גדולים מדי). אפשר לנסות להריץ שוב מאוחר יותר.'));
    return;
  }
  saveState(p);   // count the try before starting: if Google cuts this run off, the next run knows
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

// Drop a product whose state file is gone, so it can't keep the worker running.
function forget(id) {
  var m = getStages();
  delete m[id];
  setStages(m);
}

function fail(p, e) {
  p.stage = 'error';
  p.error = String(e && e.message || e);
  saveState(p);
  setRowStatus(p.id, STATUS.error, { notes: p.error });
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
  var stem = fileStem(p.research.manufacturer, p.research.model || (p.supplier && p.supplier.title) || '');
  // Without a known manufacturer/model the name isn't unique: add the product's id.
  if (!p.research.manufacturer || !p.research.model) stem += '-' + p.id.toUpperCase();
  var root = rootFolder(settings);
  var folder = null;
  var it = root.getFolders();   // re-running a product updates its existing folder
  while (it.hasNext() && !folder) {
    var f = it.next();
    if (!f.isTrashed() && (f.getName() === stem || f.getName().indexOf(stem + ' - ') === 0)) folder = f;
  }
  folder = folder || root.createFolder(stem);

  var saved = { images: [], docs: [], videos: [] };
  saved.images = saveImages(folder, stem, uniqueIndexes(c.image_indexes, off.images.length).map(function (i) { return off.images[i]; }));
  [['brochure', c.brochure_index], ['manual', c.manual_index]].forEach(function (pair) {
    var d = off.pdfs[pair[1]];
    if (!d) return;
    var r = fetchUrl(d.url);
    if (!r) return;
    var blob = r.getBlob();
    if (Utilities.newBlob(blob.getBytes().slice(0, 5)).getDataAsString() !== '%PDF-') return;
    var name = stem + '-' + pair[0].toUpperCase() + '.pdf';
    var file = replaceFile(folder, name, blob.setContentType('application/pdf'));
    saved.docs.push({ kind: pair[0], file: name, url: d.url, driveUrl: file.getUrl() });
  });
  uniqueIndexes(c.video_indexes, off.videos.length).forEach(function (i) { saved.videos.push(off.videos[i]); });
  p.saved = saved;

  p.warnings = (p.baseWarnings || (p.baseWarnings = p.warnings.slice())).slice();
  if (saved.images.length < 3) p.warnings.push('נמצאו ' + saved.images.length + ' תמונות באתר היצרן (המטרה 3-5)');
  var small = saved.images.filter(function (im) { return im.small; }).map(function (im) { return im.file.split('/').pop() + ' (' + im.width + '×' + im.height + ')'; });
  if (small.length) p.warnings.push('תמונות ברזולוציה נמוכה (לא נמצאה גרסה גדולה יותר באתר היצרן): ' + small.join(', '));
  if (!saved.docs.some(function (d) { return d.kind === 'brochure'; })) p.warnings.push('לא נמצא ברושור באתר היצרן');
  if (!saved.docs.some(function (d) { return d.kind === 'manual'; })) p.warnings.push('לא נמצא מדריך למשתמש באתר היצרן');
  if (!saved.videos.length) p.warnings.push('לא נמצא סרטון YouTube באתר היצרן');

  // Everything except the images and PDFs goes in one table. (Older versions saved an HTML file and a Doc.)
  [stem + '.html', stem + ' - תיאור'].forEach(function (old) {
    var it = folder.getFilesByName(old);
    while (it.hasNext()) { var f = it.next(); if (!f.isTrashed()) f.setTrashed(true); }
  });
  var row = productRow(p, stem, folder.getUrl());
  replaceFile(folder, stem + '.csv', csvBlob([CSV_HEADERS, row], stem + '.csv'));
  updateAllProductsCsv(root, row);
  folder.setName(stem + ' - ' + c.name);

  p.stage = 'done';
  p.folderUrl = folder.getUrl();
  setRowStatus(p.id, p.warnings.length ? STATUS.doneNotes : STATUS.done, {
    name: c.name, manufacturer: p.research.manufacturer, folderUrl: p.folderUrl, notes: p.warnings.join(' · '),
  });
}

// Images go to the product's "תמונות" subfolder, named STEM-001.jpg ... in Claude's order of preference.
// Only high-resolution files are kept; small ones are used only if there aren't 3 good ones.
function saveImages(folder, stem, candidates) {
  var dir = firstLive(folder.getFoldersByName(IMAGES_FOLDER)) || folder.createFolder(IMAGES_FOLDER);
  var good = [];
  var small = [];
  var hashes = {};
  candidates.forEach(function (im) {
    if (good.length >= 5) return;
    var best = null;
    [im.url, im.fallback].filter(String).forEach(function (u) {
      if (best && !best.small) return;
      var r = fetchUrl(u);
      if (!r) return;
      var blob = r.getBlob();
      var bytes = blob.getBytes();
      var size = imageSize(bytes);   // also tells the real format (servers often send a wrong Content-Type)
      if (!size || bytes.length < 5000) return;
      var hash = Utilities.base64Encode(Utilities.computeDigest(Utilities.DigestAlgorithm.MD5, bytes));
      if (hashes[hash]) return;
      var cand = { blob: blob.setContentType(size.type), ext: size.ext, width: size.w, height: size.h, url: u, hash: hash, small: Math.max(size.w, size.h) < MIN_IMAGE_SIDE };
      if (!best || cand.width * cand.height > best.width * best.height) best = cand;
    });
    if (!best) return;
    hashes[best.hash] = true;
    (best.small ? small : good).push(best);
  });
  small.sort(function (a, b) { return b.width * b.height - a.width * a.height; });
  var chosen = good.concat(good.length < 3 ? small.slice(0, 3 - good.length) : []);

  var existing = [];
  var it = dir.getFiles();
  while (it.hasNext()) { var f = it.next(); if (!f.isTrashed()) existing.push(f); }
  if (!chosen.length && existing.length) {
    // Nothing could be downloaded now (site down?): keep the images from the previous run.
    return existing.sort(function (a, b) { return a.getName() < b.getName() ? -1 : 1; }).map(function (f) {
      var size = imageSize(f.getBlob().getBytes()) || { w: 0, h: 0 };
      return { file: IMAGES_FOLDER + '/' + f.getName(), url: '', width: size.w, height: size.h, small: Math.max(size.w, size.h) < MIN_IMAGE_SIDE };
    });
  }
  existing.forEach(function (f) { f.setTrashed(true); });
  return chosen.map(function (im, n) {
    var name = stem + '-' + ('00' + (n + 1)).slice(-3) + '.' + im.ext;
    replaceFile(dir, name, im.blob);
    return { file: IMAGES_FOLDER + '/' + name, url: im.url, width: im.width, height: im.height, small: im.small };
  });
}

function uniqueIndexes(list, n) {
  var out = [];
  (list || []).forEach(function (i) { if (i >= 0 && i < n && out.indexOf(i) < 0) out.push(i); });
  return out;
}

// ---------------- Claude batches ----------------

function submitBatches(settings, kind) {
  var stages = getStages();
  var ids = Object.keys(stages).filter(function (id) { return stages[id] === kind + '_pending'; });
  if (!ids.length || timeLeft() < 30000) return;
  var style = kind === 'write' ? styleExamples(settings) : null;   // cached for 6 hours
  var requests = [];
  var members = [];
  var size = 0;
  var stop = false;
  var flush = function () {
    if (!requests.length || stop) return;
    var id;
    try {
      id = submitBatch(settings, requests);
    } catch (e) {
      if (e.status && e.status < 500 && e.status !== 408 && e.status !== 429) members.forEach(function (p) { fail(p, e); });
      else stop = true;   // overloaded / network: try again on the next run
      requests = []; members = []; size = 0;
      return;
    }
    setBatches(getBatches().concat([{ id: id, kind: kind, members: members.map(function (p) { return p.id; }) }]));
    var m = getStages();
    members.forEach(function (p) { p.stage = kind + '_wait'; p.batchId = id; saveState(p, m); });
    setStages(m);
    requests = []; members = []; size = 0;
  };
  ids.forEach(function (pid) {
    if (stop || timeLeft() < 30000) return;
    var p = loadState(pid);
    if (!p) { forget(pid); return; }
    if (settings.fast && !(p.useBatch && p.useBatch[kind])) return;   // fast mode: handled directly
    var params;
    try {
      params = claudeParams(settings, p, kind, style);
    } catch (e) {
      fail(p, e);
      return;
    }
    var req = { custom_id: p.id + '_' + kind + '_' + (kind === 'research' ? p.researchAttempts + '_' + p.researchPauses : p.writeAttempts), params: params };
    var bytes = JSON.stringify(req).length;
    if (size + bytes > MAX_BATCH_BYTES || requests.length >= MAX_BATCH_REQUESTS) flush();
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
    if (page) out.push({ url: u, text: page.text.slice(0, 5000) });
  });
  cache.put(key, JSON.stringify(out), 21600);
  return out;
}

var MAX_POLL_FAILURES = 10;

function pollBatches(settings) {
  var batches = getBatches();
  if (!batches.length) return;
  var remaining = [];
  batches.forEach(function (b) {
    var results;
    try {
      var batch = getBatch(settings, b.id);
      if (batch.processing_status !== 'ended') { remaining.push(b); return; }
      results = batchResults(settings, batch);
    } catch (e) {
      if (e.status === 404) return;   // the batch is gone: its products get resubmitted
      b.failures = (b.failures || 0) + 1;
      if (e.status === 401 || e.status === 403 || b.failures >= MAX_POLL_FAILURES) {
        failMembers(b, new Error('לא הצלחתי לקבל את התוצאות מ-Claude: ' + e.message));
      } else {
        remaining.push(b);
      }
      return;
    }
    var byId = {};
    results.forEach(function (line) { byId[line.custom_id.split('_')[0]] = line.result; });
    var m = getStages();
    (b.members || []).forEach(function (id) {
      if (m[id] !== b.kind + '_wait') return;   // already handled (e.g. a run was cut off halfway)
      var p = loadState(id);
      if (!p || p.batchId !== b.id) return;
      try {
        delete p.batchId;
        if (b.kind === 'research') applyResearch(p, byId[p.id]);
        else applyWrite(p, byId[p.id]);
        saveState(p, m);
      } catch (e) {
        fail(p, e);
        m = getStages();
      }
    });
    setStages(m);
  });
  setBatches(remaining);
}

function failMembers(b, e) {
  (b.members || []).forEach(function (id) {
    var p = loadState(id);
    if (p && p.batchId === b.id) fail(p, e);
  });
}

// A product waiting for a batch this script no longer tracks (a run was cut off at the wrong moment,
// or the batch disappeared) goes back to the queue instead of waiting forever.
function recoverLostWaits() {
  var stages = getStages();
  var tracked = {};
  getBatches().forEach(function (b) { (b.members || []).forEach(function (id) { tracked[id] = true; }); });
  var changed = false;
  Object.keys(stages).forEach(function (id) {
    if (!/_wait$/.test(stages[id]) || tracked[id]) return;
    stages[id] = stages[id].replace(/_wait$/, '_pending');
    var p = loadState(id);
    if (p) { p.stage = stages[id]; saveState(p, stages); }
    changed = true;
  });
  if (changed) setStages(stages);
}

function resultError(result) {
  if (!result) return 'no result';
  if (result.type === 'errored') return (result.error && result.error.error && result.error.error.message) || 'errored';
  return result.type;
}

function applyResearch(p, result) {
  if (!result || result.type !== 'succeeded') {
    p.researchAttempts++;
    p.researchContinuation = null;
    if (p.researchAttempts < 3) { p.stage = 'research_pending'; return; }
    throw new Error('Claude: ' + resultError(result));
  }
  var msg = result.message;
  // The web search hit its step limit: send the conversation back so Claude continues where it stopped.
  // All paused turns are one assistant message (the API needs user/assistant to alternate).
  if (msg.stop_reason === 'pause_turn' && (p.researchPauses || 0) < 5) {
    p.researchPauses = (p.researchPauses || 0) + 1;
    var before = p.researchContinuation ? p.researchContinuation.content : [];
    p.researchContinuation = { role: 'assistant', content: before.concat(msg.content) };
    p.stage = 'research_pending';
    return;
  }
  var r = parseResearch(msg);
  if (!r) p.researchAttempts++;
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
  if (result && result.type === 'errored' && p.lastWriteHadBrochure) {
    // Most likely the brochure PDF (too many pages, encrypted, ...): write without it.
    p.skipBrochure = true;
    p.writeAttempts--;
    p.warnings.push('Claude לא הצליח לקרוא את הברושור; הטקסט נכתב לפי אתרי היצרן והספק');
    p.stage = 'write_pending';
    return;
  }
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
  var problems = validateContent(content, readSettings().avoidWords);
  if (problems.length && p.writeAttempts < MAX_WRITE_ATTEMPTS) {
    p.writeFeedback = '\n\nבטיוטה הקודמת היו הבעיות הבאות - תקן/י:\n- ' + problems.join('\n- ') + '\nהטיוטה הקודמת:\n' + JSON.stringify(content);
    p.stage = 'write_pending';
    return;
  }
  var fatal = problems.filter(function (x) { return /^missing|not in Hebrew/.test(x); });
  if (fatal.length) throw new Error('Claude לא החזיר טקסט תקין (' + fatal.join(', ') + ')');
  p.warnings = p.warnings.concat(problems);
  p.content = content;
  p.stage = 'save';
  setRowStatus(p.id, STATUS.save, { name: content.name });
}

function finishIfDone(settings) {
  if (Object.keys(getStages()).length || getBatches().length) return;
  var had = ScriptApp.getProjectTriggers().filter(function (t) { return t.getHandlerFunction() === 'tick'; });
  deleteTriggers();
  stateFolder(settings).setTrashed(true);
  FOLDER_MEMO.state = null;
  if (!had.length || !settings.email) return;
  try {
    var appUrl = '';
    try { appUrl = ScriptApp.getService().getUrl() || ''; } catch (e) {}
    MailApp.sendEmail(Session.getEffectiveUser().getEmail(), 'סורק מוצרים: הסריקה הסתיימה',
      'כל המוצרים עובדו.' + (appUrl ? '\nבאפליקציה: ' + appUrl : '') + '\n\nהתיקייה בדרייב: ' + rootFolder(settings).getUrl());
  } catch (e) {
    console.warn('email not sent: ' + e.message);
  }
}
