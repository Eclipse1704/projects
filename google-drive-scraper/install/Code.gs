// סורק מוצרים ל-Google Drive - כל הקוד בקובץ אחד.
// מדביקים את כל הקובץ הזה ב-Code.gs בעורך של Apps Script. הוראות: README.md

// ======================================== Settings.gs ========================================
// Default settings. They are written to the "הגדרות" sheet on first setup and can be edited there.

var SHEET_PRODUCTS = 'מוצרים';
var SHEET_SETTINGS = 'הגדרות';

// Products sheet columns (1-based).
var COL = { LINK: 1, STATUS: 2, NAME: 3, MANUFACTURER: 4, FOLDER: 5, NOTES: 6, ID: 7 };
var HEADERS = ['קישור למוצר', 'סטטוס', 'שם המוצר', 'יצרן', 'תיקייה בדרייב', 'הערות', 'מזהה'];

var SHORT_MAX_WORDS = 80;
var FULL_MAX_WORDS = 500;

var DEFAULT_SETTINGS = [
  ['תיקייה בדרייב', 'NDT24 - מוצרים', 'שם התיקייה ב-Google Drive שאליה נשמרים המוצרים (תיקייה לכל מוצר)'],
  ['מודל', 'claude-sonnet-5', 'מודל Claude. claude-sonnet-5 = זול (ברירת מחדל). claude-opus-5 = חזק יותר, יקר פי 2.5'],
  ['מצב מהיר', 'כן', 'כן = כל מוצר מוכן תוך דקות (כ-0.4$ למוצר). לא = עבודת רקע, יכול לקחת עד שעה, חצי מחיר (כ-0.2$ למוצר)'],
  ['שליחת מייל בסיום', 'כן', 'כן / לא'],
  ['דפי דוגמה לסגנון', [
    'https://www.ndt24.co.il/product/%D7%9E%D7%A6%D7%9C%D7%9E%D7%94-%D7%AA%D7%A8%D7%9E%D7%99%D7%AA-fotric-348a/',
    'https://www.ndt24.co.il/product/sniffer430-%D7%9E%D7%9B%D7%A9%D7%99%D7%A8-%D7%9C%D7%90%D7%99%D7%AA%D7%95%D7%A8-%D7%A0%D7%96%D7%99%D7%9C%D7%95%D7%AA-%D7%9E%D7%99%D7%9D-%D7%91%D7%92%D7%96/',
    'https://www.ndt24.co.il/product/iris-x-pro-flexible-videoscope-system/',
  ].join('\n'), 'דפי מוצר מהאתר שלכם (כתובת בכל שורה). Claude כותב באותו סגנון ובאותם מונחים'],
  ['מילון מונחים', [
    'thermal camera = מצלמה תרמית',
    'thermal sensitivity / NETD = רגישות תרמית',
    'IR resolution = רזולוציית חיישן (למשל 640X480 פיקסלים)',
    'temperature range = טווח מדידת טמפרטורה',
    'water leak detection = איתור נזילות מים',
    'acoustic leak detector = מכשיר אקוסטי לאיתור נזילות',
    'tracer gas (hydrogen) = גז מימן / איתור נזילות בגז',
    'underground / under-floor pipes = צנרת תת-קרקעית / צנרת מתחת לריצוף',
    'pipe inspection camera / push camera = מצלמת צנרת / מצלמת ביוב',
    'videoscope = וידאוסקופ',
    'borescope = בורוסקופ',
    'fiberscope = פייברסקופ',
    'articulation = היגוי (ראש מתכוונן)',
    'probe / insertion tube = פרוב / צינור החדרה',
    'non-destructive testing (NDT) = בדיקות לא הורסות',
    'correlator = קורלטור',
  ].join('\n'), 'שורה לכל מונח: אנגלית = איך אומרים אצלנו. מוסיפים כאן כל מילה שיצאה לא טוב'],
  ['מילים שלא משתמשים בהן', [
    'הינו', 'הינה', 'הינם', 'הנו', 'מהפכני', 'מהפכנית', 'פורץ דרך', 'פתרון מושלם', 'יתר על כן', 'בנוסף לכך', 'באופן משמעותי', 'חווית משתמש',
  ].join('\n'), 'מילה או ביטוי בכל שורה. אם Claude משתמש באחד מהם, הטקסט חוזר אליו לתיקון'],
];

var SETTINGS_MEMO = null; // read once per run

function readSettings() {
  if (SETTINGS_MEMO) return SETTINGS_MEMO;
  var sheet = SpreadsheetApp.getActive().getSheetByName(SHEET_SETTINGS);
  var map = {};
  DEFAULT_SETTINGS.forEach(function (row) { map[row[0]] = row[1]; });
  if (sheet && sheet.getLastRow() > 1) {
    sheet.getRange(2, 1, sheet.getLastRow() - 1, 2).getValues().forEach(function (r) {
      if (r[0] && String(r[1]).trim() !== '') map[String(r[0]).trim()] = String(r[1]).trim();
    });
  }
  SETTINGS_MEMO = {
    rootFolder: map['תיקייה בדרייב'],
    model: map['מודל'],
    email: map['שליחת מייל בסיום'] !== 'לא',
    fast: map['מצב מהיר'] !== 'לא',
    styleUrls: map['דפי דוגמה לסגנון'].split(/\s+/).filter(function (u) { return /^https?:\/\//.test(u); }),
    glossary: map['מילון מונחים'],
    avoidWords: String(map['מילים שלא משתמשים בהן'] || '').split('\n').map(function (w) { return w.trim(); }).filter(String),
    // Stored for the whole spreadsheet, so the worker runs the same no matter which editor pressed 'run'.
    apiKey: PropertiesService.getScriptProperties().getProperty('ANTHROPIC_API_KEY') || PropertiesService.getUserProperties().getProperty('ANTHROPIC_API_KEY') || '',
    apiBase: PropertiesService.getScriptProperties().getProperty('ANTHROPIC_API_BASE') || 'https://api.anthropic.com',
  };
  return SETTINGS_MEMO;
}

// ======================================== Extract.gs ========================================
// Reading web pages without a DOM (Apps Script has none): links, images, PDFs, YouTube links and text.

var UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';
var YT_ID = /(?:youtube(?:-nocookie)?\.com\/(?:embed\/|watch\?v=|v\/|shorts\/)|youtu\.be\/)([A-Za-z0-9_-]{11})/g;
var SKIP_IMG = /(logo|icon|sprite|placeholder|avatar|badge|flag|payment|favicon|loader|spinner|pixel)/i;
var MANUAL_WORDS = ['manual', 'user guide', 'userguide', 'user-guide', 'instruction', 'operating', 'handbuch',
  'bedienungsanleitung', 'anleitung', 'quick start', 'quickstart', 'guide'];
var BROCHURE_WORDS = ['brochure', 'datasheet', 'data sheet', 'data-sheet', 'catalog', 'catalogue', 'leaflet', 'flyer',
  'prospekt', 'spec sheet', 'specification', 'datenblatt'];

// Spaces, Hebrew letters etc. must be percent-encoded (already-encoded %XX stays as is).
function encodeUrl(url) {
  return String(url).replace(/[^\x21-\x7e]+/g, function (c) { return encodeURIComponent(c); });
}

function fetchOptions(extra) {
  var opts = { muteHttpExceptions: true, followRedirects: true, headers: { 'User-Agent': UA, 'Accept-Language': 'en-US,en;q=0.9' } };
  for (var k in (extra || {})) opts[k] = extra[k];
  return opts;
}

// Responses downloaded ahead of time by prefetch(), used once by fetchUrl().
var FETCH_CACHE = {};
function fetchKey(url, extra) { return url + '|' + (extra && extra.followRedirects === false ? 'no-redirect' : ''); }

function fetchUrl(url, extra) {
  url = encodeUrl(url);
  var key = fetchKey(url, extra);
  if (key in FETCH_CACHE) {
    var hit = FETCH_CACHE[key];
    delete FETCH_CACHE[key];
    return hit;
  }
  try {
    var r = UrlFetchApp.fetch(url, fetchOptions(extra));
    return r.getResponseCode() < 400 ? r : null;
  } catch (e) {
    return null;
  }
}

// Downloads many URLs at the same time (much faster than one by one).
function prefetch(urls, extra) {
  var todo = [];
  (urls || []).forEach(function (u) {
    if (!u) return;
    u = encodeUrl(u);
    if (todo.indexOf(u) < 0 && !(fetchKey(u, extra) in FETCH_CACHE)) todo.push(u);
  });
  for (var i = 0; i < todo.length; i += 10) {
    var chunk = todo.slice(i, i + 10);
    try {
      var rs = UrlFetchApp.fetchAll(chunk.map(function (u) { var o = fetchOptions(extra); o.url = u; return o; }));
      rs.forEach(function (r, j) { FETCH_CACHE[fetchKey(chunk[j], extra)] = r.getResponseCode() < 400 ? r : null; });
    } catch (e) {
      // One of them didn't answer in time: the others are fetched one by one when needed.
    }
  }
}

function clearPrefetch() { FETCH_CACHE = {}; }

function hostOf(url) {
  var m = String(url).match(/^https?:\/\/([^\/?#:]+)/i);
  return m ? m[1].toLowerCase() : '';
}

function isOfficial(url, domains) {
  var h = hostOf(url);
  return (domains || []).some(function (d) {
    d = String(d).toLowerCase().replace(/^\.+/, '');
    return d && (h === d || h.slice(-(d.length + 1)) === '.' + d);
  });
}

function cleanDomains(list) {
  var out = [];
  (list || []).forEach(function (d) {
    d = String(d).trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
    if (d.indexOf('.') > 0 && out.indexOf(d) < 0) out.push(d);
  });
  return out;
}

// Resolve a (possibly relative) link against the page URL.
function resolveUrl(href, base) {
  href = decodeEntities(String(href || '').trim());
  if (!href || /^(javascript|mailto|tel|data):/i.test(href)) return null;
  if (/^https?:\/\//i.test(href)) return href;
  var m = base.match(/^(https?:)\/\/([^\/?#]+)([^?#]*)/i);
  if (!m) return null;
  if (href.indexOf('//') === 0) return m[1] + href;
  if (href.charAt(0) === '/') return m[1] + '//' + m[2] + href;
  if (href.charAt(0) === '?') return m[1] + '//' + m[2] + m[3] + href;
  if (href.charAt(0) === '#') return base.split('#')[0] + href;
  var dir = m[3].replace(/[^\/]*$/, '') || '/';
  var parts = (dir + href).split('/');
  var out = [];
  parts.forEach(function (p, i) {
    if (p === '..') { if (out.length > 1) out.pop(); }
    else if (p !== '.' || i === parts.length - 1) out.push(p === '.' ? '' : p);
  });
  return m[1] + '//' + m[2] + out.join('/');
}

function decodeEntities(s) {
  return String(s || '')
    .replace(/&#(\d+);/g, function (_, n) { return codePoint(+n); })
    .replace(/&#x([0-9a-f]+);/gi, function (_, n) { return codePoint(parseInt(n, 16)); })
    .replace(/&nbsp;/g, ' ').replace(/&quot;/g, '"').replace(/&#039;|&apos;/g, "'")
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

function codePoint(n) {
  try { return String.fromCodePoint(n); } catch (e) { return ''; }
}

function stripTags(s) {
  return decodeEntities(String(s || '').replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();
}

function attrsOf(tag) {
  var out = {};
  var re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/g;
  var m;
  while ((m = re.exec(tag))) out[m[1].toLowerCase()] = m[3] !== undefined ? m[3] : (m[4] !== undefined ? m[4] : m[5]);
  return out;
}

function metaContent(html, prop) {
  var re = /<meta\b[^>]*>/gi;
  var m;
  while ((m = re.exec(html))) {
    var a = attrsOf(m[0]);
    if ((a.property || a.name || '').toLowerCase() === prop) return decodeEntities(a.content || '');
  }
  return '';
}

function jsonLdProducts(html) {
  var out = [];
  var re = /<script[^>]*application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi;
  var m;
  while ((m = re.exec(html))) {
    var data;
    try { data = JSON.parse(m[1]); } catch (e) { continue; }
    var stack = [data];
    while (stack.length) {
      var d = stack.pop();
      if (Array.isArray(d)) { stack = stack.concat(d); continue; }
      if (d && typeof d === 'object') {
        var t = d['@type'];
        if (t === 'Product' || (Array.isArray(t) && t.indexOf('Product') >= 0)) out.push(d);
        for (var k in d) if (d[k] && typeof d[k] === 'object') stack.push(d[k]);
      }
    }
  }
  return out;
}

// Page text with a little structure (headings, list items, table cells), for Claude.
function pageText(html, maxChars) {
  var s = String(html)
    .replace(/<(script|style|noscript|svg|nav|header|footer|iframe)\b[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<h[1-6][^>]*>/gi, '\n## ').replace(/<li[^>]*>/gi, '\n- ')
    .replace(/<\/(td|th)>/gi, ' | ').replace(/<(br|\/p|\/div|\/tr|\/h[1-6]|\/li|\/dt|\/dd|\/section)[^>]*>/gi, '\n')
    .replace(/<[^>]*>/g, ' ');
  s = decodeEntities(s).split('\n').map(function (l) { return l.replace(/\s+/g, ' ').trim(); })
    .filter(function (l) { return l && l !== '-' && l !== '##' && l !== '|'; });
  var out = [];
  s.forEach(function (l) { if (out[out.length - 1] !== l) out.push(l); });
  return out.join('\n').slice(0, maxChars || 15000);
}

// Turn a thumbnail / resized URL into the original, full-size image URL.
function canonicalImage(url) {
  // Images served by a script (getimage.ashx?id=7 ...) need their parameters as they are.
  if (!/\.(jpe?g|png|webp)(\/|$)/i.test(url.split(/[?#]/)[0])) return url;
  return url
    .replace(/-\d{2,4}x\d{2,4}(?=\.(jpe?g|png|webp)(\?|$))/i, '')                                  // WordPress thumbnails
    .replace(/_(\d{2,4}x\d{0,4}|\d{0,4}x\d{2,4}|pico|icon|thumb|small|compact|medium|large|grande)(?=\.(jpe?g|png|webp))/i, '') // Shopify
    .replace(/(\/media\/[^\/?#]+\.(jpe?g|png|webp))\/v1\/.*$/i, '$1')                                // Wix
    .replace(/([?&])format=\d+w/i, '$1format=2500w')                                                 // Squarespace
    .replace(/([?&])(width|height|w|h|resize|fit|crop|quality|q)=[^&#]*/gi, '$1')                    // resize parameters
    .replace(/[?&]+(#|$)/, '$1').replace(/\?&+/, '?').replace(/&&+/g, '&');
}

// Same photo in different sizes -> same key.
function imageKey(url) {
  if (!/\.(jpe?g|png|webp)(\/|$)/i.test(url.split(/[?#]/)[0])) return url;
  var name = canonicalImage(url).split(/[?#]/)[0].split('/').pop().toLowerCase();
  return name.replace(/\.(jpe?g|png|webp)$/, '').replace(/(-scaled|@\dx|-e\d{10,})$/, '');
}

// Largest candidate in a srcset ("a.jpg 300w, b.jpg 1200w").
function largestFromSrcset(srcset) {
  var best = null;
  var bestW = -1;
  // Split on the commas that end a candidate ("a.jpg 300w,b.jpg 1200w"); URLs may contain commas themselves.
  String(srcset || '').trim().split(/(?<=\s\d+(?:\.\d+)?[wx])\s*,\s*/i).forEach(function (part) {
    var bits = part.trim().split(/\s+/);
    var d = bits[1] || '1x';
    var w = parseFloat(d) * (/x$/i.test(d) ? 1000 : 1);
    if (bits[0] && w > bestW) { best = bits[0]; bestW = w; }
  });
  return best;
}

// Pixel size from the file header (JPEG / PNG / WebP), without decoding the image.
function imageSize(bytes) {
  var b = function (i) { return bytes[i] & 255; };
  if (b(0) === 0x89 && b(1) === 0x50) return { type: 'image/png', ext: 'png', w: (b(16) << 24 | b(17) << 16 | b(18) << 8 | b(19)) >>> 0, h: (b(20) << 24 | b(21) << 16 | b(22) << 8 | b(23)) >>> 0 };
  if (b(0) === 0x52 && b(8) === 0x57) { // RIFF....WEBP
    var chunk = String.fromCharCode(b(12), b(13), b(14), b(15));
    if (chunk === 'VP8X') return { type: 'image/webp', ext: 'webp', w: 1 + (b(24) | b(25) << 8 | b(26) << 16), h: 1 + (b(27) | b(28) << 8 | b(29) << 16) };
    if (chunk === 'VP8 ') return { type: 'image/webp', ext: 'webp', w: (b(26) | b(27) << 8) & 0x3fff, h: (b(28) | b(29) << 8) & 0x3fff };
    if (chunk === 'VP8L') return { type: 'image/webp', ext: 'webp', w: 1 + ((b(22) << 8 | b(21)) & 0x3fff), h: 1 + ((b(24) << 10 | b(23) << 2 | b(22) >> 6) & 0x3fff) };
  }
  if (b(0) === 0xff && b(1) === 0xd8) {
    var i = 2;
    while (i + 9 < bytes.length) {
      if (b(i) !== 0xff) { i++; continue; }
      var m = b(i + 1);
      if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { i += 2; continue; }
      if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) return { type: 'image/jpeg', ext: 'jpg', h: b(i + 5) << 8 | b(i + 6), w: b(i + 7) << 8 | b(i + 8) };
      i += 2 + (b(i + 2) << 8 | b(i + 3));
    }
  }
  return null;
}

function classifyPdf(url, label) {
  var path = String(url);
  try { path = decodeURIComponent(path); } catch (e) {}   // e.g. Latin-1 "Brosch%FCre.pdf"
  var text = (label + ' ' + path).toLowerCase().replace(/_/g, ' ');
  if (MANUAL_WORDS.some(function (w) { return text.indexOf(w) >= 0; })) return 'manual';
  if (BROCHURE_WORDS.some(function (w) { return text.indexOf(w) >= 0; })) return 'brochure';
  return 'document';
}

// Everything useful on one page.
function parsePage(html, url) {
  var page = { url: url, title: '', text: pageText(html), images: [], pdfs: [], videos: [], links: [] };
  var h1 = html.match(/<h1\b[^>]*>([\s\S]*?)<\/h1>/i);
  var ld = jsonLdProducts(html);
  var ldName = ld[0] && (typeof ld[0].name === 'string' ? ld[0].name : ld[0].name && ld[0].name['@value']);
  page.title = (ldName && stripTags(ldName)) || (h1 && stripTags(h1[1])) || metaContent(html, 'og:title') || stripTags((html.match(/<title>([\s\S]*?)<\/title>/i) || [])[1]);
  var desc = [];
  ld.forEach(function (d) { if (typeof d.description === 'string') desc.push(stripTags(d.description)); });
  if (metaContent(html, 'og:description')) desc.push(metaContent(html, 'og:description'));
  if (desc.length) page.text = desc.join('\n') + '\n\n' + page.text;

  // Images: several sizes of the same photo are merged, keeping the biggest source.
  var RANK = { link: 4, zoom: 4, 'json-ld': 3, 'og:image': 3, srcset: 2, img: 1 };
  var byKey = {};
  function addImg(src, alt, source, cls) {
    src = resolveUrl(src, url);
    if (!src) return;
    var next = src.match(/\/_next\/image\?(?:.*&)?url=([^&]+)/);   // Next.js resizer: take the original file
    if (next) { try { src = resolveUrl(decodeURIComponent(next[1]), url); } catch (e) {} if (!src) return; }
    var path = src.split('?')[0].toLowerCase();
    if (SKIP_IMG.test(path) || /\.(svg|gif)$/.test(path)) return;
    var canon = canonicalImage(src);
    var key = imageKey(src);
    var have = byKey[key];
    if (have) {
      if ((RANK[source] || 0) > (RANK[have.source] || 0)) {
        if (have.url !== canon && !have.fallback) have.fallback = have.url;
        have.url = canon;
        have.source = source;
      }
      if (!have.alt && alt) have.alt = stripTags(alt).slice(0, 120);
      return;
    }
    byKey[key] = { url: canon, fallback: canon !== src ? src : '', alt: stripTags(alt).slice(0, 120), source: source, where: cls || '' };
    page.images.push(byKey[key]);
  }
  ld.forEach(function (d) {
    [].concat(d.image || []).forEach(function (i) { addImg(typeof i === 'string' ? i : (i && i.url), '', 'json-ld'); });
  });
  if (metaContent(html, 'og:image')) addImg(metaContent(html, 'og:image'), '', 'og:image');
  var m;
  var imgRe = /<img\b[^>]*>/gi;
  while ((m = imgRe.exec(html))) {
    var a = attrsOf(m[0]);
    var zoom = a['data-large_image'] || a['data-zoom-image'] || a['data-full'] || a['data-full-url'] || a['data-highres'] || a['data-orig-file'];
    var set = largestFromSrcset(a['data-srcset'] || a.srcset);
    var src = a['data-src'] || a['data-lazy-src'] || a['data-original'] || a.src;
    var cls = a['class'] ? a['class'].slice(0, 60) : '';
    if (src && !/^data:/.test(src)) addImg(src, a.alt || '', 'img', cls);
    if (set) addImg(set, a.alt || '', 'srcset', cls);
    if (zoom) addImg(zoom, a.alt || '', 'zoom', cls);
  }

  var aRe = /<a\b([^>]*)>([\s\S]*?)<\/a>/gi;
  var seenLink = {};
  while ((m = aRe.exec(html))) {
    var at = attrsOf('<a ' + m[1] + '>');
    var href = resolveUrl(at.href, url);
    if (!href) continue;
    var label = stripTags(m[2]) || at.title || '';
    if (/\.pdf(\?|#|$)/i.test(href)) {
      if (!page.pdfs.some(function (p) { return p.url === href; })) page.pdfs.push({ url: href, label: label.slice(0, 150), kind: classifyPdf(href, label) });
    } else if (/\.(jpe?g|png|webp)(\?|$)/i.test(href)) {
      addImg(href, label, 'link');
    } else if (!seenLink[href] && /^https?:/i.test(href)) {
      seenLink[href] = true;
      page.links.push({ url: href.split('#')[0], text: label.slice(0, 120) });
    }
  }

  var seenVid = {};
  YT_ID.lastIndex = 0;
  while ((m = YT_ID.exec(html))) {
    if (seenVid[m[1]] || m[1] === 'videoseries') continue;   // embed/videoseries = a playlist, not a video
    seenVid[m[1]] = true;
    var around = html.slice(Math.max(0, m.index - 300), m.index + 300);
    var t = around.match(/title=["']([^"']{3,120})["']/i);
    page.videos.push({ url: 'https://www.youtube.com/watch?v=' + m[1], title: t ? decodeEntities(t[1]) : '' });
  }
  return page;
}

// Follows redirects itself so relative links are resolved against the page's real address.
function fetchPage(url) {
  var r = null;
  for (var hop = 0; hop < 6; hop++) {
    r = fetchUrl(url, { followRedirects: false });
    if (!r) return null;
    var code = r.getResponseCode();
    var h = r.getHeaders();
    var loc = h.Location || h.location;
    if (code >= 300 && code < 400 && loc) { url = resolveUrl(loc, url); if (!url) return null; continue; }
    break;
  }
  var type = String(r.getHeaders()['Content-Type'] || r.getHeaders()['content-type'] || '');
  if (type && !/html|xml/i.test(type)) return null;
  var html = r.getContentText();
  var base = (html.match(/<base\b[^>]*href=["']([^"']+)["']/i) || [])[1];
  var page = parsePage(html, base ? (resolveUrl(base, url) || url) : url);
  page.url = url;
  return page;
}

// ======================================== Claude.gs ========================================
// Claude API over plain HTTP (Apps Script has no official SDK).
// Long work (web research, writing) goes through the Message Batches API: Apps Script cuts every
// HTTP request off after ~60 seconds, and batches also cost 50% less.

function claudeRequest(settings, method, path, body) {
  var opts = {
    method: method,
    muteHttpExceptions: true,
    contentType: 'application/json',
    headers: { 'x-api-key': settings.apiKey, 'anthropic-version': '2023-06-01' },
  };
  if (body) opts.payload = JSON.stringify(body);
  var r = UrlFetchApp.fetch(settings.apiBase + path, opts);
  var code = r.getResponseCode();
  var text = r.getContentText();
  if (code >= 400) {
    var msg = text;
    try { msg = JSON.parse(text).error.message; } catch (e) {}
    var err = new Error('Claude API ' + code + ': ' + msg + (code === 401 ? ' (מפתח ה-API לא תקין - סורק מוצרים ← הגדרת מפתח API)' : ''));
    err.status = code;
    throw err;
  }
  return text ? JSON.parse(text) : {};
}

// Fast mode: direct calls, several at the same time. Apps Script cuts every request off after ~60s;
// if one doesn't answer in time the whole group comes back as {timeout: true} and those products
// continue as batch jobs instead.
function claudeNow(settings, paramsList) {
  var reqs = paramsList.map(function (params) {
    return {
      url: settings.apiBase + '/v1/messages', method: 'post', contentType: 'application/json', muteHttpExceptions: true,
      headers: { 'x-api-key': settings.apiKey, 'anthropic-version': '2023-06-01' }, payload: JSON.stringify(params),
    };
  });
  var rs;
  try {
    rs = UrlFetchApp.fetchAll(reqs);
  } catch (e) {
    return paramsList.map(function () { return { timeout: true, message: String(e && e.message || e) }; });
  }
  return rs.map(function (r) {
    var code = r.getResponseCode();
    var text = r.getContentText();
    var body = null;
    try { body = JSON.parse(text); } catch (e) {}
    if (code < 400 && body) return { result: { type: 'succeeded', message: body } };
    var msg = 'Claude API ' + code + ': ' + ((body && body.error && body.error.message) || String(text).slice(0, 200)) +
      (code === 401 ? ' (מפתח ה-API לא תקין - סורק מוצרים ← הגדרת מפתח API)' : '');
    return { status: code, message: msg, result: { type: 'errored', error: { error: { message: msg } } } };
  });
}

function submitBatch(settings, requests) {
  return claudeRequest(settings, 'post', '/v1/messages/batches', { requests: requests }).id;
}

function getBatch(settings, id) {
  return claudeRequest(settings, 'get', '/v1/messages/batches/' + id);
}

function batchResults(settings, batch) {
  var r = UrlFetchApp.fetch(batch.results_url, {
    muteHttpExceptions: true,
    headers: { 'x-api-key': settings.apiKey, 'anthropic-version': '2023-06-01' },
  });
  if (r.getResponseCode() >= 400) throw new Error('Claude API results ' + r.getResponseCode());
  return r.getContentText().split('\n').filter(function (l) { return l.trim(); }).map(function (l) { return JSON.parse(l); });
}

function messageText(message) {
  return (message.content || []).filter(function (b) { return b.type === 'text'; }).map(function (b) { return b.text; }).join('');
}

// ---------- Stage: who makes it, and where is the official site ----------

function researchParams(settings, p) {
  var page = p.supplier || {};
  var question =
    'Product page: ' + p.link + '\n' +
    (page.title ? 'Product name on the page: ' + page.title + '\n' : '') +
    (page.text ? 'Page text (excerpt):\n' + page.text.slice(0, 5000) + '\n' : '(The page could not be downloaded directly - fetch it yourself.)\n') +
    '\nFind, using web search and web fetch:\n' +
    '1. The manufacturer (brand owner) of this product and ALL domains of its OFFICIAL websites. Distributors, resellers, marketplaces and review sites are NOT official.\n' +
    '2. The product\'s own page on the manufacturer\'s official website.\n' +
    '3. An official page that lists downloads for this product (brochure / datasheet / user manual), if there is one.\n' +
    '4. Whether ' + hostOf(p.link) + ' is itself the manufacturer\'s official site.\n' +
    'Only report URLs you actually saw. Finish with ONLY this JSON (no other text after it):\n' +
    '```json\n{"manufacturer": "", "model": "", "official_domains": [], "official_product_url": "", "official_downloads_url": "", "site_is_manufacturer": false}\n```\n' +
    'manufacturer = brand name as the manufacturer writes it (e.g. "FOTRIC"); model = model name without the brand (e.g. "348A"); use "" when not found.' +
    (settings.fast ? '\nWork quickly: usually one or two searches are enough. Use web_fetch only if the search results don\'t show the URLs you need - the pages themselves are read later by other code.' : '');
  var params = {
    model: settings.model,
    max_tokens: 16000,
    tools: [
      { type: 'web_search_20260209', name: 'web_search', max_uses: settings.fast ? 4 : 6 },
      { type: 'web_fetch_20260209', name: 'web_fetch', max_uses: settings.fast ? 2 : 6 },
    ],
    messages: [{ role: 'user', content: question }],
  };
  if (settings.fast) params.output_config = { effort: 'medium' };   // finding a website doesn't need deep thinking
  return params;
}

function parseResearch(message) {
  var text = messageText(message);
  var m = text.match(/```json\s*([\s\S]*?)```/) || text.match(/(\{[\s\S]*"official_domains"[\s\S]*\})/);
  if (!m) return null;
  try {
    var r = JSON.parse(m[1]);
    return {
      manufacturer: String(r.manufacturer || '').trim(),
      model: String(r.model || '').trim(),
      official_domains: cleanDomains(r.official_domains),
      official_product_url: String(r.official_product_url || '').trim(),
      official_downloads_url: String(r.official_downloads_url || '').trim(),
      site_is_manufacturer: r.site_is_manufacturer === true,
    };
  } catch (e) {
    return null;
  }
}

// ---------- Stage: write the Hebrew entry and choose the files ----------

var WRITE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['name', 'short_description', 'overview', 'usage', 'features', 'specs', 'image_indexes', 'brochure_index', 'manual_index', 'video_indexes'],
  properties: {
    name: { type: 'string', description: "Hebrew product title in the house style, e.g. 'מצלמה תרמית 640X480 פיקסלים Fotric 348A'" },
    short_description: { type: 'string', description: 'Hebrew, at most ' + SHORT_MAX_WORDS + ' words' },
    overview: { type: 'string', description: 'Hebrew overview; paragraphs separated by a blank line' },
    usage: { type: 'array', items: { type: 'string' }, description: 'Hebrew bullet points: applications and how the product is used' },
    features: { type: 'array', items: { type: 'string' }, description: 'Hebrew bullet points: key features' },
    specs: {
      type: 'array',
      description: 'technical specifications; Hebrew labels, values as in the source',
      items: { type: 'object', additionalProperties: false, required: ['name', 'value'], properties: { name: { type: 'string' }, value: { type: 'string' } } },
    },
    image_indexes: { type: 'array', items: { type: 'integer' }, description: 'indexes of up to 8 photos of THIS product, best first (the first 3-5 high-resolution ones are kept). No logos, icons, banners, certificates, other products or accessories' },
    brochure_index: { type: 'integer', description: 'index of the PDF that is this product\'s brochure / datasheet / catalogue, or -1' },
    manual_index: { type: 'integer', description: 'index of the PDF that is this product\'s user manual, or -1' },
    video_indexes: { type: 'array', items: { type: 'integer' }, description: 'indexes of YouTube videos that demonstrate THIS product' },
  },
};

function systemPrompt(settings, styleExamples) {
  var examples = styleExamples.map(function (e, i) {
    return '<example index="' + (i + 1) + '" url="' + e.url + '">\n' + e.text + '\n</example>';
  }).join('\n');
  return 'את/ה קופירייטר/ית טכני/ת בכיר/ה ב-NDT24, יבואנית ישראלית של ציוד לבדיקות לא הורסות (NDT), איתור נזילות מים, מצלמות צנרת, וידאוסקופים ומצלמות תרמיות.\n' +
    'המשימה: לכתוב דף מוצר בעברית לאתר, על סמך חומר מקור באנגלית (או בשפה אחרת) מאתר הספק, מאתר היצרן ומהברושור שלו, ולבחור את התמונות, הקבצים והסרטונים של המוצר.\n\n' +
    'איך כותבים:\n' +
    '- עברית טבעית, עכשווית ומקצועית - כמו שטכנאי או איש מכירות בתחום בישראל מדבר וכותב היום. לא תרגום מילולי, לא לשון גבוהה או ארכאית, ולא מילים עבריות "מומצאות" שאף אחד בענף לא משתמש בהן.\n' +
    '- כשבענף בישראל משתמשים במונח הלועזי (למשל וידאוסקופ, פרוב, Wi-Fi, NETD, IP54) - משתמשים בו. שמות מותגים, דגמים, יחידות, תקנים ופרוטוקולים נשארים באותיות לטיניות.\n' +
    '- להשתמש במונחים מרשימת המונחים ומדוגמאות הסגנון של NDT24. הדוגמאות הן המקור הקובע לסגנון, לטון ולאוצר המילים - לא לתוכן.\n' +
    '- כותרת המוצר (name) בפורמט של האתר: סוג המוצר בעברית + נתון מפתח אם רלוונטי + מותג + דגם. לדוגמה: "מצלמה תרמית 640X480 פיקסלים Fotric 348A", "Sniffer430 מכשיר לאיתור נזילות מים בגז".\n' +
    '- משפטים קצרים וברורים, בגוף פעיל. כותבים כמו טכנאי מנוסה שמסביר ללקוח מקצועי מה המכשיר עושה ולמה הוא טוב לו - בלי מליצות ובלי שפה שיווקית מתורגמת.\n' +
    '- לא לתרגם מילה במילה מאנגלית. לדוגמה: לא "המכשיר הינו פתרון מושלם עבור..." אלא "המכשיר מתאים ל..."; לא "מספק למשתמש יכולת לבצע איתור" אלא "מאתר"; לא "חווית משתמש אינטואיטיבית" אלא "תפעול פשוט".\n' +
    '- לא להשתמש במילים ובביטויים שברשימה <avoid_words>.\n' +
    '- short_description: עד ' + SHORT_MAX_WORDS + ' מילים - מה המוצר, למי הוא מיועד והיתרון המרכזי.\n' +
    '- התיאור המלא = overview + usage + features + specs, ביחד עד ' + FULL_MAX_WORDS + ' מילים. usage מתאר את השימושים וגם איך עובדים עם המוצר. כשאין מקום - לשמור את המפרטים החשובים ביותר.\n\n' +
    'עובדות:\n' +
    '- רק עובדות שמופיעות בחומר המקור. אסור להמציא נתונים, מספרים, תקנים, אחריות או טענות. מה שלא מופיע - לא נכתב.\n' +
    '- כשיש סתירה, עדיף המידע מאתר היצרן הרשמי ומהברושור שלו.\n' +
    '- בלי מחירים, בלי פרטי התקשרות, בלי סופרלטיבים שלא מופיעים במקור.\n\n' +
    'לפני שמחזירים תשובה: קוראים שוב כל משפט בעברית. משפט שנשמע מתורגם, מסורבל או לא כמו שאומרים בענף - כותבים מחדש.\n\n' +
    'בחירת קבצים: בוחרים רק מתוך הרשימות הממוספרות (כולן מאתר היצרן הרשמי). אם אין פריט מתאים - רשימה ריקה או -1.\n\n' +
    '<glossary>\n' + settings.glossary + '\n</glossary>\n\n<avoid_words>\n' + (settings.avoidWords || []).join('\n') + '\n</avoid_words>\n\n<style_examples>\n' + (examples || '(no examples)') + '\n</style_examples>';
}

function writeParams(settings, p, styleExamples, brochureBase64, feedback) {
  var off = p.official || { images: [], pdfs: [], videos: [], pages: [] };
  var parts = ['Manufacturer: ' + p.research.manufacturer, 'Model: ' + p.research.model, 'Product link: ' + p.link];
  (off.pages || []).forEach(function (pg) { parts.push('\n=== OFFICIAL MANUFACTURER PAGE: ' + pg.url + ' ===\n' + pg.text); });
  if (p.supplier && p.supplier.text && !p.research.site_is_manufacturer) parts.push('\n=== SUPPLIER PAGE: ' + p.link + ' ===\n' + p.supplier.text);
  var sources = parts.join('\n').slice(0, 60000);
  var lists =
    '<images>\n' + off.images.map(function (im, i) { return i + '\t' + im.url + '\t' + (im.alt || '') + '\t' + (im.where || ''); }).join('\n') + '\n</images>\n' +
    '<pdfs>\n' + off.pdfs.map(function (d, i) { return i + '\t' + d.url + '\t' + (d.label || ''); }).join('\n') + '\n</pdfs>\n' +
    '<videos>\n' + off.videos.map(function (v, i) { return i + '\t' + v.url + '\t' + (v.title || ''); }).join('\n') + '\n</videos>';
  var content = [];
  if (brochureBase64) content.push({ type: 'document', title: 'Official brochure', source: { type: 'base64', media_type: 'application/pdf', data: brochureBase64 } });
  content.push({ type: 'text', text: '<sources>\n' + sources + '\n</sources>\n\n' + lists + '\n\nכתוב/י את דף המוצר ובחר/י את התמונות, הקבצים והסרטונים.' + (feedback || '') });
  return {
    model: settings.model,
    max_tokens: 16000,
    system: [{ type: 'text', text: systemPrompt(settings, styleExamples), cache_control: { type: 'ephemeral' } }],
    messages: [{ role: 'user', content: content }],
    // Fast mode answers within Apps Script's ~60s limit more often at 'medium'; the Hebrew checks still apply.
    output_config: { effort: settings.fast ? 'medium' : 'high', format: { type: 'json_schema', schema: WRITE_SCHEMA } },
  };
}

function wordCount(s) {
  return (String(s || '').match(/\S+/g) || []).length;
}

// Hebrew word match (\b doesn't work for Hebrew letters).
function containsWord(text, word) {
  var esc = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp('(^|[^\u0590-\u05FF])' + esc + '(?=$|[^\u0590-\u05FF])').test(text);
}

function validateContent(c, avoidWords) {
  var problems = [];
  ['name', 'short_description', 'overview'].forEach(function (k) { if (!String(c[k] || '').trim()) problems.push('missing ' + k); });
  var s = wordCount(c.short_description);
  if (s > SHORT_MAX_WORDS) problems.push('short_description has ' + s + ' words (max ' + SHORT_MAX_WORDS + ')');
  var parts = [c.overview].concat(c.usage || [], c.features || [], (c.specs || []).map(function (x) { return x.name + ' ' + x.value; }));
  var f = parts.reduce(function (n, x) { return n + wordCount(x); }, 0);
  if (f > FULL_MAX_WORDS) problems.push('full description (overview+usage+features+specs) has ' + f + ' words (max ' + FULL_MAX_WORDS + ')');
  if (!/[\u0590-\u05FF]/.test(String(c.short_description) + String(c.overview))) problems.push('texts are not in Hebrew');
  var all = [c.name, c.short_description, c.overview].concat(c.usage || [], c.features || [], (c.specs || []).map(function (x) { return x.name; })).join('\n');
  var used = (avoidWords || []).filter(function (w) { return containsWord(all, w); });
  if (used.length) problems.push('uses words from <avoid_words>: ' + used.join(', ') + ' - rewrite those sentences');
  return problems;
}

// ======================================== Output.gs ========================================
// Output: one Drive folder per product with the Hebrew HTML page, a Google Doc copy for reading,
// 3-5 images, the brochure and the user manual.

function esc(s) {
  return String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

function slug(s) {
  return String(s || '').normalize('NFKD').replace(/[̀-ͯ]/g, '').replace(/[^A-Za-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

// MANUFACTURER-PRODUCT, upper-case, without repeating the manufacturer.
function fileStem(manufacturer, product) {
  var m = slug(manufacturer).toUpperCase();
  var p = slug(product).toUpperCase();
  if (m && p.indexOf(m + '-') === 0) p = p.slice(m.length + 1);
  if (m && p === m) p = '';
  return [m, p].filter(String).join('-') || 'PRODUCT';
}

var FOLDER_MEMO = {};

// DriveApp's name lookups also return items that are in the trash: take the first one that isn't.
function firstLive(it) {
  while (it.hasNext()) {
    var x = it.next();
    if (!x.isTrashed()) return x;
  }
  return null;
}

function rootFolder(settings) {
  if (!FOLDER_MEMO.root) {
    FOLDER_MEMO.root = firstLive(DriveApp.getFoldersByName(settings.rootFolder)) || DriveApp.createFolder(settings.rootFolder);
  }
  return FOLDER_MEMO.root;
}

// Work-in-progress data for each product (deleted automatically when everything is done).
function stateFolder(settings) {
  if (!FOLDER_MEMO.state) {
    var root = rootFolder(settings);
    FOLDER_MEMO.state = firstLive(root.getFoldersByName('_מצב_עבודה')) || root.createFolder('_מצב_עבודה');
  }
  return FOLDER_MEMO.state;
}

function replaceFile(folder, name, blob) {
  var it = folder.getFilesByName(name);
  while (it.hasNext()) { var f = it.next(); if (!f.isTrashed()) f.setTrashed(true); }
  return folder.createFile(blob.setName(name));
}

var KIND_HE = { brochure: 'ברושור', manual: 'מדריך למשתמש' };
var NOT_FOUND = '<p class="missing">לא נמצא באתר היצרן הרשמי.</p>';
var PAGE_CSS = 'body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;max-width:960px;margin:0 auto;padding:16px;line-height:1.6;color:#1a1a1a;background:#fff}' +
  'h1{font-size:1.7rem;margin-bottom:.2rem}h2{border-bottom:1px solid #ddd;padding-bottom:4px;margin-top:2rem;font-size:1.3rem}h3{font-size:1.1rem}' +
  'table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:6px 10px;text-align:start;vertical-align:top}th{background:#f5f5f5;width:35%}' +
  '.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px}.gallery img{width:100%;height:180px;object-fit:contain;border:1px solid #eee;background:#fafafa}' +
  'figure{margin:0}figcaption,.meta,.missing{font-size:.85rem;color:#666}a{color:#0b5cad}.ltr{direction:ltr;unicode-bidi:embed}';

function jsonLd(p) {
  var c = p.content;
  return {
    '@context': 'https://schema.org',
    '@type': 'Product',
    name: c.name,
    model: p.research.model,
    brand: { '@type': 'Brand', name: p.research.manufacturer },
    manufacturer: { '@type': 'Organization', name: p.research.manufacturer, url: p.research.official_domains[0] ? 'https://' + p.research.official_domains[0] : undefined },
    description: c.short_description,
    url: p.productPages.filter(function (x) { return x.official; }).concat(p.productPages)[0].url,
    image: p.saved.images.map(function (i) { return i.file; }),
    subjectOf: p.saved.videos.map(function (v) { return { '@type': 'VideoObject', name: v.title || c.name, url: v.url, embedUrl: v.url }; })
      .concat(p.saved.docs.map(function (d) { return { '@type': 'DigitalDocument', name: KIND_HE[d.kind], url: d.file, encodingFormat: 'application/pdf' }; })),
    additionalProperty: (c.specs || []).map(function (s) { return { '@type': 'PropertyValue', name: s.name, value: s.value }; }),
    inLanguage: 'he',
  };
}

function productHtml(p, forDoc) {
  var c = p.content;
  var list = function (items) { return (items || []).map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('\n'); };
  var paras = String(c.overview || '').split(/\n\s*\n|\n/).filter(function (s) { return s.trim(); })
    .map(function (s) { return '<p>' + esc(s.trim()) + '</p>'; }).join('\n');
  var specs = (c.specs || []).map(function (s) { return '<tr><th scope="row">' + esc(s.name) + '</th><td dir="auto">' + esc(s.value) + '</td></tr>'; }).join('\n');
  var videos = p.saved.videos.map(function (v) { return '<li><a href="' + esc(v.url) + '" class="ltr">' + esc(v.title || v.url) + '</a></li>'; }).join('\n');
  var images = p.saved.images.map(function (im, n) {
    return forDoc
      ? '<li class="ltr">' + esc(im.file.split('/').pop()) + ' (' + im.width + '×' + im.height + ')</li>'
      : '<figure><a href="' + esc(im.file) + '"><img src="' + esc(im.file) + '" width="' + im.width + '" height="' + im.height + '" alt="' + esc(c.name) + ' - תמונה ' + (n + 1) + '"></a><figcaption class="ltr">' + esc(im.file.split('/').pop()) + ' · ' + im.width + '×' + im.height + '</figcaption></figure>';
  }).join('\n');
  var doc = function (kind) {
    var d = p.saved.docs.filter(function (x) { return x.kind === kind; })[0];
    return d ? '<p><a href="' + esc(forDoc ? d.url : d.file) + '">' + esc(d.file) + '</a> <span class="meta">(מקור: <a href="' + esc(d.url) + '" class="ltr">' + esc(d.url) + '</a>)</span></p>' : NOT_FOUND;
  };
  var pages = p.productPages.map(function (x) {
    return '<li><a href="' + esc(x.url) + '" class="ltr">' + esc(x.url) + '</a> ' + (x.official ? '(אתר היצרן הרשמי)' : '(אתר הספק)') + '</li>';
  }).join('\n');
  return '<!doctype html>\n<html lang="he" dir="rtl">\n<head>\n<meta charset="utf-8">\n' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n' +
    '<title>' + esc(c.name) + '</title>\n<meta name="description" content="' + esc(c.short_description) + '">\n' +
    (forDoc ? '' : '<script type="application/ld+json">' + JSON.stringify(jsonLd(p), null, 1).replace(/</g, '\\u003c') + '</script>\n<style>' + PAGE_CSS + '</style>\n') +
    '</head>\n<body>\n' +
    '<article itemscope itemtype="https://schema.org/Product" data-manufacturer="' + esc(p.research.manufacturer) + '" data-model="' + esc(p.research.model) + '">\n' +
    '<header>\n<h1 id="product-name" itemprop="name">' + esc(c.name) + '</h1>\n' +
    '<p class="meta">יצרן: <span itemprop="brand">' + esc(p.research.manufacturer) + '</span> · דגם: <span class="ltr">' + esc(p.research.model) + '</span></p>\n</header>\n\n' +
    '<section id="short-description">\n<h2>תיאור קצר</h2>\n<p itemprop="description">' + esc(c.short_description) + '</p>\n</section>\n\n' +
    '<section id="full-description">\n<h2>תיאור מלא</h2>\n' +
    '<section id="overview">\n<h3>סקירה כללית</h3>\n' + paras + '\n</section>\n' +
    (c.usage && c.usage.length ? '<section id="usage">\n<h3>שימושים ואופן שימוש</h3>\n<ul>\n' + list(c.usage) + '\n</ul>\n</section>\n' : '') +
    (c.features && c.features.length ? '<section id="features">\n<h3>תכונות עיקריות</h3>\n<ul>\n' + list(c.features) + '\n</ul>\n</section>\n' : '') +
    (specs ? '<section id="specifications">\n<h3>מפרט טכני</h3>\n<table>\n<tbody>\n' + specs + '\n</tbody>\n</table>\n</section>\n' : '') +
    '</section>\n\n' +
    '<section id="videos">\n<h2>סרטוני הדגמה ב-YouTube</h2>\n' + (videos ? '<ul>\n' + videos + '\n</ul>' : NOT_FOUND) + '\n</section>\n\n' +
    '<section id="images">\n<h2>תמונות המוצר</h2>\n' + (images ? (forDoc ? '<ul>\n' + images + '\n</ul>' : '<div class="gallery">\n' + images + '\n</div>') : NOT_FOUND) + '\n</section>\n\n' +
    '<section id="brochure">\n<h2>ברושור</h2>\n' + doc('brochure') + '\n</section>\n\n' +
    '<section id="manual">\n<h2>מדריך למשתמש</h2>\n' + doc('manual') + '\n</section>\n\n' +
    '<section id="product-pages">\n<h2>קישורים לדף המוצר</h2>\n<ul>\n' + pages + '\n</ul>\n</section>\n' +
    '</article>\n</body>\n</html>\n';
}

// A readable Google Doc next to the HTML file (Drive converts the HTML). Optional: skipped if unavailable.
function saveAsGoogleDoc(folder, name, html) {
  try {
    var it = folder.getFilesByName(name);
    while (it.hasNext()) { var f = it.next(); if (!f.isTrashed()) f.setTrashed(true); }
    Drive.Files.create({ name: name, mimeType: 'application/vnd.google-apps.document', parents: [folder.getId()] },
      Utilities.newBlob(html, 'text/html', name + '.html'));
  } catch (e) {
    console.warn('Google Doc not created: ' + e.message);
  }
}

// ======================================== Main.gs ========================================
// Product scraper -> Google Drive.
// Paste product links in the "מוצרים" sheet, choose "סורק מוצרים ▸ הרץ". A 1-minute trigger then moves
// every product through these steps until its Drive folder is ready:
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
  var r = ui.prompt('מפתח API של Claude', 'הדביקו את המפתח מ-console.anthropic.com (נשמר בגיליון הזה בלבד, לא מוצג לאף אחד):', ui.ButtonSet.OK_CANCEL);
  if (r.getSelectedButton() !== ui.Button.OK) return;
  var key = r.getResponseText().trim();
  if (key) {
    PropertiesService.getScriptProperties().setProperty('ANTHROPIC_API_KEY', key);
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
  var lock = LockService.getScriptLock();
  lock.waitLock(60000);   // the worker may be running right now
  var added = 0;
  try {
    var range = sheet.getRange(2, 1, n, HEADERS.length);
    var rows = range.getValues();
    var stages = getStages();
    var stamp = Date.now().toString(36);
    rows.forEach(function (r, i) {
      var link = String(r[COL.LINK - 1]).trim();
      var status = String(r[COL.STATUS - 1]).trim();
      if (!/^https?:\/\//i.test(link) || (status && status !== STATUS.stopped && status.indexOf(STATUS.error) !== 0)) return;
      var id = 'p' + stamp + 'r' + (i + 2);
      r[COL.ID - 1] = id;
      r[COL.STATUS - 1] = STATUS.queued;
      r[COL.NOTES - 1] = '';
      saveState({ id: id, link: link, stage: 'new', writeAttempts: 0, researchAttempts: 0, researchPauses: 0, stepTries: {}, warnings: [] }, stages);
      added++;
    });
    // One write for the whole sheet (only the status, notes and id columns change).
    [COL.STATUS, COL.NOTES, COL.ID].forEach(function (c) {
      sheet.getRange(2, c, n, 1).setValues(rows.map(function (r) { return [r[c - 1]]; }));
    });
    setStages(stages);
  } finally {
    lock.releaseLock();
  }
  if (!added) {
    SpreadsheetApp.getUi().alert('אין קישורים חדשים להרצה. (שורות שכבר הושלמו לא רצות שוב; כדי להריץ שוב מוחקים את הסטטוס.)');
    return;
  }
  setTriggerEvery(1);
  SpreadsheetApp.getActive().toast(added + ' מוצרים נכנסו לתור. העבודה מתחילה תוך דקה וממשיכה ברקע - אפשר לסגור את הגיליון.', 'סורק מוצרים', 10);
}

function stopRun() {
  var lock = LockService.getScriptLock();
  lock.waitLock(60000);
  try {
    deleteTriggers();
    var settings = readSettings();
    getBatches().forEach(function (b) {   // stop paying for work that's no longer wanted
      try { claudeRequest(settings, 'post', '/v1/messages/batches/' + b.id + '/cancel'); } catch (e) {}
    });
    Object.keys(getStages()).forEach(function (id) { setRowStatus(id, STATUS.stopped); });
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
  PropertiesService.getScriptProperties().deleteProperty('TRIGGER_EVERY');
}

// Every minute while there is work to do here; every 5 minutes while only waiting for Claude
// (saves the daily trigger-time quota).
function setTriggerEvery(minutes) {
  var props = PropertiesService.getScriptProperties();
  var has = ScriptApp.getProjectTriggers().some(function (t) { return t.getHandlerFunction() === 'tick'; });
  if (has && props.getProperty('TRIGGER_EVERY') === String(minutes)) return;
  deleteTriggers();
  ScriptApp.newTrigger('tick').timeBased().everyMinutes(minutes).create();
  props.setProperty('TRIGGER_EVERY', String(minutes));
}

function ensureTrigger() { setTriggerEvery(1); }

// ---------------- State ----------------

// Where each active product is ({id: stage}), kept in Script Properties so a run can see what needs
// work without opening every product's state file.
function getStages() { return JSON.parse(getBig('STAGES') || '{}'); }
function setStages(m) { setBig('STAGES', JSON.stringify(m)); }
function getBatches() { return JSON.parse(getBig('BATCHES') || '[]'); }
function setBatches(b) { setBig('BATCHES', JSON.stringify(b)); }

// Script Properties hold at most 9KB per value: long values are split into numbered parts.
var PART_CHARS = 2500;   // Hebrew/UTF-8 safe: 2500 chars <= 9KB
function getBig(key) {
  var props = PropertiesService.getScriptProperties();
  var n = parseInt(props.getProperty(key + '_parts') || '0', 10);
  var out = '';
  for (var i = 0; i < n; i++) out += props.getProperty(key + '_' + i) || '';
  return out;
}
function setBig(key, value) {
  var props = PropertiesService.getScriptProperties();
  var old = parseInt(props.getProperty(key + '_parts') || '0', 10);
  var n = Math.ceil(value.length / PART_CHARS);
  for (var i = 0; i < n; i++) props.setProperty(key + '_' + i, value.slice(i * PART_CHARS, (i + 1) * PART_CHARS));
  for (var j = n; j < old; j++) props.deleteProperty(key + '_' + j);
  props.setProperty(key + '_parts', String(n));
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

function findRow(id) {
  var sheet = SpreadsheetApp.getActive().getSheetByName(SHEET_PRODUCTS);
  var n = sheet.getLastRow() - 1;
  if (n < 1) return 0;
  var ids = sheet.getRange(2, COL.ID, n, 1).getValues();
  for (var i = 0; i < ids.length; i++) if (ids[i][0] === id) return i + 2;
  return 0;
}

// Text from websites/Claude starting with = + - @ would become a formula.
function asText(v) {
  v = String(v === undefined || v === null ? '' : v);
  return /^[=+\-@]/.test(v) ? "'" + v : v;
}

function setRowStatus(id, status, extra) {
  var row = findRow(id);
  if (!row) return;
  var sheet = SpreadsheetApp.getActive().getSheetByName(SHEET_PRODUCTS);
  sheet.getRange(row, COL.STATUS).setValue(status);
  extra = extra || {};
  if (extra.name !== undefined) sheet.getRange(row, COL.NAME).setValue(asText(extra.name));
  if (extra.manufacturer !== undefined) sheet.getRange(row, COL.MANUFACTURER).setValue(asText(extra.manufacturer));
  if (extra.folderUrl) sheet.getRange(row, COL.FOLDER).setFormula('=HYPERLINK("' + extra.folderUrl + '","פתח תיקייה")');
  if (extra.notes !== undefined) sheet.getRange(row, COL.NOTES).setValue(asText(extra.notes));
}

// ---------------- The worker (runs every minute until everything is done) ----------------

var DEADLINE = 0;
function timeLeft() { return DEADLINE - Date.now(); }

function tick() {
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(1000)) return;
  DEADLINE = Date.now() + TICK_BUDGET_MS;
  try {
    var settings = readSettings();
    pollBatches(settings);
    recoverLostWaits();
    // Take every product as far as it can go in this run - all products together, stage after stage.
    for (var round = 0; round < 10 && timeLeft() > 45000; round++) {
      var moved = runLocalStage(settings, 'new');
      if (settings.fast) moved = runClaudeNow(settings, 'research') || moved;
      moved = runLocalStage(settings, 'official') || moved;
      if (settings.fast) moved = runClaudeNow(settings, 'write') || moved;
      moved = runLocalStage(settings, 'save') || moved;
      if (!moved) break;
    }
    submitBatches(settings, 'research');
    submitBatches(settings, 'write');
    var left = getStages();
    var busy = Object.keys(left).some(function (id) { return !/_wait$/.test(left[id]); });
    if (Object.keys(left).length) setTriggerEvery(busy ? 1 : 5);
    finishIfDone(settings);
  } finally {
    lock.releaseLock();
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
    replaceFile(folder, name, blob.setContentType('application/pdf'));
    saved.docs.push({ kind: pair[0], file: name, url: d.url });
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

  replaceFile(folder, stem + '.html', Utilities.newBlob(productHtml(p, false), 'text/html', stem + '.html'));
  saveAsGoogleDoc(folder, stem + ' - תיאור', productHtml(p, true));
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
  var ss = SpreadsheetApp.getActive();
  try {
    MailApp.sendEmail(Session.getEffectiveUser().getEmail(), 'סורק מוצרים: הסריקה הסתיימה',
      'כל המוצרים עובדו. הסטטוסים והקישורים לתיקיות בגיליון:\n' + ss.getUrl() + '\n\nהתיקייה בדרייב: ' + rootFolder(settings).getUrl());
  } catch (e) {
    console.warn('email not sent: ' + e.message);
  }
}
