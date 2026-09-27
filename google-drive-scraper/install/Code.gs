// סורק מוצרים ל-Google Drive - כל הקוד בקובץ אחד.
// מדביקים את כל הקובץ הזה ב-Code.gs בעורך של Apps Script. הוראות: README.md

// ======================================== Settings.gs ========================================
// Default settings. They can be changed in the app's settings screen (saved in User Properties).

var SHORT_MAX_WORDS = 80;
var FULL_MAX_WORDS = 500;

var DEFAULT_SETTINGS = [
  ['אתר', 'https://www.ndt24.co.il', 'כתובת האתר שלכם. המערכת קוראת ממנו את רשימת קטגוריות המוצרים'],
  ['להעלות לאתר', 'כן', 'כן = כל מוצר נכנס לאתר כטיוטה (אחרי שמחברים את האתר). לא = רק לדרייב'],
  ['שדה קטלוג pdf', '', 'השם הפנימי של השדה "קטלוג pdf" באתר (מתמלא לבד כשמחברים את האתר)'],
  ['שדה ספר הוראות', '', 'השם הפנימי של השדה "ספר הוראות" באתר'],
  ['שדה וידאו מוצר', '', 'השם הפנימי של השדה "וידאו מוצר" באתר'],
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
  var map = settingsMap();
  var publish = map['להעלות לאתר'] !== 'לא';
  SETTINGS_MEMO = {
    site: /^https?:\/\//.test(map['אתר']) ? map['אתר'] : '',
    siteUser: PropertiesService.getUserProperties().getProperty('SITE_USER') || '',
    sitePass: PropertiesService.getUserProperties().getProperty('SITE_PASS') || '',
    fieldCatalog: map['שדה קטלוג pdf'] || '',
    fieldManual: map['שדה ספר הוראות'] || '',
    fieldVideo: map['שדה וידאו מוצר'] || '',
    rootFolder: map['תיקייה בדרייב'],
    model: map['מודל'],
    email: map['שליחת מייל בסיום'] !== 'לא',
    fast: map['מצב מהיר'] !== 'לא',
    styleUrls: map['דפי דוגמה לסגנון'].split(/\s+/).filter(function (u) { return /^https?:\/\//.test(u); }),
    glossary: map['מילון מונחים'],
    avoidWords: String(map['מילים שלא משתמשים בהן'] || '').split('\n').map(function (w) { return w.trim(); }).filter(String),
    // Everything is kept per Google user: each person who opens the app has their own key, list and Drive folders.
    apiKey: PropertiesService.getUserProperties().getProperty('ANTHROPIC_API_KEY') || '',
    apiBase: PropertiesService.getUserProperties().getProperty('ANTHROPIC_API_BASE') || 'https://api.anthropic.com',
  };
  SETTINGS_MEMO.publish = publish && !!(SETTINGS_MEMO.site && SETTINGS_MEMO.siteUser && SETTINGS_MEMO.sitePass);
  return SETTINGS_MEMO;
}

// Defaults with the user's changes on top: {label: value}.
function settingsMap() {
  var map = {};
  DEFAULT_SETTINGS.forEach(function (row) { map[row[0]] = row[1]; });
  var saved = {};
  try { saved = JSON.parse(getBig('SETTINGS') || '{}'); } catch (e) {}
  Object.keys(saved).forEach(function (k) {
    if (map.hasOwnProperty(k) && String(saved[k]).trim() !== '') map[k] = String(saved[k]).trim();
  });
  return map;
}

// Saves only values that differ from the defaults, so improved defaults still reach old installs.
function saveSettings(values) {
  var out = {};
  DEFAULT_SETTINGS.forEach(function (row) {
    var v = values[row[0]];
    if (v === undefined || v === null) return;
    v = String(v).replace(/\r/g, '').trim();
    if (v !== '' && v !== String(row[1]).trim()) out[row[0]] = v;
  });
  setBig('SETTINGS', JSON.stringify(out));
  SETTINGS_MEMO = null;
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
    var err = new Error('Claude API ' + code + ': ' + msg + (code === 401 ? ' (מפתח ה-API לא תקין - מחליפים אותו בהגדרות)' : ''));
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
      (code === 401 ? ' (מפתח ה-API לא תקין - מחליפים אותו בהגדרות)' : '');
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

// The fields of the site's "add product" screen (WooCommerce + Yoast), plus the files to keep.
var WRITE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['name', 'short_description', 'description_paragraphs', 'usage', 'specs', 'category', 'tags', 'focus_keyphrase', 'seo_title', 'meta_description', 'slug',
    'image_indexes', 'brochure_index', 'manual_index', 'video_indexes'],
  properties: {
    name: { type: 'string', description: "Hebrew product title in the house style, e.g. 'מצלמה תרמית לסמארטפון 320X240 פיקסלים Fotric TP320A'" },
    short_description: { type: 'string', description: 'Hebrew, one paragraph, at most ' + SHORT_MAX_WORDS + ' words (usually 45-65): what it is and how it works, who it is for, one standout advantage' },
    description_paragraphs: { type: 'array', items: { type: 'string' }, description: 'the full description: 2-4 Hebrew paragraphs of running text (no headings, no lists)' },
    usage: { type: 'array', items: { type: 'string' }, description: 'Hebrew bullet list of applications (4-8 short lines), shown after the paragraphs' },
    specs: {
      type: 'array',
      description: 'key technical specifications for internal reference (not shown on the site - the full spec is in the catalog PDF); Hebrew labels, values as in the source',
      items: { type: 'object', additionalProperties: false, required: ['name', 'value'], properties: { name: { type: 'string' }, value: { type: 'string' } } },
    },
    category: { type: 'string', description: 'exactly one name from <site_categories> that fits this product, or "" if none fits / no list' },
    tags: { type: 'array', items: { type: 'string' }, description: '3-6 short Hebrew product tags (product type, use, brand)' },
    focus_keyphrase: { type: 'string', description: 'Yoast focus keyphrase: what a customer in Israel would search for, e.g. "מצלמה תרמית לסמארטפון"' },
    seo_title: { type: 'string', description: 'Hebrew SEO title, up to 60 characters, contains the focus keyphrase' },
    meta_description: { type: 'string', description: 'Hebrew meta description, 120-155 characters, contains the focus keyphrase' },
    slug: { type: 'string', description: 'URL slug: lowercase English words and digits joined with hyphens, e.g. "fotric-tp320a-smartphone-thermal-camera"' },
    image_indexes: { type: 'array', items: { type: 'integer' }, description: 'indexes of up to 8 photos of THIS product, best first (the first is the main product image; the first 3-5 high-resolution ones are kept). No logos, icons, banners, certificates, other products or accessories' },
    brochure_index: { type: 'integer', description: 'index of the PDF that is this product\'s brochure / datasheet / catalogue, or -1' },
    manual_index: { type: 'integer', description: 'index of the PDF that is this product\'s user manual, or -1' },
    video_indexes: { type: 'array', items: { type: 'integer' }, description: 'indexes of YouTube videos that demonstrate THIS product, best first' },
  },
};

// How a product page on the site is built (a real page, shortened), so Claude writes to the same structure.
var PAGE_STRUCTURE_EXAMPLE =
  'name: מצלמה תרמית לסמארטפון 320X240 פיקסלים Fotric TP320A\n\n' +
  'short_description: מצלמה תרמית קטנה שמתחברת ישירות לחיבור USB-C בטלפון אנדרואיד והופכת אותו למצלמת אינפרה אדום מקצועית תוך שניות, בלי סוללה ובלי זמן אתחול. מתאימה לחשמלאים, טכנאי מיזוג ובודקי בתים שצריכים לאתר נקודות חום בלוחות חשמל, מנועים ומערכות מיזוג. תומכת בתוכנת AnalyzIR לניתוח מתקדם במחשב וביצירת דוחות.\n\n' +
  'description_paragraphs:\n' +
  '1. Fotric TP320A היא מצלמה תרמית פלאג-אנד-פליי שמתחברת ישירות לחיבור USB-C בטלפון אנדרואיד והופכת אותו למצלמת אינפרה אדום מלאה תוך שניות. אין צורך בסוללה נפרדת, בזמן אתחול או בהגדרות מסובכות - מחברים את המצלמה, פותחים את אפליקציית FOTRIC Genie ומתחילים לסרוק.\n' +
  '2. המצלמה מבוססת על חיישן ברזולוציה 320X240 פיקסלים עם רזולוציית-על (Super Resolution) שמגיעה עד 640X480 פיקסלים, ורגישות תרמית (NETD) גבוהה של פחות מ-35mK. השילוב מאפשר לזהות הפרשי טמפרטורה קטנים מאוד בלוחות חשמל, מנועים ומערכות מיזוג אוויר. טווח מדידת הטמפרטורה הרחב - מ-20°C- עד 550°C - מתאים גם לעבודות תעשייתיות וגם לבדיקות ביתיות.\n' +
  '3. הגוף קומפקטי מאוד, במשקל 40 גרם בלבד ובמידות 71X33X15.5 מ"מ, ונכנס בקלות לכיס, לתיק כלים או לתרמיל. דרגת אטימות IP40 ועמידות בנפילה מגובה מטר הופכות אותה למכשיר שעומד גם בתנאי שטח.\n\n' +
  'usage:\n- בדיקת לוחות חשמל ואיתור נקודות חמות לפני שהופכות לתקלה\n- מעקב אחרי טמפרטורת מנועים וציוד מכני\n- אבחון מערכות מיזוג ואוורור (HVAC) ובדיקת פתחי אוויר\n- ביקורות אנרגיה בבתים ואיתור בעיות בידוד';

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
    '- short_description: פסקה אחת, עד ' + SHORT_MAX_WORDS + ' מילים (בדרך כלל 45-65): מה המוצר ואיך הוא עובד, למי הוא מתאים, ויתרון בולט אחד.\n' +
    '- התיאור המלא בנוי כמו בדפים באתר: description_paragraphs = 2-4 פסקאות טקסט רציף (בלי כותרות ובלי רשימות), ואחריהן usage = רשימת שימושים קצרה. הנתונים הטכניים החשובים (רזולוציה, רגישות, טווחים, מידות, משקל, אטימות) משולבים בתוך המשפטים. ביחד עד ' + FULL_MAX_WORDS + ' מילים. אין טבלת מפרט בדף - המפרט המלא נמצא בקטלוג ה-PDF; specs הוא רק רשימה פנימית לעיון.\n' +
    '- פסקה 1: מה המוצר ואיך מתחילים לעבוד איתו. פסקה 2: הנתונים הטכניים המרכזיים ומה הם נותנים בעבודה. פסקה 3: גוף, משקל, עמידות, אביזרים ותוכנה (רק מה שמופיע במקור).\n' +
    '- שדות SEO (Yoast): focus_keyphrase = מה שלקוח בישראל היה מחפש בגוגל; seo_title עד 60 תווים; meta_description עד 155 תווים; שניהם כוללים את ביטוי המפתח ונשמעים טבעי. slug באנגלית, באותיות קטנות ומקפים.\n' +
    '- category: בוחרים בדיוק שם אחד מתוך <site_categories>. tags: 3-6 תגיות קצרות בעברית.\n\n' +
    '<page_structure_example>\n' + PAGE_STRUCTURE_EXAMPLE + '\n</page_structure_example>\n\n' +
    'עובדות:\n' +
    '- רק עובדות שמופיעות בחומר המקור. אסור להמציא נתונים, מספרים, תקנים, אחריות או טענות. מה שלא מופיע - לא נכתב.\n' +
    '- כשיש סתירה, עדיף המידע מאתר היצרן הרשמי ומהברושור שלו.\n' +
    '- בלי מחירים, בלי פרטי התקשרות, בלי סופרלטיבים שלא מופיעים במקור.\n\n' +
    'לפני שמחזירים תשובה: קוראים שוב כל משפט בעברית. משפט שנשמע מתורגם, מסורבל או לא כמו שאומרים בענף - כותבים מחדש.\n\n' +
    'בחירת קבצים: בוחרים רק מתוך הרשימות הממוספרות (כולן מאתר היצרן הרשמי). אם אין פריט מתאים - רשימה ריקה או -1.\n\n' +
    '<glossary>\n' + settings.glossary + '\n</glossary>\n\n<avoid_words>\n' + (settings.avoidWords || []).join('\n') + '\n</avoid_words>\n\n<site_categories>\n' + (siteCategories(settings).join('\n') || '(no list - leave category empty)') + '\n</site_categories>\n\n<style_examples>\n' + (examples || '(no examples)') + '\n</style_examples>';
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
  var ask = 'כתוב/י את דף המוצר ובחר/י את התמונות, הקבצים והסרטונים.';
  if (p.revision) {   // the user asked to fix a finished product
    ask = '<previous_version>\n' + JSON.stringify(p.revision.previous) + '\n</previous_version>\n\n' +
      '<requested_changes>\n' + p.revision.note + '\n</requested_changes>\n\n' +
      'זו גרסה שכבר נכתבה למוצר. עדכן/י אותה לפי הבקשה, ושמור/י על כל השאר כמו שהוא (גם על בחירת התמונות, הקבצים והסרטונים, אלא אם הבקשה היא לשנות אותם). ' +
      'גם בתיקון כותבים רק עובדות שמופיעות במקורות. אם הבקשה דורשת עובדה שלא מופיעה במקורות, לא ממציאים אותה.';
  }
  content.push({ type: 'text', text: '<sources>\n' + sources + '\n</sources>\n\n' + lists + '\n\n' + ask + (feedback || '') });
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

// The full description on the site: the paragraphs and the list of uses.
function descriptionParts(c) {
  return (c.description_paragraphs || []).concat(c.usage || []);
}

function validateContent(c, avoidWords) {
  var problems = [];
  ['name', 'short_description'].forEach(function (k) { if (!String(c[k] || '').trim()) problems.push('missing ' + k); });
  if (!(c.description_paragraphs || []).some(function (x) { return String(x).trim(); })) problems.push('missing description_paragraphs');
  var s = wordCount(c.short_description);
  if (s > SHORT_MAX_WORDS) problems.push('short_description has ' + s + ' words (max ' + SHORT_MAX_WORDS + ')');
  var f = descriptionParts(c).reduce(function (n, x) { return n + wordCount(x); }, 0);
  if (f > FULL_MAX_WORDS) problems.push('full description (description_paragraphs + usage) has ' + f + ' words (max ' + FULL_MAX_WORDS + ')');
  if (!/[\u0590-\u05FF]/.test(String(c.short_description) + (c.description_paragraphs || []).join(' '))) problems.push('texts are not in Hebrew');
  if (String(c.seo_title || '').length > 80) problems.push('seo_title has ' + String(c.seo_title).length + ' characters (max 60)');
  if (String(c.meta_description || '').length > 200) problems.push('meta_description has ' + String(c.meta_description).length + ' characters (max 155)');
  var all = [c.name, c.short_description, c.seo_title, c.meta_description].concat(descriptionParts(c), c.tags || []).join('\n');
  var used = (avoidWords || []).filter(function (w) { return containsWord(all, w); });
  if (used.length) problems.push('uses words from <avoid_words>: ' + used.join(', ') + ' - rewrite those sentences');
  return problems;
}

// Small things fixed without asking Claude again.
function tidyContent(c, categories) {
  c.slug = String(c.slug || '').toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);
  c.tags = (c.tags || []).map(function (t) { return String(t).trim(); }).filter(String).slice(0, 8);
  if (categories && categories.length && categories.indexOf(c.category) < 0) c.category = '';
  return c;
}

// ======================================== Output.gs ========================================
// Output: one Drive folder per product with a CSV table (the site's product fields, links and notes),
// 3-5 images in "תמונות", the brochure and the user manual; plus one CSV of all products in the main folder.

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
    category: c.category || undefined,
    keywords: (c.tags || []).join(', ') || undefined,
    url: p.productPages.filter(function (x) { return x.official; }).concat(p.productPages)[0].url,
    image: p.saved.images.map(function (i) { return i.file; }),
    subjectOf: p.saved.videos.map(function (v) { return { '@type': 'VideoObject', name: v.title || c.name, url: v.url, embedUrl: v.url }; })
      .concat(p.saved.docs.map(function (d) { return { '@type': 'DigitalDocument', name: KIND_HE[d.kind], url: d.file, encodingFormat: 'application/pdf' }; })),
    additionalProperty: (c.specs || []).map(function (s) { return { '@type': 'PropertyValue', name: s.name, value: s.value }; }),
    inLanguage: 'he',
  };
}

function productHtml(p) {
  var c = p.content;
  var list = function (items) { return (items || []).map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('\n'); };
  var paras = (c.description_paragraphs || []).filter(function (x) { return String(x).trim(); }).map(function (x) { return '<p>' + esc(String(x).trim()) + '</p>'; }).join('\n');
  var specs = (c.specs || []).map(function (s) { return '<tr><th scope="row">' + esc(s.name) + '</th><td dir="auto">' + esc(s.value) + '</td></tr>'; }).join('\n');
  var videos = p.saved.videos.map(function (v) { return '<li><a href="' + esc(v.url) + '" class="ltr">' + esc(v.title || v.url) + '</a></li>'; }).join('\n');
  var images = p.saved.images.map(function (im, n) {
    return '<figure><a href="' + esc(im.file) + '"><img src="' + esc(im.file) + '" width="' + im.width + '" height="' + im.height + '" alt="' + esc(c.name) + ' - תמונה ' + (n + 1) + '"></a><figcaption class="ltr">' + esc(im.file.split('/').pop()) + ' · ' + im.width + '×' + im.height + '</figcaption></figure>';
  }).join('\n');
  var doc = function (kind) {
    var d = p.saved.docs.filter(function (x) { return x.kind === kind; })[0];
    return d ? '<p><a href="' + esc(d.file) + '">' + esc(d.file) + '</a> <span class="meta">(מקור: <a href="' + esc(d.url) + '" class="ltr">' + esc(d.url) + '</a>)</span></p>' : NOT_FOUND;
  };
  var pages = p.productPages.map(function (x) {
    return '<li><a href="' + esc(x.url) + '" class="ltr">' + esc(x.url) + '</a> ' + (x.official ? '(אתר היצרן הרשמי)' : '(אתר הספק)') + '</li>';
  }).join('\n');
  return '<!doctype html>\n<html lang="he" dir="rtl">\n<head>\n<meta charset="utf-8">\n' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n' +
    '<title>' + esc(c.seo_title || c.name) + '</title>\n<meta name="description" content="' + esc(c.meta_description || c.short_description) + '">\n' +
    '<meta name="keywords" content="' + esc([c.focus_keyphrase].concat(c.tags || []).filter(String).join(', ')) + '">\n' +
    '<script type="application/ld+json">' + JSON.stringify(jsonLd(p), null, 1).replace(/</g, '\\u003c') + '</script>\n<style>' + PAGE_CSS + '</style>\n' +
    '</head>\n<body>\n' +
    '<article itemscope itemtype="https://schema.org/Product" data-manufacturer="' + esc(p.research.manufacturer) + '" data-model="' + esc(p.research.model) + '">\n' +
    '<header>\n<h1 id="product-name" itemprop="name">' + esc(c.name) + '</h1>\n' +
    '<p class="meta">יצרן: <span itemprop="brand">' + esc(p.research.manufacturer) + '</span> · דגם: <span class="ltr">' + esc(p.research.model) + '</span></p>\n</header>\n\n' +
    '<section id="short-description">\n<h2>תיאור קצר</h2>\n<p itemprop="description">' + esc(c.short_description) + '</p>\n</section>\n\n' +
    '<section id="full-description">\n<h2>תיאור מלא</h2>\n' +
    '<section id="overview">\n' + paras + '\n</section>\n' +
    (c.usage && c.usage.length ? '<section id="usage">\n<h3>שימושים</h3>\n<ul>\n' + list(c.usage) + '\n</ul>\n</section>\n' : '') +
    (specs ? '<section id="specifications">\n<h3>מפרט טכני</h3>\n<table>\n<tbody>\n' + specs + '\n</tbody>\n</table>\n</section>\n' : '') +
    '</section>\n\n' +
    '<section id="videos">\n<h2>סרטוני הדגמה ב-YouTube</h2>\n' + (videos ? '<ul>\n' + videos + '\n</ul>' : NOT_FOUND) + '\n</section>\n\n' +
    '<section id="images">\n<h2>תמונות המוצר</h2>\n' + (images ? '<div class="gallery">\n' + images + '\n</div>' : NOT_FOUND) + '\n</section>\n\n' +
    '<section id="brochure">\n<h2>ברושור</h2>\n' + doc('brochure') + '\n</section>\n\n' +
    '<section id="manual">\n<h2>מדריך למשתמש</h2>\n' + doc('manual') + '\n</section>\n\n' +
    '<section id="product-pages">\n<h2>קישורים לדף המוצר</h2>\n<ul>\n' + pages + '\n</ul>\n</section>\n' +
    '</article>\n</body>\n</html>\n';
}

// ---------- CSV (opens in Excel and Google Sheets) ----------

var ALL_PRODUCTS_CSV = 'כל המוצרים.csv';
// In the order of the site's "add product" screen, then extra columns for reference.
var CSV_HEADERS = ['שם מוצר', 'תיאור המוצר (HTML)', 'תיאור קצר של המוצר', 'תמונת מוצר', 'גלריית תמונות מוצר', 'קטגוריה', 'תגיות', 'מותג',
  'ביטוי מפתח (Yoast)', 'כותרת SEO', 'סלאג', 'תיאור מטא', 'קטלוג pdf', 'ספר הוראות', 'וידאו מוצר',
  'מזהה', 'דגם', 'מפרט טכני (לעיון)', 'סרטונים נוספים', 'ברושור (בדרייב)', 'מדריך למשתמש (בדרייב)',
  'דף המוצר באתר היצרן', 'דף המוצר באתר הספק', 'תיקייה בדרייב', 'הערות', 'דף מלא ל-LLM (HTML)'];
var CSV_ID = CSV_HEADERS.indexOf('מזהה');
var CSV_CELL_MAX = 32000;   // Excel's limit per cell is 32,767 characters

// "תיאור המוצר" on the site: paragraphs, then the list of uses. Paste it in the editor's Code tab.
function siteDescriptionHtml(c) {
  var paras = (c.description_paragraphs || []).map(function (x) { return String(x).trim(); }).filter(String).map(function (x) { return '<p>' + esc(x) + '</p>'; });
  var uses = (c.usage || []).map(function (x) { return String(x).trim(); }).filter(String);
  return paras.join('\n') + (uses.length ? '\n<ul>\n' + uses.map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('\n') + '\n</ul>' : '');
}

// One product as a table row, in the order of CSV_HEADERS.
function productRow(p, stem, folderUrl) {
  var c = p.content;
  var doc = function (kind, key) { var d = p.saved.docs.filter(function (x) { return x.kind === kind; })[0]; return d ? d[key] || '' : ''; };
  var page = function (official) { return p.productPages.filter(function (x) { return !!x.official === official; }).map(function (x) { return x.url; }).join('\n'); };
  var imgs = p.saved.images.map(function (im) { return im.file.split('/').pop(); });
  var html = productHtml(p);
  if (html.length > CSV_CELL_MAX) html = html.replace(/<script type="application\/ld\+json">[\s\S]*?<\/script>\n/, '').replace(/<style>[\s\S]*?<\/style>\n/, '');
  return [
    c.name, siteDescriptionHtml(c), c.short_description, imgs[0] || '', imgs.slice(1).join(', '), c.category || '', (c.tags || []).join(', '),
    p.research.manufacturer, c.focus_keyphrase || '', c.seo_title || '', c.slug || '', c.meta_description || '',
    doc('brochure', 'url'), doc('manual', 'url'), (p.saved.videos[0] || {}).url || '',
    stem, p.research.model, (c.specs || []).map(function (x) { return x.name + ': ' + x.value; }).join('\n'),
    p.saved.videos.slice(1).map(function (v) { return v.url; }).join('\n'),
    doc('brochure', 'driveUrl'), doc('manual', 'driveUrl'),
    page(true), page(false), folderUrl, p.warnings.join('\n'), html,
  ];
}

function csvCell(v) {
  v = String(v === undefined || v === null ? '' : v).replace(/\r\n?/g, '\n');
  if (v.length > CSV_CELL_MAX) v = v.slice(0, CSV_CELL_MAX);
  if (/^[=+@]|^-[^\d.]/.test(v)) v = "'" + v;   // Excel would run it as a formula
  return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
}

// With a BOM, so Excel shows the Hebrew correctly.
function toCsv(rows) {
  return '﻿' + rows.map(function (r) { return r.map(csvCell).join(','); }).join('\r\n') + '\r\n';
}

function parseCsv(text) {
  text = String(text || '').replace(/^﻿/, '');
  var rows = [], row = [], cell = '', q = false;
  for (var i = 0; i < text.length; i++) {
    var ch = text[i];
    if (q) {
      if (ch === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (ch === '"') q = false;
      else cell += ch;
    } else if (ch === '"') q = true;
    else if (ch === ',') { row.push(cell); cell = ''; }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(cell); rows.push(row); row = []; cell = '';
    } else cell += ch;
  }
  if (cell !== '' || row.length) { row.push(cell); rows.push(row); }
  return rows;
}

function csvBlob(rows, name) {
  return Utilities.newBlob(toCsv(rows), 'text/csv', name);
}

// The main folder's table: one row per product, a product that runs again replaces its row.
function updateAllProductsCsv(root, row) {
  var file = firstLive(root.getFilesByName(ALL_PRODUCTS_CSV));
  var old = file ? parseCsv(file.getBlob().getDataAsString('UTF-8')) : [];
  // Rows written by an older version (other columns) are moved to the current columns by name.
  var at = (old[0] || []).map(function (h) { return { 'שם המוצר': 'שם מוצר', 'תיאור קצר': 'תיאור קצר של המוצר', 'יצרן': 'מותג', 'HTML': 'דף מלא ל-LLM (HTML)' }[h] || h; });
  var rows = old.slice(1).map(function (r) {
    return CSV_HEADERS.map(function (h) { var k = at.indexOf(h); return k < 0 ? '' : r[k] || ''; });
  });
  rows = rows.filter(function (r) { return r[CSV_ID] !== row[CSV_ID]; });
  rows.push(row);
  var content = toCsv([CSV_HEADERS].concat(rows));
  if (file) return file.setContent(content);
  return root.createFile(Utilities.newBlob(content, 'text/csv', ALL_PRODUCTS_CSV));
}

// ======================================== Main.gs ========================================
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
  publish: 'מעלה לאתר…',
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
    if (!Object.keys(stages).length) startNewRun();
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
  ['name', 'manufacturer', 'folderUrl', 'notes', 'cost', 'dataId', 'siteUrl'].forEach(function (k) { if (extra[k] !== undefined) it[k] = String(extra[k]).slice(0, 600); });
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
      moved = runLocalStage(settings, 'publish') || moved;
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
var LOCAL_GROUP = { new: 10, official: 5, save: 3, publish: 2 };

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
        addCost(p, a.result, false);
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
    else if (p.stage === 'publish') stepPublish(settings, p);
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
  var root = null;
  var folder = null;
  if (p.folderId) {   // a text fix: save into the product's folder, even if the main folder setting changed since
    try {
      folder = DriveApp.getFolderById(p.folderId);
      var parents = folder.getParents();
      root = !folder.isTrashed() && parents.hasNext() ? parents.next() : null;
    } catch (e) {}
    if (!root) folder = null;
  }
  if (!folder) {
    root = rootFolder(settings);
    var it = root.getFolders();   // re-running a product updates its existing folder
    while (it.hasNext() && !folder) {
      var f = it.next();
      if (!f.isTrashed() && (f.getName() === stem || f.getName().indexOf(stem + ' - ') === 0)) folder = f;
    }
    folder = folder || root.createFolder(stem);
  }

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
  var table = updateAllProductsCsv(root, row);
  folder.setName(stem + ' - ' + c.name);
  PropertiesService.getUserProperties().setProperty('RUN_FOLDER', JSON.stringify({ name: root.getName(), url: root.getUrl(), tableUrl: table.getUrl() }));

  p.folderUrl = folder.getUrl();
  p.folderId = folder.getId();
  p.revision = null;
  p.publishTries = 0;
  if (settings.publish) {
    p.stage = 'publish';
    setRowStatus(p.id, STATUS.publish, { name: c.name, manufacturer: p.research.manufacturer, folderUrl: p.folderUrl });
    return;
  }
  finishProduct(p);
}

// Done: keep what a later text fix needs, and show the product as ready.
function finishProduct(p) {
  p.stage = 'done';
  var dataId = saveProductData(p);
  setRowStatus(p.id, p.warnings.length ? STATUS.doneNotes : STATUS.done, {
    name: p.content.name, manufacturer: p.research.manufacturer, folderUrl: p.folderUrl, notes: p.warnings.join(' · '),
    cost: (p.cost || 0).toFixed(2), dataId: dataId, siteUrl: p.siteUrl || '',
  });
}

// ---------------- Fixing a finished product's text ----------------

var DATA_FOLDER = '_סורק מוצרים - נתונים (לא למחוק)';

// Everything Claude needs to rewrite a product later, kept outside the product folders.
function saveProductData(p) {
  try {
    var folder = firstLive(DriveApp.getFoldersByName(DATA_FOLDER)) || DriveApp.createFolder(DATA_FOLDER);
    var json = JSON.stringify(p);
    var file = firstLive(folder.getFilesByName(p.id + '.json'));
    if (file) file.setContent(json);
    else file = folder.createFile(p.id + '.json', json, 'application/json');
    return file.getId();
  } catch (e) {
    console.warn('product data not saved: ' + e.message);
    return '';
  }
}

// Sends a finished product back to Claude with the user's request; the save step then updates its folder and tables.
function reviseProduct(id, note) {
  var lock = LockService.getUserLock();
  lock.waitLock(60000);
  try {
    var it = getItems().filter(function (x) { return x.id === id; })[0];
    if (!it || !it.dataId) return 'אי אפשר לתקן את המוצר הזה. סורקים אותו מחדש.';
    var stages = getStages();
    if (stages[id]) return 'המוצר עדיין בעבודה.';
    var p;
    try { p = JSON.parse(DriveApp.getFileById(it.dataId).getBlob().getDataAsString('UTF-8')); } catch (e) { return 'לא מצאתי את הנתונים של המוצר. סורקים אותו מחדש.'; }
    if (!Object.keys(stages).length) startNewRun();
    p.revision = { note: note, previous: p.content };
    p.stage = 'write_pending';
    p.writeAttempts = 0;
    p.stepTries = {};
    p.nowErrors = 0;
    p.useBatch = null;
    p.cost = 0;
    delete p.batchId;
    saveState(p, stages);
    setStages(stages);
    setRowStatus(id, STATUS.write, { notes: '' });
    flushItems();
  } finally {
    lock.releaseLock();
  }
  setTriggerEvery(1);
  return '';
}

// ---------------- Cost ----------------

// USD per million tokens (standard API prices); batch jobs cost half. Web search: $10 per 1,000 searches.
var PRICES = { 'claude-sonnet-5': [2, 10], 'claude-opus-5': [5, 25] };

function addCost(p, result, batch) {
  var u = result && result.type === 'succeeded' && result.message && result.message.usage;
  if (!u) return;
  var price = PRICES[readSettings().model] || PRICES['claude-sonnet-5'];
  var tokens = (u.input_tokens || 0) + 1.25 * (u.cache_creation_input_tokens || 0) + 0.1 * (u.cache_read_input_tokens || 0);
  var usd = (tokens * price[0] + (u.output_tokens || 0) * price[1]) / 1e6 * (batch ? 0.5 : 1);
  usd += ((u.server_tool_use && u.server_tool_use.web_search_requests) || 0) * 0.01;
  p.cost = (p.cost || 0) + usd;
  var props = PropertiesService.getUserProperties();
  props.setProperty('RUN_COST', String((parseFloat(props.getProperty('RUN_COST') || '0') || 0) + usd));
}

// A new run: the cost counter and the "run folder" button start over.
function startNewRun() {
  var props = PropertiesService.getUserProperties();
  props.setProperty('RUN_COST', '0');
  props.deleteProperty('RUN_FOLDER');
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

// The product categories that exist on the site (WooCommerce's public Store API), so Claude picks one of them.
var CATEGORIES_MEMO = null;
function siteCategoryList(settings) {
  if (CATEGORIES_MEMO) return CATEGORIES_MEMO;
  CATEGORIES_MEMO = [];
  if (!settings.site) return CATEGORIES_MEMO;
  var cache = CacheService.getScriptCache();
  var key = 'cats2_' + Utilities.base64Encode(Utilities.computeDigest(Utilities.DigestAlgorithm.MD5, settings.site));
  var hit = cache.get(key);
  if (hit) return (CATEGORIES_MEMO = JSON.parse(hit));
  try {
    var r = UrlFetchApp.fetch(settings.site.replace(/\/+$/, '') + '/wp-json/wc/store/v1/products/categories?per_page=100', { muteHttpExceptions: true });
    if (r.getResponseCode() === 200) {
      CATEGORIES_MEMO = JSON.parse(r.getContentText()).map(function (x) { return { id: x.id, name: decodeEntities(String(x.name || '')).trim() }; })
        .filter(function (x) { return x.name; });
      cache.put(key, JSON.stringify(CATEGORIES_MEMO), 21600);
    }
  } catch (e) {
    console.warn('categories not read: ' + e.message);
  }
  return CATEGORIES_MEMO;
}

function siteCategories(settings) {
  return siteCategoryList(settings).map(function (x) { return x.name; });
}

function siteCategoryId(settings, name) {
  var hit = siteCategoryList(settings).filter(function (x) { return x.name === name; })[0];
  return hit ? hit.id : null;
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
        addCost(p, byId[p.id], true);
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
  tidyContent(content, siteCategories(readSettings()));
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

// ======================================== Site.gs ========================================
// Feeding the site: each finished product is created on the WooCommerce site as a DRAFT with all its fields
// (texts, images, category, tags, brand, Yoast SEO, catalog / manual / video fields), ready for a final look
// and "פרסום". Signs in with a WordPress application password (Users → Profile → Application Passwords).

var SITE_TIMEOUT_TRIES = 3;

function siteAuthHeader(settings) {
  return 'Basic ' + Utilities.base64Encode(settings.siteUser + ':' + settings.sitePass);
}

// A request to the site's REST API (/wp-json/...). Returns the parsed JSON; throws an Error with .status on failure.
function siteRequest(settings, method, path, body, extra) {
  var opts = {
    method: method, muteHttpExceptions: true, followRedirects: true,
    headers: { Authorization: siteAuthHeader(settings), 'User-Agent': UA },
  };
  if (body !== undefined && body !== null) { opts.contentType = 'application/json'; opts.payload = JSON.stringify(body); }
  for (var k in (extra || {})) {
    if (k === 'headers') { for (var h in extra.headers) opts.headers[h] = extra.headers[h]; } else opts[k] = extra[k];
  }
  var r = UrlFetchApp.fetch(settings.site.replace(/\/+$/, '') + '/wp-json' + path, opts);
  var code = r.getResponseCode();
  var text = r.getContentText();
  var json = null;
  try { json = JSON.parse(text); } catch (e) {}
  if (code >= 400 || json === null) {
    var err = new Error('האתר ' + code + ': ' + ((json && json.message) || String(text).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').slice(0, 150)));
    err.status = code;
    err.code = json && json.code;
    throw err;
  }
  return json;
}

// Uploads a file to the site's media library. Returns {id, url}.
function siteUpload(settings, blob, filename, alt) {
  var media = siteRequest(settings, 'post', '/wp/v2/media', null, {
    contentType: blob.getContentType() || 'application/octet-stream',
    payload: blob.getBytes(),
    headers: { 'Content-Disposition': 'attachment; filename="' + filename + '"' },
  });
  if (alt) {
    try { siteRequest(settings, 'post', '/wp/v2/media/' + media.id, { alt_text: alt, title: alt }); } catch (e) {}
  }
  return { id: media.id, url: media.source_url };
}

// A tag or brand by name: the existing one, or a new one.
function siteTerm(settings, base, name) {
  name = String(name || '').trim();
  if (!name) return null;
  var found = siteRequest(settings, 'get', base + '?per_page=100&search=' + encodeURIComponent(name));
  var same = (found || []).filter(function (t) { return decodeEntities(String(t.name)).trim().toLowerCase() === name.toLowerCase(); })[0];
  if (same) return same.id;
  try {
    return siteRequest(settings, 'post', base, { name: name }).id;
  } catch (e) {
    if (e.code === 'term_exists' || e.status === 400) {   // created in the meantime, or a name that differs only in case
      var again = siteRequest(settings, 'get', base + '?per_page=100&search=' + encodeURIComponent(name));
      if (again && again[0]) return again[0].id;
    }
    throw e;
  }
}

// The product that was created for this product before (a fix, or the same link scanned again).
function siteExisting(settings, p, slug) {
  if (p.wcId) {
    try {
      var own = siteRequest(settings, 'get', '/wc/v3/products/' + p.wcId);
      if (own && own.status !== 'trash') return own;
    } catch (e) {
      if (e.status !== 404) throw e;
    }
  }
  if (!slug) return null;
  var list = siteRequest(settings, 'get', '/wc/v3/products?status=any&slug=' + encodeURIComponent(slug));
  return (list || []).filter(function (x) { return x.status !== 'trash'; })[0] || null;
}

function stepPublish(settings, p) {
  p.publishTries = (p.publishTries || 0) + 1;
  try {
    publishProduct(settings, p);
  } catch (e) {
    // Busy / down / timeout: try again on the next run. Anything else (wrong password, blocked): the Drive folder is ready anyway.
    if ((!e.status || e.status >= 500 || e.status === 429) && p.publishTries < SITE_TIMEOUT_TRIES) throw e;
    p.warnings.push('לא עלה לאתר: ' + String(e.message || e) + (e.status === 401 || e.status === 403 ? ' (בודקים את החיבור לאתר בהגדרות)' : ''));
  }
  finishProduct(p);
}

function publishProduct(settings, p) {
  var c = p.content;
  var folder = DriveApp.getFolderById(p.folderId);
  var imagesDir = firstLive(folder.getFoldersByName(IMAGES_FOLDER));
  p.wcMedia = p.wcMedia || {};   // "file name|size" -> {id, url}: a fix doesn't upload the same files again

  var upload = function (file, alt) {
    var blob = file.getBlob();
    var key = file.getName() + '|' + blob.getBytes().length;
    if (!p.wcMedia[key]) p.wcMedia[key] = siteUpload(settings, blob, file.getName(), alt);
    return p.wcMedia[key];
  };

  var images = [];
  p.saved.images.forEach(function (im, n) {
    var file = imagesDir && firstLive(imagesDir.getFilesByName(im.file.split('/').pop()));
    if (file) images.push({ id: upload(file, c.name + (n ? ' - ' + (n + 1) : '')).id });
  });
  var docUrl = {};
  p.saved.docs.forEach(function (d) {
    var file = firstLive(folder.getFilesByName(d.file));
    docUrl[d.kind] = file ? upload(file, '').url : d.url;
  });

  var meta = [
    { key: '_yoast_wpseo_focuskw', value: c.focus_keyphrase || '' },
    { key: '_yoast_wpseo_title', value: c.seo_title || '' },
    { key: '_yoast_wpseo_metadesc', value: c.meta_description || '' },
  ];
  var video = (p.saved.videos[0] || {}).url || '';
  [[settings.fieldCatalog, docUrl.brochure || ''], [settings.fieldManual, docUrl.manual || ''], [settings.fieldVideo, video]].forEach(function (f) {
    if (f[0]) meta.push({ key: f[0], value: f[1] });
  });

  var body = {
    name: c.name,
    slug: c.slug || undefined,
    type: 'simple',
    description: siteDescriptionHtml(c),
    short_description: '<p>' + esc(c.short_description) + '</p>',
    images: images,
    meta_data: meta,
  };
  var catId = siteCategoryId(settings, c.category);
  if (catId) body.categories = [{ id: catId }];
  var tagIds = [];
  (c.tags || []).forEach(function (t) {
    try { var id = siteTerm(settings, '/wc/v3/products/tags', t); if (id) tagIds.push({ id: id }); } catch (e) { if (e.status === 401 || e.status === 403) throw e; }
  });
  body.tags = tagIds;
  var brandOk = false;
  try {
    var brandId = siteTerm(settings, '/wc/v3/products/brands', p.research.manufacturer);
    if (brandId) { body.brands = [{ id: brandId }]; brandOk = true; }
  } catch (e) {
    if (e.status === 401 || e.status === 403) throw e;
  }

  var existing = siteExisting(settings, p, c.slug);
  var product;
  if (existing) {
    product = siteRequest(settings, 'put', '/wc/v3/products/' + existing.id, body);
  } else {
    body.status = 'draft';
    product = siteRequest(settings, 'post', '/wc/v3/products', body);
  }
  if (brandOk && !(product.brands && product.brands.length)) brandOk = false;
  if (p.research.manufacturer && !brandOk) p.warnings.push('באתר: לבחור מותג ידנית (' + p.research.manufacturer + ')');
  if (c.category && !catId) p.warnings.push('באתר: לבחור קטגוריה ידנית');
  if (!settings.fieldCatalog || !settings.fieldManual || !settings.fieldVideo) p.warnings.push('באתר: שדות קטלוג / ספר הוראות / וידאו לא מוגדרים בהגדרות - למלא ידנית');

  p.wcId = product.id;
  p.siteUrl = settings.site.replace(/\/+$/, '') + '/wp-admin/post.php?post=' + product.id + '&action=edit';
}

// Where the site keeps the "קטלוג pdf", "ספר הוראות" and "וידאו מוצר" fields: found from existing products.
function detectSiteFields(settings) {
  var products = siteRequest(settings, 'get', '/wc/v3/products?per_page=30&status=any');
  var score = { catalog: {}, manual: {}, video: {} };
  var add = function (kind, key, n) { score[kind][key] = (score[kind][key] || 0) + n; };
  (products || []).forEach(function (pr) {
    (pr.meta_data || []).forEach(function (m) {
      var key = String(m.key || '');
      if (!key || key.charAt(0) === '_') return;
      var v = typeof m.value === 'string' ? m.value : '';
      if (/catalog|catalogue|brochure|datasheet|קטלוג/i.test(key)) add('catalog', key, 5);
      if (/manual|guide|instruction|הוראות/i.test(key)) add('manual', key, 5);
      if (/video|youtube|וידאו/i.test(key)) add('video', key, 5);
      if (/youtu\.?be|vimeo\.com/i.test(v)) add('video', key, 1);
      if (/\.pdf(\?|$)/i.test(v) && !/manual|guide|instruction|הוראות/i.test(key)) add('catalog', key, 1);
    });
  });
  var best = function (kind) {
    var keys = Object.keys(score[kind]).sort(function (a, b) { return score[kind][b] - score[kind][a]; });
    return keys[0] || '';
  };
  var out = { catalog: best('catalog'), manual: best('manual'), video: best('video') };
  if (out.manual === out.catalog) out.manual = '';
  return out;
}

// Checks the user name + application password, and finds the product fields. Returns '' or an error in Hebrew.
function connectSite(user, pass) {
  var settings = readSettings();
  if (!settings.site) return 'קודם כותבים בהגדרות את כתובת האתר.';
  var test = { site: settings.site, siteUser: user, sitePass: pass };
  var me;
  try {
    me = siteRequest(test, 'get', '/wp/v2/users/me?context=edit');
  } catch (e) {
    if (e.status === 401 || e.status === 403) return 'שם המשתמש או סיסמת האפליקציה לא נכונים (' + e.message + '). אם הם נכונים, ייתכן שחברת האחסון או תוסף אבטחה חוסמים חיבורים כאלה - שולחים את ההודעה הזאת למי שמתחזק את האתר.';
    return 'לא הצלחתי להתחבר לאתר: ' + e.message;
  }
  var caps = me.capabilities || {};
  if (!caps.edit_products && !caps.manage_woocommerce && !caps.administrator) return 'למשתמש ' + user + ' אין הרשאה לערוך מוצרים באתר.';
  var fields;
  try {
    fields = detectSiteFields(test);
  } catch (e) {
    return 'החיבור עבד, אבל ווקומרס לא ענה: ' + e.message;
  }
  var props = PropertiesService.getUserProperties();
  props.setProperty('SITE_USER', user);
  props.setProperty('SITE_PASS', pass);
  var map = settingsMap();
  if (!map['שדה קטלוג pdf'] && fields.catalog) map['שדה קטלוג pdf'] = fields.catalog;
  if (!map['שדה ספר הוראות'] && fields.manual) map['שדה ספר הוראות'] = fields.manual;
  if (!map['שדה וידאו מוצר'] && fields.video) map['שדה וידאו מוצר'] = fields.video;
  saveSettings(map);
  return '';
}

// ======================================== App.gs ========================================
// The app: a web page (Deploy -> Web app) where you paste links, press start, watch progress, open folders
// and change the settings. No spreadsheet needed.
// Deployed as "Execute as: User accessing the web app", one link serves everyone: each person who opens it
// works in their own Google account (own API key, list, settings, Drive folders, background runs).

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
  [STATUS.publish, 'מעלה לאתר כטיוטה', 93, 'working'],
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
    return {
      id: it.id, link: it.link, name: it.name, manufacturer: it.manufacturer, step: step[1], pct: step[2], state: step[3],
      folderUrl: it.folderUrl, siteUrl: it.siteUrl || '', notes: it.notes, cost: it.cost || '', canFix: !!it.dataId,
    };
  });
  var props = PropertiesService.getUserProperties();
  var runFolder = null;
  try { runFolder = JSON.parse(props.getProperty('RUN_FOLDER') || 'null'); } catch (e) {}
  var runCost = parseFloat(props.getProperty('RUN_COST') || '0') || 0;
  var settings = readSettings();
  return { hasKey: !!settings.apiKey, items: items, worker: workerStatus(), runFolder: runFolder, runCost: runCost.toFixed(2), publishing: settings.publish };
}

// "Fix the text" on a finished product: Claude rewrites it by the user's note, the folder and tables are updated.
function appRevise(id, note) {
  ensureOwnCopy();
  note = String(note || '').trim();
  if (!note) return { ok: false, message: 'כותבים מה לתקן.' };
  if (!readSettings().apiKey) return { ok: false, message: 'חסר מפתח API.' };
  var err = reviseProduct(String(id), note.slice(0, 2000));
  return err ? { ok: false, message: err } : { ok: true, message: 'Claude מתקן את הטקסט. זה לוקח כמה דקות.', state: appState() };
}

function appStart(text) {
  ensureOwnCopy();
  if (!readSettings().apiKey) return { ok: false, needKey: true, message: 'קודם מדביקים את מפתח ה-API למעלה.' };
  var seen = {};
  var links = (String(text || '').match(/https?:\/\/[^\s"'<>]+/gi) || [])
    .map(function (l) { return l.replace(/[),.;:!?]+$/, ''); })
    .filter(function (l) { if (seen[l]) return false; seen[l] = true; return true; });
  if (!links.length) return { ok: false, message: 'לא מצאתי קישורים. מדביקים קישורים שמתחילים ב-https://' };
  PropertiesService.getUserProperties().deleteProperty('LAST_ERROR');
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
  PropertiesService.getUserProperties().setProperty('ANTHROPIC_API_KEY', key);
  SETTINGS_MEMO = null;
  return { ok: true, message: 'המפתח נשמר ✓' };
}

function appStop() {
  stopRun();
  return appState();
}

// Removes finished products from the list (their Drive folders stay).
function appClearFinished() {
  var lock = LockService.getUserLock();
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
  var s = readSettings();
  return { values: settingsMap(), hasKey: !!s.apiKey, keyEnd: s.apiKey ? s.apiKey.slice(-4) : '', siteUser: s.siteUser, siteConnected: !!(s.siteUser && s.sitePass) };
}

// Connects the site: WordPress user name + application password.
function appConnectSite(user, pass) {
  ensureOwnCopy();
  user = String(user || '').trim();
  pass = String(pass || '').trim();
  if (!user || !pass) return { ok: false, message: 'כותבים שם משתמש וסיסמת אפליקציה.' };
  SETTINGS_MEMO = null;
  var err = connectSite(user, pass);
  SETTINGS_MEMO = null;
  return err ? { ok: false, message: err } : { ok: true, message: 'האתר מחובר ✓ מוצרים חדשים ייכנסו לאתר כטיוטה.', settings: appGetSettings() };
}

function appDisconnectSite() {
  var props = PropertiesService.getUserProperties();
  props.deleteProperty('SITE_USER');
  props.deleteProperty('SITE_PASS');
  SETTINGS_MEMO = null;
  return appGetSettings();
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
  .open.site { background:var(--red); border-color:var(--red); color:#fff; }
  .open.site:hover { background:var(--red-dark); border-color:var(--red-dark); }
  .btns { flex-wrap:wrap; justify-content:flex-end; }
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
  .run { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .run:empty { display:none; }
  .run a { display:inline-flex; align-items:center; gap:6px; text-decoration:none; font-weight:700; font-size:13px; color:#fff; background:var(--ink);
    border-radius:8px; padding:7px 12px; transition:background .15s; }
  .run a:hover { background:#000; }
  .run a svg { width:14px; height:14px; fill:none; stroke:currentColor; stroke-width:2; }
  .run .cost { font-size:12.5px; color:var(--ink-2); margin-inline-start:auto; font-variant-numeric:tabular-nums; }
  .btns { display:flex; gap:8px; flex:none; }
  .fixbtn { white-space:nowrap; display:inline-flex; align-items:center; gap:5px; font:500 13px "Heebo", Arial, sans-serif; color:var(--ink-2);
    background:none; border:1.5px solid var(--line); border-radius:8px; padding:6px 10px; cursor:pointer; }
  .fixbtn:hover { border-color:var(--ink); color:var(--ink); }
  .fix { display:grid; gap:8px; }
  .fix textarea { direction:rtl; text-align:right; font-family:"Heebo", Arial, sans-serif; min-height:64px; }
  .fix .row button { flex:none; width:auto; padding:9px 16px; }
  .icost { font-size:11.5px; color:var(--muted); font-variant-numeric:tabular-nums; }
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

    <div id="run" class="run"></div>
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
          <label for="s-site">האתר שלכם</label>
          <input id="s-site" data-key="אתר" placeholder="https://www.ndt24.co.il">
          <p class="hint">משם נלקחת רשימת הקטגוריות.</p>
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
      <p class="label">חיבור לאתר</p>
      <p id="siteState" class="sub"></p>
      <p class="hint" style="margin:0">כך כל מוצר נכנס לאתר כ<b>טיוטה</b> עם כל השדות והתמונות. באתר: <b>משתמשים ← הפרופיל שלי ← סיסמאות אפליקציה</b> ← כותבים שם (למשל "סורק מוצרים") ← <b>הוספה</b> ← מעתיקים את הסיסמה שמופיעה.</p>
      <div class="grid2">
        <div class="field"><label for="siteUser">שם משתמש באתר</label><input id="siteUser" autocomplete="off" placeholder="borism"></div>
        <div class="field"><label for="sitePass">סיסמת אפליקציה</label><input id="sitePass" type="password" autocomplete="off" placeholder="xxxx xxxx xxxx xxxx xxxx xxxx"></div>
      </div>
      <div class="row"><button id="connectSite" class="ghost" type="button">חבר את האתר</button><button id="disconnectSite" class="ghost" type="button" hidden>נתק</button></div>
      <p id="siteMsg" class="msg" role="status"></p>
      <div class="field">
        <label>להעלות מוצרים לאתר</label>
        <div class="seg" data-key="להעלות לאתר">
          <button type="button" data-v="כן">כן<small>כטיוטה, לבדיקה ולפרסום</small></button>
          <button type="button" data-v="לא">לא<small>רק לדרייב</small></button>
        </div>
      </div>
      <details><summary>שדות מתקדמים (מתמלאים לבד)</summary>
        <div class="grid2" style="margin-top:8px">
          <div class="field"><label>שדה "קטלוג pdf"</label><input data-key="שדה קטלוג pdf"></div>
          <div class="field"><label>שדה "ספר הוראות"</label><input data-key="שדה ספר הוראות"></div>
          <div class="field"><label>שדה "וידאו מוצר"</label><input data-key="שדה וידאו מוצר"></div>
        </div>
      </details>
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
  var STEP_NAMES = ['יצרן', 'מקור', 'עברית', 'דרייב'];
  var SITE_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/></svg>';
  var publishing = false;
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
    var names = publishing || it.siteUrl ? STEP_NAMES.concat('אתר') : STEP_NAMES;
    var now = { 25: 0, 45: 1, 65: 2, 85: 3, 93: 4 }[it.pct];
    var finished = it.pct === 100 && (it.state === 'done' || it.state === 'warn');
    return '<div class="steps" style="grid-template-columns:repeat(' + names.length + ',1fr)">' + names.map(function (n, i) {
      var cls = finished || (now !== undefined && i < now) ? 'on' : (i === now ? 'now' : '');
      return '<span class="' + cls + '">' + n + '</span>';
    }).join('') + '</div>';
  }

  function dotHtml(state) {
    return '<div class="dot" aria-hidden="true">' + ({ done: '✓', warn: '!', error: '×' }[state] || '') + '</div>';
  }

  function render(state) {
    last = state;
    publishing = !!state.publishing;
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
          '<div class="actions"><span class="state">' + esc(it.step) + (it.cost && (it.state === 'done' || it.state === 'warn') ? ' <span class="icost">· כ-' + esc(it.cost) + '$</span>' : '') + '</span>' +
            '<span class="btns">' +
            (it.canFix && (it.state === 'done' || it.state === 'warn') ? '<button class="fixbtn" type="button" data-fix="' + esc(it.id) + '">✏️ תקן טקסט</button>' : '') +
            (it.siteUrl && (it.state === 'done' || it.state === 'warn') ? '<a class="open site" href="' + esc(it.siteUrl) + '" target="_blank" rel="noopener">' + SITE_ICON + 'פתח באתר</a>' : '') +
            (it.folderUrl ? '<a class="open" href="' + esc(it.folderUrl) + '" target="_blank" rel="noopener">' + FOLDER_ICON + 'תיקייה</a>' : '') +
          '</span></div>' +
          (fixOpen[it.id] ? '<div class="fix" data-box="' + esc(it.id) + '"><textarea placeholder="מה לתקן? למשל: לקצר את התיאור הקצר, להדגיש את העמידות למים, לכתוב מצלמה תרמית ולא מצלמת חום">' + esc(fixOpen[it.id].text) + '</textarea>' +
            '<div class="row"><button class="primary" type="button" data-send="' + esc(it.id) + '">שלח לתיקון</button><button class="ghost" type="button" data-cancel="' + esc(it.id) + '">ביטול</button></div>' +
            '<p class="msg' + (fixOpen[it.id].bad ? ' bad' : ' good') + '">' + esc(fixOpen[it.id].msg || '') + '</p></div>' : '') +
          (it.notes ? '<details><summary>' + (it.state === 'error' ? 'מה קרה?' : 'מה חסר?') + '</summary>' + esc(it.notes) + '</details>' : '') +
          '</article>';
      }).join('');
    }
    var rf = state.runFolder;
    var TABLE_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 10h18M3 15h18M9 4v16"/></svg>';
    $('run').innerHTML = (rf ? '<a href="' + esc(rf.url) + '" target="_blank" rel="noopener">' + FOLDER_ICON + 'תיקיית ההרצה: ' + esc(rf.name) + '</a>' +
        (rf.tableUrl ? '<a href="' + esc(rf.tableUrl) + '" target="_blank" rel="noopener">' + TABLE_ICON + 'טבלת כל המוצרים</a>' : '') : '') +
      (items.length && +state.runCost > 0 ? '<span class="cost">עלות ההרצה עד עכשיו: כ-' + esc(state.runCost) + '$</span>' : '');
    $('stop').hidden = !n.working;
    $('clear').hidden = !(items.length - n.working);
    clearTimeout(timer);
    timer = setTimeout(refresh, n.working ? 5000 : 30000);
  }

  var fixOpen = {};   // product id -> {text, msg, bad}: the "fix the text" boxes that are open
  var last = null;
  function refresh() {
    if (document.activeElement && document.activeElement.closest && document.activeElement.closest('.fix')) { clearTimeout(timer); timer = setTimeout(refresh, 5000); return; }
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
      $('list').addEventListener('input', function (e) {
    var box = e.target.closest('.fix');
    if (box && fixOpen[box.getAttribute('data-box')]) fixOpen[box.getAttribute('data-box')].text = e.target.value;
  });
  $('list').addEventListener('click', function (e) {
    var b = e.target.closest('button');
    if (!b) return;
    var id;
    if ((id = b.getAttribute('data-fix'))) {
      fixOpen[id] = fixOpen[id] ? null : { text: '' };
      if (!fixOpen[id]) delete fixOpen[id];
      render(last);
      var t = document.querySelector('[data-box="' + id + '"] textarea');
      if (t) t.focus();
    } else if ((id = b.getAttribute('data-cancel'))) {
      delete fixOpen[id]; render(last);
    } else if ((id = b.getAttribute('data-send'))) {
      var box = fixOpen[id];
      if (!box || !box.text.trim()) { fixOpen[id] = { text: box ? box.text : '', msg: 'כותבים מה לתקן.', bad: true }; render(last); return; }
      b.disabled = true;
      google.script.run.withSuccessHandler(function (r) {
        if (r.ok) { delete fixOpen[id]; say($('msg'), r.message, true); render(r.state); }
        else { fixOpen[id].msg = r.message; fixOpen[id].bad = true; render(last); }
      }).withFailureHandler(function (err) {
        fixOpen[id].msg = 'משהו השתבש: ' + (err && err.message || err); fixOpen[id].bad = true; render(last);
      }).appRevise(id, box.text);
    }
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
    $('siteState').textContent = r.siteConnected ? 'מחובר בתור ' + r.siteUser + '.' : 'לא מחובר: המוצרים נשמרים רק בדרייב.';
    $('disconnectSite').hidden = !r.siteConnected;
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
  $('connectSite').addEventListener('click', function () {
    $('connectSite').disabled = true;
    say($('siteMsg'), 'בודק את החיבור לאתר…', true);
    google.script.run.withSuccessHandler(function (r) {
      $('connectSite').disabled = false; say($('siteMsg'), r.message, r.ok);
      if (r.ok) { $('sitePass').value = ''; fillSettings(r.settings); }
    }).withFailureHandler(function (e) { $('connectSite').disabled = false; say($('siteMsg'), 'משהו השתבש: ' + (e && e.message || e)); })
      .appConnectSite($('siteUser').value, $('sitePass').value);
  });
  $('disconnectSite').addEventListener('click', function () {
    google.script.run.withSuccessHandler(function (r) { fillSettings(r); say($('siteMsg'), 'האתר נותק.', true); }).appDisconnectSite();
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


  $('list').addEventListener('input', function (e) {
    var box = e.target.closest('.fix');
    if (box && fixOpen[box.getAttribute('data-box')]) fixOpen[box.getAttribute('data-box')].text = e.target.value;
  });
  $('list').addEventListener('click', function (e) {
    var b = e.target.closest('button');
    if (!b) return;
    var id;
    if ((id = b.getAttribute('data-fix'))) {
      fixOpen[id] = fixOpen[id] ? null : { text: '' };
      if (!fixOpen[id]) delete fixOpen[id];
      render(last);
      var t = document.querySelector('[data-box="' + id + '"] textarea');
      if (t) t.focus();
    } else if ((id = b.getAttribute('data-cancel'))) {
      delete fixOpen[id]; render(last);
    } else if ((id = b.getAttribute('data-send'))) {
      var box = fixOpen[id];
      if (!box || !box.text.trim()) { fixOpen[id] = { text: box ? box.text : '', msg: 'כותבים מה לתקן.', bad: true }; render(last); return; }
      b.disabled = true;
      google.script.run.withSuccessHandler(function (r) {
        if (r.ok) { delete fixOpen[id]; say($('msg'), r.message, true); render(r.state); }
        else { fixOpen[id].msg = r.message; fixOpen[id].bad = true; render(last); }
      }).withFailureHandler(function (err) {
        fixOpen[id].msg = 'משהו השתבש: ' + (err && err.message || err); fixOpen[id].bad = true; render(last);
      }).appRevise(id, box.text);
    }
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
    $('siteState').textContent = r.siteConnected ? 'מחובר בתור ' + r.siteUser + '.' : 'לא מחובר: המוצרים נשמרים רק בדרייב.';
    $('disconnectSite').hidden = !r.siteConnected;
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
  $('connectSite').addEventListener('click', function () {
    $('connectSite').disabled = true;
    say($('siteMsg'), 'בודק את החיבור לאתר…', true);
    google.script.run.withSuccessHandler(function (r) {
      $('connectSite').disabled = false; say($('siteMsg'), r.message, r.ok);
      if (r.ok) { $('sitePass').value = ''; fillSettings(r.settings); }
    }).withFailureHandler(function (e) { $('connectSite').disabled = false; say($('siteMsg'), 'משהו השתבש: ' + (e && e.message || e)); })
      .appConnectSite($('siteUser').value, $('sitePass').value);
  });
  $('disconnectSite').addEventListener('click', function () {
    google.script.run.withSuccessHandler(function (r) { fillSettings(r); say($('siteMsg'), 'האתר נותק.', true); }).appDisconnectSite();
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
