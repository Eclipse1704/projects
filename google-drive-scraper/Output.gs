// Output: one Drive folder per product with a CSV table (all the text, the HTML page and the links),
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
  var paras = String(c.overview || '').split(/\n\s*\n|\n/).filter(function (s) { return s.trim(); })
    .map(function (s) { return '<p>' + esc(s.trim()) + '</p>'; }).join('\n');
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
    '<title>' + esc(c.name) + '</title>\n<meta name="description" content="' + esc(c.short_description) + '">\n' +
    '<script type="application/ld+json">' + JSON.stringify(jsonLd(p), null, 1).replace(/</g, '\\u003c') + '</script>\n<style>' + PAGE_CSS + '</style>\n' +
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
    '<section id="images">\n<h2>תמונות המוצר</h2>\n' + (images ? '<div class="gallery">\n' + images + '\n</div>' : NOT_FOUND) + '\n</section>\n\n' +
    '<section id="brochure">\n<h2>ברושור</h2>\n' + doc('brochure') + '\n</section>\n\n' +
    '<section id="manual">\n<h2>מדריך למשתמש</h2>\n' + doc('manual') + '\n</section>\n\n' +
    '<section id="product-pages">\n<h2>קישורים לדף המוצר</h2>\n<ul>\n' + pages + '\n</ul>\n</section>\n' +
    '</article>\n</body>\n</html>\n';
}

// ---------- CSV (opens in Excel and Google Sheets) ----------

var ALL_PRODUCTS_CSV = 'כל המוצרים.csv';
var CSV_HEADERS = ['מזהה', 'שם המוצר', 'יצרן', 'דגם', 'תיאור קצר', 'תיאור מלא', 'שימושים ואופן שימוש', 'תכונות עיקריות', 'מפרט טכני',
  'סרטוני YouTube', 'ברושור (בדרייב)', 'ברושור (באתר היצרן)', 'מדריך למשתמש (בדרייב)', 'מדריך למשתמש (באתר היצרן)', 'תמונות',
  'דף המוצר באתר היצרן', 'דף המוצר באתר הספק', 'תיקייה בדרייב', 'הערות', 'HTML'];
var CSV_CELL_MAX = 32000;   // Excel's limit per cell is 32,767 characters

// One product as a table row, in the order of CSV_HEADERS.
function productRow(p, stem, folderUrl) {
  var c = p.content;
  var lines = function (items) { return (items || []).map(function (x) { return '• ' + x; }).join('\n'); };
  var doc = function (kind, key) { var d = p.saved.docs.filter(function (x) { return x.kind === kind; })[0]; return d ? d[key] || '' : ''; };
  var page = function (official) { return p.productPages.filter(function (x) { return !!x.official === official; }).map(function (x) { return x.url; }).join('\n'); };
  var html = productHtml(p);
  if (html.length > CSV_CELL_MAX) html = html.replace(/<script type="application\/ld\+json">[\s\S]*?<\/script>\n/, '').replace(/<style>[\s\S]*?<\/style>\n/, '');
  return [
    stem, c.name, p.research.manufacturer, p.research.model, c.short_description,
    String(c.overview || '').trim(), lines(c.usage), lines(c.features),
    (c.specs || []).map(function (x) { return x.name + ': ' + x.value; }).join('\n'),
    p.saved.videos.map(function (v) { return v.url; }).join('\n'),
    doc('brochure', 'driveUrl'), doc('brochure', 'url'), doc('manual', 'driveUrl'), doc('manual', 'url'),
    p.saved.images.map(function (im) { return im.file.split('/').pop() + ' (' + im.width + '×' + im.height + ')'; }).join('\n'),
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
  var rows = file ? parseCsv(file.getBlob().getDataAsString('UTF-8')).slice(1) : [];
  rows = rows.filter(function (r) { return r[0] !== row[0]; });
  rows.push(row);
  var content = toCsv([CSV_HEADERS].concat(rows));
  if (file) file.setContent(content);
  else root.createFile(Utilities.newBlob(content, 'text/csv', ALL_PRODUCTS_CSV));
}
