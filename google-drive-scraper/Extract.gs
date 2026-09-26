// Reading web pages without a DOM (Apps Script has none): links, images, PDFs, YouTube links and text.

var UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';
var YT_ID = /(?:youtube(?:-nocookie)?\.com\/(?:embed\/|watch\?v=|v\/|shorts\/)|youtu\.be\/)([A-Za-z0-9_-]{11})/g;
var SKIP_IMG = /(logo|icon|sprite|placeholder|avatar|badge|flag|payment|favicon|loader|spinner|pixel)/i;
var MANUAL_WORDS = ['manual', 'user guide', 'userguide', 'user-guide', 'instruction', 'operating', 'handbuch',
  'bedienungsanleitung', 'anleitung', 'quick start', 'quickstart', 'guide'];
var BROCHURE_WORDS = ['brochure', 'datasheet', 'data sheet', 'data-sheet', 'catalog', 'catalogue', 'leaflet', 'flyer',
  'prospekt', 'spec sheet', 'specification', 'datenblatt'];

function fetchUrl(url, extra) {
  var opts = { muteHttpExceptions: true, followRedirects: true, headers: { 'User-Agent': UA, 'Accept-Language': 'en-US,en;q=0.9' } };
  for (var k in (extra || {})) opts[k] = extra[k];
  try {
    var r = UrlFetchApp.fetch(url, opts);
    return r.getResponseCode() < 400 ? r : null;
  } catch (e) {
    return null;
  }
}

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
    .replace(/&#(\d+);/g, function (_, n) { return String.fromCharCode(+n); })
    .replace(/&#x([0-9a-f]+);/gi, function (_, n) { return String.fromCharCode(parseInt(n, 16)); })
    .replace(/&nbsp;/g, ' ').replace(/&quot;/g, '"').replace(/&#039;|&apos;/g, "'")
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
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
    .replace(/<(script|style|noscript|svg|nav|header|footer|form|iframe)\b[\s\S]*?<\/\1>/gi, ' ')
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

function canonicalImage(url) {
  return url
    .replace(/-\d{2,4}x\d{2,4}(?=\.(jpe?g|png|webp)(\?|$))/i, '')
    .replace(/_(\d{2,4}x\d{0,4}|\d{0,4}x\d{2,4}|small|medium|large|grande|compact)(?=\.(jpe?g|png|webp))/i, '');
}

function classifyPdf(url, label) {
  var text = (label + ' ' + decodeURIComponent(String(url).replace(/%(?![0-9a-f]{2})/gi, '%25'))).toLowerCase().replace(/_/g, ' ');
  if (MANUAL_WORDS.some(function (w) { return text.indexOf(w) >= 0; })) return 'manual';
  if (BROCHURE_WORDS.some(function (w) { return text.indexOf(w) >= 0; })) return 'brochure';
  return 'document';
}

// Everything useful on one page.
function parsePage(html, url) {
  var page = { url: url, title: '', text: pageText(html), images: [], pdfs: [], videos: [], links: [] };
  var h1 = html.match(/<h1\b[^>]*>([\s\S]*?)<\/h1>/i);
  var ld = jsonLdProducts(html);
  page.title = (ld[0] && ld[0].name) || (h1 && stripTags(h1[1])) || metaContent(html, 'og:title') || stripTags((html.match(/<title>([\s\S]*?)<\/title>/i) || [])[1]);
  var desc = [];
  ld.forEach(function (d) { if (d.description) desc.push(stripTags(d.description)); });
  if (metaContent(html, 'og:description')) desc.push(metaContent(html, 'og:description'));
  if (desc.length) page.text = desc.join('\n') + '\n\n' + page.text;

  var seenImg = {};
  function addImg(src, alt, source) {
    src = resolveUrl(src, url);
    if (!src) return;
    var path = src.split('?')[0].toLowerCase();
    if (SKIP_IMG.test(path) || /\.(svg|gif)$/.test(path)) return;
    var canon = canonicalImage(src);
    if (seenImg[canon]) return;
    seenImg[canon] = true;
    page.images.push({ url: canon, fallback: canon !== src ? src : '', alt: stripTags(alt).slice(0, 120), source: source });
  }
  ld.forEach(function (d) {
    [].concat(d.image || []).forEach(function (i) { addImg(typeof i === 'string' ? i : (i && i.url), '', 'json-ld'); });
  });
  if (metaContent(html, 'og:image')) addImg(metaContent(html, 'og:image'), '', 'og:image');
  var m;
  var imgRe = /<img\b[^>]*>/gi;
  while ((m = imgRe.exec(html))) {
    var a = attrsOf(m[0]);
    var src = a['data-large_image'] || a['data-zoom-image'] || a['data-src'] || a['data-lazy-src'] || a['data-original'] || a.src;
    if ((!src || /^data:/.test(src)) && (a.srcset || a['data-srcset'])) src = (a.srcset || a['data-srcset']).split(',').pop().trim().split(' ')[0];
    if (src && !/^data:/.test(src)) addImg(src, a.alt || '', 'img' + (a['class'] ? ' .' + a['class'].slice(0, 60) : ''));
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
    if (seenVid[m[1]]) continue;
    seenVid[m[1]] = true;
    var around = html.slice(Math.max(0, m.index - 300), m.index + 300);
    var t = around.match(/title=["']([^"']{3,120})["']/i);
    page.videos.push({ url: 'https://www.youtube.com/watch?v=' + m[1], title: t ? decodeEntities(t[1]) : '' });
  }
  return page;
}

function fetchPage(url) {
  var r = fetchUrl(url);
  if (!r) return null;
  var type = String(r.getHeaders()['Content-Type'] || r.getHeaders()['content-type'] || '');
  if (type && !/html|xml/i.test(type)) return null;
  return parsePage(r.getContentText(), url);
}
