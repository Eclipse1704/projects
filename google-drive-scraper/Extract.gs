// Reading web pages without a DOM (Apps Script has none): links, images, PDFs, YouTube links and text.

var UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';
var YT_ID = /(?:youtube(?:-nocookie)?\.com\/(?:embed\/|watch\?v=|v\/|shorts\/)|youtu\.be\/)([A-Za-z0-9_-]{11})/g;
var SKIP_IMG = /(logo|icon|sprite|placeholder|avatar|badge|flag|payment|favicon|loader|spinner|pixel)/i;
var MANUAL_WORDS = ['manual', 'user guide', 'userguide', 'user-guide', 'instruction', 'operating', 'handbuch',
  'bedienungsanleitung', 'anleitung', 'quick start', 'quickstart', 'guide'];
var BROCHURE_WORDS = ['brochure', 'datasheet', 'data sheet', 'data-sheet', 'catalog', 'catalogue', 'leaflet', 'flyer',
  'prospekt', 'spec sheet', 'specification', 'datenblatt'];

function fetchUrl(url, extra) {
  // Spaces, Hebrew letters etc. must be percent-encoded (already-encoded %XX stays as is).
  url = String(url).replace(/[^\x21-\x7e]+/g, function (c) { return encodeURIComponent(c); });
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
