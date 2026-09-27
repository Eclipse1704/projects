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
