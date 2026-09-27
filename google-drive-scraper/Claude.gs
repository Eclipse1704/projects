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
