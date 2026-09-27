// Default settings. They can be changed in the app's settings screen (saved in User Properties).

var SHORT_MAX_WORDS = 80;
var FULL_MAX_WORDS = 500;

var DEFAULT_SETTINGS = [
  ['אתר', 'https://www.ndt24.co.il', 'כתובת האתר שלכם. המערכת קוראת ממנו את רשימת קטגוריות המוצרים'],
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
  SETTINGS_MEMO = {
    site: /^https?:\/\//.test(map['אתר']) ? map['אתר'] : '',
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
