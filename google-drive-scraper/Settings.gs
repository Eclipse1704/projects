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
  ['מודל', 'claude-opus-5', 'מודל Claude'],
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
    styleUrls: map['דפי דוגמה לסגנון'].split(/\s+/).filter(function (u) { return /^https?:\/\//.test(u); }),
    glossary: map['מילון מונחים'],
    // Stored for the whole spreadsheet, so the worker runs the same no matter which editor pressed 'run'.
    apiKey: PropertiesService.getScriptProperties().getProperty('ANTHROPIC_API_KEY') || PropertiesService.getUserProperties().getProperty('ANTHROPIC_API_KEY') || '',
    apiBase: PropertiesService.getScriptProperties().getProperty('ANTHROPIC_API_BASE') || 'https://api.anthropic.com',
  };
  return SETTINGS_MEMO;
}
