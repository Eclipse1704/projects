// Known suppliers. When the active tab is on one of these hosts the toolbar icon
// shows a badge and the popup is pre-filled. Everything can be edited in the popup.
export const PRESETS = [
  {
    id: "jacobs-mc",
    manufacturer: "Jacobs-MC",
    hosts: ["jacobs-mc.com", "jacobs-mc.co"],
    officialDomains: ["jacobs-mc.com", "jacobs-mc.co"],
    productType: "מכשירים לאיתור נזילות מים ומצלמות צנרת (Lixener30, MultiPro, Sniffer430, Vister)",
  },
  {
    id: "fotric",
    manufacturer: "FOTRIC",
    hosts: ["fotric.com"],
    officialDomains: ["fotric.com"],
    productType: "מצלמות תרמיות",
    startUrl: "https://us.fotric.com/collections/all-products",
  },
  {
    id: "riezler",
    manufacturer: "Riezler",
    hosts: ["riezler.eu"],
    officialDomains: ["riezler.eu"],
    productType: "מצלמות דחיפה לצנרת (Push systems)",
    startUrl: "https://www.riezler.eu/en/products/push-systems",
  },
  {
    id: "mitcorp",
    manufacturer: "Mitcorp",
    hosts: ["mitcorp.com.tw", "mitcorpusa.com"],
    officialDomains: ["mitcorp.com.tw", "mitcorpusa.com"],
    productType: "וידאוסקופים תעשייתיים X-Series",
    startUrl: "https://www.mitcorp.com.tw/product-category/model-type/x-series/",
    downloadsPages: ["https://www.mitcorp.com.tw/downloads/"],
  },
];

export function presetForUrl(url) {
  let h = "";
  try { h = new URL(url).hostname.toLowerCase(); } catch { return null; }
  return PRESETS.find((p) => p.hosts.some((d) => h === d || h.endsWith("." + d))) || null;
}

// Defaults for the options page.
export const DEFAULT_SETTINGS = {
  apiKey: "",
  model: "claude-opus-5",
  outputFolder: "NDT24-import",
  publishStatus: "0",            // 0 = import as draft, 1 = publish
  imagesBaseUrl: "",             // e.g. https://www.ndt24.co.il/wp-content/uploads/import/ (after uploading the images folder)
  styleExampleUrls: [
    "https://www.ndt24.co.il/product/%D7%9E%D7%A6%D7%9C%D7%9E%D7%94-%D7%AA%D7%A8%D7%9E%D7%99%D7%AA-fotric-348a/",
    "https://www.ndt24.co.il/product/sniffer430-%D7%9E%D7%9B%D7%A9%D7%99%D7%A8-%D7%9C%D7%90%D7%99%D7%AA%D7%95%D7%A8-%D7%A0%D7%96%D7%99%D7%9C%D7%95%D7%AA-%D7%9E%D7%99%D7%9D-%D7%91%D7%92%D7%96/",
    "https://www.ndt24.co.il/product/iris-x-pro-flexible-videoscope-system/",
  ].join("\n"),
  glossary: [
    "thermal camera = מצלמה תרמית",
    "thermal sensitivity / NETD = רגישות תרמית",
    "IR resolution = רזולוציית חיישן (למשל 640X480 פיקסלים)",
    "temperature range = טווח מדידת טמפרטורה",
    "water leak detection = איתור נזילות מים",
    "acoustic leak detector = מכשיר אקוסטי לאיתור נזילות",
    "tracer gas (hydrogen) = גז מימן / איתור נזילות בגז",
    "underground / under-floor pipes = צנרת תת-קרקעית / צנרת מתחת לריצוף",
    "pipe inspection camera / push camera = מצלמת צנרת / מצלמת ביוב",
    "videoscope = וידאוסקופ",
    "borescope = בורוסקופ",
    "fiberscope = פייברסקופ",
    "articulation = היגוי (ראש מתכוונן)",
    "probe / insertion tube = פרוב / צינור החדרה",
    "non-destructive testing (NDT) = בדיקות לא הורסות",
    "correlator = קורלטור",
  ].join("\n"),
};
