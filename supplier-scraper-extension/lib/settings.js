// Extension settings (options page), stored in chrome.storage.local.
export const DEFAULT_SETTINGS = {
  apiKey: "",
  model: "claude-opus-5",
  maxProducts: "100",
  outputFolder: "NDT24-import",
  publishStatus: "0",            // 0 = import as draft, 1 = publish
  imagesBaseUrl: "",             // e.g. https://www.ndt24.co.il/wp-content/uploads/import/ (after uploading the output folder)
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

export async function loadSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(settings || {}) };
}

export async function saveSettings(patch) {
  const current = await loadSettings();
  await chrome.storage.local.set({ settings: { ...current, ...patch } });
}
