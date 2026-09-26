import { loadSettings, saveSettings } from "./lib/settings.js";

const KEYS = ["apiKey", "model", "maxProducts", "outputFolder", "publishStatus", "imagesBaseUrl", "styleExampleUrls", "glossary"];
const settings = await loadSettings();
for (const k of KEYS) document.getElementById(k).value = settings[k] ?? "";

document.getElementById("save").onclick = async () => {
  const patch = Object.fromEntries(KEYS.map((k) => [k, document.getElementById(k).value.trim()]));
  patch.outputFolder = patch.outputFolder.replace(/[^A-Za-z0-9_\-֐-׿ ]+/g, "") || "NDT24-import";
  await saveSettings(patch);
  await chrome.storage.local.remove("styleCache");
  document.getElementById("status").textContent = "נשמר ✓";
};
