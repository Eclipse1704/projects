// Marks the toolbar icon when the active tab is on a known supplier site.
import { presetForUrl } from "./lib/presets.js";

async function updateBadge(tabId, url) {
  const preset = url ? presetForUrl(url) : null;
  await chrome.action.setBadgeText({ tabId, text: preset ? "✓" : "" });
  if (preset) {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: "#1a7f37" });
    await chrome.action.setTitle({ tabId, title: `סורק מוצרים - ${preset.manufacturer}` });
  }
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.url || info.status === "complete") updateBadge(tabId, tab.url).catch(() => {});
});
chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId).then((t) => updateBadge(tabId, t.url)).catch(() => {});
});
