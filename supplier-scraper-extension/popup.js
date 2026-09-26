import { loadSettings } from "./lib/settings.js";

const $ = (id) => document.getElementById(id);
const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
const tabUrl = /^https?:/.test(tab?.url || "") ? tab.url : "";
const settings = await loadSettings();
const { lastProductType = "" } = await chrome.storage.local.get("lastProductType");

$("nokey").hidden = !!settings.apiKey;
$("openOptions").onclick = (ev) => { ev.preventDefault(); chrome.runtime.openOptionsPage(); };
$("startUrl").value = tabUrl;
$("productType").value = lastProductType;
(tabUrl ? $("productType") : $("startUrl")).focus();

// The current tab's rendered page (covers sites that build their pages with JavaScript).
async function liveHtml(url) {
  if (url !== tabUrl || !tab?.id) return null;
  try {
    const [res] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: () => document.documentElement.outerHTML });
    return res?.result || null;
  } catch {
    return null;
  }
}

$("start").onclick = async () => {
  let startUrl = $("startUrl").value.trim();
  const productType = $("productType").value.trim();
  if (startUrl && !/^https?:\/\//.test(startUrl)) startUrl = "https://" + startUrl;
  try { new URL(startUrl); } catch { $("msg").textContent = "כתובת האתר לא תקינה."; return; }
  if (!productType) { $("msg").textContent = "כתבו סוג מוצר, למשל: מצלמות תרמיות."; return; }
  if (!settings.apiKey) { chrome.runtime.openOptionsPage(); return; }
  const job = { startUrl, productType, startHtml: await liveHtml(startUrl) };
  const id = `job-${Date.now()}`;
  await chrome.storage.local.set({ [id]: job, lastProductType: productType });
  await chrome.tabs.create({ url: chrome.runtime.getURL(`runner.html?job=${id}`) });
  window.close();
};
