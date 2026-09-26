import { hostOf } from "./lib/common.js";
import { presetForUrl } from "./lib/presets.js";
import { loadSettings } from "./lib/settings.js";

const $ = (id) => document.getElementById(id);
const FIELDS = ["manufacturer", "officialDomains", "productType", "category", "maxProducts"];

const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
const url = tab?.url || "";
const host = hostOf(url);
const preset = presetForUrl(url);
const settings = await loadSettings();

$("site").textContent = preset ? `✓ ספק מוכר: ${preset.manufacturer}` : host ? `אתר: ${host}` : "פתחו אתר של ספק ואז לחצו על התוסף.";
$("nokey").hidden = !!settings.apiKey;
$("openOptions").onclick = (ev) => { ev.preventDefault(); chrome.runtime.openOptionsPage(); };

// Pre-fill: last values used on this host, else the preset, else the current site.
const { lastByHost = {} } = await chrome.storage.local.get("lastByHost");
const last = lastByHost[host] || {};
$("manufacturer").value = last.manufacturer ?? preset?.manufacturer ?? "";
$("officialDomains").value = last.officialDomains ?? (preset?.officialDomains || [host.replace(/^www\./, "")]).join(", ");
$("productType").value = last.productType ?? preset?.productType ?? "";
$("category").value = last.category ?? "";
$("maxProducts").value = last.maxProducts ?? 50;
$("startUrl").value = url;

async function liveHtml(targetUrl) {
  if (targetUrl !== url || !tab?.id) return null;
  try {
    const [res] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: () => document.documentElement.outerHTML });
    return res?.result || null;
  } catch {
    return null;
  }
}

async function start(mode) {
  const job = {
    mode,
    startUrl: $("startUrl").value.trim(),
    manufacturer: $("manufacturer").value.trim(),
    officialDomains: $("officialDomains").value.split(/[,\s]+/).map((s) => s.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "")).filter(Boolean),
    productType: $("productType").value.trim(),
    category: $("category").value.trim(),
    maxProducts: Math.max(1, parseInt($("maxProducts").value, 10) || 50),
    downloadsPages: preset?.downloadsPages || [],
    supplierId: preset?.id || host.replace(/^www\./, "").replace(/[^a-z0-9]+/gi, "-"),
  };
  if (!job.manufacturer || !job.startUrl || !job.officialDomains.length) {
    $("site").textContent = "צריך למלא יצרן, אתר רשמי ודף התחלה.";
    $("site").className = "box err";
    return;
  }
  lastByHost[host] = Object.fromEntries(FIELDS.map((f) => [f, f === "officialDomains" ? job.officialDomains.join(", ") : job[f]]));
  job.startHtml = await liveHtml(job.startUrl);
  const id = `job-${Date.now()}`;
  await chrome.storage.local.set({ lastByHost, [id]: job });
  await chrome.tabs.create({ url: chrome.runtime.getURL(`runner.html?job=${id}`) });
  window.close();
}

$("single").onclick = () => start("single");
$("catalog").onclick = () => start("catalog");
