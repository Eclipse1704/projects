// Getting page HTML: plain fetch first; if the page is built by JavaScript, load it in a
// background tab and read the rendered DOM.
import { hostOf, sleep } from "./common.js";

const lastHit = new Map();
const cache = new Map();
export const DELAY_MS = 800;

async function throttle(url) {
  const h = hostOf(url);
  const wait = (lastHit.get(h) || 0) + DELAY_MS - Date.now();
  if (wait > 0) await sleep(wait);
  lastHit.set(h, Date.now());
}

export async function fetchResponse(url, init = {}) {
  await throttle(url);
  try {
    const r = await fetch(url, { credentials: "omit", ...init });
    return r.ok ? r : null;
  } catch {
    return null;
  }
}

export async function fetchJson(url) {
  const r = await fetchResponse(url, { headers: { Accept: "application/json" } });
  if (!r) return null;
  try { return await r.json(); } catch { return null; }
}

export function parseHtml(html) {
  return new DOMParser().parseFromString(html, "text/html");
}

function looksEmpty(doc) {
  const text = (doc.body?.innerText || doc.body?.textContent || "").trim();
  return text.length < 400 || doc.querySelectorAll("img").length < 2;
}

export async function renderInTab(url, settleMs = 2500) {
  const tab = await chrome.tabs.create({ url, active: false });
  try {
    await new Promise((resolve) => {
      const timer = setTimeout(done, 30000);
      function done() { clearTimeout(timer); chrome.tabs.onUpdated.removeListener(onUpd); resolve(); }
      function onUpd(id, info) { if (id === tab.id && info.status === "complete") done(); }
      chrome.tabs.onUpdated.addListener(onUpd);
    });
    await sleep(settleMs);
    // Scroll once so lazy-loaded galleries fill in.
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: () => window.scrollTo(0, document.body.scrollHeight) });
    await sleep(800);
    const [res] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: () => document.documentElement.outerHTML });
    return res?.result || null;
  } catch {
    return null;
  } finally {
    chrome.tabs.remove(tab.id).catch(() => {});
  }
}

// Returns {html, doc} or null. `preRendered` lets the caller pass the live DOM of the active tab.
export async function getPage(url, { preRendered = null, allowRender = true } = {}) {
  if (cache.has(url)) return cache.get(url);
  let html = preRendered;
  if (!html) {
    const r = await fetchResponse(url);
    html = r ? await r.text() : null;
  }
  let doc = html ? parseHtml(html) : null;
  if (allowRender && !preRendered && (!doc || looksEmpty(doc))) {
    const rendered = await renderInTab(url);
    if (rendered) { html = rendered; doc = parseHtml(html); }
  }
  const out = doc ? { html, doc } : null;
  cache.set(url, out);
  return out;
}
