// Shared helpers.

export function slugify(text) {
  return String(text || "")
    .normalize("NFKD").replace(/[̀-ͯ]/g, "")
    .replace(/[^A-Za-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

// MANUFACTURER-PRODUCT, upper-case, without repeating the manufacturer.
export function fileStem(manufacturer, product) {
  const m = slugify(manufacturer).toUpperCase();
  let p = slugify(product).toUpperCase();
  if (p.startsWith(m + "-")) p = p.slice(m.length + 1);
  return p ? `${m}-${p}` : m;
}

export function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
}

export function isOfficial(url, domains) {
  const h = hostOf(url);
  return (domains || []).some((d) => {
    d = d.toLowerCase().replace(/^\.+/, "");
    return h === d || h.endsWith("." + d);
  });
}

export function cleanUrl(url) {
  return url.split("#")[0];
}

export function resolve(href, base) {
  try { return new URL(href, base).href; } catch { return null; }
}

export function normKey(text) {
  return String(text || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

export function matchesAny(text, terms) {
  const k = normKey(text);
  return (terms || []).find((t) => normKey(t) && k.includes(normKey(t))) || null;
}

export function wordCount(text) {
  return (String(text || "").match(/\S+/g) || []).length;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

export function lastSegment(url) {
  try { return new URL(url).pathname.replace(/\/+$/, "").split("/").pop() || ""; } catch { return ""; }
}

export function escapeRegex(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
