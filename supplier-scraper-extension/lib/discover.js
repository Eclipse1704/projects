// Find candidate product pages on any website.
// Order: store APIs (Shopify / WooCommerce) -> guided crawl -> sitemap. Claude filters the result later.
import { cleanUrl, hostOf, resolve } from "./common.js";
import { fetchJson, fetchResponse, getPage } from "./fetchpage.js";

const PRODUCT_HINT = /\/(products?|produkte?|produits?|prodotti|productos|product-details|shop|item|p)\/[^/?#]+/i;
const PAGINATION = /(\/page\/\d+\/?$|[?&](page|paged|p|pg)=\d+)/i;
const LISTING_HINT = /\/(product-category|category|categories|collections?|catalog|catalogue|shop|products?|kategorie|produkte)(\/|$)/i;
const SKIP = /\.(pdf|jpe?g|png|gif|webp|svg|zip|mp4|docx?|xlsx?)(\?|$)|\/(cart|checkout|account|login|wp-login|my-account|blog|news|contact|privacy|terms|tag)\b|mailto:|tel:/i;

function origin(url) { const u = new URL(url); return `${u.protocol}//${u.host}`; }
const sameSite = (a, b) => hostOf(a).replace(/^www\./, "") === hostOf(b).replace(/^www\./, "");

export function keywordScore(text, keywords) {
  const t = String(text || "").toLowerCase().replace(/[-_+]/g, " ");
  return keywords.reduce((n, k) => n + (k && t.includes(k.toLowerCase().replace(/[-_+]/g, " ")) ? 1 : 0), 0);
}

export function linksOf(doc, pageUrl) {
  const out = new Map();
  for (const a of doc.querySelectorAll("a[href]")) {
    const url = resolve(a.getAttribute("href"), pageUrl);
    if (!url || !url.startsWith("http")) continue;
    const u = cleanUrl(url);
    if (SKIP.test(u)) continue;
    const title = (a.textContent || a.getAttribute("title") || "").replace(/\s+/g, " ").trim().slice(0, 150);
    const prev = out.get(u);
    if (!prev || title.length > prev.title.length) out.set(u, { url: u, title });
  }
  return [...out.values()];
}

async function shopifyProducts(startUrl) {
  const out = [];
  for (let page = 1; page < 40; page++) {
    const data = await fetchJson(`${origin(startUrl)}/products.json?limit=250&page=${page}`);
    if (!data || !Array.isArray(data.products) || !data.products.length) return page === 1 ? null : out;
    for (const p of data.products) {
      out.push({ url: `${origin(startUrl)}/products/${p.handle}`, title: p.title || "", type: [p.product_type, ...(p.tags || [])].filter(Boolean).join(", "), shopify: p });
    }
  }
  return out;
}

async function wooProducts(startUrl) {
  const out = [];
  for (let page = 1; page < 60; page++) {
    const data = await fetchJson(`${origin(startUrl)}/wp-json/wc/store/v1/products?per_page=100&page=${page}`);
    if (!Array.isArray(data) || !data.length) return page === 1 ? null : out;
    for (const p of data) {
      if (!p.permalink) continue;
      const div = new DOMParser().parseFromString(p.name || "", "text/html");
      out.push({ url: p.permalink, title: div.body.textContent.trim(), type: (p.categories || []).map((c) => c.name).join(", ") });
    }
  }
  return out;
}

async function sitemapProducts(startUrl, keywords) {
  const todo = [`${origin(startUrl)}/sitemap.xml`, `${origin(startUrl)}/sitemap_index.xml`, `${origin(startUrl)}/product-sitemap.xml`];
  const seen = new Set();
  const out = new Map();
  while (todo.length && seen.size < 30) {
    const sm = todo.shift();
    if (seen.has(sm)) continue;
    seen.add(sm);
    const r = await fetchResponse(sm);
    if (!r) continue;
    const xml = await r.text();
    for (const [, loc] of xml.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/g)) {
      if (/\.xml(\.gz)?$/.test(loc)) { if (/product|page|post/i.test(loc)) todo.push(loc); }
      else if (PRODUCT_HINT.test(new URL(loc).pathname) || keywordScore(decodeURIComponent(loc), keywords)) out.set(loc, { url: loc, title: decodeURIComponent(loc.split("/").filter(Boolean).pop() || "").replace(/-/g, " ") });
    }
  }
  return [...out.values()];
}

function pageIsProduct(doc) {
  if (doc.querySelector('meta[property="og:type"][content*="product" i]')) return true;
  return [...doc.querySelectorAll('script[type="application/ld+json"]')].some((s) => /"@type"\s*:\s*"Product"/.test(s.textContent));
}

// Guided crawl: follows the pages most likely to list this product type first.
async function crawl({ startUrl, startHtml, keywords, seedLinks, maxPages, log }) {
  const found = new Map();
  const queued = new Map([[startUrl, 100]]);
  for (const s of seedLinks) queued.set(s, 50);
  const visited = new Set();
  while (queued.size && visited.size < maxPages) {
    const [page] = [...queued.entries()].sort((a, b) => b[1] - a[1])[0];
    queued.delete(page);
    visited.add(page);
    const got = await getPage(page, { preRendered: page === startUrl ? startHtml : null });
    if (!got) continue;
    if (pageIsProduct(got.doc)) {
      const h1 = got.doc.querySelector("h1")?.textContent.trim() || got.doc.title;
      if (!found.has(page)) found.set(page, { url: page, title: h1 });
    }
    for (const l of linksOf(got.doc, page)) {
      if (!sameSite(l.url, startUrl) || visited.has(l.url)) continue;
      const path = new URL(l.url).pathname;
      const kw = keywordScore(`${l.title} ${decodeURIComponent(path)}`, keywords);
      if (PRODUCT_HINT.test(path) || kw) {
        const prev = found.get(l.url);
        if (!prev) found.set(l.url, { url: l.url, title: l.title });
        else if (l.title.length > prev.title.length) prev.title = l.title;
      }
      let score = kw * 10;
      if (PAGINATION.test(l.url)) score += 8;
      if (LISTING_HINT.test(path)) score += 4;
      if (PRODUCT_HINT.test(path)) score += 1;
      if (score > 0) queued.set(l.url, Math.max(queued.get(l.url) || 0, score));
    }
    log?.(`נסרקו ${visited.size} דפים באתר, ${found.size} קישורים אפשריים למוצרים`);
  }
  return [...found.values()];
}

export async function discover({ startUrl, startHtml, keywords, seedLinks = [], maxPages = 60, log }) {
  const shop = await shopifyProducts(startUrl);
  if (shop?.length) { log?.(`זוהתה חנות Shopify: ${shop.length} מוצרים באתר`); return shop; }
  const woo = await wooProducts(startUrl);
  if (woo?.length) { log?.(`זוהתה חנות WooCommerce: ${woo.length} מוצרים באתר`); return woo; }
  let items = await crawl({ startUrl, startHtml, keywords, seedLinks, maxPages, log });
  if (items.length < 3) {
    const more = await sitemapProducts(startUrl, keywords);
    log?.(`מפת האתר: ${more.length} קישורים נוספים`);
    const seen = new Set(items.map((i) => i.url));
    items = items.concat(more.filter((m) => !seen.has(m.url)));
  }
  return items.slice(0, 1500);
}
