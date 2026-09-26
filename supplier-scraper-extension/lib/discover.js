// Find the product pages reachable from the start page.
import { cleanUrl, hostOf, isOfficial, resolve } from "./common.js";
import { fetchJson, getPage } from "./fetchpage.js";

const PRODUCT_HINT = /\/(products?|produkte?|produits?|product-details|item|p)\/[^/?#]+/i;
const PAGINATION = /(\/page\/\d+\/?$|[?&](page|paged|p)=\d+)/i;
const CATEGORY = /\/(product-category|category|collections?|tag|kategorie)\/?[^/]*\/?$/i;

function origin(url) { const u = new URL(url); return `${u.protocol}//${u.host}`; }

async function shopifyProducts(startUrl) {
  const m = new URL(startUrl).pathname.match(/\/collections\/([^/?#]+)/);
  const root = m ? `${origin(startUrl)}/collections/${m[1]}` : origin(startUrl);
  const out = [];
  for (let page = 1; page < 40; page++) {
    const data = await fetchJson(`${root}/products.json?limit=250&page=${page}`);
    if (!data || !Array.isArray(data.products)) return page === 1 ? null : out;
    if (!data.products.length) return page === 1 ? null : out;
    for (const p of data.products) {
      out.push({ url: `${origin(startUrl)}/products/${p.handle}`, title: p.title || "", type: p.product_type || "", shopify: p });
    }
  }
  return out;
}

function looksLikeProduct(url, listing) {
  const path = new URL(url).pathname;
  if (PAGINATION.test(url) || CATEGORY.test(path)) return false;
  const lpath = new URL(listing).pathname.replace(/\/+$/, "");
  if (lpath && path.replace(/\/+$/, "") !== lpath && path.startsWith(lpath + "/")) return true;
  return PRODUCT_HINT.test(path);
}

async function crawl(startUrl, startHtml, officialDomains, maxPages, log) {
  const queue = [startUrl];
  const seen = new Set();
  const found = new Map();
  const hosts = new Set([hostOf(startUrl)]);
  const lpath = new URL(startUrl).pathname.replace(/\/+$/, "");
  while (queue.length && seen.size < maxPages) {
    const page = queue.shift();
    if (seen.has(page)) continue;
    seen.add(page);
    const got = await getPage(page, { preRendered: page === startUrl ? startHtml : null });
    if (!got) continue;
    for (const a of got.doc.querySelectorAll("a[href]")) {
      const url = resolve(a.getAttribute("href"), page);
      if (!url || !url.startsWith("http")) continue;
      const u = cleanUrl(url);
      if (!hosts.has(hostOf(u)) && !isOfficial(u, officialDomains)) continue;
      const rel = (a.getAttribute("rel") || "").toLowerCase();
      if (rel.includes("next") || (PAGINATION.test(u) && new URL(u).pathname.startsWith(lpath))) {
        if (!seen.has(u)) queue.push(u);
        continue;
      }
      if (looksLikeProduct(u, startUrl)) {
        const title = (a.textContent || a.getAttribute("title") || "").replace(/\s+/g, " ").trim();
        const prev = found.get(u);
        if (!prev) found.set(u, { url: u, title });
        else if (title.length > prev.title.length) prev.title = title;
      }
    }
    log?.(`נסרק דף קטלוג ${seen.size}: ${found.size} קישורים למוצרים עד עכשיו`);
  }
  return [...found.values()];
}

export async function discover({ startUrl, startHtml, officialDomains, maxPages = 15, log }) {
  const shop = await shopifyProducts(startUrl);
  if (shop) {
    log?.(`זוהתה חנות Shopify: ${shop.length} מוצרים`);
    return shop;
  }
  const items = await crawl(startUrl, startHtml, officialDomains, maxPages, log);
  return items.slice(0, 400);
}
