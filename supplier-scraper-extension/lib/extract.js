// Pull raw product facts, images, videos and PDFs out of product pages.
// Assets (images, PDFs, YouTube links) are kept ONLY from pages on the manufacturer's
// official domains. An image served from the site's own CDN still counts: the official
// page is what vouches for it.
import { cleanUrl, escapeRegex, isOfficial, lastSegment, normKey, resolve } from "./common.js";
import { getPage } from "./fetchpage.js";

const MANUAL_WORDS = ["manual", "user guide", "userguide", "user-guide", "instruction", "operating", "handbuch",
  "bedienungsanleitung", "anleitung", "quick start", "quickstart", "guide"];
const BROCHURE_WORDS = ["brochure", "datasheet", "data sheet", "data-sheet", "catalog", "catalogue", "leaflet", "flyer",
  "prospekt", "spec sheet", "specification", "datenblatt"];
const SKIP_IMG = /(logo|icon|sprite|placeholder|avatar|badge|flag|payment|banner|favicon|loader|spinner)/i;
const YT_ID = /(?:youtube(?:-nocookie)?\.com\/(?:embed\/|watch\?v=|v\/|shorts\/)|youtu\.be\/)([A-Za-z0-9_-]{11})/;
const PRODUCT_LINK = /\/(products?|produkte?|produits?|product-details)\/[^/?#]+/i;
const NOISE = "script,style,noscript,nav,header,footer,form,svg,iframe";

export function classifyPdf(url, label) {
  let path = url;
  try { path = new URL(url).pathname; } catch {}
  const text = `${label} ${decodeURIComponent(path)}`.toLowerCase().replace(/_/g, " ");
  if (MANUAL_WORDS.some((w) => text.includes(w))) return "manual";
  if (BROCHURE_WORDS.some((w) => text.includes(w))) return "brochure";
  return "document";
}

export function youtubeUrl(src) {
  const m = String(src).match(YT_ID);
  return m ? `https://www.youtube.com/watch?v=${m[1]}` : null;
}

function jsonLdProducts(doc) {
  const out = [];
  for (const s of doc.querySelectorAll('script[type="application/ld+json"]')) {
    let data;
    try { data = JSON.parse(s.textContent); } catch { continue; }
    const stack = [data];
    while (stack.length) {
      const d = stack.pop();
      if (Array.isArray(d)) stack.push(...d);
      else if (d && typeof d === "object") {
        const t = d["@type"];
        if (t === "Product" || (Array.isArray(t) && t.includes("Product"))) out.push(d);
        stack.push(...Object.values(d).filter((v) => v && typeof v === "object"));
      }
    }
  }
  return out;
}

function meta(doc, prop) {
  const el = doc.querySelector(`meta[property="${prop}"]`) || doc.querySelector(`meta[name="${prop}"]`);
  return (el?.getAttribute("content") || "").trim();
}

function canonicalImage(url) {
  return url
    .replace(/-\d{2,4}x\d{2,4}(?=\.(jpe?g|png|webp)$)/i, "")   // WordPress thumbnails
    .replace(/_(\d{2,4}x\d{0,4}|\d{0,4}x\d{2,4}|small|medium|large|grande|compact)(?=\.(jpe?g|png|webp))/i, ""); // Shopify
}

function imgSrc(img, base) {
  for (const attr of ["data-large_image", "data-zoom-image", "data-src", "data-lazy-src", "data-original", "src"]) {
    const v = img.getAttribute(attr);
    if (v && !v.startsWith("data:")) return resolve(v, base);
  }
  const srcset = img.getAttribute("srcset") || img.getAttribute("data-srcset");
  if (srcset) return resolve(srcset.split(",").pop().trim().split(" ")[0], base);
  return null;
}

function mainRegion(doc) {
  for (const sel of ["main", "article", "[class*=product]", "#content", ".content", "body"]) {
    const el = doc.querySelector(sel);
    if (el && el.textContent.trim().length > 200) return el;
  }
  return doc.body || doc.documentElement;
}

function textBlocks(node) {
  const clone = node.cloneNode(true);
  clone.querySelectorAll(NOISE).forEach((n) => n.remove());
  const lines = [];
  for (const el of clone.querySelectorAll("h1,h2,h3,h4,p,li,td,th,dt,dd")) {
    const t = el.textContent.replace(/\s+/g, " ").trim();
    if (!t || lines[lines.length - 1]?.endsWith(t)) continue;
    const tag = el.tagName.toLowerCase();
    lines.push((/^h\d$/.test(tag) ? "## " : tag === "li" ? "- " : "") + t);
  }
  return lines.join("\n").slice(0, 40000);
}

function specs(node) {
  const out = [];
  const seen = new Set();
  const add = (k, v) => {
    const key = k + "\u0000" + v;
    if (k && v && !seen.has(key) && k.length < 120 && v.length < 600) { seen.add(key); out.push([k, v]); }
  };
  for (const tr of node.querySelectorAll("table tr")) {
    const cells = [...tr.querySelectorAll("th,td")].map((c) => c.textContent.replace(/\s+/g, " ").trim()).filter(Boolean);
    if (cells.length >= 2) add(cells[0], cells.slice(1).join(" | "));
  }
  for (const dt of node.querySelectorAll("dl dt")) {
    const dd = dt.nextElementSibling;
    if (dd?.tagName === "DD") add(dt.textContent.trim(), dd.textContent.trim());
  }
  return out.slice(0, 150);
}

function addUnique(list, item) {
  if (!list.some((x) => x.url === item.url)) list.push(item);
}

export function emptyRaw(manufacturer) {
  return { manufacturer, name: "", productPages: [], descriptions: [], specs: [], images: [], videos: [], documents: [], officialLinks: [] };
}

export async function extractPage(job, url, raw, { shopify = null, preRendered = null } = {}) {
  const official = isOfficial(url, job.officialDomains);
  const page = await getPage(url, { preRendered });
  if (!page) return;
  const { doc } = page;
  raw.productPages.push({ url, official });

  const ld = jsonLdProducts(doc);
  const h1 = doc.querySelector("h1");
  let name = shopify?.title || ld[0]?.name || h1?.textContent.trim() || meta(doc, "og:title");
  const firstOfficial = official && !raw.productPages.slice(0, -1).some((p) => p.official);
  if (name && (!raw.name || firstOfficial)) raw.name = name.replace(/\s+/g, " ").trim();

  const main = mainRegion(doc);
  const parts = [];
  if (shopify?.body_html) parts.push(textBlocks(new DOMParser().parseFromString(shopify.body_html, "text/html").body));
  for (const d of ld) if (d.description) parts.push(String(d.description).replace(/<[^>]+>/g, " "));
  if (meta(doc, "og:description")) parts.push(meta(doc, "og:description"));
  parts.push(textBlocks(main));
  raw.descriptions.push({ source: url, official, text: parts.filter(Boolean).join("\n\n") });
  for (const kv of specs(main)) if (!raw.specs.some(([k, v]) => k === kv[0] && v === kv[1])) raw.specs.push(kv);

  if (!official) {
    // A distributor page often links to the manufacturer's page for the same product.
    for (const a of doc.querySelectorAll("a[href]")) {
      const link = resolve(a.getAttribute("href"), url);
      if (link && isOfficial(link, job.officialDomains) && PRODUCT_LINK.test(new URL(link).pathname) && !link.includes("category")
          && !raw.officialLinks.includes(cleanUrl(link))) raw.officialLinks.push(cleanUrl(link));
    }
    return; // assets only from the manufacturer's own site
  }

  // Images: structured sources first (best quality, product-specific), then the page gallery.
  const imgs = [];
  for (const i of shopify?.images || []) if (i.src) imgs.push([i.src, i.alt || ""]);
  for (const d of ld) for (const i of [].concat(d.image || [])) {
    const src = typeof i === "string" ? i : i?.url;
    if (src) imgs.push([resolve(src, url), ""]);
  }
  if (meta(doc, "og:image")) imgs.push([resolve(meta(doc, "og:image"), url), ""]);
  let gallery = main.querySelectorAll("[class*=gallery] img, [class*=Gallery] img, [class*=slider] img, [class*=product] img, figure img");
  if (!gallery.length) gallery = main.querySelectorAll("img");
  for (const img of gallery) { const s = imgSrc(img, url); if (s) imgs.push([s, img.getAttribute("alt") || ""]); }
  for (const a of main.querySelectorAll("a[href]")) {
    if (/\.(jpe?g|png|webp)(\?|$)/i.test(a.getAttribute("href"))) imgs.push([resolve(a.getAttribute("href"), url), a.textContent.trim()]);
  }
  for (let [src, alt] of imgs) {
    if (!src) continue;
    if (src.startsWith("//")) src = "https:" + src;
    src = canonicalImage(src);
    const path = new URL(src).pathname.toLowerCase();
    if (SKIP_IMG.test(path) || path.endsWith(".svg") || path.endsWith(".gif")) continue;
    addUnique(raw.images, { url: src, alt, sourcePage: url });
  }

  // YouTube: embeds and links on the official page.
  for (const el of doc.querySelectorAll("iframe, a[href], lite-youtube, [data-video-id], [data-src*=youtu]")) {
    let src = el.getAttribute("src") || el.getAttribute("data-src") || el.getAttribute("href") || "";
    const id = el.getAttribute("videoid") || el.getAttribute("data-video-id");
    if (!youtubeUrl(src) && id && /^[A-Za-z0-9_-]{11}$/.test(id)) src = `https://youtu.be/${id}`;
    const yt = youtubeUrl(src);
    if (yt) addUnique(raw.videos, { url: yt, title: el.getAttribute("title") || el.textContent.trim().slice(0, 120), sourcePage: url });
  }

  // PDFs linked from the official page.
  for (const a of doc.querySelectorAll("a[href]")) {
    const href = resolve(a.getAttribute("href"), url);
    if (!href) continue;
    const label = (a.textContent || a.getAttribute("title") || "").replace(/\s+/g, " ").trim();
    if (/\.pdf(\?|$)/i.test(href) || (/download/i.test(href) && /pdf/i.test(label))) {
      addUnique(raw.documents, { url: href, kind: classifyPdf(href, label), label, sourcePage: url });
    }
  }
}

// PDFs on official "Downloads" pages, matched to products by model name.
export async function matchDownloadPages(job, raws) {
  for (const page of job.downloadsPages || []) {
    if (!isOfficial(page, job.officialDomains)) continue;
    const got = await getPage(page);
    if (!got) continue;
    for (const a of got.doc.querySelectorAll("a[href]")) {
      const href = resolve(a.getAttribute("href"), page);
      if (!href || !/\.pdf(\?|$)/i.test(href)) continue;
      const label = a.textContent.trim();
      const ctx = a.closest("tr,li,div");
      const hay = normKey(`${label} ${href} ${ctx?.textContent || ""}`);
      for (const raw of raws) {
        const key = normKey(raw.name.replace(new RegExp(escapeRegex(job.manufacturer), "gi"), ""));
        if (key.length >= 3 && hay.includes(key)) addUnique(raw.documents, { url: href, kind: classifyPdf(href, label), label, sourcePage: page });
      }
    }
  }
}

// One product may be described on several pages (supplier + manufacturer).
export async function extractProduct(job, candidate) {
  const raw = emptyRaw(job.manufacturer);
  await extractPage(job, candidate.url, raw, { shopify: candidate.shopify, preRendered: candidate.preRendered });
  const key = normKey(raw.name.replace(new RegExp(escapeRegex(job.manufacturer), "gi"), ""));
  const visited = new Set(raw.productPages.map((p) => p.url));
  for (const link of raw.officialLinks) {
    const seg = normKey(lastSegment(link));
    if (!visited.has(link) && key && seg && (seg.includes(key) || key.includes(seg))) {
      await extractPage(job, link, raw);
      visited.add(link);
    }
  }
  delete raw.officialLinks;
  return raw;
}

// Main text of a page (used for the style examples from the shop's own site).
export function pageText(doc, maxChars = 3500) {
  return textBlocks(mainRegion(doc)).slice(0, maxChars);
}
