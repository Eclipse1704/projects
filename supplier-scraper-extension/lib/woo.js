// WooCommerce output: product description HTML (semantic, LLM friendly), the import CSV,
// and a preview page for checking everything before importing.
import { escapeHtml as e } from "./common.js";

const KIND_HE = { brochure: "ברושור", manual: "מדריך למשתמש" };

function fileUrl(settings, file, fallback) {
  return settings.imagesBaseUrl ? settings.imagesBaseUrl.replace(/\/?$/, "/") + file : fallback;
}

export function descriptionHtml(p, settings) {
  const c = p.content;
  const paras = String(c.overview || "").split(/\n\s*\n|\n/).filter((s) => s.trim()).map((s) => `<p>${e(s.trim())}</p>`).join("\n");
  const list = (items) => items.map((x) => `<li>${e(x)}</li>`).join("\n");
  const out = [`<section class="product-overview">\n<h2>סקירה כללית</h2>\n${paras}\n</section>`];
  if (c.usage?.length) out.push(`<section class="product-usage">\n<h2>שימושים</h2>\n<ul>\n${list(c.usage)}\n</ul>\n</section>`);
  if (c.features?.length) out.push(`<section class="product-features">\n<h2>תכונות עיקריות</h2>\n<ul>\n${list(c.features)}\n</ul>\n</section>`);
  if (c.specs?.length) {
    const rows = c.specs.map((s) => `<tr><th scope="row">${e(s.name)}</th><td dir="auto">${e(s.value)}</td></tr>`).join("\n");
    out.push(`<section class="product-specs">\n<h2>מפרט טכני</h2>\n<table>\n<tbody>\n${rows}\n</tbody>\n</table>\n</section>`);
  }
  if (p.videos.length) {
    // A bare YouTube URL in its own paragraph is auto-embedded by WordPress.
    out.push(`<section class="product-videos">\n<h2>סרטוני הדגמה</h2>\n${p.videos.map((v) => `<p>${e(v.url)}</p>`).join("\n")}\n</section>`);
  }
  const docs = p.documents.filter((d) => d.file);
  if (docs.length) {
    const items = docs.map((d) => `<li><a href="${e(fileUrl(settings, d.file, d.url))}" target="_blank" rel="noopener">${KIND_HE[d.kind]} (PDF)</a></li>`).join("\n");
    out.push(`<section class="product-downloads">\n<h2>קבצים להורדה</h2>\n<ul>\n${items}\n</ul>\n</section>`);
  }
  return out.join("\n\n");
}

const COLUMNS = ["Type", "SKU", "Name", "Published", "Is featured?", "Visibility in catalog", "Short description", "Description",
  "Tax status", "In stock?", "Categories", "Images", "Attribute 1 name", "Attribute 1 value(s)", "Attribute 1 visible",
  "Attribute 1 global", "Meta: _source_product_pages", "Meta: _source_youtube"];

function csvCell(v) {
  return `"${String(v ?? "").replace(/"/g, '""')}"`;
}

export function productsCsv(products, job, settings) {
  const rows = [COLUMNS.map(csvCell).join(",")];
  for (const p of products) {
    const images = p.images.map((i) => fileUrl(settings, i.file, i.url)).join(", ");
    rows.push([
      "simple", "", p.content.name, settings.publishStatus, "0", "visible",
      `<p>${e(p.content.short_description)}</p>`, descriptionHtml(p, settings),
      "taxable", "1", job.category || "", images,
      "מותג", job.manufacturer, "1", "0",
      p.productPages.map((x) => x.url).join(" "), p.videos.map((v) => v.url).join(" "),
    ].map(csvCell).join(","));
  }
  return "﻿" + rows.join("\r\n") + "\r\n";
}

export function previewHtml(products, job, settings) {
  const cards = products.map((p) => {
    const imgs = p.images.map((i) => `<figure><img src="images/${e(i.file)}" alt="${e(p.content.name)}" loading="lazy"><figcaption dir="ltr">${e(i.file)}</figcaption></figure>`).join("");
    const warn = p.warnings.length ? `<ul class="warn">${p.warnings.map((w) => `<li>${e(w)}</li>`).join("")}</ul>` : "";
    const pages = p.productPages.map((x) => `<li><a href="${e(x.url)}" dir="ltr">${e(x.url)}</a> ${x.official ? "(אתר היצרן הרשמי)" : "(אתר הספק)"}</li>`).join("");
    return `<article class="product" itemscope itemtype="https://schema.org/Product">
<h1 itemprop="name">${e(p.content.name)}</h1>
<p class="muted">יצרן: <span itemprop="brand">${e(job.manufacturer)}</span> · דגם במקור: <span dir="ltr">${e(p.name)}</span></p>
${warn}
<h2>תיאור קצר</h2>
<p itemprop="description">${e(p.content.short_description)}</p>
<h2>תמונות</h2>
${imgs ? `<div class="gallery">${imgs}</div>` : "<p class=\"muted\">לא נמצאו תמונות באתר היצרן הרשמי.</p>"}
<div class="desc">${descriptionHtml(p, settings)}</div>
<h2>קישורים לדף המוצר</h2>
<ul>${pages}</ul>
</article>`;
  }).join("\n<hr>\n");
  return `<!doctype html>
<html lang="he" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>תצוגה מקדימה - ${e(job.manufacturer)}</title>
<style>
body{font-family:system-ui,Arial,sans-serif;max-width:960px;margin:0 auto;padding:16px;line-height:1.6;color:#1a1a1a;background:#fff}
h1{font-size:1.6rem}h2{font-size:1.15rem;margin-top:1.5rem}hr{margin:3rem 0}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:6px 10px;text-align:start;vertical-align:top}th{background:#f5f5f5;width:35%}
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px}.gallery img{width:100%;height:170px;object-fit:contain;border:1px solid #eee}
figure{margin:0}figcaption,.muted{font-size:.8rem;color:#666}.warn{background:#fff4e0;border:1px solid #f0c36d;padding:8px 28px}
</style></head><body>
<p class="muted">${products.length} מוצרים · קטגוריה: ${e(job.category || "-")} · לייבוא: products.csv</p>
${cards}
</body></html>`;
}
