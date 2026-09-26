// Output files:
//   <STEM>/<STEM>.html  - one Hebrew, LLM-friendly HTML page per product (semantic sections + schema.org JSON-LD)
//   index.html          - list of all products with warnings
//   products.csv        - WooCommerce product import file
import { escapeHtml as e } from "./common.js";

const KIND_HE = { brochure: "ברושור", manual: "מדריך למשתמש" };
const NOT_FOUND = '<p class="missing">לא נמצא באתר היצרן הרשמי.</p>';

// Where a product's local file lives on the shop site (if the user uploads the output folder), else the official URL.
function siteUrl(settings, p, file, fallback) {
  return settings.imagesBaseUrl ? `${settings.imagesBaseUrl.replace(/\/?$/, "/")}${p.stem}/${file}` : fallback;
}

// The product description body (also the WooCommerce "Description").
export function descriptionHtml(p, docHref) {
  const c = p.content;
  const paras = String(c.overview || "").split(/\n\s*\n|\n/).filter((s) => s.trim()).map((s) => `<p>${e(s.trim())}</p>`).join("\n");
  const list = (items) => items.map((x) => `<li>${e(x)}</li>`).join("\n");
  const out = [`<section id="overview">\n<h3>סקירה כללית</h3>\n${paras}\n</section>`];
  if (c.usage?.length) out.push(`<section id="usage">\n<h3>שימושים ואופן שימוש</h3>\n<ul>\n${list(c.usage)}\n</ul>\n</section>`);
  if (c.features?.length) out.push(`<section id="features">\n<h3>תכונות עיקריות</h3>\n<ul>\n${list(c.features)}\n</ul>\n</section>`);
  if (c.specs?.length) {
    const rows = c.specs.map((s) => `<tr><th scope="row">${e(s.name)}</th><td dir="auto">${e(s.value)}</td></tr>`).join("\n");
    out.push(`<section id="specifications">\n<h3>מפרט טכני</h3>\n<table>\n<tbody>\n${rows}\n</tbody>\n</table>\n</section>`);
  }
  if (docHref) {
    if (p.videos.length) {
      // A bare YouTube URL in its own paragraph is auto-embedded by WordPress.
      out.push(`<section id="videos">\n<h3>סרטוני הדגמה</h3>\n${p.videos.map((v) => `<p>${e(v.url)}</p>`).join("\n")}\n</section>`);
    }
    const docs = p.documents.filter((d) => d.file);
    if (docs.length) {
      const items = docs.map((d) => `<li><a href="${e(docHref(d))}" target="_blank" rel="noopener">${KIND_HE[d.kind]} (PDF)</a></li>`).join("\n");
      out.push(`<section id="downloads">\n<h3>קבצים להורדה</h3>\n<ul>\n${items}\n</ul>\n</section>`);
    }
  }
  return out.join("\n\n");
}

function jsonLd(p) {
  const c = p.content;
  const official = p.productPages.find((x) => x.official)?.url || p.productPages[0]?.url || "";
  return {
    "@context": "https://schema.org",
    "@type": "Product",
    name: c.name,
    alternateName: p.name,
    model: p.model || p.name,
    brand: { "@type": "Brand", name: p.manufacturer },
    manufacturer: { "@type": "Organization", name: p.manufacturer, url: p.officialDomains[0] ? `https://${p.officialDomains[0]}` : undefined },
    category: p.productType,
    description: c.short_description,
    url: official,
    image: p.images.map((i) => i.file),
    subjectOf: [
      ...p.videos.map((v) => ({ "@type": "VideoObject", name: v.title || c.name, url: v.url, embedUrl: v.url })),
      ...p.documents.filter((d) => d.file).map((d) => ({ "@type": "DigitalDocument", name: KIND_HE[d.kind], url: d.file, encodingFormat: "application/pdf" })),
    ],
    additionalProperty: c.specs.map((s) => ({ "@type": "PropertyValue", name: s.name, value: s.value })),
    inLanguage: "he",
  };
}

const PAGE_CSS = `body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;max-width:960px;margin:0 auto;padding:16px;line-height:1.6;color:#1a1a1a;background:#fff}
h1{font-size:1.7rem;margin-bottom:.2rem}h2{border-bottom:1px solid #ddd;padding-bottom:4px;margin-top:2rem;font-size:1.3rem}h3{font-size:1.1rem}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:6px 10px;text-align:start;vertical-align:top}th{background:#f5f5f5;width:35%}
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px}.gallery img{width:100%;height:180px;object-fit:contain;border:1px solid #eee;background:#fafafa}
figure{margin:0}figcaption,.meta,.missing{font-size:.85rem;color:#666}.warn{background:#fff4e0;border:1px solid #f0c36d;padding:8px 28px}
a{color:#0b5cad}.ltr{direction:ltr;unicode-bidi:embed}`;

export function productPageHtml(p) {
  const c = p.content;
  const videos = p.videos.map((v) => `<li><a href="${e(v.url)}" class="ltr">${e(v.title || v.url)}</a> <span class="meta">(מקור: <a href="${e(v.sourcePage)}" class="ltr">${e(v.sourcePage)}</a>)</span></li>`).join("\n");
  const images = p.images.map((i, n) => `<figure><a href="${e(i.file)}"><img src="${e(i.file)}" alt="${e(c.name)} - תמונה ${n + 1}"></a><figcaption class="ltr">${e(i.file.split("/").pop())}</figcaption></figure>`).join("\n");
  const doc = (kind) => {
    const d = p.documents.find((x) => x.kind === kind && x.file);
    return d ? `<p><a href="${e(d.file)}">${e(d.file.split("/").pop())}</a> <span class="meta">(מקור: <a href="${e(d.url)}" class="ltr">${e(d.url)}</a>)</span></p>` : NOT_FOUND;
  };
  const pages = p.productPages.map((x) => `<li><a href="${e(x.url)}" class="ltr">${e(x.url)}</a> ${x.official ? "(אתר היצרן הרשמי)" : "(אתר הספק)"}</li>`).join("\n");
  return `<!doctype html>
<html lang="he" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${e(c.name)}</title>
<meta name="description" content="${e(c.short_description)}">
<script type="application/ld+json">${JSON.stringify(jsonLd(p), null, 1).replace(/</g, "\\u003c")}</script>
<style>${PAGE_CSS}</style>
</head>
<body>
<article itemscope itemtype="https://schema.org/Product" data-manufacturer="${e(p.manufacturer)}" data-model="${e(p.model || p.name)}">
<header>
<h1 id="product-name" itemprop="name">${e(c.name)}</h1>
<p class="meta">יצרן: <span itemprop="brand">${e(p.manufacturer)}</span> · דגם: <span class="ltr">${e(p.model || p.name)}</span> · סוג מוצר: ${e(p.productType)}</p>
</header>
<section id="short-description">
<h2>תיאור קצר</h2>
<p itemprop="description">${e(c.short_description)}</p>
</section>

<section id="full-description">
<h2>תיאור מלא</h2>
${descriptionHtml(p, null)}
</section>

<section id="videos">
<h2>סרטוני הדגמה ב-YouTube</h2>
${videos ? `<ul>\n${videos}\n</ul>` : NOT_FOUND}
</section>

<section id="images">
<h2>תמונות המוצר</h2>
${images ? `<div class="gallery">\n${images}\n</div>` : NOT_FOUND}
</section>

<section id="brochure">
<h2>ברושור</h2>
${doc("brochure")}
</section>

<section id="manual">
<h2>מדריך למשתמש</h2>
${doc("manual")}
</section>

<section id="product-pages">
<h2>קישורים לדף המוצר</h2>
<ul>
${pages}
</ul>
</section>
</article>
</body>
</html>
`;
}

export function indexHtml(products, job) {
  const rows = products.map((p) => `<li><h2><a href="${e(p.stem)}/${e(p.stem)}.html">${e(p.content.name)}</a></h2>
<p>${e(p.content.short_description)}</p>
<p class="meta">${p.images.length} תמונות · ${p.videos.length} סרטונים · ${p.documents.filter((d) => d.file).length} קובצי PDF</p>
${p.warnings.length ? `<ul class="warn">${p.warnings.map((w) => `<li>${e(w)}</li>`).join("")}</ul>` : ""}</li>`).join("\n");
  return `<!doctype html>
<html lang="he" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${e(job.productType)} - ${e(new URL(job.startUrl).hostname)}</title>
<style>${PAGE_CSS} ul.products{list-style:none;padding:0}ul.products>li{border-bottom:1px solid #ddd;padding-bottom:1rem}ul.products h2{border:0;font-size:1.2rem}</style></head>
<body><h1>${e(job.productType)}</h1>
<p class="meta">מקור: <a href="${e(job.startUrl)}" class="ltr">${e(job.startUrl)}</a> · ${products.length} מוצרים · קובץ ייבוא לווקומרס: products.csv</p>
<ul class="products">
${rows}
</ul></body></html>`;
}

const COLUMNS = ["Type", "SKU", "Name", "Published", "Is featured?", "Visibility in catalog", "Short description", "Description",
  "Tax status", "In stock?", "Categories", "Images", "Attribute 1 name", "Attribute 1 value(s)", "Attribute 1 visible",
  "Attribute 1 global", "Meta: _source_product_pages", "Meta: _source_youtube"];

const csvCell = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;

export function productsCsv(products, job, settings) {
  const rows = [COLUMNS.map(csvCell).join(",")];
  for (const p of products) {
    const images = p.images.map((i) => siteUrl(settings, p, i.file, i.url)).join(", ");
    const desc = descriptionHtml(p, (d) => siteUrl(settings, p, d.file, d.url));
    rows.push([
      "simple", "", p.content.name, settings.publishStatus, "0", "visible",
      `<p>${e(p.content.short_description)}</p>`, desc,
      "taxable", "1", job.productType, images,
      "מותג", p.manufacturer, "1", "0",
      p.productPages.map((x) => x.url).join(" "), p.videos.map((v) => v.url).join(" "),
    ].map(csvCell).join(","));
  }
  return "\uFEFF" + rows.join("\r\n") + "\r\n";
}
