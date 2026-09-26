// Runs one job automatically: site + product type in -> Hebrew HTML pages + WooCommerce CSV out.
import { identifyManufacturer, planSearch, selectProducts, writeHebrew } from "./lib/claude.bundle.js";
import { escapeHtml as e, fileStem, hostOf, isOfficial } from "./lib/common.js";
import { discover, linksOf } from "./lib/discover.js";
import { emptyRaw, extractPage, modelKeyOf, officialLinksFrom, pageText, scanDocuments } from "./lib/extract.js";
import { getPage } from "./lib/fetchpage.js";
import { blobToBase64, downloadDocuments, downloadImages, saveText } from "./lib/media.js";
import { indexHtml, productPageHtml, productsCsv } from "./lib/output.js";
import { loadSettings } from "./lib/settings.js";

const MAX_PDF_FOR_CLAUDE = 10 * 1024 * 1024;
const $ = (id) => document.getElementById(id);
const jobId = new URLSearchParams(location.search).get("job");
const job = (await chrome.storage.local.get(jobId))[jobId];
const settings = await loadSettings();

function log(msg, cls = "") {
  const li = document.createElement("li");
  li.textContent = `${new Date().toLocaleTimeString("he-IL")}  ${msg}`;
  if (cls) li.className = cls;
  $("log").prepend(li);
}
function progress(value, max) { $("progress").max = max; $("progress").value = value; }
function fail(msg) { log(msg, "err"); $("done").hidden = false; $("done").innerHTML = `<p class="err">${e(msg)}</p>`; }
function setRow(i, cells) {
  const tds = $(`r${i}`).children;
  cells.forEach((v, k) => { if (v !== undefined) tds[k].innerHTML = v; });
}

async function loadStyleExamples() {
  const urls = settings.styleExampleUrls.split(/\s+/).filter((u) => /^https?:\/\//.test(u));
  const { styleCache } = await chrome.storage.local.get("styleCache");
  if (styleCache && styleCache.key === urls.join(" ") && Date.now() - styleCache.at < 7 * 864e5) return styleCache.examples;
  const examples = [];
  for (const url of urls) {
    const page = await getPage(url, { allowRender: false });
    if (page) examples.push({ url, text: pageText(page.doc) });
    else log(`⚠ לא הצלחתי לטעון דף דוגמה: ${url}`, "warn");
  }
  await chrome.storage.local.set({ styleCache: { key: urls.join(" "), at: Date.now(), examples } });
  return examples;
}

function cleanDomains(list) {
  return [...new Set((list || []).map((d) => String(d).trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "")).filter((d) => d.includes(".")))];
}

// Everything for one product page found on the site.
async function processProduct(c, ctxShared) {
  const { styleExamples, known, runFolder, stems } = ctxShared;
  const supplierHost = hostOf(c.url).replace(/^www\./, "");
  let raw = emptyRaw();
  const preRendered = c.url === job.startUrl ? job.startHtml : null;
  await extractPage({ officialDomains: [] }, c.url, raw, { shopify: c.shopify, preRendered });
  if (!raw.productPages.length) throw new Error("הדף לא נטען");

  // Who makes it, and where is the manufacturer's official site?
  const ident = await identifyManufacturer(settings, { name: raw.name, url: c.url, excerpt: raw.descriptions[0]?.text || "", known });
  let domains = cleanDomains(ident.official_domains);
  if (ident.site_is_manufacturer) domains = [...new Set([...domains, supplierHost])];
  else domains = domains.filter((d) => d !== supplierHost);
  const ctx = { manufacturer: ident.manufacturer.trim() || raw.name.split(" ")[0], officialDomains: domains };
  if (!known.some((k) => k.manufacturer === ctx.manufacturer)) known.push({ manufacturer: ctx.manufacturer, official_domains: domains });
  const key = modelKeyOf(ident.model || raw.name, ctx.manufacturer);

  if (ident.site_is_manufacturer) {
    raw = emptyRaw();
    await extractPage(ctx, c.url, raw, { shopify: c.shopify, preRendered });
  } else {
    const officialUrls = [ident.official_product_url, ...(await officialLinksFrom(ctx, c.url, key))]
      .filter((u) => u && isOfficial(u, domains));
    for (const u of [...new Set(officialUrls)].slice(0, 3)) await extractPage(ctx, u, raw);
  }
  await scanDocuments(ctx, ident.official_downloads_url, raw, key);
  raw.manufacturer = ctx.manufacturer;

  let stem = fileStem(ctx.manufacturer, ident.model || raw.name);
  for (let n = 2; stems.has(stem); n++) stem = `${fileStem(ctx.manufacturer, ident.model || raw.name)}-${n}`;
  stems.add(stem);
  const folder = `${runFolder}/${stem}`;
  const images = await downloadImages(ctx, raw, folder, stem);
  const documents = await downloadDocuments(ctx, raw, folder, stem);

  // The official brochure/catalogue is read by Claude too (more complete specs than the web page).
  const pdfs = [];
  const brochure = documents.find((d) => d.kind === "brochure" && d.blob && d.blob.size <= MAX_PDF_FOR_CLAUDE);
  const manual = documents.find((d) => d.kind === "manual" && d.blob && d.blob.size <= MAX_PDF_FOR_CLAUDE / 2);
  for (const d of [brochure || manual].filter(Boolean)) pdfs.push({ title: d.file.split("/").pop(), base64: await blobToBase64(d.blob) });
  const opts = { glossary: settings.glossary, styleExamples, pdfs };
  let result;
  try {
    result = await writeHebrew(settings, raw, opts);
  } catch (err) {
    if (!pdfs.length) throw err;
    log(`${raw.name}: הברושור לא נקרא (${err.message}), ממשיך בלעדיו`, "warn");
    result = await writeHebrew(settings, raw, { ...opts, pdfs: [] });
  }

  const warnings = [...result.problems];
  if (!domains.length) warnings.push("לא נמצא אתר רשמי של היצרן");
  if (images.length < 3) warnings.push(`נמצאו ${images.length} תמונות באתר היצרן (המטרה 3-5)`);
  if (!documents.some((d) => d.kind === "brochure" && d.file)) warnings.push("לא נמצא ברושור באתר היצרן");
  if (!documents.some((d) => d.kind === "manual" && d.file)) warnings.push("לא נמצא מדריך למשתמש באתר היצרן");
  if (!raw.videos.length) warnings.push("לא נמצא סרטון YouTube באתר היצרן");

  const product = {
    ...raw, stem, model: ident.model || raw.name, officialDomains: domains, productType: job.productType,
    content: result.content, images, documents, warnings,
  };
  await saveText(productPageHtml(product), `${folder}/${stem}.html`, "text/html;charset=utf-8");
  return product;
}

async function main() {
  $("job").innerHTML = `<b>${e(job.productType)}</b> · <span class="ltr">${e(job.startUrl)}</span>`;
  if (!settings.apiKey) return fail("חסר מפתח API של Claude. פתחו את הגדרות התוסף והדביקו מפתח.");

  log("טוען דפי דוגמה לסגנון מהאתר שלכם…");
  const styleExamples = await loadStyleExamples();

  log("פותח את האתר…");
  const start = await getPage(job.startUrl, { preRendered: job.startHtml });
  if (!start) return fail("לא הצלחתי לפתוח את האתר.");
  const startLinks = linksOf(start.doc, job.startUrl).filter((l) => hostOf(l.url).replace(/^www\./, "") === hostOf(job.startUrl).replace(/^www\./, "")).slice(0, 400);
  const plan = await planSearch(settings, job.productType, job.startUrl, startLinks);
  log(`מילות חיפוש: ${plan.keywords.join(", ")}`);

  log("מחפש מוצרים באתר…");
  const candidates = await discover({
    startUrl: job.startUrl, startHtml: job.startHtml, keywords: plan.keywords,
    seedLinks: plan.links.filter((i) => startLinks[i]).map((i) => startLinks[i].url), log,
  });
  if (!candidates.length) return fail("לא נמצאו מוצרים באתר.");
  log(`Claude בודק ${candidates.length} קישורים ומשאיר רק ${job.productType}…`);
  const picked = (await selectProducts(settings, job.productType, candidates)).map((i) => candidates[i]);
  const max = Math.max(1, parseInt(settings.maxProducts, 10) || 100);
  if (picked.length > max) log(`נמצאו ${picked.length} מוצרים, מעבד את ${max} הראשונים (אפשר לשנות בהגדרות)`, "warn");
  const chosen = picked.slice(0, max);
  if (!chosen.length) return fail(`לא נמצאו באתר מוצרים מסוג "${job.productType}".`);
  log(`נמצאו ${chosen.length} מוצרים מסוג "${job.productType}"`, "ok");

  $("results").hidden = false;
  $("resultRows").innerHTML = chosen.map((c, i) =>
    `<tr id="r${i}"><td>${e(c.title || c.url)}<div class="url">${e(c.url)}</div></td><td></td><td></td><td></td><td></td><td>ממתין</td></tr>`).join("");

  const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
  const runFolder = `${settings.outputFolder}/${hostOf(job.startUrl).replace(/^www\./, "")}-${stamp}`;
  const shared = { styleExamples, known: [], runFolder, stems: new Set() };
  const products = [];
  for (const [i, c] of chosen.entries()) {
    setRow(i, [undefined, undefined, undefined, undefined, undefined, "בעבודה…"]);
    try {
      const p = await processProduct(c, shared);
      products.push(p);
      setRow(i, [`${e(p.content.name)}<div class="url">${e(c.url)}</div>`, e(p.manufacturer),
        String(p.images.length), String(p.videos.length), String(p.documents.filter((d) => d.file).length),
        p.warnings.length ? `<span class="warn" title="${e(p.warnings.join("\n"))}">✓ עם הערות</span>` : `<span class="ok">✓</span>`]);
    } catch (err) {
      log(`${c.url}: ${err.message}`, "err");
      setRow(i, [undefined, undefined, undefined, undefined, undefined, `<span class="err">שגיאה: ${e(err.message)}</span>`]);
    }
    progress(i + 1, chosen.length);
  }
  if (!products.length) return fail("לא נוצרו מוצרים.");

  await saveText(indexHtml(products, job), `${runFolder}/index.html`, "text/html;charset=utf-8");
  await saveText(productsCsv(products, job, settings), `${runFolder}/products.csv`, "text/csv;charset=utf-8");
  await saveText(JSON.stringify({ job: { ...job, startHtml: undefined }, products }, null, 2), `${runFolder}/data.json`, "application/json");
  await chrome.storage.local.remove(jobId);

  $("done").hidden = false;
  $("done").innerHTML = `
    <p class="ok"><b>סיום: ${products.length} מוצרים מוכנים.</b> נשמר בתיקיית ההורדות: <span class="ltr">${e(runFolder)}</span></p>
    <ul>
      <li><b>index.html</b>: רשימת כל המוצרים, עם קישור לדף ה-HTML של כל מוצר.</li>
      <li>תיקייה לכל מוצר: דף HTML בעברית, התמונות, הברושור והמדריך למשתמש.</li>
      <li><b>products.csv</b>: לייבוא לווקומרס (בוורדפרס: מוצרים ← ייבוא). המוצרים ייכנסו ${settings.publishStatus === "1" ? "מפורסמים" : "כטיוטה"}.</li>
    </ul>
    <div class="row"><button id="openFolder">פתח את תיקיית ההורדות</button></div>`;
  $("openFolder").onclick = () => chrome.downloads.showDefaultFolder();
}

main().catch((err) => fail(`שגיאה: ${err.message}`));
