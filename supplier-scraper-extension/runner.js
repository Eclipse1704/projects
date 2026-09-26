// Runs one scraping job end to end: discover -> choose -> extract -> Hebrew -> downloads -> CSV.
import { selectProducts, writeHebrew } from "./lib/claude.bundle.js";
import { escapeHtml as e } from "./lib/common.js";
import { discover } from "./lib/discover.js";
import { extractProduct, matchDownloadPages, pageText } from "./lib/extract.js";
import { getPage } from "./lib/fetchpage.js";
import { downloadDocuments, downloadImages, saveText } from "./lib/media.js";
import { loadSettings } from "./lib/settings.js";
import { previewHtml, productsCsv } from "./lib/woo.js";

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

function pickProducts(candidates, preselected) {
  $("pick").hidden = false;
  $("pickRows").innerHTML = candidates.map((c, i) =>
    `<tr><td><input type="checkbox" data-i="${i}" ${preselected.has(i) ? "checked" : ""}></td>` +
    `<td>${e(c.title || "(ללא כותרת)")}${c.type ? ` <span class="hint">· ${e(c.type)}</span>` : ""}<div class="url">${e(c.url)}</div></td></tr>`).join("");
  const boxes = () => [...document.querySelectorAll("#pickRows input")];
  $("all").onclick = () => boxes().forEach((b) => { b.checked = true; });
  $("none").onclick = () => boxes().forEach((b) => { b.checked = false; });
  return new Promise((resolve) => {
    $("go").onclick = () => {
      $("pick").hidden = true;
      resolve(boxes().filter((b) => b.checked).map((b) => candidates[+b.dataset.i]));
    };
  });
}

function resultRow(i, name) {
  const tr = document.createElement("tr");
  tr.id = `r${i}`;
  tr.innerHTML = `<td>${e(name)}</td><td></td><td></td><td></td><td>ממתין…</td>`;
  $("resultRows").append(tr);
}
function updateRow(i, cells) {
  const tds = $(`r${i}`).children;
  cells.forEach((v, k) => { if (v !== undefined) tds[k].innerHTML = v; });
}

async function main() {
  $("job").innerHTML = `<b>${e(job.manufacturer)}</b> · ${e(job.productType || "כל המוצרים")} · <span class="ltr">${e(job.startUrl)}</span>`;
  if (!settings.apiKey) return fail("חסר מפתח API של Claude. פתחו את הגדרות התוסף והדביקו מפתח.");

  log("טוען דפי דוגמה לסגנון מהאתר שלכם…");
  const styleExamples = await loadStyleExamples();
  log(`נטענו ${styleExamples.length} דפי דוגמה`);

  let chosen;
  if (job.mode === "single") {
    chosen = [{ url: job.startUrl, title: "", preRendered: job.startHtml }];
  } else {
    log("מחפש מוצרים…");
    const candidates = await discover({ startUrl: job.startUrl, startHtml: job.startHtml, officialDomains: job.officialDomains, log });
    if (!candidates.length) return fail("לא נמצאו קישורים למוצרים בדף הזה. נסו לפתוח את דף הקטגוריה או את רשימת המוצרים של הספק.");
    let pre = new Set(candidates.map((_, i) => i));
    if (job.productType) {
      log(`Claude בוחר מתוך ${candidates.length} קישורים את המוצרים מסוג "${job.productType}"…`);
      pre = new Set(await selectProducts(settings, job.productType, candidates));
    }
    log(`נמצאו ${candidates.length} קישורים, ${pre.size} מתאימים`);
    chosen = (await pickProducts(candidates, pre)).slice(0, job.maxProducts);
    if (!chosen.length) return fail("לא נבחרו מוצרים.");
  }

  const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
  const folder = `${settings.outputFolder}/${job.supplierId}-${stamp}`;
  $("results").hidden = false;
  chosen.forEach((c, i) => resultRow(i, c.title || c.url));
  const total = chosen.length * 2 + 1;
  let step = 0;

  const raws = [];
  for (const [i, c] of chosen.entries()) {
    updateRow(i, [undefined, undefined, undefined, undefined, "סורק…"]);
    try {
      const raw = await extractProduct(job, c);
      if (!raw.productPages.length) throw new Error("הדף לא נטען");
      raw.index = i;
      raws.push(raw);
      updateRow(i, [e(raw.name), undefined, undefined, undefined, "נסרק"]);
    } catch (err) {
      updateRow(i, [undefined, undefined, undefined, undefined, `<span class="err">שגיאה: ${e(err.message)}</span>`]);
    }
    progress(++step, total);
  }
  await matchDownloadPages(job, raws);

  const products = [];
  for (const raw of raws) {
    const i = raw.index;
    try {
      updateRow(i, [undefined, undefined, undefined, undefined, "כותב בעברית…"]);
      const { content, problems } = await writeHebrew(settings, raw, { glossary: settings.glossary, styleExamples, category: job.category });
      updateRow(i, [undefined, undefined, undefined, undefined, "מוריד קבצים…"]);
      const images = await downloadImages(job, raw, folder, { log });
      const documents = await downloadDocuments(job, raw, folder);
      const warnings = [...problems];
      if (images.length < 3) warnings.push(`נמצאו רק ${images.length} תמונות באתר היצרן`);
      for (const k of ["brochure", "manual"]) if (!documents.some((d) => d.kind === k && d.file)) warnings.push(k === "brochure" ? "לא נמצא ברושור באתר היצרן" : "לא נמצא מדריך למשתמש באתר היצרן");
      if (!raw.videos.length) warnings.push("לא נמצא סרטון YouTube באתר היצרן");
      products.push({ ...raw, content, images, documents, warnings });
      const pdfs = documents.filter((d) => d.file).length;
      updateRow(i, [e(content.name), String(images.length), String(raw.videos.length), String(pdfs),
        warnings.length ? `<span class="warn">✓ עם הערות</span>` : `<span class="ok">✓</span>`]);
    } catch (err) {
      log(`${raw.name}: ${err.message}`, "err");
      updateRow(i, [undefined, undefined, undefined, undefined, `<span class="err">שגיאה: ${e(err.message)}</span>`]);
    }
    progress(++step, total);
  }
  if (!products.length) return fail("לא נוצרו מוצרים.");

  await saveText(productsCsv(products, job, settings), `${folder}/products.csv`, "text/csv;charset=utf-8");
  await saveText(previewHtml(products, job, settings), `${folder}/preview.html`, "text/html;charset=utf-8");
  await saveText(JSON.stringify({ job: { ...job, startHtml: undefined }, products }, null, 2), `${folder}/data.json`, "application/json");
  progress(total, total);
  await chrome.storage.local.remove(jobId);

  $("done").hidden = false;
  $("done").innerHTML = `
    <p class="ok"><b>סיום: ${products.length} מוצרים מוכנים.</b> הקבצים נשמרו בתיקיית ההורדות: <span class="ltr">${e(folder)}</span></p>
    <ol>
      <li>פתחו את <b>preview.html</b> ובדקו את הטקסטים והתמונות.</li>
      <li>${settings.imagesBaseUrl ? `העלו את התיקיות images ו-docs לכתובת <span class="ltr">${e(settings.imagesBaseUrl)}</span>.` : "ווקומרס ימשוך את התמונות ישירות מאתר היצרן בזמן הייבוא."}</li>
      <li>בוורדפרס: <b>מוצרים ← ייבוא</b>, בוחרים את <b>products.csv</b> ומאשרים. המוצרים ייכנסו ${settings.publishStatus === "1" ? "מפורסמים" : "כטיוטה"}.</li>
    </ol>
    <div class="row"><button id="openFolder">פתח את תיקיית ההורדות</button></div>`;
  $("openFolder").onclick = () => chrome.downloads.showDefaultFolder();
}

main().catch((err) => fail(`שגיאה: ${err.message}`));
