// End-to-end test of the Apps Script code under Node, with fake Google services, fake websites
// and a fake Claude Batches API. Run: node tests/test.mjs
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { makeGoogle } from "./fake-google.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
// A JPEG header with real dimensions (SOF0), then filler.
const jpeg = (w, h) => Buffer.concat([
  Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0]),
  Buffer.from([0xff, 0xc0, 0x00, 0x11, 0x08, h >> 8, h & 255, w >> 8, w & 255, 3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]),
  randomBytes(20000),
]);
const PDF = Buffer.concat([Buffer.from("%PDF-1.4\n"), Buffer.alloc(3000, 48)]);
const IMG = {
  "maker.test/img/x2000-main.jpg": jpeg(2000, 1500), "maker.test/img/x2000-main-300x300.jpg": jpeg(300, 300),
  "maker.test/img/x2000-side.jpg": jpeg(1600, 1200),
  "maker.test/img/x2000-probe.jpg": jpeg(1800, 1800), "maker.test/img/x2000-probe-150x150.jpg": jpeg(150, 150), "maker.test/img/x2000-probe-768x768.jpg": jpeg(768, 768),
  "maker.test/img/x2000-case.jpg": jpeg(500, 400),
  "maker.test/img/x1000-300x200.jpg": jpeg(300, 200),              // only a small version exists
  "thermo.test/cdn/226s-a.jpg": jpeg(2400, 1800), "thermo.test/cdn/226s-a_400x.jpg": jpeg(400, 300),
  "thermo.test/cdn/226s-b.jpg": jpeg(1200, 900), "thermo.test/cdn/226s-c.jpg": jpeg(1000, 1000),
  "supplier.test/img/dist.jpg": jpeg(2000, 2000),
};
const html = (body) => ({ body: `<!doctype html><html><head><title>t</title></head><body>${body}</body></html>` });

const SITES = {
  "www.ndt24.co.il/wp-json/wc/store/v1/products/categories?per_page=100": { body: [{ id: 1, name: "וידאוסקופים" }, { id: 2, name: "מצלמות תרמיות &amp; אביזרים" }], type: "application/json" },
  "supplier.test/product/x2000": html(`<nav><a href="/">Home</a></nav><main><h1>X2000 Videoscope</h1>
    <p>${"Distributor text about the X2000. ".repeat(20)}</p><img src="/img/dist.jpg" alt="x2000">
    <a href="/files/x2000-brochure.pdf">Brochure</a> <a href="https://maker.test/product/x2000/">Manufacturer page</a></main>`),
  "maker.test/product/x2000/": html(`<main><h1>X2000</h1>
    <script type="application/ld+json">{"@type":"Product","name":"X2000","description":"Industrial videoscope with 7 inch screen."}</script>
    <p>${"Official X2000 description. ".repeat(20)}</p>
    <div class="gallery"><img src="/img/x2000-main-300x300.jpg" alt="X2000 front"><img data-src="/img/x2000-side.jpg" src="data:image/gif;base64,R0">
    <a href="/img/x2000-probe.jpg"><img src="/img/x2000-probe-150x150.jpg" srcset="/img/x2000-probe-150x150.jpg 150w, /img/x2000-probe-768x768.jpg 768w"></a>
    <img src="/img/x2000-case.jpg"><img src="/img/logo.png"></div>
    <table><tr><th>Screen</th><td>7" LCD</td></tr><tr><th>Protection</th><td>IP54</td></tr></table>
    <iframe title="X2000 demo" src="https://www.youtube.com/embed/AbCdEfGhIjK"></iframe>
    <a href="/files/X2000_User_Manual.pdf">User manual</a> <a href="/files/X2000-datasheet.pdf">Datasheet</a></main>`),
  "maker.test/product/x1000-plus/": html(`<main><h1>X1000 Plus</h1><p>${"Older model. ".repeat(30)}</p><img src="/img/x1000-300x200.jpg"></main>`),
  "maker.test/downloads/": html(`<main><table><tr><td>X1000 Plus</td><td><a href="/files/X1000-Plus-manual.pdf">Manual</a></td></tr>
    <tr><td>Other</td><td><a href="/files/other.pdf">Other brochure</a></td></tr></table></main>`),
  "thermo.test/products/thermal-226s": html(`<main><h1>Thermal Camera 226s</h1><p>${"Handheld thermal camera. ".repeat(20)}</p>
    <img src="https://thermo.test/cdn/226s-a_400x.jpg" srcset="https://thermo.test/cdn/226s-a_400x.jpg 400w, https://thermo.test/cdn/226s-a_1600x.jpg 1600w"><img src="https://thermo.test/cdn/226s-b.jpg"><img src="https://thermo.test/cdn/226s-c.jpg">
    <a href="https://youtu.be/ZyXwVuTsRqP">Watch the video</a><a href="/docs/226s-brochure.pdf">Brochure</a></main>`),
  "www.ndt24.co.il/product/%D7%9E%D7%A6%D7%9C%D7%9E%D7%94-%D7%AA%D7%A8%D7%9E%D7%99%D7%AA-fotric-348a/": html(
    `<main><h1>מצלמה תרמית 640X480 פיקסלים Fotric 348A</h1><p>${"מצלמה תרמית מקצועית לאיתור נזילות ובדיקת לוחות חשמל. ".repeat(6)}</p></main>`),
};
const FILES = {
  "supplier.test/files/x2000-brochure.pdf": PDF, "maker.test/files/X2000_User_Manual.pdf": PDF, "maker.test/files/X2000-datasheet.pdf": PDF,
  "maker.test/files/X1000-Plus-manual.pdf": PDF, "thermo.test/docs/226s-brochure.pdf": PDF,
};

// ---- fake Claude Batches API ----
const batches = new Map();
const claudeRequests = [];
let researchX2000Calls = 0;

function research(params) {
  const q = params.messages[0].content;
  const link = q.match(/Product page: (\S+)/)[1];
  const json = (o) => ({ content: [{ type: "text", text: "Found it.\n```json\n" + JSON.stringify(o) + "\n```" }], stop_reason: "end_turn" });
  if (link.includes("x2000")) {
    researchX2000Calls++;
    if (params.messages.length === 1) return { content: [{ type: "server_tool_use", id: "s1", name: "web_search", input: { query: "X2000" } }], stop_reason: "pause_turn" };
    return json({ manufacturer: "Mitcorp", model: "X2000", official_domains: ["maker.test", "supplier.test"], official_product_url: "https://maker.test/product/x2000/", official_downloads_url: "", site_is_manufacturer: false });
  }
  if (link.includes("thermal-226s")) {
    return json({ manufacturer: "Thermo", model: "226s", official_domains: ["thermo.test"], official_product_url: link, official_downloads_url: "", site_is_manufacturer: true });
  }
  return json({ manufacturer: "Mitcorp", model: "X1000 Plus", official_domains: ["https://www.maker.test/"], official_product_url: "https://maker.test/product/x1000-plus/", official_downloads_url: "https://maker.test/downloads/", site_is_manufacturer: false });
}

let x2000Writes = 0;
function write(params) {
  const text = params.messages[0].content.find((b) => b.type === "text").text;
  const model = text.match(/Model: (.+)/)[1];
  const listed = (tag) => (text.match(new RegExp(`<${tag}>\\n([\\s\\S]*?)\\n?</${tag}>`))[1] || "").split("\n").filter(Boolean).map((l) => l.split("\t"));
  const imgs = listed("images");
  const pdfs = listed("pdfs");
  const idx = (re) => { const r = pdfs.find((p) => re.test(p[1] + p[2])); return r ? +r[0] : -1; };
  let short = `${model} - מכשיר מקצועי לבדיקה.`;
  if (model === "X2000" && x2000Writes++ === 0) short = "מילה ".repeat(90); // too long -> must be retried
  const content = {
    name: `מוצר ${model}`, short_description: short, description_paragraphs: ["סקירה של המוצר.", "פסקה שנייה עם נתונים: IP54."],
    usage: ["שימוש ראשון", "שימוש שני"], specs: [{ name: "הגנה", value: "IP54" }],
    // A category that exists on the site, and one that doesn't (must be left empty).
    category: /226/i.test(model) ? "קטגוריה שלא קיימת" : "וידאוסקופים", tags: ["וידאוסקופ", "Mitcorp"],
    focus_keyphrase: "וידאוסקופ " + model, seo_title: "וידאוסקופ " + model + " | NDT24", meta_description: "וידאוסקופ תעשייתי " + model + " לבדיקה חזותית.",
    slug: "Mitcorp " + model + " Videoscope!",
    image_indexes: imgs.filter((i) => !/logo/.test(i[1])).map((i) => +i[0]).slice(0, 4),
    brochure_index: idx(/datasheet|brochure/i), manual_index: idx(/manual/i), video_indexes: listed("videos").map((v) => +v[0]),
  };
  return { content: [{ type: "text", text: JSON.stringify(content) }], stop_reason: "end_turn" };
}

function claude(url, opts) {
  const u = new URL(url);
  if (opts.headers["x-api-key"] !== "sk-test") return { code: 401, body: { error: { message: "bad key" } } };
  if (opts.method === "post" && u.pathname === "/v1/messages") {   // direct call (fast mode)
    const params = JSON.parse(opts.payload);
    claudeRequests.push({ custom_id: "direct", params });
    const message = params.tools ? research(params) : write(params);
    return { body: { type: "message", role: "assistant", ...message }, type: "application/json" };
  }
  if (opts.method === "post" && u.pathname === "/v1/messages/batches") {
    const body = JSON.parse(opts.payload);
    body.requests.forEach((r) => claudeRequests.push(r));
    const id = `batch${batches.size + 1}`;
    batches.set(id, { requests: body.requests, polls: 0 });
    return { body: { id, processing_status: "in_progress" }, type: "application/json" };
  }
  const m = u.pathname.match(/^\/v1\/messages\/batches\/(\w+)$/);
  if (m) {
    const b = batches.get(m[1]);
    b.polls++;
    return { body: { id: m[1], processing_status: b.polls >= 2 ? "ended" : "in_progress", results_url: `https://api.test/results/${m[1]}` }, type: "application/json" };
  }
  const r = u.pathname.match(/^\/results\/(\w+)$/);
  if (r) {
    const lines = batches.get(r[1]).requests.map((req) => {
      const message = req.params.tools ? research(req.params) : write(req.params);
      return JSON.stringify({ custom_id: req.custom_id, result: { type: "succeeded", message: { type: "message", role: "assistant", ...message } } });
    });
    return { body: lines.join("\n"), type: "application/x-jsonlines" };
  }
  return null;
}

function fetchHandler(url, opts) {
  if (url.startsWith("https://api.test")) return claude(url, opts);
  const key = url.replace(/^https?:\/\//, "");
  if (SITES[key]) return SITES[key];
  if (FILES[key]) return { body: FILES[key], type: "application/pdf" };
  if (IMG[key]) return { body: IMG[key], type: "image/jpeg" };
  return null;
}

// ---- run ----
const g = makeGoogle({ fetchHandler });
const ctx = vm.createContext({ ...g.google, JSON, Date, Math, String, Array, Object, RegExp, Error, parseInt, decodeURIComponent, encodeURIComponent });
const code = readdirSync(ROOT).filter((f) => f.endsWith(".gs")).map((f) => readFileSync(path.join(ROOT, f), "utf8")).join("\n;\n");
vm.runInContext(code, ctx);

ctx.doGet();
// FAST=1: direct calls (the default setting); otherwise batch jobs.
const FAST = process.env.FAST === "1";
g.userProps.setProperty("ANTHROPIC_API_KEY", "sk-test");
g.userProps.setProperty("ANTHROPIC_API_BASE", "https://api.test");
ctx.appSaveSettings({ ...ctx.appGetSettings().values, "מצב מהיר": FAST ? "כן" : "לא" });
const reset = () => vm.runInContext("SETTINGS_MEMO = null; CATEGORIES_MEMO = null; FOLDER_MEMO = {}; ITEMS_MEMO = null; ITEMS_DIRTY = false; BIG_SEEN = {};", ctx);
reset();
const started = ctx.appStart(["https://supplier.test/product/x2000", "https://thermo.test/products/thermal-226s", "https://supplier.test/product/broken"].join("\n"));
assert.equal(started.ok, true, started.message);
for (let i = 0; i < 40 && g.triggers.some((t) => t.getHandlerFunction() === "tick"); i++) { reset(); ctx.tick(); }
reset();

// ---- checks ----
const rows = ctx.getItems().map((it) => [it.link, it.status, it.name, it.manufacturer, it.folderUrl, it.notes, it.id]);
assert.equal(rows.length, 3);
const statusOf = rows.map((r) => r[1]);
assert.ok(statusOf.every((s) => s.startsWith("✓")), "all done: " + JSON.stringify(rows.map((r) => [r[1], r[5]])));
assert.deepEqual(rows.map((r) => r[3]), ["Mitcorp", "Thermo", "Mitcorp"]);
assert.ok(rows.every((r) => String(r[4]).startsWith("https://drive.google.com/drive/folders/")));

const root = g.myDrive.getFoldersByName("NDT24 - מוצרים").next();
const live = (f) => f.folders.filter((x) => !x.trashed);
const names = live(root).map((f) => f.name).sort();
assert.deepEqual(names, ["MITCORP-X1000-PLUS - מוצר X1000 Plus", "MITCORP-X2000 - מוצר X2000", "THERMO-226S - מוצר 226s"], "one folder per product, work folder removed");
const folderOf = (name) => live(root).find((f) => f.name.startsWith(name));
const filesIn = (folder) => folder.files.filter((f) => !f.trashed).map((f) => f.getName()).sort();
const imagesOf = (name) => filesIn(live(folderOf(name)).find((f) => f.name === "תמונות"));
assert.deepEqual(filesIn(folderOf("MITCORP-X2000 ")), ["MITCORP-X2000-BROCHURE.pdf", "MITCORP-X2000-MANUAL.pdf", "MITCORP-X2000.csv"]);
assert.deepEqual(filesIn(folderOf("THERMO-226S")), ["THERMO-226S-BROCHURE.pdf", "THERMO-226S.csv"]);
assert.deepEqual(filesIn(folderOf("MITCORP-X1000")), ["MITCORP-X1000-PLUS-MANUAL.pdf", "MITCORP-X1000-PLUS.csv"]);

// Images: full-size versions, in Claude's order, in each product's "תמונות" folder; the 500x400 photo is dropped
// because there are 3 high-resolution ones; the X1000 only has a small one, which is kept and flagged.
assert.deepEqual(imagesOf("MITCORP-X2000 "), ["MITCORP-X2000-001.jpg", "MITCORP-X2000-002.jpg", "MITCORP-X2000-003.jpg"]);
assert.deepEqual(imagesOf("THERMO-226S"), ["THERMO-226S-001.jpg", "THERMO-226S-002.jpg", "THERMO-226S-003.jpg"]);
assert.deepEqual(imagesOf("MITCORP-X1000"), ["MITCORP-X1000-PLUS-001.jpg"]);
const imgBytes = (name, file) => live(folderOf(name)).find((f) => f.name === "תמונות").files.find((f) => f.getName() === file).getBlob().buf;
assert.ok(imgBytes("MITCORP-X2000 ", "MITCORP-X2000-001.jpg").equals(IMG["maker.test/img/x2000-main.jpg"]), "full-size main photo, not the 300x300 thumbnail");
assert.ok(imgBytes("MITCORP-X2000 ", "MITCORP-X2000-003.jpg").equals(IMG["maker.test/img/x2000-probe.jpg"]), "photo behind the link, not the thumbnail / srcset");
assert.ok(imgBytes("THERMO-226S", "THERMO-226S-001.jpg").equals(IMG["thermo.test/cdn/226s-a.jpg"]), "Shopify size suffix removed");
assert.match(rows[2][5], /רזולוציה נמוכה.*300×200/);

const x2000Folder = live(root).find((f) => f.name.startsWith("MITCORP-X2000 "));
// Everything except images and PDFs is in the product's CSV table (header row + one product row).
const csvText = x2000Folder.files.find((f) => f.getName() === "MITCORP-X2000.csv").getBlob().getDataAsString();
assert.ok(csvText.startsWith("\uFEFF"), "no BOM: Excel would show gibberish instead of Hebrew");
const table = ctx.parseCsv(csvText);
assert.equal(table.length, 2);
const col = (name) => table[1][table[0].indexOf(name)];
// The columns follow the site's "add product" screen.
assert.deepEqual([...table[0].slice(0, 15)], ["שם מוצר", "תיאור המוצר (HTML)", "תיאור קצר של המוצר", "תמונת מוצר", "גלריית תמונות מוצר", "קטגוריה", "תגיות", "מותג",
  "ביטוי מפתח (Yoast)", "כותרת SEO", "סלאג", "תיאור מטא", "קטלוג pdf", "ספר הוראות", "וידאו מוצר"]);
assert.equal(col("שם מוצר"), "מוצר X2000");
assert.equal(col("תיאור המוצר (HTML)"), "<p>סקירה של המוצר.</p>\n<p>פסקה שנייה עם נתונים: IP54.</p>\n<ul>\n<li>שימוש ראשון</li>\n<li>שימוש שני</li>\n</ul>");
assert.ok(col("תיאור קצר של המוצר").startsWith("X2000 - "));
assert.equal(col("תמונת מוצר"), "MITCORP-X2000-001.jpg");
assert.equal(col("גלריית תמונות מוצר"), "MITCORP-X2000-002.jpg, MITCORP-X2000-003.jpg");
assert.equal(col("קטגוריה"), "וידאוסקופים");
assert.equal(col("תגיות"), "וידאוסקופ, Mitcorp");
assert.equal(col("מותג"), "Mitcorp");
assert.equal(col("ביטוי מפתח (Yoast)"), "וידאוסקופ X2000");
assert.equal(col("סלאג"), "mitcorp-x2000-videoscope");
assert.match(col("קטלוג pdf"), /^https:\/\/maker\.test\/files\//);
assert.match(col("ספר הוראות"), /^https:\/\/maker\.test\/files\/.*[Mm]anual/);
assert.match(col("וידאו מוצר"), /watch\?v=AbCdEfGhIjK/);
assert.match(col("ברושור (בדרייב)"), /^https:\/\/drive\.google\.com\/file\//);
assert.ok(col("מפרט טכני (לעיון)").includes("הגנה: IP54"));
assert.equal(col("דף המוצר באתר היצרן"), "https://maker.test/product/x2000/");
assert.equal(col("דף המוצר באתר הספק"), "https://supplier.test/product/x2000");
assert.equal(col("תיקייה בדרייב"), x2000Folder.getUrl());
const page = col("דף מלא ל-LLM (HTML)");
for (const s of ['lang="he" dir="rtl"', 'id="product-name"', 'id="short-description"', 'id="full-description"', 'id="usage"', 'id="specifications"',
  "watch?v=AbCdEfGhIjK", 'src="תמונות/MITCORP-X2000-001.jpg" width="2000" height="1500"', "2000×1500", 'href="MITCORP-X2000-BROCHURE.pdf"', 'href="MITCORP-X2000-MANUAL.pdf"',
  "https://supplier.test/product/x2000", "(אתר הספק)", "https://maker.test/product/x2000/", "(אתר היצרן הרשמי)", "application/ld+json"]) {
  assert.ok(page.includes(s), "product page has " + s);
}
assert.ok(!page.includes("supplier.test/files") && !page.includes("dist.jpg"), "nothing taken from the distributor");

// The main folder has one table with every product.
if (process.env.DUMP) (await import('node:fs')).writeFileSync(process.env.DUMP, root.files.find((f) => f.getName() === "כל המוצרים.csv").getBlob().getDataAsString());
const all = ctx.parseCsv(root.files.find((f) => f.getName() === "כל המוצרים.csv" && !f.trashed).getBlob().getDataAsString());
const idCol = all[0].indexOf("מזהה");
assert.deepEqual([...all.slice(1).map((r) => r[idCol])].sort(), ["MITCORP-X1000-PLUS", "MITCORP-X2000", "THERMO-226S"]);
assert.equal(all.find((r) => r[idCol] === "THERMO-226S")[all[0].indexOf("קטגוריה")], "", "a category that isn't on the site was kept");
assert.ok(all.every((r) => r.length === all[0].length), "rows with a different number of columns");

// Claude usage
const researchReqs = claudeRequests.filter((r) => r.params.tools);
assert.deepEqual(researchReqs[0].params.tools.map((t) => t.type), ["web_search_20260209", "web_fetch_20260209"]);
assert.equal(researchX2000Calls, 2, "pause_turn continued");
const writes = claudeRequests.filter((r) => r.params.system);
assert.ok(writes[0].params.system[0].text.includes("וידאוסקופים\nמצלמות תרמיות & אביזרים"), "site categories not in the prompt");
assert.equal(writes.length, 4, "3 products + 1 retry for the too-long short description");
assert.ok(writes.some((w) => w.params.messages[0].content.at(-1).text.includes("short_description has 90 words")), "retry got the feedback");
assert.ok(writes[0].params.system[0].text.includes("מצלמה תרמית מקצועית לאיתור נזילות"), "NDT24 style example in prompt");
assert.ok(writes[0].params.system[0].text.includes("videoscope = וידאוסקופ"), "glossary in prompt");
assert.equal(writes[0].params.output_config.format.type, "json_schema");
assert.equal(writes[0].params.model, "claude-sonnet-5");
assert.equal(writes[0].params.output_config.effort, FAST ? "medium" : "high");
assert.ok(writes[0].params.system[0].text.includes("<avoid_words>\nהינו"), "avoid-words list in prompt");
const x2000Write = writes.find((w) => w.params.messages[0].content.at(-1).text.includes("Model: X2000"));
assert.equal(x2000Write.params.messages[0].content[0].type, "document", "official brochure given to Claude");
assert.ok(!x2000Write.params.messages[0].content.at(-1).text.includes("dist.jpg"), "distributor images never offered");

// Finished cleanly
assert.equal(g.triggers.length, 0, "trigger removed");
assert.equal(g.mails.length, 1, "done email");
// research(3) -> continuation(X2000) ; write(2 ready) -> write(X2000, ready one step later) -> retry(X2000)
assert.equal(batches.size, FAST ? 0 : 5);
// install/Code.gs (what users paste) must match the source files
if ((await import("node:fs")).existsSync(path.join(ROOT, "build.sh"))) {
  const { execFileSync } = await import("node:child_process");
  const before = readFileSync(path.join(ROOT, "install", "Code.gs"), "utf8");
  execFileSync(path.join(ROOT, "build.sh"));
  assert.equal(readFileSync(path.join(ROOT, "install", "Code.gs"), "utf8"), before, "install/Code.gs is out of date: run ./build.sh");
}
console.log("✓ all checks passed");
