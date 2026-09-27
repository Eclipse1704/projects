// Failure modes and edge cases. Run: node tests/robustness.mjs
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { FAST, fakeClaude, hebrew, loadProject, researchJson, text } from "./harness.mjs";

const results = [];
// Tests of the batch-job path: in the FAST run they force batch mode.
const batchOnly = { fast: false };
function test(name, fn) {
  try { fn(); results.push(["✓", name]); } catch (e) { results.push(["✗", name, e.message.split("\n").slice(0, 3).join(" ")]); }
}

const PAGE = (body) => ({ body: `<!doctype html><html><body>${body}</body></html>` });
const PDF = Buffer.concat([Buffer.from("%PDF-1.4\n"), Buffer.alloc(3000, 48)]);
const jpeg = (w, h) => Buffer.concat([
  Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0]),
  Buffer.from([0xff, 0xc0, 0x00, 0x11, 0x08, h >> 8, h & 255, w >> 8, w & 255, 3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]), randomBytes(9000)]);
const SITE = {
  "maker.test/p/a100": PAGE(`<main><h1>A100</h1><p>${"Good product. ".repeat(40)}</p><img src="/i/a1.jpg"><img src="/i/a2.jpg"><img src="/i/a3.jpg">
    <a href="/d/A100-brochure.pdf">Brochure</a></main>`),
};
const BIN = { "maker.test/i/a1.jpg": jpeg(1200, 900), "maker.test/i/a2.jpg": jpeg(1200, 900), "maker.test/i/a3.jpg": jpeg(1200, 900), "maker.test/d/A100-brochure.pdf": PDF };
const OFFICIAL = { manufacturer: "Maker", model: "A100", official_domains: ["maker.test"], official_product_url: "https://maker.test/p/a100", official_downloads_url: "", site_is_manufacturer: true };
const web = (claude, extra = {}) => (url, opts) => {
  if (url.startsWith("https://api.test")) return claude.handle(url, opts);
  const k = url.replace(/^https?:\/\//, "");
  if (extra[k]) return extra[k];
  if (SITE[k]) return SITE[k];
  if (BIN[k]) return { body: BIN[k], type: k.endsWith(".pdf") ? "application/pdf" : "image/jpeg" };
  return null;
};
const normal = (params) => (params.tools ? researchJson(OFFICIAL) : hebrew({ image_indexes: [0, 1, 2], brochure_index: 0 }));

test("invalid API key: the row shows the error and the run stops (no endless trigger)", () => {
  const claude = fakeClaude(normal, { key: "sk-right" });
  const p = loadProject(web(claude), { apiKey: "sk-wrong" });
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.runUntilIdle(10);
  const [row] = p.rows();
  assert.match(String(row[1]), /שגיאה/, "status: " + row[1]);
  assert.match(String(row[5]), /401|invalid x-api-key/, "notes: " + row[5]);
  assert.equal(p.g.triggers.filter((t) => t.getHandlerFunction() === "tick").length, 0, "trigger still running");
});

test("temporary API overload (529) when submitting: retried on the next run", () => {
  const claude = fakeClaude(normal, { failCreate: (n) => (n === 1 ? { code: 529, body: { error: { message: "overloaded" } }, type: "application/json" } : null) });
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.runUntilIdle();
  assert.match(String(p.rows()[0][1]), /✓/, "status: " + p.rows()[0][1] + " " + p.rows()[0][5]);
});

test("research paused twice (pause_turn): continuation is a valid conversation", () => {
  let pauses = 0;
  const claude = fakeClaude((params) => {
    if (!params.tools) return hebrew({ image_indexes: [0, 1, 2] });
    const roles = params.messages.map((m) => m.role).join(",");
    if (/assistant,assistant/.test(roles)) return { error: "messages: roles must alternate" };
    if (pauses < 2) { pauses++; return { content: [{ type: "server_tool_use", id: "s" + pauses, name: "web_search", input: {} }], stop_reason: "pause_turn" }; }
    return researchJson(OFFICIAL);
  });
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.runUntilIdle();
  const [row] = p.rows();
  assert.equal(row[3], "Maker", "manufacturer: " + row[3] + " / " + row[1] + " / " + row[5]);
  const last = claude.requests.filter((r) => r.params.tools).pop();
  assert.deepEqual(last.params.messages.map((m) => m.role), ["user", "assistant"]);
  assert.equal(last.params.messages[1].content.length, 2, "both paused turns' content kept");
});

test("a brochure Claude can't read (errored request) doesn't fail the product: retried without it", () => {
  const claude = fakeClaude((params) => {
    if (params.tools) return researchJson(OFFICIAL);
    return params.messages[0].content[0].type === "document" ? { error: "The PDF specified could not be processed" } : hebrew({ image_indexes: [0, 1, 2], brochure_index: 0 });
  });
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.runUntilIdle();
  assert.match(String(p.rows()[0][1]), /✓/, "status: " + p.rows()[0][1] + " " + p.rows()[0][5]);
});

test("a product whose work data is gone (deleted/lost) doesn't keep the trigger running forever", () => {
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.runUntilIdle();
  for (const stage of ["new", "research_pending", "research_wait", "write_pending"]) {
    p.ctx.setStages({ pGONE: stage });
    p.run("ensureTrigger");
    const ticks = p.runUntilIdle(10);
    assert.ok(ticks < 10, "trigger never stopped for a lost product in stage " + stage);
  }
  p.run("ensureTrigger");
  const ticks = p.runUntilIdle(10);
  assert.ok(ticks < 10, "trigger never stopped");
});

test("a product waiting on a batch that was lost gets resubmitted", () => {
  const claude = fakeClaude(normal, { pollsUntilEnded: 1000 });
  const p = loadProject(web(claude), batchOnly);
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.run("tick");
  p.g.scriptProps.setProperty("BATCHES", "[]"); // e.g. the run was killed after submitting
  claude.batches.clear();
  const before = claude.requests.length;
  p.run("tick");
  p.run("tick");
  assert.ok(claude.requests.length > before, "not resubmitted");
});

test("menu 'run' returns quickly: it only queues (the minute trigger does the work)", () => {
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100"]);
  const n = p.g.log.fetches.length;
  p.run("startRun");
  assert.equal(p.g.log.fetches.length, n, "startRun fetched pages itself (the user waits minutes on a spinner)");
});

test("waiting minutes/hours for Claude: an idle run doesn't read every product's state from Drive", () => {
  const claude = fakeClaude(normal, { pollsUntilEnded: 1000 });
  const p = loadProject(web(claude), batchOnly);
  p.addLinks(Array.from({ length: 20 }, () => "https://maker.test/p/a100"));
  p.run("startRun");
  p.run("tick");
  p.run("tick");
  let reads = 0;
  const root = p.g.myDrive.getFoldersByName("NDT24 - מוצרים").next();
  const state = root.getFoldersByName("_מצב_עבודה").next();
  state.files.forEach((f) => { const orig = f.getBlob.bind(f); f.getBlob = () => { reads++; return orig(); }; });
  p.run("tick");
  assert.equal(reads, 0, `idle run read ${reads} state files`);
});

test("saving progress doesn't fill the Drive trash with old copies", () => {
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100", "https://maker.test/p/a100"]);
  p.run("startRun");
  for (let i = 0; i < 6; i++) p.run("tick");
  const root = p.g.myDrive.getFoldersByName("NDT24 - מוצרים").next();
  const state = root.folders.find((f) => f.name === "_מצב_עבודה");
  const trashed = state ? state.files.filter((f) => f.trashed).length : 0;
  assert.equal(trashed, 0, `${trashed} trashed state files`);
});

test("a step that keeps getting cut off (6-minute limit) stops after 3 tries with a clear message", () => {
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  // Simulate: three earlier runs started the 'new' step and were killed before finishing.
  const id = p.rows()[0][6];
  const root = p.g.myDrive.getFoldersByName("NDT24 - מוצרים").next();
  const f = root.folders.find((x) => x.name === "_מצב_עבודה").files.find((x) => x.getName() === id + ".json" && !x.trashed);
  const st = JSON.parse(f.getBlob().getDataAsString());
  st.stepTries = { new: 3 };
  f.blob.buf = Buffer.from(JSON.stringify(st));
  p.run("tick");
  const [row] = p.rows();
  assert.match(String(row[1]), /שגיאה/, "status " + row[1]);
  assert.match(String(row[5]), /נקטע|איטי/, "notes " + row[5]);
});

test("Hebrew-only product name and no manufacturer found: products don't overwrite each other's folder", () => {
  const claude = fakeClaude((params) => (params.tools ? text("I could not find it.") : hebrew({ name: params.messages[0].content.at(-1).text.includes("b1") ? "מוצר ב" : "מוצר א" })));
  const p = loadProject(web(claude, {
    "shop.test/a1": PAGE("<h1>מכשיר מדידה</h1><p>" + "טקסט. ".repeat(50) + "</p>"),
    "shop.test/b1": PAGE("<h1>מכשיר בדיקה</h1><p>" + "טקסט. ".repeat(50) + "</p>"),
  }));
  p.addLinks(["https://shop.test/a1", "https://shop.test/b1"]);
  p.run("startRun");
  p.runUntilIdle();
  const root = p.g.myDrive.getFoldersByName("NDT24 - מוצרים").next();
  const folders = root.folders.filter((f) => !f.trashed);
  assert.equal(folders.length, 2, "folders: " + folders.map((f) => f.name).join(" | ") + " / " + p.rows().map((r) => r[1] + " " + r[5]).join(" | "));
});

test("page parsing: YouTube playlists aren't videos; ASP.NET pages (whole page in a <form>) still have text", () => {
  const p = loadProject(() => null);
  const page = p.ctx.parsePage(`<form id="form1"><h1>Model X</h1><p>${"Important specs here. ".repeat(10)}</p>
    <iframe src="https://www.youtube.com/embed/videoseries?list=PL123"></iframe><iframe src="https://www.youtube.com/embed/AbCdEfGhIjK"></iframe></form>`, "https://x.test/p");
  assert.equal(JSON.stringify(page.videos.map((v) => v.url)), JSON.stringify(["https://www.youtube.com/watch?v=AbCdEfGhIjK"]));
  assert.match(page.text, /Important specs/);
});

test("links with spaces or Hebrew letters are downloaded (URL-encoded)", () => {
  const seen = [];
  const p = loadProject((url) => { seen.push(url); return { body: "ok" }; });
  p.ctx.fetchUrl("https://x.test/files/User Manual.pdf");
  p.ctx.fetchUrl("https://x.test/קטלוג/מוצר.pdf");
  assert.deepEqual(seen, ["https://x.test/files/User%20Manual.pdf", "https://x.test/%D7%A7%D7%98%D7%9C%D7%95%D7%92/%D7%9E%D7%95%D7%A6%D7%A8.pdf"]);
});

test("many products at once (400 links): no crash on Google's 9KB-per-setting limit", () => {
  const claude = fakeClaude(normal, { pollsUntilEnded: 1000 });
  const p = loadProject(web(claude));
  p.addLinks(Array.from({ length: 400 }, (_, i) => "https://maker.test/p/a100?n=" + i));
  p.run("startRun");
  assert.equal(p.rows().filter((r) => r[1] === "ממתין בתור").length, 400);
  for (let i = 0; i < 12; i++) p.run("tick");
  assert.ok(p.rows().every((r) => !/שגיאה/.test(r[1])), p.rows().find((r) => /שגיאה/.test(r[1]))?.[5]);
});

// ---------- from the independent review ----------

const liveFolders = (f) => f.folders.filter((x) => !x.trashed);
const rootOf = (p) => p.g.myDrive.folders.find((f) => f.name === "NDT24 - מוצרים" && !f.trashed);

test("a second run after a finished one doesn't use the trashed work folder / trashed product folders", () => {
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.runUntilIdle();
  const first = liveFolders(rootOf(p)).find((f) => f.name.startsWith("MAKER-A100"));
  first.setTrashed(true);   // the user deleted the product folder
  p.sheet.set(2, 2, "");    // ...and runs it again
  p.run("startRun");
  p.runUntilIdle();
  const state = rootOf(p).folders.filter((f) => f.name === "_מצב_עבודה");
  assert.ok(state.every((f) => f.trashed), "work folder left behind");
  assert.match(String(p.rows()[0][1]), /✓/, "status " + p.rows()[0][1] + " " + p.rows()[0][5]);
  const again = liveFolders(rootOf(p)).find((f) => f.name.startsWith("MAKER-A100"));
  assert.ok(again && again !== first, "saved into the trashed folder");
});

test("results download keeps failing: the run doesn't loop forever", () => {
  const claude = fakeClaude(normal);
  const p = loadProject((url, opts) => (url.includes("/results/") ? { code: 500, body: "boom" } : web(claude)(url, opts)), batchOnly);
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  const ticks = p.runUntilIdle(60);
  assert.ok(ticks < 60, "still running after 60 runs");
  assert.match(String(p.rows()[0][1]), /שגיאה/);
});

test("a link that redirects: relative image/PDF links resolve against the final address", () => {
  const claude = fakeClaude((params) => (params.tools ? researchJson({ ...OFFICIAL, official_product_url: "https://maker.test/p/123" }) : hebrew({ image_indexes: [0, 1, 2], brochure_index: 0 })));
  const p = loadProject(web(claude, {
    "maker.test/p/123": { code: 301, location: "/en/products/a100/" },
    "maker.test/en/products/a100/": PAGE(`<main><h1>A100</h1><p>${"Text. ".repeat(40)}</p><img src="img/r1.jpg"><img src="img/r2.jpg"><img src="img/r3.jpg"><a href="docs/A100-brochure.pdf">Brochure</a></main>`),
    "maker.test/en/products/a100/img/r1.jpg": { body: jpeg(1200, 900), type: "image/jpeg" },
    "maker.test/en/products/a100/img/r2.jpg": { body: jpeg(1200, 900), type: "image/jpeg" },
    "maker.test/en/products/a100/img/r3.jpg": { body: jpeg(1200, 900), type: "image/jpeg" },
    "maker.test/en/products/a100/docs/A100-brochure.pdf": { body: PDF, type: "application/pdf" },
  }));
  p.addLinks(["https://maker.test/p/123"]);
  p.run("startRun");
  p.runUntilIdle();
  const row = p.rows()[0];
  assert.doesNotMatch(String(row[5]), /תמונות|ברושור/, "notes: " + row[5]);
});

test("Next.js sites (/_next/image?url=...): every photo is kept, at full size", () => {
  const p = loadProject(() => null);
  const page = p.ctx.parsePage(`<img src="/_next/image?url=%2Fimg%2Fa1.jpg&w=640&q=75"><img src="/_next/image?url=%2Fimg%2Fa2.jpg&w=640&q=75">
    <img src="/getimage.ashx?id=7"><img src="/getimage.ashx?id=8">`, "https://x.test/p");
  assert.equal(JSON.stringify(page.images.map((i) => i.url)),
    JSON.stringify(["https://x.test/img/a1.jpg", "https://x.test/img/a2.jpg", "https://x.test/getimage.ashx?id=7", "https://x.test/getimage.ashx?id=8"]));
});

test("images a CDN sends as application/octet-stream are accepted (type read from the file itself)", () => {
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude, Object.fromEntries(["a1", "a2", "a3"].map((n) => [`maker.test/i/${n}.jpg`, { body: jpeg(1200, 900), type: "binary/octet-stream" }]))));
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.runUntilIdle();
  assert.doesNotMatch(String(p.rows()[0][5]), /תמונות/, "notes: " + p.rows()[0][5]);
});

test("a PDF link with a Latin-1 escape (Brosch%FCre.pdf) doesn't fail the product", () => {
  const p = loadProject(() => null);
  const page = p.ctx.parsePage(`<a href="/d/A100-Brosch%FCre.pdf">Broschüre</a>`, "https://x.test/p");
  assert.equal(page.pdfs.length, 1);
});

test("re-running a product while the manufacturer's site is down keeps the images it already has", () => {
  let down = false;
  const claude = fakeClaude(normal);
  const base = web(claude);
  const p = loadProject((url, opts) => (down && /\/i\//.test(url) ? null : base(url, opts)));
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.runUntilIdle();
  down = true;
  p.sheet.set(2, 2, "");
  p.run("startRun");
  p.runUntilIdle();
  const folder = liveFolders(rootOf(p)).find((f) => f.name.startsWith("MAKER-A100"));
  const imgs = liveFolders(folder).find((f) => f.name === "תמונות").files.filter((f) => !f.trashed);
  assert.equal(imgs.length, 3, "images deleted");
});

test("'Stop' cancels the jobs already sent to Claude (they cost money)", () => {
  const claude = fakeClaude(normal, { pollsUntilEnded: 1000 });
  const p = loadProject(web(claude), batchOnly);
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.run("tick");
  p.run("stopRun");
  assert.ok(p.g.log.fetches.some((f) => f.method === "post" && /\/cancel$/.test(f.url)), "no cancel request");
  assert.equal(p.g.triggers.length, 0);
});

test("a product name starting with '=' is written as text, not a formula", () => {
  const claude = fakeClaude((params) => (params.tools ? researchJson(OFFICIAL) : hebrew({ name: "=IMPORTXML(1)", image_indexes: [0, 1, 2] })));
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.runUntilIdle();
  assert.equal(p.rows()[0][2], "'=IMPORTXML(1)");
});

test("srcset without spaces after commas: the largest image is chosen", () => {
  const p = loadProject(() => null);
  assert.equal(p.ctx.largestFromSrcset("a.jpg 300w,b.jpg 1200w,c.jpg 600w"), "b.jpg");
  assert.equal(p.ctx.largestFromSrcset("a.jpg 1x, b.jpg 2x"), "b.jpg");
});

test("Claude's text still invalid after all retries (no product name): error, not a folder named 'undefined'", () => {
  const claude = fakeClaude((params) => (params.tools ? researchJson(OFFICIAL) : hebrew({ name: "" })));
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.runUntilIdle();
  assert.match(String(p.rows()[0][1]), /שגיאה/, "status " + p.rows()[0][1]);
  assert.ok(!liveFolders(rootOf(p)).some((f) => /undefined| - $/.test(f.name)));
});

test("text details: emoji entities, JSON-LD names given as objects", () => {
  const p = loadProject(() => null);
  assert.equal(p.ctx.decodeEntities("&#128512; &#x1F600;"), "😀 😀");
  const page = p.ctx.parsePage(`<script type="application/ld+json">{"@type":"Product","name":{"@value":"Model Z"},"description":{"x":1}}</script><h1>h</h1>`, "https://x.test/p");
  assert.equal(page.title, "Model Z");
});

test("research jobs are split into batches of at most 20 products", () => {
  const claude = fakeClaude(normal, { pollsUntilEnded: 1000 });
  const p = loadProject(web(claude), batchOnly);
  p.addLinks(Array.from({ length: 45 }, (_, i) => "https://maker.test/p/a100?n=" + i));
  p.run("startRun");
  for (let i = 0; i < 3; i++) p.run("tick");
  const sizes = [...claude.batches.values()].map((b) => b.reqs.length);
  assert.ok(sizes.length >= 3 && sizes.every((n) => n <= 20), "batch sizes " + sizes);
});

test("Hebrew quality: a word from 'words we don't use' sends the text back to Claude for a rewrite", () => {
  let writes = 0;
  const claude = fakeClaude((params) => {
    if (params.tools) return researchJson(OFFICIAL);
    writes++;
    return hebrew({ overview: writes === 1 ? "המכשיר הינו פתרון מושלם לאיתור נזילות." : "המכשיר מתאים לאיתור נזילות.", image_indexes: [0, 1, 2] });
  });
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.runUntilIdle();
  assert.equal(writes, 2, "not retried");
  const retry = claude.requests.filter((r) => r.params.system).pop();
  assert.match(retry.params.messages[0].content.at(-1).text, /avoid_words>: הינו, פתרון מושלם/);
  assert.doesNotMatch(String(p.rows()[0][5]), /avoid/);
  // Hebrew word boundaries: "הינו" inside another word is fine
  assert.equal(p.ctx.containsWord("בהינותו", "הינו"), false);
  assert.equal(p.ctx.containsWord("המכשיר הינו טוב", "הינו"), true);
});

// ---------- installation ----------

test("'make a copy' of a sheet: the copy doesn't get the original's API key or work queue", () => {
  const claude = fakeClaude(normal, { pollsUntilEnded: 1000 });
  const p = loadProject(web(claude), batchOnly);
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.run("tick");
  assert.ok(p.g.scriptProps.getProperty("ANTHROPIC_API_KEY"));
  p.g.sheetId.value = "sheet-2";   // the copy has a different id; Google copies the script and its properties
  p.run("onOpen");
  assert.equal(p.g.scriptProps.getProperty("ANTHROPIC_API_KEY"), null, "API key copied to the copy");
  assert.equal(p.ctx.getBatches().length, 0);
  assert.equal(Object.keys(p.ctx.getStages()).length, 0);
});

test("fresh install: opening the sheet creates the products, settings and instructions sheets", () => {
  const p = loadProject(() => null);
  p.g.sheets.clear();
  p.run("onOpen");
  assert.deepEqual([...p.g.sheets.keys()].sort(), ["הגדרות", "הוראות", "מוצרים"].sort());
  assert.match(String(p.g.sheets.get("הוראות").get(2, 1)), /פתח את הסורק/);
});

test("no advanced services needed (install = paste one file); the readable Google Doc is built with DocumentApp", () => {
  const code = ["Main.gs", "Claude.gs", "Output.gs", "Extract.gs", "Settings.gs"].map((f) => readFileSync(new URL("../" + f, import.meta.url), "utf8")).join("\n");
  assert.doesNotMatch(code, /\bDrive\.Files\b/);
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.runUntilIdle();
  const folder = rootOf(p).folders.find((f) => f.name.startsWith("MAKER-A100") && !f.trashed);
  const doc = folder.files.find((f) => f.mime === "application/vnd.google-apps.document" && !f.trashed);
  assert.ok(doc, "no Google Doc in the product folder");
  const lines = JSON.parse(doc.getBlob().getDataAsString());
  assert.equal(lines[0].heading, "TITLE");
  assert.ok(lines.some((l) => l.text === "תיאור קצר") && lines.every((l) => l.kind === "table" || l.rtl), "missing sections or not right-to-left");
});

test("a background run that crashes shows the error on the rows and in 'מצב המערכת'", () => {
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  const drive = p.ctx.DriveApp;
  p.ctx.DriveApp = { ...drive, getFoldersByName: () => { throw new Error("Exception: Access denied: DriveApp."); } };
  p.run("tick");
  p.run("showStatus");
  p.ctx.DriveApp = drive;
  const notes = String(p.rows()[0][5]);
  assert.ok(/תקלה|שגיאה/.test(notes + p.rows()[0][1]), "nothing shown: " + p.rows()[0][1] + " / " + notes);
  const status = p.g.alerts.at(-1);
  assert.match(status, /עבודה ברקע: פעילה/);
  assert.match(status, /מפתח API: מוגדר/);
  assert.match(status, /Access denied: DriveApp/);
});

// ---------- the scraper window ----------

test("window: API key is checked and saved from the window", () => {
  const claude = fakeClaude(normal, { key: "sk-ant-good" });
  const p = loadProject(web(claude), { apiKey: "" });
  assert.equal(p.run("sidebarState").hasKey, false);
  assert.equal(p.run("sidebarSaveKey", "hello").ok, false);
  const bad = p.run("sidebarSaveKey", "sk-ant-wrong");
  assert.equal(bad.ok, false, "wrong key accepted");
  assert.match(bad.message, /לא תקין/);
  assert.equal(p.run("sidebarSaveKey", "  sk-ant-good  ").ok, true);
  assert.equal(p.run("sidebarState").hasKey, true);
});

test("window: paste messy text with links, press start, watch progress, get the folder link", () => {
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude));
  const started = p.run("sidebarStart", "תבדוק את זה: https://maker.test/p/a100, וגם את\nhttps://maker.test/p/a100?n=2.\nhttps://maker.test/p/a100");
  assert.equal(started.ok, true, started.message);
  assert.match(started.message, /2 מוצרים התחילו/);
  assert.equal(p.rows().length, 2);
  let st = p.run("sidebarState");
  assert.equal(st.items.length, 2);
  assert.ok(st.items.every((i) => i.state === "working" && i.step === "ממתין להתחלה"));
  p.runUntilIdle();
  st = p.run("sidebarState");
  assert.ok(st.items.every((i) => (i.state === "done" || i.state === "warn") && i.pct === 100), JSON.stringify(st.items));
  assert.ok(st.items.every((i) => i.folderUrl.startsWith("https://drive.google.com/")), "no folder link");
  assert.ok(st.items.every((i) => i.name && i.manufacturer === "Maker"));
});

test("window: start without an API key asks for the key; text without links explains", () => {
  const p = loadProject(() => null, { apiKey: "" });
  const r = p.run("sidebarStart", "https://maker.test/p/a100");
  assert.equal(r.needKey, true);
  p.g.scriptProps.setProperty("ANTHROPIC_API_KEY", "sk-test");
  const r2 = p.run("sidebarStart", "בלי קישורים בכלל");
  assert.equal(r2.ok, false);
  assert.match(r2.message, /לא מצאתי קישורים/);
});

test("window: opens from the menu, and after that opens by itself (one trigger, not one per open)", () => {
  const p = loadProject(() => null);
  p.run("openScraper");
  p.run("openScraper");
  assert.equal(p.g.ui.sidebars.length, 2);
  assert.equal(p.g.ui.sidebars[0].title, "סורק מוצרים");
  assert.equal(p.g.triggers.filter((t) => t.getHandlerFunction() === "autoOpenScraper").length, 1);
});

// ---------- fast mode (direct calls) ----------
const fastMode = { fast: true };

test("fast mode: a product goes from link to finished Drive folder in a single run", () => {
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude), fastMode);
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.run("tick");
  assert.match(String(p.rows()[0][1]), /✓/, "status after one run: " + p.rows()[0][1]);
  assert.equal(claude.batches.size, 0, "used batch jobs");
});

test("fast mode: 12 products finish in one run, fetched and written in parallel", () => {
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude), fastMode);
  p.addLinks(Array.from({ length: 12 }, (_, i) => "https://maker.test/p/a100?n=" + i));
  p.run("startRun");
  p.run("tick");
  const done = p.rows().filter((r) => /✓/.test(r[1])).length;
  assert.equal(done, 12, "finished after one run: " + done);
  assert.ok(Math.max(...p.g.log.fetchAlls) >= 5, "no parallel requests: " + p.g.log.fetchAlls);
});

test("fast mode: a direct call that runs past Google's 60s limit continues as a batch job", () => {
  const claude = fakeClaude((params, req) => {
    if (!req.custom_id && !params.tools) return { timeout: true };   // the direct write call is too slow
    return normal(params);
  });
  const p = loadProject(web(claude), fastMode);
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.runUntilIdle();
  assert.match(String(p.rows()[0][1]), /✓/, "status " + p.rows()[0][1] + " " + p.rows()[0][5]);
  assert.equal(claude.direct.filter((x) => !x.tools).length, 1, "direct write retried after a timeout (money wasted)");
  assert.equal(claude.batches.size, 1, "write step didn't fall back to a batch");
});

test("fast mode: Claude busy (529) on a direct call: retried, and after 3 times sent as a batch job", () => {
  let busy = 0;
  const claude = fakeClaude((params, req) => {
    if (!req.custom_id && params.tools) { busy++; return { status: 529, error: "overloaded" }; }
    return normal(params);
  });
  const p = loadProject(web(claude), fastMode);
  p.addLinks(["https://maker.test/p/a100"]);
  p.run("startRun");
  p.runUntilIdle();
  assert.match(String(p.rows()[0][1]), /✓/, "status " + p.rows()[0][1] + " " + p.rows()[0][5]);
  assert.equal(busy, 3);
});

for (const r of results) console.log(r.join("  "));
const failed = results.filter((r) => r[0] === "✗").length;
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
