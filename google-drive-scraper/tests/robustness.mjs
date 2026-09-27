// Failure modes and edge cases. Run: node tests/robustness.mjs
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { FAST, fakeClaude, hebrew, loadProject, researchJson, setSetting, text } from "./harness.mjs";

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
  p.start();
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
  p.start();
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
  p.start();
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
  p.start();
  p.runUntilIdle();
  assert.match(String(p.rows()[0][1]), /✓/, "status: " + p.rows()[0][1] + " " + p.rows()[0][5]);
});

test("a product whose work data is gone (deleted/lost) doesn't keep the trigger running forever", () => {
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100"]);
  p.start();
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
  p.start();
  p.run("tick");
  p.g.userProps.setProperty("BATCHES", "[]"); // e.g. the run was killed after submitting
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
  p.start();
  assert.equal(p.g.log.fetches.length, n, "startRun fetched pages itself (the user waits minutes on a spinner)");
});

test("waiting minutes/hours for Claude: an idle run doesn't read every product's state from Drive", () => {
  const claude = fakeClaude(normal, { pollsUntilEnded: 1000 });
  const p = loadProject(web(claude), batchOnly);
  p.addLinks(Array.from({ length: 20 }, () => "https://maker.test/p/a100"));
  p.start();
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
  p.start();
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
  p.start();
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
  p.start();
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
  p.start();
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
  p.start();
  p.runUntilIdle();
  const first = liveFolders(rootOf(p)).find((f) => f.name.startsWith("MAKER-A100"));
  first.setTrashed(true);   // the user deleted the product folder
  p.addLinks(["https://maker.test/p/a100"]);   // ...and runs it again
  p.start();
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
  p.start();
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
  p.start();
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
  p.start();
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
  p.start();
  p.runUntilIdle();
  down = true;
  p.addLinks(["https://maker.test/p/a100"]);
  p.start();
  p.runUntilIdle();
  const folder = liveFolders(rootOf(p)).find((f) => f.name.startsWith("MAKER-A100"));
  const imgs = liveFolders(folder).find((f) => f.name === "תמונות").files.filter((f) => !f.trashed);
  assert.equal(imgs.length, 3, "images deleted");
});

test("'Stop' cancels the jobs already sent to Claude (they cost money)", () => {
  const claude = fakeClaude(normal, { pollsUntilEnded: 1000 });
  const p = loadProject(web(claude), batchOnly);
  p.addLinks(["https://maker.test/p/a100"]);
  p.start();
  p.run("tick");
  p.run("stopRun");
  assert.ok(p.g.log.fetches.some((f) => f.method === "post" && /\/cancel$/.test(f.url)), "no cancel request");
  assert.equal(p.g.triggers.length, 0);
});

test("a strange product name ('=…', HTML) is kept as plain text", () => {
  const claude = fakeClaude((params) => (params.tools ? researchJson(OFFICIAL) : hebrew({ name: "=IMPORTXML(1) <b>", image_indexes: [0, 1, 2] })));
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100"]);
  p.start();
  p.runUntilIdle();
  assert.equal(p.rows()[0][2], "=IMPORTXML(1) <b>");
  assert.match(p.run("doGet").html, /esc\(it\.name \|\| guessName/, "the app must escape names");
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
  p.start();
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
  p.start();
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
  p.start();
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

test("'make a copy' of the script: the copy doesn't get the original's API key or work queue", () => {
  const claude = fakeClaude(normal, { pollsUntilEnded: 1000 });
  const p = loadProject(web(claude), batchOnly);
  p.addLinks(["https://maker.test/p/a100"]);
  p.start();
  p.run("tick");
  assert.ok(p.g.userProps.getProperty("ANTHROPIC_API_KEY"));
  p.g.sheetId.value = "script-2";   // the copy has a different id; Google copies the script and its properties
  p.run("doGet");
  assert.equal(p.g.userProps.getProperty("ANTHROPIC_API_KEY"), null, "API key copied to the copy");
  assert.equal(p.ctx.getBatches().length, 0);
  assert.equal(Object.keys(p.ctx.getStages()).length, 0);
  assert.equal(p.run("appState").items.length, 0, "the original's product list copied");
});

test("one shared link, many people: each Google user has their own key, list and settings", () => {
  const claude = fakeClaude(normal, { pollsUntilEnded: 1000 });
  const p = loadProject(web(claude), batchOnly);
  p.addLinks(["https://maker.test/p/a100"]);
  p.start();
  setSetting(p, "מודל", "claude-opus-5");
  const mine = p.ctx.PropertiesService;
  const other = new Map();
  const store = { getProperty: (k) => (other.has(k) ? other.get(k) : null), setProperty: (k, v) => { other.set(k, String(v)); return store; },
    deleteProperty: (k) => { other.delete(k); return store; }, deleteAllProperties: () => { other.clear(); return store; }, getProperties: () => Object.fromEntries(other) };
  p.ctx.PropertiesService = { ...mine, getUserProperties: () => store };   // dad opens the same link
  const st = p.run("appState");
  assert.equal(st.hasKey, false, "dad got my API key");
  assert.equal(st.items.length, 0, "dad sees my products");
  assert.equal(p.run("appGetSettings").values["מודל"], "claude-sonnet-5");
  p.ctx.PropertiesService = mine;
  assert.equal(p.run("appState").items.length, 1);
});

test("install: the web app opens (title, phone-friendly), with no spreadsheet at all", () => {
  const p = loadProject(() => null);
  const page = p.run("doGet");
  assert.equal(page.title, "סורק מוצרים");
  assert.match(page.meta.viewport, /width=device-width/);
  assert.match(page.html, /id="links"/);
  const code = readdirSync(new URL("..", import.meta.url)).filter((f) => f.endsWith(".gs")).map((f) => readFileSync(new URL("../" + f, import.meta.url), "utf8")).join("\n");
  assert.doesNotMatch(code, /SpreadsheetApp/);
});

test("no advanced services needed (install = paste one file); the readable Google Doc is built with DocumentApp", () => {
  const code = ["Main.gs", "Claude.gs", "Output.gs", "Extract.gs", "Settings.gs"].map((f) => readFileSync(new URL("../" + f, import.meta.url), "utf8")).join("\n");
  assert.doesNotMatch(code, /\bDrive\.Files\b/);
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100"]);
  p.start();
  p.runUntilIdle();
  const folder = rootOf(p).folders.find((f) => f.name.startsWith("MAKER-A100") && !f.trashed);
  const doc = folder.files.find((f) => f.mime === "application/vnd.google-apps.document" && !f.trashed);
  assert.ok(doc, "no Google Doc in the product folder");
  const lines = JSON.parse(doc.getBlob().getDataAsString());
  assert.equal(lines[0].heading, "TITLE");
  assert.ok(lines.some((l) => l.text === "תיאור קצר") && lines.every((l) => l.kind === "table" || l.rtl), "missing sections or not right-to-left");
});

test("a background run that crashes shows the error on the products and in the app", () => {
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude));
  p.addLinks(["https://maker.test/p/a100"]);
  p.start();
  const drive = p.ctx.DriveApp;
  p.ctx.DriveApp = { ...drive, getFoldersByName: () => { throw new Error("Exception: Access denied: DriveApp."); } };
  p.run("tick");
  p.ctx.DriveApp = drive;
  const notes = String(p.rows()[0][5]);
  assert.ok(/תקלה|שגיאה/.test(notes + p.rows()[0][1]), "nothing shown: " + p.rows()[0][1] + " / " + notes);
  const w = p.run("appState").worker;
  assert.equal(w.running, true);
  assert.match(w.lastError, /Access denied: DriveApp/);
  p.runUntilIdle();   // Drive is back: the product finishes and the error goes away on the next start
  assert.match(String(p.rows()[0][1]), /✓/);
});

// ---------- the app ----------

test("app: API key is checked and saved from the window", () => {
  const claude = fakeClaude(normal, { key: "sk-ant-good" });
  const p = loadProject(web(claude), { apiKey: "" });
  assert.equal(p.run("appState").hasKey, false);
  assert.equal(p.run("appSaveKey", "hello").ok, false);
  const bad = p.run("appSaveKey", "sk-ant-wrong");
  assert.equal(bad.ok, false, "wrong key accepted");
  assert.match(bad.message, /לא תקין/);
  assert.equal(p.run("appSaveKey", "  sk-ant-good  ").ok, true);
  assert.equal(p.run("appState").hasKey, true);
});

test("app: paste messy text with links, press start, watch progress, get the folder link", () => {
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude));
  const started = p.run("appStart", "תבדוק את זה: https://maker.test/p/a100, וגם את\nhttps://maker.test/p/a100?n=2.\nhttps://maker.test/p/a100");
  assert.equal(started.ok, true, started.message);
  assert.match(started.message, /2 מוצרים התחילו/);
  assert.equal(p.rows().length, 2);
  let st = p.run("appState");
  assert.equal(st.items.length, 2);
  assert.ok(st.items.every((i) => i.state === "working" && i.step === "ממתין להתחלה"));
  p.runUntilIdle();
  st = p.run("appState");
  assert.ok(st.items.every((i) => (i.state === "done" || i.state === "warn") && i.pct === 100), JSON.stringify(st.items));
  assert.ok(st.items.every((i) => i.folderUrl.startsWith("https://drive.google.com/")), "no folder link");
  assert.ok(st.items.every((i) => i.name && i.manufacturer === "Maker"));
});

test("app: start without an API key asks for the key; text without links explains", () => {
  const p = loadProject(() => null, { apiKey: "" });
  const r = p.run("appStart", "https://maker.test/p/a100");
  assert.equal(r.needKey, true);
  p.g.userProps.setProperty("ANTHROPIC_API_KEY", "sk-test");
  const r2 = p.run("appStart", "בלי קישורים בכלל");
  assert.equal(r2.ok, false);
  assert.match(r2.message, /לא מצאתי קישורים/);
});

test("app: settings are saved, used by the worker, and can be reset to the defaults", () => {
  const p = loadProject(() => null);
  let st = p.run("appGetSettings");
  assert.equal(st.values["מודל"], "claude-sonnet-5");
  assert.equal(st.keyEnd, "test");
  st = p.run("appSaveSettings", { ...st.values, "מודל": "claude-opus-5", "תיקייה בדרייב": "  מוצרים חדשים ", "מילון מונחים": st.values["מילון מונחים"] + "\r\nleak = נזילה" });
  assert.equal(st.values["מודל"], "claude-opus-5");
  const s = p.run("readSettings");
  assert.equal(s.model, "claude-opus-5");
  assert.equal(s.rootFolder, "מוצרים חדשים");
  assert.match(s.glossary, /\nleak = נזילה$/);
  assert.ok(!JSON.parse(p.ctx.getBig("SETTINGS"))["מילים שלא משתמשים בהן"], "unchanged defaults saved (improved defaults would never reach this install)");
  st = p.run("appResetSettings");
  assert.equal(st.values["מודל"], "claude-sonnet-5");
  assert.equal(p.run("readSettings").rootFolder, "NDT24 - מוצרים");
});

test("app: the list keeps finished products (with links) until cleared; clearing keeps running ones", () => {
  const claude = fakeClaude(normal, { pollsUntilEnded: 1000 });
  const p = loadProject(web(claude), batchOnly);
  p.addLinks(["https://maker.test/p/a100"]);
  p.start();
  p.run("tick");   // waiting on Claude
  const fin = p.ctx.getItems();
  fin.unshift({ id: "old", link: "https://x.test/old", status: "✓ הושלם", name: "ישן", manufacturer: "", folderUrl: "https://drive.google.com/x", notes: "" });
  p.ctx.flushItems();
  assert.equal(p.run("appState").items.length, 2);
  const after = p.run("appClearFinished");
  assert.deepEqual(after.items.map((i) => i.link), ["https://maker.test/p/a100"]);
});

test("app: the list is capped (oldest finished products dropped), and updates don't rewrite unchanged parts", () => {
  const p = loadProject(() => null);
  const list = p.ctx.getItems();
  for (let i = 0; i < 260; i++) list.push({ id: "x" + i, link: "https://x.test/" + i, status: "✓ הושלם", name: "מוצר " + i, manufacturer: "", folderUrl: "https://drive.google.com/" + i, notes: "הערה ".repeat(20) });
  p.ctx.flushItems();
  const items = p.run("getItems");
  assert.equal(items.length, 200);
  assert.equal(items[0].id, "x60");
  let writes = 0;
  const set = p.g.userProps.setProperty.bind(p.g.userProps);
  p.g.userProps.setProperty = (k, v) => { writes++; return set(k, v); };
  p.run("getItems");
  p.ctx.setRowStatus("x259", "✗ שגיאה", { notes: "x" });
  p.ctx.flushItems();
  p.g.userProps.setProperty = set;
  assert.ok(writes <= 3, "writes for one changed product: " + writes);
  assert.equal(p.run("getItems").at(-1).status, "✗ שגיאה");
});

// ---------- fast mode (direct calls) ----------
const fastMode = { fast: true };

test("fast mode: a product goes from link to finished Drive folder in a single run", () => {
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude), fastMode);
  p.addLinks(["https://maker.test/p/a100"]);
  p.start();
  p.run("tick");
  assert.match(String(p.rows()[0][1]), /✓/, "status after one run: " + p.rows()[0][1]);
  assert.equal(claude.batches.size, 0, "used batch jobs");
});

test("fast mode: 12 products finish in one run, fetched and written in parallel", () => {
  const claude = fakeClaude(normal);
  const p = loadProject(web(claude), fastMode);
  p.addLinks(Array.from({ length: 12 }, (_, i) => "https://maker.test/p/a100?n=" + i));
  p.start();
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
  p.start();
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
  p.start();
  p.runUntilIdle();
  assert.match(String(p.rows()[0][1]), /✓/, "status " + p.rows()[0][1] + " " + p.rows()[0][5]);
  assert.equal(busy, 3);
});

for (const r of results) console.log(r.join("  "));
const failed = results.filter((r) => r[0] === "✗").length;
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
