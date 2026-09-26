// End-to-end test: loads the unpacked extension in Chromium and runs a full job against
// fake sites on localhost plus a fake Claude API. No internet needed.
//   localhost  = distributor site (and the "own shop" style example page)
//   127.0.0.1  = manufacturer's official site + fake Claude API
// Run: npm test
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const EXT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const JPEG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), randomBytes(20000)]);
const JPEG2 = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), randomBytes(20000)]);
const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47]), randomBytes(15000)]);
const PDF = Buffer.concat([Buffer.from("%PDF-1.4\n"), Buffer.alloc(2000, 48)]);
const claudeCalls = [];

const HEBREW = {
  name: "וידאוסקופ תעשייתי Mitcorp X2000",
  short_description: "וידאוסקופ תעשייתי עם מסך מגע 7 אינץ' לבדיקה חזותית של מנועים וצנרת.",
  overview: "וידאוסקופ לבדיקות לא הורסות.\n\nמתאים לעבודה בשטח.",
  usage: ["בדיקת מנועים", "בדיקת צנרת"],
  features: ["מסך מגע 7 אינץ'", "חיבור Wi-Fi"],
  specs: [{ name: "מסך", value: '7" LCD' }, { name: "דרגת הגנה", value: "IP54" }],
};

function routes(port) {
  const sup = `http://localhost:${port}`;
  const man = `http://127.0.0.1:${port}`;
  const html = (b) => [b, "text/html; charset=utf-8"];
  return {
    // Distributor: home page -> categories -> products
    "localhost/": html(`<html><body><nav>
      <a href="${sup}/product-category/scopes/">Videoscopes</a><a href="${sup}/product-category/pumps/">Pumps</a>
      <a href="${sup}/about/">About us</a></nav><main><p>${"Welcome to our shop. ".repeat(30)}</p><img src="a.jpg"><img src="b.jpg"></main></body></html>`),
    "localhost/product-category/scopes/": html(`<html><body><main>
      <a href="${sup}/product/x2000/">X2000 Videoscope</a>
      <a href="${sup}/product/x2000-probe-adapter/">X2000 probe adapter (accessory)</a>
      <a href="${sup}/product-category/scopes/page/2/">2</a><p>${"Scopes. ".repeat(80)}</p><img src="a.jpg"><img src="b.jpg"></main></body></html>`),
    "localhost/product-category/scopes/page/2/": html(`<html><body><main><a href="${sup}/product/x1000-plus/">X1000 Plus</a><p>${"Scopes. ".repeat(80)}</p><img src="a.jpg"><img src="b.jpg"></main></body></html>`),
    "localhost/product-category/pumps/": html(`<html><body><main><a href="${sup}/product/pump-100/">Pump 100</a><p>${"Pumps. ".repeat(80)}</p><img src="a.jpg"><img src="b.jpg"></main></body></html>`),
    "localhost/product/x2000/": html(`<html><body><main><h1>X2000 Videoscope</h1><p>${"Distributor text. ".repeat(30)}</p>
      <img src="${sup}/img/dist.jpg"><img src="${sup}/img/dist2.jpg"><a href="${sup}/files/x2000-brochure.pdf">Brochure</a>
      <a href="${man}/product/x2000/">Manufacturer page</a></main></body></html>`),
    "localhost/product/x1000-plus/": html(`<html><body><main><h1>X1000 Plus</h1><p>${"Older model. ".repeat(40)}</p><img src="a.jpg"><img src="b.jpg"></main></body></html>`),
    "localhost/product/x2000-probe-adapter/": html(`<html><body><main><h1>Adapter</h1><p>${"Adapter. ".repeat(60)}</p><img src="a.jpg"><img src="b.jpg"></main></body></html>`),
    "localhost/product/pump-100/": html(`<html><body><main><h1>Pump 100</h1><p>${"Pump. ".repeat(80)}</p><img src="a.jpg"><img src="b.jpg"></main></body></html>`),
    "localhost/img/dist.jpg": [JPEG, "image/jpeg"],
    "localhost/files/x2000-brochure.pdf": [PDF, "application/pdf"],
    "localhost/shop/example-product/": html(`<html><body><main><h1>מצלמה תרמית 640X480 פיקסלים Fotric 348A</h1>
      <p>${"מצלמה תרמית מקצועית לאיתור נזילות ובדיקת לוחות חשמל. ".repeat(8)}</p></main></body></html>`),
    // Manufacturer's official site
    "127.0.0.1/product/x2000/": html(`<html><head>
      <meta property="og:image" content="${man}/wp-content/uploads/x2000-main-300x300.jpg">
      <script type="application/ld+json">{"@type":"Product","name":"X2000","description":"Industrial videoscope."}</script></head>
      <body><main><h1>X2000</h1><p>${"Official description of X2000. ".repeat(20)}</p>
      <div class="woocommerce-product-gallery">
        <img src="${man}/wp-content/uploads/x2000-main-300x300.jpg">
        <img data-large_image="${man}/wp-content/uploads/x2000-side.jpg" src="${man}/wp-content/uploads/x2000-side-100x100.jpg">
        <img src="${man}/wp-content/uploads/x2000-probe.png"><img src="${man}/wp-content/uploads/logo.png"></div>
      <table><tr><th>Screen</th><td>7" LCD touchscreen</td></tr><tr><th>Protection</th><td>IP54</td></tr></table>
      <iframe src="https://www.youtube.com/embed/AbCdEfGhIjK"></iframe>
      <a href="${man}/files/X2000_User_Manual.pdf">User manual</a><a href="${man}/files/X2000-datasheet.pdf">Datasheet</a>
      </main></body></html>`),
    "127.0.0.1/downloads/": html(`<html><body><main><h1>Downloads</h1><table>
      <tr><td>X1000 Plus</td><td><a href="${man}/files/X1000-Plus-manual.pdf">Manual</a></td></tr>
      <tr><td>X2000</td><td><a href="${man}/files/X2000_User_Manual.pdf">Manual</a></td></tr></table><p>${"Downloads. ".repeat(60)}</p></main></body></html>`),
    "127.0.0.1/wp-content/uploads/x2000-main.jpg": [JPEG, "image/jpeg"],
    "127.0.0.1/wp-content/uploads/x2000-side.jpg": [JPEG2, "image/jpeg"],
    "127.0.0.1/wp-content/uploads/x2000-probe.png": [PNG, "image/png"],
    "127.0.0.1/wp-content/uploads/logo.png": [PNG, "image/png"],
    "127.0.0.1/files/X2000_User_Manual.pdf": [PDF, "application/pdf"],
    "127.0.0.1/files/X2000-datasheet.pdf": [PDF, "application/pdf"],
    "127.0.0.1/files/X1000-Plus-manual.pdf": [PDF, "application/pdf"],
  };
}

function claudeReply(body, port) {
  const req = JSON.parse(body);
  claudeCalls.push(req);
  const user = JSON.stringify(req.messages);
  const man = `http://127.0.0.1:${port}`;
  const text = (out) => JSON.stringify({
    id: "msg_test", type: "message", role: "assistant", model: req.model,
    content: [{ type: "text", text: typeof out === "string" ? out : JSON.stringify(out) }],
    stop_reason: "end_turn", stop_sequence: null, usage: { input_tokens: 10, output_tokens: 10 },
  });
  const listed = () => req.messages[0].content.split("\n").filter((l) => /^\d+\t/.test(l));
  if (user.includes("Give search keywords")) {
    return text({ keywords: ["videoscope", "scope", "borescope"], links: listed().filter((l) => /Videoscopes/.test(l)).map((l) => +l.split("\t")[0]) });
  }
  if (user.includes("pages of individual products")) {
    return text({ selected: listed().filter((l) => /X2000 Videoscope|X1000 Plus/.test(l)).map((l) => +l.split("\t")[0]) });
  }
  if (req.tools) return text("Research: made by Mitcorp (Taiwan). Official site 127.0.0.1 ...");
  if (user.includes("Extract the answer into the schema")) {
    const x2000 = user.includes("X2000");
    return text({
      manufacturer: "Mitcorp", model: x2000 ? "X2000" : "X1000 Plus", official_domains: ["127.0.0.1", "localhost"],
      official_product_url: x2000 ? `${man}/product/x2000/` : "", official_downloads_url: `${man}/downloads/`, site_is_manufacturer: false,
    });
  }
  return text(user.includes("X1000") ? { ...HEBREW, name: "וידאוסקופ Mitcorp X1000 Plus" } : HEBREW);
}

const server = http.createServer((req, res) => {
  const host = (req.headers.host || "").split(":")[0];
  const url = new URL(req.url, "http://x");
  if (req.method === "OPTIONS") {
    res.writeHead(204, { "access-control-allow-origin": "*", "access-control-allow-headers": "*", "access-control-allow-methods": "*" });
    return res.end();
  }
  if (url.pathname === "/v1/messages") {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json", "access-control-allow-origin": "*" });
      res.end(claudeReply(body, PORT));
    });
    return;
  }
  const r = ROUTES[`${host}${url.pathname}`];
  if (!r) { res.writeHead(404); return res.end("nope"); }
  res.writeHead(200, { "content-type": r[1] });
  res.end(r[0]);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const PORT = server.address().port;
const ROUTES = routes(PORT);

const userDir = mkdtempSync(path.join(tmpdir(), "ext-profile-"));
const downloadDir = mkdtempSync(path.join(tmpdir(), "ext-downloads-"));
// Chrome's own download folder (Playwright's download handling would rename the files).
mkdirSync(path.join(userDir, "Default"), { recursive: true });
writeFileSync(path.join(userDir, "Default", "Preferences"), JSON.stringify({
  download: { default_directory: downloadDir, prompt_for_download: false, directory_upgrade: true },
}));
const exe = existsSync("/opt/pw-browsers/chromium") ? "/opt/pw-browsers/chromium" : chromium.executablePath();
const chrome = spawn(exe, [
  "--headless=new", "--no-first-run", "--no-default-browser-check", "--remote-debugging-port=0",
  `--user-data-dir=${userDir}`, `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`,
  "--no-proxy-server", "--no-sandbox", "about:blank",
], { stdio: ["ignore", "ignore", "pipe"] });
const wsUrl = await new Promise((resolve, reject) => {
  let buf = "";
  chrome.stderr.on("data", (d) => {
    buf += d;
    const m = buf.match(/DevTools listening on (ws:\/\/\S+)/);
    if (m) resolve(m[1]);
  });
  chrome.on("exit", () => reject(new Error("chrome exited: " + buf)));
});
const browser = await chromium.connectOverCDP(wsUrl);
const context = browser.contexts()[0];
const bcdp = await browser.newBrowserCDPSession();
await bcdp.send("Browser.setDownloadBehavior", { behavior: "default" });

let failed = false;
try {
  // Unpacked extension id = first 32 hex chars of sha256(path), mapped 0-f -> a-p.
  const extId = [...createHash("sha256").update(EXT).digest("hex").slice(0, 32)].map((h) => String.fromCharCode(97 + parseInt(h, 16))).join("");
  const page = await context.newPage();
  page.on("pageerror", (err) => console.error("page error:", err.message));

  // Badge on a known supplier host is covered by presets; here: configure settings + a job.
  await page.goto(`chrome-extension://${extId}/options.html`);
  await page.fill("#apiKey", "sk-test");
  await page.fill("#outputFolder", "NDT24-import");
  await page.fill("#styleExampleUrls", `http://localhost:${PORT}/shop/example-product/`);
  await page.click("#save");
  await page.waitForSelector("#status:has-text('נשמר')");
  await page.evaluate(async (base) => {
    const { settings } = await chrome.storage.local.get("settings");
    // Exactly what the popup stores: the site and the product type.
    await chrome.storage.local.set({
      settings: { ...settings, apiBaseUrl: base },
      "job-test": { startUrl: `http://localhost:${new URL(base).port}/`, productType: "וידאוסקופים", startHtml: null },
    });
  }, `http://127.0.0.1:${PORT}`);

  await page.goto(`chrome-extension://${extId}/runner.html?job=job-test`);
  await page.waitForSelector("#done:not([hidden])", { timeout: 300000 });
  const doneText = await page.textContent("#done");
  assert.match(doneText, /2 מוצרים מוכנים/, doneText + "\n" + (await page.textContent("#log")));

  // Files on disk
  const [runDir] = readdirSync(path.join(downloadDir, "NDT24-import"));
  const base = path.join(downloadDir, "NDT24-import", runDir);
  assert.match(runDir, /^localhost-/);
  assert.deepEqual(readdirSync(base).sort(), ["MITCORP-X1000-PLUS", "MITCORP-X2000", "data.json", "index.html", "products.csv"]);
  const x = path.join(base, "MITCORP-X2000");
  assert.deepEqual(readdirSync(path.join(x, "images")).sort(), ["MITCORP-X2000-001.jpg", "MITCORP-X2000-002.jpg", "MITCORP-X2000-003.png"]);
  assert.deepEqual(readdirSync(path.join(x, "docs")).sort(), ["MITCORP-X2000-BROCHURE.pdf", "MITCORP-X2000-MANUAL.pdf"]);
  assert.deepEqual(readdirSync(path.join(base, "MITCORP-X1000-PLUS", "docs")), ["MITCORP-X1000-PLUS-MANUAL.pdf"], "manual from the official downloads page");
  assert.ok(!existsSync(path.join(base, "MITCORP-X1000-PLUS", "images")), "no images from the distributor");

  const page1 = readFileSync(path.join(x, "MITCORP-X2000.html"), "utf8");
  for (const needle of ['lang="he" dir="rtl"', 'id="product-name"', 'id="short-description"', 'id="full-description"', 'id="usage"',
    'id="specifications"', 'id="videos"', "watch?v=AbCdEfGhIjK", 'src="images/MITCORP-X2000-001.jpg"', 'href="docs/MITCORP-X2000-BROCHURE.pdf"',
    'href="docs/MITCORP-X2000-MANUAL.pdf"', `http://localhost:${PORT}/product/x2000/`, `http://127.0.0.1:${PORT}/product/x2000/`,
    "application/ld+json", "IP54"]) assert.ok(page1.includes(needle), `product page has ${needle}`);
  assert.ok(!page1.includes(`localhost:${PORT}/files`), "distributor PDF must not be used");

  const csv = readFileSync(path.join(base, "products.csv"), "utf8");
  assert.ok(csv.startsWith("﻿\"Type\",\"SKU\",\"Name\""));
  assert.ok(csv.includes("וידאוסקופ תעשייתי Mitcorp X2000") && csv.includes(`"וידאוסקופים"`));
  assert.ok(csv.includes(`http://127.0.0.1:${PORT}/wp-content/uploads/x2000-main.jpg`));
  const index = readFileSync(path.join(base, "index.html"), "utf8");
  assert.ok(index.includes('href="MITCORP-X2000/MITCORP-X2000.html"'));

  // Claude: only the requested type, web search for the official site, style + glossary + brochure in the writing call
  const search = claudeCalls.find((c) => c.tools);
  assert.equal(search.tools[0].type, "web_search_20260209");
  const writes = claudeCalls.filter((c) => c.system);
  assert.equal(writes.length, 2);
  assert.ok(writes[0].system[0].text.includes("מצלמה תרמית מקצועית לאיתור נזילות"), "style example in prompt");
  assert.ok(writes[0].system[0].text.includes("videoscope = וידאוסקופ"), "glossary in prompt");
  const x2000Write = writes.find((c) => JSON.stringify(c.messages).includes("X2000"));
  assert.equal(x2000Write.messages[0].content[0].type, "document", "brochure PDF given to Claude");
  assert.equal(x2000Write.model, "claude-opus-5");
  if (process.env.SHOTS) {
    await page.setViewportSize({ width: 1000, height: 900 });
    await page.screenshot({ path: path.join(process.env.SHOTS, "runner.png"), fullPage: true });
    const pv = await context.newPage();
    await pv.setViewportSize({ width: 1000, height: 900 });
    await pv.goto("file://" + path.join(x, "MITCORP-X2000.html"));
    await pv.screenshot({ path: path.join(process.env.SHOTS, "product.png"), fullPage: true });
    await pv.goto(`chrome-extension://${extId}/popup.html`);
    await pv.setViewportSize({ width: 390, height: 330 });
    await pv.screenshot({ path: path.join(process.env.SHOTS, "popup.png") });
  }
  console.log("✓ e2e passed:", base);
} catch (err) {
  failed = true;
  console.error(err);
} finally {
  await browser.close().catch(() => {});
  const exited = new Promise((r) => chrome.once("exit", r));
  chrome.kill();
  await exited;
  server.close();
  try { rmSync(userDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 }); } catch {}
  if (!failed) rmSync(downloadDir, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
