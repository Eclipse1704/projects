// End-to-end test: loads the unpacked extension in Chromium and runs a full job against
// fake sites on localhost plus a fake Claude API. No internet needed.
//   localhost  = distributor site (and the "own shop" style example page)
//   127.0.0.1  = manufacturer's official site + fake Claude API
// Run: npm test
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
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
    "localhost/product-category/scopes/": html(`<html><body><main>
      <a href="${sup}/product/x2000/">X2000 Videoscope</a>
      <a href="${sup}/product/x2000-probe-adapter/">X2000 probe adapter (accessory)</a>
      <a href="${sup}/product-category/scopes/page/2/">2</a><a href="${sup}/about/">About</a></main></body></html>`),
    "localhost/product-category/scopes/page/2/": html(`<html><body><a href="${sup}/product/x1000-plus/">X1000 Plus</a></body></html>`),
    "localhost/product/x2000/": html(`<html><body><main><h1>X2000 Videoscope</h1><p>${"Distributor text. ".repeat(30)}</p>
      <img src="${sup}/img/dist.jpg"><img src="${sup}/img/dist2.jpg"><a href="${sup}/files/x2000-brochure.pdf">Brochure</a>
      <a href="${man}/product/x2000/">Manufacturer page</a></main></body></html>`),
    "localhost/product/x1000-plus/": html(`<html><body><main><h1>X1000 Plus</h1><p>${"Older model. ".repeat(40)}</p><img src="a.jpg"><img src="b.jpg"></main></body></html>`),
    "localhost/product/x2000-probe-adapter/": html(`<html><body><main><h1>Adapter</h1><p>${"Adapter. ".repeat(60)}</p><img src="a.jpg"><img src="b.jpg"></main></body></html>`),
    "localhost/img/dist.jpg": [JPEG, "image/jpeg"],
    "localhost/files/x2000-brochure.pdf": [PDF, "application/pdf"],
    "localhost/shop/example-product/": html(`<html><body><main><h1>מצלמה תרמית 640X480 פיקסלים Fotric 348A</h1>
      <p>${"מצלמה תרמית מקצועית לאיתור נזילות ובדיקת לוחות חשמל. ".repeat(8)}</p></main></body></html>`),
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
    "127.0.0.1/wp-content/uploads/x2000-main.jpg": [JPEG, "image/jpeg"],
    "127.0.0.1/wp-content/uploads/x2000-side.jpg": [JPEG2, "image/jpeg"],
    "127.0.0.1/wp-content/uploads/x2000-probe.png": [PNG, "image/png"],
    "127.0.0.1/wp-content/uploads/logo.png": [PNG, "image/png"],
    "127.0.0.1/files/X2000_User_Manual.pdf": [PDF, "application/pdf"],
    "127.0.0.1/files/X2000-datasheet.pdf": [PDF, "application/pdf"],
  };
}

function claudeReply(body) {
  const req = JSON.parse(body);
  claudeCalls.push(req);
  const user = JSON.stringify(req.messages);
  let out;
  if (user.includes("Select the ones")) {
    // Pretend Claude kept the real videoscopes and dropped the accessory.
    const lines = req.messages[0].content.split("\n").filter((l) => /^\d+\t/.test(l));
    out = { selected: lines.filter((l) => !/adapter/i.test(l)).map((l) => +l.split("\t")[0]) };
  } else {
    out = user.includes("X1000") ? { ...HEBREW, name: "וידאוסקופ Mitcorp X1000 Plus" } : HEBREW;
  }
  return JSON.stringify({
    id: "msg_test", type: "message", role: "assistant", model: req.model,
    content: [{ type: "text", text: JSON.stringify(out) }],
    stop_reason: "end_turn", stop_sequence: null, usage: { input_tokens: 10, output_tokens: 10 },
  });
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
      res.end(claudeReply(body));
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
  let [sw] = context.serviceWorkers();
  if (!sw) sw = await context.waitForEvent("serviceworker");
  const extId = new URL(sw.url()).host;
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
    await chrome.storage.local.set({
      settings: { ...settings, apiBaseUrl: base },
      "job-test": {
        mode: "catalog", startUrl: `http://localhost:${new URL(base).port}/product-category/scopes/`, startHtml: null,
        manufacturer: "Mitcorp", officialDomains: ["127.0.0.1"], productType: "וידאוסקופים", category: "ציוד לבדיקות לא הורסות > וידאוסקופים",
        maxProducts: 10, downloadsPages: [], supplierId: "mitcorp",
      },
    });
  }, `http://127.0.0.1:${PORT}`);

  await page.goto(`chrome-extension://${extId}/runner.html?job=job-test`);
  await page.waitForSelector("#pick:not([hidden])", { timeout: 60000 });
  const checked = await page.$$eval("#pickRows tr", (rows) => rows.map((r) => [r.querySelector(".url").textContent, r.querySelector("input").checked]));
  const byUrl = Object.fromEntries(checked.map(([u, c]) => [new URL(u).pathname, c]));
  assert.deepEqual(byUrl, { "/product/x2000/": true, "/product/x2000-probe-adapter/": false, "/product/x1000-plus/": true });
  await page.click("#go");
  await page.waitForSelector("#done:not([hidden])", { timeout: 180000 });
  const doneText = await page.textContent("#done");
  assert.match(doneText, /2 מוצרים מוכנים/, doneText);

  // Files on disk
  const [runDir] = readdirSync(path.join(downloadDir, "NDT24-import"));
  const base = path.join(downloadDir, "NDT24-import", runDir);
  assert.match(runDir, /^mitcorp-/);
  const images = readdirSync(path.join(base, "images")).sort();
  assert.deepEqual(images, ["MITCORP-X2000-001.jpg", "MITCORP-X2000-002.jpg", "MITCORP-X2000-003.png"]);
  assert.deepEqual(readdirSync(path.join(base, "docs")).sort(), ["MITCORP-X2000-BROCHURE.pdf", "MITCORP-X2000-MANUAL.pdf"]);
  const csv = readFileSync(path.join(base, "products.csv"), "utf8");
  assert.ok(csv.startsWith("﻿\"Type\",\"SKU\",\"Name\""));
  assert.ok(csv.includes("וידאוסקופ תעשייתי Mitcorp X2000"));
  assert.ok(csv.includes("ציוד לבדיקות לא הורסות > וידאוסקופים"));
  assert.ok(csv.includes(`http://127.0.0.1:${PORT}/wp-content/uploads/x2000-main.jpg`), "CSV image URLs from official site");
  assert.ok(csv.includes("<p>https://www.youtube.com/watch?v=AbCdEfGhIjK</p>"));
  assert.ok(!csv.includes("localhost:" + PORT + "/files"), "distributor PDF must not be used");
  const preview = readFileSync(path.join(base, "preview.html"), "utf8");
  assert.ok(preview.includes('lang="he" dir="rtl"') && preview.includes("images/MITCORP-X2000-001.jpg") && preview.includes("IP54"));

  // Claude got the style example + glossary, and structured-output requests
  const writeCall = claudeCalls.find((c) => c.system);
  assert.ok(writeCall.system[0].text.includes("מצלמה תרמית מקצועית לאיתור נזילות"), "style example in prompt");
  assert.ok(writeCall.system[0].text.includes("videoscope = וידאוסקופ"), "glossary in prompt");
  assert.equal(writeCall.output_config.format.type, "json_schema");
  assert.equal(writeCall.model, "claude-opus-5");
  if (process.env.SHOTS) {
    await page.setViewportSize({ width: 1000, height: 900 });
    await page.screenshot({ path: path.join(process.env.SHOTS, "runner.png"), fullPage: true });
    const pv = await context.newPage();
    await pv.setViewportSize({ width: 1000, height: 900 });
    await pv.goto("file://" + path.join(base, "preview.html"));
    await pv.screenshot({ path: path.join(process.env.SHOTS, "preview.png"), fullPage: true });
    await pv.goto(`chrome-extension://${extId}/popup.html`);
    await pv.setViewportSize({ width: 410, height: 640 });
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
  rmSync(userDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  if (!failed) rmSync(downloadDir, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
