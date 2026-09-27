// Loads the .gs files into a Node VM with the fake Google services.
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { makeGoogle } from "./fake-google.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// FAST=1 runs everything in fast mode (direct Claude calls); otherwise batch jobs.
export const FAST = process.env.FAST === "1";

// Changes one setting the way the app's settings screen does.
export function setSetting(p, name, value) {
  const values = p.run("appGetSettings").values;
  if (!(name in values)) throw new Error("no setting " + name);
  p.run("appSaveSettings", { ...values, [name]: value });
}

export function loadProject(fetchHandler, { apiKey = "sk-test", fast = FAST } = {}) {
  const g = makeGoogle({ fetchHandler });
  const ctx = vm.createContext({ ...g.google, JSON, Date, Math, String, Array, Object, RegExp, Error, parseInt, decodeURIComponent, encodeURIComponent, encodeURI });
  const code = readdirSync(ROOT).filter((f) => f.endsWith(".gs")).map((f) => readFileSync(path.join(ROOT, f), "utf8")).join("\n;\n");
  vm.runInContext(code, ctx);
  // Every trigger run / menu click is a fresh execution: module-level caches start empty.
  const fresh = () => vm.runInContext("SETTINGS_MEMO = null; FOLDER_MEMO = {}; ITEMS_MEMO = null; ITEMS_DIRTY = false; BIG_SEEN = {};", ctx);
  const run = (fn, ...args) => { fresh(); return ctx[fn](...args); };
  run("doGet");
  if (apiKey) g.userProps.setProperty("ANTHROPIC_API_KEY", apiKey);
  g.userProps.setProperty("ANTHROPIC_API_BASE", "https://api.test");
  const p = {
    g, ctx, run,
    // Links pasted in the app, not started yet: "start" sends them (like pressing התחל).
    pending: [],
    addLinks(links) { p.pending.push(...links); },
    start() { const t = p.pending.join("\n"); p.pending = []; return run("appStart", t); },
    items() { return run("getItems"); },
    // [link, status, name, manufacturer, folderUrl, notes, id] per product, oldest first.
    rows() { return p.items().map((it) => [it.link, it.status, it.name, it.manufacturer, it.folderUrl, it.notes, it.id]); },
    active() { return JSON.parse(g.userProps.getProperty("ACTIVE") || "[]"); },
    runUntilIdle(max = 40) { let i = 0; for (; i < max && g.triggers.some((t) => t.getHandlerFunction() === "tick"); i++) run("tick"); return i; },
  };
  setSetting(p, "מצב מהיר", fast ? "כן" : "לא");
  return p;
}

// Every fake answer costs this much: 100,000 input tokens, 5,000 output tokens, 2 web searches.
export const USAGE = { input_tokens: 100000, output_tokens: 5000, server_tool_use: { web_search_requests: 2 } };

// A tiny fake Claude Batches API. `answer(params, req)` returns {content, stop_reason} or {error}.
export function fakeClaude(answer, { key = "sk-test", pollsUntilEnded = 1, failCreate = null } = {}) {
  const batches = new Map();
  const requests = [];
  const direct = [];
  let creates = 0;
  function handle(url, opts) {
    const u = new URL(url);
    if (opts.headers["x-api-key"] !== key) return { code: 401, body: { type: "error", error: { type: "authentication_error", message: "invalid x-api-key" } }, type: "application/json" };
    if (opts.method === "post" && u.pathname === "/v1/messages") {   // direct call (fast mode)
      const params = JSON.parse(opts.payload);
      direct.push(params);
      requests.push({ custom_id: "direct", params });
      const a = answer(params, { params });
      if (a.timeout) return { timeout: true };
      if (a.status) return { code: a.status, body: { type: "error", error: { message: a.error || "error" } }, type: "application/json" };
      if (a.error) return { code: 400, body: { type: "error", error: { type: "invalid_request_error", message: a.error } }, type: "application/json" };
      return { body: { type: "message", role: "assistant", content: a.content, stop_reason: a.stop_reason || "end_turn", usage: a.usage || USAGE }, type: "application/json" };
    }
    if (opts.method === "post" && u.pathname === "/v1/messages/batches") {
      creates++;
      const f = failCreate && failCreate(creates);
      if (f) return f;
      const body = JSON.parse(opts.payload);
      const id = `msgbatch_${batches.size + 1}`;
      batches.set(id, { reqs: body.requests, polls: 0 });
      body.requests.forEach((r) => requests.push(r));
      return { body: { id, processing_status: "in_progress" }, type: "application/json" };
    }
    if (u.pathname === "/v1/models") return { body: { data: [] }, type: "application/json" };
    const m = u.pathname.match(/^\/v1\/messages\/batches\/(\w+)$/);
    if (m) {
      const b = batches.get(m[1]);
      if (!b) return { code: 404, body: { error: { message: "not found" } }, type: "application/json" };
      b.polls++;
      return { body: { id: m[1], processing_status: b.polls > pollsUntilEnded ? "ended" : "in_progress", results_url: `https://api.test/results/${m[1]}` }, type: "application/json" };
    }
    const r = u.pathname.match(/^\/results\/(\w+)$/);
    if (r) {
      const lines = batches.get(r[1]).reqs.map((req) => {
        const a = answer(req.params, req);
        const result = a.error ? { type: "errored", error: { type: "error", error: { type: "invalid_request_error", message: a.error } } }
          : a.expired ? { type: "expired" }
          : { type: "succeeded", message: { type: "message", role: "assistant", content: a.content, stop_reason: a.stop_reason || "end_turn", usage: a.usage || USAGE } };
        return JSON.stringify({ custom_id: req.custom_id, result });
      });
      return { body: lines.join("\n"), type: "application/x-jsonlines" };
    }
    return null;
  }
  return { handle, batches, requests, direct };
}

export const text = (t) => ({ content: [{ type: "text", text: t }], stop_reason: "end_turn" });
export const researchJson = (o) => text("```json\n" + JSON.stringify(o) + "\n```");
export const hebrew = (extra = {}) => text(JSON.stringify({
  name: "מוצר לדוגמה", short_description: "תיאור קצר של המוצר.", overview: "סקירה.", usage: ["שימוש"], features: ["תכונה"],
  specs: [], image_indexes: [], brochure_index: -1, manual_index: -1, video_indexes: [], ...extra,
}));
