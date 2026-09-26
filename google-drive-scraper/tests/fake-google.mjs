// Minimal in-memory stand-ins for the Apps Script services the scraper uses,
// so the whole flow can run under Node without a Google account.
import { createHash } from "node:crypto";

class Blob {
  constructor(data, type = "application/octet-stream", name = "") {
    this.buf = Buffer.isBuffer(data) ? data : Array.isArray(data) ? Buffer.from(data.map((b) => b & 255)) : Buffer.from(String(data ?? ""), "utf8");
    this.type = type;
    this.name = name;
  }
  getBytes() { return [...this.buf].map((b) => (b > 127 ? b - 256 : b)); } // Java-style signed bytes
  getDataAsString() { return this.buf.toString("utf8"); }
  getContentType() { return this.type; }
  setContentType(t) { this.type = t; return this; }
  getName() { return this.name; }
  setName(n) { this.name = n; return this; }
  copyBlob() { return new Blob(Buffer.from(this.buf), this.type, this.name); }
}

const iter = (arr) => { let i = 0; return { hasNext: () => i < arr.length, next: () => arr[i++] }; };
let nextId = 1;

class DFile {
  constructor(parent, blob, mime) { this.id = `file${nextId++}`; this.parent = parent; this.blob = blob; this.mime = mime || blob.type; this.trashed = false; }
  getName() { return this.blob.name; }
  getBlob() { return this.blob; }
  getId() { return this.id; }
  getMimeType() { return this.mime; }
  setTrashed(t) { this.trashed = t; return this; }
}

class DFolder {
  constructor(name, parent = null) { this.id = `folder${nextId++}`; this.name = name; this.parent = parent; this.folders = []; this.files = []; this.trashed = false; }
  live(list) { return list.filter((x) => !x.trashed); }
  getName() { return this.name; }
  setName(n) { this.name = n; return this; }
  getId() { return this.id; }
  getUrl() { return `https://drive.google.com/drive/folders/${this.id}`; }
  setTrashed(t) { this.trashed = t; return this; }
  getFolders() { return iter(this.live(this.folders)); }
  getFoldersByName(n) { return iter(this.live(this.folders).filter((f) => f.name === n)); }
  getFilesByName(n) { return iter(this.live(this.files).filter((f) => f.getName() === n)); }
  getFiles() { return iter(this.live(this.files)); }
  createFolder(n) { const f = new DFolder(n, this); this.folders.push(f); return f; }
  createFile(blob) { const f = new DFile(this, blob.copyBlob()); this.files.push(f); return f; }
}

class Range {
  constructor(sheet, r, c, nr = 1, nc = 1) { Object.assign(this, { sheet, r, c, nr, nc }); }
  getValues() {
    return Array.from({ length: this.nr }, (_, i) => Array.from({ length: this.nc }, (_, j) => this.sheet.get(this.r + i, this.c + j)));
  }
  setValues(v) { v.forEach((row, i) => row.forEach((x, j) => this.sheet.set(this.r + i, this.c + j, x))); return this; }
  setValue(x) { this.sheet.set(this.r, this.c, x); return this; }
  setFormula(x) { this.sheet.set(this.r, this.c, x); return this; }
  setFontWeight() { return this; }
  setWrap() { return this; }
  setVerticalAlignment() { return this; }
}

class Sheet {
  constructor(name) { this.name = name; this.cells = []; }
  get(r, c) { return (this.cells[r - 1] || [])[c - 1] ?? ""; }
  set(r, c, v) { (this.cells[r - 1] ||= [])[c - 1] = v; }
  getLastRow() { return this.cells.reduce((n, row, i) => (row && row.some((x) => x !== "" && x !== undefined) ? i + 1 : n), 0); }
  getRange(r, c, nr, nc) { return new Range(this, r, c, nr, nc); }
  setFrozenRows() {} setRightToLeft() {} setColumnWidth() {} hideColumns() {}
}

export function makeGoogle({ fetchHandler }) {
  const sheets = new Map();
  const ss = {
    getSheetByName: (n) => sheets.get(n) || null,
    insertSheet: (n) => { const s = new Sheet(n); sheets.set(n, s); return s; },
    getUrl: () => "https://docs.google.com/spreadsheets/d/test",
    toast: () => {},
  };
  const props = () => { const m = new Map(); return { getProperty: (k) => m.get(k) ?? null, setProperty: (k, v) => m.set(k, String(v)), deleteProperty: (k) => m.delete(k), m }; };
  const userProps = props();
  const scriptProps = props();
  const myDrive = new DFolder("My Drive");
  const triggers = [];
  const mails = [];
  const cache = new Map();
  const log = { fetches: [] };
  const alerts = [];

  const response = (code, body, headers = {}) => {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : JSON.stringify(body ?? ""), "utf8");
    const type = headers["Content-Type"] || "text/plain";
    return {
      getResponseCode: () => code,
      getContentText: () => buf.toString("utf8"),
      getBlob: () => new Blob(buf, type),
      getHeaders: () => headers,
    };
  };

  const google = {
    SpreadsheetApp: {
      getActive: () => ss,
      getUi: () => ({
        createMenu: () => { const m = { addItem: () => m, addSeparator: () => m, addToUi: () => {} }; return m; },
        alert: (msg) => alerts.push(msg),
        prompt: () => ({ getSelectedButton: () => "CANCEL", getResponseText: () => "" }),
        ButtonSet: { OK_CANCEL: 1 },
        Button: { OK: "OK" },
      }),
    },
    UrlFetchApp: {
      fetch(url, opts = {}) {
        log.fetches.push({ url, method: (opts.method || "get").toLowerCase(), payload: opts.payload, headers: opts.headers });
        const r = fetchHandler(url, opts);
        if (!r) return response(404, "not found");
        return response(r.code || 200, r.body, { "Content-Type": r.type || "text/html; charset=utf-8" });
      },
    },
    DriveApp: {
      getFoldersByName: (n) => myDrive.getFoldersByName(n),
      createFolder: (n) => myDrive.createFolder(n),
    },
    Drive: {
      Files: {
        create(resource, blob) {
          const find = (f) => (f.id === resource.parents[0] ? f : f.folders.map(find).find(Boolean));
          const folder = find(myDrive);
          const file = new DFile(folder, new Blob(blob.buf, resource.mimeType, resource.name), resource.mimeType);
          folder.files.push(file);
          return { id: file.id };
        },
      },
    },
    Utilities: {
      newBlob: (data, type, name) => new Blob(data, type, name),
      base64Encode: (x) => (typeof x === "string" ? Buffer.from(x, "utf8") : Buffer.from(x.map((b) => b & 255))).toString("base64"),
      computeDigest: (alg, x) => [...createHash("md5").update(typeof x === "string" ? Buffer.from(x, "utf8") : Buffer.from(x.map((b) => b & 255))).digest()].map((b) => (b > 127 ? b - 256 : b)),
      DigestAlgorithm: { MD5: "MD5" },
    },
    PropertiesService: { getUserProperties: () => userProps, getScriptProperties: () => scriptProps },
    CacheService: { getScriptCache: () => ({ get: (k) => cache.get(k) ?? null, put: (k, v) => cache.set(k, v) }) },
    LockService: { getScriptLock: () => ({ tryLock: () => true, releaseLock: () => {} }) },
    ScriptApp: {
      newTrigger: (fn) => ({ timeBased: () => ({ everyMinutes: () => ({ create: () => { const t = { getHandlerFunction: () => fn }; triggers.push(t); return t; } }) }) }),
      getProjectTriggers: () => [...triggers],
      deleteTrigger: (t) => { const i = triggers.indexOf(t); if (i >= 0) triggers.splice(i, 1); },
    },
    MailApp: { sendEmail: (to, subject, body) => mails.push({ to, subject, body }) },
    Session: { getEffectiveUser: () => ({ getEmail: () => "dad@example.com" }) },
    console: { log() {}, warn() {}, error: console.error },
  };
  return { google, sheets, myDrive, userProps, scriptProps, triggers, mails, log, alerts };
}
