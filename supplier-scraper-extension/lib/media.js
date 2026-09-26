// Download images (3-5) and brochure/manual PDFs from official sources into the
// user's Downloads folder, named MANUFACTURER-PRODUCT-001.jpg etc.
import { fileStem, isOfficial } from "./common.js";
import { fetchResponse } from "./fetchpage.js";

const MIN_IMAGE_BYTES = 8000;
const IMAGE_TYPES = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp" };

export async function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  try {
    const id = await chrome.downloads.download({ url, filename, conflictAction: "overwrite", saveAs: false });
    await new Promise((resolve) => {
      const onChange = (d) => {
        if (d.id === id && d.state && d.state.current !== "in_progress") {
          chrome.downloads.onChanged.removeListener(onChange);
          resolve();
        }
      };
      chrome.downloads.onChanged.addListener(onChange);
      setTimeout(resolve, 120000);
    });
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }
}

export function saveText(text, filename, type = "text/plain;charset=utf-8") {
  return saveBlob(new Blob([text], { type }), filename);
}

async function sha1(buf) {
  const d = await crypto.subtle.digest("SHA-1", buf);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function downloadImages(job, raw, folder, { min = 3, max = 5, log } = {}) {
  const stem = fileStem(job.manufacturer, raw.name);
  const saved = [];
  const hashes = new Set();
  for (const img of raw.images) {
    if (saved.length >= max) break;
    if (!isOfficial(img.sourcePage, job.officialDomains)) continue;
    const r = await fetchResponse(img.url);
    if (!r) continue;
    const blob = await r.blob();
    const type = (blob.type || "").split(";")[0];
    const ext = IMAGE_TYPES[type] || (img.url.match(/\.(jpe?g|png|webp)(\?|$)/i)?.[1] || "").toLowerCase().replace("jpeg", "jpg");
    if (!ext || blob.size < MIN_IMAGE_BYTES) continue;
    const h = await sha1(await blob.arrayBuffer());
    if (hashes.has(h)) continue;
    hashes.add(h);
    const name = `${stem}-${String(saved.length + 1).padStart(3, "0")}.${ext}`;
    await saveBlob(blob, `${folder}/images/${name}`);
    saved.push({ file: name, url: img.url, sourcePage: img.sourcePage });
  }
  if (saved.length < min) log?.(`⚠ ${raw.name}: נמצאו רק ${saved.length} תמונות באתר היצרן`);
  return saved;
}

// One brochure and one manual per product.
export async function downloadDocuments(job, raw, folder) {
  const stem = fileStem(job.manufacturer, raw.name);
  const have = new Set();
  const order = { manual: 0, brochure: 1 };
  const docs = [...raw.documents].sort((a, b) => (order[a.kind] ?? 2) - (order[b.kind] ?? 2));
  for (const doc of docs) {
    if (!["manual", "brochure"].includes(doc.kind) || have.has(doc.kind) || !isOfficial(doc.sourcePage, job.officialDomains)) continue;
    const r = await fetchResponse(doc.url);
    if (!r) continue;
    const blob = await r.blob();
    const head = new Uint8Array(await blob.slice(0, 5).arrayBuffer());
    if (String.fromCharCode(...head) !== "%PDF-") continue;
    doc.file = `${stem}-${doc.kind.toUpperCase()}.pdf`;
    await saveBlob(blob, `${folder}/docs/${doc.file}`);
    have.add(doc.kind);
  }
  return docs;
}
