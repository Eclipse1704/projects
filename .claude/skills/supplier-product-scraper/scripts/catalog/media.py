"""Stage 3: download images (3-5), brochure and manual from official sources."""
from __future__ import annotations

import hashlib
from pathlib import Path
from urllib.parse import urlparse

from .common import Supplier, file_stem, is_official
from .http import Fetcher

MIN_IMAGE_BYTES = 8_000          # skip thumbnails/icons
IMAGE_TYPES = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}


def _download(fetcher: Fetcher, url: str, max_bytes: int = 80_000_000) -> tuple[bytes, str] | None:
    resp = fetcher.get(url, stream=True, cache=False)
    if resp is None:
        return None
    chunks, size = [], 0
    for chunk in resp.iter_content(64 * 1024):
        size += len(chunk)
        if size > max_bytes:
            print(f"  ! too large, skipped {url}")
            return None
        chunks.append(chunk)
    ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    return b"".join(chunks), ctype


def download_images(fetcher: Fetcher, sup: Supplier, raw: dict, out_dir: Path) -> list[dict]:
    stem = file_stem(sup.manufacturer, raw["name"])
    img_dir = out_dir / "images"
    saved, hashes = [], set()
    for img in raw["images"]:
        if len(saved) >= sup.max_images:
            break
        if not is_official(img["source_page"], sup.official_domains):
            continue
        got = _download(fetcher, img["url"], max_bytes=25_000_000)
        if not got:
            continue
        data, ctype = got
        ext = IMAGE_TYPES.get(ctype) or Path(urlparse(img["url"]).path).suffix.lower()
        if ext not in (".jpg", ".jpeg", ".png", ".webp") or len(data) < MIN_IMAGE_BYTES:
            continue
        digest = hashlib.sha1(data).hexdigest()
        if digest in hashes:
            continue
        hashes.add(digest)
        name = f"{stem}-{len(saved) + 1:03d}{'.jpg' if ext == '.jpeg' else ext}"
        img_dir.mkdir(parents=True, exist_ok=True)
        (img_dir / name).write_bytes(data)
        saved.append({"file": f"images/{name}", "url": img["url"], "source_page": img["source_page"], "alt": img.get("alt", "")})
    if len(saved) < sup.min_images:
        print(f"  ! only {len(saved)} official image(s) for {raw['name']}")
    return saved


def download_documents(fetcher: Fetcher, sup: Supplier, raw: dict, out_dir: Path) -> list[dict]:
    """Keep one brochure and one manual (plus extra documents listed but not downloaded)."""
    stem = file_stem(sup.manufacturer, raw["name"])
    saved, have = [], set()
    for doc in sorted(raw["documents"], key=lambda d: {"manual": 0, "brochure": 1}.get(d["kind"], 2)):
        entry = dict(doc)
        if doc["kind"] in ("manual", "brochure") and doc["kind"] not in have and is_official(doc["source_page"], sup.official_domains):
            got = _download(fetcher, doc["url"])
            if got and got[0][:5] == b"%PDF-":
                name = f"{stem}-{doc['kind'].upper()}.pdf"
                (out_dir / "docs").mkdir(parents=True, exist_ok=True)
                (out_dir / "docs" / name).write_bytes(got[0])
                entry["file"] = f"docs/{name}"
                have.add(doc["kind"])
        saved.append(entry)
    return saved

