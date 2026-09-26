"""Command line entry point.  Run `python run.py --help`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

from . import content as content_mod
from .common import Supplier, host, load_suppliers, matches_any, read_json, slugify, write_json
from .discover import Candidate, discover
from .extract import extract_product, match_download_pages
from .http import Fetcher
from .media import download_documents, download_images
from .render import render_index, render_product

SCRIPTS_DIR = Path(__file__).resolve().parent.parent


def _group(sup: Supplier, cands: list[Candidate]) -> dict[str, list[Candidate]]:
    """Several pages (supplier site + manufacturer site) can describe one product."""
    groups: dict[str, list[Candidate]] = {}
    for c in cands:
        term = matches_any(f"{c.title} {urlparse(c.url).path}", sup.include) if sup.include else None
        key = term or urlparse(c.url).path.rstrip("/").rsplit("/", 1)[-1] or c.url
        groups.setdefault(slugify(key).lower(), []).append(c)
    return groups


def cmd_scrape(sup: Supplier, out: Path, limit: int | None) -> None:
    fetcher = Fetcher(delay=sup.delay_seconds)
    print(f"[{sup.id}] discovering products ...")
    groups = _group(sup, discover(fetcher, sup))
    print(f"[{sup.id}] {len(groups)} product(s)")
    items = list(groups.items())[:limit] if limit else list(groups.items())
    raws = []
    for key, group in items:
        print(f"[{sup.id}] extracting {key} ({len(group)} page(s))")
        raw = extract_product(fetcher, sup, group)
        raw["key"] = key
        raw["name"] = raw["name"] or key
        raws.append(raw)
    match_download_pages(fetcher, sup, raws)
    for raw in raws:
        pdir = out / sup.id / raw["key"]
        raw["downloaded_images"] = download_images(fetcher, sup, raw, pdir)
        raw["documents"] = download_documents(fetcher, sup, raw, pdir)
        write_json(pdir / "product.json", raw)
        print(f"  -> {raw['name']}: {len(raw['downloaded_images'])} images, {len(raw['videos'])} videos, "
              f"{sum(1 for d in raw['documents'] if d.get('file'))} PDFs")


def _product_dirs(out: Path, sup: Supplier) -> list[Path]:
    return sorted(p.parent for p in (out / sup.id).glob("*/product.json"))


def cmd_generate(sup: Supplier, out: Path, model: str, force: bool) -> None:
    for pdir in _product_dirs(out, sup):
        target = pdir / "content.he.json"
        if target.exists() and not force:
            continue
        raw = read_json(pdir / "product.json")
        print(f"[{sup.id}] writing Hebrew content for {raw['name']}")
        write_json(target, content_mod.generate(raw, model=model))


def cmd_validate(sup: Supplier, out: Path) -> int:
    bad = 0
    for pdir in _product_dirs(out, sup):
        target = pdir / "content.he.json"
        problems = content_mod.validate_content(read_json(target)) if target.exists() else ["content.he.json missing"]
        raw = read_json(pdir / "product.json")
        if len(raw.get("downloaded_images", [])) < sup.min_images:
            problems.append(f"only {len(raw.get('downloaded_images', []))} images (want {sup.min_images}-{sup.max_images}) - check official site")
        kinds = {d["kind"] for d in raw.get("documents", []) if d.get("file")}
        for k in ("brochure", "manual"):
            if k not in kinds:
                problems.append(f"no {k} downloaded - check official site")
        if not raw.get("videos"):
            problems.append("no official YouTube video found")
        status = "OK" if not problems else "; ".join(problems)
        hard = [p for p in problems if "check official" not in p and "YouTube" not in p]
        bad += bool(hard)
        print(f"[{sup.id}] {pdir.name}: {status}")
    return bad


def cmd_render(sups: list[Supplier], out: Path) -> None:
    top = []
    for sup in sups:
        entries = []
        for pdir in _product_dirs(out, sup):
            p = read_json(pdir / "product.json")
            cfile = pdir / "content.he.json"
            p["content"] = read_json(cfile) if cfile.exists() else {}
            (pdir / "index.html").write_text(render_product(p), encoding="utf-8")
            c = p["content"]
            entries.append((f"{pdir.name}/index.html", c.get("product_name") or p["name"], c.get("short_description", "")))
        if entries:
            (out / sup.id / "index.html").write_text(render_index(f"קטלוג מוצרים - {sup.manufacturer}", entries), encoding="utf-8")
            top.append((f"{sup.id}/index.html", sup.manufacturer, f"{len(entries)} מוצרים"))
            print(f"[{sup.id}] rendered {len(entries)} product page(s)")
    if top:
        out.mkdir(parents=True, exist_ok=True)
        (out / "index.html").write_text(render_index("קטלוג מוצרים", top), encoding="utf-8")


def _has_credentials() -> bool:
    import os
    return any(os.environ.get(k) for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")) or \
        Path.home().joinpath(".config", "anthropic").exists()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scrape supplier products and build Hebrew HTML catalogue pages.")
    ap.add_argument("command", choices=["all", "scrape", "generate", "validate", "render", "list"])
    ap.add_argument("--config", default=str(SCRIPTS_DIR / "suppliers.yaml"))
    ap.add_argument("--supplier", action="append", help="supplier id from the config (repeatable); default: all")
    ap.add_argument("--out", default="output", help="output directory (default: ./output)")
    ap.add_argument("--limit", type=int, help="only the first N products per supplier (for testing)")
    ap.add_argument("--model", default=content_mod.DEFAULT_MODEL)
    ap.add_argument("--force", action="store_true", help="regenerate existing Hebrew content")
    ap.add_argument("--no-llm", action="store_true", help="`all`: skip the Claude API step")
    # Ad-hoc supplier, no config edit needed:
    ap.add_argument("--url", action="append", help="ad-hoc: listing or product URL (repeatable)")
    ap.add_argument("--product-url", action="append", default=[], help="ad-hoc: a single product page URL (repeatable)")
    ap.add_argument("--manufacturer", help="ad-hoc: manufacturer name")
    ap.add_argument("--official-domain", action="append", help="ad-hoc: manufacturer's official domain (repeatable)")
    ap.add_argument("--include", action="append", default=[], help="ad-hoc: keep only products matching this name")
    ap.add_argument("--pattern", help="ad-hoc: regex for product URL paths")
    a = ap.parse_args(argv)

    if a.url or a.product_url:
        if not a.manufacturer:
            ap.error("--url/--product-url need --manufacturer")
        urls = (a.url or []) + a.product_url
        sups = [Supplier(id=slugify(a.manufacturer).lower(), manufacturer=a.manufacturer, listing_urls=a.url or [],
                         product_urls=a.product_url, official_domains=a.official_domain or [host(u) for u in urls],
                         include=a.include, product_url_pattern=a.pattern)]
    else:
        sups = load_suppliers(a.config)
        if a.supplier:
            sups = [s for s in sups if s.id in a.supplier]
            if not sups:
                ap.error(f"unknown supplier id(s): {a.supplier}")
    out = Path(a.out)

    if a.command == "list":
        for s in sups:
            print(f"{s.id:15} {s.manufacturer:20} {', '.join(s.listing_urls)}")
        return 0
    if a.command in ("all", "scrape"):
        for s in sups:
            cmd_scrape(s, out, a.limit)
    if a.command == "generate" or (a.command == "all" and not a.no_llm):
        if a.command == "all" and not _has_credentials():
            print("No Claude API credentials found - skipping Hebrew generation. Ask Claude Code to write "
                  "content.he.json files (see SKILL.md) or set ANTHROPIC_API_KEY, then run `generate`.")
        else:
            for s in sups:
                cmd_generate(s, out, a.model, a.force)
    if a.command in ("all", "render", "generate"):
        cmd_render(sups, out)
    if a.command in ("all", "validate"):
        return 1 if sum(cmd_validate(s, out) for s in sups) else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
