"""Stage 1: find every product page reachable from a supplier's listing URLs."""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .common import Supplier, clean_url, host, is_official, matches_any
from .http import Fetcher

DEFAULT_PRODUCT_HINTS = re.compile(r"/(products?|produkte?|produits?|item|p)/[^/?#]+", re.I)
PAGINATION = re.compile(r"(/page/\d+/?$|[?&](page|paged|p)=\d+)", re.I)


@dataclass
class Candidate:
    url: str
    title: str = ""
    shopify: dict | None = None   # raw Shopify product JSON when available


def origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _shopify_products(fetcher: Fetcher, listing: str) -> list[Candidate] | None:
    base = origin(listing)
    m = re.search(r"/collections/([^/?#]+)", listing)
    root = f"{base}/collections/{m.group(1)}" if m else base
    out: list[Candidate] = []
    for page in range(1, 40):
        data = fetcher.get_json(f"{root}/products.json?limit=250&page={page}")
        if not isinstance(data, dict) or "products" not in data:
            return None if page == 1 else out
        items = data["products"]
        if not items:
            return None if page == 1 else out
        for p in items:
            out.append(Candidate(url=f"{base}/products/{p['handle']}", title=p.get("title", ""), shopify=p))
    return out


def _looks_like_product(url: str, listing: str, pattern: re.Pattern | None) -> bool:
    path = urlparse(url).path
    if pattern is not None:
        return bool(pattern.search(path))
    lpath = urlparse(listing).path.rstrip("/")
    if PAGINATION.search(url):
        return False
    if lpath and path.rstrip("/") != lpath and path.startswith(lpath + "/"):
        return True
    return bool(DEFAULT_PRODUCT_HINTS.search(path)) and "/category/" not in path and "/product-category/" not in path


def _crawl_listing(fetcher: Fetcher, sup: Supplier, listing: str) -> list[Candidate]:
    pattern = re.compile(sup.product_url_pattern, re.I) if sup.product_url_pattern else None
    allowed_hosts = {host(listing)}
    queue, seen_pages = [listing], set()
    found: dict[str, Candidate] = {}
    while queue and len(seen_pages) < sup.max_listing_pages:
        page = queue.pop(0)
        if page in seen_pages:
            continue
        seen_pages.add(page)
        html = fetcher.get_text(page)
        if not html:
            continue
        soup = BeautifulSoup(html, "lxml")
        for a in soup.find_all("a", href=True):
            url = clean_url(urljoin(page, a["href"]))
            if not url.startswith("http"):
                continue
            if host(url) not in allowed_hosts and not is_official(url, sup.official_domains):
                continue
            rel = " ".join(a.get("rel", []))
            if "next" in rel or (PAGINATION.search(url) and urlparse(url).path.startswith(urlparse(listing).path.rstrip("/"))):
                if url not in seen_pages:
                    queue.append(url)
                continue
            if _looks_like_product(url, listing, pattern):
                title = a.get_text(" ", strip=True) or a.get("title", "")
                c = found.setdefault(url, Candidate(url=url))
                if len(title) > len(c.title):
                    c.title = title
    return list(found.values())


def _sitemap_products(fetcher: Fetcher, sup: Supplier, listing: str) -> list[Candidate]:
    pattern = re.compile(sup.product_url_pattern, re.I) if sup.product_url_pattern else None
    base = origin(listing)
    todo = [f"{base}/sitemap.xml", f"{base}/sitemap_index.xml", f"{base}/product-sitemap.xml"]
    seen, out = set(), {}
    while todo and len(seen) < 30:
        sm = todo.pop(0)
        if sm in seen:
            continue
        seen.add(sm)
        xml = fetcher.get_text(sm)
        if not xml:
            continue
        for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", xml):
            if loc.endswith(".xml"):
                if "product" in loc or "page" in loc:
                    todo.append(loc)
            elif _looks_like_product(loc, listing, pattern):
                out[loc] = Candidate(url=loc)
    return list(out.values())


def discover(fetcher: Fetcher, sup: Supplier) -> list[Candidate]:
    cands: dict[str, Candidate] = {}
    for u in sup.product_urls:
        cands[u] = Candidate(url=u)
    for listing in sup.listing_urls:
        found = None
        if sup.platform in ("auto", "shopify"):
            found = _shopify_products(fetcher, listing)
            if found is not None:
                print(f"  shopify catalogue: {len(found)} products at {listing}")
        if found is None:
            found = _crawl_listing(fetcher, sup, listing)
            print(f"  crawl: {len(found)} product links at {listing}")
            if not found:
                found = _sitemap_products(fetcher, sup, listing)
                print(f"  sitemap fallback: {len(found)} product links")
        for c in found:
            prev = cands.get(c.url)
            if prev is None or (c.shopify and not prev.shopify):
                cands[c.url] = c

    def text_of(c: Candidate) -> str:
        extra = ""
        if c.shopify:
            extra = " ".join([c.shopify.get("product_type", ""), " ".join(c.shopify.get("tags", []) or [])])
        return f"{c.title} {urlparse(c.url).path} {extra}"

    result = list(cands.values())
    if sup.include:
        result = [c for c in result if matches_any(text_of(c), sup.include)]
    if sup.exclude:
        result = [c for c in result if not matches_any(text_of(c), sup.exclude)]
    return result
