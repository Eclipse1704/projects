"""Stage 2: pull raw product facts, images, videos and PDFs out of product pages.

Only assets referenced from pages on the manufacturer's official domains are kept.
(An image served from the site's own CDN, e.g. cdn.shopify.com, still counts: the
official page is what vouches for it.)
"""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup, Tag

from .common import Supplier, clean_url, is_official, norm_key
from .discover import Candidate
from .http import Fetcher

MANUAL_WORDS = ("manual", "user guide", "userguide", "user-guide", "instruction", "operating",
                "operation guide", "handbuch", "bedienungsanleitung", "anleitung", "quick start",
                "quickstart", "guide")
BROCHURE_WORDS = ("brochure", "datasheet", "data sheet", "data-sheet", "catalog", "catalogue",
                  "leaflet", "flyer", "prospekt", "spec sheet", "specification", "datenblatt")
SKIP_IMG = re.compile(r"(logo|icon|sprite|placeholder|avatar|badge|flag|payment|banner|favicon|loader|spinner)", re.I)
YOUTUBE_ID = re.compile(r"(?:youtube(?:-nocookie)?\.com/(?:embed/|watch\?v=|v/|shorts/)|youtu\.be/)([A-Za-z0-9_-]{11})")
PRODUCT_LINK = re.compile(r"/(products?|produkte?|produits?|product-details)/[^/?#]+", re.I)
NOISE_TAGS = ("script", "style", "noscript", "nav", "header", "footer", "form", "svg", "iframe")


def _jsonld_products(soup: BeautifulSoup) -> list[dict]:
    out = []
    for s in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(s.string or "")
        except (ValueError, TypeError):
            continue
        stack = data if isinstance(data, list) else [data]
        while stack:
            d = stack.pop()
            if isinstance(d, dict):
                t = d.get("@type")
                if t == "Product" or (isinstance(t, list) and "Product" in t):
                    out.append(d)
                stack.extend(v for v in d.values() if isinstance(v, (dict, list)))
            elif isinstance(d, list):
                stack.extend(d)
    return out


def _meta(soup: BeautifulSoup, prop: str) -> str:
    tag = soup.find("meta", attrs={"property": prop}) or soup.find("meta", attrs={"name": prop})
    return (tag.get("content") or "").strip() if tag else ""


def _canonical_image(url: str) -> str:
    """Strip thumbnail size suffixes so the largest variant is downloaded."""
    url = re.sub(r"-\d{2,4}x\d{2,4}(?=\.(jpe?g|png|webp)$)", "", url, flags=re.I)        # WordPress
    url = re.sub(r"_(\d{2,4}x\d{0,4}|\d{0,4}x\d{2,4}|small|medium|large|grande|compact)(?=\.(jpe?g|png|webp))", "", url, flags=re.I)  # Shopify
    if url.startswith("//"):
        url = "https:" + url
    return url


def _img_src(img: Tag, base: str) -> str | None:
    for attr in ("data-large_image", "data-zoom-image", "data-src", "data-lazy-src", "data-original", "src"):
        v = img.get(attr)
        if v and not v.startswith("data:"):
            return urljoin(base, v)
    srcset = img.get("srcset") or img.get("data-srcset")
    if srcset:
        last = srcset.split(",")[-1].strip().split(" ")[0]
        return urljoin(base, last)
    return None


def _main_region(soup: BeautifulSoup) -> Tag:
    for sel in ("main", "article", "[class*=product]", "#content", ".content", "body"):
        node = soup.select_one(sel)
        if node is not None and len(node.get_text(strip=True)) > 200:
            return node
    return soup.body or soup


def _text_blocks(node: Tag) -> str:
    node = BeautifulSoup(str(node), "lxml")
    for t in node.find_all(NOISE_TAGS):
        t.decompose()
    lines = []
    for el in node.find_all(["h1", "h2", "h3", "h4", "p", "li", "td", "th", "dt", "dd"]):
        txt = el.get_text(" ", strip=True)
        if txt and (not lines or lines[-1] != txt):
            prefix = "## " if el.name in ("h1", "h2", "h3", "h4") else ("- " if el.name == "li" else "")
            lines.append(prefix + txt)
    text = "\n".join(lines)
    return text[:40000]


def _specs(node: Tag) -> list[list[str]]:
    specs = []
    for tr in node.select("table tr"):
        cells = [c.get_text(" ", strip=True) for c in tr.find_all(["th", "td"])]
        cells = [c for c in cells if c]
        if len(cells) >= 2:
            specs.append([cells[0], " | ".join(cells[1:])])
    for dl in node.find_all("dl"):
        for dt in dl.find_all("dt"):
            dd = dt.find_next_sibling("dd")
            if dd:
                specs.append([dt.get_text(" ", strip=True), dd.get_text(" ", strip=True)])
    seen, out = set(), []
    for k, v in specs:
        if (k, v) not in seen and len(k) < 120 and len(v) < 600:
            seen.add((k, v))
            out.append([k, v])
    return out[:150]


def classify_pdf(url: str, label: str) -> str:
    text = f"{label} {urlparse(url).path}".lower().replace("_", " ")
    if any(w in text for w in MANUAL_WORDS):
        return "manual"
    if any(w in text for w in BROCHURE_WORDS):
        return "brochure"
    return "document"


def youtube_url(src: str) -> str | None:
    m = YOUTUBE_ID.search(src)
    if m:
        return f"https://www.youtube.com/watch?v={m.group(1)}"
    q = parse_qs(urlparse(src).query)
    if "youtube" in src and "v" in q:
        return f"https://www.youtube.com/watch?v={q['v'][0]}"
    return None


def empty_raw(sup: Supplier) -> dict:
    return {
        "manufacturer": sup.manufacturer,
        "name": "",
        "product_pages": [],
        "descriptions": [],   # [{source, text}]
        "specs": [],          # [[key, value]]
        "images": [],         # [{url, source_page, alt}]
        "videos": [],         # [{url, source_page, title}]
        "documents": [],      # [{url, kind, label, source_page}]
        "_official_links": [],  # manufacturer pages linked from supplier pages
    }


def _add_unique(items: list[dict], new: dict, key: str = "url") -> None:
    if all(i[key] != new[key] for i in items):
        items.append(new)


def extract_page(fetcher: Fetcher, sup: Supplier, url: str, raw: dict, shopify: dict | None = None) -> None:
    official = is_official(url, sup.official_domains)
    html = fetcher.get_text(url)
    if not html:
        return
    soup = BeautifulSoup(html, "lxml")
    raw["product_pages"].append({"url": url, "official": official})

    ld = _jsonld_products(soup)
    h1 = soup.find("h1")
    name = (ld[0].get("name") if ld else "") or (h1.get_text(" ", strip=True) if h1 else "") or _meta(soup, "og:title")
    if shopify:
        name = shopify.get("title") or name
    first_official = official and not any(pg["official"] for pg in raw["product_pages"][:-1])
    if name and (not raw["name"] or first_official):
        raw["name"] = name.strip()  # the manufacturer's own product name wins

    main = _main_region(soup)
    desc_parts = []
    if shopify and shopify.get("body_html"):
        desc_parts.append(_text_blocks(BeautifulSoup(shopify["body_html"], "lxml")))
    for d in ld:
        if d.get("description"):
            desc_parts.append(BeautifulSoup(str(d["description"]), "lxml").get_text(" ", strip=True))
    if _meta(soup, "og:description"):
        desc_parts.append(_meta(soup, "og:description"))
    desc_parts.append(_text_blocks(main))
    raw["descriptions"].append({"source": url, "official": official, "text": "\n\n".join(p for p in desc_parts if p)})
    for kv in _specs(main):
        if kv not in raw["specs"]:
            raw["specs"].append(kv)

    if not official:
        # A distributor page often links to the manufacturer's page for the same product.
        for a in soup.find_all("a", href=True):
            link = clean_url(urljoin(url, a["href"]))
            if is_official(link, sup.official_domains) and PRODUCT_LINK.search(urlparse(link).path) \
                    and "category" not in link and link not in raw["_official_links"]:
                raw["_official_links"].append(link)
        return  # assets only from the manufacturer's own sites

    # Images: structured sources first (best quality, product-specific), then page gallery.
    img_urls: list[tuple[str, str]] = []
    if shopify:
        img_urls += [(i["src"], i.get("alt") or "") for i in shopify.get("images", []) if i.get("src")]
    for d in ld:
        imgs = d.get("image") or []
        for i in imgs if isinstance(imgs, list) else [imgs]:
            src = i.get("url") if isinstance(i, dict) else i
            if isinstance(src, str):
                img_urls.append((urljoin(url, src), ""))
    if _meta(soup, "og:image"):
        img_urls.append((urljoin(url, _meta(soup, "og:image")), "og:image"))
    gallery = main.select("[class*=gallery] img, [class*=Gallery] img, [class*=slider] img, [class*=product] img, figure img") or main.find_all("img")
    for img in gallery:
        src = _img_src(img, url)
        if src:
            img_urls.append((src, img.get("alt", "")))
    for a in main.select("a[href]"):
        if re.search(r"\.(jpe?g|png|webp)(\?|$)", a["href"], re.I):
            img_urls.append((urljoin(url, a["href"]), a.get_text(" ", strip=True)))
    for src, alt in img_urls:
        src = _canonical_image(clean_url(src) if "?" not in src else src)
        path = urlparse(src).path.lower()
        if SKIP_IMG.search(path) or path.endswith((".svg", ".gif")):
            continue
        _add_unique(raw["images"], {"url": src, "alt": alt, "source_page": url})

    # Videos: embeds and links on the official page.
    for el in soup.find_all(["iframe", "a", "lite-youtube", "div"]):
        src = el.get("src") or el.get("data-src") or el.get("href") or el.get("videoid") or el.get("data-video-id") or ""
        if el.name in ("lite-youtube", "div") and re.fullmatch(r"[A-Za-z0-9_-]{11}", src or ""):
            src = f"https://youtu.be/{src}"
        yt = youtube_url(src) if src else None
        if yt:
            _add_unique(raw["videos"], {"url": yt, "title": el.get("title", "") or el.get_text(" ", strip=True)[:120], "source_page": url})

    # Documents: every PDF linked from the official page.
    for a in soup.find_all("a", href=True):
        href = urljoin(url, a["href"])
        if re.search(r"\.pdf(\?|$)", href, re.I) or ("download" in href.lower() and "pdf" in (a.get("type", "") + a.get_text()).lower()):
            label = a.get_text(" ", strip=True) or a.get("title", "")
            _add_unique(raw["documents"], {"url": href, "kind": classify_pdf(href, label), "label": label, "source_page": url})


def match_download_pages(fetcher: Fetcher, sup: Supplier, products: list[dict]) -> None:
    """Attach PDFs from official 'downloads' pages to the product whose name they mention."""
    for page in sup.downloads_pages:
        if not is_official(page, sup.official_domains):
            continue
        html = fetcher.get_text(page)
        if not html:
            continue
        soup = BeautifulSoup(html, "lxml")
        for a in soup.find_all("a", href=True):
            href = urljoin(page, a["href"])
            if not re.search(r"\.pdf(\?|$)", href, re.I):
                continue
            label = a.get_text(" ", strip=True)
            ctx = a.find_parent(["tr", "li", "div"])
            haystack = norm_key(f"{label} {urlparse(href).path} {ctx.get_text(' ', strip=True) if ctx else ''}")
            for raw in products:
                key = norm_key(raw["name"].replace(sup.manufacturer, ""))
                if key and len(key) >= 3 and key in haystack:
                    _add_unique(raw["documents"], {"url": href, "kind": classify_pdf(href, label), "label": label, "source_page": page})


def extract_product(fetcher: Fetcher, sup: Supplier, group: list[Candidate]) -> dict:
    raw = empty_raw(sup)
    # Official pages first so the name/assets come from the manufacturer.
    for c in sorted(group, key=lambda c: not is_official(c.url, sup.official_domains)):
        extract_page(fetcher, sup, c.url, raw, c.shopify)
    visited = {pg["url"] for pg in raw["product_pages"]}
    key = norm_key(raw["name"].replace(sup.manufacturer, ""))
    for link in raw.pop("_official_links"):
        seg = norm_key(urlparse(link).path.rstrip("/").rsplit("/", 1)[-1])
        if link not in visited and key and seg and (key in seg or seg in key):
            extract_page(fetcher, sup, link, raw)
            visited.add(link)
    return raw
