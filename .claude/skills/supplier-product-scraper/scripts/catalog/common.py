"""Config loading and small helpers."""
from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urldefrag, urlparse

import yaml


@dataclass
class Supplier:
    id: str
    manufacturer: str
    listing_urls: list[str]
    official_domains: list[str]
    platform: str = "auto"                 # auto | shopify | woocommerce | generic
    product_url_pattern: str | None = None  # regex matched against product URL paths
    include: list[str] = field(default_factory=list)   # keep only products matching one of these
    exclude: list[str] = field(default_factory=list)   # drop products matching any of these
    product_urls: list[str] = field(default_factory=list)  # explicit product pages (skips discovery)
    downloads_pages: list[str] = field(default_factory=list)  # official pages listing PDFs for many products
    max_listing_pages: int = 20
    min_images: int = 3
    max_images: int = 5
    delay_seconds: float = 1.0


def load_suppliers(path: str | Path) -> list[Supplier]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    defaults = data.get("defaults", {}) or {}
    out = []
    for raw in data["suppliers"]:
        merged = {**defaults, **raw}
        out.append(Supplier(**{k: v for k, v in merged.items() if k in Supplier.__dataclass_fields__}))
    return out


def slugify(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    text = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-")
    return text


def file_stem(manufacturer: str, product: str) -> str:
    """MANUFACTURER-PRODUCT, upper-case, without repeating the manufacturer."""
    m = slugify(manufacturer).upper()
    p = slugify(product).upper()
    if p.startswith(m + "-"):
        p = p[len(m) + 1:]
    return f"{m}-{p}" if p else m


def host(url: str) -> str:
    return urlparse(url).netloc.lower().split(":")[0]


def is_official(url: str, domains: list[str]) -> bool:
    h = host(url)
    return any(h == d or h.endswith("." + d) for d in (d.lower().lstrip(".") for d in domains))


def clean_url(url: str) -> str:
    return urldefrag(url)[0]


def norm_key(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def matches_any(text: str, terms: list[str]) -> str | None:
    k = norm_key(text)
    for t in terms:
        if norm_key(t) and norm_key(t) in k:
            return t
    return None


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def word_count(text: str) -> int:
    return len(re.findall(r"\S+", text or ""))
