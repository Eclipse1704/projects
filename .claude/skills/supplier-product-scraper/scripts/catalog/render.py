"""Stage 5: render LLM-friendly Hebrew HTML pages (+ JSON-LD) from product.json."""
from __future__ import annotations

import json
from html import escape
from pathlib import Path

STYLE = """
body{font-family:system-ui,-apple-system,"Segoe UI",Arial,sans-serif;max-width:960px;margin:0 auto;padding:16px;line-height:1.6;color:#1a1a1a;background:#fff}
h1{font-size:1.8rem;margin-bottom:.2rem}h2{border-bottom:1px solid #ddd;padding-bottom:4px;margin-top:2rem}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:6px 10px;text-align:start;vertical-align:top}th{background:#f5f5f5;width:35%}
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px}.gallery img{width:100%;height:180px;object-fit:contain;border:1px solid #eee;background:#fafafa}
figcaption,.muted{font-size:.8rem;color:#666}.ltr{direction:ltr;unicode-bidi:embed}
"""

KIND_HE = {"brochure": "ברושור", "manual": "מדריך למשתמש", "document": "מסמך"}


def _e(s) -> str:
    return escape(str(s or ""), quote=True)


def _ltr_link(url: str, text: str | None = None) -> str:
    return f'<a href="{_e(url)}" class="ltr" rel="noopener">{_e(text or url)}</a>'


def product_json_ld(p: dict) -> dict:
    c = p.get("content") or {}
    main_page = next((pg["url"] for pg in p["product_pages"] if pg.get("official")), p["product_pages"][0]["url"] if p["product_pages"] else "")
    return {
        "@context": "https://schema.org",
        "@type": "Product",
        "name": c.get("product_name") or p["name"],
        "alternateName": p["name"],
        "brand": {"@type": "Brand", "name": p["manufacturer"]},
        "manufacturer": {"@type": "Organization", "name": p["manufacturer"]},
        "category": c.get("category", ""),
        "description": c.get("short_description", ""),
        "url": main_page,
        "image": [i["file"] for i in p.get("downloaded_images", [])],
        "subjectOf": [{"@type": "VideoObject", "name": v.get("title") or p["name"], "url": v["url"], "embedUrl": v["url"]} for v in p.get("videos", [])],
        "additionalProperty": [{"@type": "PropertyValue", "name": s["name"], "value": s["value"]} for s in c.get("specs", [])],
        "inLanguage": "he",
    }


def render_product(p: dict) -> str:
    c = p.get("content") or {}
    name_he = c.get("product_name") or p["name"]
    missing = "<p class=\"muted\">לא נמצא באתר היצרן הרשמי.</p>"

    usage = "".join(f"<li>{_e(u)}</li>" for u in c.get("usage", []))
    features = "".join(f"<li>{_e(f)}</li>" for f in c.get("features", []))
    specs = "".join(f"<tr><th scope=\"row\">{_e(s['name'])}</th><td dir=\"auto\">{_e(s['value'])}</td></tr>" for s in c.get("specs", []))
    videos = "".join(
        f"<li>{_ltr_link(v['url'], v.get('title') or v['url'])} <span class=\"muted\">(מקור: {_ltr_link(v['source_page'])})</span></li>"
        for v in p.get("videos", []))
    images = "".join(
        f"<figure><a href=\"{_e(i['file'])}\"><img src=\"{_e(i['file'])}\" alt=\"{_e(name_he)} - תמונה {n}\" loading=\"lazy\"></a>"
        f"<figcaption class=\"ltr\">{_e(Path(i['file']).name)}</figcaption></figure>"
        for n, i in enumerate(p.get("downloaded_images", []), 1))
    docs = ""
    for d in p.get("documents", []):
        if d.get("file") or d["kind"] in ("brochure", "manual"):
            local = f" | <a href=\"{_e(d['file'])}\">קובץ מקומי</a>" if d.get("file") else ""
            docs += f"<li data-kind=\"{_e(d['kind'])}\"><strong>{KIND_HE.get(d['kind'], 'מסמך')}:</strong> {_ltr_link(d['url'], d.get('label') or None)}{local}</li>"
    pages = "".join(
        f"<li>{_ltr_link(pg['url'])} {'(אתר היצרן הרשמי)' if pg.get('official') else '(אתר הספק)'}</li>"
        for pg in p["product_pages"])

    return f"""<!doctype html>
<html lang="he" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(name_he)} | {_e(p['manufacturer'])}</title>
<meta name="description" content="{_e(c.get('short_description', ''))}">
<script type="application/ld+json">{json.dumps(product_json_ld(p), ensure_ascii=False)}</script>
<style>{STYLE}</style>
</head>
<body>
<article itemscope itemtype="https://schema.org/Product" data-manufacturer="{_e(p['manufacturer'])}" data-model="{_e(p['name'])}">
<header>
<h1 id="product-name" itemprop="name">{_e(name_he)}</h1>
<p class="muted">יצרן: <span itemprop="brand">{_e(p['manufacturer'])}</span> · דגם: <span class="ltr">{_e(p['name'])}</span>{' · קטגוריה: ' + _e(c['category']) if c.get('category') else ''}</p>
</header>

<section id="short-description" aria-labelledby="h-short">
<h2 id="h-short">תיאור קצר</h2>
<p itemprop="description">{_e(c.get('short_description', ''))}</p>
</section>

<section id="full-description" aria-labelledby="h-full">
<h2 id="h-full">תיאור מלא</h2>
<section id="overview"><h3>סקירה כללית</h3><p>{_e(c.get('overview', '')).replace(chr(10), '</p><p>')}</p></section>
<section id="usage"><h3>שימושים ואופן שימוש</h3><ul>{usage}</ul></section>
<section id="features"><h3>תכונות עיקריות</h3><ul>{features}</ul></section>
<section id="specifications"><h3>מפרט טכני</h3><table><tbody>{specs}</tbody></table></section>
</section>

<section id="videos" aria-labelledby="h-videos">
<h2 id="h-videos">סרטוני הדגמה (YouTube, מאתר היצרן הרשמי)</h2>
{f'<ul>{videos}</ul>' if videos else missing}
</section>

<section id="images" aria-labelledby="h-images">
<h2 id="h-images">תמונות מוצר</h2>
{f'<div class="gallery">{images}</div>' if images else missing}
</section>

<section id="documents" aria-labelledby="h-docs">
<h2 id="h-docs">ברושור ומדריך למשתמש</h2>
{f'<ul>{docs}</ul>' if docs else missing}
</section>

<section id="product-pages" aria-labelledby="h-pages">
<h2 id="h-pages">קישורים לדף המוצר</h2>
<ul>{pages}</ul>
</section>
</article>
</body>
</html>
"""


def render_index(title: str, entries: list[tuple[str, str, str]]) -> str:
    """entries: (href, name, short description)."""
    items = "".join(
        f"<li><h2><a href=\"{_e(h)}\">{_e(n)}</a></h2><p>{_e(d)}</p></li>" for h, n, d in entries)
    return f"""<!doctype html>
<html lang="he" dir="rtl">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title><style>{STYLE} ul{{list-style:none;padding:0}} li h2{{font-size:1.2rem;border:0}}</style></head>
<body><h1>{_e(title)}</h1><ul>{items}</ul></body></html>
"""
