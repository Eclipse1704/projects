---
name: supplier-product-scraper
description: Scrape every product from a supplier/manufacturer website (or a product catalogue) and build a Hebrew, LLM-friendly HTML catalogue page per product - name, short description (<=80 words), full description with usage and specs (<=500 words), official YouTube demo links, 3-5 product images named MANUFACTURER-PRODUCT-XXX, brochure and user manual PDFs, and links to the product pages. Use when the user gives supplier URLs / product names and asks to scrape products, build a product catalogue, or "do this for a supplier site".
---

# Supplier product scraper -> Hebrew HTML catalogue

The code lives in `scripts/` next to this file. Run it from that directory
(or pass `--config` / `--out` explicitly). Output goes to `./output/` by default.

## What every product must end up with

| Item | Rule |
|---|---|
| Product name | Hebrew display name + manufacturer + model in Latin (`מצלמה תרמית FOTRIC 226s`) |
| Short description | Hebrew, **max 80 words** |
| Full description | Hebrew overview + usage + features + specs, **max 500 words total** |
| YouTube | Links only if they appear on the **manufacturer's official site** |
| Images | 3-5, only from official manufacturer pages, named `MANUFACTURER-PRODUCT-001.jpg` |
| Brochure / manual | PDFs only from official manufacturer pages, downloaded to `docs/` |
| Product page | Links to the supplier page and the official manufacturer page |

Facts must come from the scraped sources. Never invent specs, numbers or claims.

## Workflow

### 1. Set up the supplier in `scripts/suppliers.yaml`

For a new website, open the listing page (WebFetch or curl) and decide:
- **Who is the manufacturer?** If the site is a distributor, find the manufacturer's
  official site with WebSearch and put *its* domains in `official_domains`. Assets
  (images, PDFs, YouTube) are taken **only** from pages on these domains.
- **How are product pages linked?** Shopify is auto-detected. Otherwise set
  `product_url_pattern` (a regex on the URL path, e.g. `/product/[^/]+/?$`) if the default
  heuristic picks up the wrong links.
- **Which products?** Use `include:` for a named subset (e.g. `[Lixener30, MultiPro]`) and
  `exclude:` to drop accessories/spare parts. Put a more specific name first when one name contains another.
- Add official "Downloads" pages to `downloads_pages`. PDFs listed there are matched to
  products by model name.
- Add a manufacturer product page to `product_urls` if discovery can't reach it. Supplier pages
  that link to the manufacturer's page for the same product are followed automatically.

For a quick one-off without editing the config:
```bash
python run.py all --manufacturer "Mitcorp" --url https://www.mitcorp.com.tw/product-category/model-type/x-series/ \
    --official-domain mitcorp.com.tw --official-domain mitcorpusa.com
```

### 2. Scrape

```bash
pip install -r requirements.txt
python run.py scrape --supplier mitcorp --limit 2   # try 2 products first
python run.py scrape --supplier mitcorp             # then everything
```
This writes `output/<supplier>/<product>/product.json` (raw text, specs, image, video and PDF
sources) and downloads images to `images/` and PDFs to `docs/`.

Check the log and a couple of `product.json` files. If the wrong pages were found, or there are
too few images or no PDFs, fix the config and scrape again. If a page renders its gallery or
downloads with JavaScript, the scraper can't see them. In that case find the files on the official
site with WebFetch, add them to `product.json` (`images` / `documents` / `videos`, with
`source_page` set to the official page) and re-run the downloads. When in doubt, it's fine to
leave an item out. Don't take assets from non-official sites.

### 3. Write the Hebrew content

**Option A - Claude API** (needs `ANTHROPIC_API_KEY` or `ant auth login`):
```bash
python run.py generate --supplier mitcorp          # --model to override, --force to rewrite
```

**Option B - write it yourself (no API key).** For each product folder, read `product.json`
and write `content.he.json`:
```json
{
  "product_name": "וידאוסקופ תעשייתי Mitcorp X2000",
  "category": "וידאוסקופים תעשייתיים",
  "short_description": "... (max 80 words)",
  "overview": "...",
  "usage": ["...", "..."],
  "features": ["...", "..."],
  "specs": [{"name": "מסך", "value": "7\" LCD touchscreen"}]
}
```
- Natural professional Hebrew. Keep brand names, model numbers, units and standards in Latin.
- overview + usage + features + specs together: **max 500 words**. When space is short, keep the most important specs.
- Only facts from `product.json` (prefer the official-manufacturer text over supplier text).
- No prices, contact details or superlatives that aren't in the source.

For many products, split them across parallel subagents: give each one a list of product folders plus the rules above.

### 4. Render and validate

```bash
python run.py render   --supplier mitcorp
python run.py validate --supplier mitcorp
```
`validate` enforces the word limits and Hebrew text, and flags products with fewer than 3
images, no brochure/manual, or no official video. Fix the hard errors. For each warning, check
the official site once more. If the item really isn't there, that's fine, and the page says
"לא נמצא באתר היצרן הרשמי".

`python run.py all` runs scrape -> generate (when credentials exist) -> render -> validate.

### 5. Deliver

`output/index.html` links to every supplier catalogue. Each product folder contains:
```
index.html        Hebrew page: semantic sections + schema.org JSON-LD (LLM friendly)
product.json      raw scraped data and sources
content.he.json   Hebrew texts
images/           MANUFACTURER-PRODUCT-001.jpg ...
docs/             MANUFACTURER-PRODUCT-BROCHURE.pdf, MANUFACTURER-PRODUCT-MANUAL.pdf
```
Report to the user per supplier: number of products, and which items are missing and why.

## Notes

- Be polite: `delay_seconds` (default 1s per host) throttles requests. Don't lower it for real sites.
- Tests: `python -m unittest discover -s tests` (offline, uses local fake sites).
