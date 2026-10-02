---
name: ndt24-add-products
description: Adds products to the NDT24 WooCommerce shop (ndt24.co.il) as drafts from product links - finds the manufacturer's official site, writes the Hebrew product page in the shop's style, takes 3-5 full-size images, catalog/brochure, user manual and YouTube video from the official site only, and uploads everything through the site's REST API. Use whenever the user sends product links (any site) and wants them on the site / in the shop, asks to "add these products", "תכניס לאתר", "תוסיף מוצרים", or asks to fix the text of a product that was added this way.
---

# Adding products to the NDT24 shop

The user (often on an iPhone/iPad, Hebrew speaker, not technical) sends product links. For each link, create a **draft** product
on ndt24.co.il with everything filled in, then report the draft links in short, simple Hebrew.

## Before anything: the connection

Run `python3 .claude/skills/ndt24-add-products/scripts/publish.py check`.

- `NDT24_WP_USER` / `NDT24_WP_APP_PASSWORD` not set → the user stores them in the environment settings (cloud environment menu in the
  session title → Edit → environment variables) and opens a new session. The password is a WordPress **application password**
  (site: שלום, borism → עריכת פרופיל → סיסמאות אפליקציה → הוספה; 6 groups of 4 letters), not the login password.
  **Never ask for it in the chat.** If they paste a password in chat anyway, don't use it; tell them to change it.
- Network errors / proxy 403 for ndt24.co.il or manufacturer sites → the environment's network access must allow them (same settings
  menu → Network access: full, or at least the shop and the manufacturers' domains). Say so in a few lines.
- `site 401 ... incorrect_password` → it's not an application password, see above.
- The output lists the shop's categories, the brand endpoint and where the theme keeps the catalog / manual / video fields. Use these
  category names exactly.

## Per product (do several in parallel when there are many)

1. **Read the link** (curl / WebFetch). Note the product name, model, and any links to the manufacturer.
2. **Find the manufacturer and its official site** (WebSearch). Distributors, resellers and marketplaces are not official.
   If the link itself is the manufacturer's site, use it.
3. **From the official site only**, collect:
   - the product page text (and the downloads page if there is one);
   - images: 3-5 photos of THIS product, the **full-size** originals (follow zoom/link targets, the largest `srcset` entry, strip
     WordPress `-300x300`, Shopify `_600x` style suffixes). Download them, check the real size (e.g. `python3 -c "from PIL import Image"`
     or `file`), prefer ≥ 800 px on the long side, drop logos/icons/banners/other products, no duplicates;
   - the brochure / datasheet PDF and the user manual PDF (check the file starts with `%PDF-`);
   - YouTube links on the official pages (not from other channels' searches).
   Never take images, files or videos from the supplier or other sites. Missing → leave it out and say so.
4. **Name the files** `MANUFACTURER-MODEL-001.jpg`, `-002.jpg`… (main image first), `MANUFACTURER-MODEL-BROCHURE.pdf`,
   `MANUFACTURER-MODEL-MANUAL.pdf` (upper-case, Latin letters/digits/hyphens, manufacturer not repeated: `FOTRIC-348A`).
5. **Write the Hebrew** following `references/writing.md` (read it once per session; it is the house style, glossary and the words to
   avoid). Check: short description ≤ 80 words, paragraphs + uses ≤ 500 words, none of the avoided words, facts only from the sources.
6. **Write `product.json`** (format in the docstring of `scripts/publish.py`) and run `python3 .../publish.py product.json`.
   It creates the draft (or updates the product made earlier from the same link), uploads images (main + gallery) and PDFs,
   sets category, tags, brand, the Yoast focus keyphrase and the theme's catalog / manual / video fields.
   For a **text fix** of a product made before, run it again with the new text and `"images": []`, `"catalog_pdf": ""`,
   `"manual_pdf": ""` so the files are not uploaded again.

## Report to the user

Short Hebrew, per product: name, the draft link (`edit` from the script), and what's missing (no video on the manufacturer's site,
only 2 images, category to pick by hand, warnings from the script). Remind them the products are **drafts**: they open each one,
check, and press "פרסום". Don't publish yourself.
