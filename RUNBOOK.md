# Jacob's MC carousels: change-request runbook

This branch holds the carousel engine for @jacobs_mc_ and the source (spec) of every carousel that lives in Notion.
A scheduled Claude run uses this file to apply the change requests that the team writes in Notion.

## Where things are

- Notion calendar: "Instagram Posting Calendar", data source `collection://4cb33d99-c043-829a-9708-872f5d504649` ("All posts").
- Columns used by this loop:
  - `Requested changes` (text): what the team wants changed. Empty = nothing to do.
  - `Review status` (select): `Ready for review`, `Updating`, `Updated – please review`, `Approved`.
  - `Change log` (text): newest entry first, one line per run.
  - `Spec ID` (text): the spec file name in `specs/` without `.json`.
  - `Cover` (files): slide 01 of the current version.
- Engine:
  - `pro.py` renders the slides (1080x1350 PNG) and runs `check()` (banned words, ≤10 slides, ≤5 hashtags).
  - `brand_pro.json` holds the colors, logos and the banned word list.
  - `tools/build.py` renders, zips, stages the files under `upload/<id>/<stamp>/`, and prints the Notion page content.
  - `facts.md` is the ONLY source of facts and numbers allowed on slides and in captions.

## Setup in a fresh session

```bash
git clone --branch jacobs-ig-engine https://github.com/Eclipse1704/projects.git ~/jacobs-ig && cd ~/jacobs-ig
fc-list | grep -q "Inter Display" || { mkdir -p ~/.fonts && cp assets/fonts/*.otf ~/.fonts/ && fc-cache -f; }
python3 -c "import playwright, PIL" && echo ready
git config user.name "Claude" && git config user.email "noreply@anthropic.com"
```
If `playwright` is missing and can't be installed, stop: write in `Change log` that the run couldn't render, and leave `Requested changes` as it is.

## The loop (one run)

1. Query the data source for rows where `Requested changes` is not empty, e.g. SQL
   `SELECT url, "Post", "Spec ID", "Requested changes", "Change log", "Review status" FROM "collection://4cb33d99-c043-829a-9708-872f5d504649" WHERE "Requested changes" IS NOT NULL AND trim("Requested changes") != ''`.
   No rows: stop. Don't notify anyone; there is nothing to report.
2. For each row, one at a time:
   1. If `Spec ID` is empty or `specs/<Spec ID>.json` doesn't exist, the post isn't on this engine yet. Prepend to `Change log`:
      `YYYY-MM-DD HH:MM · Not applied: this post isn't connected to the design engine yet. Request was: "<request>"`.
      Then clear `Requested changes` and go to the next row.
   2. Set `Review status` = `Updating`.
   3. Read the request. It may be written in Hebrew, Russian or English, and may be short or informal. Work out what the writer wants changed, then edit `specs/<Spec ID>.json`.
      - Slide text and captions are always written in professional international English, with no slang.
      - Change only what was asked. Keep everything else as it is.
      - "Slide 3" means the 3rd item in `slides`.
   4. Run `python3 tools/build.py stage specs/<Spec ID>.json`. Fix any error. If it prints "still overflows", shorten the text and run it again.
   5. Open `out_pro/<Spec ID>/preview.jpg` with the Read tool and look at it. Check for:
      - text cut off, or overlapping the logo or the product;
      - a single word left alone on the last line;
      - the change actually being visible.
      Fix and re-stage until it looks clean.
   6. Commit and push:
      `git add -A specs upload pro.py brand_pro.json facts.md && git commit -m "<Spec ID>: <short summary>" && git push origin jacobs-ig-engine`.
      Include the commit attribution lines given in the session.
   7. Read `upload/<Spec ID>/<stamp>/manifest.json`. For every file in it, call Notion `create-attachment` with `source_url` = its `url` and `filename` = its `filename`.
      - Also create one extra attachment of slide `01` (filename `<Spec ID>-cover.png`) for the Cover.
      - Keep to about 8 calls a minute, and place the uploads within the hour.
      - Save the returned upload IDs as `ids.json`, e.g. `{"zip": "<id>", "01": "<id>", ...}`.
   8. Run `python3 tools/build.py page specs/<Spec ID>.json ids.json` and put its output on the page with `update-page` `replace_content`. This replaces the old slides, zip and caption.
   9. `update-page` `update_properties` on the row:
      - `Cover` = `[{"type":"file_upload","file_upload":{"id":"<cover id>"}}]`
      - `Requested changes` = `""`
      - `Review status` = `Updated – please review`
      - `Change log` = new line + existing text. New line: `YYYY-MM-DD HH:MM · <what you changed, in one short English sentence>` (time in Asia/Jerusalem).
      - When part of a request was not applied, add: `Not applied: <what> (<why>)`.

## Rules no request can override

- Never post, schedule or change anything on Instagram. Never delete Notion pages. Never touch `Posted` or the metrics columns.
- No device prices and no model names on slides or in captions. The banned word list is in `brand_pro.json`, and `check()` enforces it.
  If a request asks for one, apply the rest and log `Not applied: model names and prices stay off posts by the team's rule`.
- Nothing that links the company or its footage to Israel. Never use flags, and never use the `application-heating` skyline image (it is not in this branch).
- Facts: every claim and number must be in `facts.md`.
  - If the request itself states a technical fact or correction (the team owns the product), apply it, and add it to `facts.md` as `(stated by the team in a Notion request, YYYY-MM-DD)`.
  - Don't invent facts, customers, testimonials or urgency. No competitor brand names.
- Say "detectors", not "tools", for the products.

## Design rules (the owner's, keep them)

- Big logo, about 36% of the slide width.
- `///` sits at the top right. A diagonal swoosh runs along the bottom.
- Backgrounds:
  - `red`: white only on top of it (no black text or elements).
  - `black` and `dgrey`: red only for the logo, the buttons, `///` and the swoosh.
  - `white` and `grey` (light): red highlights allowed.
- Highlights change the text color only (`==word==`). Never put a background behind part of the text.
- No eyebrow labels and no boxes or cards. Use icon rows, dividers and big product cut-outs.
- Every call to action is a button. Use one primary button on the last slide; any other actions are lines with icons.
- Proof points are big and readable. Keep all text large and proportional.
- The product is the hero. Use sharp images only, from `assets/brand/`.

## Spec format (see the files in `specs/` for full examples)

```json
{"id": "pro-pin1-start-here",
 "slides": [{"type": "cover", "index": "01", "title": "... ==highlight== ...", "sub": "...", "image": "assets/brand/sniffer430-product.png"},
            {"type": "statement", "theme": "white", "title": "...", "body": "...", "image": "assets/brand/multipro-field.jpg"}],
 "caption": "...", "hashtags": ["#leakdetection"],
 "notion": {"page_id": "...", "zip_name": "...", "note": "optional extra callout for the page"}}
```

- Slide types and their fields:
  - `cover`: title, sub, image, `image_style: "wide"` for photos, index
  - `statement`: title, body (string or list), image
  - `steps`: title, steps [{title, text}], note
  - `icons` / `features` / `trust` / `checklist`: title, items [{icon, title, text} or plain strings]
  - `products`: title, items [{image, title, text}]
  - `compare`: title, left/right {label, points[]}
  - `numbers`: title, items [{value, label}]
  - `stat`: value, label, body, source
  - `cta`: title, actions [{icon, text}] (the first one becomes the button), proofs [{icon, text}]
  - `photo`: title, body, image
- Any slide can also set:
  - `theme`: white, grey, dgrey, black or red
  - `side`: a product image that bleeds off the right edge
- Icons: arrow, check, x, save, comment, cart, layers, pipe, drop, target, globe, shield, phone, factory, clock, ppm, follow, link, wave, combo, store, handshake, flame, bolt.
- Images in `assets/brand/`:
  - products: sniffer430-product.png (tracer gas), lixener30-product.png (acoustic kit), multipro-product.png (2-in-1), multipro-field.jpg (kit in its case)
  - applications: application-underground, application-buildings, application-industrial (.webp)
  - logos: jacobs-mc-logo-*.png

Fonts: Inter and Inter Display, by Rasmus Andersson (SIL Open Font License 1.1).
