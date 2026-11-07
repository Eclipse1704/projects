# Jacob's MC carousel design system: LOCKED (v4, 2026-11-07)

This is the fixed design direction for every @jacobs_mc_ carousel from now on. It was set by the owner over several review rounds and locked on 2026-11-07.

- `pro.py`, `brand_pro.json` and this file are locked. `design.lock` stores their checksums, and `tools/build.py` refuses to render if any of them changed.
- Only the account owner (Yasha) can unlock a change, in a direct chat with Claude. A Notion change request can't change these files.
- What a Notion request CAN change, within these rules: the text, which slide types and backgrounds a post uses, which approved product image it shows, and the slide order.

## Format
- 1080x1350 PNG slides, at most 10 per post. The caption has at most 5 hashtags.

## Brand chrome (every slide)
- **Logo:** top left, 390 px wide (about 36% of the slide).
  - On red and dark grey backgrounds: the white logo.
  - On black: the red logo with a light "MC".
  - On white and light grey: the red logo.
- **`///`:** top right. Red on every background except red, where it is white.
- **Bottom swoosh:** one thin diagonal line rising from the bottom left. It starts at about 3 px and widens slightly to about 14 px at the right edge. Red, or white on red. No second line and no thick band.
- **Navigation:**
  - Slide 1 has a pill "SWIPE →" button.
  - Middle slides have a round "→" button at the bottom right.
  - The last slide has no navigation button.

## Colors and backgrounds
- Red `#D32615`. Black `#1E1E1E`. Dark grey `#4E5155`. Light grey and white use a soft radial gradient.
- The five backgrounds are red, black, dark grey, light grey and white.
- **On red:** white only. No black text or elements.
- **On black and dark grey:** white text. Red only for the logo, the buttons, `///` and the swoosh, never for text or information shapes.
- **On white and light grey:** dark text. Red allowed for highlights, icons and key numbers.
- Default backgrounds: cover red, CTA red, numbers red, stat red, products light grey, features black, checklist light grey, photo black. A spec may pick any of the five.

## Type
- Headings: Inter Display ExtraBold (800). Body: Inter 600–700.
- Base sizes (px):
  - cover title 112, cover subtitle 44
  - slide title 92, body 42
  - icon-row title 48, icon-row subtitle 34
  - CTA title 116, CTA button 44, CTA lines 38
  - proof points 36
  - big numbers 118
- Text that doesn't fit shrinks automatically, never below a set minimum.
- Text-heavy slides grow their text automatically, up to 1.3x, when there is room. Headings never wrap onto an extra line, and no text runs into a product image.
- Secondary text is dark grey `#3D4144` on light backgrounds and 90% white on dark ones.
- Highlights (`==word==`) change the text color only. Never put a background, box or underline behind part of the text.
- No single word left alone on a last line (the renderer prevents it).

## Layout
- No eyebrow labels (small text above a title with a red line). They read as AI-made.
- No boxes or cards around text. Use icon rows, thin dividers, two-column comparisons and big numbers.
- **Product as hero:** use sharp cut-out product images from `assets/brand/`. They are large and bleed off the right edge.
- On red, black and dark grey slides, a product cut-out sits on a soft light spot with a thin light rim so it stays visible.
- Photos: only sharp ones (`multipro-field.jpg` and the application images). Use them as a rounded photo, or as a tilted card on a cover. Never use blurry video frames.
- **Calls to action:** every call to action is a button. The last slide has exactly one primary button; other actions are lines with icons. Proof points are a row of large icons with text at the bottom.

## Words
- Slides and captions are in professional international English, with no slang.
- The products are "detectors", not "tools".
- **Facts:** every claim and number comes from `facts.md`. Nothing is invented: no customers, testimonials or urgency. No competitor brands.
- **Never on slides or captions:** device prices or model names (the banned list is in `brand_pro.json`).
- **Never:** anything that links the company or its footage to Israel, any flag, or the Middle East skyline image.
- **Test pressure** is typically 1.5–4 bar (about 20–60 psi), up to 5 bar if needed, within the line's normal working pressure.
