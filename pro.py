"""Jacob's MC carousel renderer, "pro" template v3 (Nov 2026, after the owner's reference tiles).

Rules baked in:
- Backgrounds: white, grey (light), dgrey (mid grey), black, red. Subtle gradients.
- On red: white only (no black text or elements). On dark: red only for logo, button, /// and swoosh.
- Big logo (~36% width), "///" top right, diagonal swoosh at the bottom of every slide.
- No eyebrow labels, no boxes: icon rows, dividers, big product cut-outs.
- Every call to action is a button. One primary button per final slide.

Slide types: cover, statement, steps, icons (also: features, trust, checklist), products,
compare, numbers, stat, cta, photo. "==word==" highlights by text colour only.

  python3 pro.py render specs/pro-pin1-start-here.json
"""
import argparse, base64, html, json, math, mimetypes, re, shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_brand(path=None):
    return json.loads((Path(path) if path else HERE / "brand_pro.json").read_text(encoding="utf-8"))


def md(t):
    if t is None:
        return ""
    s = html.escape(str(t), quote=False)
    s = re.sub(r"==(.+?)==", r"<mark>\1</mark>", s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    return s.replace("\n", "<br>")


def data_uri(rel):
    p = (HERE / rel) if not Path(rel).is_absolute() else Path(rel)
    mime = mimetypes.guess_type(str(p))[0] or "application/octet-stream"
    return f"data:{mime};base64," + base64.b64encode(p.read_bytes()).decode()


ICONS = {
    "arrow": '<path d="M4 12h15M13 5.5l6.5 6.5-6.5 6.5"/>',
    "check": '<path d="M4.5 12.5l5 5L19.5 7"/>',
    "x": '<path d="M6 6l12 12M18 6L6 18"/>',
    "save": '<path d="M6 3h12v18l-6-4.6L6 21z"/>',
    "comment": '<path d="M21 11.5a8.5 8.5 0 0 1-12.4 7.6L3 21l1.9-5.4A8.5 8.5 0 1 1 21 11.5z"/>',
    "cart": '<circle cx="9" cy="20" r="1.4"/><circle cx="18" cy="20" r="1.4"/><path d="M2.5 3.5h3l2.4 11.2a1.6 1.6 0 0 0 1.6 1.3h8.3a1.6 1.6 0 0 0 1.6-1.2L21.5 7H6.4"/>',
    "layers": '<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>',
    "pipe": '<path d="M3 9h12a4 4 0 0 1 4 4v8"/><path d="M3 15h9a1 1 0 0 1 1 1v5"/><path d="M3 7v10"/>',
    "drop": '<path d="M12 2.5C9 7 6 10.2 6 14a6 6 0 0 0 12 0c0-3.8-3-7-6-11.5z"/>',
    "target": '<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r=".8"/>',
    "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.6 2.6 3.9 5.6 3.9 9s-1.3 6.4-3.9 9c-2.6-2.6-3.9-5.6-3.9-9S9.4 5.6 12 3z"/>',
    "shield": '<path d="M12 2.5l8 3v6c0 5-3.4 8.7-8 10-4.6-1.3-8-5-8-10v-6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',
    "phone": '<path d="M5 3h4l2 5-2.5 1.5a11 11 0 0 0 6 6L16 13l5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 5a2 2 0 0 1 2-2z"/>',
    "factory": '<path d="M3 21V10l6 4V10l6 4V5h6v16z"/><path d="M7 18h2M12 18h2M17 18h2"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/>',
    "ppm": '<path d="M3 20h18"/><path d="M6 16v-3M10 16V9M14 16v-5M18 16V5"/>',
    "follow": '<circle cx="9" cy="8" r="4"/><path d="M2 21c0-3.9 3.1-7 7-7s7 3.1 7 7"/><path d="M19 7v7M15.5 10.5h7"/>',
    "link": '<path d="M10 14a4.5 4.5 0 0 0 6.4 0l3.2-3.2a4.5 4.5 0 0 0-6.4-6.4L12 5.6"/><path d="M14 10a4.5 4.5 0 0 0-6.4 0l-3.2 3.2a4.5 4.5 0 0 0 6.4 6.4l1.2-1.2"/>',
    "wave": '<path d="M2 12h2.5l2-5 3 10 3-14 3 18 3-12 1.5 3H22"/>',
    "combo": '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="M7 15l2.5-5 2.5 6 2-4 1.5 3H18"/>',
    "store": '<path d="M3 9l1.5-5h15L21 9"/><path d="M4 9v11h16V9"/><path d="M3 9h18"/><path d="M10 20v-5h4v5"/>',
    "handshake": '<path d="M2 11l4-4 4 2 4-2 4 2 4 4"/><path d="M6 13l4 4a1.5 1.5 0 0 0 2-2l-1-1M10 15l2 2a1.5 1.5 0 0 0 2-2l-1-1M13 14l1 1a1.5 1.5 0 0 0 2-2l-3-3"/>',
    "flame": '<path d="M12 2.5c1 3.5 5 5.5 5 10.5a5 5 0 0 1-10 0c0-2.5 1.5-4 2.5-5 .3 1.6 1.2 2.6 2.2 3 .3-3.3-.7-6-.7-8.5z"/>',
    "bolt": '<path d="M13 2.5L4.5 13.5H11l-1 8 8.5-11H12z"/>',
}


def icon(name, size=40, stroke=2.4):
    return (f'<svg class="ic" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            f'stroke-width="{stroke}" stroke-linecap="round" stroke-linejoin="round">{ICONS.get(name, ICONS["check"])}</svg>')


SLASHES = ('<svg class="slashes" width="84" height="40" viewBox="0 0 84 40" fill="currentColor">'
           '<path d="M14 40L28 0h12L26 40z"/><path d="M36 40L50 0h12L48 40z"/><path d="M58 40L72 0h12L70 40z"/></svg>')
SWOOSH = ('<svg class="swoosh" width="1080" height="130" viewBox="0 0 1080 130" preserveAspectRatio="none" fill="currentColor">'
          '<path d="M0 130 L1080 62 L1080 84 L330 130 Z"/><path class="thin" d="M0 112 L1080 44 L1080 48 L0 117 Z"/></svg>')


def font_faces(brand):
    css = ""
    for key in ("head_font", "body_font"):
        f = brand.get(key) or {}
        for w, rel in (f.get("files") or {}).items():
            style = "italic" if "italic" in w else "normal"
            weight = re.sub(r"\D", "", w) or "400"
            css += f"@font-face{{font-family:'{f['family']}';src:url('{data_uri(rel)}');font-weight:{weight};font-style:{style}}}\n"
    return css


CSS = """
*{box-sizing:border-box;margin:0;padding:0}
html,body{width:1080px;height:1350px;overflow:hidden;background:#000}
body{font-family:var(--body);-webkit-font-smoothing:antialiased;text-rendering:geometricPrecision}
.slide{position:absolute;inset:0;overflow:hidden;display:flex;flex-direction:column;padding:62px 72px 64px;color:var(--fg)}
/* themes */
.t-white{--fg:#1E1E1E;--fg2:#4D5255;--acc:var(--red);--line:rgba(0,0,0,.13);background:radial-gradient(120% 90% at 75% 20%,#FFFFFF 0%,#F2F2F0 60%,#E9E9E7 100%)}
.t-grey{--fg:#1E1E1E;--fg2:#4D5255;--acc:var(--red);--line:rgba(0,0,0,.14);background:radial-gradient(120% 90% at 75% 20%,#F0F0EF 0%,#E1E2E0 60%,#D5D6D4 100%)}
.t-dgrey{--fg:#fff;--fg2:rgba(255,255,255,.84);--acc:#fff;--line:rgba(255,255,255,.24);background:radial-gradient(120% 90% at 75% 20%,#63666A 0%,#4E5155 55%,#3E4144 100%)}
.t-black{--fg:#fff;--fg2:rgba(255,255,255,.84);--acc:#fff;--line:rgba(255,255,255,.2);background:radial-gradient(120% 90% at 75% 20%,#323232 0%,#1C1C1C 55%,#111 100%)}
.t-red{--fg:#fff;--fg2:#fff;--acc:#fff;--line:rgba(255,255,255,.45);background:radial-gradient(120% 90% at 75% 20%,#E2361F 0%,var(--red) 55%,#B81C0E 100%)}

/* chrome: big logo, ///, swoosh */
.top{position:relative;z-index:4;display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.logo img{width:390px;height:auto;display:block}
.slashes{color:var(--red);display:block}
.t-red .slashes{color:#fff}
.swoosh{position:absolute;left:0;bottom:0;z-index:1;color:var(--red)}
.swoosh .thin{opacity:.35}
.t-red .swoosh{color:#fff}
.bottom{position:relative;z-index:4;display:flex;justify-content:flex-end;align-items:center;min-height:92px}
.main{position:relative;z-index:3;flex:1;min-height:0;display:flex;flex-direction:column;justify-content:safe center;padding:26px 0 20px}

/* buttons */
.btn{display:inline-flex;align-items:center;gap:18px;border-radius:999px;font-weight:800;line-height:1;background:var(--red);color:#fff;
  box-shadow:0 14px 28px rgba(0,0,0,.22)}
.t-red .btn{background:#fff;color:var(--red)}
.swipe-btn{padding:22px 32px 22px 38px;font-size:31px;letter-spacing:.1em;text-transform:uppercase}
.swipe-btn .ic{width:40px;height:40px}
.next{width:92px;height:92px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:var(--red);color:#fff;box-shadow:0 10px 22px rgba(0,0,0,.2)}
.t-red .next{background:#fff;color:var(--red)}
.next .ic{width:48px;height:48px}

/* type */
h1,h2,h3{font-family:var(--head);font-weight:var(--head-w);letter-spacing:-.01em}
h1,h2{line-height:1.08}
mark{background:none;color:var(--acc)}
.t-white mark,.t-grey mark{color:var(--red)}
.title{font-size:92px}
.body{margin-top:30px;font-size:42px;line-height:1.3;font-weight:600;color:var(--fg2)}
.has-side .main>*{max-width:600px}

/* side product image (bleeds off the right edge) */
.side{position:absolute;z-index:2;right:-70px;bottom:200px;max-width:620px;max-height:640px;width:auto;height:auto;filter:drop-shadow(0 26px 30px rgba(0,0,0,.3))}

/* cover */
.k-cover .main{justify-content:flex-start;padding-top:46px}
.cover-title{font-size:112px;max-width:960px;line-height:1.04}
.cover-sub{margin-top:30px;font-size:44px;line-height:1.26;font-weight:700;max-width:520px;color:var(--fg2)}
.hero{position:absolute;z-index:2;right:-60px;bottom:150px;width:640px;max-height:560px;object-fit:contain;filter:drop-shadow(0 30px 36px rgba(0,0,0,.35))}
.hero-card{position:absolute;z-index:2;right:56px;bottom:170px;width:620px;height:370px;border-radius:26px;overflow:hidden;border:10px solid #fff;transform:rotate(-2deg);box-shadow:0 30px 60px rgba(0,0,0,.35)}
.hero-card img{width:100%;height:100%;object-fit:cover;display:block}
.cover-index{position:absolute;left:56px;bottom:70px;z-index:2;font-family:var(--head);font-weight:900;font-size:230px;line-height:.8;letter-spacing:-.06em;
  color:transparent;-webkit-text-stroke:5px var(--line)}
.t-red .cover-index,.t-black .cover-index,.t-dgrey .cover-index{-webkit-text-stroke-color:rgba(255,255,255,.6)}

/* statement photo */
.pic{margin-top:40px;border-radius:28px;overflow:hidden;height:440px;flex-shrink:0;box-shadow:0 20px 40px rgba(0,0,0,.18)}
.pic img{width:100%;height:100%;object-fit:cover;display:block}

/* icon rows (no boxes) */
.irows{margin-top:46px;display:flex;flex-direction:column;gap:34px}
.irow{display:flex;align-items:center;gap:30px}
.irow>.ic{flex-shrink:0;width:78px;height:78px;color:var(--acc)}
.irow .t{font-family:var(--head);font-weight:var(--head-w);font-size:48px;line-height:1.1;letter-spacing:-.01em}
.irow .s{font-size:34px;line-height:1.28;font-weight:600;color:var(--fg2);margin-top:6px}

/* steps */
.steps{margin-top:48px;display:flex;flex-direction:column}
.step{display:flex;gap:34px;position:relative;padding-bottom:40px}
.step:last-child{padding-bottom:0}
.step:not(:last-child):after{content:"";position:absolute;left:45px;top:96px;bottom:6px;width:5px;background:var(--line)}
.num{flex-shrink:0;width:94px;height:94px;border-radius:50%;background:var(--red);color:#fff;display:flex;align-items:center;justify-content:center;
  font-family:var(--head);font-weight:var(--head-w);font-size:48px}
.t-red .num,.t-black .num,.t-dgrey .num{background:#fff;color:var(--black)}
.t-red .num{color:var(--red)}
.step h3{font-size:52px;line-height:1.08;margin-top:8px}
.step p{font-size:37px;line-height:1.3;font-weight:600;color:var(--fg2);margin-top:10px}
.note{margin-top:38px;font-size:32px;font-weight:700;color:var(--fg2)}

/* products: image + text rows with dividers */
.prods{margin-top:40px;display:flex;flex-direction:column}
.prod{display:flex;gap:30px;align-items:center;padding:24px 0;border-top:4px solid var(--line)}
.prod:last-child{border-bottom:4px solid var(--line)}
.pimg{flex-shrink:0;width:250px;height:180px;display:flex;align-items:center;justify-content:center}
.pimg img{max-width:100%;max-height:100%;object-fit:contain;filter:drop-shadow(0 12px 14px rgba(0,0,0,.2))}
.prod h3{font-size:50px;line-height:1.06}
.prod p{font-size:34px;line-height:1.26;font-weight:600;color:var(--fg2);margin-top:8px}

/* compare: two columns, divider, no boxes */
.cmp{margin-top:50px;display:grid;grid-template-columns:1fr 1fr}
.col{padding-right:34px}
.col.good{padding:0 0 0 34px;border-left:5px solid var(--line)}
.col h3{font-size:48px;line-height:1.08;margin-bottom:30px}
.col.bad h3{color:var(--fg2)}
.t-white .col.good h3,.t-grey .col.good h3{color:var(--red)}
.col ul{list-style:none;display:flex;flex-direction:column;gap:28px}
.col li{display:flex;gap:16px;align-items:flex-start;font-size:37px;line-height:1.24;font-weight:700}
.col.bad li{color:var(--fg2)}
.col li .ic{flex-shrink:0;width:44px;height:44px;margin-top:2px}
.col.good li .ic{color:var(--acc)}

/* numbers: big values with dividers */
.nums{margin-top:40px;display:grid;grid-template-columns:1fr 1fr;column-gap:48px}
.numt{padding:34px 0 36px;border-top:5px solid var(--line)}
.numt .v{font-family:var(--head);font-weight:var(--head-w);font-size:118px;line-height:1;letter-spacing:-.03em;white-space:nowrap}
.t-white .numt .v,.t-grey .numt .v{color:var(--red)}
.numt .l{margin-top:16px;font-size:36px;font-weight:700;line-height:1.2;color:var(--fg2)}

/* stat */
.stat{font-family:var(--head);font-weight:var(--head-w);letter-spacing:-.03em;font-size:168px;line-height:1;white-space:nowrap}
.stat-label{margin-top:26px;font-size:54px;line-height:1.16;font-weight:800;max-width:900px}
.source{margin-top:44px;font-size:30px;font-weight:700;color:var(--fg2)}

/* cta: one button, text lines, proof icons, product */
.k-cta .main{justify-content:flex-start;padding-top:40px}
.cta-title{font-size:116px;line-height:1.04;max-width:940px}
.cta-btn{margin-top:52px;align-self:flex-start;padding:34px 46px 34px 50px;font-size:44px}
.cta-btn .ic{width:52px;height:52px}
.lines{margin-top:38px;display:flex;flex-direction:column;gap:20px}
.ln{display:flex;align-items:center;gap:18px;font-size:38px;font-weight:700;color:var(--fg)}
.ln .ic{flex-shrink:0;width:48px;height:48px;color:var(--acc)}
.proofs{margin-top:auto;display:flex;gap:40px;padding-top:30px}
.proof{display:flex;flex-direction:column;gap:12px;font-family:var(--head);font-weight:var(--head-w);font-size:36px;line-height:1.08}
.proof .ic{width:58px;height:58px;color:var(--acc)}
.k-cta .side{bottom:300px;max-width:470px;max-height:430px}
.k-cta.has-side .main>.cta-title,.k-cta.has-side .main>.lines{max-width:960px}
.k-cta.has-side .main>.cta-btn{max-width:none}
.cta-btn,.ln{white-space:nowrap}

/* photo (strong solid overlay under the text) */
.k-photo .bg{position:absolute;inset:0;z-index:0}
.k-photo .bg img{width:100%;height:100%;object-fit:cover;display:block}
.k-photo .shade{position:absolute;left:0;right:0;bottom:0;height:62%;z-index:1;background:linear-gradient(180deg,rgba(17,17,17,0) 0%,rgba(17,17,17,.92) 26%,#111 100%)}
.k-photo .main{justify-content:flex-end}
"""

FIT_JS = """
() => {
  const main = document.querySelector('.main');
  const els = [...document.querySelectorAll('[data-fit]')];
  const over = () => main.scrollHeight > main.clientHeight + 1 || els.some(e => e.scrollWidth > e.clientWidth + 1);
  let guard = 0;
  while (over() && guard++ < 60) {
    let changed = false;
    for (const el of els) {
      const min = parseFloat(el.dataset.fit) || 24, fs = parseFloat(getComputedStyle(el).fontSize);
      if (fs > min) { el.style.fontSize = Math.max(min, fs * 0.95) + 'px'; changed = true; }
    }
    if (!changed) break;
  }
  return { overflow: over() };
}
"""


def title(s, cls="title", fit=66):
    return f'<h2 class="{cls}" data-fit="{fit}">{md(s["title"])}</h2>' if s.get("title") else ""


def body(s, fit=32):
    b = s.get("body")
    if not b:
        return ""
    items = b if isinstance(b, list) else [b]
    return f'<div class="body" data-fit="{fit}">' + "".join(f"<p>{md(p)}</p>" for p in items) + "</div>"


def b_cover(s):
    sub = f'<div class="cover-sub" data-fit="34">{md(s["sub"])}</div>' if s.get("sub") else ""
    return f'<h1 class="cover-title" data-fit="78">{md(s["title"])}</h1>{sub}'


def b_statement(s):
    pic = f'<div class="pic"><img src="{data_uri(s["image"])}"></div>' if s.get("image") else ""
    return f'{title(s)}{body(s)}{pic}'


def b_photo(s):
    return f'{title(s)}{body(s)}'


def b_steps(s):
    st = "".join(f'<div class="step"><div class="num">{i}</div><div><h3 data-fit="42">{md(x["title"])}</h3><p data-fit="30">{md(x["text"])}</p></div></div>'
                 for i, x in enumerate(s["steps"], 1))
    note = f'<div class="note">{md(s["note"])}</div>' if s.get("note") else ""
    return f'{title(s)}<div class="steps">{st}</div>{note}'


def b_icons(s):
    rows = ""
    for x in s["items"]:
        if isinstance(x, str):
            x = {"icon": s.get("icon", "check"), "title": x}
        sub = f'<div class="s" data-fit="28">{md(x["text"])}</div>' if x.get("text") else ""
        rows += f'<div class="irow">{icon(x.get("icon", "check"), 78, 2.2)}<div><div class="t" data-fit="38">{md(x["title"])}</div>{sub}</div></div>'
    return f'{title(s)}<div class="irows">{rows}</div>'


def b_products(s):
    r = "".join(f'<div class="prod"><div class="pimg"><img src="{data_uri(x["image"])}"></div><div><h3 data-fit="40">{md(x["title"])}</h3><p data-fit="28">{md(x["text"])}</p></div></div>'
                for x in s["items"])
    return f'{title(s)}<div class="prods">{r}</div>'


def b_compare(s):
    def col(c, good):
        ic = icon("check" if good else "x", 44, 3)
        lis = "".join(f'<li>{ic}<span data-fit="29">{md(x)}</span></li>' for x in c["points"])
        return f'<div class="col {"good" if good else "bad"}"><h3>{md(c["label"])}</h3><ul>{lis}</ul></div>'
    return f'{title(s)}<div class="cmp">{col(s["left"], False)}{col(s["right"], True)}</div>'


def b_numbers(s):
    t = "".join(f'<div class="numt"><div class="v" data-fit="66">{md(x["value"])}</div><div class="l" data-fit="26">{md(x["label"])}</div></div>' for x in s["items"])
    return f'{title(s)}<div class="nums">{t}</div>'


def b_stat(s):
    lab = f'<div class="stat-label" data-fit="40">{md(s["label"])}</div>' if s.get("label") else ""
    src = f'<div class="source">{md(s["source"])}</div>' if s.get("source") else ""
    return f'<div class="stat" data-fit="100">{md(s["value"])}</div>{lab}{body(s)}{src}'


def b_cta(s):
    acts = s.get("actions", [])
    btn = ""
    if acts:
        a = acts[0]
        btn = f'<div class="btn cta-btn"><span>{md(a["text"])}</span>{icon("arrow", 52, 2.8)}</div>'
    lines = "".join(f'<div class="ln">{icon(a.get("icon", "arrow"), 48, 2.4)}<span>{md(a["text"])}</span></div>' for a in acts[1:])
    lines = f'<div class="lines">{lines}</div>' if lines else ""
    pr = "".join(f'<div class="proof">{icon(x.get("icon", "check"), 58, 2.2)}<span>{md(x["text"])}</span></div>' for x in s.get("proofs", []))
    pr = f'<div class="proofs">{pr}</div>' if pr else ""
    return f'<h2 class="cta-title" data-fit="80">{md(s["title"])}</h2>{btn}{lines}{pr}'


BODIES = {"cover": b_cover, "statement": b_statement, "photo": b_photo, "steps": b_steps, "icons": b_icons,
          "features": b_icons, "trust": b_icons, "checklist": b_icons, "products": b_products, "compare": b_compare,
          "numbers": b_numbers, "stat": b_stat, "cta": b_cta}
DEFAULT_THEME = {"cover": "red", "cta": "red", "stat": "red", "numbers": "red", "features": "black", "products": "grey",
                 "checklist": "grey", "photo": "black"}


def logo_html(brand, theme, kind):
    if theme == "red":
        key = "logo_white"
    elif theme == "dgrey":
        key = "logo_white"
    elif theme == "black" or kind == "photo":
        key = "logo_dark"
    else:
        key = "logo"
    return f'<div class="logo"><img src="{data_uri(brand[key])}"></div>'


def slide_html(spec, s, i, n, brand):
    kind = s.get("type", "statement")
    theme = s.get("theme") or DEFAULT_THEME.get(kind, "white")
    c = brand["colors"]
    hf, bf = brand["head_font"], brand["body_font"]
    root = (f":root{{--red:{c['red']};--black:{c['black']};"
            f"--head:'{hf['family']}',{hf.get('fallback', 'sans-serif')};--head-w:{hf.get('weight', 800)};"
            f"--body:'{bf['family']}',{bf.get('fallback', 'sans-serif')}}}")
    if i == n:
        nav = ""
    elif i == 1:
        nav = f'<div class="btn swipe-btn">Swipe {icon("arrow", 40, 3)}</div>'
    else:
        nav = f'<div class="next">{icon("arrow", 48, 3)}</div>'
    extra, cls = "", ""
    if kind == "photo":
        extra = f'<div class="bg"><img src="{data_uri(s["image"])}"></div><div class="shade"></div>'
    elif kind == "cover" and s.get("image"):
        if s.get("image_style") == "wide":
            extra = f'<div class="hero-card"><img src="{data_uri(s["image"])}"></div>'
        else:
            extra = f'<img class="hero" src="{data_uri(s["image"])}">'
    if kind == "cover" and s.get("index"):
        extra += f'<div class="cover-index">{md(s["index"])}</div>'
    if s.get("side"):
        extra += f'<img class="side" src="{data_uri(s["side"])}">'
        cls = " has-side"
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>{font_faces(brand)}{root}{CSS}</style></head>
<body><div class="slide k-{kind} t-{theme}{cls}">{extra}{SWOOSH}
<div class="top">{logo_html(brand, theme, kind)}{SLASHES}</div>
<div class="main">{BODIES[kind](s)}</div>
<div class="bottom">{nav}</div>
</div></body></html>"""


def check(spec, brand):
    def strip(o):
        if isinstance(o, dict):
            return {k: strip(v) for k, v in o.items() if k not in ("image", "side")}
        if isinstance(o, list):
            return [strip(v) for v in o]
        return o
    text = json.dumps(strip(spec), ensure_ascii=False).lower()
    errs = [f"banned on slides/caption: {w}" for w in brand.get("banned_on_slides", []) if w.lower() in text]
    if len(spec["slides"]) > 10:
        errs.append("more than 10 slides")
    if len(spec.get("hashtags", [])) > 5:
        errs.append("more than 5 hashtags")
    return errs


def render(spec_path, brand, out_root):
    from playwright.sync_api import sync_playwright
    from PIL import Image

    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    errs = check(spec, brand)
    if errs:
        raise SystemExit("\n".join(errs))
    out = Path(out_root) / spec["id"]
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    n = len(spec["slides"])
    paths = []
    with sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception:
            exe = next(shutil.which(x) for x in ("google-chrome", "chromium", "chromium-browser") if shutil.which(x))
            b = p.chromium.launch(executable_path=exe)
        page = b.new_page(viewport={"width": 1080, "height": 1350})
        for i, s in enumerate(spec["slides"], 1):
            page.set_content(slide_html(spec, s, i, n, brand), wait_until="load")
            page.evaluate("document.fonts.ready.then(() => true)")
            if page.evaluate(FIT_JS).get("overflow"):
                print(f"  ! slide {i} still overflows; shorten it")
            pth = out / f"{i:02d}.png"
            page.screenshot(path=str(pth))
            paths.append(pth)
        b.close()
    cap = spec.get("caption", "").strip() + "\n\n" + " ".join(spec.get("hashtags", []))
    (out / "caption.txt").write_text(cap.strip() + "\n", encoding="utf-8")
    ims = [Image.open(x).convert("RGB") for x in paths]
    tw, gap, cols = 360, 20, 4
    th = int(tw * 1350 / 1080)
    rows = math.ceil(len(ims) / cols)
    sheet = Image.new("RGB", (cols * tw + (cols + 1) * gap, rows * th + (rows + 1) * gap), (210, 210, 208))
    for k, im in enumerate(ims):
        r, c = divmod(k, cols)
        sheet.paste(im.resize((tw, th), Image.LANCZOS), (gap + c * (tw + gap), gap + r * (th + gap)))
    sheet.save(out / "preview.jpg", quality=90)
    print(f"  ✓ {spec['id']}: {n} slides -> {out}")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["render"])
    ap.add_argument("specs", nargs="+")
    ap.add_argument("--brand", default=None)
    ap.add_argument("--out", default=str(HERE / "out_pro"))
    a = ap.parse_args()
    br = load_brand(a.brand)
    for f in a.specs:
        render(f, br, a.out)
