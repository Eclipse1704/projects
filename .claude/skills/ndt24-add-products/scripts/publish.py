#!/usr/bin/env python3
"""Puts one product into the WooCommerce shop as a DRAFT, through the site's REST API.

Needs: NDT24_WP_USER, NDT24_WP_APP_PASSWORD (a WordPress application password), optional NDT24_SITE.

  publish.py check                       connection, role, categories, brand taxonomy, detected custom fields
  publish.py product.json                create (or update, same source link) a draft from product.json

product.json:
  {"source_link": "...", "name": "...", "short_description": "...", "description_paragraphs": [...], "usage": [...],
   "category": "<exact name from `check`>", "tags": [...], "brand": "FOTRIC", "focus_keyphrase": "...",
   "images": ["/path/FOTRIC-348A-001.jpg", ...],   # first = main image, rest = gallery
   "catalog_pdf": "/path/FOTRIC-348A-BROCHURE.pdf" or "", "manual_pdf": "..." or "", "video_url": "https://www.youtube.com/watch?v=..." or ""}
"""
import base64, html, json, mimetypes, os, re, sys, urllib.error, urllib.parse, urllib.request

SITE = os.environ.get("NDT24_SITE", "https://www.ndt24.co.il").rstrip("/")
USER = os.environ.get("NDT24_WP_USER", "")
PASS = os.environ.get("NDT24_WP_APP_PASSWORD", "")
AUTH = "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode()
UA = "Mozilla/5.0 ndt24-add-products"


class SiteError(Exception):
    def __init__(self, status, msg, code=""):
        super().__init__(f"site {status}: {msg}")
        self.status, self.code = status, code


def req(method, path, body=None, raw=None, headers=None):
    h = {"Authorization": AUTH, "User-Agent": UA, "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    if raw is not None:
        data = raw
    h.update(headers or {})
    r = urllib.request.Request(SITE + "/wp-json" + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=120) as resp:
            return json.loads(resp.read().decode() or "null")
    except urllib.error.HTTPError as e:
        txt = e.read().decode(errors="replace")
        try:
            j = json.loads(txt)
            raise SiteError(e.code, j.get("message", txt[:200]), j.get("code", ""))
        except ValueError:
            raise SiteError(e.code, re.sub(r"<[^>]+>", " ", txt)[:200])


def all_pages(path):
    out, page = [], 1
    while True:
        sep = "&" if "?" in path else "?"
        chunk = req("GET", f"{path}{sep}per_page=100&page={page}")
        out += chunk
        if len(chunk) < 100:
            return out
        page += 1


def detect_fields():
    """Where the theme keeps 'קטלוג pdf', 'ספר הוראות', 'וידאו מוצר': scored from existing products' meta."""
    score = {"catalog": {}, "manual": {}, "video": {}}
    refs = {}
    for p in req("GET", "/wc/v3/products?per_page=40&status=any"):
        meta = {m["key"]: m["value"] for m in p.get("meta_data", [])}
        for k, v in meta.items():
            if k.startswith("_"):
                continue
            v = v if isinstance(v, str) else ""
            add = lambda kind, n: score[kind].__setitem__(k, score[kind].get(k, 0) + n)
            manual_name = re.search(r"manual|guide|instruction|הוראות", k, re.I)
            if re.search(r"catalog|catalogue|brochure|datasheet|קטלוג", k, re.I): add("catalog", 5)
            if manual_name: add("manual", 5)
            if re.search(r"video|youtube|וידאו", k, re.I): add("video", 5)
            if re.search(r"youtu\.?be|vimeo\.com", v, re.I): add("video", 1)
            if re.search(r"\.pdf(\?|$)", v, re.I) and not manual_name: add("catalog", 1)
            if str(meta.get("_" + k, "")).startswith("field_"):
                refs[k] = meta["_" + k]
    best = {kind: (max(s, key=s.get) if s else "") for kind, s in score.items()}
    if best["manual"] == best["catalog"]:
        best["manual"] = ""
    return best, refs


def brand_base():
    for base in ("/wc/v3/products/brands", "/wp/v2/product_brand", "/wp/v2/pwb-brand"):
        try:
            req("GET", base + "?per_page=1")
            return base
        except SiteError:
            continue
    return ""


def term_id(base, name):
    name = name.strip()
    if not name:
        return None
    for t in req("GET", f"{base}?per_page=100&search={urllib.parse.quote(name)}"):
        if html.unescape(t["name"]).strip().lower() == name.lower():
            return t["id"]
    try:
        return req("POST", base, {"name": name})["id"]
    except SiteError as e:
        if e.code == "term_exists":
            return req("GET", f"{base}?per_page=100&search={urllib.parse.quote(name)}")[0]["id"]
        raise


def upload(path, alt=""):
    name = os.path.basename(path)
    with open(path, "rb") as f:
        data = f.read()
    m = req("POST", "/wp/v2/media", raw=data, headers={
        "Content-Type": mimetypes.guess_type(name)[0] or "application/octet-stream",
        "Content-Disposition": f'attachment; filename="{urllib.parse.quote(name)}"'})
    if alt:
        req("POST", f"/wp/v2/media/{m['id']}", {"alt_text": alt, "title": alt})
    return m["id"], m["source_url"]


def description_html(c):
    paras = "".join(f"<p>{html.escape(p.strip(), quote=False)}</p>\n" for p in c.get("description_paragraphs", []) if p.strip())
    uses = [u.strip() for u in c.get("usage", []) if u.strip()]
    if uses:
        paras += "<ul>\n" + "\n".join(f"<li>{html.escape(u, quote=False)}</li>" for u in uses) + "\n</ul>"
    return paras.strip()


def check():
    me = req("GET", "/wp/v2/users/me?context=edit")
    cats = all_pages("/wc/v3/products/categories")
    fields, refs = detect_fields()
    print(json.dumps({
        "user": me.get("slug"), "roles": me.get("roles"),
        "can_edit_products": bool(me.get("capabilities", {}).get("edit_products")),
        "categories": [html.unescape(c["name"]) for c in cats if c["slug"] != "uncategorized"],
        "brand_endpoint": brand_base(), "fields": fields, "acf_refs": refs,
    }, ensure_ascii=False, indent=1))


def publish(path):
    c = json.load(open(path, encoding="utf-8"))
    warnings = []
    cats = {html.unescape(x["name"]): x["id"] for x in all_pages("/wc/v3/products/categories")}
    fields, refs = detect_fields()
    body = {
        "name": c["name"], "type": "simple",
        "description": description_html(c),
        "short_description": f"<p>{html.escape(c['short_description'].strip(), quote=False)}</p>",
        "meta_data": [{"key": "_nps_source_link", "value": c["source_link"]}],
    }
    if c.get("focus_keyphrase"):
        body["meta_data"].append({"key": "_yoast_wpseo_focuskw", "value": c["focus_keyphrase"]})
    if c.get("category") in cats:
        body["categories"] = [{"id": cats[c["category"]]}]
    elif c.get("category"):
        warnings.append(f"category '{c['category']}' not on the site - pick one by hand")
    body["tags"] = [{"id": term_id("/wc/v3/products/tags", t)} for t in c.get("tags", []) if t.strip()]

    # the same source link -> update that product (a fix / a rescan)
    existing = [p for p in req("GET", "/wc/v3/products?status=any&per_page=100&search=" + urllib.parse.quote(c["name"][:40]))
                if any(m["key"] == "_nps_source_link" and m["value"] == c["source_link"] for m in p.get("meta_data", []))]
    if existing:
        product = req("PUT", f"/wc/v3/products/{existing[0]['id']}", body)
    else:
        body["status"] = "draft"
        product = req("POST", "/wc/v3/products", body)
    pid = product["id"]

    images = [{"id": upload(p, c["name"] + (f" - {i + 1}" if i else ""))[0]} for i, p in enumerate(c.get("images", []))]
    docs = {}
    for kind in ("catalog_pdf", "manual_pdf"):
        if c.get(kind):
            docs[kind] = upload(c[kind])
    meta = []
    for kind, key in (("catalog_pdf", fields["catalog"]), ("manual_pdf", fields["manual"])):
        if key and kind in docs:
            meta.append({"key": key, "value": docs[kind][1]})
            if key in refs:
                meta.append({"key": "_" + key, "value": refs[key]})
    if fields["video"] and c.get("video_url"):
        meta.append({"key": fields["video"], "value": c["video_url"]})
        if fields["video"] in refs:
            meta.append({"key": "_" + fields["video"], "value": refs[fields["video"]]})
    update = {"meta_data": meta}
    if images:
        update["images"] = images
    bb = brand_base()
    if bb and c.get("brand"):
        bid = term_id(bb, c["brand"])
        if bb.startswith("/wc/"):
            update["brands"] = [{"id": bid}]
        else:
            req("POST", f"/wp/v2/product/{pid}", {bb.rsplit('/', 1)[1]: [bid]})
    elif c.get("brand"):
        warnings.append("no brand taxonomy reachable - pick the brand by hand")
    product = req("PUT", f"/wc/v3/products/{pid}", update)
    if not all(fields.values()):
        warnings.append(f"theme fields not all detected {fields} - fill the missing ones by hand")
    print(json.dumps({"id": pid, "status": product["status"], "edit": f"{SITE}/wp-admin/post.php?post={pid}&action=edit",
                      "images": len(images), "docs": list(docs), "warnings": warnings}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    if not USER or not PASS:
        sys.exit("NDT24_WP_USER / NDT24_WP_APP_PASSWORD are not set (environment settings), never paste them in chat")
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    check() if sys.argv[1] == "check" else publish(sys.argv[1])
