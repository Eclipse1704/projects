"""Offline end-to-end test against two fake sites served on localhost.

`localhost` plays the distributor, `127.0.0.1` plays the manufacturer's official site,
so the "assets only from official sites" rule can be checked.
Run:  python -m unittest discover -s tests   (from the scripts/ directory)
"""
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catalog import cli  # noqa: E402
from catalog.common import file_stem, read_json  # noqa: E402
from catalog.content import validate_content  # noqa: E402

JPEG = b"\xff\xd8\xff\xe0" + os.urandom(20_000)
PDF = b"%PDF-1.4\n" + b"0" * 2_000
ROUTES: dict = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        host = self.headers["Host"].split(":")[0]
        key = (host, u.path)
        if u.path.endswith("products.json"):
            page = int(parse_qs(u.query).get("page", ["1"])[0])
            body = ROUTES.get(key, {}).get(page, json.dumps({"products": []}))
            ctype = "application/json"
        elif key in ROUTES:
            body, ctype = ROUTES[key]
        else:
            self.send_response(404)
            self.end_headers()
            return
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class PipelineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        sup = f"http://localhost:{cls.port}"
        man = f"http://127.0.0.1:{cls.port}"
        html = "text/html; charset=utf-8"
        ROUTES.update({
            # Distributor (WordPress-like) listing with pagination
            ("localhost", "/product-category/scopes/"): (f"""<html><body><main>
                <a href="{sup}/product/x2000/">X2000 Videoscope</a>
                <a href="{sup}/product-category/scopes/page/2/">2</a>
                <a href="{sup}/about/">About</a></main></body></html>""", html),
            ("localhost", "/product-category/scopes/page/2/"): (f"""<html><body>
                <a href="{sup}/product/x1000-plus/">X1000 Plus</a></body></html>""", html),
            ("localhost", "/product/x2000/"): (f"""<html><body><main><h1>X2000 Videoscope</h1>
                <p>{'Distributor text about the scope. ' * 20}</p>
                <img src="{sup}/img/dist.jpg">
                <a href="{sup}/files/x2000-brochure.pdf">Brochure</a>
                <a href="{man}/product/x2000/">Manufacturer page</a></main></body></html>""", html),
            ("localhost", "/product/x1000-plus/"): (f"""<html><body><main><h1>X1000 Plus</h1>
                <p>{'Older model text. ' * 20}</p></main></body></html>""", html),
            ("localhost", "/img/dist.jpg"): (JPEG, "image/jpeg"),
            ("localhost", "/files/x2000-brochure.pdf"): (PDF, "application/pdf"),
            # Manufacturer official page
            ("127.0.0.1", "/product/x2000/"): (f"""<html><head>
                <meta property="og:image" content="{man}/wp-content/uploads/x2000-main-300x300.jpg">
                <script type="application/ld+json">{{"@type":"Product","name":"X2000","description":"Industrial videoscope with 7 inch touchscreen."}}</script>
                </head><body><main><h1>X2000</h1><p>{'Official description of X2000. ' * 20}</p>
                <div class="woocommerce-product-gallery">
                  <img src="{man}/wp-content/uploads/x2000-main-300x300.jpg">
                  <img data-large_image="{man}/wp-content/uploads/x2000-side.jpg" src="{man}/wp-content/uploads/x2000-side-100x100.jpg">
                  <img src="{man}/wp-content/uploads/x2000-probe.png">
                  <img src="{man}/wp-content/uploads/logo.png">
                </div>
                <table><tr><th>Screen</th><td>7" LCD touchscreen</td></tr><tr><th>Protection</th><td>IP54</td></tr></table>
                <iframe src="https://www.youtube.com/embed/AbCdEfGhIjK"></iframe>
                <a href="{man}/files/X2000_User_Manual.pdf">User manual</a>
                <a href="{man}/files/X2000-datasheet.pdf">Datasheet</a>
                </main></body></html>""", html),
            ("127.0.0.1", "/wp-content/uploads/x2000-main.jpg"): (JPEG, "image/jpeg"),
            ("127.0.0.1", "/wp-content/uploads/x2000-side.jpg"): (JPEG[:-5] + b"side!", "image/jpeg"),
            ("127.0.0.1", "/wp-content/uploads/x2000-probe.png"): (b"\x89PNG" + os.urandom(15_000), "image/png"),
            ("127.0.0.1", "/wp-content/uploads/logo.png"): (b"\x89PNG" + os.urandom(15_000), "image/png"),
            ("127.0.0.1", "/files/X2000_User_Manual.pdf"): (PDF, "application/pdf"),
            ("127.0.0.1", "/files/X2000-datasheet.pdf"): (PDF, "application/pdf"),
            # Shopify-style manufacturer store
            ("127.0.0.1", "/collections/all-products/products.json"): {1: json.dumps({"products": [
                {"handle": "fotric-226s", "title": "FOTRIC 226s", "product_type": "Thermal Camera", "tags": [],
                 "body_html": "<p>Handheld thermal camera.</p>",
                 "images": [{"src": f"{man}/cdn/226s_800x.jpg"}, {"src": f"{man}/cdn/226s-b.jpg"}]},
                {"handle": "lens-25", "title": "25° Lens", "product_type": "Accessory", "tags": [], "images": []},
            ]})},
            ("127.0.0.1", "/products/fotric-226s"): ("<html><body><main><h1>FOTRIC 226s</h1>"
                                                    "<p>" + "Thermal imaging. " * 30 + "</p></main></body></html>", html),
            ("127.0.0.1", "/cdn/226s.jpg"): (JPEG, "image/jpeg"),
            ("127.0.0.1", "/cdn/226s-b.jpg"): (JPEG[:-3] + b"bbb", "image/jpeg"),
        })
        cls.sup, cls.man = sup, man

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def run_cli(self, *args):
        return cli.main(list(args))

    def test_generic_site_with_official_manufacturer(self):
        with tempfile.TemporaryDirectory() as out:
            rc = self.run_cli("scrape", "--out", out, "--manufacturer", "Mitcorp",
                              "--url", f"{self.sup}/product-category/scopes/",
                              "--official-domain", "127.0.0.1")
            self.assertEqual(rc, 0)
            base = Path(out) / "mitcorp"
            self.assertEqual(sorted(p.name for p in base.iterdir()), ["x1000-plus", "x2000"])
            p = read_json(base / "x2000" / "product.json")
            self.assertEqual(p["name"], "X2000")
            files = [i["file"] for i in p["downloaded_images"]]
            self.assertEqual(files, [f"images/MITCORP-X2000-00{n}.{e}" for n, e in ((1, "jpg"), (2, "jpg"), (3, "png"))])
            self.assertTrue(all(i["source_page"].startswith(self.man) for i in p["downloaded_images"]))
            self.assertEqual(p["videos"][0]["url"], "https://www.youtube.com/watch?v=AbCdEfGhIjK")
            got = {d["kind"]: d.get("file") for d in p["documents"] if d.get("file")}
            self.assertEqual(got, {"manual": "docs/MITCORP-X2000-MANUAL.pdf", "brochure": "docs/MITCORP-X2000-BROCHURE.pdf"})
            self.assertFalse(any("localhost" in d["url"] for d in p["documents"]))   # distributor PDF ignored
            self.assertIn(["Protection", "IP54"], p["specs"])

            # Hebrew content written by hand (what Claude Code does without an API key)
            content = {"product_name": "וידאוסקופ תעשייתי Mitcorp X2000", "category": "וידאוסקופים",
                       "short_description": "וידאוסקופ תעשייתי עם מסך מגע 7 אינץ'.",
                       "overview": "מכשיר לבדיקה חזותית.", "usage": ["בדיקת מנועים"], "features": ["מסך מגע"],
                       "specs": [{"name": "מסך", "value": "7\" LCD"}, {"name": "הגנה", "value": "IP54"}]}
            (base / "x2000" / "content.he.json").write_text(json.dumps(content, ensure_ascii=False), encoding="utf-8")
            self.run_cli("render", "--out", out, "--manufacturer", "Mitcorp", "--url", f"{self.sup}/x")
            page = (base / "x2000" / "index.html").read_text(encoding="utf-8")
            for needle in ('lang="he" dir="rtl"', 'id="short-description"', 'id="specifications"',
                           "MITCORP-X2000-001.jpg", "watch?v=AbCdEfGhIjK", "application/ld+json", "IP54"):
                self.assertIn(needle, page)
            self.assertTrue((Path(out) / "index.html").exists())

    def test_shopify_catalogue_and_exclude(self):
        with tempfile.TemporaryDirectory() as cfgdir, tempfile.TemporaryDirectory() as out:
            cfg = Path(cfgdir) / "s.yaml"
            cfg.write_text(f"""suppliers:
  - id: fotric
    manufacturer: FOTRIC
    listing_urls: [{self.man}/collections/all-products]
    official_domains: [127.0.0.1]
    exclude: [accessor, lens]
    delay_seconds: 0
""")
            self.run_cli("scrape", "--config", str(cfg), "--out", out)
            dirs = [p.name for p in (Path(out) / "fotric").iterdir()]
            self.assertEqual(dirs, ["fotric-226s"])
            p = read_json(Path(out) / "fotric" / "fotric-226s" / "product.json")
            self.assertEqual([i["file"] for i in p["downloaded_images"]],
                             ["images/FOTRIC-226S-001.jpg", "images/FOTRIC-226S-002.jpg"])
            self.assertIn("Handheld thermal camera", p["descriptions"][0]["text"])

    def test_helpers(self):
        self.assertEqual(file_stem("Jacobs-MC", "LIXENER30"), "JACOBS-MC-LIXENER30")
        self.assertEqual(file_stem("FOTRIC", "FOTRIC 226s"), "FOTRIC-226S")
        long = {"product_name": "x", "short_description": "מילה " * 81, "overview": "א", "usage": [], "features": [], "specs": []}
        self.assertTrue(any("short_description" in p for p in validate_content(long)))
        self.assertTrue(any("Hebrew" in p for p in validate_content({"product_name": "x", "short_description": "English", "overview": "text"})))


if __name__ == "__main__":
    unittest.main()
