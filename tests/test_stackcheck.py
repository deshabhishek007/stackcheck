"""Offline unit tests:  python3 -m unittest discover tests"""
import gzip
import os
import socket
import sys
import unittest
import zlib
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import stackcheck as sc  # noqa: E402


class NormalizeTests(unittest.TestCase):
    def test_variants(self):
        for raw in ["example.com", "Example.COM", "https://example.com/path?q=1", "https:/example.com",
                    "http://user:pw@example.com:8080/", "example.com.", "/example.com/"]:
            self.assertEqual(sc.normalize_domain(raw), "example.com", raw)

    def test_idn(self):
        self.assertEqual(sc.normalize_domain("bücher.de"), "xn--bcher-kva.de")

    def test_rejects(self):
        for raw in ["", "localhost", "127.0.0.1", "foo_bar.com", "-a.com", "a..com", "x" * 300 + ".com"]:
            with self.assertRaises(sc.ScanError, msg=raw):
                sc.normalize_domain(raw)


class SSRFTests(unittest.TestCase):
    def test_private_ips(self):
        for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "169.254.169.254", "::1", "fc00::1",
                   "::ffff:127.0.0.1", "0.0.0.0", "100.64.0.1"]:
            self.assertFalse(sc.ip_is_public(ip), ip)
        for ip in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"]:
            self.assertTrue(sc.ip_is_public(ip), ip)


class DNSParseTests(unittest.TestCase):
    def test_name_compression(self):
        # header(12) + name "a.bc" + pointer back to offset 12
        data = b"\x00" * 12 + b"\x01a\x02bc\x00" + b"\xc0\x0c"
        self.assertEqual(sc._read_name(data, 12), ("a.bc", 18))
        self.assertEqual(sc._read_name(data, 18), ("a.bc", 20))


class FingerprintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fp = sc.fingerprints()

    def names(self, signals):
        return {t["name"]: t for t in self.fp.analyze(signals)}

    def test_all_regexes_compile_and_implies_exist(self):
        for name, t in self.fp.techs.items():
            for imp in t["implies"]:
                self.assertIn(imp, self.fp.techs, f"{name} implies unknown {imp}")

    def test_wordpress(self):
        html = '<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
        page = sc.extract_html(html + '<meta name="generator" content="WordPress 6.6.1">')
        r = self.names({"html": html, "meta": page["meta"], "urls": page["urls"],
                        "headers": {"server": "nginx/1.25.3"}})
        self.assertEqual(r["WordPress"]["version"], "6.6.1")
        self.assertEqual(r["WordPress"]["level"], "high")
        self.assertEqual(r["Nginx"]["version"], "1.25.3")
        self.assertIn("PHP", r)  # implied

    def test_dns_and_cookies(self):
        r = self.names({"dns": {"MX": ["aspmx.l.google.com"], "NS": ["ada.ns.cloudflare.com"]},
                        "cookie_names": ["_shopify_y"], "headers": {"cf-ray": "abc-LHR"}})
        for n in ["Google Workspace", "Cloudflare DNS", "Shopify", "Cloudflare"]:
            self.assertIn(n, r)

    def test_nextjs(self):
        html = '<script src="/_next/static/chunks/main.js"></script><script id="__NEXT_DATA__" type="application/json">'
        page = sc.extract_html(html)
        r = self.names({"html": html, "urls": page["urls"], "meta": page["meta"]})
        self.assertIn("Next.js", r)
        self.assertIn("React", r)
        self.assertEqual(r["React"]["evidence"][0]["source"], "implied")

    def test_no_false_positives_on_empty(self):
        self.assertEqual(self.fp.analyze({}), [])


class SitemapTests(unittest.TestCase):
    def test_parse(self):
        idx = '<?xml version="1.0"?><sitemapindex xmlns="x"><sitemap><loc>https://ex.com/a.xml</loc></sitemap></sitemapindex>'
        self.assertEqual(sc.parse_sitemap(idx)["kind"], "index")
        self.assertEqual(sc.parse_sitemap(idx)["locs"], ["https://ex.com/a.xml"])
        urlset = ('<urlset><url><loc>https://ex.com/1</loc><image:image><image:loc>i.jpg</image:loc></image:image>'
                  '</url><url><loc>https://ex.com/2</loc></url></urlset>')
        self.assertEqual((sc.parse_sitemap(urlset)["kind"], sc.parse_sitemap(urlset)["urls"]), ("urlset", 2))
        self.assertIsNone(sc.parse_sitemap("<!DOCTYPE html><html>404</html>")["kind"])

    def test_types(self):
        cases = {
            "https://ex.com/wp-sitemap-posts-post-1.xml": "post",
            "https://ex.com/wp-sitemap-taxonomies-category-1.xml": "category",
            "https://ex.com/wp-sitemap-users-1.xml": "users",
            "https://ex.com/post-sitemap2.xml": "post",
            "https://ex.com/post_tag-sitemap.xml": "post_tag",
            "https://ex.com/post-type-page-sitemap-1.xml": "page",
            "https://ex.com/sitemap-posts.xml": "posts",
            "https://ex.com/sitemap-page-3.xml": None,  # pagination, not pages
            "https://ex.com/sitemap-2024-01.xml": None,
            "https://ex.com/sitemap.xml": None,
        }
        for url, want in cases.items():
            self.assertEqual(sc.sitemap_type(url), want, url)


class WordPressTests(unittest.TestCase):
    HTML = """
<link rel='stylesheet' href='https://ex.com/wp-content/themes/astra-child/style.css?ver=6.6.1'>
<link rel='stylesheet' href='https://ex.com/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.9.3'>
<script src='https://ex.com/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.9.3'></script>
<script src='/wp-content/plugins/my-custom-thing/app.js?ver=6.6.1&#038;x=1'></script>
<script>var cfg = {"url":"https:\\/\\/ex.com\\/wp-content\\/plugins\\/elementor\\/assets\\/js\\/f.js?ver=3.21.0"};</script>
<!-- This site is optimized with the Yoast SEO plugin v22.6 - https://yoast.com/wordpress/plugins/seo/ -->
"""

    def test_assets(self):
        page = sc.extract_html(self.HTML)
        wp = sc.wp_assets(self.HTML, page["urls"], "https://ex.com/", core_version="6.6.1")
        plugins = {p["slug"]: p for p in wp["plugins"]}
        self.assertEqual(set(plugins), {"contact-form-7", "my-custom-thing", "elementor", "wordpress-seo"})
        self.assertEqual(plugins["contact-form-7"]["version"], "5.9.3")
        self.assertEqual(plugins["contact-form-7"]["assets"], 2)
        self.assertIsNone(plugins["my-custom-thing"]["version"])  # ?ver= equal to core is WordPress's default
        self.assertEqual(plugins["my-custom-thing"]["name"], "My Custom Thing")
        self.assertEqual(plugins["elementor"]["version"], "3.21.0")  # found in escaped inline JSON
        self.assertEqual(plugins["wordpress-seo"]["name"], "Yoast SEO")
        self.assertEqual(plugins["wordpress-seo"]["version"], "22.6")
        self.assertEqual([t["slug"] for t in wp["themes"]], ["astra-child"])
        self.assertEqual(wp["themes"][0]["stylesheet"], "https://ex.com/wp-content/themes/astra-child/style.css")

    def test_theme_header(self):
        css = "/*\nTheme Name: Astra Child\nTemplate: astra\n Version: 1.0.2\n*/\nbody{}"
        h = sc.parse_theme_header(css)
        self.assertEqual((h["theme name"], h["template"], h["version"]), ("Astra Child", "astra", "1.0.2"))
        self.assertEqual(sc.parse_theme_header("body{color:red}"), {})

    def test_rest_url(self):
        self.assertEqual(sc.wp_rest_url("https://ex.com/wp-json/", "wp/v2/posts", per_page=1),
                         "https://ex.com/wp-json/wp/v2/posts?per_page=1")
        self.assertEqual(sc.wp_rest_url("https://ex.com/?rest_route=/", "wp/v2/posts", per_page=1),
                         "https://ex.com/?rest_route=%2Fwp%2Fv2%2Fposts&per_page=1")

    def test_rest_root_from_link_header(self):
        http = {"headers": {"link": '<https://ex.com/api/>; rel="https://api.w.org/"'}, "html": "",
                "final_url": "https://ex.com/"}
        self.assertEqual(sc.wp_rest_root(http), "https://ex.com/api/")
        http = {"headers": {}, "html": "", "final_url": "https://ex.com/blog/"}
        self.assertEqual(sc.wp_rest_root(http), "https://ex.com/wp-json/")

    def test_merge_rest_plugins(self):
        wp = {"themes": [{"slug": "astra"}],
              "plugins": [{"slug": "elementor", "name": "Elementor", "version": "3.2", "mu": False, "assets": 4,
                           "evidence": ["/wp-content/plugins/elementor/x.js"]}],
              "rest": {"namespaces": ["oembed/1.0", "wp/v2", "elementor/v1", "elementor/v1/documents", "yoast/v1",
                                      "astra/v1", "acme-thing/v2"]}}
        sc.merge_rest_plugins(wp)
        plugins = {p["slug"]: p for p in wp["plugins"]}
        self.assertEqual(set(plugins), {"elementor", "wordpress-seo"})
        self.assertEqual(plugins["elementor"]["evidence"][-1], "REST API namespace elementor/v1")
        self.assertEqual(len(plugins["elementor"]["evidence"]), 2)  # one namespace entry per plugin
        self.assertEqual(plugins["wordpress-seo"]["name"], "Yoast SEO")
        self.assertEqual(wp["rest"]["other_namespaces"], ["acme-thing"])  # theme and core namespaces left out

    def test_content_prefers_rest_then_sitemap(self):
        rest = {"counts": {"posts": 682, "users": 3}}
        sitemap = {"by_type": {"post": 600, "page": 42, "post_tag": 10}, "partial": True}
        c = sc.wp_content(rest, sitemap)
        self.assertEqual(c["posts"], {"count": 682, "source": "REST API", "partial": False})
        self.assertEqual(c["pages"], {"count": 42, "source": "sitemap", "partial": True})
        self.assertEqual(c["tags"]["count"], 10)
        self.assertNotIn("categories", c)

    def test_not_wordpress(self):
        self.assertEqual(sc.wp_assets("<html></html>", [], "https://ex.com/"), {"themes": [], "plugins": []})


if __name__ == "__main__":
    unittest.main()


class SecurityTests(unittest.TestCase):
    """Attacks a scanned site (or its DNS) could try. All offline: DNS and HTTP are mocked."""

    def test_decompression_bomb_is_capped(self):
        bomb = gzip.compress(b"\0" * 200_000_000)  # ~194 KB on the wire, 200 MB expanded
        out, truncated = sc._decompress(bomb, "gzip", 3_000_000)
        self.assertEqual(len(out), 3_000_000)
        self.assertTrue(truncated)
        raw = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        deflated = raw.compress(b"\0" * 50_000_000) + raw.flush()
        out, truncated = sc._decompress(deflated, "deflate", 1_000)
        self.assertEqual((len(out), truncated), (1_000, True))
        self.assertEqual(sc._decompress(gzip.compress(b"hello"), "gzip", 100), (b"hello", False))
        self.assertEqual(sc._decompress(b"plain", "", 100), (b"plain", False))

    def test_only_ports_80_and_443(self):
        with self.assertRaises(sc.ScanError):
            sc._connect_public("example.com", 8080, 1)

    def test_dns_rebinding_is_refused_at_connect(self):
        """The name looks public when first checked, then resolves to loopback for the real connection."""
        answers = iter([[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0))]] +
                       [[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]] * 5)
        with mock.patch.object(sc.socket, "getaddrinfo", side_effect=lambda *a, **k: next(answers)), \
                mock.patch.object(sc.socket, "socket") as sock:
            sc.assert_public("rebind.example")  # first answer: public, passes
            with self.assertRaises(sc.ScanError):
                sc._fetch_once("http://rebind.example/", True)
            sock.assert_not_called()  # refused before any connection was opened

    def test_redirect_guard(self):
        req = mock.Mock(full_url="https://ex.com/")
        g = sc._GuardedRedirect(scope=("ex.com",))
        for bad in ["ftp://ex.com/x", "file:///etc/passwd", "https://victim.org/"]:
            with self.assertRaises(sc.ScanError, msg=bad):
                g.redirect_request(req, None, 302, "Found", mock.Mock(), bad)

    def test_scope(self):
        roots = sc.site_roots("www.ex.com", "ex.com", None)
        self.assertEqual(roots, ("ex.com",))
        self.assertTrue(sc.in_scope("cdn.ex.com", roots))
        self.assertTrue(sc.in_scope("EX.com.", roots))
        self.assertFalse(sc.in_scope("evilex.com", roots))
        self.assertFalse(sc.in_scope("ex.com.victim.org", roots))
        with mock.patch.object(sc, "_fetch_once") as fetch:
            self.assertIsNone(sc._get("https://victim.org/sitemap.xml", scope=roots))
            self.assertIsNone(sc._get("javascript:alert(1)", scope=roots))
            fetch.assert_not_called()

    def test_rest_root_must_be_on_site(self):
        http = {"headers": {"link": '<https://victim.org/wp-json/>; rel="https://api.w.org/"'}, "html": "",
                "final_url": "https://ex.com/"}
        self.assertEqual(sc.wp_rest_root(http, ("ex.com",)), "https://ex.com/wp-json/")

    def test_stream_sitemap_counts_big_compressed_files(self):
        """A 60 MB gzip sitemap is counted exactly, a few KB at a time, and a bomb stops at the ceiling."""
        entry = b"<url><loc>https://ex.com/p</loc></url>\n"
        body = gzip.compress(b"<?xml version='1.0'?><urlset>" + entry * 1_500_000 + b"</urlset>")

        class Resp:
            def __init__(self, data):
                self.data, self.pos, self.status = data, 0, 200
                self.headers = {"Content-Encoding": "gzip"}
            def read(self, n):
                chunk = self.data[self.pos:self.pos + n]
                self.pos += n
                return chunk
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        with mock.patch.object(sc, "_open", return_value=(Resp(body), None)):
            r = sc._stream_sitemap("https://ex.com/s.xml", True, ("ex.com",))
        self.assertEqual((r["urls"], r["truncated"]), (1_500_000, False))
        self.assertIn("<urlset>", r["head"])
        with mock.patch.object(sc, "_open", return_value=(Resp(gzip.compress(entry * 6_000_000)), None)):
            r = sc._stream_sitemap("https://ex.com/s.xml", True, ("ex.com",))
        self.assertTrue(r["truncated"])  # 240 MB expanded: stopped at STREAM_MAX_OUT
        self.assertIsNone(sc._stream_sitemap("https://victim.org/s.xml", True, ("ex.com",)))

    def test_sitemaps_off_site_are_not_fetched(self):
        index = ("<sitemapindex><sitemap><loc>https://ex.com/post-sitemap.xml</loc></sitemap>"
                 + "".join(f"<sitemap><loc>https://victim.org/{i}.xml</loc></sitemap>" for i in range(12))
                 + "</sitemapindex>")
        pages = {
            "https://ex.com/robots.txt": "Sitemap: https://victim.org/big.xml\nSitemap: https://ex.com/sitemap_index.xml",
            "https://ex.com/sitemap_index.xml": index,
        }
        fetched = []

        def fake_get(url, verify=True, scope=None, max_bytes=None):
            fetched.append(url)
            if url not in pages:
                return None
            return {"status": 200, "html": pages[url], "final_url": url, "headers": {"content-type": "text/plain"},
                    "truncated": False}

        def fake_stream(url, verify, scope):
            fetched.append(url)
            return {"status": 200, "head": "<urlset>", "urls": 1, "truncated": False}

        with mock.patch.object(sc, "_get", side_effect=fake_get), \
                mock.patch.object(sc, "_stream_sitemap", side_effect=fake_stream):
            s = sc.sitemap_info("https://ex.com/", True, ("ex.com",))
        self.assertFalse([u for u in fetched if "victim.org" in u])
        self.assertEqual((s["url"], s["urls"], s["offsite"]), ("https://ex.com/sitemap_index.xml", 1, 13))

    def test_theme_uri_must_be_http(self):
        html = "<link rel='stylesheet' href='https://ex.com/wp-content/themes/evil/style.css'>"
        http = {"html": html, "final_url": "https://ex.com/", "verified": True}
        with mock.patch.object(sc, "_theme_header",
                               return_value={"theme name": "Evil", "theme uri": "javascript:alert(1)"}):
            wp = sc.wordpress_details(http, sc.extract_html(html)["urls"], None, ("ex.com",))
        self.assertIsNone(wp["themes"][0]["uri"])
