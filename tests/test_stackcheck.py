"""Offline unit tests:  python3 -m unittest discover tests"""
import os
import sys
import unittest

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

    def test_not_wordpress(self):
        self.assertEqual(sc.wp_assets("<html></html>", [], "https://ex.com/"), {"themes": [], "plugins": []})


if __name__ == "__main__":
    unittest.main()
