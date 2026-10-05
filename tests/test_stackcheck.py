"""Offline unit tests:  python3 -m unittest discover tests"""
import base64
import gzip
import http.client
import json
import os
import socket
import threading
import time
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


class LimitTests(unittest.TestCase):
    def setUp(self):
        self.patches = [mock.patch.object(sc, "CACHE", sc.TTLCache()),
                        mock.patch.object(sc, "LIMITER", sc.RateLimiter()),
                        mock.patch.object(sc, "SITE_LIMITER", sc.RateLimiter(lambda: sc.Config.site_rate_limit)),
                        mock.patch.object(sc, "scan", side_effect=lambda d: {"domain": d})]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def test_site_key(self):
        self.assertEqual(sc.site_key("a.b.example.com"), "example.com")
        self.assertEqual(sc.site_key("shop.example.co.uk"), "example.co.uk")
        self.assertEqual(sc.site_key("example.com"), "example.com")

    def test_refresh_cooldown_serves_cache(self):
        self.assertFalse(sc.cached_scan("example.com", "1.1.1.1")["cached"])
        self.assertTrue(sc.cached_scan("example.com", "1.1.1.1", refresh=True)["cached"])
        with mock.patch.object(sc.Config, "refresh_cooldown", 0):
            self.assertFalse(sc.cached_scan("example.com", "1.1.1.1", refresh=True)["cached"])

    def test_subdomains_share_the_site_limit(self):
        with mock.patch.object(sc.Config, "site_rate_limit", 3):
            for i in range(3):
                sc.cached_scan(f"a{i}.victim.org", f"10.0.0.{i}")
            with self.assertRaises(sc.ScanError) as cm:
                sc.cached_scan("a9.victim.org", "10.0.0.9")  # different IP, different subdomain
            self.assertEqual(cm.exception.status, 429)
            sc.cached_scan("other.org", "10.0.0.9")  # other sites are unaffected

    def test_busy_when_all_scan_slots_are_taken(self):
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        with mock.patch.object(sc, "scan_slots", return_value=slots), mock.patch.object(sc.Config, "timeout", 0.05):
            with self.assertRaises(sc.ScanError) as cm:
                sc.cached_scan("example.com", "1.1.1.1")
        self.assertEqual(cm.exception.status, 503)


class ServerTests(unittest.TestCase):
    """Runs the real server on a random local port. Scans are mocked, so no network is used."""

    def start(self, **config):
        patches = [mock.patch.object(sc.Config, k, v) for k, v in config.items()]
        patches.append(mock.patch.object(sc.Handler, "log_message", lambda *a: None))
        patches.append(mock.patch.object(sc, "cached_scan",
                                         side_effect=lambda d, ip, refresh=False: {"domain": d, "ip": ip}))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.srv = sc.Server(("127.0.0.1", 0), sc.Handler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def get(self, path, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        body = r.read()
        c.close()
        return r, body

    def test_host_allowlist(self):
        self.start(hosts={"localhost", "127.0.0.1", "::1"})
        r, _ = self.get("/example.com.json", {"Host": "attacker.example"})  # DNS rebinding: wrong Host header
        self.assertEqual(r.status, 421)
        r, _ = self.get("/example.com.json", {"Host": f"127.0.0.1:{self.port}"})
        self.assertEqual(r.status, 200)
        r, _ = self.get("/healthz", {"Host": "anything.example"})  # health checks work under any name
        self.assertEqual(r.status, 200)

    def test_token(self):
        self.start(hosts=None, token="s3cret")
        r, _ = self.get("/example.com.json")
        self.assertEqual(r.status, 401)
        self.assertIn("Basic", r.getheader("WWW-Authenticate"))
        self.assertEqual(self.get("/example.com.json", {"Authorization": "Bearer wrong"})[0].status, 401)
        self.assertEqual(self.get("/example.com.json", {"Authorization": "Bearer s3cret"})[0].status, 200)
        basic = "Basic " + base64.b64encode(b"anyone:s3cret").decode()
        self.assertEqual(self.get("/example.com.json", {"Authorization": basic})[0].status, 200)
        self.assertEqual(self.get("/healthz")[0].status, 200)  # health checks need no token

    def test_cors_is_opt_in(self):
        self.start(hosts=None, cors=[])
        r, _ = self.get("/api/example.com", {"Origin": "https://evil.example"})
        self.assertIsNone(r.getheader("Access-Control-Allow-Origin"))
        self.srv.shutdown()
        self.start(hosts=None, cors=["https://ok.example"])
        r, _ = self.get("/api/example.com", {"Origin": "https://ok.example"})
        self.assertEqual(r.getheader("Access-Control-Allow-Origin"), "https://ok.example")
        r, _ = self.get("/api/example.com", {"Origin": "https://evil.example"})
        self.assertIsNone(r.getheader("Access-Control-Allow-Origin"))

    def test_forwarded_for_uses_the_proxys_entry(self):
        self.start(hosts=None, trust_proxy=True)
        _, body = self.get("/api/example.com", {"X-Forwarded-For": "6.6.6.6, 203.0.113.9"})
        self.assertEqual(json.loads(body)["ip"], "203.0.113.9")  # 6.6.6.6 was written by the client

    def test_slow_clients_are_dropped(self):
        with mock.patch.object(sc.Handler, "timeout", 0.3):
            self.start(hosts=None)
            s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            s.sendall(b"GET /healthz HTTP/1.1\r\n")  # ...and never finishes the request
            t = time.monotonic()
            self.assertEqual(s.recv(100), b"")  # server closed the connection
            self.assertLess(time.monotonic() - t, 3)
            s.close()

    def test_connection_cap(self):
        self.start(hosts=None, max_connections=1)
        idle = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        time.sleep(0.2)
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        self.assertTrue(s.recv(100).startswith(b"HTTP/1.1 503"))
        s.close()
        idle.close()


class StartupTests(unittest.TestCase):
    def test_allowed_hosts(self):
        self.assertEqual(sc.effective_allowed_hosts("127.0.0.1", []), {"localhost", "127.0.0.1", "::1"})
        self.assertIsNone(sc.effective_allowed_hosts("0.0.0.0", []))
        self.assertEqual(sc.effective_allowed_hosts("0.0.0.0", ["Scan.Example.com"]), {"scan.example.com"})
        self.assertIsNone(sc.effective_allowed_hosts("127.0.0.1", ["*"]))
        self.assertEqual(sc.host_name("Example.com:8080"), "example.com")
        self.assertEqual(sc.host_name("[::1]:8080"), "::1")

    def test_token_parsing(self):
        self.assertEqual(sc.token_from("Bearer abc"), "abc")
        self.assertEqual(sc.token_from("Basic " + base64.b64encode(b"u:p:w").decode()), "p:w")
        self.assertEqual(sc.token_from("Basic !!!"), "")
        self.assertEqual(sc.token_from(""), "")

    def test_allow_private_needs_loopback_or_token(self):
        with mock.patch.object(sc.Config, "token", ""), mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                sc.main(["--host", "0.0.0.0", "--allow-private"])


class BlockPageTests(unittest.TestCase):
    CF_CHALLENGE = {
        "status": 403, "html": "<html><head><title>Just a moment...</title></head><body>"
        "<script src='/cdn-cgi/challenge-platform/h/g/orchestrate/chl_page/v1'></script>"
        "<script src='https://challenges.cloudflare.com/turnstile/v0/api.js'></script></body></html>",
        "headers": {"server": "cloudflare", "cf-mitigated": "challenge", "cf-ray": "abc-MRS",
                    "content-security-policy": "default-src 'none'", "x-frame-options": "SAMEORIGIN"},
        "url": "https://ex.com/", "final_url": "https://ex.com/", "verified": True, "redirects": [],
        "response_ms": 50, "cookies": [], "truncated": False,
    }

    def detect(self, status, html="", headers=None, title=None):
        return sc.detect_block({"status": status, "html": html, "headers": headers or {}}, title)

    def test_providers(self):
        self.assertEqual(sc.detect_block(self.CF_CHALLENGE, "Just a moment...")["by"], "Cloudflare")
        cf_block = self.detect(403, '<div id="cf-error-details">', {"server": "cloudflare"},
                               "Attention Required! | Cloudflare")
        self.assertEqual((cf_block["by"], cf_block["kind"]), ("Cloudflare", "block"))
        self.assertEqual(self.detect(403, "Incapsula incident ID: 123")["by"], "Imperva")
        self.assertEqual(self.detect(403, "", {"server": "Sucuri/Cloudproxy"})["by"], "Sucuri")
        self.assertEqual(self.detect(403, "", {"server": "AkamaiGHost"}, "Access Denied")["by"], "Akamai")
        self.assertEqual(self.detect(403, "", {"x-datadome": "protected"})["by"], "DataDome")
        self.assertEqual(self.detect(200, "", {"x-amzn-waf-action": "captcha"})["by"], "AWS WAF")
        generic = self.detect(503, "", {}, "Please verify you are a human")
        self.assertEqual((generic["by"], generic["kind"]), (None, "challenge"))
        self.assertEqual(self.detect(429)["kind"], "rate limit")

    def test_normal_pages_are_not_flagged(self):
        self.assertIsNone(self.detect(200, "<p>Just a moment, loading</p>", {"server": "cloudflare"}, "Just a moment"))
        self.assertIsNone(self.detect(403, "<h1>Forbidden</h1>", {"server": "nginx"}, "403 Forbidden"))
        self.assertIsNone(self.detect(404, "", {"server": "cloudflare"}, "Page not found"))

    def test_scan_ignores_the_block_page(self):
        dns = {"records": [], "cname": [], "ad": False}
        with mock.patch.object(sc, "assert_public", return_value=["104.21.60.233"]), \
                mock.patch.object(sc, "http_fetch", return_value=self.CF_CHALLENGE), \
                mock.patch.object(sc, "tls_probe", return_value={"valid": True}), \
                mock.patch.object(sc, "find_zone", return_value=("ex.com", ["ada.ns.cloudflare.com"])), \
                mock.patch.object(sc, "dns_query", return_value=dns), \
                mock.patch.object(sc, "sitemap_info", return_value={"found": False}):
            r = sc.scan("ex.com")
        names = {t["name"] for t in r["technologies"]}
        self.assertEqual(r["blocked"]["by"], "Cloudflare")
        self.assertIn("Cloudflare", names)                     # the CDN is real
        self.assertNotIn("Content Security Policy", names)     # the challenge page's CSP isn't the site's
        self.assertNotIn("Cloudflare Turnstile", names)        # nor is the challenge's own script
        self.assertIsNone(r["security_headers"])
        self.assertIsNone(r["summary"]["title"])
        self.assertIsNone(r["wordpress"])
