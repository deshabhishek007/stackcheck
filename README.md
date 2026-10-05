# StackCheck

[![Tests](https://github.com/deshabhishek007/stackcheck/actions/workflows/test.yml/badge.svg)](https://github.com/deshabhishek007/stackcheck/actions/workflows/test.yml)

A small, self-hosted website technology scanner, in the same spirit as BuiltWith or Wappalyzer.
Put a domain after your StackCheck URL to see what that site runs on:

```
https://stackcheck.yourdomain.com/stripe.com
```

The report covers **hosting, CDN, web server, CMS, ecommerce, frameworks, JS libraries, analytics, tag managers,
marketing pixels, payment providers, live chat, cookie consent, DNS and email providers, SSL certificate and
security headers**. Each detection shows the evidence it's based on and a confidence score.
It also finds the site's **sitemap and robots.txt**. For WordPress sites it lists the **theme and plugins**,
checks the **REST API**, and counts **posts, pages, categories and tags**.

- **One Python file, no dependencies.** Needs only Python 3.9+ and the standard library.
- **No third-party APIs.** It talks to the target site and a DNS resolver directly.
- **JSON API built in.** `curl` any report URL, or add `.json` to the end.
- **Fingerprints live in plain JSON** (`fingerprints.json`), so adding a technology is a one-line change.

---

## Quick start

```bash
git clone https://github.com/deshabhishek007/stackcheck.git && cd stackcheck
python3 stackcheck.py
# → open http://localhost:8080/github.com
```

One-off scan from the terminal:

```bash
python3 stackcheck.py scan example.com
```

In a terminal this prints a summary:

```
generatepress.com  -  GeneratePress - The perfect foundation for your WordPress website.
https://generatepress.com/  ·  HTTP 200  ·  TLS 1.3, certificate valid, 63 days left  ·  scanned in 2.5 s

Technologies (21)
  CDN                 Cloudflare                         100%
  CMS                 WordPress 7.1.2                    100%
  ...

WordPress
  Theme     GeneratePress Official 0.1 (child of GeneratePress)
  Theme     GeneratePress 3.6.1 (parent theme)
  Plugins   9: Affiliate WP 1.4.0, Easy Digital Downloads 3.6.9.1, ...
  REST API  restricted
  Content   288 posts, 42 pages, 6 categories (counted from the sitemap)

Sitemap     https://generatepress.com/wp-sitemap.xml  (listed in robots.txt, 336 URLs)
```

Add `--json` for the full report. When the output is piped (`| jq`, `> report.json`), it's JSON automatically.

### Docker

```bash
docker build -t stackcheck .
docker run -d --name stackcheck -p 127.0.0.1:8080:8080 --restart unless-stopped \
  -e STACKCHECK_ALLOWED_HOSTS=localhost,127.0.0.1 stackcheck
```

The image listens on all interfaces inside the container, so publish the port on `127.0.0.1` (as above) unless
you mean to expose it. Before putting it on a network, read [SECURITY.md](SECURITY.md) and set
`STACKCHECK_TOKEN` and `STACKCHECK_ALLOWED_HOSTS`.

---

## URLs

| URL | Returns |
| --- | --- |
| `/` | Home page with a search box |
| `/example.com` | HTML report in a browser, JSON for `curl` / API clients (based on the `Accept` header) |
| `/example.com.json` or `/example.com?format=json` | Always JSON |
| `/api/example.com` | Always JSON |
| `?refresh=1` | Skip the cache and rescan |
| `/https://example.com/some/page` | Also works; it's normalised to `/example.com` |
| `/healthz` | Health check |

```bash
curl -s http://localhost:8080/shopify.com | jq '.technologies[] | {name, category, confidence}'
```

### JSON shape (abridged)

```jsonc
{
  "domain": "vercel.com",
  "summary": { "title": "...", "technologies": 25, "categories": 14 },
  "technologies": [
    {
      "name": "Next.js", "category": "JavaScript Framework", "version": null,
      "confidence": 100, "level": "high",
      "evidence": [
        { "source": "headers", "match": "x-nextjs-cache: HIT", "confidence": 100 },
        { "source": "scripts", "match": "/_next/static/chunks/main.js", "confidence": 90 }
      ]
    }
  ],
  "blocked": null, // or { "by": "Cloudflare", "kind": "challenge", "status": 403, "evidence": "cf-mitigated: challenge" }
  "wordpress": {   // null when the site isn't WordPress
    "themes":  [ { "slug": "astra-child", "name": "Astra Child", "version": "1.1.8", "role": "child theme", "parent": "astra" } ],
    "plugins": [ { "slug": "wordpress-seo", "name": "Yoast SEO", "version": "22.6", "mu": false, "assets": 0, "evidence": ["..."] } ],
    "rest":    { "status": "open", "url": ".../wp-json/", "name": "...", "timezone": "America/Los_Angeles",
                 "namespaces": [], "other_namespaces": [], "users_public": false, "counts": { "posts": 682, "pages": 66 } },
    "content": { "posts": { "count": 682, "source": "REST API", "partial": false } }
  },
  "sitemap": { "found": true, "robots_txt": true, "url": ".../sitemap_index.xml", "source": "robots.txt", "kind": "index",
               "generator": "Yoast SEO", "urls": 1718, "partial": false, "children": 12, "sitemaps": [], "by_type": { "post": 682 } },
  "http":  { "final_url": "...", "status": 200, "response_ms": 125, "redirects": [], "headers": {}, "cookies": [] },
  "tls":   { "valid": true, "issuer": "R11", "protocol": "TLSv1.3", "alpn": "h2", "days_left": 61 },
  "dns":   { "zone": "...", "A": [], "AAAA": [], "NS": [], "MX": [], "TXT": [], "CAA": [], "DMARC": [], "PTR": {}, "dnssec": false },
  "security_headers": [ { "header": "HSTS", "present": true, "value": "max-age=..." } ]
}
```

---

## How detection works

For each scan StackCheck runs these steps in parallel (usually 1–3 seconds in total):

1. **HTTP fetch** of the homepage (HTTPS first, then HTTP). It follows redirects and records the headers, cookies and HTML.
2. **TLS handshake.** Records the certificate issuer and expiry, the TLS version and ALPN (used to detect HTTP/2).
3. **DNS lookups.** A, AAAA, CNAME, NS, MX, TXT, CAA, `_dmarc` and reverse DNS. It uses its own DNS client
   (UDP/TCP, with DNS-over-HTTPS as a fallback for restricted networks).
4. **Fingerprint matching** against `fingerprints.json`. Sources:

| Source | Example | Default confidence |
| --- | --- | --- |
| `headers` | `server: cloudflare`, `x-vercel-id` | 100 |
| `meta` | `<meta name="generator" content="WordPress 6.6">` | 100 |
| `cert` | issuer `Let's Encrypt` | 100 |
| `dns` | `MX aspmx.l.google.com`, `NS *.ns.cloudflare.com`, TXT `include:sendgrid.net` | 95 |
| `scripts` | `<script src="https://js.stripe.com/v3">` | 90 |
| `url_re` | final URL on `*.pages.dev` | 90 |
| `cookies` | `_shopify_y`, `laravel_session` | 85 |
| `ptr` | reverse DNS `*.amazonaws.com` | 80 |
| `html` | `data-reactroot`, `fbq('init'` | 70 |

When several pieces of evidence point to the same technology they are combined as `1 − Π(1 − cᵢ)`.
**High** means 85 or more, **medium** 60–84, **low** below 60. A technology can also be *implied* by another
(for example Next.js implies React). Implied technologies get a lower confidence and are labelled as implied.

### WordPress themes and plugins

When a site looks like WordPress, StackCheck also lists its theme and plugins in a **WordPress** tab
(and under `wordpress` in the JSON):

- **Files on the homepage.** Any path under `/wp-content/plugins/`, `/wp-content/mu-plugins/` or `/wp-content/themes/`,
  including escaped paths inside inline JSON. Versions come from the `?ver=` query string; a `?ver=` equal to the
  WordPress core version is ignored, because that's WordPress's default rather than the plugin's own version.
- **HTML comments.** Some SEO and cache plugins load no files but leave a comment: Yoast SEO, Rank Math,
  All in One SEO, Site Kit, WP Rocket, LiteSpeed Cache, W3 Total Cache and WP Super Cache.
- **The theme's `style.css`.** One extra request reads the theme header for its real name, version, author and
  parent. A child theme's parent is listed too, even when the page doesn't load it directly.

- **REST API namespaces.** Most plugins register a namespace (`yoast/v1`, `wc/v3`, `elementor/v1`), which
  reveals plugins that leave nothing on the homepage. Known namespaces are mapped to plugins; the rest are listed
  as "Other APIs".

Only what's visible from outside shows up. Plugins that run only in the admin or on other pages, or whose files
are merged by an optimiser such as Autoptimize, won't be listed.

The **REST API** panel shows whether `/wp-json/` is open, restricted to logged-in users or disabled, plus the site
name, tagline, timezone and login methods it reports. It also checks whether `/wp/v2/users` lists users publicly
(a common way to find login names). StackCheck only counts them and never requests or stores the usernames.

The **Content** panel counts posts, pages, categories and tags from the REST API's `X-WP-Total` header. When the
API is locked, it falls back to counting URLs in the matching sitemaps.

### Sitemap and robots.txt

For every site, StackCheck reads `robots.txt` for `Sitemap:` lines, then tries `/sitemap.xml`,
`/sitemap_index.xml` and `/wp-sitemap.xml`. For a sitemap index it counts the URLs in the first 12 child
sitemaps and groups them by type (post, page, category …) from the file names. Totals for larger indexes are
marked as partial (`≥`).

### Adding a technology

Add an entry to `fingerprints.json`, then restart:

```json
"Plausible": {
  "cat": "Analytics",
  "url": "https://plausible.io",
  "scripts": ["plausible\\.io/js/"],
  "headers": { "x-some-header": "" },
  "cookies": { "plausible_": "" },
  "meta": { "generator": "^Plausible ([\\d.]+)" },
  "html": ["plausible\\("],
  "dns": { "TXT": ["^plausible-verification="], "NS": [], "MX": [], "CNAME": [] },
  "implies": ["Some Other Tech"],
  "conf": 80
}
```

- Patterns are case-insensitive regexes. An empty string means "present".
- The first capture group becomes the **version**.
- Header keys are exact header names. Cookie and meta keys are regexes matched from the start of the name.
- `conf` (optional) overrides the default confidence for every pattern in the entry.

Run `python3 -m unittest discover tests` after editing. The tests check that every regex compiles and every
`implies` target exists.

---

## Configuration

Set these with environment variables (or `--host`, `--port`, `--allow-private` and `--trust-proxy` on the command line):

| Variable | Default | Meaning |
| --- | --- | --- |
| `STACKCHECK_HOST` | `127.0.0.1` | Bind address. Only this machine can connect; use `0.0.0.0` to listen on the network |
| `STACKCHECK_PORT` | `8080` | Port. If unset, the `PORT` variable that Render, Railway, Fly and similar hosts provide is used |
| `STACKCHECK_ALLOWED_HOSTS` | localhost names | Host names the server answers to, comma-separated (`*` for any). Defaults to `localhost`, `127.0.0.1` and `::1` when bound to loopback, and to any name (with a warning) on a network address |
| `STACKCHECK_TOKEN` | *(none)* | If set, every request except `/healthz` needs it: `Authorization: Bearer <token>`, or HTTP Basic with any username and the token as the password (browsers prompt for it) |
| `STACKCHECK_CORS` | *(none)* | Origins allowed to read the JSON API from another site, comma-separated (`*` for any). Off by default |
| `STACKCHECK_TRUST_PROXY` | `false` | Use `X-Forwarded-For` (its right-most entry) for rate limiting. Turn on behind nginx or Caddy |
| `STACKCHECK_RATE_LIMIT` | `30` | New scans per client IP per minute (0 = unlimited) |
| `STACKCHECK_SITE_RATE_LIMIT` | `10` | New scans of one site per minute, counting all its subdomains (0 = unlimited) |
| `STACKCHECK_REFRESH_COOLDOWN` | `60` | A `?refresh=1` within this many seconds of the last scan gets the cached report |
| `STACKCHECK_MAX_SCANS` | `8` | Scans running at once; more wait briefly, then get a 503 |
| `STACKCHECK_MAX_CONNECTIONS` | `64` | Open connections; more get an immediate 503 |
| `STACKCHECK_CLIENT_TIMEOUT` | `20` | Seconds a client may take to send its request |
| `STACKCHECK_DNS` | `1.1.1.1,8.8.8.8` | DNS resolvers (comma-separated), or `system` to use `/etc/resolv.conf` |
| `STACKCHECK_DOH` | `https://cloudflare-dns.com/dns-query` | DNS-over-HTTPS fallback (empty string turns it off) |
| `STACKCHECK_USER_AGENT` | browser-like, ending `StackCheck/<version> (+repo URL)` | User-Agent sent to scanned sites |
| `STACKCHECK_TIMEOUT` | `10` | Seconds per network operation |
| `STACKCHECK_CACHE_TTL` | `900` | Seconds to cache a report (0 turns caching off) |
| `STACKCHECK_ALLOW_PRIVATE` | `false` | Allow scanning private and internal IPs. Refused on a network address unless `STACKCHECK_TOKEN` is set. **Only use this on a trusted LAN.** |

---

## Running in production

Run StackCheck on `127.0.0.1` behind a reverse proxy that handles HTTPS, and tell it the name it's served on.
See [SECURITY.md](SECURITY.md) for what to lock down.

### Behind Caddy (automatic HTTPS)

```
stackcheck.yourdomain.com {
    reverse_proxy 127.0.0.1:8080
}
```

### Behind nginx

```nginx
server {
    server_name stackcheck.yourdomain.com;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 60s;
    }
}
```

Note: with nginx, keep the default `merge_slashes on`. StackCheck already handles paths like `/https:/example.com`.

### systemd

```ini
# /etc/systemd/system/stackcheck.service
[Unit]
Description=StackCheck
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/stackcheck/stackcheck.py --host 127.0.0.1 --port 8080 --trust-proxy
Environment=STACKCHECK_ALLOWED_HOSTS=stackcheck.yourdomain.com
# Environment=STACKCHECK_TOKEN=change-me      # for a private instance
Restart=always
User=nobody
DynamicUser=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now stackcheck
```

---

## Security notes

- **SSRF protection.** Every connection (page fetches, redirects, the TLS check) resolves the host once,
  refuses it if any address is private, loopback, link-local, CGNAT or reserved, and then connects to an
  address that passed the check. A DNS answer that changes between the check and the connection (DNS
  rebinding) can't reach an internal service. Only ports 80 and 443 are used, only `http:` and `https:`
  redirects are followed, and environment proxy settings are ignored. If you run StackCheck inside a
  sensitive network, also limit its outbound traffic at the firewall as a second layer.
- **Requests stay on the scanned site.** The extra requests (robots.txt, sitemaps, REST API, theme
  stylesheet) only go to the scanned domain, the host it redirected to, and their subdomains, including on
  redirects. Sitemaps or API roots that point elsewhere are listed but not fetched, so a scanned site can't
  use StackCheck to send traffic to someone else.
- **Size limits.** A page is read up to 3 MB, and compressed responses are only expanded up to the same
  limit, so a small compressed "bomb" can't use gigabytes of memory. robots.txt and REST responses are
  limited to 512 KB and a theme stylesheet to 256 KB. Sitemaps are counted while streaming, 1 MB at a time,
  up to 20 MB downloaded and 200 MB expanded.
- Only those few files are fetched, and JavaScript is not executed. Technologies that load entirely at
  runtime through a tag manager can be missed. That is the trade-off for being lightweight.
- The HTML report escapes everything taken from scanned sites, only turns `http:` and `https:` URLs into
  links, and is served with a CSP that allows no inline scripts.
- **Server.** It listens on `127.0.0.1` and only answers localhost names unless configured otherwise, so a web
  page can't use DNS rebinding to drive a StackCheck on your machine. The JSON API isn't readable from other
  sites unless you set `STACKCHECK_CORS`. Connections, concurrent scans and scans per IP and per site are
  limited, and slow clients are dropped.

See [SECURITY.md](SECURITY.md) for the threat model, deployment checklist and how to report a vulnerability.

## Limitations and ideas

- No headless browser, so client-side-only tags are invisible. A Playwright mode could be added as an option.
- Sites behind bot protection (Cloudflare, Imperva, Sucuri, Akamai, DataDome, AWS WAF and others) may serve a
  challenge or block page instead of the homepage. StackCheck recognises these, says so at the top of the report
  (and in `"blocked"` in the JSON), and ignores that page's content. DNS, TLS, hosting and CDN results are still
  reliable. It doesn't try to get past bot protection.
- Possible next steps: a scan history page, a diff between two scans, a bulk CSV endpoint, and IP→ASN lookup with an offline database.

## License

MIT
