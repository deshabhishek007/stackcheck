# StackCheck

A small, self-hosted website technology scanner, in the same spirit as BuiltWith or Wappalyzer.
Put a domain after your StackCheck URL to see what that site runs on:

```
https://stackcheck.yourdomain.com/stripe.com
```

The report covers **hosting, CDN, web server, CMS, ecommerce, frameworks, JS libraries, analytics, tag managers,
marketing pixels, payment providers, live chat, cookie consent, DNS and email providers, SSL certificate and
security headers**. Each detection shows the evidence it's based on and a confidence score.

- **One Python file, no dependencies.** Needs only Python 3.9+ and the standard library.
- **No third-party APIs.** It talks to the target site and a DNS resolver directly.
- **JSON API built in.** `curl` any report URL, or add `.json` to the end.
- **Fingerprints live in plain JSON** (`fingerprints.json`), so adding a technology is a one-line change.

---

## Quick start

```bash
git clone <your-repo-url> stackcheck && cd stackcheck
python3 stackcheck.py
# → open http://localhost:8080/github.com
```

One-off scan from the terminal:

```bash
python3 stackcheck.py scan example.com
```

### Docker

```bash
docker build -t stackcheck .
docker run -d --name stackcheck -p 8080:8080 --restart unless-stopped stackcheck
```

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
| `STACKCHECK_HOST` | `0.0.0.0` | Bind address |
| `STACKCHECK_PORT` | `8080` | Port |
| `STACKCHECK_DNS` | `1.1.1.1,8.8.8.8` | DNS resolvers (comma-separated) |
| `STACKCHECK_DOH` | `https://cloudflare-dns.com/dns-query` | DNS-over-HTTPS fallback (empty string turns it off) |
| `STACKCHECK_TIMEOUT` | `10` | Seconds per network operation |
| `STACKCHECK_CACHE_TTL` | `900` | Seconds to cache a report (0 turns caching off) |
| `STACKCHECK_RATE_LIMIT` | `30` | New scans per client IP per minute (0 = unlimited) |
| `STACKCHECK_TRUST_PROXY` | `false` | Use `X-Forwarded-For` for rate limiting (turn on behind nginx or Caddy) |
| `STACKCHECK_ALLOW_PRIVATE` | `false` | Allow scanning private and internal IPs. **Only use this on a trusted LAN.** |

---

## Running in production

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

- **SSRF protection.** Before connecting, StackCheck resolves the target and refuses private, loopback,
  link-local, CGNAT and reserved addresses. It checks again on every redirect hop. This guards against
  the common cases, but it is not proof against a determined DNS-rebinding attack. If you run StackCheck
  inside a sensitive network, also limit its outbound traffic at the firewall.
- Only the homepage is fetched (capped at 3 MB), and JavaScript is not executed. Technologies that load
  entirely at runtime through a tag manager can be missed. That is the trade-off for being lightweight.
- The HTML report has a strict CSP and escapes everything taken from scanned sites.

## Limitations and ideas

- No headless browser, so client-side-only tags are invisible. A Playwright mode could be added as an option.
- WAFs (Akamai, Cloudflare bot fight mode and others) may return 403 pages. The headers and DNS are still analysed.
- Possible next steps: a scan history page, a diff between two scans, a bulk CSV endpoint, and IP→ASN lookup with an offline database.

## License

MIT
