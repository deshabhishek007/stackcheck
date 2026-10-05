# Security

StackCheck takes a domain from whoever asks and connects to whatever that domain points to. That makes it a
network tool other people can steer, so it's worth knowing what it protects against and what you still need
to set up yourself.

## Reporting a vulnerability

Please report security problems privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Please don't open a public issue.

## Threat model

There are three kinds of people who can attack a StackCheck instance:

| Who | What they control | What StackCheck does about it |
| --- | --- | --- |
| **The site being scanned** | Every byte of its responses and DNS | Size limits on everything it reads; compressed responses can't expand past those limits; only ports 80 and 443; each connection goes to an address that was checked as public at connect time (no DNS rebinding); secondary requests stay on the scanned site; anything it returns is escaped in the report, and only `http(s)` URLs become links |
| **Anyone who can reach your instance** | Which domains get scanned, and how often | Rate limits per IP and per target site, a cap on concurrent scans and connections, slow clients dropped, a refresh cooldown, and an optional access token |
| **A web page open in your browser** | Requests your browser makes to a StackCheck on your machine or network | Listens on `127.0.0.1` by default; only answers allowed host names, which blocks DNS rebinding against StackCheck itself; the JSON API isn't readable cross-site unless you enable `STACKCHECK_CORS`; the page has a CSP with no inline scripts |

### What a scan sends

A scan of one domain makes, at most:

- DNS queries to your configured resolvers (`1.1.1.1` and `8.8.8.8` by default, so Cloudflare and Google see
  which domains you scan; set `STACKCHECK_DNS=system` to use your own).
- A TLS handshake and a homepage request to the site.
- `robots.txt`, the sitemaps it lists (or up to 3 common sitemap paths), and up to 12 child sitemaps.
- For WordPress: the theme's `style.css` (two for a child theme) and 6 small REST API requests, including a
  check of whether `/wp/v2/users` is public. StackCheck only counts users; it never requests or stores
  usernames.

All of it is sent with a User-Agent that ends in `StackCheck/<version> (+https://github.com/deshabhishek007/stackcheck)`
so site owners can identify and block it. Scans come from your server's IP address, so abuse complaints about
an open instance will come to you.

### Known limits

- The private-address check covers loopback, private, link-local (including cloud metadata at
  `169.254.169.254`), CGNAT and reserved ranges. If StackCheck runs inside a sensitive network, also restrict
  its outbound traffic at the firewall.
- The per-site limit groups subdomains by their last two labels (three for names like `example.co.uk`). It
  isn't a full public-suffix list.
- Python's built-in HTTP server isn't hardened against every malformed request. Put a reverse proxy in front
  of anything reachable from the internet.
- The token is sent with every request, so only use it over HTTPS.

## Deployment checklist

**On your own machine:** the defaults are fine. StackCheck listens on `127.0.0.1` and only answers
`localhost`, `127.0.0.1` and `::1`.

**On a server:**

1. Keep `STACKCHECK_HOST=127.0.0.1` and put Caddy or nginx in front for HTTPS.
2. Set `STACKCHECK_ALLOWED_HOSTS` to the name you serve it on, e.g. `stackcheck.example.com`.
3. Set `STACKCHECK_TRUST_PROXY=true`. With nginx, send `proxy_set_header X-Forwarded-For $remote_addr;` or
   `$proxy_add_x_forwarded_for`; StackCheck uses the right-most entry, which your proxy added.
4. For a private instance, set `STACKCHECK_TOKEN` to a long random value, e.g. `openssl rand -hex 24`.
   Browsers will prompt for it (use any username), and API clients send `Authorization: Bearer <token>`.
5. For a public instance, keep the rate limits. Consider lowering `STACKCHECK_MAX_SCANS`, and restrict
   outbound traffic to ports 53, 80 and 443.
6. Don't use `STACKCHECK_ALLOW_PRIVATE` on anything others can reach. StackCheck refuses it on a network
   address unless a token is set.

**With Docker:** the image listens on all interfaces inside the container. Publish it on loopback
(`-p 127.0.0.1:8080:8080`) behind a reverse proxy, or set `STACKCHECK_TOKEN` and `STACKCHECK_ALLOWED_HOSTS`
before publishing it on the network.

## Logs

Each request is logged to stderr with the client IP and the path, which includes the scanned domain. Rotate
or discard those logs to suit your privacy needs. Scan results are kept only in memory, for
`STACKCHECK_CACHE_TTL` seconds.
