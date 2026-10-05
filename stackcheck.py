#!/usr/bin/env python3
"""
StackCheck - a self-hosted website technology scanner.

Run it, then visit  http://localhost:8080/example.com  to see what powers example.com.

  python3 stackcheck.py                    # serve on 127.0.0.1:8080
  python3 stackcheck.py --port 3000
  python3 stackcheck.py scan example.com   # one-off scan: a summary in a terminal, JSON when piped
  python3 stackcheck.py scan example.com --json

Pure Python standard library (3.9+). No pip install needed.
License: MIT
"""
from __future__ import annotations

import argparse
import base64
import hmac
import html as html_lib
import http.client
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import struct
import sys
import tempfile
import textwrap
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__version__ = "1.0.0"

HERE = os.path.dirname(os.path.abspath(__file__))
# Browser-like so sites serve their normal page, but it names StackCheck and links to it so site owners can
# see what the requests are and block them if they want.
DEFAULT_USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      f"Chrome/129.0 Safari/537.36 StackCheck/{__version__} "
                      "(+https://github.com/deshabhishek007/stackcheck)")


# --------------------------------------------------------------------------- config

def env(name, default):
    v = os.environ.get("STACKCHECK_" + name)
    if v is None:
        return default
    if isinstance(default, bool):
        return v.lower() in ("1", "true", "yes", "on")
    if isinstance(default, int):
        return int(v)
    return v


def _system_resolvers() -> list[str]:
    """Nameservers from /etc/resolv.conf, for STACKCHECK_DNS=system."""
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as f:
            return [m.group(1) for m in re.finditer(r"(?m)^\s*nameserver\s+(\S+)", f.read())]
    except OSError:
        return []


def default_port() -> int:
    """STACKCHECK_PORT, else PORT (set by Render, Railway, Fly, Heroku and similar hosts), else 8080."""
    return int(os.environ.get("STACKCHECK_PORT") or os.environ.get("PORT") or 8080)


def _split(value: str) -> list[str]:
    return [x.strip() for x in value.split(",") if x.strip()]


class Config:
    host = env("HOST", "127.0.0.1")           # 0.0.0.0 exposes it to the network (the Docker image sets that)
    port = default_port()
    dns_servers = (_system_resolvers() if env("DNS", "").strip().lower() == "system"
                   else _split(env("DNS", "1.1.1.1,8.8.8.8")))
    doh_url = env("DOH", "https://cloudflare-dns.com/dns-query")
    timeout = env("TIMEOUT", 10)              # seconds per network operation
    max_body = env("MAX_BODY", 3_000_000)     # bytes of HTML to read
    cache_ttl = env("CACHE_TTL", 900)         # seconds; 0 disables cache
    cache_size = env("CACHE_SIZE", 500)
    rate_limit = env("RATE_LIMIT", 30)        # fresh scans per IP per minute; 0 disables
    allow_private = env("ALLOW_PRIVATE", False)  # allow scanning private/internal IPs (SSRF risk!)
    trust_proxy = env("TRUST_PROXY", False)   # honour X-Forwarded-For for rate limiting
    allowed_hosts = _split(env("ALLOWED_HOSTS", ""))  # Host header names to answer; see effective_allowed_hosts()
    cors = _split(env("CORS", ""))           # origins allowed to read the JSON API cross-site ("*" for any)
    token = env("TOKEN", "")                  # if set, every request except /healthz needs this token
    user_agent = env("USER_AGENT", DEFAULT_USER_AGENT)
    max_scans = env("MAX_SCANS", 8)           # scans running at once; more wait, then get 503
    max_connections = env("MAX_CONNECTIONS", 64)
    client_timeout = env("CLIENT_TIMEOUT", 20)    # seconds a client may take to send its request
    site_rate_limit = env("SITE_RATE_LIMIT", 10)  # fresh scans of one site (any subdomain) per minute
    refresh_cooldown = env("REFRESH_COOLDOWN", 60)  # ?refresh=1 within this many seconds serves the cache
    hosts: set[str] | None = None              # effective Host allowlist, set at startup; None = any
    fingerprints = env("FINGERPRINTS", os.path.join(HERE, "fingerprints.json"))


# --------------------------------------------------------------------------- helpers

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9-]{1,63}(?<!-)\.)+[a-z][a-z0-9-]{0,62}(?<!-)$")


class ScanError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def normalize_domain(raw: str) -> str:
    """Turn 'https://www.Example.com/path?x' into 'www.example.com'. Raises ScanError."""
    s = urllib.parse.unquote(raw or "").strip().strip("/")
    s = re.sub(r"^[a-z][a-z0-9+.-]*:/{1,2}", "", s, flags=re.I)  # tolerate https:/ (collapsed slashes)
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    s = s.rsplit("@", 1)[-1]               # drop credentials
    s = re.sub(r":\d+$", "", s).rstrip(".").lower()
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError:
        raise ScanError("That doesn't look like a valid domain name.")
    if not DOMAIN_RE.match(s):
        raise ScanError("That doesn't look like a valid domain name.")
    return s


def ip_is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return a.is_global and not (a.is_multicast or a.is_reserved)


def resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    out = []
    for info in infos:
        ip = info[4][0]
        if ip not in out:
            out.append(ip)
    return out


def assert_public(host: str) -> list[str]:
    """SSRF guard: refuse hosts that resolve to private / loopback / link-local addresses."""
    ips = resolve_host(host)
    if not ips:
        raise ScanError(f"Could not resolve {host}.", 404)
    if not Config.allow_private:
        bad = [ip for ip in ips if not ip_is_public(ip)]
        if bad:
            raise ScanError(f"{host} resolves to a non-public address; refusing to scan.", 403)
    return ips


# --------------------------------------------------------------------------- DNS client

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}
QTYPE_NAMES = {v: k for k, v in QTYPES.items()}


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("ascii")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _read_name(data: bytes, off: int) -> tuple[str, int]:
    labels, end, hops = [], None, 0
    while True:
        length = data[off]
        if length & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | data[off + 1]
            hops += 1
            if hops > 30:
                raise ValueError("DNS compression loop")
            continue
        if length == 0:
            off += 1
            break
        labels.append(data[off + 1: off + 1 + length].decode("ascii", "replace"))
        off += 1 + length
    return ".".join(labels), (end if end is not None else off)


def _parse_rdata(rtype: int, data: bytes, off: int, rdlen: int):
    rd = data[off: off + rdlen]
    if rtype == 1 and rdlen == 4:
        return socket.inet_ntop(socket.AF_INET, rd)
    if rtype == 28 and rdlen == 16:
        return socket.inet_ntop(socket.AF_INET6, rd)
    if rtype in (2, 5, 12):
        return _read_name(data, off)[0]
    if rtype == 15:
        pref = struct.unpack(">H", rd[:2])[0]
        return f"{pref} {_read_name(data, off + 2)[0]}"
    if rtype == 16:
        parts, i = [], 0
        while i < len(rd):
            n = rd[i]
            parts.append(rd[i + 1: i + 1 + n].decode("utf-8", "replace"))
            i += 1 + n
        return "".join(parts)
    if rtype == 257 and rdlen >= 2:
        flags, tlen = rd[0], rd[1]
        tag = rd[2: 2 + tlen].decode("ascii", "replace")
        val = rd[2 + tlen:].decode("utf-8", "replace")
        return f'{flags} {tag} "{val}"'
    if rtype == 6:
        mname, o = _read_name(data, off)
        rname, o = _read_name(data, o)
        return f"{mname} {rname}"
    return rd.hex()


def _dns_wire(name: str, qtype: int, server: str, timeout: float):
    qid = random.randint(0, 0xFFFF)
    # flags: RD (0x0100) + AD (0x0020) so validating resolvers tell us about DNSSEC
    # EDNS0 OPT record: 1232-byte UDP buffer (DNS Flag Day 2020) avoids fragmentation; bigger answers use TCP
    packet = (struct.pack(">HHHHHH", qid, 0x0120, 1, 0, 0, 1) + _encode_name(name) + struct.pack(">HH", qtype, 1)
              + b"\x00" + struct.pack(">HHIH", 41, 1232, 0, 0))
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server, 53))
        while True:
            data, _ = s.recvfrom(65535)
            if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == qid:
                break
    if struct.unpack(">H", data[2:4])[0] & 0x0200:  # truncated -> retry over TCP
        with socket.create_connection((server, 53), timeout=min(timeout, 2)) as s:
            s.sendall(struct.pack(">H", len(packet)) + packet)
            ln = struct.unpack(">H", _recv_exact(s, 2))[0]
            data = _recv_exact(s, ln)
    return data


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed")
        buf += chunk
    return buf


def _parse_dns(data: bytes, qtype: int):
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    rcode = flags & 0x000F
    ad = bool(flags & 0x0020)
    off = 12
    for _ in range(qd):
        _, off = _read_name(data, off)
        off += 4
    answers = []
    for _ in range(an):
        _, off = _read_name(data, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[off: off + 10])
        off += 10
        if rtype == qtype or (qtype != 5 and rtype == 5):
            answers.append((rtype, _parse_rdata(rtype, data, off, rdlen)))
        off += rdlen
    return rcode, ad, answers


def _dns_doh(name: str, qtype: int, timeout: float):
    url = f"{Config.doh_url}?name={urllib.parse.quote(name)}&type={qtype}"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": Config.user_agent})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        j = json.loads(r.read())
    answers = []
    for a in j.get("Answer", []) or []:
        data = a.get("data", "")
        if a.get("type") == 16:
            data = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', data)) or data
        data = data.rstrip(".") if a.get("type") in (2, 5, 12) else data
        if a.get("type") == 15:
            data = data.rstrip(".")
        answers.append((a.get("type"), data))
    return j.get("Status", 0), bool(j.get("AD")), answers


def dns_query(name: str, rtype: str, timeout: float | None = None) -> dict:
    """Returns {'records': [...], 'cname': [...], 'ad': bool}. Never raises."""
    qtype = QTYPES[rtype]
    timeout = timeout or min(Config.timeout, 3)
    # order: primary resolver -> DNS-over-HTTPS (works behind firewalls) -> remaining resolvers
    attempts = [("udp", srv) for srv in Config.dns_servers[:1]]
    if Config.doh_url:
        attempts.append(("doh", Config.doh_url))
    attempts += [("udp", srv) for srv in Config.dns_servers[1:]]
    result = None
    for kind, srv in attempts:
        try:
            if kind == "udp":
                result = _parse_dns(_dns_wire(name, qtype, srv, timeout), qtype)
            else:
                result = _dns_doh(name, qtype, timeout)
            break
        except Exception:
            continue
    if result is None:
        if rtype in ("A", "AAAA"):  # last resort: system resolver
            fam = socket.AF_INET if rtype == "A" else socket.AF_INET6
            try:
                ips = sorted({i[4][0] for i in socket.getaddrinfo(name, None, fam)})
            except socket.gaierror:
                ips = []
            return {"records": ips, "cname": [], "ad": False}
        return {"records": [], "cname": [], "ad": False, "error": "lookup failed"}
    _, ad, answers = result
    return {
        "records": [d for t, d in answers if t == qtype],
        "cname": [d for t, d in answers if t == 5 and qtype != 5],
        "ad": ad,
    }


def reverse_name(ip: str) -> str:
    return ipaddress.ip_address(ip).reverse_pointer


# --------------------------------------------------------------------------- TLS probe

def _decode_der_cert(der: bytes) -> dict:
    """Decode a certificate we could not verify, using CPython's internal helper."""
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(pem)
            path = f.name
        try:
            return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        finally:
            os.unlink(path)
    except Exception:
        return {}


def _name_field(rdns, key):
    for rdn in rdns or ():
        for k, v in rdn:
            if k == key:
                return v
    return None


def tls_probe(host: str) -> dict:
    out: dict = {"valid": False}

    def handshake(verify: bool):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with _connect_public(host, 443, Config.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert() if verify else _decode_der_cert(ss.getpeercert(binary_form=True) or b"")
                return cert, ss.version(), ss.cipher(), ss.selected_alpn_protocol()

    try:
        cert, proto, cipher, alpn = handshake(True)
        out["valid"] = True
    except ssl.SSLCertVerificationError as e:
        out["error"] = e.verify_message or str(e)
        try:
            cert, proto, cipher, alpn = handshake(False)
        except Exception as e2:
            out["error"] += f" ({e2})"
            return out
    except Exception as e:
        out["error"] = str(e) or e.__class__.__name__
        return out

    out["protocol"] = proto
    out["cipher"] = cipher[0] if cipher else None
    out["alpn"] = alpn
    if cert:
        out["subject"] = _name_field(cert.get("subject"), "commonName")
        out["issuer"] = _name_field(cert.get("issuer"), "commonName")
        out["issuer_org"] = _name_field(cert.get("issuer"), "organizationName")
        out["san"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:50]
        for k in ("notBefore", "notAfter"):
            if cert.get(k):
                ts = ssl.cert_time_to_seconds(cert[k])
                out["not_before" if k == "notBefore" else "not_after"] = (
                    datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d"))
                if k == "notAfter":
                    out["days_left"] = int((ts - time.time()) // 86400)
    return out


# --------------------------------------------------------------------------- HTTP fetch

ALLOWED_PORTS = {80, 443}


def _connect_public(host: str, port: int, timeout) -> socket.socket:
    """Open a TCP connection to host:port, resolving the name exactly once.

    Every resolved address must be public (unless --allow-private), and the socket connects to one of those
    same addresses. Checking a name and then letting the HTTP library resolve it again would let a DNS answer
    that changes in between (DNS rebinding) reach an internal service."""
    if port not in ALLOWED_PORTS:
        raise ScanError(f"Refusing to connect to {host} on port {port}; only ports 80 and 443 are allowed.", 403)
    if not isinstance(timeout, (int, float)):
        timeout = Config.timeout
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ScanError(f"Could not resolve {host}.", 404)
    if not Config.allow_private and any(not ip_is_public(info[4][0]) for info in infos):
        raise ScanError(f"{host} resolves to a non-public address; refusing to connect.", 403)
    last: OSError | None = None
    for family, stype, proto, _, addr in infos:
        s = socket.socket(family, stype, proto)
        s.settimeout(timeout)
        try:
            s.connect(addr)
            return s
        except OSError as e:
            last = e
            s.close()
    raise last or OSError(f"Could not connect to {host}")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = _connect_public(self.host, self.port, self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        sock = _connect_public(self.host, self.port, self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_PinnedHTTPConnection, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PinnedHTTPSConnection, req, context=self._context)


def site_roots(*hosts: str | None) -> tuple[str, ...]:
    """Hosts that, with their subdomains, count as the scanned site: the domain and final host, minus www."""
    out: list[str] = []
    for h in hosts:
        h = (h or "").lower().rstrip(".")
        h = h[4:] if h.startswith("www.") else h
        if h and h not in out:
            out.append(h)
    return tuple(out)


def in_scope(host: str, roots: tuple[str, ...]) -> bool:
    host = (host or "").lower().rstrip(".")
    return any(host == r or host.endswith("." + r) for r in roots)


class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 8

    def __init__(self, scope: tuple[str, ...] | None = None):
        self.scope = scope
        self.chain: list[dict] = []
        self.cookies: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        if parts.scheme not in ("http", "https"):
            raise ScanError(f"Refusing to follow a redirect to a {parts.scheme or 'relative'}: URL.", 403)
        host = parts.hostname or ""
        if self.scope is not None and not in_scope(host, self.scope):
            raise ScanError(f"Refusing to follow a redirect off the scanned site to {host}.", 403)
        assert_public(host)  # early, friendlier error; _connect_public re-checks the address it connects to
        self.chain.append({"status": code, "from": req.full_url, "to": newurl})
        self.cookies.extend(headers.get_all("Set-Cookie") or [])
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _decompress(body: bytes, encoding: str, limit: int) -> tuple[bytes, bool]:
    """Decode gzip/deflate into at most `limit` bytes, so a small compressed body can't expand into gigabytes.
    Returns (data, truncated)."""
    encoding = (encoding or "").lower()
    if "gzip" in encoding:
        modes = [16 + zlib.MAX_WBITS]
    elif "deflate" in encoding:
        modes = [zlib.MAX_WBITS, -zlib.MAX_WBITS]  # zlib-wrapped, then raw deflate
    else:
        modes = []
    for wbits in modes:
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(body, limit)
            return out, bool(d.unconsumed_tail)
        except zlib.error:
            continue
    return body[:limit], len(body) > limit


def http_fetch(host: str) -> dict:
    last_err = None
    for scheme in ("https", "http"):
        for verify in (True, False):
            if scheme == "http" and not verify:
                continue
            try:
                try:
                    return _fetch_once(f"{scheme}://{host}/", verify)
                except urllib.error.URLError as e:
                    if not isinstance(e.reason, ConnectionResetError):
                        raise
                    return _fetch_once(f"{scheme}://{host}/", verify)  # some servers reset now and then; retry once
            except ScanError:
                raise
            except urllib.error.URLError as e:
                last_err = e
                if isinstance(e.reason, ssl.SSLCertVerificationError):
                    continue  # retry unverified so we still see the stack
                break
            except Exception as e:
                last_err = e
                break
    raise ScanError(f"Could not fetch {host}: {getattr(last_err, 'reason', last_err)}", 502)


def _open(url: str, verify: bool, scope: tuple[str, ...] | None):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    redirect = _GuardedRedirect(scope)
    # Built by hand rather than with build_opener(): only http(s), every connection pinned and checked,
    # and no ftp:, file: or environment proxy handlers.
    opener = urllib.request.OpenerDirector()
    for handler in (_PinnedHTTPHandler(), _PinnedHTTPSHandler(context=ctx), redirect,
                    urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor()):
        opener.add_handler(handler)
    req = urllib.request.Request(url, headers={
        "User-Agent": Config.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
    })
    try:
        return opener.open(req, timeout=Config.timeout), redirect
    except urllib.error.HTTPError as e:  # 4xx/5xx still carry useful headers and HTML
        return e, redirect


def _fetch_once(url: str, verify: bool, scope: tuple[str, ...] | None = None, max_bytes: int | None = None) -> dict:
    limit = max_bytes or Config.max_body
    t0 = time.monotonic()
    resp, redirect = _open(url, verify, scope)
    with resp:
        raw = resp.read(limit + 1)
        status = resp.status if hasattr(resp, "status") else resp.code
        headers = resp.headers
        final_url = resp.geturl()
    elapsed = int((time.monotonic() - t0) * 1000)
    body, cut = _decompress(raw[:limit], headers.get("Content-Encoding", ""), limit)
    m = re.search(r"charset=([\w-]+)", headers.get("Content-Type", ""), re.I)
    charset = m.group(1) if m else "utf-8"
    try:
        html = body.decode(charset, "replace")
    except LookupError:
        html = body.decode("utf-8", "replace")
    hdrs: dict[str, str] = {}
    for k, v in headers.items():
        k = k.lower()
        hdrs[k] = f"{hdrs[k]}, {v}" if k in hdrs and k != "set-cookie" else v
    cookies = list(redirect.cookies) + (headers.get_all("Set-Cookie") or [])
    return {
        "url": url, "final_url": final_url, "status": status, "verified": verify,
        "redirects": redirect.chain, "response_ms": elapsed,
        "headers": hdrs, "cookies": cookies, "html": html, "truncated": len(raw) > limit or cut,
    }


STREAM_MAX_RAW = 20_000_000    # bytes downloaded when streaming a large sitemap
STREAM_MAX_OUT = 200_000_000   # bytes decompressed; scanned in 1 MB pieces and never held in memory
_URL_TAG = re.compile(rb"<url[\s>]", re.I)  # 5 bytes, so a 4-byte carry-over can't hold a whole match


def _stream_sitemap(url: str, verify: bool, scope: tuple[str, ...]) -> dict | None:
    """Count <url> entries in a sitemap of any size with flat memory use: decompress in 1 MB pieces, count,
    and keep only the first 64 KB (enough to tell an index from a urlset). None on failure."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not in_scope(parts.hostname or "", scope):
        return None
    try:
        resp, _ = _open(url, verify, scope)
        with resp:
            status = resp.status if hasattr(resp, "status") else resp.code
            enc = resp.headers.get("Content-Encoding", "").lower()
            wbits = 16 + zlib.MAX_WBITS if "gzip" in enc else zlib.MAX_WBITS if "deflate" in enc else None
            d = zlib.decompressobj(wbits) if wbits else None
            head, carry, count, raw, out, truncated = bytearray(), b"", 0, 0, 0, False
            while not truncated:
                chunk = resp.read(65536)
                if not chunk:
                    break
                raw += len(chunk)
                pending = chunk
                while pending and not truncated:  # one 1 MB piece at a time, however well it compresses
                    if d is None:
                        buf, pending = pending, b""
                    else:
                        buf = d.decompress(pending, 1 << 20)
                        pending = d.unconsumed_tail
                    out += len(buf)
                    if len(head) < 65536:
                        head += buf[:65536 - len(head)]
                    text = carry + buf
                    count += len(_URL_TAG.findall(text))
                    carry = text[-4:]
                    truncated = out > STREAM_MAX_OUT
                truncated = truncated or raw > STREAM_MAX_RAW
    except Exception:
        return None
    return {"status": status, "head": head.decode("utf-8", "replace"), "urls": count, "truncated": truncated}


def _get(url: str, verify: bool = True, scope: tuple[str, ...] | None = None,
         max_bytes: int | None = None) -> dict | None:
    """Fetch a secondary URL (robots.txt, sitemap, REST API, theme stylesheet). None on any failure.
    With `scope`, the URL and every redirect must stay on the scanned site, so a scanned page can't
    point StackCheck's requests at someone else."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or (scope is not None and not in_scope(parts.hostname or "", scope)):
        return None
    try:
        return _fetch_once(url, verify, scope, max_bytes)
    except Exception:
        return None


# --------------------------------------------------------------------------- HTML extraction

ATTR_RE = re.compile(r"""([a-zA-Z_:][-\w:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")


def _attrs(tag: str) -> dict:
    return {m.group(1).lower(): (m.group(2) or m.group(3) or m.group(4) or "") for m in ATTR_RE.finditer(tag)}


def extract_html(html: str) -> dict:
    head = html[:600_000]
    meta: dict[str, list[str]] = {}
    for tag in re.findall(r"<meta\b[^>]*>", head, re.I):
        a = _attrs(tag)
        key = (a.get("name") or a.get("property") or a.get("http-equiv") or "").lower()
        if key and "content" in a:
            meta.setdefault(key, []).append(html_lib.unescape(a["content"]))  # e.g. several generators
    urls = []
    for tag in re.findall(r"<(?:script|link|iframe|img|source)\b[^>]*>", html, re.I):
        a = _attrs(tag)
        u = a.get("src") or a.get("href") or a.get("data-src")
        if u and not u.startswith("data:"):
            urls.append(u)
    title = re.search(r"<title[^>]*>(.*?)</title>", head, re.I | re.S)
    return {
        "meta": meta,
        "urls": list(dict.fromkeys(urls)),
        "title": html_lib.unescape(re.sub(r"\s+", " ", title.group(1))).strip()[:200] if title else None,
    }


# --------------------------------------------------------------------------- fingerprint engine

DEFAULT_CONF = {"headers": 100, "cookies": 85, "meta": 100, "scripts": 90, "html": 70,
                "dns": 95, "ptr": 80, "cert": 100, "url": 90, "scanner": 100}


class Fingerprints:
    def __init__(self, path: str):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.techs: dict[str, dict] = {}
        for name, t in data.items():
            if name.startswith("_"):
                continue
            c = re.compile
            self.techs[name] = {
                "cat": t.get("cat", "Miscellaneous"),
                "website": t.get("url"),
                "conf": t.get("conf"),
                "implies": t.get("implies", []),
                "headers": [(k.lower(), c(v, re.I)) for k, v in t.get("headers", {}).items()],
                "cookies": [(c("^" + k, re.I), c(v, re.I)) for k, v in t.get("cookies", {}).items()],
                "meta": [(c("^" + k + "$", re.I), c(v, re.I)) for k, v in t.get("meta", {}).items()],
                "scripts": [c(p, re.I) for p in t.get("scripts", [])],
                "html": [c(p, re.I) for p in t.get("html", [])],
                "ptr": [c(p, re.I) for p in t.get("ptr", [])],
                "cert": [c(p, re.I) for p in t.get("cert", [])],
                "url_re": [c(p, re.I) for p in t.get("url_re", [])],
                "dns": {k: [c(p, re.I) for p in v] for k, v in t.get("dns", {}).items()},
            }

    def analyze(self, signals: dict) -> list[dict]:
        found: dict[str, dict] = {}

        def hit(name, source, detail, m=None):
            t = self.techs[name]
            entry = found.setdefault(name, {"evidence": [], "version": None})
            conf = t["conf"] if t["conf"] is not None else DEFAULT_CONF[source]
            if len(entry["evidence"]) < 8:
                entry["evidence"].append({"source": source, "match": detail[:180], "confidence": conf})
            if m is not None and m.groups() and m.group(1) and not entry["version"]:
                entry["version"] = m.group(1).strip(".")

        headers = signals.get("headers", {})
        cookie_names = signals.get("cookie_names", [])
        meta = signals.get("meta", {})
        urls = signals.get("urls", [])
        html = signals.get("html", "")
        dns = signals.get("dns", {})

        for name, t in self.techs.items():
            for hname, rx in t["headers"]:
                if hname in headers and (m := rx.search(headers[hname])):
                    hit(name, "headers", f"{hname}: {headers[hname]}", m)
            for nrx, vrx in t["cookies"]:
                for cn in cookie_names:
                    if nrx.search(cn):
                        hit(name, "cookies", f"cookie {cn}")
                        break
            for krx, vrx in t["meta"]:
                for k, values in meta.items():
                    if krx.search(k):
                        for v in values:
                            if m := vrx.search(v):
                                hit(name, "meta", f'<meta name="{k}" content="{v}">', m)
            for rx in t["scripts"]:
                for u in urls:
                    if m := rx.search(u):
                        hit(name, "scripts", u, m)
                        break
            for rx in t["html"]:
                if m := rx.search(html):
                    s = max(0, m.start() - 30)
                    hit(name, "html", "…" + re.sub(r"\s+", " ", html[s:m.end() + 30]) + "…", m)
            for rtype, rxs in t["dns"].items():
                for rx in rxs:
                    for rec in dns.get(rtype, []):
                        if m := rx.search(rec):
                            hit(name, "dns", f"{rtype} {rec}", m)
                            break
            for rx in t["ptr"]:
                for ptr in signals.get("ptr", []):
                    if rx.search(ptr):
                        hit(name, "ptr", f"reverse DNS {ptr}")
                        break
            for rx in t["cert"]:
                for issuer in signals.get("cert_issuer", []):
                    if issuer and rx.search(issuer):
                        hit(name, "cert", f"certificate issuer: {issuer}")
                        break
            for rx in t["url_re"]:
                if rx.search(signals.get("final_url", "")):
                    hit(name, "url", signals["final_url"])

        for name, detail in signals.get("scanner", []):
            if name in self.techs:
                hit(name, "scanner", detail)

        # confidence: combine independent evidence  1 - Π(1 - c)
        for name, e in found.items():
            p = 1.0
            for ev in e["evidence"]:
                p *= 1 - ev["confidence"] / 100
            e["confidence"] = round((1 - p) * 100)

        # implied technologies
        changed = True
        while changed:
            changed = False
            for name in list(found):
                for imp in self.techs[name]["implies"]:
                    if imp in self.techs and imp not in found:
                        found[imp] = {"evidence": [{"source": "implied", "match": f"implied by {name}",
                                                    "confidence": 0}],
                                      "version": None,
                                      "confidence": min(80, round(found[name]["confidence"] * 0.8))}
                        changed = True

        out = []
        for name, e in found.items():
            t = self.techs[name]
            c = e["confidence"]
            out.append({
                "name": name, "category": t["cat"], "website": t["website"], "version": e["version"],
                "confidence": c, "level": "high" if c >= 85 else "medium" if c >= 60 else "low",
                "evidence": e["evidence"],
            })
        out.sort(key=lambda x: (x["category"], -x["confidence"], x["name"].lower()))
        return out


# --------------------------------------------------------------------------- WordPress themes & plugins

SMALL_FETCH = 512_000     # robots.txt and REST API responses
STYLE_FETCH = 256_000     # a theme's style.css; only the header comment at the top is read

WP_ASSET_RE = re.compile(r"/wp-content/(plugins|mu-plugins|themes)/([a-z0-9_.-]+)/([^\s\"'<>()\\]*)", re.I)
WP_VERSION_RE = re.compile(r"\d+(?:\.\d+)+[a-z0-9.-]*", re.I)
WP_THEME_HEADER_RE = re.compile(r"^[\s/*#@]*(Theme Name|Version|Template|Author|Theme URI)\s*:\s*(.+?)\s*$",
                                re.I | re.M)

# Plugins that often load no files on the front end but announce themselves in an HTML comment.
WP_COMMENT_PLUGINS = [
    ("wordpress-seo", re.compile(r"optimized with the Yoast SEO(?: Premium)? plugin v?([\d.]+)?", re.I)),
    ("seo-by-rank-math", re.compile(r"Search Engine Optimization by Rank Math", re.I)),
    ("all-in-one-seo-pack", re.compile(r"All in One SEO(?: Pro)? ([\d.]+)", re.I)),
    ("google-site-kit", re.compile(r"snippet added by Site Kit", re.I)),
    ("wp-rocket", re.compile(r"Performance optimized by WP Rocket", re.I)),
    ("litespeed-cache", re.compile(r"Page (?:optimized|cached|generated) by LiteSpeed Cache(?: ([\d.]+))?", re.I)),
    ("w3-total-cache", re.compile(r"Performance optimized by W3 Total Cache", re.I)),
    ("wp-super-cache", re.compile(r"generated by WP-Super-Cache", re.I)),
]

# Display names for popular slugs; anything else gets a title-cased slug.
WP_NAMES = {
    "wordpress-seo": "Yoast SEO", "seo-by-rank-math": "Rank Math SEO", "all-in-one-seo-pack": "All in One SEO",
    "google-site-kit": "Site Kit by Google", "wp-rocket": "WP Rocket", "litespeed-cache": "LiteSpeed Cache",
    "w3-total-cache": "W3 Total Cache", "wp-super-cache": "WP Super Cache", "woocommerce": "WooCommerce",
    "elementor": "Elementor", "elementor-pro": "Elementor Pro", "contact-form-7": "Contact Form 7",
    "wpforms-lite": "WPForms Lite", "wpforms": "WPForms", "gravityforms": "Gravity Forms", "jetpack": "Jetpack",
    "js_composer": "WPBakery Page Builder", "revslider": "Slider Revolution", "LayerSlider": "LayerSlider",
    "wp-smushit": "Smush", "autoptimize": "Autoptimize", "wordfence": "Wordfence", "akismet": "Akismet",
    "advanced-custom-fields": "Advanced Custom Fields", "advanced-custom-fields-pro": "ACF Pro",
    "beaver-builder-lite-version": "Beaver Builder", "bb-plugin": "Beaver Builder Pro",
    "divi-builder": "Divi Builder", "fusion-builder": "Avada Builder", "fusion-core": "Avada Core",
    "essential-addons-for-elementor-lite": "Essential Addons for Elementor",
    "header-footer-elementor": "Ultimate Addons for Elementor", "ultimate-addons-for-gutenberg": "Spectra",
    "premium-addons-for-elementor": "Premium Addons for Elementor", "elementskit-lite": "ElementsKit",
    "kadence-blocks": "Kadence Blocks", "generateblocks": "GenerateBlocks", "gp-premium": "GP Premium",
    "astra-addon": "Astra Pro", "cookie-law-info": "CookieYes", "complianz-gdpr": "Complianz",
    "cookie-notice": "Cookie Notice", "mailchimp-for-wp": "MC4WP: Mailchimp for WordPress",
    "wp-optimize": "WP-Optimize", "sg-cachepress": "SiteGround Speed Optimizer",
    "instagram-feed": "Smash Balloon Instagram Feed", "custom-facebook-feed": "Smash Balloon Facebook Feed",
    "the-events-calendar": "The Events Calendar", "bbpress": "bbPress", "buddypress": "BuddyPress",
    "tablepress": "TablePress", "polylang": "Polylang", "sitepress-multilingual-cms": "WPML",
    "translatepress-multilingual": "TranslatePress", "woocommerce-payments": "WooPayments",
    "woocommerce-gateway-stripe": "WooCommerce Stripe Gateway", "google-analytics-for-wordpress": "MonsterInsights",
    "duracelltomi-google-tag-manager": "GTM4WP", "insert-headers-and-footers": "WPCode",
    "ninja-forms": "Ninja Forms", "formidable": "Formidable Forms", "fluentform": "Fluent Forms",
    "popup-maker": "Popup Maker", "coblocks": "CoBlocks", "otter-blocks": "Otter Blocks",
    "stackable-ultimate-gutenberg-blocks": "Stackable", "really-simple-ssl": "Really Simple SSL",
    "wp-fastest-cache": "WP Fastest Cache", "siteorigin-panels": "Page Builder by SiteOrigin",
    "so-widgets-bundle": "SiteOrigin Widgets Bundle", "nextgen-gallery": "NextGEN Gallery",
    "add-to-any": "AddToAny Share Buttons", "co-authors-plus": "Co-Authors Plus", "elasticpress": "ElasticPress",
    "publish-to-apple-news": "Publish to Apple News", "wp-parsely": "Parse.ly", "jetpack-boost": "Jetpack Boost",
    "suremails": "SureMails", "surerank": "SureRank", "suretriggers": "SureTriggers", "ninja-tables": "Ninja Tables",
    "duplicate-post": "Yoast Duplicate Post", "two-factor": "Two-Factor", "code-snippets": "Code Snippets",
    "mailpoet": "MailPoet", "wp-mail-smtp": "WP Mail SMTP", "updraftplus": "UpdraftPlus",
    "better-wp-security": "Solid Security", "presto-player": "Presto Player", "spectra-pro": "Spectra Pro", "wp-google-maps": "WP Go Maps", "shortcodes-ultimate": "Shortcodes Ultimate",
}
_WP_WORDS = {"wp": "WP", "seo": "SEO", "woocommerce": "WooCommerce", "gdpr": "GDPR", "ssl": "SSL", "smtp": "SMTP",
             "ai": "AI", "css": "CSS", "js": "JS", "ui": "UI", "pro": "Pro", "cf7": "CF7", "edd": "EDD", "gp": "GP",
             "acf": "ACF", "generateblocks": "GenerateBlocks", "affiliatewp": "AffiliateWP", "sureforms": "SureForms",
             "surecart": "SureCart", "surecookie": "SureCookie", "thirstyaffiliates": "ThirstyAffiliates"}


def wp_name(slug: str) -> str:
    if slug in WP_NAMES:
        return WP_NAMES[slug]
    words = [w for w in re.split(r"[-_.]+", slug) if w]
    return " ".join(_WP_WORDS.get(w.lower(), w[:1].upper() + w[1:]) for w in words) or slug


def parse_theme_header(css: str) -> dict:
    """Read the comment block at the top of a theme's style.css (Theme Name, Version, Template, ...)."""
    out = {}
    for m in WP_THEME_HEADER_RE.finditer(css[:8192]):
        out.setdefault(m.group(1).lower(), m.group(2).strip()[:120])
    return out if "theme name" in out else {}


def wp_assets(html: str, urls: list[str], final_url: str, core_version: str | None = None) -> dict:
    """Themes and plugins referenced by the page, with versions and the evidence for each. No network."""
    text = html.replace("\\/", "/")  # paths inside inline JSON are often escaped
    found: dict[str, dict] = {"plugins": {}, "themes": {}}

    def entry(kind, slug):
        bucket = found["themes" if kind == "themes" else "plugins"]
        return bucket.setdefault(slug, {"slug": slug, "mu": kind == "mu-plugins", "versions": [],
                                        "evidence": [], "assets": 0})

    for m in WP_ASSET_RE.finditer(text):
        kind, slug, rest = m.group(1).lower(), m.group(2), html_lib.unescape(m.group(3))
        if slug in (".", ".."):
            continue
        e = entry(kind, slug)
        e["assets"] += 1
        ver = urllib.parse.parse_qs(urllib.parse.urlsplit(rest).query).get("ver", [""])[0]
        if WP_VERSION_RE.fullmatch(ver) and len(ver) <= 20:
            e["versions"].append(ver)
        sample = m.group(0)[:180]
        if len(e["evidence"]) < 3 and sample not in e["evidence"]:
            e["evidence"].append(sample)

    for slug, rx in WP_COMMENT_PLUGINS:
        if m := rx.search(text):
            e = entry("plugins", slug)
            if m.groups() and m.group(1):
                e["versions"].insert(0, m.group(1).strip("."))
            s = max(0, m.start() - 10)
            e["evidence"].insert(0, "…" + re.sub(r"\s+", " ", text[s:m.end() + 10]) + "…")

    def finish(e):
        # A ?ver= equal to the core version is WordPress's default, not the plugin's own version.
        vers = [v for v in e.pop("versions") if v != core_version]
        e["version"] = max(set(vers), key=vers.count) if vers else None
        e["name"] = wp_name(e["slug"])
        return e

    themes = [finish(e) for e in found["themes"].values()][:5]
    for t in themes:
        base = next((urllib.parse.urljoin(final_url, u) for u in urls if f"/wp-content/themes/{t['slug']}/" in u), None)
        base = base or urllib.parse.urljoin(final_url, f"/wp-content/themes/{t['slug']}/")
        t["stylesheet"] = base[:base.index(f"/themes/{t['slug']}/") + len(f"/themes/{t['slug']}/")] + "style.css"
    plugins = sorted((finish(e) for e in found["plugins"].values()), key=lambda p: p["name"].lower())[:80]
    return {"themes": themes, "plugins": plugins}


def _theme_header(url: str, verify: bool, scope: tuple[str, ...]) -> dict:
    r = _get(url, verify, scope, STYLE_FETCH)
    return parse_theme_header(r["html"]) if r and r["status"] == 200 else {}


def wordpress_details(http: dict, urls: list[str], core_version: str | None, scope: tuple[str, ...]) -> dict:
    wp = wp_assets(http["html"], urls, http["final_url"], core_version)
    themes = wp["themes"]

    def apply_headers(items):
        futs = [(t, _leaf_pool.submit(_theme_header, t["stylesheet"], http["verified"], scope)) for t in items]
        for t, f in futs:
            h = f.result()
            if h:
                t["name"] = h["theme name"]
                t["version"] = h.get("version") or t["version"]
                t["author"] = h.get("author")
                uri = h.get("theme uri") or ""
                t["uri"] = uri if re.match(r"https?://", uri, re.I) else None  # never javascript: and friends
                t["parent"] = h.get("template")
                t["evidence"].append(f"{t['stylesheet']} → Theme Name: {h['theme name']}")

    apply_headers(themes)
    # A child theme names its parent in "Template:"; add the parent if the page doesn't load it directly.
    slugs = {t["slug"] for t in themes}
    parents = []
    for t in list(themes):
        p = t.get("parent")
        if p and p not in slugs and re.fullmatch(r"[a-z0-9_.-]+", p, re.I):
            slugs.add(p)
            parents.append({"slug": p, "name": wp_name(p), "version": None, "mu": False, "assets": 0,
                            "evidence": [f"parent of child theme {t['slug']}"],
                            "stylesheet": t["stylesheet"].replace(f"/themes/{t['slug']}/", f"/themes/{p}/")})
    apply_headers(parents)
    themes += parents
    for t in themes:
        is_parent = any(o.get("parent") == t["slug"] for o in themes)
        t["role"] = "child theme" if t.get("parent") else "parent theme" if is_parent else "theme"
    themes.sort(key=lambda t: ["child theme", "theme", "parent theme"].index(t["role"]))
    return wp


# REST namespaces that belong to WordPress itself rather than a plugin.
WP_REST_CORE = {"oembed", "wp", "wp-site-health", "wp-block-editor", "wp-abilities", "batch"}
# Namespace (first segment) -> plugin slug, where the two differ or the namespace is generic.
WP_REST_PLUGINS = {
    "yoast": "wordpress-seo", "wc": "woocommerce", "wc-analytics": "woocommerce", "wc-admin": "woocommerce",
    "wc-telemetry": "woocommerce", "contact-form-7": "contact-form-7", "elementor": "elementor",
    "elementor-pro": "elementor-pro", "jetpack": "jetpack", "my-jetpack": "jetpack", "wpcom": "jetpack",
    "jetpack-boost": "jetpack-boost", "akismet": "akismet", "redirection": "redirection",
    "rankmath": "seo-by-rank-math", "aioseo": "all-in-one-seo-pack", "wordfence": "wordfence", "wpforms": "wpforms",
    "gf": "gravityforms", "litespeed": "litespeed-cache", "google-site-kit": "google-site-kit",
    "code-snippets": "code-snippets", "duplicate-post": "duplicate-post", "two-factor": "two-factor",
    "fluentform": "fluentform", "tribe": "the-events-calendar", "buddypress": "buddypress",
    "wp-parsely": "wp-parsely", "coauthors": "co-authors-plus", "apple-news": "publish-to-apple-news",
    "elasticpress": "elasticpress", "simple-page-ordering": "simple-page-ordering", "presto-player": "presto-player",
    "sureforms": "sureforms", "sureforms-pro": "sureforms-pro", "spectra": "ultimate-addons-for-gutenberg",
    "uag": "ultimate-addons-for-gutenberg", "spectra-pro": "spectra-pro", "surecookie": "surecookie",
    "suremails": "suremails", "sure-triggers": "suretriggers", "surerank": "surerank", "ninjatables": "ninja-tables",
    "astra-addon": "astra-addon", "wpml": "sitepress-multilingual-cms", "complianz": "complianz-gdpr",
    "mailpoet": "mailpoet", "wp-mail-smtp": "wp-mail-smtp", "monsterinsights": "google-analytics-for-wordpress",
    "updraftplus": "updraftplus", "wp-statistics": "wp-statistics", "ithemes-security": "better-wp-security",
    "solid-security": "better-wp-security", "generateblocks": "generateblocks", "kadence-blocks": "kadence-blocks",
    "ninja-forms": "ninja-forms", "formidable": "formidable", "wpcode": "insert-headers-and-footers",
    "complianz-gdpr": "complianz-gdpr", "cookieyes": "cookie-law-info", "tablepress": "tablepress",
    "wp-rocket": "wp-rocket", "sg-cachepress": "sg-cachepress", "siteground-optimizer": "sg-cachepress",
}
WP_REST_COUNTS = [("posts", "wp/v2/posts"), ("pages", "wp/v2/pages"), ("categories", "wp/v2/categories"),
                  ("tags", "wp/v2/tags"), ("users", "wp/v2/users")]


def wp_rest_root(http: dict, scope: tuple[str, ...] | None = None) -> str:
    """The REST API root the site advertises (Link header or <link rel>), else /wp-json/ on the final origin.
    An advertised root off the scanned site is ignored."""
    found = []
    m = re.search(r'<([^>]+)>\s*;\s*rel="https://api\.w\.org/"', http["headers"].get("link", ""))
    if m:
        found.append(m.group(1))
    for tag in re.findall(r"<link\b[^>]*>", http["html"][:600_000], re.I):
        a = _attrs(tag)
        if a.get("rel") == "https://api.w.org/" and a.get("href"):
            found.append(html_lib.unescape(a["href"]))
    for u in found:
        u = urllib.parse.urljoin(http["final_url"], u)
        parts = urllib.parse.urlsplit(u)
        if parts.scheme in ("http", "https") and (scope is None or in_scope(parts.hostname or "", scope)):
            return u
    return urllib.parse.urljoin(http["final_url"], "/wp-json/")


def wp_rest_url(root: str, route: str, **params) -> str:
    """Build a REST URL for both pretty (/wp-json/) and plain (?rest_route=/) permalinks."""
    if "rest_route=" in root:
        sp = urllib.parse.urlsplit(root)
        q = dict(urllib.parse.parse_qsl(sp.query))
        q["rest_route"] = "/" + route
        q.update(params)
        return urllib.parse.urlunsplit(sp._replace(query=urllib.parse.urlencode(q)))
    return root.rstrip("/") + "/" + route + ("?" + urllib.parse.urlencode(params) if params else "")


def wp_rest_info(http: dict, scope: tuple[str, ...]) -> dict:
    """What the public REST API reveals: status, site settings, namespaces and content counts.
    The users endpoint is only checked for being public and counted; usernames are never requested."""
    root = wp_rest_root(http, scope)
    fields = "name,description,timezone_string,gmt_offset,namespaces,authentication,show_on_front"
    urls = {"index": wp_rest_url(root, "", _fields=fields)}
    urls.update({key: wp_rest_url(root, route, per_page=1, _fields="id") for key, route in WP_REST_COUNTS})
    futs = {k: _leaf_pool.submit(_get, u, http["verified"], scope, SMALL_FETCH) for k, u in urls.items()}
    res = {k: f.result() for k, f in futs.items()}

    idx = res["index"]
    data = None
    if idx and idx["status"] == 200:
        try:
            data = json.loads(idx["html"])
        except ValueError:
            pass
    if isinstance(data, dict) and "namespaces" in data:
        status = "open"
    elif idx and idx["status"] in (401, 403):
        status = "restricted"
    elif idx:
        status = "unavailable"
    else:
        status = "unreachable"
    data = data if isinstance(data, dict) else {}

    counts = {}
    for key, _ in WP_REST_COUNTS:
        r = res[key]
        total = r and r["status"] == 200 and r["headers"].get("x-wp-total", "")
        if total and total.isdigit():
            counts[key] = int(total)
    users = res["users"]
    users_public = None if not users else users["status"] == 200 and users["html"].lstrip().startswith("[")

    return {
        "url": root, "status": status, "http_status": idx["status"] if idx else None,
        "name": html_lib.unescape(data.get("name") or "") or None,
        "description": html_lib.unescape(data.get("description") or "") or None,
        "timezone": data.get("timezone_string") or (f"UTC{data['gmt_offset']:+g}" if isinstance(
            data.get("gmt_offset"), (int, float)) else None),
        "show_on_front": data.get("show_on_front"),
        "namespaces": [n for n in data.get("namespaces", []) if isinstance(n, str)],
        "authentication": sorted(data.get("authentication") or {}) if isinstance(data.get("authentication"), dict) else [],
        "users_public": users_public,
        "counts": counts,
    }


def merge_rest_plugins(wp: dict) -> None:
    """Add plugins revealed only by REST namespaces; add the namespace as evidence to ones already found."""
    plugins = {p["slug"]: p for p in wp["plugins"]}
    theme_slugs = {t["slug"] for t in wp["themes"]}
    other = []
    for ns in wp["rest"]["namespaces"]:
        base = ns.split("/", 1)[0]
        if base in WP_REST_CORE:
            continue
        slug = WP_REST_PLUGINS.get(base) or (base if base in plugins else None)
        if not slug:
            if base not in theme_slugs and base not in other:
                other.append(base)
            continue
        p = plugins.get(slug)
        if not p:
            p = plugins[slug] = {"slug": slug, "name": wp_name(slug), "version": None, "mu": False, "assets": 0,
                                 "evidence": []}
        ev = f"REST API namespace {ns}"
        if not any(e.startswith("REST API namespace " + base) for e in p["evidence"]) and len(p["evidence"]) < 5:
            p["evidence"].append(ev)
    wp["plugins"] = sorted(plugins.values(), key=lambda p: p["name"].lower())
    wp["rest"]["other_namespaces"] = other


# --------------------------------------------------------------------------- sitemap

SITEMAP_GUESSES = ["/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml"]
SITEMAP_MAX_CHILDREN = 12
SITEMAP_GENERATORS = [
    ("Yoast SEO", re.compile(r"generated by Yoast|yoast", re.I)),
    ("Rank Math", re.compile(r"Rank ?Math", re.I)),
    ("All in One SEO", re.compile(r"aioseo|All in One SEO", re.I)),
    ("Jetpack", re.compile(r"jetpack", re.I)),
    ("WordPress", re.compile(r"wp-sitemap", re.I)),
]


def parse_sitemap(xml: str) -> dict:
    head = xml[:5000]
    kind = ("index" if re.search(r"<sitemapindex[\s>]", head, re.I)
            else "urlset" if re.search(r"<urlset[\s>]", head, re.I) else None)
    locs = [html_lib.unescape(x.strip()) for x in re.findall(r"<loc>\s*(.*?)\s*</loc>", xml, re.I | re.S)]
    return {"kind": kind, "locs": locs, "urls": len(re.findall(r"<url[\s>]", xml, re.I))}


def sitemap_type(url: str) -> str | None:
    """Content type from a child sitemap's file name: wp-sitemap-posts-post-1.xml, page-sitemap.xml, sitemap-page-1.xml."""
    name = urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1].lower()
    m = (re.match(r"wp-sitemap-(?:posts|taxonomies)-([a-z0-9_-]+?)-\d+\.xml$", name)
         or re.match(r"wp-sitemap-(users)-\d+\.xml$", name)
         or re.match(r"([a-z0-9_-]+?)[-_]sitemap(?:[-_]?\d+)?\.xml$", name))
    if not m and (m := re.match(r"sitemap[-_]([a-z0-9_-]+?)([-_]\d+)?\.xml$", name)):
        if m.group(1) == "page" and m.group(2):
            return None  # sitemap-page-3.xml is usually pagination, not WordPress pages
    t = m.group(1) if m else None
    if t:
        t = re.sub(r"^(?:post-type|taxonomy-type|taxonomy|posttype)-", "", t)  # SureRank-style names
    return None if not t or re.fullmatch(r"[\d_-]+", t) else t


def _count_sitemap(url: str, verify: bool, scope: tuple[str, ...]) -> dict:
    r = _stream_sitemap(url, verify, scope)
    ok = r and r["status"] == 200 and parse_sitemap(r["head"])["kind"] == "urlset"
    return {"url": url, "type": sitemap_type(url), "urls": r["urls"] if ok else None,
            "truncated": bool(ok and r["truncated"])}


def sitemap_info(final_url: str, verify: bool, scope: tuple[str, ...]) -> dict:
    origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(final_url))
    guesses = [origin + p for p in SITEMAP_GUESSES]
    f_robots = _leaf_pool.submit(_get, origin + "/robots.txt", verify, scope, SMALL_FETCH)
    f_guess = {u: _leaf_pool.submit(_get, u, verify, scope) for u in guesses}

    robots = f_robots.result()
    robots_ok = bool(robots and robots["status"] == 200
                     and "html" not in robots["headers"].get("content-type", "").lower())
    declared = []
    if robots_ok:
        declared = list(dict.fromkeys(re.findall(r"(?im)^\s*sitemap\s*:\s*(\S+)", robots["html"])))[:10]
    # Sitemaps on other sites are listed but never fetched: a scanned site mustn't steer our requests elsewhere.
    offsite = [u for u in declared if not in_scope(urllib.parse.urlsplit(u).hostname or "", scope)]

    out = {"found": False, "robots_txt": robots_ok, "declared": declared, "url": None, "source": None,
           "kind": None, "generator": None, "urls": None, "partial": False, "sitemaps": [], "children": 0,
           "by_type": {}, "offsite": len(offsite)}
    for url, source in [(u, "robots.txt") for u in declared if u not in offsite] + [(u, "guessed") for u in guesses]:
        r = f_guess[url].result() if url in f_guess else _get(url, verify, scope)
        if not r or r["status"] != 200:
            continue
        sm = parse_sitemap(r["html"])
        if not sm["kind"]:
            continue
        gen = next((name for name, rx in SITEMAP_GENERATORS if rx.search(r["html"][:20000]) or rx.search(url)), None)
        out.update(found=True, url=r["final_url"], source=source, kind=sm["kind"], generator=gen)
        if sm["kind"] == "urlset":
            out.update(urls=sm["urls"], partial=r["truncated"])
            if r["truncated"]:  # larger than one normal fetch: count it again by streaming
                c = _count_sitemap(r["final_url"], verify, scope)
                if c["urls"] is not None:
                    out.update(urls=c["urls"], partial=c["truncated"])
        else:
            locs = list(dict.fromkeys(sm["locs"]))
            children = [u for u in locs if in_scope(urllib.parse.urlsplit(u).hostname or "", scope)]
            out["offsite"] += len(locs) - len(children)
            counted = [f.result() for f in [_leaf_pool.submit(_count_sitemap, u, verify, scope)
                                            for u in children[:SITEMAP_MAX_CHILDREN]]]
            out["children"] = len(children)
            out["sitemaps"] = counted + [{"url": u, "type": sitemap_type(u), "urls": None, "truncated": False}
                                         for u in children[SITEMAP_MAX_CHILDREN:100]]
            out["urls"] = sum(c["urls"] or 0 for c in counted)
            out["partial"] = len(children) > len(counted) or any(c["truncated"] or c["urls"] is None for c in counted)
            for c in counted:
                if c["type"] and c["urls"] is not None:
                    out["by_type"][c["type"]] = out["by_type"].get(c["type"], 0) + c["urls"]
        break
    return out


def wp_content(rest: dict, sitemap: dict | None) -> dict:
    """Posts, pages, categories, tags and users: REST API totals first, sitemap URL counts as a fallback."""
    by_type = (sitemap or {}).get("by_type", {})
    aliases = {"posts": ["post"], "pages": ["page"], "categories": ["category"], "tags": ["post_tag", "tag"],
               "users": ["users", "author"]}
    out = {}
    for key, names in aliases.items():
        if key in rest["counts"]:
            out[key] = {"count": rest["counts"][key], "source": "REST API", "partial": False}
        elif any(n in by_type for n in names):
            # Only sitemaps that were actually counted contribute, so a capped index gives a lower bound.
            out[key] = {"count": sum(by_type.get(n, 0) for n in names), "source": "sitemap",
                        "partial": bool(sitemap.get("partial"))}
    return out


# --------------------------------------------------------------------------- bot protection / block pages

# Response headers that describe the page that was served. On a block page they describe the firewall's page,
# not the site, so they're left out of detection and the security-header check.
PAGE_HEADERS = {"content-security-policy", "content-security-policy-report-only", "x-frame-options",
                "x-content-type-options", "referrer-policy", "permissions-policy", "cross-origin-opener-policy",
                "cross-origin-embedder-policy", "cross-origin-resource-policy"}
BLOCK_TITLE_RE = re.compile(r"just a moment|attention required|access denied|verify (?:you are|you're) (?:a )?human|"
                            r"are you (?:a )?(?:robot|human)|captcha|ddos protection|security check|request blocked|"
                            r"you have been blocked|bot (?:check|verification)", re.I)


def detect_block(http: dict, title: str | None) -> dict | None:
    """Recognise a bot challenge or firewall block page served instead of the homepage.
    Returns {"by", "kind", "status", "evidence"} or None. StackCheck reports these; it never tries to get past them."""
    st, h, title = http["status"], http["headers"], title or ""
    html = http["html"][:200_000]
    server = h.get("server", "").lower()

    def found(by, kind, evidence):
        return {"by": by, "kind": kind, "status": st, "evidence": evidence[:200]}

    # Explicit headers: reliable whatever the status code.
    if h.get("cf-mitigated", "").lower() == "challenge":
        return found("Cloudflare", "challenge", "cf-mitigated: challenge")
    if h.get("x-vercel-mitigated"):
        return found("Vercel", "challenge", f"x-vercel-mitigated: {h['x-vercel-mitigated']}")
    if h.get("x-amzn-waf-action"):
        return found("AWS WAF", "challenge", f"x-amzn-waf-action: {h['x-amzn-waf-action']}")
    if h.get("x-sucuri-block"):
        return found("Sucuri", "block", f"x-sucuri-block: {h['x-sucuri-block']}")

    # Page signatures: only on error statuses, so a normal page that mentions these words isn't flagged.
    if st not in (401, 403, 405, 406, 429, 503):
        return None
    if "cloudflare" in server:
        if "/cdn-cgi/challenge-platform/" in html or title.lower().startswith("just a moment"):
            return found("Cloudflare", "challenge", f"title: {title}" if title else "Cloudflare challenge script")
        if "cf-error-details" in html or "attention required" in title.lower():
            return found("Cloudflare", "block", f"title: {title}" if title else "Cloudflare error page")
    if "_Incapsula_Resource" in html or "Incapsula incident ID" in html:
        return found("Imperva", "challenge" if "_Incapsula_Resource" in html else "block", "Incapsula page")
    if "sucuri" in server or "Sucuri WebSite Firewall" in html:
        return found("Sucuri", "block", f"server: {h.get('server', '')}")
    if "akamaighost" in server and ("access denied" in title.lower() or "errors.edgesuite.net" in html):
        return found("Akamai", "block", f"title: {title}")
    if h.get("x-datadome") or "captcha-delivery.com" in html:
        return found("DataDome", "challenge", "DataDome captcha")
    if "px-captcha" in html or "perimeterx" in html.lower():
        return found("HUMAN (PerimeterX)", "challenge", "PerimeterX captcha")
    if BLOCK_TITLE_RE.search(title):
        return found(None, "challenge" if re.search(r"moment|human|robot|captcha|check|verif", title, re.I)
                     else "block", f"title: {title}")
    if st == 429:
        return found(None, "rate limit", "HTTP 429 Too Many Requests")
    return None


# --------------------------------------------------------------------------- scan orchestration

SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS", "Forces HTTPS on future visits"),
    ("content-security-policy", "Content-Security-Policy", "Restricts where scripts/styles can load from"),
    ("x-frame-options", "X-Frame-Options", "Clickjacking protection"),
    ("x-content-type-options", "X-Content-Type-Options", "Stops MIME-type sniffing"),
    ("referrer-policy", "Referrer-Policy", "Controls referrer leakage"),
    ("permissions-policy", "Permissions-Policy", "Restricts powerful browser features"),
]

_pool = ThreadPoolExecutor(max_workers=32)
# Single-request tasks only. Tasks running on _pool may wait on these without risking a deadlock.
_leaf_pool = ThreadPoolExecutor(max_workers=32)


def find_zone(host: str) -> tuple[str, list[str]]:
    """Walk up the labels until we find a name with NS records (the DNS zone apex)."""
    labels = host.split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        ns = dns_query(name, "NS")["records"]
        if ns:
            return name, ns
    return host, []


def scan(domain: str) -> dict:
    t0 = time.monotonic()
    domain = normalize_domain(domain)
    assert_public(domain)
    errors: list[str] = []

    f_http = _pool.submit(http_fetch, domain)
    f_tls = _pool.submit(tls_probe, domain)
    f_zone = _pool.submit(find_zone, domain)
    f_a = _pool.submit(dns_query, domain, "A")
    f_aaaa = _pool.submit(dns_query, domain, "AAAA")
    f_cname = _pool.submit(dns_query, domain, "CNAME")

    zone, ns = f_zone.result()
    f_mx = _pool.submit(dns_query, zone, "MX")
    f_txt = _pool.submit(dns_query, zone, "TXT")
    f_caa = _pool.submit(dns_query, zone, "CAA")
    f_dmarc = _pool.submit(dns_query, "_dmarc." + zone, "TXT")
    f_www = _pool.submit(dns_query, "www." + zone, "CNAME") if domain == zone else None

    a = f_a.result()
    ips = a["records"]
    ptr_futs = {ip: _pool.submit(dns_query, reverse_name(ip), "PTR") for ip in ips[:3]}

    try:
        http = f_http.result()
    except ScanError as e:
        http = None
        errors.append(str(e))
    tls = f_tls.result()

    cnames = {}
    c = f_cname.result()["records"] or a["cname"]
    if c:
        cnames[domain] = c
    if f_www:
        w = f_www.result()["records"]
        if w:
            cnames["www." + zone] = w
    final_host = urllib.parse.urlsplit(http["final_url"]).hostname if http else None
    if final_host and final_host != domain and final_host not in cnames:
        fc = dns_query(final_host, "CNAME")["records"]
        if fc:
            cnames[final_host] = fc

    dns = {
        "zone": zone,
        "A": ips,
        "AAAA": f_aaaa.result()["records"],
        "CNAME": cnames,
        "NS": sorted(ns),
        "MX": sorted(f_mx.result()["records"], key=lambda r: int(r.split()[0]) if r.split()[0].isdigit() else 0),
        "TXT": f_txt.result()["records"],
        "CAA": f_caa.result()["records"],
        "DMARC": [r for r in f_dmarc.result()["records"] if r.lower().startswith("v=dmarc")],
        "PTR": {ip: f.result()["records"] for ip, f in ptr_futs.items()},
        "dnssec": bool(a.get("ad")),
    }

    # ---- signals for the fingerprint engine
    signals: dict = {
        "headers": http["headers"] if http else {},
        "cookie_names": [ck.split("=", 1)[0].strip() for ck in (http["cookies"] if http else [])],
        "html": http["html"] if http else "",
        "final_url": http["final_url"] if http else "",
        "dns": {
            "NS": dns["NS"],
            "MX": [m.split()[-1] for m in dns["MX"]],
            "TXT": dns["TXT"],
            "CAA": dns["CAA"],
            "DMARC": dns["DMARC"],
            "CNAME": [x for v in cnames.values() for x in v],
        },
        "ptr": [p for v in dns["PTR"].values() for p in v],
        "cert_issuer": [tls.get("issuer"), tls.get("issuer_org")],
        "scanner": [],
    }
    page = extract_html(signals["html"]) if http else {"meta": {}, "urls": [], "title": None}
    blocked = detect_block(http, page["title"]) if http else None
    if blocked:
        # The HTML and page headers belong to the firewall's page, so don't detect from them.
        # Server, CDN and cookie headers still describe the site's real edge and stay.
        page = {"meta": {}, "urls": [], "title": None}
        signals["html"] = ""
        signals["headers"] = {k: v for k, v in signals["headers"].items() if k not in PAGE_HEADERS}
    signals["meta"] = page["meta"]
    signals["urls"] = page["urls"]
    if tls.get("alpn") == "h2":
        signals["scanner"].append(("HTTP/2", "TLS ALPN negotiated h2"))
    if dns["dnssec"]:
        signals["scanner"].append(("DNSSEC", "resolver returned authenticated data (AD) flag"))

    techs = fingerprints().analyze(signals)

    scope = site_roots(domain, urllib.parse.urlsplit(http["final_url"]).hostname if http else None)
    f_sitemap = _pool.submit(sitemap_info, http["final_url"], http["verified"], scope) if http else None
    wordpress = None
    wp_tech = next((t for t in techs if t["name"] == "WordPress"), None)
    if http and not blocked and (wp_tech or "/wp-content/" in http["html"]):
        f_rest = _pool.submit(wp_rest_info, http, scope)
        wordpress = wordpress_details(http, page["urls"], wp_tech and wp_tech["version"], scope)
        wordpress["rest"] = f_rest.result()
        merge_rest_plugins(wordpress)
    sitemap = f_sitemap.result() if f_sitemap else None
    if wordpress:
        wordpress["content"] = wp_content(wordpress["rest"], sitemap)

    hdrs = http["headers"] if http else {}
    security = None if blocked else [{"header": label, "present": key in hdrs, "value": hdrs.get(key), "why": why}
                                     for key, label, why in SECURITY_HEADERS]

    result = {
        "domain": domain,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_ms": int((time.monotonic() - t0) * 1000),
        "summary": {
            "title": page["title"],
            "description": (page["meta"].get("description") or page["meta"].get("og:description") or [None])[0],
            "technologies": len(techs),
            "categories": len({t["category"] for t in techs}),
        },
        "technologies": techs,
        "blocked": blocked,
        "wordpress": wordpress,
        "sitemap": sitemap,
        "http": None if not http else {
            "url": http["url"], "final_url": http["final_url"], "status": http["status"],
            "response_ms": http["response_ms"], "redirects": http["redirects"],
            "https": http["final_url"].startswith("https://"),
            "server": hdrs.get("server"), "powered_by": hdrs.get("x-powered-by"),
            "headers": {k: v for k, v in hdrs.items() if k != "set-cookie"},
            "cookies": sorted(set(signals["cookie_names"])),
        },
        "tls": tls,
        "dns": dns,
        "security_headers": security,
        "errors": errors,
        "version": __version__,
    }
    if not http and not techs:
        raise ScanError(errors[0] if errors else f"Could not scan {domain}.", 502)
    return result


# --------------------------------------------------------------------------- cache & rate limit

class TTLCache:
    def __init__(self):
        self.data: dict[str, tuple[float, dict]] = {}
        self.lock = threading.Lock()
        self.key_locks: dict[str, threading.Lock] = {}

    def get(self, key):
        if Config.cache_ttl <= 0:
            return None
        with self.lock:
            v = self.data.get(key)
            if v and time.time() - v[0] < Config.cache_ttl:
                return v[1]
            self.data.pop(key, None)
        return None

    def age(self, key) -> float | None:
        """Seconds since `key` was cached, or None."""
        with self.lock:
            v = self.data.get(key)
            return time.time() - v[0] if v else None

    def put(self, key, value):
        if Config.cache_ttl <= 0:
            return
        with self.lock:
            if len(self.data) >= Config.cache_size:
                oldest = min(self.data, key=lambda k: self.data[k][0])
                self.data.pop(oldest, None)
            self.data[key] = (time.time(), value)

    def lock_for(self, key) -> threading.Lock:
        with self.lock:
            if len(self.key_locks) > 2000:
                self.key_locks.clear()
            return self.key_locks.setdefault(key, threading.Lock())


class RateLimiter:
    def __init__(self, limit=lambda: Config.rate_limit):
        self.limit = limit  # a callable, so tests and config changes take effect without rebuilding
        self.hits: dict[str, deque] = {}
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        limit = self.limit()
        if limit <= 0:
            return True
        now = time.time()
        with self.lock:
            q = self.hits.setdefault(key, deque())
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self.hits) > 10000:
                self.hits = {k: v for k, v in self.hits.items() if v and now - v[-1] < 60}
            return True


def site_key(domain: str) -> str:
    """Group subdomains under one site for the per-site limit: a.b.example.com -> example.com,
    shop.example.co.uk -> example.co.uk. A rough stand-in for the public suffix list."""
    labels = domain.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in ("co", "com", "net", "org", "gov", "ac", "edu"):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


CACHE = TTLCache()
LIMITER = RateLimiter()                                         # fresh scans per client IP
SITE_LIMITER = RateLimiter(lambda: Config.site_rate_limit)     # fresh scans per target site
_scan_slots: threading.BoundedSemaphore | None = None
_scan_slots_lock = threading.Lock()


def scan_slots() -> threading.BoundedSemaphore:
    global _scan_slots
    with _scan_slots_lock:
        if _scan_slots is None:
            _scan_slots = threading.BoundedSemaphore(max(1, Config.max_scans))
        return _scan_slots
_FP: Fingerprints | None = None


def fingerprints() -> Fingerprints:
    global _FP
    if _FP is None:
        _FP = Fingerprints(Config.fingerprints)
    return _FP


def cached_scan(domain: str, client_ip: str, refresh=False) -> dict:
    domain = normalize_domain(domain)
    if not refresh and (hit := CACHE.get(domain)):
        return {**hit, "cached": True}
    with CACHE.lock_for(domain):  # collapse concurrent scans of the same domain
        hit = CACHE.get(domain)
        age = CACHE.age(domain)
        if hit and (not refresh or (age is not None and age < Config.refresh_cooldown)):
            return {**hit, "cached": True}  # a rescan within the cooldown gets the fresh-enough report
        if not LIMITER.allow(client_ip):
            raise ScanError("Too many scans from your address. Please wait a minute.", 429)
        if not SITE_LIMITER.allow(site_key(domain)):
            raise ScanError(f"Too many scans of {site_key(domain)} right now. Please wait a minute.", 429)
        slots = scan_slots()
        if not slots.acquire(timeout=Config.timeout * 2):
            raise ScanError("StackCheck is busy with other scans. Please try again shortly.", 503)
        try:
            result = scan(domain)
        finally:
            slots.release()
        CACHE.put(domain, result)
        return {**result, "cached": False}


# --------------------------------------------------------------------------- web server

def load_static(name: str) -> bytes:
    with open(os.path.join(HERE, "static", name), "rb") as f:
        return f.read()


FAVICON = (b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" '
           b'fill="#4f46e5"/><g fill="#fff"><rect x="7" y="8" width="18" height="4" rx="1.5"/><rect x="7" '
           b'y="14" width="13" height="4" rx="1.5" opacity=".8"/><rect x="7" y="20" width="8" height="4" '
           b'rx="1.5" opacity=".6"/></g></svg>')


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def effective_allowed_hosts(bind: str, allowed: list[str]) -> set[str] | None:
    """Which Host header names the server answers. Checking it stops a web page in your browser from using
    DNS rebinding to read a StackCheck running on your machine. None means any name.

    STACKCHECK_ALLOWED_HOSTS wins ("*" for any). Otherwise a loopback-only server answers only localhost
    names, and a server listening on the network answers any name (with a warning at startup)."""
    if allowed:
        return None if "*" in allowed else {h.lower().rstrip(".") for h in allowed}
    if is_loopback(bind):
        return {"localhost", "127.0.0.1", "::1"}
    return None


def host_name(header: str) -> str:
    """'Example.com:8080' -> 'example.com', '[::1]:8080' -> '::1'."""
    h = (header or "").strip().lower()
    if h.startswith("["):
        return h[1:h.find("]")] if "]" in h else h
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def token_from(authorization: str) -> str:
    """The token from 'Bearer <token>' or HTTP Basic (any username, token as the password)."""
    kind, _, value = (authorization or "").partition(" ")
    if kind.lower() == "bearer":
        return value.strip()
    if kind.lower() == "basic":
        try:
            return base64.b64decode(value.strip(), validate=True).decode("utf-8").partition(":")[2]
        except (ValueError, UnicodeDecodeError):
            return ""
    return ""


class Handler(BaseHTTPRequestHandler):
    server_version = "StackCheck/" + __version__
    protocol_version = "HTTP/1.1"
    timeout = Config.client_timeout  # a client that sends its request too slowly is dropped

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[{self.log_date_time_string()}] {self.client_ip()} {fmt % args}\n")

    def client_ip(self) -> str:
        if Config.trust_proxy:
            # The right-most entry is the one our own proxy added; anything to its left came from the
            # client and can be forged.
            xff = [x.strip() for x in self.headers.get("X-Forwarded-For", "").split(",") if x.strip()]
            if xff:
                return xff[-1]
        return self.client_address[0]

    def cors_headers(self) -> dict:
        origin = self.headers.get("Origin", "")
        if "*" in Config.cors:
            return {"Access-Control-Allow-Origin": "*"}
        if origin and origin in Config.cors:
            return {"Access-Control-Allow-Origin": origin, "Vary": "Origin"}
        return {}

    def guard(self, path: str) -> bool:
        """Host allowlist and optional token. Sends the refusal and returns False when the request is refused.
        /healthz is exempt from both so container and load-balancer health checks work; it reveals only the version."""
        if path == "/healthz":
            return True
        if Config.hosts is not None and host_name(self.headers.get("Host", "")) not in Config.hosts:
            self.send(421, b"This StackCheck does not answer for that host name. "
                           b"Set STACKCHECK_ALLOWED_HOSTS to allow it.\n", "text/plain; charset=utf-8")
            return False
        if Config.token:
            supplied = token_from(self.headers.get("Authorization", ""))
            if not hmac.compare_digest(supplied.encode(), Config.token.encode()):
                self.send(401, b"This StackCheck needs a token.\n", "text/plain; charset=utf-8",
                          {"WWW-Authenticate": 'Basic realm="StackCheck", charset="UTF-8"'})
                return False
        return True

    def send(self, status, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if ctype.startswith("text/html"):
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                             "img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; "
                             "frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, status, obj):
        body = json.dumps(obj, indent=2, ensure_ascii=False).encode()
        self.send(status, body, "application/json; charset=utf-8", {"Cache-Control": "no-store", **self.cors_headers()})

    def wants_json(self, query) -> bool:
        if query.get("format", [""])[0] == "json":
            return True
        if query.get("format", [""])[0] == "html":
            return False
        return "text/html" not in self.headers.get("Accept", "")

    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):  # CORS preflight, e.g. for API calls that send an Authorization header
        cors = self.cors_headers()
        if not cors or Config.hosts is not None and host_name(self.headers.get("Host", "")) not in Config.hosts:
            return self.send(403, b"", "text/plain")
        self.send(204, b"", "text/plain", {**cors, "Access-Control-Allow-Methods": "GET, HEAD",
                                            "Access-Control-Allow-Headers": "Authorization",
                                            "Access-Control-Max-Age": "600"})

    def do_GET(self):
        parts = urllib.parse.urlsplit(self.path)
        path = parts.path
        query = urllib.parse.parse_qs(parts.query)
        if not self.guard(path):
            return
        try:
            if path == "/" and "d" in query:
                target = normalize_domain(query["d"][0])
                return self.send(302, b"", "text/plain", {"Location": "/" + target})
            if path in ("/", "/index.html"):
                return self.send(200, load_static("index.html"), "text/html; charset=utf-8")
            if path == "/app.js":
                return self.send(200, load_static("app.js"), "text/javascript; charset=utf-8")
            if path in ("/favicon.ico", "/favicon.svg"):
                return self.send(200, FAVICON, "image/svg+xml", {"Cache-Control": "max-age=86400"})
            if path == "/healthz":
                return self.send_json(200, {"ok": True, "version": __version__})
            if path == "/robots.txt":
                return self.send(200, b"User-agent: *\nDisallow: /api/\n", "text/plain")
            if path.startswith("/api/"):
                domain = path[len("/api/"):]
                result = cached_scan(domain, self.client_ip(), refresh="refresh" in query)
                return self.send_json(200, result)

            # /<domain>  (also /https://example.com/anything)
            raw = path.lstrip("/")
            if raw.endswith(".json"):
                raw, query["format"] = raw[:-5], ["json"]
            domain = normalize_domain(raw)
            if self.wants_json(query):
                return self.send_json(200, cached_scan(domain, self.client_ip(), refresh="refresh" in query))
            if raw != domain:  # canonical URL
                return self.send(302, b"", "text/plain", {"Location": "/" + domain})
            return self.send(200, load_static("index.html"), "text/html; charset=utf-8")
        except ScanError as e:
            if path.startswith("/api/") or self.wants_json(query):
                return self.send_json(e.status, {"error": str(e)})
            return self.send(e.status, load_static("index.html"), "text/html; charset=utf-8")
        except Exception as e:  # pragma: no cover
            self.log_message("error: %r", e)
            return self.send_json(500, {"error": "Internal error while scanning."})


class Server(ThreadingHTTPServer):
    """ThreadingHTTPServer with a cap on open connections; past it, new ones get a 503 straight away."""
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.slots = threading.BoundedSemaphore(max(1, Config.max_connections))

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


# --------------------------------------------------------------------------- CLI

def format_report(r: dict) -> str:
    """A plain-text summary of a scan for the terminal. The JSON (--json) has everything."""
    out: list[str] = []
    add = out.append
    http, tls, dns = r.get("http") or {}, r.get("tls") or {}, r.get("dns") or {}
    title = (r.get("summary") or {}).get("title")
    add(r["domain"] + (f"  -  {title}" if title else ""))
    facts = [http.get("final_url") or "no HTTP response"]
    if http.get("status") is not None:
        facts.append(f"HTTP {http['status']}")
    if tls.get("protocol"):
        cert = (f"certificate valid, {tls['days_left']} days left" if tls.get("valid") and tls.get("days_left") is not None
                else "certificate valid" if tls.get("valid") else f"certificate problem: {tls.get('error', 'unknown')}")
        facts.append(f"{tls['protocol'].replace('TLSv', 'TLS ')}, {cert}")
    facts.append(f"scanned in {r.get('duration_ms', 0) / 1000:.1f} s")
    add("  ".join(f"{f}  ·" for f in facts[:-1]) + "  " + facts[-1])

    b = r.get("blocked")
    if b:
        add("")
        add(f"! Blocked by {b['by'] or 'the site firewall'} ({b['kind']}, HTTP {b['status']}). Page-based results are "
            "missing; DNS, TLS, hosting and CDN results are reliable.")

    techs = r.get("technologies") or []
    add("")
    add(f"Technologies ({len(techs)})")
    if not techs:
        add("  none detected")
    width = max([len(t["category"]) for t in techs] + [10])
    for t in sorted(techs, key=lambda t: (t["category"], -t["confidence"], t["name"].lower())):
        name = t["name"] + (f" {t['version']}" if t.get("version") else "")
        low = "  (low confidence)" if t["level"] == "low" else ""
        add(f"  {t['category']:<{width}}  {name:<34} {t['confidence']:>3}%{low}")

    wp = r.get("wordpress")
    if wp:
        add("")
        add("WordPress")
        themes = wp.get("themes", [])
        by_slug = {t["slug"]: t["name"] for t in themes}
        for t in themes:
            ver = f" {t['version']}" if t.get("version") else ""
            role = (f" (child of {by_slug.get(t['parent'], t['parent'])})" if t.get("parent")
                    else " (parent theme)" if t.get("role") == "parent theme" else "")
            add(f"  Theme     {t['name']}{ver}{role}")
        plugins = wp.get("plugins", [])
        names = ", ".join(p["name"] + (f" {p['version']}" if p.get("version") else "") for p in plugins)
        add(textwrap.fill(f"{len(plugins)}" + (f": {names}" if names else ""), width=100,
                          initial_indent="  Plugins   ", subsequent_indent=" " * 12))
        rest = wp.get("rest") or {}
        content = wp.get("content") or {}
        from_sitemap = {c["source"] for c in content.values()} == {"sitemap"}
        counts = ", ".join(f"{c['count']:,}{'+' if c['partial'] else ''} {k}"
                           + (" (sitemap)" if c["source"] == "sitemap" and not from_sitemap else "")
                           for k, c in content.items())
        if counts and from_sitemap:
            counts += " (counted from the sitemap)"
        add(f"  REST API  {rest.get('status', 'unknown')}")
        if counts:
            add(f"  Content   {counts}")
        if rest.get("users_public"):
            add("  Users     the user list is public (usernames exposed)")

    sm = r.get("sitemap")
    if sm is not None:
        add("")
        if sm.get("found"):
            n = f"{'at least ' if sm.get('partial') else ''}{(sm.get('urls') or 0):,} URLs"
            add(f"Sitemap     {sm['url']}  ({'listed in robots.txt' if sm.get('source') == 'robots.txt' else 'common path'}, {n})")
        else:
            add(f"Sitemap     not found{' (robots.txt exists)' if sm.get('robots_txt') else ''}")

    add(f"DNS         NS {', '.join(dns.get('NS') or ['-'])}")
    if dns.get("MX"):
        add(f"            MX {', '.join(dns['MX'][:3])}{' ...' if len(dns['MX']) > 3 else ''}")
    sec = r.get("security_headers")
    if sec is not None:
        missing = [h["header"] for h in sec if not h["present"]]
        add(f"Security    {len(sec) - len(missing)}/{len(sec)} security headers"
            + (f" (missing: {', '.join(missing)})" if missing else ""))
    for e in r.get("errors") or []:
        add(f"! {e}")
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(description="StackCheck - self-hosted website technology scanner")
    p.add_argument("command", nargs="?", default="serve", choices=["serve", "scan"])
    p.add_argument("domain", nargs="?")
    p.add_argument("--host", default=Config.host)
    p.add_argument("--port", type=int, default=Config.port)
    p.add_argument("--allow-private", action="store_true", default=Config.allow_private,
                   help="allow scanning hosts on private networks (only for trusted, local use)")
    p.add_argument("--trust-proxy", action="store_true", default=Config.trust_proxy,
                   help="use X-Forwarded-For for rate limiting (when behind nginx/Caddy/etc.)")
    p.add_argument("--json", action="store_true",
                   help="scan: print the full JSON report (the default when output is piped)")
    a = p.parse_args(argv)
    Config.allow_private, Config.trust_proxy = a.allow_private, a.trust_proxy
    fp = fingerprints()

    if a.command == "scan":
        if not a.domain:
            p.error("scan needs a domain, e.g.  stackcheck.py scan example.com")
        try:
            result = scan(a.domain)
        except ScanError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        # Scripts piping the output keep getting JSON; a person at a terminal gets a summary.
        if a.json or not sys.stdout.isatty():
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(format_report(result))
        return 0

    if Config.allow_private and not is_loopback(a.host) and not Config.token:
        p.error("--allow-private on a network address would let anyone who can reach this server scan your "
                "internal network. Listen on 127.0.0.1, or set STACKCHECK_TOKEN as well.")
    Config.hosts = effective_allowed_hosts(a.host, Config.allowed_hosts)
    if Config.hosts is None and not Config.allowed_hosts:
        print("warning: listening on a network address and answering any host name. Set "
              "STACKCHECK_ALLOWED_HOSTS to the name(s) you serve it on.", file=sys.stderr)
    if not is_loopback(a.host) and not Config.token:
        print("warning: no STACKCHECK_TOKEN set, so anyone who can reach this server can run scans "
              "from it.", file=sys.stderr)

    srv = Server((a.host, a.port), Handler)
    shown = "localhost" if a.host in ("0.0.0.0", "::") else a.host
    print(f"StackCheck {__version__} - {len(fp.techs)} fingerprints loaded")
    print(f"Listening on http://{shown}:{a.port}   try  http://{shown}:{a.port}/github.com")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    return 0


if __name__ == "__main__":
    sys.exit(main())
