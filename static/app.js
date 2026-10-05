(() => {
const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
// Links built from scanned data must be http(s); a javascript: URL in an href would run on click.
const safeUrl = u => /^https?:\/\//i.test(String(u ?? "")) ? String(u) : null;
const show = id => ["home","loading","error","report"].forEach(s => $("#" + s).hidden = s !== id);

const PALETTE = ["#4f46e5","#0891b2","#059669","#d97706","#dc2626","#7c3aed","#db2777","#2563eb","#65a30d","#ea580c","#0d9488","#9333ea"];
const colorFor = s => { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) >>> 0; return PALETTE[h % PALETTE.length]; };
const initials = s => s.replace(/[^A-Za-z0-9 .]/g, "").split(/[\s.]+/).filter(Boolean).slice(0, 2).map(w => w[0]).join("").toUpperCase() || "?";

const CAT_ORDER = ["Hosting","CDN","Web Server","Operating System","Caching","CMS","Ecommerce","Headless CMS","Page Builder","Static Site Generator",
  "JavaScript Framework","Framework","Language","Database","JavaScript Library","UI Framework","Build Tool","Font","Analytics","Tag Manager","Monitoring",
  "Marketing Pixel","Advertising","Marketing Automation","Email Marketing","Payment","Live Chat","A/B Testing","Feature Flags","Cookie Consent","SEO",
  "Search","Media","Video","Maps","Forms","Scheduling","Comments","Social","Reviews","WordPress Plugin","DNS","Email Hosting","Email Delivery",
  "Email Security","SSL Certificate","Security","Protocol","SaaS","Miscellaneous"];
const catRank = c => { const i = CAT_ORDER.indexOf(c); return i < 0 ? 99 : i; };

// ---------- routing
const host = location.host;
$("#hostPrefix").textContent = host + "/";
$("#urlHint").textContent = host + "/example.com";

function go(raw) {
  let d = String(raw || "").trim().replace(/^[a-z]+:\/\//i, "").split(/[/?#]/)[0].toLowerCase();
  if (d) location.href = "/" + encodeURIComponent(d).replace(/%2E/gi, ".");
}
for (const f of [$("#homeSearch"), $("#topSearch")]) f.addEventListener("submit", e => { e.preventDefault(); go(f.d.value); });

const target = decodeURIComponent(location.pathname.slice(1)).replace(/\/+$/, "");
if (!target) { show("home"); document.title = "StackCheck · What is that website built with?"; }
else run(target, new URLSearchParams(location.search).has("refresh"));

// ---------- scan
async function run(domain, refresh) {
  $("#topSearch").hidden = false;
  $("#topSearch").d.value = domain;
  $("#loadingDomain").textContent = domain;
  document.title = domain + " · StackCheck";
  show("loading");
  const msgs = ["Resolving DNS…","Fetching the homepage…","Inspecting TLS certificate…","Matching fingerprints…","Checking mail & DNS providers…","Almost there…"];
  let i = 0; const timer = setInterval(() => $("#steps").textContent = msgs[Math.min(++i, msgs.length - 1)], 1100);
  try {
    const r = await fetch("/api/" + encodeURIComponent(domain) + (refresh ? "?refresh=1" : ""), {headers: {Accept: "application/json"}});
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
    render(data);
    if (refresh) history.replaceState(null, "", "/" + data.domain);
  } catch (e) {
    $("#errorMsg").textContent = e.message;
    show("error");
  } finally { clearInterval(timer); }
}

// ---------- render
function render(d) {
  const techs = d.technologies || [];
  const http = d.http || {}; const tls = d.tls || {}; const dns = d.dns || {};
  document.title = d.domain + " · StackCheck";
  const secCount = (d.security_headers || []).filter(h => h.present).length;
  const days = tls.days_left;
  const wp = d.wordpress;
  const tabs = [
    ["Technologies", techPanel(techs)],
    ...(wp ? [[`WordPress <span class="badge">${wp.themes.length + wp.plugins.length}</span>`, wpPanel(wp)]] : []),
    ["Infrastructure", infraPanel(d)],
    ["Security", securityPanel(d)],
    ["Headers", headersPanel(http)],
    ["Raw JSON", `<pre class="raw">${esc(JSON.stringify(d, null, 2))}</pre>`],
  ];

  $("#report").innerHTML = `
    <div class="site">
      <div class="avatar" style="background:${colorFor(d.domain)}">${esc(d.domain[0].toUpperCase())}</div>
      <div style="min-width:0;flex:1">
        <h2>${esc(d.domain)}</h2>
        <div class="title">${esc(d.summary?.title || "")}</div>
      </div>
      <div class="actions">
        <a class="btn" href="${esc(safeUrl(http.final_url) || "https://" + d.domain)}" target="_blank" rel="noopener noreferrer">Visit ↗</a>
        <a class="btn" href="/${esc(d.domain)}?refresh=1">Rescan</a>
        <a class="btn" href="/${esc(d.domain)}.json" target="_blank">JSON</a>
      </div>
    </div>
    ${blockedBanner(d.blocked)}
    <div class="stats">
      ${stat("Technologies", techs.length)}
      ${stat("HTTP status", http.status ?? "–")}
      ${stat("Response", http.response_ms != null ? http.response_ms + " ms" : "–")}
      ${stat("TLS", tls.protocol ? tls.protocol.replace("TLSv", "TLS ") : "none")}
      ${stat("Cert expires", days != null ? days + " days" : "–")}
      ${stat("Security headers", d.security_headers ? secCount + " / " + d.security_headers.length : "–")}
      ${wp ? stat("WP plugins", wp.plugins.length) : ""}
    </div>
    <div class="tabs" role="tablist">
      ${tabs.map(([t], i) =>
        `<button class="tab" role="tab" data-tab="${i}" aria-selected="${i === 0}">${t}</button>`).join("")}
    </div>
    ${tabs.map(([, html], i) => `<div data-panel="${i}"${i ? " hidden" : ""}>${html}</div>`).join("")}
    <p class="note">Scanned ${esc(new Date(d.scanned_at).toLocaleString())} in ${d.duration_ms} ms${d.cached ? ' <span class="badge">cached</span>' : ""}.
      ${(d.errors || []).map(e => `<br>⚠ ${esc(e)}`).join("")}</p>`;
  show("report");

  $("#report").querySelectorAll(".tab").forEach(b => b.addEventListener("click", () => {
    $("#report").querySelectorAll(".tab").forEach(x => x.setAttribute("aria-selected", x === b));
    $("#report").querySelectorAll("[data-panel]").forEach(p => p.hidden = p.dataset.panel !== b.dataset.tab);
  }));
  const q = $("#techFilter"), hideLow = $("#hideLow");
  const apply = () => {
    const term = q.value.trim().toLowerCase();
    const panel = $('#report [data-panel="0"]');
    panel.querySelectorAll(".tech").forEach(t => {
      const match = !term || t.dataset.search.includes(term);
      t.hidden = !match || (hideLow.checked && t.dataset.level === "low");
    });
    panel.querySelectorAll(".cat").forEach(c => c.hidden = ![...c.querySelectorAll(".tech")].some(t => !t.hidden));
  };
  q?.addEventListener("input", apply); hideLow?.addEventListener("change", apply);
}

const stat = (k, v) => `<div class="stat"><div class="k">${esc(k)}</div><div class="v" title="${esc(v)}">${esc(v)}</div></div>`;

function techPanel(techs) {
  if (!techs.length) return `<div class="panel">No technologies detected. The site may block automated requests or render everything client-side.</div>`;
  const groups = {};
  for (const t of techs) (groups[t.category] ||= []).push(t);
  const cats = Object.keys(groups).sort((a, b) => catRank(a) - catRank(b) || a.localeCompare(b));
  return `
    <div class="filter">
      <input id="techFilter" placeholder="Filter technologies…" aria-label="Filter technologies">
      <label><input type="checkbox" id="hideLow"> Hide low confidence</label>
    </div>
    <div class="cats">${cats.map(c => `
      <div class="cat"><h3><span>${esc(c)}</span><span>${groups[c].length}</span></h3>
        ${groups[c].sort((a, b) => b.confidence - a.confidence).map(techRow).join("")}
      </div>`).join("")}
    </div>`;
}

function techRow(t) {
  return `<details class="tech" data-level="${t.level}" data-search="${esc((t.name + " " + t.category).toLowerCase())}">
    <summary>
      <span class="ico" style="background:${colorFor(t.name)}">${esc(initials(t.name))}</span>
      <span class="tname">${esc(t.name)}</span>
      ${t.version ? `<span class="ver">${esc(t.version)}</span>` : ""}
      <span class="conf ${t.level}" title="Confidence">${t.confidence}%</span>
      <svg class="chev" width="14" height="14" viewBox="0 0 16 16"><path d="M6 3l5 5-5 5" fill="none" stroke="currentColor" stroke-width="2"/></svg>
    </summary>
    <div class="evidence">
      ${t.evidence.map(e => `<div class="row"><span class="src">${esc(e.source)}</span><code>${esc(e.match)}</code></div>`).join("")}
      ${safeUrl(t.website) ? `<a class="site-link" href="${esc(t.website)}" target="_blank" rel="noopener noreferrer">${esc(t.website.replace(/^https?:\/\/(www\.)?/, "").replace(/\/$/, ""))} ↗</a>` : ""}
    </div>
  </details>`;
}

function wpPanel(wp) {
  const row = (x, kind) => {
    const tag = kind === "themes" ? x.role : x.mu ? "must-use" : "";
    const wporg = `https://wordpress.org/${kind}/${encodeURIComponent(x.slug)}/`;
    return `<details class="tech wp">
      <summary>
        <span class="ico" style="background:${colorFor(x.slug)}">${esc(initials(x.name))}</span>
        <span class="tname">${esc(x.name)}</span>
        ${x.version ? `<span class="ver">${esc(x.version)}</span>` : ""}
        ${tag ? `<span class="badge">${esc(tag)}</span>` : ""}
        <span class="slug">${esc(x.slug)}</span>
        <svg class="chev" width="14" height="14" viewBox="0 0 16 16"><path d="M6 3l5 5-5 5" fill="none" stroke="currentColor" stroke-width="2"/></svg>
      </summary>
      <div class="evidence">
        ${x.author ? `<div class="row"><span class="src">author</span><code>${esc(x.author)}</code></div>` : ""}
        ${x.assets ? `<div class="row"><span class="src">files</span><code>${x.assets} reference${x.assets === 1 ? "" : "s"} on the homepage</code></div>` : ""}
        ${x.evidence.map(e => `<div class="row"><span class="src">seen</span><code>${esc(e)}</code></div>`).join("")}
        <a class="site-link" href="${esc(wporg)}" target="_blank" rel="noopener noreferrer">wordpress.org/${kind}/${esc(x.slug)} ↗</a>
        ${safeUrl(x.uri) ? ` · <a class="site-link" href="${esc(x.uri)}" target="_blank" rel="noopener noreferrer">${esc(x.uri.replace(/^https?:\/\/(www\.)?/, "").replace(/\/$/, ""))} ↗</a>` : ""}
      </div>
    </details>`;
  };
  const rest = wp.rest || {};
  const LABEL = {posts: "Posts", pages: "Pages", categories: "Categories", tags: "Tags", users: "Users"};
  const content = Object.entries(wp.content || {});
  const contentPanel = `<div class="panel"><h3>Content</h3>${content.length
    ? `<dl class="kv">${content.map(([k, c]) => `<dt>${esc(LABEL[k] || k)}</dt>
        <dd><b>${c.partial ? "≥ " : ""}${c.count.toLocaleString()}</b> <span class="badge">${esc(c.source)}</span></dd>`).join("")}</dl>`
    : `<div style="color:var(--muted);font-size:14px">Not available: the REST API is ${esc(rest.status || "unreachable")} and no sitemap lists posts or pages.</div>`}</div>`;
  const STATUS = {open: ["ok", "Open"], restricted: ["no", "Restricted to logged-in users"],
                  unavailable: ["no", "Disabled or not found"], unreachable: ["no", "Unreachable"]};
  const [cls, label] = STATUS[rest.status] || ["no", rest.status || "–"];
  const users = rest.users_public == null ? "–" : rest.users_public
    ? `<span style="color:var(--bad)">Public${rest.counts?.users != null ? `: ${rest.counts.users.toLocaleString()} user${rest.counts.users === 1 ? "" : "s"}` : ""} (usernames exposed)</span>`
    : `<span style="color:var(--good)">Not public</span>`;
  const front = {posts: "Latest posts", page: "Static page"}[rest.show_on_front];
  const restPanel = `<div class="panel"><h3>REST API</h3><dl class="kv">
      <dt>Status</dt><dd><span style="color:var(--${cls === "ok" ? "good" : "bad"})">${esc(label)}</span>${rest.http_status ? ` <span class="badge">HTTP ${rest.http_status}</span>` : ""}</dd>
      <dt>Endpoint</dt><dd>${lines([rest.url])}</dd>
      ${rest.name ? `<dt>Site name</dt><dd>${lines([rest.name])}</dd>` : ""}
      ${rest.description ? `<dt>Tagline</dt><dd>${lines([rest.description])}</dd>` : ""}
      ${rest.timezone ? `<dt>Timezone</dt><dd>${lines([rest.timezone])}</dd>` : ""}
      ${front ? `<dt>Front page</dt><dd>${lines([front])}</dd>` : ""}
      ${(rest.authentication || []).length ? `<dt>Auth</dt><dd>${lines(rest.authentication)}</dd>` : ""}
      <dt>User list</dt><dd>${users}</dd>
      ${(rest.other_namespaces || []).length ? `<dt>Other APIs</dt><dd>${esc(rest.other_namespaces.join(", "))}</dd>` : ""}
    </dl></div>`;
  const group = (title, items, kind, empty) => `<div class="cat"><h3><span>${title}</span><span>${items.length}</span></h3>
    ${items.length ? items.map(x => row(x, kind)).join("") : `<div class="tech" style="padding:10px 14px;color:var(--muted)">${empty}</div>`}</div>`;
  return `<div class="grid2" style="margin-bottom:14px">${contentPanel}${restPanel}</div>
    <div class="cats">
      ${group("Theme", wp.themes, "themes", "No theme files referenced on the homepage.")}
      ${group("Plugins", wp.plugins, "plugins", "No plugin files referenced on the homepage.")}
    </div>
    <p class="note">Plugins come from files and markers on the homepage, plus the namespaces the public REST API lists.
      Plugins that work only in the admin, on other pages, or are bundled into a combined file won't show up.
      Versions come from <code>?ver=</code> on asset URLs and the theme's <code>style.css</code>, so treat them as a guide.
      A wordpress.org link 404s for premium or custom plugins.</p>`;
}

const lines = arr => (arr && arr.length) ? arr.map(x => `<div>${esc(x)}</div>`).join("") : `<span style="color:var(--muted)">–</span>`;

function infraPanel(d) {
  const dns = d.dns || {}, tls = d.tls || {}, http = d.http || {};
  const ptr = Object.entries(dns.PTR || {}).map(([ip, n]) => `${ip} → ${n.join(", ") || "no PTR"}`);
  const cname = Object.entries(dns.CNAME || {}).map(([h, v]) => `${h} → ${v.join(", ")}`);
  const redirects = (http.redirects || []).map(r => `${r.status} → ${r.to}`);
  return `<div class="grid2">
    <div class="panel"><h3>Server</h3><dl class="kv">
      <dt>Final URL</dt><dd>${lines([http.final_url])}</dd>
      <dt>Redirects</dt><dd>${lines(redirects)}</dd>
      <dt>Server</dt><dd>${lines(http.server ? [http.server] : [])}</dd>
      <dt>Powered by</dt><dd>${lines(http.powered_by ? [http.powered_by] : [])}</dd>
      <dt>IPv4</dt><dd>${lines(dns.A)}</dd>
      <dt>IPv6</dt><dd>${lines(dns.AAAA)}</dd>
      <dt>Reverse DNS</dt><dd>${lines(ptr)}</dd>
    </dl></div>
    <div class="panel"><h3>SSL / TLS</h3><dl class="kv">
      <dt>Status</dt><dd>${tls.valid ? '<span style="color:var(--good)">valid</span>' : `<span style="color:var(--bad)">${esc(tls.error || "not available")}</span>`}</dd>
      <dt>Issuer</dt><dd>${lines([tls.issuer, tls.issuer_org].filter(Boolean))}</dd>
      <dt>Subject</dt><dd>${lines(tls.subject ? [tls.subject] : [])}</dd>
      <dt>Valid</dt><dd>${lines(tls.not_before ? [tls.not_before + " → " + tls.not_after + (tls.days_left != null ? ` (${tls.days_left} days left)` : "")] : [])}</dd>
      <dt>Protocol</dt><dd>${lines([tls.protocol, tls.cipher, tls.alpn && ("ALPN " + tls.alpn)].filter(Boolean))}</dd>
      <dt>Names</dt><dd>${lines((tls.san || []).slice(0, 8).concat((tls.san || []).length > 8 ? [`+${tls.san.length - 8} more`] : []))}</dd>
    </dl></div>
    <div class="panel"><h3>DNS <span class="badge">zone ${esc(dns.zone || "")}</span>${dns.dnssec ? '<span class="badge">DNSSEC</span>' : ""}</h3><dl class="kv">
      <dt>Nameservers</dt><dd>${lines(dns.NS)}</dd>
      <dt>CNAME</dt><dd>${lines(cname)}</dd>
      <dt>MX</dt><dd>${lines(dns.MX)}</dd>
      <dt>CAA</dt><dd>${lines(dns.CAA)}</dd>
      <dt>DMARC</dt><dd>${lines(dns.DMARC)}</dd>
    </dl></div>
    <div class="panel"><h3>TXT records</h3><dl class="kv" style="grid-template-columns:1fr"><dd>${lines(dns.TXT)}</dd></dl></div>
    ${sitemapPanel(d.sitemap, d.blocked)}
  </div>`;
}

function sitemapPanel(s, blocked) {
  if (!s) return "";
  const count = c => c.urls == null ? "–" : (c.truncated ? "≥ " : "") + c.urls.toLocaleString();
  const name = u => { try { return new URL(u).pathname; } catch { return u; } };
  const counted = (s.sitemaps || []).filter(c => c.urls != null);
  const rows = (s.sitemaps || []).slice(0, 12).map(c => `<tr><td>${esc(name(c.url))}</td><td>${esc(c.type || "")}</td><td>${count(c)}</td></tr>`).join("");
  return `<div class="panel"><h3>Sitemap &amp; robots.txt${s.generator ? ` <span class="badge">${esc(s.generator)}</span>` : ""}</h3><dl class="kv">
      <dt>robots.txt</dt><dd>${s.robots_txt ? '<span style="color:var(--good)">found</span>' : '<span style="color:var(--bad)">not found</span>'}</dd>
      ${blocked && !s.found ? `<dt></dt><dd style="color:var(--muted)">May be hidden by the block page.</dd>` : ""}
      <dt>Sitemap</dt><dd>${s.found ? `${safeUrl(s.url) ? `<a href="${esc(s.url)}" target="_blank" rel="noopener noreferrer">${esc(s.url)}</a>` : esc(s.url)}<div style="color:var(--muted)">${s.source === "robots.txt" ? "listed in robots.txt" : "found at a common path (not in robots.txt)"}</div>`
        : '<span style="color:var(--bad)">not found</span>'}</dd>
      ${s.found ? `<dt>URLs</dt><dd><b>${s.partial ? "≥ " : ""}${(s.urls || 0).toLocaleString()}</b>${s.kind === "index" ? ` in ${counted.length} of ${s.children.toLocaleString()} sitemap${s.children === 1 ? "" : "s"}` : ""}</dd>` : ""}
      ${(s.declared || []).length > 1 ? `<dt>Declared</dt><dd>${lines(s.declared)}</dd>` : ""}
      ${s.offsite ? `<dt>Skipped</dt><dd>${s.offsite} sitemap${s.offsite === 1 ? "" : "s"} on other sites (not fetched)</dd>` : ""}
    </dl>
    ${rows ? `<table class="headers" style="width:100%;border-collapse:collapse;margin-top:10px">${rows}</table>` : ""}
    ${(s.sitemaps || []).length > 12 ? `<div class="note" style="margin-top:6px">+${(s.children - 12).toLocaleString()} more sitemaps not counted.</div>` : ""}
  </div>`;
}

function blockedBanner(b) {
  if (!b) return "";
  const KIND = {challenge: "a bot check that needs a real browser", block: "an access-denied page", "rate limit": "a rate limit"};
  const who = b.by ? esc(b.by) : "The site's firewall";
  return `<div class="alert" role="status">
    <b>${who} blocked this scan</b> with ${esc(KIND[b.kind] || b.kind)} (HTTP ${esc(b.status)}).
    StackCheck saw that page instead of the homepage, so page-based results such as the CMS, frameworks,
    analytics, WordPress and security headers are missing. DNS, TLS, hosting and CDN results are still reliable.
    StackCheck doesn't try to get past bot protection.
    <div class="ev">${esc(b.evidence)}</div>
  </div>`;
}

function securityPanel(d) {
  const tls = d.tls || {}, dns = d.dns || {}, http = d.http || {};
  const spf = (dns.TXT || []).find(t => /^v=spf1/i.test(t));
  const extra = [
    {header: "HTTPS", present: !!http.https, why: "Final page is served over HTTPS"},
    {header: "Valid certificate", present: !!tls.valid, why: "Certificate chain verifies for this hostname", value: tls.valid ? null : tls.error},
    {header: "SPF", present: !!spf, why: "Declares which servers may send mail for the domain", value: spf},
    {header: "DMARC", present: !!(dns.DMARC || []).length, why: "Tells receivers what to do with spoofed mail", value: (dns.DMARC || [])[0]},
    {header: "CAA", present: !!(dns.CAA || []).length, why: "Restricts which CAs may issue certificates"},
    {header: "DNSSEC", present: !!dns.dnssec, why: "DNS answers are cryptographically signed"},
  ];
  const row = h => `<div class="check"><span class="dot ${h.present ? "ok" : "no"}">${h.present ? "✓" : "✕"}</span>
    <div><b>${esc(h.header)}</b><small>${esc(h.why)}</small>${h.value ? `<code>${esc(String(h.value).slice(0, 220))}</code>` : ""}</div></div>`;
  return `<div class="grid2">
    <div class="panel"><h3>HTTP security headers</h3>${d.security_headers ? d.security_headers.map(row).join("")
      : `<div style="color:var(--muted);font-size:14px">Not checked: the headers came from a block page, not the site.</div>`}</div>
    <div class="panel"><h3>Transport & email</h3>${extra.map(row).join("")}</div>
  </div>`;
}

function headersPanel(http) {
  const h = http.headers || {};
  const rows = Object.keys(h).sort().map(k => `<tr><td>${esc(k)}</td><td>${esc(h[k])}</td></tr>`).join("");
  return `<div class="panel"><h3>Response headers</h3><table class="headers" style="width:100%;border-collapse:collapse">${rows || "<tr><td>none</td></tr>"}</table>
    ${(http.cookies || []).length ? `<h3 style="margin-top:18px">Cookies set</h3><div style="font-family:var(--mono);font-size:12px">${http.cookies.map(esc).join(", ")}</div>` : ""}</div>`;
}
})();
