'use strict';
/*
 * CloudJuice - an intentionally attack-VISIBLE (not attack-VULNERABLE) juice shop.
 *
 * Safety model: this app is a sensor, not a victim. It recognizes attack
 * signatures, logs a structured security event, and returns a benign,
 * vulnerable-LOOKING response. It NEVER executes attacker input:
 *   - no database (products/reviews are in-memory)
 *   - no eval / child_process / dynamic require / fs access from user input
 *   - reflected values are escaped by the browser client, so payloads log but never run
 *
 * It also enforces the SIEM's blocklist: the console can block a source IP, and
 * this app polls the blocklist over HTTP and starts returning 403 to that source
 * (logged as a security event) - closing the detect -> respond loop.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const PRODUCTS = require('./products');

const PORT = process.env.PORT || 8080;
const BLOCKLIST_URL = process.env.BLOCKLIST_URL || '';
const BLOCKLIST_POLL_MS = 10000;

// ---- static storefront assets (served from ./public) ----------------------
const PUBLIC = path.join(__dirname, 'public');
const ASSETS = {};
for (const f of ['index.html', 'app.css', 'app.js']) {
  try { ASSETS[f] = fs.readFileSync(path.join(PUBLIC, f)); } catch (e) { ASSETS[f] = Buffer.from(''); }
}
const CT = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript' };

// ---- attack signatures (flag only, never execute) --------------------------
const SIGNATURES = [
  { type: 'sqli', re: /('|%27)?\s*(or|and)\s+\d+\s*=\s*\d+|union\s+select|select\s+.+\s+from|insert\s+into|drop\s+table|;\s*--|\/\*|xp_cmdshell|sleep\s*\(|benchmark\s*\(/i },
  { type: 'xss', re: /<script|javascript:|onerror\s*=|onload\s*=|<svg|<img[^>]+src|%3cscript|document\.cookie|alert\s*\(/i },
  { type: 'command_injection', re: /;\s*(cat|ls|wget|curl|nc|bash|sh|id|whoami)\b|`[^`]+`|\$\([^)]+\)|\|\s*(cat|ls|id|whoami)\b|&&\s*(cat|ls|id)\b/i },
  { type: 'log4shell', re: /\$\{jndi:(ldap|ldaps|rmi|dns|iiop):\/\//i },
  { type: 'ssti', re: /\{\{.*[\*\+].*\}\}|\$\{[^}]+\}|#\{[^}]+\}|<%=.+%>/i },
  { type: 'nosqli', re: /\$ne\b|\$gt\b|\$lt\b|\$where\b|\$regex\b|\{\s*"?\$/i },
  { type: 'xxe', re: /<!entity|<!doctype[^>]+system|SYSTEM\s+"file:/i },
  { type: 'path_traversal', re: /\.\.\/|\.\.%2f|%2e%2e%2f|\.\.\\|\/etc\/passwd|\/proc\/self|c:\\windows/i },
  { type: 'lfi_rfi', re: /php:\/\/(filter|input)|file:\/\/|data:\/\/|expect:\/\//i },
  { type: 'ssrf', re: /169\.254\.169\.254|metadata\.google|=https?:\/\/(10|192\.168|172\.(1[6-9]|2\d|3[01]))\.|=https?:\/\/(localhost|127\.0\.0\.1)/i },
  { type: 'open_redirect', re: /(redirect|next|url|return|dest)=(https?:)?\/\//i },
  { type: 'pii_exposure', re: /\b(?:\d[ -]*?){13,16}\b|AKIA[0-9A-Z]{16}|-----BEGIN/i },
];
const SCANNER_UA = /sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|acunetix|nessus|zgrab|feroxbuster|(python-requests|curl|go-http-client)\//i;
const SENSITIVE = /^\/(\.env|\.git|\.aws|backup\.|dump\.|db\.|wp-config|config\.php|id_rsa|phpinfo|wp-login|phpmyadmin|admin\.php|server-status)/i;

// ---- blocklist (polled from the SIEM) --------------------------------------
let BLOCKED = new Set();
async function refreshBlocklist() {
  if (!BLOCKLIST_URL) return;
  try {
    const r = await fetch(BLOCKLIST_URL, { signal: AbortSignal.timeout(4000) });
    if (!r.ok) return;
    const data = await r.json();
    BLOCKED = new Set((data.blocked || []).map((b) => b.src_ip));
  } catch (e) { /* best effort */ }
}
if (BLOCKLIST_URL) { refreshBlocklist(); setInterval(refreshBlocklist, BLOCKLIST_POLL_MS); }

// ---- helpers ---------------------------------------------------------------
function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return xff.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}
function scan(text) {
  const hits = [];
  if (text) for (const s of SIGNATURES) if (s.re.test(text)) hits.push(s.type);
  return hits;
}
function logSecurity(req, signal, detail) {
  process.stdout.write(JSON.stringify({
    event_type: 'security', ts: new Date().toISOString(), source: 'cloudjuice-app',
    src_ip: clientIp(req), method: req.method, path: req._path, query: req._query || '',
    user_agent: req.headers['user-agent'] || '', referer: req.headers['referer'] || '',
    signal, detail: detail || {},
  }) + '\n');
}
function logAccess(req, status) {
  process.stdout.write(JSON.stringify({
    event_type: 'access', ts: new Date().toISOString(), source: 'cloudjuice-app',
    src_ip: clientIp(req), method: req.method, path: req._path, status,
  }) + '\n');
}
function send(res, status, body, ct) {
  res.writeHead(status, { 'Content-Type': ct || 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
function readBody(req, cb) {
  let b = '';
  req.on('data', (c) => { b += c; if (b.length > 16384) req.destroy(); });
  req.on('end', () => cb(b));
}

// in-memory reviews (stored-XSS honeypot surface; rendered escaped client-side)
const REVIEWS = { 1: [{ author: 'Mara', text: 'Best orange juice in the cloud!' }] };

// ---- request handling ------------------------------------------------------
const server = http.createServer((req, res) => {
  let parsed;
  try { parsed = new URL(req.url, 'http://local'); }
  catch (e) { return send(res, 400, { error: 'bad request' }); }
  req._path = parsed.pathname;
  req._query = parsed.search ? parsed.search.slice(1) : '';
  const p = parsed.pathname;
  const ua = req.headers['user-agent'] || '';
  const ip = clientIp(req);

  // health check must never be blocked or logged noisily
  if (p === '/healthz') return send(res, 200, { status: 'ok' });

  // blocklist enforcement (the SIEM's automated response)
  if (BLOCKED.has(ip)) {
    logSecurity(req, 'blocked_request', { reason: 'source on SIEM blocklist' });
    return send(res, 403, { error: 'forbidden' });
  }

  // scanner fingerprint on the user agent
  if (SCANNER_UA.test(ua)) logSecurity(req, 'scanner', { user_agent: ua.slice(0, 120) });

  // dangerous HTTP methods
  if (['PUT', 'DELETE', 'TRACE'].includes(req.method) && !p.startsWith('/api/')) {
    logSecurity(req, 'http_method_abuse', { method: req.method });
    return send(res, 405, { error: 'method not allowed' });
  }

  // ---- static storefront ----
  if (p === '/' || p === '/index.html') { logAccess(req, 200); return send(res, 200, ASSETS['index.html'], CT['.html']); }
  if (p === '/app.css') return send(res, 200, ASSETS['app.css'], CT['.css']);
  if (p === '/app.js') return send(res, 200, ASSETS['app.js'], CT['.js']);
  if (p === '/favicon.ico') return send(res, 204, '');
  if (p === '/robots.txt') { logAccess(req, 200); return send(res, 200, 'User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /.git\n', 'text/plain'); }

  // ---- product catalog ----
  if (p === '/api/products') { logAccess(req, 200); return send(res, 200, { products: PRODUCTS }); }

  if (p === '/api/products/search') {
    const q = parsed.searchParams.get('q') || '';
    const hits = scan(q + ' ' + ua);
    if (hits.length) {
      logSecurity(req, hits[0], { signals: hits, field: 'q', value: q.slice(0, 256) });
      return send(res, 200, { results: [], echo: q.slice(0, 128), note: 'query executed' });
    }
    logAccess(req, 200);
    const t = q.toLowerCase();
    return send(res, 200, { results: PRODUCTS.filter((x) => x.name.toLowerCase().includes(t) || x.tag.includes(t)) });
  }

  if (p.startsWith('/api/products/')) {
    const id = decodeURIComponent(p.slice('/api/products/'.length));
    const hits = scan(id);
    if (hits.length || !/^\d+$/.test(id)) {
      logSecurity(req, hits[0] || 'idor_probe', { field: 'id', value: id.slice(0, 128) });
      return send(res, 404, { error: 'not found' });
    }
    logAccess(req, 200);
    const prod = PRODUCTS.find((x) => String(x.id) === id);
    return prod ? send(res, 200, prod) : send(res, 404, { error: 'not found' });
  }

  // ---- reviews (stored-XSS surface) ----
  if (p === '/api/reviews' && req.method === 'GET') {
    const pid = parsed.searchParams.get('product') || '1';
    logAccess(req, 200);
    return send(res, 200, { reviews: REVIEWS[pid] || [] });
  }
  if (p === '/api/reviews' && req.method === 'POST') {
    return readBody(req, (body) => {
      const hits = scan(body);
      let data = {}; try { data = JSON.parse(body); } catch (e) { /* ignore */ }
      const pid = String(data.product || '1');
      (REVIEWS[pid] = REVIEWS[pid] || []).push({ author: String(data.author || 'anon').slice(0, 40), text: String(data.text || '').slice(0, 240) });
      if (hits.length) { logSecurity(req, hits[0], { signals: hits, surface: 'review', value: body.slice(0, 256) }); }
      else logAccess(req, 200);
      return send(res, 200, { ok: true });
    });
  }

  // ---- basket (IDOR surface) ----
  if (p.startsWith('/api/basket/')) {
    const bid = decodeURIComponent(p.slice('/api/basket/'.length));
    if (bid !== '1') { logSecurity(req, 'idor_probe', { field: 'basket_id', value: bid.slice(0, 64) }); }
    else logAccess(req, 200);
    return send(res, 200, { basket_id: bid, items: [{ product: 1, qty: 2 }] });
  }

  // ---- auth ----
  if (p === '/api/login' && req.method === 'POST') {
    return readBody(req, (body) => {
      const hits = scan(body);
      let data = {}; try { data = JSON.parse(body); } catch (e) { /* urlencoded ok */ }
      const username = data.email || data.username ||
        (new URLSearchParams(body).get('email')) || (new URLSearchParams(body).get('username')) || '';
      // every login fails (no real auth store); we log the failure for correlation
      logSecurity(req, hits.length ? hits[0] : 'login_failed',
        { signals: hits, outcome: 'failed', username: String(username).slice(0, 64) });
      return send(res, 401, { error: 'invalid credentials' });
    });
  }
  if (p === '/api/register' && req.method === 'POST') {
    return readBody(req, (body) => {
      const hits = scan(body);
      if (hits.length) logSecurity(req, hits[0], { signals: hits, surface: 'register' });
      else logAccess(req, 201);
      return send(res, 201, { ok: true });
    });
  }

  // ---- admin ----
  if (p === '/admin' || p.startsWith('/admin/') || p === '/api/admin') {
    logSecurity(req, 'unauthorized_admin_access', { path: p });
    return send(res, 403, { error: 'forbidden' });
  }

  // ---- recon: sensitive files ----
  if (SENSITIVE.test(p)) {
    logSecurity(req, 'sensitive_file', { path: p.slice(0, 128) });
    return send(res, 404, { error: 'not found' });
  }

  // ---- everything else: check for injection in the path, else recon 404 ----
  const pathHits = scan(p + ' ' + req._query);
  if (pathHits.length) {
    logSecurity(req, pathHits[0], { signals: pathHits, path: p.slice(0, 128), query: req._query.slice(0, 128) });
    return send(res, 404, { error: 'not found' });
  }
  logSecurity(req, 'recon_404', { path: p.slice(0, 200) });
  return send(res, 404, { error: 'not found' });
});

server.listen(PORT, () => {
  process.stdout.write(JSON.stringify({
    event_type: 'access', ts: new Date().toISOString(), source: 'cloudjuice-app',
    message: 'listening', port: Number(PORT), blocklist: !!BLOCKLIST_URL,
  }) + '\n');
});
