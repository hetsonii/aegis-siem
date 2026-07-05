'use strict';
window.AEGIS = window.AEGIS || {};

// Shared, app-wide query state. Every page reads from it so the global time
// picker, search bar, and filter pills apply consistently (Kibana-style).
AEGIS.state = {
  rangeLabel: '24h',
  rangeSeconds: 86400,
  q: '',
  filters: {},          // { severity, type, status, src_ip, country_code }
  refreshMs: 0,
};

AEGIS.since = function () {
  if (AEGIS.state.rangeSeconds === 0) return 0;
  return Math.floor(Date.now() / 1000) - AEGIS.state.rangeSeconds;
};

AEGIS.query = function (extra) {
  const p = new URLSearchParams();
  const since = AEGIS.since();
  if (since) p.set('since', since);
  if (AEGIS.state.q) p.set('q', AEGIS.state.q);
  Object.entries(AEGIS.state.filters).forEach(([k, v]) => { if (v) p.set(k, v); });
  Object.entries(extra || {}).forEach(([k, v]) => { if (v != null) p.set(k, v); });
  return p.toString();
};

const BASE = (window.APP_CONFIG && window.APP_CONFIG.API_BASE) || '';

async function req(method, path, body) {
  const opts = { method, headers: {} };
  if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const r = await fetch(BASE + path, opts);
  if (!r.ok) throw new Error(`${method} ${path} -> ${r.status}`);
  return r.json();
}

AEGIS.api = {
  base: BASE,
  stats: (extra) => req('GET', '/stats?' + AEGIS.query(extra)),
  findings: (extra) => req('GET', '/findings?' + AEGIS.query(extra)),
  finding: (id) => req('GET', `/findings/${id}?evidence=1`),
  patchFinding: (id, status) => req('PATCH', `/findings/${id}`, { status }),
  incidents: (extra) => req('GET', '/incidents?' + AEGIS.query(extra)),
  patchIncident: (ip, status) => req('PATCH', `/incidents/${encodeURIComponent(ip)}`, { status }),
  geo: (extra) => req('GET', '/geo?' + AEGIS.query(extra)),
  blocklist: () => req('GET', '/blocklist'),
  block: (src_ip, note) => req('POST', '/blocklist', { src_ip, note }),
  unblock: (ip) => req('DELETE', `/blocklist/${encodeURIComponent(ip)}`),
};
