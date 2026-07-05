'use strict';
/* Aegis SOC console - vanilla JS, no build step. Kibana-style spine:
   Overview (dashboard) · Discover (search + histogram + field sidebar +
   expandable rows) · Incidents · Detections (rules + ATT&CK matrix) ·
   Threat Map (Leaflet) · Response (block / unblock). */

const view = document.getElementById('view');
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const $ = (id) => document.getElementById(id);
let CHARTS = [];
let MAP = null;
let refreshTimer = null;

function cleanup() {
  CHARTS.forEach((c) => { try { c.destroy(); } catch (e) {} });
  CHARTS = [];
  if (MAP) { try { MAP.remove(); } catch (e) {} MAP = null; }
}
function sevBadge(s) { return `<span class="sev sev-${esc(s)}">${esc(s)}</span>`; }
function fmtTime(ep) {
  if (!ep) return '—';
  const d = new Date(ep * 1000); const now = new Date();
  const t = d.toTimeString().slice(0, 8);
  return d.toDateString() === now.toDateString() ? t
    : `${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${t}`;
}
function humanDur(s) {
  if (s == null) return '—';
  s = Math.round(s);
  if (s < 60) return s + 's';
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}
function errorBox(e) { return `<div class="err">Could not load data: ${esc(e.message || e)}.<br>Check that the API is reachable and the time range contains events.</div>`; }
function empty(msg, big) { return `<div class="empty"><div class="big">${big || '◌'}</div>${esc(msg)}</div>`; }

/* ---------- global controls ---------- */
function renderPills() {
  const p = $('pills'); const f = AEGIS.state.filters;
  const items = Object.entries(f).filter(([, v]) => v);
  p.innerHTML = items.map(([k, v]) =>
    `<span class="pill"><b>${esc(k)}</b>: ${esc(v)} <button data-pill="${esc(k)}">×</button></span>`).join('');
  p.querySelectorAll('button[data-pill]').forEach((b) =>
    b.onclick = () => { delete AEGIS.state.filters[b.dataset.pill]; render(); });
}
function addFilter(k, v) { AEGIS.state.filters[k] = v; render(); }

function wireControls() {
  $('q').addEventListener('keydown', (e) => { if (e.key === 'Enter') { AEGIS.state.q = $('q').value.trim(); render(); } });
  $('q-run').onclick = () => { AEGIS.state.q = $('q').value.trim(); render(); };
  $('range').onchange = (e) => {
    AEGIS.state.rangeSeconds = Number(e.target.value);
    AEGIS.state.rangeLabel = e.target.selectedOptions[0].textContent;
    render();
  };
  $('refresh').onchange = (e) => {
    AEGIS.state.refreshMs = Number(e.target.value);
    if (refreshTimer) clearInterval(refreshTimer);
    if (AEGIS.state.refreshMs) refreshTimer = setInterval(render, AEGIS.state.refreshMs);
  };
  $('refresh-now').onclick = () => render();
  document.querySelectorAll('#nav a').forEach((a) =>
    a.onclick = () => { location.hash = '#/' + a.dataset.route; });
}

/* ---------- charts ---------- */
function donut(canvas, labels, data, colors) {
  if (!window.Chart) return;
  CHARTS.push(new Chart(canvas, { type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: colors, borderColor: '#0f1424', borderWidth: 2 }] },
    options: { plugins: { legend: { position: 'right', labels: { color: '#8a94b8', boxWidth: 12 } } }, cutout: '62%' } }));
}
function bars(canvas, labels, data, color, horizontal) {
  if (!window.Chart) return;
  CHARTS.push(new Chart(canvas, { type: 'bar',
    data: { labels, datasets: [{ data, backgroundColor: color, borderRadius: 5 }] },
    options: { indexAxis: horizontal ? 'y' : 'x', plugins: { legend: { display: false } },
      scales: { x: { ticks: { color: '#8a94b8' }, grid: { color: '#1a2138' } },
        y: { ticks: { color: '#8a94b8' }, grid: { color: '#1a2138' } } } } }));
}
function line(canvas, labels, data) {
  if (!window.Chart) return;
  CHARTS.push(new Chart(canvas, { type: 'line',
    data: { labels, datasets: [{ data, borderColor: '#22d3ee', backgroundColor: 'rgba(34,211,238,.12)',
      fill: true, tension: .3, pointRadius: 0, borderWidth: 2 }] },
    options: { plugins: { legend: { display: false } },
      scales: { x: { ticks: { color: '#8a94b8', maxTicksLimit: 8 }, grid: { color: '#1a2138' } },
        y: { ticks: { color: '#8a94b8' }, grid: { color: '#1a2138' }, beginAtZero: true } } } }));
}

/* ---------- Overview ---------- */
async function pageOverview() {
  let stats, finds;
  try { [stats, finds] = await Promise.all([AEGIS.api.stats(), AEGIS.api.findings({ limit: 400 })]); }
  catch (e) { view.innerHTML = errorBox(e); return; }
  const sv = stats.by_severity || {};
  const crit = (sv.CRITICAL || 0) + (sv.HIGH || 0);
  const techSeen = new Set();
  (finds.findings || []).forEach((f) => (f.mitre || []).forEach((m) => techSeen.add(m.technique)));

  view.innerHTML = `
    <div class="grid g-kpi">
      ${kpi(stats.total || 0, 'Findings', AEGIS.state.rangeLabel)}
      ${kpi(stats.open_incidents || 0, 'Open incidents', 'unresolved sources')}
      ${kpi(crit, 'High + Critical', 'need triage', crit > 0)}
      ${kpi(stats.blocked || 0, 'Blocked sources', 'active response')}
      ${kpi(humanDur(stats.mtta_seconds), 'MTTA', 'mean time to acknowledge')}
      ${kpi(humanDur(stats.mttr_seconds), 'MTTR', 'mean time to resolve')}
    </div>
    <div class="grid g-2" style="margin-top:16px">
      <div class="panel"><h3>Findings over time</h3><canvas id="c-time" height="90"></canvas></div>
      <div class="panel"><h3>By severity</h3><canvas id="c-sev" height="180"></canvas></div>
    </div>
    <div class="grid g-3" style="margin-top:16px">
      <div class="panel"><h3>Top attack types</h3><canvas id="c-type" height="200"></canvas></div>
      <div class="panel"><h3>Top sources</h3>${topList(stats.top_sources || [], 'src_ip')}</div>
      <div class="panel"><h3>ATT&CK techniques observed</h3>
        <div class="kpi"><div class="num" style="color:var(--violet)">${techSeen.size}</div>
        <div class="sub">distinct techniques in range · ${AEGIS.RULES.filter(r=>r.technique).length} in catalog</div></div>
        <div class="chips" style="margin-top:12px">${[...techSeen].slice(0, 12).map((t) => `<span class="chip tech">${esc(t)}</span>`).join('') || '<span class="dim">none yet</span>'}</div>
      </div>
    </div>`;
  const tl = stats.timeline || [];
  line($('c-time'), tl.map((b) => fmtTime(b.t)), tl.map((b) => b.count));
  const order = AEGIS.SEVERITIES.filter((s) => sv[s]);
  donut($('c-sev'), order, order.map((s) => sv[s]), order.map((s) => AEGIS.SEV_COLOR[s]));
  const types = Object.entries(stats.by_type || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  bars($('c-type'), types.map((t) => ruleName(t[0])), types.map((t) => t[1]), '#8b5cf6', true);
}
function kpi(num, lbl, sub, alarm) {
  return `<div class="panel kpi ${alarm ? 'alarm' : ''}"><div class="num">${esc(num)}</div>
    <div class="lbl">${esc(lbl)}</div><div class="sub">${esc(sub || '')}</div></div>`;
}
function topList(rows, key) {
  if (!rows.length) return '<div class="dim">No data.</div>';
  const max = Math.max(...rows.map((r) => r.count));
  return rows.map((r) => `<div style="margin-bottom:9px">
    <div style="display:flex;justify-content:space-between"><span class="mono">${esc(r[key])}</span><span class="dim mono">${esc(r.count)}</span></div>
    <div class="bar"><span style="width:${(r.count / max * 100).toFixed(0)}%;background:var(--teal)"></span></div></div>`).join('');
}
function ruleName(id) { return (AEGIS.RULE_BY_ID[id] || {}).name || id; }

/* ---------- Discover ---------- */
let expandedId = null;
async function pageDiscover() {
  let res;
  try { res = await AEGIS.api.findings({ limit: 500 }); } catch (e) { view.innerHTML = errorBox(e); return; }
  const items = res.findings || [];
  view.innerHTML = `<div class="discover">
    <div class="panel fields"><h3>Fields</h3><div id="fieldbox"></div></div>
    <div>
      <div class="panel"><h3>${items.length} events · ${esc(AEGIS.state.rangeLabel)}</h3>
        <div class="histo"><canvas id="c-histo"></canvas></div></div>
      <div class="panel" style="margin-top:16px">
        ${items.length ? `<table><thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Source</th><th>Geo</th><th>Request</th></tr></thead>
        <tbody id="rows"></tbody></table>` : empty('No events match this search and time range.', '❖')}
      </div>
    </div></div>`;

  // histogram
  if (items.length) {
    const times = items.map((f) => f.ts_epoch).filter(Boolean);
    const lo = Math.min(...times), hi = Math.max(...times), step = Math.max(Math.floor((hi - lo) / 36) || 1, 1);
    const buckets = {};
    times.forEach((t) => { const b = Math.floor(t / step) * step; buckets[b] = (buckets[b] || 0) + 1; });
    const keys = Object.keys(buckets).map(Number).sort((a, b) => a - b);
    bars($('c-histo'), keys.map(fmtTime), keys.map((k) => buckets[k]), '#22d3ee');
  }

  // field sidebar
  const fieldbox = $('fieldbox');
  ['severity', 'type', 'country', 'src_ip', 'method'].forEach((fld) => {
    const counts = {};
    items.forEach((f) => { const v = f[fld]; if (v) counts[v] = (counts[v] || 0) + 1; });
    const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
    if (!top.length) return;
    const div = document.createElement('div'); div.className = 'field';
    div.innerHTML = `<div class="fname">${esc(fld)}</div>` + top.map(([v, c]) =>
      `<div class="fval" data-f="${fld === 'country' ? 'country_code' : fld}" data-v="${esc(fld === 'country' ? (items.find((x) => x.country === v) || {}).country_code || v : v)}">
        <span>${esc(v)}</span><span class="c">${c}</span></div>`).join('');
    fieldbox.appendChild(div);
  });
  fieldbox.querySelectorAll('.fval').forEach((el) => el.onclick = () => addFilter(el.dataset.f, el.dataset.v));

  // rows
  const tb = $('rows');
  if (tb) {
    items.forEach((f) => {
      const tr = document.createElement('tr');
      tr.style.setProperty('--sevc', AEGIS.SEV_COLOR[f.severity] || '#64748b');
      tr.className = 'row-sev';
      tr.innerHTML = `<td class="mono dim">${fmtTime(f.ts_epoch)}</td><td>${sevBadge(f.severity)}</td>
        <td>${esc(ruleName(f.type))}</td><td class="mono">${esc(f.src_ip)}</td>
        <td class="dim">${esc(f.country || '—')}</td>
        <td class="mono dim">${esc(f.method)} ${esc((f.path || '').slice(0, 42))}</td>`;
      tr.onclick = () => toggleRow(tr, f.finding_id);
      tb.appendChild(tr);
    });
  }
}
async function toggleRow(tr, id) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains('expand')) { next.remove(); return; }
  document.querySelectorAll('tr.expand').forEach((e) => e.remove());
  const exp = document.createElement('tr'); exp.className = 'expand';
  const td = document.createElement('td'); td.colSpan = 6; td.innerHTML = '<span class="dim">Loading evidence…</span>';
  exp.appendChild(td); tr.after(exp);
  try {
    const full = await AEGIS.api.finding(id);
    const doc = { finding: strip(full), ocsf: (full.evidence || {}).ocsf, evidence: (full.evidence || {}).event };
    td.innerHTML = `<div class="actions" style="margin-bottom:10px">
        ${triageBtns(id, 'finding')}
        <button class="btn sm danger" data-block="${esc(full.src_ip)}">Block ${esc(full.src_ip)}</button></div>
      <pre class="json">${esc(JSON.stringify(doc, null, 2))}</pre>`;
    wireTriage(td);
  } catch (e) { td.innerHTML = errorBox(e); }
}
function strip(f) { const c = Object.assign({}, f); delete c.evidence; return c; }

/* ---------- Incidents ---------- */
async function pageIncidents() {
  let res;
  try { res = await AEGIS.api.incidents(); } catch (e) { view.innerHTML = errorBox(e); return; }
  const inc = res.incidents || [];
  if (!inc.length) { view.innerHTML = `<div class="panel">${empty('No incidents in this time range. Incidents group findings by source.', '⚠')}</div>`; return; }
  view.innerHTML = `<div class="panel"><h3>${inc.length} incidents · grouped by source</h3>
    <table><thead><tr><th>Severity</th><th>Source</th><th>Events</th><th>ATT&CK</th><th>First → last seen</th><th>Status</th><th>Actions</th></tr></thead>
    <tbody>${inc.map((g) => `<tr style="--sevc:${AEGIS.SEV_COLOR[g.max_severity]}" class="row-sev">
      <td>${sevBadge(g.max_severity)}</td>
      <td><span class="mono">${esc(g.src_ip)}</span><div class="dim small">${esc(g.country || 'Unknown')}</div></td>
      <td class="mono">${g.count}<div class="dim small">${g.open} open</div></td>
      <td><div class="chips">${(g.techniques || []).slice(0, 4).map((t) => `<span class="chip tech" title="${esc(t.name)}">${esc(t.technique)}</span>`).join('') || '<span class="dim">—</span>'}</div></td>
      <td class="mono dim">${fmtTime(g.first_seen)}<br>${fmtTime(g.last_seen)}</td>
      <td>${Object.entries(g.statuses || {}).map(([s, c]) => `<span class="chip">${esc(s)}:${c}</span>`).join(' ')}</td>
      <td><div class="actions">
        ${triageBtns(g.src_ip, 'incident')}
        <button class="btn sm danger" data-block="${esc(g.src_ip)}">Block</button>
        <button class="btn sm" data-view="${esc(g.src_ip)}">Events</button>
      </div></td></tr>`).join('')}</tbody></table></div>`;
  wireTriage(view);
  view.querySelectorAll('button[data-view]').forEach((b) =>
    b.onclick = () => { AEGIS.state.filters.src_ip = b.dataset.view; location.hash = '#/discover'; });
}

/* triage + block wiring shared by Discover and Incidents */
function triageBtns(id, kind) {
  return `<button class="btn sm" data-triage="investigating" data-id="${esc(id)}" data-kind="${kind}">Investigate</button>
    <button class="btn sm" data-triage="resolved" data-id="${esc(id)}" data-kind="${kind}">Resolve</button>
    <button class="btn sm" data-triage="false_positive" data-id="${esc(id)}" data-kind="${kind}">False+</button>`;
}
function wireTriage(root) {
  root.querySelectorAll('button[data-triage]').forEach((b) => b.onclick = async (e) => {
    e.stopPropagation();
    const { triage, id, kind } = b.dataset;
    try { kind === 'incident' ? await AEGIS.api.patchIncident(id, triage) : await AEGIS.api.patchFinding(id, triage); render(); }
    catch (err) { alert('Update failed: ' + err.message); }
  });
  root.querySelectorAll('button[data-block]').forEach((b) => b.onclick = async (e) => {
    e.stopPropagation();
    try { await AEGIS.api.block(b.dataset.block, 'blocked from console'); b.textContent = 'Blocked ✓'; b.disabled = true; }
    catch (err) { alert('Block failed: ' + err.message); }
  });
}

/* ---------- Detections ---------- */
async function pageDetections() {
  let counts = {};
  try {
    const res = await AEGIS.api.findings({ limit: 500 });
    (res.findings || []).forEach((f) => (f.mitre || []).forEach((m) => { counts[m.technique] = (counts[m.technique] || 0) + 1; }));
  } catch (e) { /* matrix still renders from catalog */ }

  const byTactic = AEGIS.techniquesByTactic();
  const matrix = AEGIS.TACTICS.map((tac) => {
    const cells = Object.entries(byTactic[tac]).map(([tid, tn]) => {
      const c = counts[tid] || 0;
      return `<div class="cell ${c ? 'hit' : ''}">${c ? `<span class="ct">${c}</span>` : ''}
        <div class="tid">${esc(tid)}</div><div class="tn">${esc(tn)}</div></div>`;
    }).join('') || '<div class="dim small">—</div>';
    return `<div class="col"><div class="colhead">${esc(tac)}</div>${cells}</div>`;
  }).join('');

  const rules = [...AEGIS.RULES].sort((a, b) => AEGIS.SEV_ORDER[b.severity] - AEGIS.SEV_ORDER[a.severity]);
  view.innerHTML = `
    <div class="panel"><h3>MITRE ATT&CK coverage · counts are findings in range</h3>
      <div class="matrix" style="grid-template-columns:repeat(${AEGIS.TACTICS.length},minmax(150px,1fr))">${matrix}</div>
    </div>
    <div class="panel" style="margin-top:16px"><h3>Detection rules · ${rules.length} rules (detection-as-code)</h3>
      <table><thead><tr><th>Rule</th><th>Severity</th><th>ATT&CK</th><th>Tactic</th><th>Kind</th><th>Description</th></tr></thead>
      <tbody>${rules.map((r) => `<tr style="--sevc:${AEGIS.SEV_COLOR[r.severity]}" class="row-sev">
        <td><b>${esc(r.name)}</b><div class="dim small mono">${esc(r.id)}</div></td>
        <td>${sevBadge(r.severity)}</td>
        <td class="mono">${r.technique ? esc(r.technique) : '<span class="dim">—</span>'}<div class="dim small">${esc(r.technique_name || '')}</div></td>
        <td class="dim">${esc(r.tactic || '—')}</td>
        <td><span class="chip">${r.stat ? 'behavioral' : 'signature'}</span></td>
        <td class="small">${esc(r.desc)}</td></tr>`).join('')}</tbody></table>
    </div>`;
}

/* ---------- Threat Map ---------- */
async function pageMap() {
  let geo, stats;
  try { [geo, stats] = await Promise.all([AEGIS.api.geo(), AEGIS.api.stats()]); }
  catch (e) { view.innerHTML = errorBox(e); return; }
  const pts = geo.points || [];
  const countries = Object.entries(stats.by_country || {}).filter(([c]) => c !== 'Unknown')
    .sort((a, b) => b[1] - a[1]).slice(0, 10);
  view.innerHTML = `<div class="grid g-2">
    <div class="panel"><h3>Attack origins · ${pts.length} located sources</h3><div id="map"></div>
      <div class="legend">${AEGIS.SEVERITIES.map((s) => `<span><span class="dot" style="background:${AEGIS.SEV_COLOR[s]}"></span>${s}</span>`).join('')}</div></div>
    <div class="panel"><h3>Top countries</h3>${countries.length ? topList(countries.map(([country, count]) => ({ country, count })), 'country') : empty('No geolocated sources yet.', '◎')}</div>
  </div>`;
  if (!window.L) { $('map').innerHTML = errorBox({ message: 'map library unavailable' }); return; }
  MAP = L.map('map', { worldCopyJump: true, attributionControl: false }).setView([20, 0], 2);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png', { maxZoom: 8 }).addTo(MAP);
  pts.forEach((p) => {
    if (p.lat == null || p.lon == null) return;
    L.circleMarker([p.lat, p.lon], {
      radius: Math.min(6 + p.count * 1.5, 22), color: AEGIS.SEV_COLOR[p.max_severity] || '#64748b',
      fillColor: AEGIS.SEV_COLOR[p.max_severity] || '#64748b', fillOpacity: .5, weight: 2,
    }).addTo(MAP).bindPopup(`<b>${esc(p.src_ip)}</b><br>${esc(p.city ? p.city + ', ' : '')}${esc(p.country)}<br>${p.count} findings · ${esc(p.max_severity)}`);
  });
}

/* ---------- Response ---------- */
async function pageResponse() {
  let bl;
  try { bl = await AEGIS.api.blocklist(); } catch (e) { view.innerHTML = errorBox(e); return; }
  const rows = bl.blocked || [];
  view.innerHTML = `<div class="grid g-2">
    <div class="panel"><h3>Blocklist · ${rows.length} active</h3>
      ${rows.length ? `<table><thead><tr><th>Source IP</th><th>Blocked</th><th>Note</th><th></th></tr></thead>
      <tbody>${rows.map((r) => `<tr><td class="mono">${esc(r.src_ip)}</td><td class="dim mono">${fmtTime(r.blocked_at)}</td>
        <td class="small">${esc(r.note || '')}</td>
        <td><button class="btn sm" data-unblock="${esc(r.src_ip)}">Unblock</button></td></tr>`).join('')}</tbody></table>`
      : empty('No sources are blocked. Block one here or from an incident.', '⦻')}
    </div>
    <div class="panel"><h3>Block a source</h3>
      <input class="field-input" id="blk-ip" placeholder="Source IP (e.g. 185.220.101.5)">
      <input class="field-input" id="blk-note" placeholder="Note (optional)">
      <button class="btn go" id="blk-go" style="width:100%;margin-top:6px">Block source</button>
      <p class="small" style="margin-top:14px">Blocking writes the IP to the shared blocklist. The CloudJuice honeypot
      polls it every 10 seconds and starts returning <span class="mono">403</span> to that source, logging each
      hit as a <span class="mono">blocked_request</span> finding. Unblocking removes it and traffic resumes — the
      full detect → respond → recover loop, driven from here.</p>
    </div></div>`;
  view.querySelectorAll('button[data-unblock]').forEach((b) => b.onclick = async () => {
    try { await AEGIS.api.unblock(b.dataset.unblock); render(); } catch (e) { alert('Unblock failed: ' + e.message); }
  });
  $('blk-go').onclick = async () => {
    const ip = $('blk-ip').value.trim(); if (!ip) return;
    try { await AEGIS.api.block(ip, $('blk-note').value.trim()); render(); } catch (e) { alert('Block failed: ' + e.message); }
  };
}

/* ---------- router ---------- */
const PAGES = {
  overview: { title: 'Overview', fn: pageOverview },
  discover: { title: 'Discover', fn: pageDiscover },
  incidents: { title: 'Incidents', fn: pageIncidents },
  detections: { title: 'Detections', fn: pageDetections },
  map: { title: 'Threat Map', fn: pageMap },
  response: { title: 'Response', fn: pageResponse },
};
function currentRoute() { return (location.hash.replace('#/', '') || 'overview'); }
async function render() {
  const route = currentRoute();
  const page = PAGES[route] || PAGES.overview;
  document.querySelectorAll('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.route === route));
  $('page-title').textContent = page.title;
  $('q').value = AEGIS.state.q;
  renderPills();
  cleanup();
  view.innerHTML = '<div class="empty"><div class="big">◌</div>Loading…</div>';
  await page.fn();
}
window.addEventListener('hashchange', render);
wireControls();
if (!location.hash) location.hash = '#/overview';
render();
