// ThreatBadger — app.js
// All frontend logic: login, lookup, history, settings, rendering

'use strict';

// ─── State ─────────────────────────────────────────────────────
const App = {
  currentResult:   null,
  currentHistId:   null,
  historyItems:    [],
  settings:        null,
  settingsDraft:   {},
  selectedSources: new Set(),  // keys of sources the user has toggled ON
  sourcesInitialized: false,     // true after first load seeds the set
};

// ─── Helpers ───────────────────────────────────────────────────
function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function detectType(q) {
  if (!q) return null;
  q = q.trim();
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(q))              return 'IPv4 Address';
  if (/^[a-fA-F0-9]{64}$/.test(q))                     return 'SHA-256 Hash';
  if (/^[a-fA-F0-9]{40}$/.test(q))                     return 'SHA-1 Hash';
  if (/^[a-fA-F0-9]{32}$/.test(q))                     return 'MD5 Hash';
  if (/^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$/.test(q))    return 'Domain';
  if (/^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(q)) return 'Email Address';
  if (/^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,6}))$/.test(q)) return 'IPv6 Address';
  return null;
}

const RISK_COLORS = { CRITICAL:'#f85149', HIGH:'#f0883e', MEDIUM:'#d29922', LOW:'#3fb950' };
const VERDICT_COLORS = { MALICIOUS:'#f85149', SUSPICIOUS:'#d29922', CLEAN:'#3fb950' };

async function apiFetch(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers||{}) },
    ...opts,
  });
  let data;
  try { data = await res.json(); } catch(e) { data = {}; }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// ─── Login ─────────────────────────────────────────────────────
async function doLogin() {
  const user = document.getElementById('login-user').value.trim();
  const pass = document.getElementById('login-pass').value;
  const err  = document.getElementById('login-err');
  const btn  = document.getElementById('login-btn');

  if (!user || !pass) { err.textContent = 'Enter credentials.'; return; }
  btn.textContent = 'Signing in…'; btn.disabled = true;

  const fd = new FormData();
  fd.append('action', 'login');
  fd.append('username', user);
  fd.append('password', pass);

  try {
    const res = await fetch('index.php', { method: 'POST', body: fd });
    const data = await res.json();
    if (data.success) {
      window.location.reload();
    } else {
      err.textContent = data.error || 'Login failed';
      btn.textContent = 'Sign in'; btn.disabled = false;
    }
  } catch(e) {
    err.textContent = '⚠ ' + e.message;
    //err.textContent = 'Network error — is the server running?';
    btn.textContent = 'Sign in'; btn.disabled = false;
  }
}

// Allow Enter key on login
document.addEventListener('DOMContentLoaded', function() {
  const lp = document.getElementById('login-pass');
  if (lp) lp.addEventListener('keydown', e => { if(e.key === 'Enter') doLogin(); });
  const lu = document.getElementById('login-user');
  if (lu) lu.addEventListener('keydown', e => { if(e.key === 'Enter') doLogin(); });
});

// ─── View switching ────────────────────────────────────────────
function switchView(view, btn) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('view-' + view).classList.add('active');
  if (btn) btn.classList.add('active');

  // Refresh history and settings list every time the tab is opened so new lookups appear
  if (view === 'history') loadHistory();
  if (view === 'settings') loadSettings();
}

// ─── Source status badges ──────────────────────────────────────
const SOURCE_DEFS = [
  { key:'elasticsearch', label:'Elasticsearch' },
  { key:'misp',          label:'MISP' },
  { key:'virustotal',    label:'VirusTotal' },
  { key:'greynoise',     label:'GreyNoise' },
  { key:'geoip',         label:'GeoIP' },
  { key:'whois',         label:'WHOIS' },
  { key:'hibp',          label: 'HiBP' },
  { key:'custom_lists',  label: 'Custom Lists'},
  { key:'hackertarget',  label: 'HackerTarget'},
];

// Set up event delegation once on DOMContentLoaded
document.addEventListener('DOMContentLoaded', function() {
  const wrap = document.getElementById('source-badges');
  if (wrap) {
    wrap.addEventListener('click', function(e) {
      const badge = e.target.closest('.source-badge[data-source-key]');
      if (!badge) return;
      const key = badge.getAttribute('data-source-key');
      if (!key) return;
      // Toggle in/out of selected set
      if (App.selectedSources.has(key)) {
        App.selectedSources.delete(key);
      } else {
        App.selectedSources.add(key);
      }
      // Update just this badge's classes no full re-render needed
      const nowSelected = App.selectedSources.has(key);
      badge.classList.toggle('selected', nowSelected);
      badge.classList.toggle('deselected', !nowSelected);
      badge.title = 'Click to ' + (nowSelected ? 'exclude' : 'include') + ' ' + badge.getAttribute('data-label');
    });
  }
});

async function loadSourceStatus() {
  try {
    const data = await apiFetch('api/settings.php');
    App.settings = data;
    const wrap = document.getElementById('source-badges');
    if (!wrap) return;

    // On first load: seed selectedSources with all currently-enabled sources.
    // On subsequent calls (after a lookup): keep existing selections.
    if (App.selectedSources.size === 0 && !App.sourcesInitialized) {
      SOURCE_DEFS.forEach(s => {
        if (s.key === 'custom_lists') {
          if (Array.isArray(data.custom_lists) && data.custom_lists.length > 0)
            App.selectedSources.add('custom_lists');
        } else if (s.key === 'hackertarget') {
          if (data.hackertarget?.enabled) App.selectedSources.add('hackertarget');
        } else if (data[s.key]?.enabled) {
          App.selectedSources.add(s.key);
        }
      });
      App.sourcesInitialized = true;
    }

    renderSourceBadges(wrap, data);
  } catch(e) { console.error('loadSourceStatus failed:', e); }
}

function renderSourceBadges(wrap, data) {
  // Seed custom_lists as selected on first load (it's always available if configured)
  if (!App.sourcesInitialized) {
    const hasCustomLists = data?.custom_lists?.length > 0;
    if (hasCustomLists) App.selectedSources.add('custom_lists');
  }

  wrap.innerHTML = SOURCE_DEFS.map(s => {
    const enabled = data
    ? (s.key === 'custom_lists'
        ? Array.isArray(data.custom_lists) && data.custom_lists.length > 0
        : s.key === 'hackertarget'
        ? !!(data.hackertarget?.enabled)
        : !!(data[s.key]?.enabled))
    : false;
    if (!enabled) {
      // Source not configured - show as disabled, non-interactive
      return `<div class="source-badge off" title="${esc(s.label)} is not configured"><div class="dot"></div>${esc(s.label)}</div>`;
    }
    const selected = App.selectedSources.has(s.key);
    const action   = selected ? 'exclude' : 'include';
    return `<div class="source-badge on ${selected ? 'selected' : 'deselected'}" data-source-key="${esc(s.key)}" data-label="${esc(s.label)}" title="Click to ${action} ${esc(s.label)}"><div class="dot"></div>${esc(s.label)}</div>`;
  }).join('');
}

// ─── Type badge ─────────────────────────────────────────────────
function updateTypeBadge() {
  const q = document.getElementById('query-input').value.trim();
  const t = detectType(q);
  const wrap = document.getElementById('type-badge-wrap');
  if (!wrap) return;
  const typeColors = {
    'IPv4 Address':  { color:'var(--accent)', bg:'rgba(88,166,255,.12)' },
    'Domain':        { color:'var(--green)',  bg:'rgba(63,185,80,.12)' },
    'MD5 Hash':      { color:'var(--purple)', bg:'rgba(188,140,255,.12)' },
    'SHA-1 Hash':    { color:'var(--purple)', bg:'rgba(188,140,255,.12)' },
    'SHA-256 Hash':  { color:'var(--purple)', bg:'rgba(188,140,255,.12)' },
    'Email Address': { color:'var(--orange)', bg:'rgba(240,136,62,.12)' },
    'IPv6 Address':  { color:'var(--accent)', bg:'rgba(88,166,255,.12)' },
  };
  if (t && typeColors[t]) {
    const c = typeColors[t];
    wrap.innerHTML = `<span class="type-badge" style="background:${c.bg};color:${c.color}">● ${esc(t)}</span>`;
  } else {
    wrap.innerHTML = '';
  }
}

// ─── Lookup ────────────────────────────────────────────────────
async function doLookup(prefillQuery) {
  const input = document.getElementById('query-input');
  if (prefillQuery) input.value = prefillQuery;
  const q = input.value.trim();
  if (!q) return;

  const elErr     = document.getElementById('lookup-error');
  const elLoading = document.getElementById('lookup-loading');
  const elEmpty   = document.getElementById('lookup-empty');
  const elResults = document.getElementById('lookup-results');
  const btn       = document.getElementById('search-btn');

  elErr.style.display = 'none';
  elLoading.style.display = 'block';
  elEmpty.style.display = 'none';
  elResults.style.display = 'none';
  btn.disabled = true; btn.textContent = 'Analyzing…';

  try {
    const activeSourcesList = App.selectedSources.size > 0 ? [...App.selectedSources] : null;
    const data = await apiFetch('api/lookup.php', {
      method: 'POST',
      body: JSON.stringify({ indicator: q, active_sources: activeSourcesList }),
    });
    App.currentResult = data;
    App.currentHistId = data.history_id;
    elResults.innerHTML = renderResults(data);
    elResults.style.display = 'block';
    loadHistory(); // refresh history badge count
    loadSourceStatus();
  } catch(e) {
    elErr.textContent = '⚠ ' + e.message;
    elErr.style.display = 'block';
    elEmpty.style.display = 'block';
  } finally {
    elLoading.style.display = 'none';
    btn.disabled = false; btn.textContent = 'Analyze →';
  }
}

// ─── Render results ────────────────────────────────────────────
function renderResults(r) {
  const riskColor = RISK_COLORS[r.risk_level] || '#8b949e';
  const circ = 2 * Math.PI * 26;
  const offset = circ - (r.score / 100) * circ;
  const histId = r.history_id || App.currentHistId;

  // Score ring
  const scoreRing = `
    <div class="score-ring-outer">
      <svg width="80" height="80" viewBox="0 0 80 80">
        <circle cx="40" cy="40" r="26" fill="none" stroke="var(--bg3)" stroke-width="7"/>
        <circle cx="40" cy="40" r="26" fill="none" stroke="${riskColor}" stroke-width="7"
          stroke-dasharray="${circ.toFixed(2)}" stroke-dashoffset="${offset.toFixed(2)}" stroke-linecap="round"/>
      </svg>
      <div class="score-num" style="color:${riskColor}">${r.score}</div>
    </div>`;

  // IOC rows — for Custom Lists source, only show it if there are threat-scoring matches
  const iocRows = (r.ioc_results || []).map(src => {
    if (src.source === 'Custom Lists') {
      // Filter matches to threat-only for the IOC panel
      const threatMatches = (src.matches || []).filter(m => (m.list_scoring || 'threats') === 'threats');
      if (!threatMatches.length) return ''; // hide entirely if no threat matches
      return renderIocRow({ ...src, matches: threatMatches, found: true });
    }
    return renderIocRow(src);
  }).join('');

  // VT bar
  const vtStats = r.vt_stats;
  let vtBar = '';
  if (vtStats && vtStats.total > 0) {
    const t = vtStats.total;
    vtBar = `<div class="vt-bar-wrap">
      <div class="vt-bar">
        <div class="vt-bar-seg" style="width:${(vtStats.malicious/t*100).toFixed(1)}%;background:var(--red)"></div>
        <div class="vt-bar-seg" style="width:${(vtStats.suspicious/t*100).toFixed(1)}%;background:var(--amber)"></div>
        <div class="vt-bar-seg" style="width:${(vtStats.harmless/t*100).toFixed(1)}%;background:var(--green)"></div>
        <div class="vt-bar-seg" style="width:${(vtStats.undetected/t*100).toFixed(1)}%;background:var(--bg4)"></div>
      </div>
      <div class="vt-stats">
        <span style="color:var(--red)">${vtStats.malicious} Malicious</span>
        <span style="color:var(--amber)">${vtStats.suspicious} Suspicious</span>
        <span style="color:var(--green)">${vtStats.harmless} Harmless</span>
        <span style="color:var(--muted)">${vtStats.undetected} Undetected</span>
      </div>
    </div>`;
  }

  // Tags
  const tags = (r.tags || []).map(t => `<span class="tag tag-blue">${esc(t)}</span>`).join('');

  // Geo card
  let geoCard = '';
  if (r.geo && r.geo.found) {
    const g = r.geo;
    geoCard = `<div class="card">
      ${cardHeader('📍','Geolocation','var(--green)')}
      ${kv('Country', (g.country||'')+(g.country_code?` (${g.country_code})`:''))}
      ${kv('City / Region', [g.city, g.region].filter(Boolean).join(', '))}
      ${kv('ASN', g.asn, true)}
      ${kv('ISP / Org', g.org || g.isp)}
      ${kv('Timezone', g.timezone)}
      ${kv('Hosting', g.hosting ? 'Yes — datacenter/cloud' : 'No')}
      ${kv('Proxy / VPN', g.proxy ? '⚠ Detected' : 'Not detected')}
    </div>`;
  }

  // WHOIS card — always show if whois data exists (even on error)
  let whoisCard = '';
  if (r.whois) {
    const w = r.whois;

    if (!w.found) {
      // Show error or skipped state — never silently disappear
      const msg = w.error_message || w.reason || w.error || 'WHOIS lookup returned no data';
      const isErr = w.error === true;
      whoisCard = `<div class="card">
        ${cardHeader('📄','WHOIS / Registry','var(--accent)')}
        <div style="display:flex;align-items:center;gap:8px;padding:8px 0;font-size:13px;color:${isErr ? 'var(--red)' : 'var(--muted)'}">
          <span style="font-size:16px">${isErr ? '⚠' : 'ℹ'}</span>
          <span>${esc(msg)}</span>
        </div>
      </div>`;
    } else {
      // Field label map — controls order, labels, and formatting
      const fieldDefs = [
        { key: 'record_type', label: 'Record type' },
        { key: 'provider',    label: 'Data source' },
        { key: 'handle',      label: 'Handle' },
        { key: 'network',     label: 'Network range' },
        { key: 'name',        label: 'Network name' },
        { key: 'org',         label: 'Organization' },
        { key: 'registrar',   label: 'Registrar' },
        { key: 'registrant',  label: 'Registrant' },
        { key: 'country',     label: 'Country' },
        { key: 'registered',  label: 'Registered', mono: true },
        { key: 'dates',       label: 'Dates',    mono: true },
        { key: 'expires',     label: 'Expires',    mono: true },
        { key: 'updated',     label: 'Last updated', mono: true },
        { key: 'nameservers', label: 'Nameservers', mono: true },
        { key: 'status',      label: 'Status' },
        { key: 'dnssec',      label: 'DNSSEC' },
        { key: 'abuse_email', label: 'Abuse contact', mono: true },
        { key: 'type',        label: 'IP version' },
        { key: 'admin_email', label: 'Admin contact', mono: true },
        { key: 'tech_email',  label: 'Tech contact', mono: true },
      ];

      const kvRows = fieldDefs
        .filter(f => w[f.key] != null && w[f.key] !== '' && w[f.key] !== false)
        .map(f => {
          let val = w[f.key];
          // Format booleans
          if (val === true)  val = 'Yes';
          if (val === false) val = 'No';
//          return kv(f.label, esc(String(val)), f.mono || false);
          return kv(f.label, val, f.mono || false);
        })
        .join('');

      whoisCard = `<div class="card">
        ${cardHeader('📄','WHOIS / Registry','var(--accent)')}
        ${kvRows || '<div style="color:var(--muted);font-size:12px">No registry details returned</div>'}
      </div>`;
    }
  }

  // File intel card (hashes)
  let fileCard = '';
  if (r.file_intel) {
    const skip = ['tags'];
    const kvRows = Object.entries(r.file_intel)
      .filter(([k,v]) => !skip.includes(k) && v && !Array.isArray(v))
      .map(([k,v]) => kv(k.charAt(0).toUpperCase()+k.slice(1).replace(/_/g,' '), v, true))
      .join('');
    const fileTags = (r.file_intel.tags||[]).map(t=>`<span class="tag tag-red">${esc(t)}</span>`).join('');
    fileCard = `<div class="card">
      ${cardHeader('🦠','File Intelligence','var(--red)')}
      ${kvRows}
      ${fileTags ? `<div style="margin-top:8px">${fileTags}</div>` : ''}
    </div>`;
  }

  // GreyNoise card
  let gnCard = '';
  const gn = (r.ioc_results||[]).find(r => r.source==='GreyNoise' && r.found && !r.error && !r.skipped);
  if (gn) {
    const gnTags = (gn.tags||[]).map(t=>`<span class="tag tag-purple">${esc(t)}</span>`).join('');
    const cveLine = gn.cve?.length ? `<div style="margin-top:6px;font-size:11px;color:var(--red)">CVEs: ${esc(gn.cve.join(', '))}</div>` : '';
    gnCard = `<div class="card">
      ${cardHeader('📡','GreyNoise Context','var(--purple)')}
      ${kv('Classification', gn.classification)}
      ${kv('Name / Actor', gn.name)}
      ${kv('Scanner noise', gn.noise ? 'Yes — observed in background scans' : 'No')}
      ${kv('RIOT (known safe)', gn.riot ? 'Yes' : 'No')}
      ${kv('Country', gn.country)}
      ${kv('Organization', gn.organization)}
      ${kv('OS', gn.os)}
      ${kv('Last seen', gn.last_seen, true)}
      ${gnTags ? `<div style="margin-top:8px">${gnTags}</div>` : ''}
      ${cveLine}
    </div>`;
  }

  // Email Intelligence card
  let emailCard = '';
  const emailSrc = (r.ioc_results||[]).find(s => s.source === 'Email Blacklists');
  if (emailSrc) {
    emailCard = renderEmailCard(emailSrc);
  }

  // VT link
  const vtResult = (r.ioc_results||[]).find(s => s.source==='VirusTotal' && !s.error);
  const vtLink = vtResult?.vt_link ? `<a href="${esc(vtResult.vt_link)}" target="_blank" rel="noopener" style="font-size:11px;color:var(--accent);display:block;margin-top:4px">${esc(vtResult.vt_link)} ↗</a>` : '';

  return `
  <div class="summary-bar">
    <span class="sb-label">Query</span><span class="sb-val" style="color:var(--accent)">${esc(r.indicator)}</span>
    <div class="sb-div"></div>
    <span class="sb-label">Type</span><span class="sb-val">${esc(r.type)}</span>
    <div class="sb-div"></div>
    <span class="sb-label">Sources</span><span class="sb-val">${r.summary?.sources_queried||0}</span>
    <div class="sb-div"></div>
    <span class="sb-label">Queried</span><span class="sb-val">${new Date(r.queried_at).toLocaleString()}</span>
    ${histId ? `<div class="sb-export">
      <a href="api/export.php?format=pdf&id=${encodeURIComponent(histId)}" target="_blank" class="btn-ghost">⬇ PDF</a>
      <a href="api/export.php?format=json&id=${encodeURIComponent(histId)}" target="_blank" class="btn-ghost">⬇ JSON</a>
    </div>` : ''}
  </div>

  <div class="results-grid">
    <div class="card">
      ${cardHeader('🛡','Threat Score','var(--red)')}
      <div class="score-wrap">
        ${scoreRing}
        <div>
          <div class="score-risk" style="color:${riskColor}">${esc(r.risk_level)} RISK</div>
          <div class="score-detail">
            ${r.summary?.malicious_signals||0} malicious · ${r.summary?.suspicious_signals||0} suspicious<br>
            ${r.summary?.sources_matched||0}/${r.summary?.sources_queried||0} sources matched
          </div>
        </div>
      </div>
      ${vtBar}
      <div style="margin-top:10px">${tags}</div>
    </div>

    <div class="card">
      ${cardHeader('ℹ','Summary','var(--amber)')}
      ${kv('Indicator type', r.type)}
      ${kv('Risk level', `<span style="color:${riskColor};font-weight:600">${esc(r.risk_level)}</span>`)}
      ${kv('Score', r.score + ' / 100')}
      ${kv('Sources queried', r.summary?.sources_queried)}
      ${kv('Malicious signals', r.summary?.malicious_signals)}
      ${vtLink}
    </div>

    ${geoCard}${whoisCard}${fileCard}${gnCard}${emailCard}

    ${renderCustomListCard(r.custom_list_results)}

    ${renderHackerTargetCard(r.hackertarget)}

    <div class="card full-width">
      ${cardHeader('🗃','IOC Matches — All Sources','var(--purple)')}
      ${iocRows || '<div style="color:var(--muted);font-size:13px;text-align:center;padding:16px">No source results</div>'}
    </div>
  </div>`;
}

function renderEmailCard(src) {
  // src is the full Email Blacklists ioc_result object from PHP
  const ed   = src.email_data  || {};   // address, domain, mx_records, domain_age
  const er   = src.emailrep    || null; // EmailRep.io data
  const hibp = src.hibp        || null; // HaveIBeenPwned data

  // ─── Blacklist hit rows ───────────────────────────────────────────────────
  const SEV_COLOR = { high: '#f85149', medium: '#d29922', low: '#8b949e' };
  const hitRows = (src.matches || []).map(m => {
    const c = SEV_COLOR[m.severity] || 'var(--muted)';
    return `<div class="ioc-row" style="cursor:default">
      <span class="verdict-badge" style="background:${c}18;color:${c};min-width:72px;text-align:center;font-size:10px">
        ${esc((m.severity||'').toUpperCase())}
      </span>
      <span style="font-size:12px;font-weight:500;min-width:130px;color:var(--text)">${esc(m.list)}</span>
      <span style="font-size:12px;color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(m.detail)}</span>
      <span style="font-size:10px;color:var(--dim);flex-shrink:0;margin-left:8px">${esc(m.type)}</span>
    </div>`;
  }).join('');

  const noHits = !src.found
    ? `<div style="display:flex;align-items:center;gap:8px;padding:6px 0;font-size:13px;color:var(--green)">
        <span>‚úì</span><span>No blacklist matches found</span>
       </div>`
    : '';

  // ─── EmailRep Section ───────────────────────────────────────────────────
  let erepSection = '';
  if (er) {
    const repColor = er.reputation === 'high'   ? '#3fb950'
                   : er.reputation === 'medium' ? '#d29922'
                   : er.reputation === 'low'    ? '#f85149'
                   : '#8b949e';

    const flags = [
      er.blacklisted        && { label: 'Blacklisted',         color: '#f85149' },
      er.malicious_activity && { label: 'Malicious activity',  color: '#f85149' },
      er.credentials_leaked && { label: 'Credentials leaked',  color: '#f0883e' },
      er.data_breach        && { label: 'Data breach',         color: '#f0883e' },
      er.spam               && { label: 'Spam sender',         color: '#d29922' },
      er.disposable         && { label: 'Disposable address',  color: '#d29922' },
      er.free_provider      && { label: 'Free provider',       color: '#8b949e' },
    ].filter(Boolean);

    const flagHtml = flags.length
      ? flags.map(f => `<span class="tag" style="background:${f.color}18;color:${f.color}">${esc(f.label)}</span>`).join('')
      : `<span class="tag tag-green">No flags</span>`;

    const profiles = (er.profiles || []).slice(0, 6)
      .map(p => `<span class="tag tag-blue">${esc(p)}</span>`).join('');

    erepSection = `
      <div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border)">
        <div style="font-size:11px;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">EmailRep.io</div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <div style="font-size:22px;font-weight:700;color:${repColor};font-family:var(--mono)">${esc((er.reputation||'unknown').toUpperCase())}</div>
          <div style="font-size:11px;color:var(--muted);line-height:1.6">
            Reputation score<br>
            ${er.references != null ? `${er.references} reference(s) found` : ''}
          </div>
        </div>
        <div style="margin-bottom:6px">${flagHtml}</div>
        ${kv('First seen',   er.first_seen,  true)}
        ${kv('Last seen',    er.last_seen,   true)}
        ${kv('Domain age',   ed.domain_age != null ? esc(String(ed.domain_age)) : null)}
        ${profiles ? `<div style="margin-top:6px;font-size:11px;color:var(--muted)">Known profiles: ${profiles}</div>` : ''}
      </div>`;
  }

  // ─── HaveIBeenPwned Section ───────────────────────────────────────────────────
  let hibpSection = '';
  if (hibp) {
    if (hibp.breach_count === 0) {
      hibpSection = `
        <div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border)">
          <div style="font-size:11px;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">HaveIBeenPwned</div>
          <div style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--green)">
            <span>-</span><span>Not found in any known data breach</span>
          </div>
        </div>`;
    } else {
      const breachRows = (hibp.breaches || []).map(b => {
        const dataClasses = (b.data_classes || []).slice(0, 4).join(', ');
        return `<div style="padding:6px 0;border-bottom:1px solid #30363d44;font-size:12px">
          <div style="display:flex;justify-content:space-between;align-items:baseline">
            <span style="font-weight:500;color:var(--text)">${esc(b.name)}</span>
            <span style="font-size:11px;font-family:var(--mono);color:var(--muted)">${esc(b.date||'')}</span>
          </div>
          ${dataClasses ? `<div style="color:var(--muted);margin-top:2px;font-size:11px">${esc(dataClasses)}${(b.data_classes||[]).length > 4 ? '‚Ä¶' : ''}</div>` : ''}
          ${b.is_sensitive ? `<span class="tag tag-red" style="font-size:9px">Sensitive</span>` : ''}
        </div>`;
      }).join('');

      hibpSection = `
        <div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border)">
          <div style="font-size:11px;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">HaveIBeenPwned</div>
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <span style="font-size:20px;font-weight:700;font-family:var(--mono);color:var(--red)">${hibp.breach_count}</span>
            <span style="font-size:12px;color:var(--muted)">data breach${hibp.breach_count !== 1 ? 'es' : ''} found</span>
          </div>
          ${breachRows}
        </div>`;
    }
  }

  // ─── MX / Domain Section ───────────────────────────────────────────────────
  const mxRecords = (ed.mx_records || []);
  const mxHtml = mxRecords.length
    ? mxRecords.map(mx => `<span style="font-family:var(--mono);font-size:11px;display:block;color:var(--text)">${esc(mx)}</span>`).join('')
    : '<span style="font-size:12px;color:var(--muted)">No MX records found</span>';

  const domainSection = `
    <div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border)">
      <div style="font-size:11px;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Domain Intelligence</div>
      ${kv('Email address',  ed.address,    true)}
      ${kv('Local part',     ed.local_part, true)}
      ${kv('Domain',         ed.domain,     true)}
      ${kv('Domain age',     ed.domain_age)}
      <div class="kv">
        <span class="k">MX records</span>
        <span class="v" style="text-align:right">${mxHtml}</span>
      </div>
      ${src.surbl_hit ? `<div style="margin-top:6px"><span class="tag tag-red">SURBL listed</span></div>` : ''}
      ${src.dbl_hit   ? `<div style="margin-top:2px"><span class="tag tag-red">Spamhaus DBL listed</span></div>` : ''}
    </div>`;

  // ─── Assemble Card ───────────────────────────────────────────────────
  return `<div class="card full-width">
    ${cardHeader('-', 'Email Intelligence', '#f0883e')}

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:0 24px">
      <div>
        <!-- Blacklist hits -->
        <div style="font-size:11px;font-weight:500;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">
          Blacklist Results
          <span style="font-weight:400;color:var(--dim);margin-left:6px">${src.match_count || 0} hit(s)</span>
        </div>
        ${hitRows}
        ${noHits}
        ${domainSection}
      </div>
      <div>
        ${erepSection}
        ${hibpSection}
      </div>
    </div>
    </div>`;
}

function renderCustomListCard(listResults) {
  if (!listResults || listResults.length === 0) return '';

  const rows = listResults.map(l => {
    const isInfo = (l.list_scoring || 'threats') === 'information';
    if (l.found && l.matches?.length) {
      const matchItems = l.matches.slice(0, 5).map(m =>
        `<div class="ioc-match-row"><span class="mv">${esc(m)}</span><span class="mm">— matched entry</span></div>`
      ).join('');
      if (isInfo) {
        // Information list — green badge, no scoring impact
        return `<div style="margin-bottom:12px;padding-bottom:12px;border-bottom:1px solid var(--border)">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
            <span class="verdict-badge" style="font-size:10px;background:var(--green)18;color:var(--accent);border:1px solid var(--accent)40">INFORMATION</span>
            <span style="font-size:13px;font-weight:500;color:var(--text)">${esc(l.list_name)}</span>
            <span style="font-size:11px;color:var(--muted);margin-left:auto">${esc(l.list_type)} list · ${l.matches.length} match(es) · informational only</span>
          </div>
          ${matchItems}
        </div>`;
      } else {
        // Threat list — red badge, contributes to score
        return `<div style="margin-bottom:12px;padding-bottom:12px;border-bottom:1px solid var(--border)">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
            <span class="verdict-badge verdict-MALICIOUS" style="font-size:10px">THREAT</span>
            <span style="font-size:13px;font-weight:500;color:var(--text)">${esc(l.list_name)}</span>
            <span style="font-size:11px;color:var(--muted);margin-left:auto">${esc(l.list_type)} list · ${l.matches.length} match(es)</span>
          </div>
          ${matchItems}
        </div>`;
      }
    } else {
      return `<div style="margin-bottom:12px;padding-bottom:12px;border-bottom:1px solid var(--border)">
        <div style="display:flex;align-items:center;gap:8px">
          <span class="verdict-badge verdict-CLEAN" style="font-size:10px">CLEAN</span>
          <span style="font-size:13px;font-weight:500;color:var(--text)">${esc(l.list_name)}</span>
          <span style="font-size:11px;color:var(--muted);margin-left:auto">${esc(l.list_type)} list · no matches</span>
        </div>
      </div>`;
    }
  }).join('');

  return `<div class="card full-width">
    ${cardHeader('📋', 'Custom List Matches', 'var(--amber)')}
    ${rows}
  </div>`;
}

function renderHackerTargetCard(ht) {
  if (!ht) return '';

  // Always show the card for applicable indicator types, even if no data returned
  const hasError = !ht.found && ht.error_message;
  const queryNote = ht.query_note
    ? `<div style="font-size:11px;color:var(--muted);margin-bottom:10px">🔍 ${esc(ht.query_note)}</div>`
    : '';

  const SECTION_META = {
    reverse_dns:  { icon: '↩', label: 'Reverse DNS',         desc: 'PTR records for this IP' },
    reverse_ip:   { icon: '🌐', label: 'Reverse IP Lookup',   desc: 'Other domains hosted on this IP' },
    dns_records:  { icon: '📋', label: 'DNS Records',         desc: 'A, MX, NS, TXT and other records' },
    host_search:  { icon: '🔎', label: 'Hosted Domains',      desc: 'Domains sharing the same host IPs' },
  };

  let bodyHtml = '';

  if (hasError) {
    bodyHtml = `<div style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--muted);padding:6px 0">
      <span>⚠</span><span>${esc(ht.error_message)}</span>
    </div>`;
  } else if (!ht.found || !ht.sections || Object.keys(ht.sections).length === 0) {
    bodyHtml = `<div style="font-size:13px;color:var(--muted);text-align:center;padding:12px 0">No data returned from HackerTarget</div>`;
  } else {
    // Shared line renderer used for both visible and hidden rows
    const renderLine = l => {
      let display = esc(l);
      if (l.includes(',')) {
        const parts = l.split(',');
        display = `<span style="color:var(--text);font-family:var(--mono)">${esc(parts[0])}</span>`
                + (parts[1] ? `<span style="color:var(--muted);font-size:11px;margin-left:8px">${esc(parts.slice(1).join(','))}</span>` : '');
      } else if (/\sIN\s/i.test(l)) {
        const m = l.match(/^(\S+)\s+\d*\s*IN\s+(\w+)\s+(.+)$/i);
        if (m) {
          const recColors = {A:'var(--accent)',AAAA:'var(--accent)',MX:'var(--amber)',NS:'var(--purple)',TXT:'var(--green)',CNAME:'var(--orange)',SOA:'var(--muted)'};
          const rc = recColors[m[2].toUpperCase()] || 'var(--muted)';
          display = `<span style="color:var(--dim);font-family:var(--mono);font-size:11px;min-width:60px">${esc(m[1])}</span>`
                  + `<span style="background:${rc}18;color:${rc};font-size:9px;font-weight:700;padding:1px 5px;border-radius:3px;margin:0 6px;font-family:var(--mono)">${esc(m[2])}</span>`
                  + `<span style="color:var(--text);font-family:var(--mono);font-size:12px;word-break:break-all">${esc(m[3])}</span>`;
        }
      }
      return `<div style="padding:3px 0;border-bottom:1px solid var(--border);font-size:12px;display:flex;align-items:baseline;gap:4px;line-height:1.6">${display}</div>`;
    };

    bodyHtml = Object.entries(ht.sections).map(([key, lines]) => {
      const meta = SECTION_META[key] || { icon: '📄', label: key, desc: '' };
      const MAX_VISIBLE = 8;
      const visibleLines = lines.slice(0, MAX_VISIBLE);
      const hiddenLines  = lines.slice(MAX_VISIBLE);
      const hiddenCount  = hiddenLines.length;
      const sectionId    = 'ht-sec-' + key;
      const moreId       = sectionId + '-more';
      const moreLinkId   = sectionId + '-toggle';

      const lineItems    = visibleLines.map(renderLine).join('');
      const hiddenItems  = hiddenLines.map(renderLine).join('');

      const moreRow = hiddenCount > 0
        ? `<div id="${moreId}-hidden" style="display:none">${hiddenItems}</div>
           <div id="${moreLinkId}" onclick="htExpandSection('${moreId}','${moreLinkId}')"
             style="font-size:11px;color:var(--accent);padding:5px 0;cursor:pointer;user-select:none">
             ▸ show ${hiddenCount} more result${hiddenCount > 1 ? 's' : ''}
           </div>`
        : '';

      return `<div style="margin-bottom:14px" id="${sectionId}">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
          <span style="font-size:15px">${meta.icon}</span>
          <span style="font-size:13px;font-weight:600;color:var(--text)">${esc(meta.label)}</span>
          <span style="font-size:11px;color:var(--muted)">${esc(meta.desc)}</span>
          <span style="margin-left:auto;font-size:11px;color:var(--dim);font-family:var(--mono)">${lines.length} record${lines.length !== 1 ? 's' : ''}</span>
        </div>
        <div style="background:var(--bg2);border-radius:6px;padding:6px 10px">
          ${lineItems}
          ${moreRow}
        </div>
      </div>`;
    }).join('');
  }

  // Info banner
  const infoBanner = `<div style="margin-top:10px;padding:7px 11px;background:rgba(88,166,255,.06);border-radius:6px;font-size:11px;color:var(--muted)">
    ℹ️ HackerTarget data is <strong style="color:var(--text)">informational only</strong> — it does not affect the threat score.
    ${ht.query_target && ht.query_target !== (ht.indicator || ht.query_target) ? `Query target: <code style="font-size:11px">${esc(ht.query_target)}</code>` : ''}
  </div>`;

  return `<div class="card full-width">
    ${cardHeader('🎯', 'HackerTarget Intelligence', 'var(--accent)')}
    ${queryNote}
    ${bodyHtml}
    ${infoBanner}
  </div>`;
}

function htExpandSection(moreId, linkId) {
  const hidden = document.getElementById(moreId + '-hidden');
  const link   = document.getElementById(linkId);
  if (!hidden || !link) return;
  hidden.style.display = 'block';
  link.style.display   = 'none';
}

function renderIocRow(src) { 
  const verdict = src.error ? 'ERROR' : (src.skipped ? 'SKIPPED' : (src.verdict || 'N/A'));
  const summary = esc(src.summary || src.error_message || (src.skipped ? src.reason : (src.found ? 'Match found' : 'No match')));
  const hasMatches = src.matches && src.matches.length > 0;
  const rowId = 'ioc-' + src.source.replace(/\s/g,'');

  let detailHtml = '';
  if (hasMatches) {
    detailHtml = `<div class="ioc-detail-box" id="${rowId}-detail" style="display:none">` +
      src.matches.slice(0, 5).map(m => {
        const val = m.value || m.indicator || m.result || '';
        const info = m.event_info || m.description || ' ';
        const cat = m.category || m.details || m.detail || ' ';
        const tags = (m.tags || []).slice(0,3).map(t=>`<span class="tag tag-purple" style="font-size:9px">${esc(t)}</span>`).join('');
        return `<div class="ioc-match-row"><span class="mv">${esc(val)}</span>${info?`<span class="mm">— ${esc(info)}</span>`:''}${cat?`<span class="mi">[ ${cat} ]</span>`:''}${tags}</div>`;
      }).join('') +
      '</div>';
  }

  return `
    <div class="ioc-row" onclick="${hasMatches ? `toggleIocDetail('${rowId}')` : ''}">
      <span class="verdict-badge verdict-${verdict}">${verdict}</span>
      <span class="ioc-source">${esc(src.source)}</span>
      <span class="ioc-summary">${summary}</span>
      ${hasMatches ? `<span class="ioc-expand-count" id="${rowId}-toggle">▼ ${src.matches.length}</span>` : ''}
    </div>
    ${detailHtml}`;
}

function toggleIocDetail(rowId) {
  const box    = document.getElementById(rowId + '-detail');
  const toggle = document.getElementById(rowId + '-toggle');
  if (!box) return;
  const open = box.style.display !== 'none';
  box.style.display = open ? 'none' : 'block';
  if (toggle) toggle.textContent = (open ? '▼' : '▲') + toggle.textContent.slice(1);
}

function cardHeader(icon, title, color) {
  return `<div class="card-header">
    <div class="card-icon" style="background:${color}18;color:${color}">${icon}</div>
    <span class="card-title">${esc(title)}</span>
  </div>`;
}

function kv(label, value, mono = false) {
  if (!value && value !== 0) return '';
  return `<div class="kv">
    <span class="k">${esc(label)}</span>
    <span class="v${mono?' mono':''}">${value}</span>
  </div>`;
}

// ─── History ───────────────────────────────────────────────────
async function loadHistory() {
  const el    = document.getElementById('history-list');
  const count = document.getElementById('history-count');

  // Element only exists in the history view ‚ skip if not rendered yet
  if (!el) return;

  if (count) count.textContent = 'Loading‚';
  el.innerHTML = `<div style="text-align:center;padding:40px 0;color:var(--muted)">
    <div class="dots-loader"><div></div><div></div><div></div></div>
  </div>`;

  try {
    const data = await apiFetch('api/history.php?limit=100');
    App.historyItems = data.items || [];
    renderHistoryList(App.historyItems);
  } catch(e) {
    if (count) count.textContent = 'Error loading history';
    el.innerHTML = `<div class="error-box">Failed to load history: ${esc(e.message)}<br>
      <small style="color:var(--muted)">Check that the <code>data/</code> directory exists and is writable by the web server.</small>
    </div>`;
  }
}

function filterHistory() {
  const query  = (document.getElementById('hist-filter')?.value || '').toLowerCase();
  const type   = document.getElementById('hist-type')?.value || '';
  const items  = App.historyItems.filter(i =>
    (!query || i.query.toLowerCase().includes(query) || (i.user||'').toLowerCase().includes(query)) &&
    (!type  || i.query_type === type)
  );
  renderHistoryList(items);
}

function renderHistoryList(items) {
  const count = document.getElementById('history-count');
  if (count) count.textContent = `${items.length} lookup${items.length !== 1 ? 's' : ''} recorded`;

  const el = document.getElementById('history-list');
  if (!el) return;

  if (!items.length) {
    el.innerHTML = `<div class="empty-state"><div class="empty-icon">📋</div><div>No history yet. Run a lookup to see results here.</div></div>`;
    return;
  }

  el.innerHTML = `<div class="history-list">` + items.map(item => {
    const riskColor = RISK_COLORS[item.risk_level] || '#8b949e';
    const ts = new Date(item.timestamp).toLocaleString();
    return `
      <div class="history-item" id="hist-${esc(item.id)}">
        <div class="history-row" onclick="toggleHistDetail('${esc(item.id)}')">
          <div class="hist-score-box" style="background:${riskColor}18;color:${riskColor}">${item.score??'—'}</div>
          <div class="hist-info">
            <div class="hist-query">${esc(item.query)}</div>
            <div class="hist-meta">${esc(item.query_type)} · ${esc(item.user)} · ${esc(ts)}</div>
          </div>
          <div class="hist-badges">
            <span class="risk-badge risk-${esc(item.risk_level)}">${esc(item.risk_level)}</span>
            ${item.malicious_signals > 0 ? `<span class="verdict-badge verdict-MALICIOUS">⚠ ${item.malicious_signals} malicious</span>` : ''}
            <button class="hist-replay" onclick="event.stopPropagation();replayLookup('${esc(item.query)}')">↩ Replay</button>
            <span class="hist-expand" id="hist-expand-${esc(item.id)}">▼</span>
          </div>
        </div>
        <div class="history-detail" id="hist-detail-${esc(item.id)}" style="display:none">
          <div style="color:var(--muted);font-size:12px;padding:12px 0;text-align:center" id="hist-loading-${esc(item.id)}">Loading…</div>
        </div>
      </div>`;
  }).join('') + '</div>';
}

async function toggleHistDetail(id) {
  const detail  = document.getElementById(`hist-detail-${id}`);
  const expander= document.getElementById(`hist-expand-${id}`);
  if (!detail) return;

  const isOpen = detail.style.display !== 'none';
  detail.style.display = isOpen ? 'none' : 'block';
  if (expander) expander.textContent = isOpen ? '▼' : '▲';

  if (!isOpen && detail.dataset.loaded !== 'true') {
    detail.dataset.loaded = 'true';
    try {
      const full = await apiFetch(`api/history.php?id=${encodeURIComponent(id)}`);
      const r = full.result;
      detail.innerHTML = `<div style="margin-top:12px">${renderResults(r)}</div>`;
    } catch(e) {
      detail.innerHTML = `<div class="error-box" style="margin-top:12px">Failed to load: ${esc(e.message)}</div>`;
    }
  }
}

async function clearHistory() {
  if (!confirm('Clear all history entries?')) return;
  try {
    await apiFetch('api/history.php', { method: 'DELETE' });
    App.historyItems = [];
    renderHistoryList([]);
  } catch(e) { alert('Failed: ' + e.message); }
}

function exportCSV() {
  window.open('api/export.php?format=csv', '_blank');
}

function replayLookup(query) {
  document.getElementById('query-input').value = query;
  updateTypeBadge();
  switchView('lookup', document.querySelector('[data-view="lookup"]'));
  doLookup();
}

// ─── Settings ──────────────────────────────────────────────────
const SOURCE_CONFIGS = [
  {
    key: 'misp', label: 'MISP', icon: '🔴', color: 'var(--red)',
    desc: 'MISP threat intelligence sharing platform',
    fields: [
      { key: 'url',        label: 'Instance URL',    type: 'url',      placeholder: 'https://misp.yourorg.local' },
      { key: 'api_key',   label: 'API Key',          type: 'password', placeholder: '••••••••••••••••••••••••••••••' },
      { key: 'verify_ssl',label: 'Verify SSL',       type: 'bool' },
    ]
  },
  {
    key: 'elasticsearch', label: 'Elasticsearch', icon: '🔵', color: 'var(--accent)',
    desc: 'Elasticsearch IOC index',
    fields: [
      { key: 'url',      label: 'Cluster URL',   type: 'url',      placeholder: 'https://elastic.yourorg.local:9200' },
      { key: 'api_key', label: 'API Key',        type: 'password', placeholder: 'Base64-encoded API key' },
      { key: 'index',   label: 'Index Pattern',  type: 'text',     placeholder: 'ioc-*' },
    ]
  },
  {
    key: 'virustotal', label: 'VirusTotal', icon: '🦠', color: '#4a6cf7',
    desc: 'File, URL, domain, and IP analysis',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'password', placeholder: '64-character VirusTotal API key' },
    ]
  },
  {
    key: 'greynoise', label: 'GreyNoise', icon: '📡', color: 'var(--purple)',
    desc: 'Internet scan noise and IP context intelligence',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'password', placeholder: 'GreyNoise API key' },
    ]
  },
  {
    key: 'geoip', label: 'GeoIP', icon: '🌍', color: 'var(--green)',
    desc: 'IP geolocation enrichment (ip-api.com is free, no key required)',
    fields: [
      { key: 'provider',    label: 'Provider',         type: 'select', options: ['ipapi','maxmind'] },
      { key: 'maxmind_key', label: 'MaxMind Account ID:License', type: 'password', placeholder: 'AccountID:LicenseKey (MaxMind only)' },
    ]
  },
  {
    key: 'hibp', label: 'HiBP', icon: '🌍', color: 'var(--green)',
    desc: 'HaveiBeenPwnd key required',
    fields: [
      { key: 'api_key', label: 'API Key', type: 'password', placeholder: 'HiBP API Key' },
    ]
  },
  {
    key: 'hackertarget', label: 'HackerTarget', icon: '🎯', color: 'var(--accent)',
    desc: 'DNS, reverse IP & host search — informational enrichment (no threat scoring). Free tier works without a key; register at hackertarget.com for higher rate limits.',
    fields: [
      { key: 'api_key', label: 'API Key (optional)', type: 'password', placeholder: 'HackerTarget registered API key — leave blank for free tier' },
    ]
  },
];

async function loadSettings() {
  try {
    App.settings = await apiFetch('api/settings.php');
    App.settingsDraft = JSON.parse(JSON.stringify(App.settings));
    renderSettingsPanels();

    renderStorageDiagnostic(App.settings._diagnostics);

  } catch(e) {
    const stordiag = document.getElementById('storage-diagnostic');
    if (stordiag) {
      stordiag.innerHTML = `<div style="background:#f8514920;border:1px solid #f8514950;border-radius:7px;
        padding:11px 16px;margin-bottom:12px;font-size:12px;color:#f85149;line-height:1.6">
        ⚠ <strong>Could not load settings:</strong> ${esc(e.message)} ${JSON.stringify(App.settings)}
      </div>`;
    }
  }
}

function renderStorageDiagnostic(diag) {
  const stordiag = document.getElementById('storage-diagnostic');
  if (!stordiag) return;

  if (!diag) {
    stordiag.innerHTML = 'No diag';
    return;
  }

  const writable = diag.data_dir_writable;

  // Use hardcoded hex colours — CSS var() cannot be concatenated with hex opacity
  const bgColour     = writable ? '#3fb95018' : '#f8514920';
  const borderColour = writable ? '#3fb95050' : '#f8514950';
  const textColour   = writable ? '#3fb950'   : '#f85149';
  const icon         = writable ? '✓' : '⚠';

  let statusMsg;
  if (writable) {
    const count = diag.history_count;
    statusMsg = `Writable &mdash; history saving is active
      <span style="color:#8b949e;margin-left:8px">(${count} entr${count === 1 ? 'y' : 'ies'} stored)</span>`;
  } else {
    const dir     = esc(diag.data_dir);
    const phpUser = esc(diag.php_user || 'www-data');
    const exists  = diag.data_dir_exists;
    statusMsg = `<strong>NOT WRITABLE &mdash; history will not be saved.</strong>
      <br>Run on the server as root:
      <br><code style="font-size:11px;background:#0d111780;padding:3px 7px;border-radius:4px;display:inline-block;margin-top:4px">
        ${exists ? '' : `mkdir -p ${dir} &amp;&amp; `}chown ${phpUser} ${dir} &amp;&amp; chmod 750 ${dir}
      </code>
      <br><span style="color:#8b949e;font-size:11px;margin-top:4px;display:block">
        PHP is running as: <strong>${phpUser}</strong> &nbsp;|&nbsp; Path: ${dir}
      </span>`;
  }

  stordiag.innerHTML = `<div style="
      background:${bgColour};
      border:1px solid ${borderColour};
      border-radius:7px;
      padding:12px 16px;
      margin-bottom:14px;
      font-size:12px;
      color:${textColour};
      line-height:1.8">
    <strong>${icon} History storage directory:</strong>
    &nbsp;${statusMsg}
  </div>`;
}

function renderCustomListSettings(lists) {
  if (!lists || lists.length === 0) {
    return `<div class="settings-source-card">
      <div class="settings-card-header">
        <div class="settings-card-title">
          <div class="settings-icon" style="background:var(--amber)15">📋</div>
          <div>
            <div class="settings-name">Custom Lists</div>
            <div class="settings-desc">User-defined threat indicator lists loaded from URLs</div>
          </div>
        </div>
      </div>
      <div style="padding:12px 0;font-size:13px;color:var(--muted)">
        No custom lists configured. Add entries to the <code>CUSTOM_LISTS</code> array in <code>config.php</code>.
      </div>
    </div>`;
  }

  const TYPE_COLORS = {
    IP:     { color: 'var(--accent)',  bg: 'rgba(88,166,255,.12)' },
    Domain: { color: 'var(--green)',   bg: 'rgba(63,185,80,.12)' },
    Email:  { color: 'var(--orange)',  bg: 'rgba(240,136,62,.12)' },
    Hash:   { color: 'var(--purple)',  bg: 'rgba(188,140,255,.12)' },
  };

  const rows = lists.map(l => {
    const tc = TYPE_COLORS[l.type?.toUpperCase()] || { color: 'var(--muted)', bg: 'rgba(139,148,158,.12)' };
    return `<div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid var(--border);font-size:13px">
      <span style="background:${tc.bg};color:${tc.color};font-size:10px;font-family:var(--mono);font-weight:600;padding:2px 7px;border-radius:4px;min-width:54px;text-align:center">${esc(l.type?.toUpperCase())}</span>
      <span style="font-weight:500;color:var(--text);min-width:180px">${esc(l.name)}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(l.url)}">${esc(l.url)}</span>
    </div>`;
  }).join('');

  return `<div class="settings-source-card">
    <div class="settings-card-header">
      <div class="settings-card-title">
        <div class="settings-icon" style="background:var(--amber)15">📋</div>
        <div>
          <div class="settings-name">Custom Lists</div>
          <div class="settings-desc">User-defined threat indicator lists loaded from URLs — edit <code>config.php</code> to modify</div>
        </div>
      </div>
      <span style="font-size:12px;color:var(--muted)">${lists.length} list${lists.length !== 1 ? 's' : ''} configured</span>
    </div>
    <div style="padding:4px 0">
      <div style="display:flex;gap:12px;padding:6px 0;border-bottom:1px solid var(--border);margin-bottom:4px">
        <span style="font-size:11px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.05em;min-width:54px">Type</span>
        <span style="font-size:11px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.05em;min-width:180px">Name</span>
        <span style="font-size:11px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.05em">URL</span>
      </div>
      ${rows}
    </div>
    <div style="margin-top:10px;padding:8px 12px;background:rgba(88,166,255,.06);border-radius:6px;font-size:12px;color:var(--muted);line-height:1.6">
      💡 <strong style="color:var(--text)">Scoring:</strong> <br />1 match raises threat level to <strong>Suspicious</strong>. <br /> 2+ matches raises it to <strong>Malicious</strong>.
    </div>
  </div>`;
}

function renderSettingsPanels() {
  const wrap = document.getElementById('settings-panels');
  if (!wrap) return;

  wrap.innerHTML = SOURCE_CONFIGS.map(src => {
    const vals = App.settingsDraft[src.key] || {};
    const fields = src.fields.map(f => {
      if (f.type === 'bool') {
        return `<div class="settings-field-full" style="display:flex;align-items:center;gap:8px">
          <input type="checkbox" id="s-${src.key}-${f.key}" ${vals[f.key] ? 'checked' : ''} onchange="patchSetting('${src.key}','${f.key}',this.checked)" style="width:16px;height:16px;accent-color:var(--accent)">
          <label for="s-${src.key}-${f.key}" style="font-size:13px;color:var(--muted);cursor:pointer">${esc(f.label)}</label>
        </div>`;
      }
      if (f.type === 'select') {
        const opts = f.options.map(o => `<option value="${esc(o)}" ${vals[f.key]===o?'selected':''}>${esc(o)}</option>`).join('');
        return `<div><label class="form-label">${esc(f.label)}</label>
          <select class="form-input" id="s-${src.key}-${f.key}" onchange="patchSetting('${src.key}','${f.key}',this.value)">${opts}</select></div>`;
      }
      return `<div><label class="form-label">${esc(f.label)}</label>
        <input class="form-input" type="text" id="s-${src.key}-${f.key}"
          value="${esc(vals[f.key]||'')}" placeholder="${esc(f.placeholder||'')}"
          oninput="patchSetting('${src.key}','${f.key}',this.value)" readonly></div>`;
    }).join('');

    const canTest = ['misp','elasticsearch','virustotal','greynoise','hibp','hackertarget'].includes(src.key);
    return `
      <div class="settings-source-card">
        <div class="settings-card-header">
          <div class="settings-card-title">
            <div class="settings-icon" style="background:${src.color}15">${src.icon}</div>
            <div>
              <div class="settings-name">${esc(src.label)}</div>
              <div class="settings-desc">${esc(src.desc)}</div>
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:8px">
            <span class="test-result" id="test-result-${src.key}"></span>
            ${canTest ? `<button class="btn-ghost" onclick="testSource('${src.key}')">Test connection</button>` : ''}
          </div>
        </div>
        <div class="settings-fields">${fields}</div>
      </div>`;
  }).join('');

  // Append Custom Lists section
  const customLists = App.settings?.custom_lists || [];
  wrap.innerHTML += renderCustomListSettings(customLists);
}

function patchSetting(source, field, value) {
  if (!App.settingsDraft[source]) App.settingsDraft[source] = {};
  App.settingsDraft[source][field] = value;
}

async function saveSettings() {
  const btn = document.querySelector('[onclick="saveSettings()"]');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
  try {
    await apiFetch('api/settings.php?action=save', {
      method: 'POST',
      body: JSON.stringify(App.settingsDraft),
    });
    const ok = document.getElementById('save-ok');
    if (ok) { ok.style.display = 'inline'; setTimeout(() => ok.style.display = 'none', 3000); }
    loadSourceStatus();
    App.settings = await apiFetch('api/settings.php');
  } catch(e) {
    alert('Save failed: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Save Settings'; }
  }
}

async function testSource(source) {
  const el = document.getElementById(`test-result-${source}`);
  if (el) { el.className = 'test-result test-ing'; el.textContent = 'Saving & testing…'; }

  // Save current draft first so test uses latest values
  try { await apiFetch('api/settings.php?action=save', { method: 'POST', body: JSON.stringify(App.settingsDraft) }); } catch(e) {}

  try {
    const data = await apiFetch(`api/settings.php?action=test&source=${encodeURIComponent(source)}`, { method: 'POST' });
    if (el) {
      el.className = 'test-result ' + (data.success ? 'test-ok' : 'test-err');
      el.textContent = (data.success ? '✓ ' : '✗ ') + (data.message || '');
    }
  } catch(e) {
    if (el) { el.className = 'test-result test-err'; el.textContent = '✗ ' + e.message; }
  }
}
