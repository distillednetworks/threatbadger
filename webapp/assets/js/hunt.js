// ============================================================
//  ThreatBadger — assets/js/hunt.js
//  All Hunt page logic: search, rendering, expand/collapse
//  Depends on: app.js (esc, detectType, apiFetch)
// ============================================================

'use strict';

// ─── State ────────────────────────────────────────────────────
const Hunt = {
  indicator  : '',
  type       : null,
  index      : 'logs-*',
  source     : 'elasticsearch',  // 'elasticsearch' | 'fortianalyzer'
  total      : 0,
  from       : 0,
  size       : 25,
  loading    : false,
  timeMode   : 'relative',   // 'relative' | 'absolute'
  relValue   : 30,
  relUnit    : 'd',
  absFrom    : null,
  absTo      : null,
};

const HUNT_SOURCE_TEXT = {
  elasticsearch: {
    pageSub:  'Search your log Elasticsearch cluster for any indicator across standard ECS fields — network, DNS, HTTP, file, process, and more',
    emptySub: 'Searches standard ECS fields — source.ip · destination.ip · dns.question.name · url.domain · file.hash.* · and more',
  },
  fortianalyzer: {
    pageSub:  'Search a FortiAnalyzer instance for IPv4/IPv6 or Domain indicators',
    emptySub: 'IPv4/IPv6 indicators search Traffic + VPN logs (source/destination IP, or VPN remote/assigned IP). Domains search DNS + Web Filter logs.',
  },
};

// ─── Log source toggle ─────────────────────────────────────────
function huntSetSource(source) {
  if (source !== 'elasticsearch' && source !== 'fortianalyzer') return;
  Hunt.source = source;

  document.querySelectorAll('#hunt-source-toggle .source-badge').forEach(badge => {
    const selected = badge.getAttribute('data-hunt-source') === source;
    badge.classList.toggle('selected', selected);
    badge.classList.toggle('deselected', !selected);
  });

  const indexGroup = document.getElementById('hunt-index-group');
  if (indexGroup) indexGroup.style.display = source === 'elasticsearch' ? '' : 'none';

  const adomGroup   = document.getElementById('hunt-faz-adom-group');
  const deviceGroup = document.getElementById('hunt-faz-device-group');
  const fazDisplay  = source === 'fortianalyzer' ? '' : 'none';
  if (adomGroup)   adomGroup.style.display   = fazDisplay;
  if (deviceGroup) deviceGroup.style.display = fazDisplay;

  const text = HUNT_SOURCE_TEXT[source];
  const pageSub  = document.getElementById('hunt-page-sub');
  const emptySub = document.getElementById('hunt-empty-sub');
  if (pageSub)  pageSub.textContent  = text.pageSub;
  if (emptySub) emptySub.textContent = text.emptySub;

  // Results from the previous source no longer apply — reset the view.
  document.getElementById('hunt-error').style.display   = 'none';
  document.getElementById('hunt-results').style.display = 'none';
  document.getElementById('hunt-empty').style.display   = 'block';
}

// ─── Kick off a hunt ──────────────────────────────────────────
async function doHunt(resetPage) {
  if (Hunt.loading) return;

  const q   = document.getElementById('hunt-input').value.trim();
  const idx = document.getElementById('hunt-index').value.trim() || 'logs-*';
  const fazAdom   = document.getElementById('hunt-faz-adom').value.trim() || 'root';
  const fazDevice = document.getElementById('hunt-faz-device').value.trim();

  if (!q) { huntShowError('Enter an indicator to hunt for.'); return; }

  const type = detectType(q);
  if (!type) { huntShowError('Cannot detect indicator type — check your input.'); return; }

  // ── Resolve time range ──────────────────────────────────────
  const timeRange = huntBuildTimeRange();
  if (!timeRange) return; // huntBuildTimeRange() shows its own error

  if (resetPage !== false) Hunt.from = 0;
  Hunt.indicator = q;
  Hunt.type      = type;
  Hunt.index     = idx;
  Hunt.loading   = true;

  huntUpdateTypeBadge(q, type);
  document.getElementById('hunt-error').style.display   = 'none';
  document.getElementById('hunt-empty').style.display   = 'none';
  document.getElementById('hunt-results').style.display = 'none';
  document.getElementById('hunt-loading').style.display = 'block';
  document.getElementById('hunt-btn').disabled           = true;

  try {
    const data = await apiFetch('api/hunt.php', {
      method : 'POST',
      body   : JSON.stringify({
        indicator  : q,
        index      : idx,
        source     : Hunt.source,
        adom       : fazAdom,
        device     : fazDevice,
        from       : Hunt.from,
        size       : Hunt.size,
        time_from  : timeRange.from,
        time_to    : timeRange.to,
      }),
    });
    renderHuntResults(data);
  } catch(e) {
    const cfgHint = Hunt.source === 'fortianalyzer' ? 'FortiAnalyzer' : 'Hunt Elasticsearch';
    huntShowError(e.message || `Hunt request failed. Check your ${cfgHint} configuration.`);
  } finally {
    Hunt.loading = false;
    document.getElementById('hunt-loading').style.display = 'none';
    document.getElementById('hunt-btn').disabled           = false;
  }
}

// ─── Render the full results panel ────────────────────────────
function renderHuntResults(data) {
  const wrap = document.getElementById('hunt-results');
  const hits = data.hits || [];

  if (hits.length === 0) {
    const empty = document.getElementById('hunt-empty');
    empty.style.display = 'block';
    empty.innerHTML = `
      <div class="empty-icon">🔍</div>
      <div>No log matches found</div>
      <div class="empty-sub">
        Searched <code>${esc(data.index)}</code> for
        <code>${esc(data.indicator)}</code>
        ${data.took_ms != null ? '— took ' + data.took_ms + 'ms' : ''}
      </div>`;
    return;
  }

  const shownFrom = data.from + 1;
  const shownTo   = Math.min(data.from + hits.length, data.total);
  const totalFmt  = (data.total || 0).toLocaleString();

  const hasPrev = data.from > 0;
  const hasNext = shownTo < data.total;

  const pager = (data.total > data.size) ? `
    <div class="hunt-pager">
      <span class="hunt-pager-info">
        ${shownFrom.toLocaleString()}–${shownTo.toLocaleString()} of ${totalFmt} matches
      </span>
      <button class="btn-ghost hunt-pager-btn" onclick="huntPage(-1)" ${hasPrev ? '' : 'disabled'}>← Prev</button>
      <button class="btn-ghost hunt-pager-btn" onclick="huntPage(1)"  ${hasNext ? '' : 'disabled'}>Next →</button>
    </div>` : '';

  wrap.innerHTML = `
    <div class="card" style="margin-bottom:8px">
      <div class="hunt-result-header">
        <div class="hunt-result-meta">
          <span style="font-size:16px">🎯</span>
          <div>
            <div class="hunt-result-title">
              <code class="hunt-indicator-val">${esc(data.indicator)}</code>
              <span class="hunt-indicator-type">${esc(data.type)}</span>
            </div>
            <div class="hunt-result-subtitle">
              index&nbsp;<code>${esc(data.index)}</code>
              &nbsp;·&nbsp;
              <span class="hunt-time-range-pill">${esc(huntFormatTimeRange(data.time_from, data.time_to))}</span>
              ${data.took_ms != null ? `&nbsp;·&nbsp;${data.took_ms}ms` : ''}
            </div>
          </div>
        </div>
        <div class="hunt-total-badge">${totalFmt}&nbsp;hit${data.total !== 1 ? 's' : ''}</div>
      </div>
    </div>

    <div id="hunt-hit-list">
      ${hits.map((hit, i) => renderHuntRow(hit, i)).join('')}
    </div>
    ${pager}`;

  wrap.style.display = 'block';
}

// ─── Single collapsed hit row ─────────────────────────────────
function renderHuntRow(hit, i) {
  const src = hit.source || {};
  const detailId = 'hd-' + i;

  // --- timestamp ---
  const ts = hit.timestamp
    ? new Date(hit.timestamp).toLocaleString(undefined, {
        year:'2-digit', month:'2-digit', day:'2-digit',
        hour:'2-digit', minute:'2-digit', second:'2-digit',
        hour12: false })
    : '—';

  // --- key surface fields ---
  const srcIp  = src.source?.ip      || src.src_ip  || '';
  const dstIp  = src.destination?.ip || src.dst_ip  || '';
  const evtCat = [].concat(src.event?.category || []).slice(0,2).join(', ');
  const evtAct = src.event?.action   || '';
  const hostN  = src.host?.hostname  || src.host?.name || '';
  const dsName = src.data_stream?.dataset || hit._index.split('-')[0] || '';

  // direction pill: src → dst
  const dirPill = (srcIp || dstIp) ? `
    <span class="hunt-net-flow">
      ${srcIp ? `<span class="hunt-ip src">${esc(srcIp)}</span>` : ''}
      ${srcIp && dstIp ? '<span class="hunt-arrow">→</span>' : ''}
      ${dstIp ? `<span class="hunt-ip dst">${esc(dstIp)}</span>` : ''}
    </span>` : '';

  const kibanaBtn = hit.kibana_link
    ? `<a href="${esc(hit.kibana_link)}" target="_blank" rel="noopener"
          class="hunt-kibana-link" onclick="event.stopPropagation()">↗ Kibana</a>`
    : '';

  return `
    <div class="hunt-hit-card" onclick="huntToggleDetail('${detailId}', this)">
      <div class="hunt-hit-summary">
        <span class="hunt-chevron" id="chev-${detailId}">▶</span>
        <span class="hunt-ts mono">${esc(ts)}</span>
        ${dsName  ? `<span class="tag tag-blue hunt-tag">${esc(dsName)}</span>` : ''}
        ${evtCat  ? `<span class="tag tag-purple hunt-tag">${esc(evtCat)}</span>` : ''}
        ${evtAct  ? `<span class="hunt-action">${esc(evtAct)}</span>` : ''}
        ${dirPill}
        ${hostN   ? `<span class="hunt-host">${esc(hostN)}</span>` : ''}
        <span class="hunt-grow"></span>
        ${kibanaBtn}
      </div>
      <div id="${detailId}" class="hunt-hit-detail" style="display:none">
        ${renderHuntDetail(hit)}
      </div>
    </div>`;
}

// ─── Expanded detail: sectioned KV grid + raw JSON ───────────
function renderHuntDetail(hit) {
  const src = hit.source || {};

  const sections = huntFlattenSource(src);

  const secHtml = sections.map(sec => `
    <div class="hunt-section">
      <div class="hunt-sec-label">${esc(sec.label)}</div>
      ${sec.rows.map(r => `
        <div class="kv">
          <span class="k">${esc(r.key)}</span>
          <span class="v mono">${esc(r.val)}</span>
        </div>`).join('')}
    </div>`).join('');

  const rawJson = JSON.stringify(src, null, 2)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  const idxInfo = `_index: <b>${esc(hit._index)}</b>  _id: <b>${esc(hit._id)}</b>`;

  return `
    <div class="hunt-detail-inner">
      <div class="hunt-sections-grid">${secHtml}</div>
      <details class="hunt-raw-wrap">
        <summary class="hunt-raw-toggle">
          { } Raw document &nbsp;·&nbsp; <span style="color:var(--dim)">${idxInfo}</span>
        </summary>
        <pre class="hunt-raw-pre">${rawJson}</pre>
      </details>
    </div>`;
}

// ─── Flatten ECS _source into labelled sections ───────────────
const ECS_GROUPS = [
  { key:'@timestamp',   label:'Timestamp'   },
  { key:'message',      label:'Message'     },
  { key:'event',        label:'Event'       },
  { key:'source',       label:'Source'      },
  { key:'destination',  label:'Destination' },
  { key:'network',      label:'Network'     },
  { key:'dns',          label:'DNS'         },
  { key:'http',         label:'HTTP'        },
  { key:'url',          label:'URL'         },
  { key:'tls',          label:'TLS'         },
  { key:'email',        label:'Email'       },
  { key:'file',         label:'File'        },
  { key:'process',      label:'Process'     },
  { key:'host',         label:'Host'        },
  { key:'user',         label:'User'        },
  { key:'agent',        label:'Agent'       },
  { key:'log',          label:'Log'         },
  { key:'threat',       label:'Threat'      },
  { key:'rule',         label:'Rule'        },
  { key:'signal',       label:'Signal'      },
  { key:'data_stream',  label:'Data Stream' },
  { key:'tags',         label:'Tags'        },
  { key:'labels',       label:'Labels'      },
];

function huntFlattenSource(src) {
  const seen = new Set();
  const out  = [];

  for (const g of ECS_GROUPS) {
    if (!(g.key in src)) continue;
    seen.add(g.key);
    const rows = huntBuildRows(g.key, src[g.key]);
    if (rows.length) out.push({ label: g.label, rows });
  }

  // Catch anything outside the known groups
  const extraRows = [];
  for (const [k, v] of Object.entries(src)) {
    if (!seen.has(k)) extraRows.push(...huntBuildRows(k, v));
  }
  if (extraRows.length) out.push({ label: 'Other', rows: extraRows });

  return out;
}

function huntBuildRows(prefix, val, depth) {
  depth = depth || 0;
  if (depth > 6) return [{ key: prefix, val: JSON.stringify(val) }];
  if (val === null || val === undefined) return [];
  if (typeof val === 'object' && !Array.isArray(val)) {
    const rows = [];
    for (const [k, v] of Object.entries(val)) {
      rows.push(...huntBuildRows(prefix + '.' + k, v, depth + 1));
    }
    return rows;
  }
  if (Array.isArray(val)) {
    if (val.every(v => typeof v !== 'object' || v === null)) {
      return [{ key: prefix, val: val.join(', ') }];
    }
    return val.flatMap((v, i) => huntBuildRows(prefix + '[' + i + ']', v, depth + 1));
  }
  return [{ key: prefix, val: String(val) }];
}

// ─── Toggle expand / collapse ─────────────────────────────────
function huntToggleDetail(detailId, cardEl) {
  if (event && event.target.closest('a')) return; // don't trap link clicks
  const detail = document.getElementById(detailId);
  const chev   = document.getElementById('chev-' + detailId);
  if (!detail) return;
  const isOpen = detail.style.display !== 'none';
  detail.style.display = isOpen ? 'none' : 'block';
  if (chev)   chev.textContent = isOpen ? '▶' : '▼';
  if (cardEl) cardEl.classList.toggle('hunt-hit-card--open', !isOpen);
}

// ─── Pagination ───────────────────────────────────────────────
function huntPage(dir) {
  Hunt.from = Math.max(0, Hunt.from + dir * Hunt.size);
  doHunt(false);
  document.getElementById('view-hunt').scrollTop = 0;
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ─── Type badge on the hunt input ─────────────────────────────
function huntUpdateTypeBadge(q, type) {
  const wrap = document.getElementById('hunt-type-badge');
  if (!wrap) return;
  if (!type) { wrap.innerHTML = ''; return; }
  const C = {
    'IPv4 Address' : { c:'var(--accent)', bg:'rgba(88,166,255,.12)'  },
    'IPv6 Address' : { c:'var(--accent)', bg:'rgba(88,166,255,.12)'  },
    'Domain'       : { c:'var(--green)',  bg:'rgba(63,185,80,.12)'   },
    'Email Address': { c:'var(--orange)', bg:'rgba(240,136,62,.12)'  },
    'MD5 Hash'     : { c:'var(--purple)', bg:'rgba(188,140,255,.12)' },
    'SHA-1 Hash'   : { c:'var(--purple)', bg:'rgba(188,140,255,.12)' },
    'SHA-256 Hash' : { c:'var(--purple)', bg:'rgba(188,140,255,.12)' },
  };
  const s = C[type] || { c:'var(--muted)', bg:'rgba(139,148,158,.1)' };
  wrap.innerHTML = `<span style="font-size:10px;font-family:var(--mono);padding:2px 8px;
    border-radius:3px;background:${s.bg};color:${s.c}">${esc(type)}</span>`;
}

function huntUpdateTypeBadgeFromInput() {
  const q = (document.getElementById('hunt-input') || {}).value || '';
  huntUpdateTypeBadge(q.trim(), detectType(q.trim()));
}

// ─── Error display ────────────────────────────────────────────
function huntShowError(msg) {
  document.getElementById('hunt-loading').style.display  = 'none';
  document.getElementById('hunt-results').style.display  = 'none';
  document.getElementById('hunt-empty').style.display    = 'none';
  const el = document.getElementById('hunt-error');
  el.textContent   = '⚠ ' + msg;
  el.style.display = 'block';
}

// ════════════════════════════════════════════════════════════
//  Time Range helpers
// ════════════════════════════════════════════════════════════

// Switch between relative / absolute mode tabs
function huntSetTimeMode(mode) {
  Hunt.timeMode = mode;
  document.getElementById('hunt-time-relative').style.display = mode === 'relative' ? 'flex' : 'none';
  document.getElementById('hunt-time-absolute').style.display = mode === 'absolute' ? 'flex' : 'none';
  document.querySelectorAll('.hunt-time-tab').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.mode === mode);
  });
}

// Build { from, to } strings to send to the API.
// Returns null and shows an error if the inputs are invalid.
function huntBuildTimeRange() {
  if (Hunt.timeMode === 'relative') {
    const val  = parseInt(document.getElementById('hunt-rel-value').value, 10);
    const unit = document.getElementById('hunt-rel-unit').value;
    if (!val || val < 1) { huntShowError('Enter a valid number for the relative time range.'); return null; }
    // ES "now minus" shorthand: "now-30d", "now-24h", etc.
    return { from: `now-${val}${unit}`, to: 'now' };
  }

  // Absolute mode — convert datetime-local values to ISO 8601
  const fromVal = document.getElementById('hunt-abs-from').value;
  const toVal   = document.getElementById('hunt-abs-to').value;
  if (!fromVal) { huntShowError('Enter a start date/time for the absolute time range.'); return null; }
  const fromISO = new Date(fromVal).toISOString();
  const toISO   = toVal ? new Date(toVal).toISOString() : new Date().toISOString();
  if (new Date(fromISO) >= new Date(toISO)) {
    huntShowError('Start date must be before end date.'); return null;
  }
  return { from: fromISO, to: toISO };
}

// Keep the "Last 30 days" preview label updated as user types
function huntUpdateRelativeLabel() {
  const val  = parseInt((document.getElementById('hunt-rel-value') || {}).value, 10);
  const unit = (document.getElementById('hunt-rel-unit') || {}).value || 'd';
  const labels = { d:'day', h:'hour', m:'minute', w:'week', M:'month' };
  const noun   = labels[unit] || unit;
  const el     = document.getElementById('hunt-rel-preview');
  if (!el) return;
  if (!val || val < 1) { el.textContent = ''; return; }
  el.textContent = `Last ${val} ${noun}${val !== 1 ? 's' : ''}`;
}

// ─── Initialise time UI defaults on page load ─────────────────
function huntInitTimeRange() {
  // Pre-fill absolute fields with a sensible default window (last 30 days)
  const now   = new Date();
  const past  = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const fmt   = d => d.toISOString().slice(0, 16); // "YYYY-MM-DDTHH:MM"
  const fromEl = document.getElementById('hunt-abs-from');
  const toEl   = document.getElementById('hunt-abs-to');
  if (fromEl) fromEl.value = fmt(past);
  if (toEl)   toEl.value   = fmt(now);

  // Trigger the preview label
  huntUpdateRelativeLabel();

  // Re-calculate preview whenever relative inputs change
  const relVal  = document.getElementById('hunt-rel-value');
  const relUnit = document.getElementById('hunt-rel-unit');
  if (relVal)  relVal.addEventListener('input',  huntUpdateRelativeLabel);
  if (relUnit) relUnit.addEventListener('change', huntUpdateRelativeLabel);
}

// Run init once DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', huntInitTimeRange);
} else {
  huntInitTimeRange();
}

// ─── Format time range for display in results header ─────────
function huntFormatTimeRange(from, to) {
  if (!from) return '';
  // Relative shorthand e.g. "now-30d"
  const relMatch = from.match(/^now-(\d+)([mhdwM])$/);
  if (relMatch) {
    const n = relMatch[1], u = relMatch[2];
    const labels = { m:'min', h:'hr', d:'day', w:'week', M:'month' };
    const noun = labels[u] || u;
    return `Last ${n} ${noun}${parseInt(n) !== 1 ? 's' : ''}`;
  }
  // Absolute: format both ends
  try {
    const opts = { year:'numeric', month:'short', day:'numeric',
                   hour:'2-digit', minute:'2-digit', hour12:false };
    const f = new Date(from).toLocaleString(undefined, opts);
    const t = to && to !== 'now' ? new Date(to).toLocaleString(undefined, opts) : 'now';
    return `${f} → ${t}`;
  } catch(_) { return from; }
}
