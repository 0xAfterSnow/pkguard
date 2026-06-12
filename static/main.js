const SEV_ICONS = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', safe: '✅' };
const TYPE_ICONS = { backdoor: '🚪', malware: '💀', sabotage: '💣', typosquat: '🎭', vulnerability: '⚠️', new_package: '🆕', single_maintainer: '👤', high_velocity: '🚀', not_found: '❓' };

// ── Render tools ──────────────────────────────────────────────────────────
async function loadAndRenderTools(id) {
  try {
    const res = await fetch('/api/tools');
    const tools = await res.json();
    document.getElementById(id).innerHTML = tools.map(t => `
      <div class="tool-card">
        <span class="tool-type ${t.cls}">${t.type}</span>
        <div class="tool-name">${t.name}</div>
        <div class="tool-desc">${t.desc}</div>
        <a class="tool-link" href="${t.url}" target="_blank" rel="noopener">Learn more →</a>
      </div>`).join('');
  } catch (e) {
    console.error("Failed to load tools", e);
  }
}

// ── Stats ──────────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const r = await fetch('/api/stats');
    const d = await r.json();
    document.getElementById('stat-known').textContent = d.total_known_malicious.toLocaleString();
    document.getElementById('stat-critical').textContent = d.critical.toLocaleString();
    document.getElementById('stat-targets').textContent = d.typosquat_targets.toLocaleString();
    const badge = document.getElementById('db-badge');
    if (badge) badge.textContent = `${d.total_known_malicious} packages tracked`;
  } catch {
    const badge = document.getElementById('db-badge');
    if (badge) badge.textContent = 'Offline';
  }
}

// ── Tabs ──────────────────────────────────────────────────────────────────
function showTab(name, btn) {
  ['flagged', 'direct', 'peer', 'tools'].forEach(t => {
    const el = document.getElementById(`tab-${t}`);
    if(el) el.style.display = t === name ? 'block' : 'none';
  });
  document.querySelectorAll('.t-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  if (name === 'tools') loadAndRenderTools('tools-in-results');
}

// ── Example ───────────────────────────────────────────────────────────────
const EXAMPLE_PKG = {
  name: "demo-app",
  version: "1.0.0",
  dependencies: {
    "express": "^4.18.2",
    "lodash": "^4.17.15",
    "axios": "^0.21.0",
    "ua-parser-js": "^0.7.29",
    "colors": "^1.4.44-liberty-2",
    "event-stream": "^3.3.6",
    "mongoose": "^7.0.0",
    "jsonwebtoken": "^8.5.1",
    "mongose": "^1.0.0"
  },
  devDependencies: {
    "jest": "^29.0.0",
    "eslint": "^8.0.0"
  }
};

function updatePrismHighlight() {
  const input = document.getElementById('pkg-input').value;
  const highlightEl = document.getElementById('pkg-highlight');
  // Escape HTML before passing to Prism to prevent XSS/rendering issues
  let escaped = input.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  // Ensure the last newline renders
  if (escaped[escaped.length - 1] === '\n') escaped += ' ';
  highlightEl.innerHTML = escaped;
  if(window.Prism) Prism.highlightElement(highlightEl);
}

function loadExample() {
  const ta = document.getElementById('pkg-input');
  ta.value = JSON.stringify(EXAMPLE_PKG, null, 2);
  updatePrismHighlight();
}

async function loadExampleAndScan() {
  loadExample();
  document.getElementById('scanner').scrollIntoView({ behavior: 'smooth' });
  await new Promise(r => setTimeout(r, 600));
  startScan();
}

function clearAll() {
  const ta = document.getElementById('pkg-input');
  ta.value = '';
  updatePrismHighlight();
  document.getElementById('results-feed').style.display = 'none';
  document.getElementById('empty-feed').style.display = 'block';
  hideErr();
}

// ── Loading animation ─────────────────────────────────────────────────────
let stepTimer;
const STEPS = ['lstep-db', 'lstep-osv', 'lstep-typo', 'lstep-npm'];
const MSGS = ['Checking local DB…', 'Querying OSV advisories…', 'Detecting typosquats…', 'Fetching npm metadata…'];

function startSteps() {
  STEPS.forEach(s => document.getElementById(s).className = 'lstep');
  let i = 0;
  stepTimer = setInterval(() => {
    if (i > 0) document.getElementById(STEPS[i - 1]).className = 'lstep done';
    if (i < STEPS.length) {
      document.getElementById(STEPS[i]).className = 'lstep active';
      document.getElementById('loader-msg').textContent = MSGS[i];
      i++;
    } else clearInterval(stepTimer);
  }, 850);
}

function stopSteps() {
  clearInterval(stepTimer);
  STEPS.forEach(s => document.getElementById(s).className = 'lstep');
}

// ── Scan ──────────────────────────────────────────────────────────────────
async function startScan() {
  const input = document.getElementById('pkg-input').value.trim();
  if (!input) { showErr('Please paste your package.json content.'); return; }

  hideErr();
  document.getElementById('empty-feed').style.display = 'none';
  document.getElementById('results-feed').style.display = 'none';
  document.getElementById('loading').classList.add('visible');
  document.getElementById('scan-btn').disabled = true;
  startSteps();

  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ packageJson: input })
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Scan failed');
    renderResults(data);
  } catch (e) {
    showErr(e.message);
    document.getElementById('empty-feed').style.display = 'block';
  } finally {
    document.getElementById('loading').classList.remove('visible');
    document.getElementById('scan-btn').disabled = false;
    stopSteps();
  }
}

function showErr(msg) {
  const el = document.getElementById('error-strip');
  el.textContent = '⚠ ' + msg;
  el.classList.add('visible');
}

function hideErr() { document.getElementById('error-strip').classList.remove('visible'); }

// ── Render results ────────────────────────────────────────────────────────
function renderResults(data) {
  const { summary, direct, indirect } = data;
  const allFlagged = [...direct, ...indirect].filter(p => !p.safe);

  // Risk summary
  const score = summary.risk_score;
  const riskLabel = score === 0 ? 'All Clear' : score < 20 ? 'Low Risk' : score < 50 ? 'Moderate Risk' : score < 80 ? 'High Risk' : 'Critical Risk';
  const riskColor = score === 0 ? 'var(--green)' : score < 20 ? '#60c0a0' : score < 50 ? 'var(--yellow)' : score < 80 ? 'var(--orange)' : 'var(--red)';

  document.getElementById('rs-num').textContent = score;
  document.getElementById('rs-num').style.color = riskColor;
  document.getElementById('rs-title').textContent = riskLabel;
  document.getElementById('rs-meta').textContent = `${summary.flagged} of ${summary.total_packages} packages flagged`;

  const tags = document.getElementById('sev-tags');
  tags.innerHTML = '';
  const bySev = summary.by_severity;
  ['critical', 'high', 'medium', 'low'].forEach(s => {
    if (bySev[s]) tags.innerHTML += `<span class="sev-tag st-${s}">${SEV_ICONS[s]} ${bySev[s]} ${s}</span>`;
  });
  if (summary.safe) tags.innerHTML += `<span class="sev-tag st-safe">✅ ${summary.safe} safe</span>`;

  // Counts
  document.getElementById('tc-flagged').textContent = allFlagged.length;
  document.getElementById('tc-direct').textContent = direct.length;
  document.getElementById('tc-peer').textContent = indirect.length;

  // Lists
  buildList('list-flagged', allFlagged.length ? allFlagged : null, true);
  buildList('list-direct', direct);
  buildList('list-peer', indirect);

  document.getElementById('results-feed').style.display = 'block';
  showTab('flagged', document.querySelector('.t-btn'));
}

function buildList(id, pkgs, isFlagged) {
  const el = document.getElementById(id);
  if (!pkgs || pkgs.length === 0) {
    el.innerHTML = `<div class="empty-state">
  <div class="empty-icon">${isFlagged ? '✅' : '📦'}</div>
  <div class="empty-title">${isFlagged ? 'No threats found' : 'Nothing here'}</div>
  <div class="empty-sub">${isFlagged ? 'All scanned packages appear clean.' : 'No packages in this category.'}</div>
</div>`;
    return;
  }
  el.innerHTML = pkgs.map((p, i) => pkgCard(p, i)).join('');
}

function copySuggestion(cmd, btn) {
  navigator.clipboard.writeText(cmd).then(() => {
    const orig = btn.innerHTML;
    btn.innerHTML = '✓ Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.innerHTML = orig; btn.classList.remove('copied'); }, 2000);
  }).catch(() => {});
}

function buildSuggestionHtml(sugg) {
  if (!sugg) return '';
  if (sugg.warning) {
    const ref = sugg.url ? `<a class="sugg-ref" href="${sugg.url}" target="_blank" rel="noopener">npm →</a>` : '';
    return `<div class="suggestion-bar suggestion-warn"><span class="sugg-warn-icon">⚠</span><span class="sugg-warn-text">${sugg.reason}</span>${ref}</div>`;
  }
  const label = `${sugg.name}${sugg.version ? '@' + sugg.version : ''}`;
  const cmd = sugg.install || `npm install ${sugg.name}`;
  return `<div class="suggestion-bar">
  <span class="sugg-label">Use instead:</span>
  <button class="sugg-chip" onclick="copySuggestion('${cmd}', this)" title="Click to copy: ${cmd}">📦 ${label}</button>
  <span class="sugg-reason">${sugg.reason}</span>
  <a class="sugg-ref" href="${sugg.url}" target="_blank" rel="noopener">npm →</a>
</div>`;
}

function pkgCard(pkg, idx) {
  const sev = pkg.max_severity || 'safe';
  const flags = pkg.flags || [];
  const cardId = `pc-${idx}-${pkg.name.replace(/[^a-z0-9]/gi, '')}`;

  const flagsHtml = flags.map(f => `
<div class="flag-row">
  <div class="flag-icon-box fib-${f.severity}">${TYPE_ICONS[f.type] || '⚠️'}</div>
  <div class="flag-content">
    <div class="flag-title-row">
      <span class="flag-title">${f.title}</span>
      <span class="flag-sev fs-${f.severity}">${f.severity.toUpperCase()}</span>
    </div>
    <div class="flag-desc">${f.description || ''}</div>
    <div class="flag-foot">
      <span class="tag-mono">${f.source}</span>
      ${f.cve && f.cve !== 'N/A' ? `<span class="tag-mono">${f.cve}</span>` : ''}
      ${f.reference ? `<a class="tag-link" href="${f.reference}" target="_blank" rel="noopener">View advisory →</a>` : ''}
    </div>
  </div>
</div>`).join('');

  return `
<div class="pkg-card sev-${sev}" id="${cardId}">
  <div class="pkg-head" onclick="toggleCard('${cardId}')">
    <div class="pkg-icon pi-${sev}">${SEV_ICONS[sev]}</div>
    <span class="pkg-name">${pkg.name}</span>
    <span class="pkg-ver">${pkg.version || '*'}</span>
    <div class="pkg-right">
      ${flags.length ? `<span class="chip-sm c-issues">${flags.length} issue${flags.length > 1 ? 's' : ''}</span>` : '<span class="chip-sm c-clean">clean</span>'}
      <span class="chip-sm ${pkg.is_direct ? 'c-direct' : 'c-peer'}">${pkg.is_direct ? 'direct' : 'peer'}</span>
      <span class="chevron">▾</span>
    </div>
  </div>
  ${buildSuggestionHtml(pkg.suggestion)}
  ${flags.length ? `<div class="flag-list">${flagsHtml}</div>` : ''}
</div>`;
}

function toggleCard(id) { document.getElementById(id).classList.toggle('open'); }

document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') startScan();
});

// Setup syntax highlight syncing
document.addEventListener('DOMContentLoaded', () => {
  const ta = document.getElementById('pkg-input');
  if(ta) {
    ta.addEventListener('input', updatePrismHighlight);
    ta.addEventListener('scroll', () => {
      document.getElementById('pkg-highlight-pre').scrollTop = ta.scrollTop;
      document.getElementById('pkg-highlight-pre').scrollLeft = ta.scrollLeft;
    });
  }
  loadStats();
  if(document.getElementById('tools-main')) {
    loadAndRenderTools('tools-main');
  }
});

// ── Dev Modal ─────────────────────────────────────────────────────────────
function openDevModal() {
  const modal = document.getElementById('modal-dev');
  modal.style.display = 'flex';
  // Small timeout to allow display: flex to apply before adding class for transition
  setTimeout(() => {
    modal.classList.add('active');
  }, 10);
}

function closeDevModal() {
  const modal = document.getElementById('modal-dev');
  modal.classList.remove('active');
  setTimeout(() => {
    modal.style.display = 'none';
  }, 200); // match CSS transition duration
}

document.addEventListener('DOMContentLoaded', () => {
  const modal = document.getElementById('modal-dev');
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        closeDevModal();
      }
    });
  }
});
