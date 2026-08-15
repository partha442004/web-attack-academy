// Lab page logic — loads one lab, embeds it, tracks solve state via the worker.
(function () {
  const params = new URLSearchParams(location.search);
  const id = params.get('id');
  const frame = document.getElementById('lab-frame');
  const consoleEl = document.getElementById('console');

  // State
  let labData = null;
  let requestHistory = [];
  let currentStep = 1;
  const STEPS = ['Recon', 'Exploit', 'Verify', 'Mitigate'];

  function log(msg, cls) {
    const line = document.createElement('div');
    if (cls) line.className = cls;
    line.textContent = msg;
    consoleEl.appendChild(line);
    consoleEl.scrollTop = consoleEl.scrollHeight;
  }

  function api(url, opts) {
    return fetch(url, Object.assign({ credentials: 'include' }, opts || {}));
  }

  function markSolved() {
    const pill = document.getElementById('lab-pill');
    pill.textContent = 'SOLVED';
    pill.className = 'pill solved';
    document.getElementById('solved-banner').style.display = 'block';
    document.getElementById('btn-open').textContent = '✔ Solved — open in new tab';
    try {
      const raw = localStorage.getItem('waa-solved');
      const arr = raw ? JSON.parse(raw) : [];
      if (!arr.includes(id)) { arr.push(id); localStorage.setItem('waa-solved', JSON.stringify(arr)); }
    } catch (e) { /* localStorage unavailable */ }
  }

  async function checkStatus() {
    try {
      const r = await api(CONFIG.API_BASE + '/api/status/' + id);
      const d = await r.json();
      if (d.solved) markSolved();
    } catch (e) { /* worker not running */ }
  }

  function loadLab() {
    const sep = frame.getAttribute('data-path') ? '#' : '';
    const base = CONFIG.API_BASE + '/lab/' + id;
    frame.src = (frame.getAttribute('data-path') || base);
    frame.removeAttribute('data-path');
    log('→ Loaded lab ' + id, 'req');
  }

  // Step tracker
  function updateStep(step) {
    currentStep = Math.max(1, Math.min(4, step));
    document.querySelectorAll('.step').forEach((el, i) => {
      const n = i + 1;
      el.classList.toggle('complete', n < currentStep);
      el.classList.toggle('active', n === currentStep);
    });
  }

  function autoStepFromEvent(eventType) {
    if (eventType === 'req' && currentStep < 2) updateStep(2);
    if (eventType === 'solved') updateStep(4);
  }

  // Progressive hints
  function setupHints(lab) {
    const box = document.getElementById('lab-hint');
    const hints = Array.isArray(lab.hints) && lab.hints.length ? lab.hints : [lab.hint || ''];
    let level = -1;

    function render() {
      if (level < 0) { box.style.display = 'none'; return; }
      box.style.display = 'block';
      box.innerHTML = '<div class="hint-tag">Hint ' + (level + 1) + ' / ' + hints.length + '</div>' +
        (hints[level] || hints[hints.length - 1]);
      for (let i = 0; i < Math.min(3, hints.length); i++) {
        const b = document.getElementById('hint-' + i);
        b.classList.toggle('active', i === level);
        b.classList.toggle('used', i < level);
        b.style.display = i === level + 1 ? '' : 'none';
      }
    }

    for (let i = 0; i < Math.min(3, hints.length); i++) {
      document.getElementById('hint-' + i).addEventListener('click', () => {
        level = i;
        render();
      });
    }
    for (let i = 0; i < Math.min(3, hints.length); i++) {
      document.getElementById('hint-' + i).style.display = i === 0 ? '' : 'none';
    }
    render();
  }

  // Lab metadata display
  function renderLabMeta(lab) {
    const metaEl = document.getElementById('lab-meta');
    const tagsEl = document.getElementById('lab-tags');
    const timeEl = document.getElementById('lab-time');
    const prereqEl = document.getElementById('lab-prereqs');
    const prereqLinksEl = document.getElementById('lab-prereq-links');

    if (lab.tags && lab.tags.length) {
      tagsEl.innerHTML = lab.tags.map(t => '<span class="meta-tag">' + t + '</span>').join('');
    }
    if (lab.estimatedTimeMinutes) {
      timeEl.textContent = '⏱ ~' + lab.estimatedTimeMinutes + ' min';
    }
    if (lab.prerequisites && lab.prerequisites.length) {
      prereqEl.style.display = 'inline-flex';
      prereqLinksEl.innerHTML = lab.prerequisites.map(p =>
        '<a href="lab.html?id=' + p + '">' + p + '</a>'
      ).join(', ');
    }
    metaEl.style.display = 'flex';
  }

  // Cheatsheet panel
  function openCheatsheet() {
    const body = document.getElementById('cheatsheet-body');
    const panel = document.getElementById('cheatsheet-panel');
    if (!labData.cheatsheet) {
      body.innerHTML = '<p class="muted">No cheatsheet available for this lab.</p>';
    } else {
      const cs = labData.cheatsheet;
      let html = '';
      if (cs.payloads && cs.payloads.length) {
        html += '<div class="cheatsheet-section"><h4>💣 Payloads</h4><div class="payload-list">' +
          cs.payloads.map(p => '<div class="payload-item"><code>' + escapeHtml(p) + '</code><button class="payload-copy" data-payload="' + escapeHtml(p) + '">Copy</button></div>').join('') +
        '</div></div>';
      }
      if (cs.tools && cs.tools.length) {
        html += '<div class="cheatsheet-section"><h4>🛠 Tools</h4><ul style="margin:0;padding-left:18px;font-size:13px;">' +
          cs.tools.map(t => '<li>' + t + '</li>').join('') + '</ul></div>';
      }
      if (cs.references && cs.references.length) {
        html += '<div class="cheatsheet-section"><h4>📚 References</h4><ul style="margin:0;padding-left:18px;font-size:13px;">' +
          cs.references.map(r => '<li><a href="' + r + '" target="_blank" rel="noopener">' + r + '</a></li>').join('') + '</ul></div>';
      }
      body.innerHTML = html;
      body.querySelectorAll('.payload-copy').forEach(btn => {
        btn.addEventListener('click', () => {
          navigator.clipboard.writeText(btn.dataset.payload);
          btn.textContent = '✓';
          setTimeout(() => btn.textContent = 'Copy', 1500);
        });
      });
    }
    panel.classList.add('open');
    panel.setAttribute('aria-hidden', 'false');
  }

  // History panel
  function openHistory() {
    const body = document.getElementById('history-body');
    const panel = document.getElementById('history-panel');
    const empty = document.getElementById('history-empty');
    if (!requestHistory.length) {
      empty.style.display = 'block';
    } else {
      empty.style.display = 'none';
      body.innerHTML = '<div class="history-list">' +
        requestHistory.map((r, i) => '<div class="history-item" data-index="' + i + '">' +
          '<div class="history-header">' +
            '<span class="history-method">' + r.method + '</span>' +
            '<span class="history-path" title="' + escapeHtml(r.url) + '">' + escapeHtml(r.url) + '</span>' +
            '<span class="history-time">' + new Date(r.time).toLocaleTimeString() + '</span>' +
            '<button class="history-toggle" aria-label="Expand">▼</button>' +
          '</div>' +
          '<div class="history-details"><pre>' + escapeHtml(r.response || '(no response yet)') + '</pre></div>' +
        '</div>').join('') + '</div>';
      body.querySelectorAll('.history-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
          btn.closest('.history-item').classList.toggle('open');
          btn.textContent = btn.closest('.history-item').classList.contains('open') ? '▲' : '▼';
        });
      });
    }
    panel.classList.add('open');
    panel.setAttribute('aria-hidden', 'false');
  }

  // Modal helpers
  function openModal(overlayId) {
    const overlay = document.getElementById(overlayId);
    overlay.classList.add('open');
    overlay.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
  }
  function closeModal(overlayId) {
    const overlay = document.getElementById(overlayId);
    overlay.classList.remove('open');
    overlay.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
  }

  // Solution walkthrough
  function openSolution() {
    const body = document.getElementById('solution-body');
    if (!labData.solution) {
      body.innerHTML = '<p class="muted">No solution walkthrough available.</p>';
    } else {
      const sol = labData.solution;
      let html = '<div class="solution-section"><h4>🎯 Payload</h4><pre>' + escapeHtml(sol.payload) + '</pre></div>';
      if (sol.explanation) html += '<div class="solution-section"><h4>📖 Explanation</h4><p>' + escapeHtml(sol.explanation) + '</p></div>';
      if (sol.mitigation && Object.keys(sol.mitigation).length) {
        html += '<div class="solution-section"><h4>🛡 Mitigation</h4><div class="solution-mitigation">';
        for (const [lang, code] of Object.entries(sol.mitigation)) {
          html += '<div class="mitigation-block"><h5>' + lang.toUpperCase() + '</h5><pre><code>' + escapeHtml(code) + '</code></pre></div>';
        }
        html += '</div></div>';
      }
      body.innerHTML = html;
    }
    openModal('solution-modal');
  }

  // Related labs
  function renderRelated() {
    const card = document.getElementById('related-card');
    const grid = document.getElementById('related-labs');
    if (!labData.related || !labData.related.length) { card.style.display = 'none'; return; }
    grid.innerHTML = labData.related.map(relId => {
      const rel = labData.related ? null : null; // fetch from labs data if needed
      // We need the full labs data to get titles. Store it globally.
      return '';
    }).join('');
    // Actually fill after labs data is loaded globally
  }

  function fillRelated(allLabs) {
    const card = document.getElementById('related-card');
    const grid = document.getElementById('related-labs');
    if (!labData.related || !labData.related.length) { card.style.display = 'none'; return; }
    grid.innerHTML = labData.related.map(relId => {
      const rel = allLabs[relId];
      if (!rel) return '';
      const tags = rel.tags ? rel.tags.slice(0, 3) : [];
      return '<a class="related-card" href="lab.html?id=' + relId + '" style="text-decoration:none;color:inherit;">' +
        '<div class="related-title">' + escapeHtml(rel.title) + '</div>' +
        '<div class="related-meta">' +
          '<span>⏱ ~' + (rel.estimatedTimeMinutes || '?') + ' min</span>' +
          '<span>★'.repeat(rel.difficulty || 1) + '</span>' +
        '</div>' +
        '<div class="related-tags">' + tags.map(t => '<span class="related-tag">' + t + '</span>').join('') + '</div>' +
      '</a>';
    }).join('');
    card.style.display = 'block';
  }

  // Copy as cURL / fetch
  function buildCurl() {
    const method = document.getElementById('ri-method').value;
    const url = CONFIG.API_BASE + (document.getElementById('ri-path').value.trim() || '/lab/' + id);
    const headers = parseHeaders(document.getElementById('ri-headers').value);
    const body = document.getElementById('ri-body').value;
    let curl = 'curl -X ' + method + ' ';
    for (const [k, v] of Object.entries(headers)) {
      curl += '-H "' + k + ': ' + v.replace(/"/g, '\\"') + '" ';
    }
    if (body && !['GET', 'HEAD'].includes(method)) {
      curl += '-d "' + body.replace(/"/g, '\\"') + '" ';
    }
    curl += '"' + url + '"';
    return curl;
  }

  function buildFetch() {
    const method = document.getElementById('ri-method').value;
    const url = CONFIG.API_BASE + (document.getElementById('ri-path').value.trim() || '/lab/' + id);
    const headers = parseHeaders(document.getElementById('ri-headers').value);
    const body = document.getElementById('ri-body').value;
    let code = 'fetch("' + url + '", {\n  method: "' + method + '",\n  credentials: "include",\n  headers: {\n';
    for (const [k, v] of Object.entries(headers)) {
      code += '    "' + k + '": "' + v.replace(/"/g, '\\"') + '",\n';
    }
    code += '  }';
    if (body && !['GET', 'HEAD'].includes(method)) {
      code += ',\n  body: "' + body.replace(/"/g, '\\"') + '"';
    }
    code += '\n}).then(r => r.text()).then(console.log)';
    return code;
  }

  // Request inspector
  function parseHeaders(text) {
    const h = {};
    (text || '').split('\n').forEach(line => {
      const i = line.indexOf(':');
      if (i > 0) h[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    });
    return h;
  }

  function fmtHeaders(headers) {
    const lines = [];
    headers.forEach((v, k) => lines.push(`${k}: ${v}`));
    return lines.join('\n');
  }

  async function sendRaw() {
    const method = document.getElementById('ri-method').value;
    const path = document.getElementById('ri-path').value.trim() || '/lab/' + id;
    const headers = parseHeaders(document.getElementById('ri-headers').value);
    const body = document.getElementById('ri-body').value;
    const isHead = method === 'HEAD';
    const opts = { method, headers, credentials: 'include' };
    if (body && !['GET', 'HEAD'].includes(method)) opts.body = body;
    const riOut = document.getElementById('ri-out');
    riOut.textContent = '→ ' + method + ' ' + CONFIG.API_BASE + path + '\n';
    try {
      const r = await fetch(CONFIG.API_BASE + path, opts);
      const text = isHead ? '' : await r.text();
      riOut.textContent += '→ Headers sent: ' + (Object.keys(headers).length ? '\n' + fmtHeaders(headers) : '(none)') + '\n\n';
      riOut.textContent += '← ' + r.status + ' ' + r.statusText + '\n' + fmtHeaders(r.headers) + '\n\n';
      if (text) riOut.textContent += text.slice(0, 4000) + (text.length > 4000 ? '\n… (truncated)' : '');
      log('→ ' + method + ' ' + path + ' → ' + r.status, r.headers.get('x-lab-solved') === 'true' ? 'solved' : 'req');
      autoStepFromEvent(r.headers.get('x-lab-solved') === 'true' ? 'solved' : 'req');

      // Record history
      requestHistory.unshift({
        method, url: path, time: Date.now(),
        requestHeaders: headers, requestBody: body,
        response: '← ' + r.status + ' ' + r.statusText + '\n' + fmtHeaders(r.headers) + '\n\n' + (text || '')
      });
      if (requestHistory.length > 50) requestHistory.pop();

      if (r.headers.get('x-lab-solved') === 'true') markSolved();
    } catch (e) {
      riOut.textContent += '\n✘ Request failed: ' + e.message;
      log('✘ Inspector request failed: ' + e.message, 'req');
    }
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, c => ({'&':'&','<':'<','>':'>','"':'"',"'":'''}[c]));
  }

  // Keyboard shortcuts
  function setupKeyboard() {
    document.addEventListener('keydown', (e) => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;
      if (e.ctrlKey && e.key === 'Enter') { e.preventDefault(); sendRaw(); }
      else if (e.key === 'c' || e.key === 'C') { e.preventDefault(); openCheatsheet(); }
      else if (e.key === 'h' || e.key === 'H') { e.preventDefault(); openHistory(); }
      else if (e.key === '?') { e.preventDefault(); openModal('shortcuts-modal'); }
      else if (e.key === 'r' || e.key === 'R') { e.preventDefault(); loadLab(); }
      else if (e.key === 'Escape') {
        document.querySelectorAll('.slide-panel.open, .modal-overlay.open').forEach(el => {
          el.classList.remove('open');
          el.setAttribute('aria-hidden', 'true');
        });
        document.body.style.overflow = '';
      }
    });
  }

  function boot() {
    if (!id) { document.getElementById('lab-title').textContent = 'Missing lab id'; return; }
    fetch('data/labs.json').then(r => r.json()).then(data => {
      labData = data.labs[id];
      if (!labData) { document.getElementById('lab-title').textContent = 'Unknown lab: ' + id; return; }
      document.title = labData.title + ' — Web Attack Academy';
      document.getElementById('lab-title').textContent = labData.title;
      document.getElementById('lab-objective').innerHTML = labData.objective;
      setupHints(labData);
      renderLabMeta(labData);
      fillRelated(data.labs);
      document.getElementById('lab-id-label').textContent = 'Lab id: ' + id + ' · type: ' + labData.type;
      document.getElementById('btn-open').href = CONFIG.API_BASE + '/lab/' + id;
      frame.dataset.path = CONFIG.API_BASE + '/lab/' + id;
      loadLab();
      checkStatus();
      setupKeyboard();
    });
  }

  document.getElementById('btn-reload').addEventListener('click', () => {
    frame.dataset.path = CONFIG.API_BASE + '/lab/' + id;
    loadLab();
    updateStep(1);
  });

  // Request inspector events
  document.getElementById('ri-send').addEventListener('click', sendRaw);
  document.getElementById('ri-copy-curl').addEventListener('click', () => {
    navigator.clipboard.writeText(buildCurl());
    log('📋 Copied as cURL', 'req');
  });
  document.getElementById('ri-copy-fetch').addEventListener('click', () => {
    navigator.clipboard.writeText(buildFetch());
    log('📋 Copied as fetch', 'req');
  });
  document.getElementById('ri-path').value = '/lab/' + id;

  // Panel/modal buttons
  document.getElementById('btn-cheatsheet').addEventListener('click', openCheatsheet);
  document.getElementById('btn-history').addEventListener('click', openHistory);
  document.getElementById('btn-shortcuts').addEventListener('click', () => openModal('shortcuts-modal'));
  document.getElementById('cheatsheet-close').addEventListener('click', () => closeModal('cheatsheet-panel'));
  document.getElementById('history-close').addEventListener('click', () => closeModal('history-panel'));
  document.getElementById('shortcuts-close').addEventListener('click', () => closeModal('shortcuts-modal'));
  document.getElementById('solution-close').addEventListener('click', () => closeModal('solution-modal'));
  // Close on overlay click
  document.querySelectorAll('.modal-overlay').forEach(ov => ov.addEventListener('click', (e) => {
    if (e.target === ov) closeModal(ov.id);
  }));

  // Solution button (hint-2 = Solution)
  document.getElementById('hint-2').addEventListener('click', openSolution);

  // Client-side labs announce solves via postMessage
  window.addEventListener('message', (e) => {
    if (typeof e.data !== 'string') return;
    const m = e.data.match(/^academy-solved:([\w-]+)$/);
    if (!m) return;
    const labId = m[1];
    log('⤴ Received solve signal for ' + labId, 'solved');
    api(CONFIG.API_BASE + '/api/mark/' + labId, { method: 'POST' }).then(() => {
      markSolved();
      checkStatus();
    });
  });

  // Auth gate
  let booted = false;
  function tryBoot() {
    if (booted) return;
    if (window.Auth && Auth.user) { booted = true; boot(); }
  }
  function requireAuth() {
    if (!window.Auth) { tryBoot(); return; }
    if (Auth.user) { tryBoot(); return; }
    Auth.onChange(({ user }) => {
      if (user) tryBoot();
      else if (!booted) window.location.replace('index.html');
    });
    // Also check current state in case notify already fired
    tryBoot();
  }
  requireAuth();
})();