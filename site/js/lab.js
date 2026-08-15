// Lab page logic — loads one lab, embeds it, tracks solve state via the worker.
(function () {
  const params = new URLSearchParams(location.search);
  const id = params.get('id');
  const frame = document.getElementById('lab-frame');
  const consoleEl = document.getElementById('console');

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
  }

  async function checkStatus() {
    try {
      const r = await api(CONFIG.API_BASE + '/api/status/' + id);
      const d = await r.json();
      if (d.solved) markSolved();
    } catch (e) { /* worker not running */ }
  }

  function loadLab() {
    // Always reload with a fresh timestamp to avoid cached lab state.
    const sep = frame.getAttribute('data-path') ? '#' : '';
    const base = CONFIG.API_BASE + '/lab/' + id;
    frame.src = (frame.getAttribute('data-path') || base);
    frame.removeAttribute('data-path');
    log('→ Loaded lab ' + id, 'req');
  }

  // Progressive hints: three escalating levels revealed one at a time.
  function setupHints(lab) {
    const box = document.getElementById('lab-hint');
    const hints = Array.isArray(lab.hints) && lab.hints.length ? lab.hints : [lab.hint || ''];
    let level = -1;

    function render() {
      if (level < 0) {
        box.style.display = 'none';
        return;
      }
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
    // Only Hint 1 is visible initially.
    for (let i = 0; i < Math.min(3, hints.length); i++) {
      document.getElementById('hint-' + i).style.display = i === 0 ? '' : 'none';
    }
    render();
  }

  function boot() {
    if (!id) { document.getElementById('lab-title').textContent = 'Missing lab id'; return; }
    fetch('data/labs.json').then(r => r.json()).then(data => {
      const lab = data.labs[id];
      if (!lab) { document.getElementById('lab-title').textContent = 'Unknown lab: ' + id; return; }
      document.title = lab.title + ' — Web Attack Academy';
      document.getElementById('lab-title').textContent = lab.title;
      document.getElementById('lab-objective').innerHTML = lab.objective;
      setupHints(lab);
      document.getElementById('lab-id-label').textContent = 'Lab id: ' + id + ' · type: ' + lab.type;
      document.getElementById('btn-open').href = CONFIG.API_BASE + '/lab/' + id;
      frame.dataset.path = CONFIG.API_BASE + '/lab/' + id;
      loadLab();
      checkStatus();
    });
  }

  function setupTheme() {
    const btn = document.getElementById('theme-toggle');
    const apply = (dark) => {
      document.documentElement.dataset.theme = dark ? 'dark' : 'light';
      btn.textContent = dark ? '☀️ Light' : '🌙 Dark';
    };
    btn.addEventListener('click', () => {
      const dark = document.documentElement.dataset.theme !== 'dark';
      apply(dark);
      localStorage.setItem('waa-theme', dark ? 'dark' : 'light');
    });
    apply(localStorage.getItem('waa-theme') === 'dark');
  }
  setupTheme();

  document.getElementById('btn-reload').addEventListener('click', () => {
    frame.dataset.path = CONFIG.API_BASE + '/lab/' + id;
    loadLab();
  });

  // ---- Request inspector ----
  const riMethod = document.getElementById('ri-method');
  const riPath = document.getElementById('ri-path');
  const riHeaders = document.getElementById('ri-headers');
  const riBody = document.getElementById('ri-body');
  const riOut = document.getElementById('ri-out');

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
    const method = riMethod.value;
    const path = riPath.value.trim() || '/lab/' + id;
    const headers = parseHeaders(riHeaders.value);
    const body = riBody.value;
    const isHead = method === 'HEAD';
    const opts = { method, headers, credentials: 'include' };
    if (body && !['GET', 'HEAD'].includes(method)) opts.body = body;
    riOut.textContent = '→ ' + method + ' ' + CONFIG.API_BASE + path + '\n';
    try {
      const r = await fetch(CONFIG.API_BASE + path, opts);
      const text = isHead ? '' : await r.text();
      riOut.textContent += '→ Headers sent: ' + (Object.keys(headers).length ? '\n' + fmtHeaders(headers) : '(none)') + '\n\n';
      riOut.textContent += '← ' + r.status + ' ' + r.statusText + '\n' + fmtHeaders(r.headers) + '\n\n';
      if (text) riOut.textContent += text.slice(0, 4000) + (text.length > 4000 ? '\n… (truncated)' : '');
      log('→ ' + method + ' ' + path + ' → ' + r.status, r.headers.get('x-lab-solved') === 'true' ? 'solved' : 'req');
      if (r.headers.get('x-lab-solved') === 'true') markSolved();
    } catch (e) {
      riOut.textContent += '\n✘ Request failed: ' + e.message;
      log('✘ Inspector request failed: ' + e.message, 'req');
    }
  }

  document.getElementById('ri-send').addEventListener('click', sendRaw);
  riPath.value = '/lab/' + id;

  // Client-side labs (DOM XSS, clickjacking) announce solves via postMessage.
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

  boot();
})();