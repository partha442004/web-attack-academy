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

  function boot() {
    if (!id) { document.getElementById('lab-title').textContent = 'Missing lab id'; return; }
    fetch('data/labs.json').then(r => r.json()).then(data => {
      const lab = data.labs[id];
      if (!lab) { document.getElementById('lab-title').textContent = 'Unknown lab: ' + id; return; }
      document.title = lab.title + ' — Web Attack Academy';
      document.getElementById('lab-title').textContent = lab.title;
      document.getElementById('lab-objective').innerHTML = lab.objective;
      document.getElementById('lab-hint').innerHTML = lab.hint;
      document.getElementById('lab-id-label').textContent = 'Lab id: ' + id + ' · type: ' + lab.type;
      document.getElementById('btn-open').href = CONFIG.API_BASE + '/lab/' + id;
      frame.dataset.path = CONFIG.API_BASE + '/lab/' + id;
      loadLab();
      checkStatus();
    });
  }

  document.getElementById('btn-reload').addEventListener('click', () => {
    frame.dataset.path = CONFIG.API_BASE + '/lab/' + id;
    loadLab();
  });

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